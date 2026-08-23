"""Durable actuator mutation intent, lease recovery, and settlement."""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.actions import ExecutionAuthorization
from solvan.application.actuator import (
    ActuatorDispatch,
    DispatchPhase,
    ExecutionReceiptWrite,
    ExecutionResult,
    PredictedEffect,
    ReservationConflict,
    ReservationLost,
    TargetObservation,
    TargetReservation,
    UndoPlan,
)
from solvan.domain import Scope, canonical_json_hash, new_identifier
from solvan.persistence.action_material import material_from_action
from solvan.persistence.actuator_dispatch_settlement import (
    extend_reservation,
    insert_execution_receipt,
    settle_action,
)


def count_dispatches_in_window(connection: Connection[Any], *, window_seconds: int) -> int:
    """Mutation dispatches recorded in the trailing window, fleet-wide.

    The in-process ActionRateBudget bounds one instance and resets on every
    cold start; with scale-to-zero an actor pacing mutations slower than the
    idle timeout faced no ceiling at all. Every mutation writes its
    actuator_dispatches row before any connector acts, so this count is the
    durable form of the same ceiling: shared by all instances and unaffected
    by restarts. Deliberately unscoped -- the ceiling is a property of the
    deployment, not of one tenant scope.
    """

    row = connection.execute(
        """SELECT count(*) AS recent FROM solvan.actuator_dispatches
            WHERE dispatched_at > now() - make_interval(secs => %(window)s)""",
        {"window": window_seconds},
    ).fetchone()
    return int(row[0]) if row else 0


class ActuatorDispatchMixin:
    """Implement the existing actuator tables as the one mutation-attempt truth."""

    _connection: Connection[Any]

    def prepare_dispatch(
        self,
        *,
        scope: Scope,
        reservation: TargetReservation,
        authority: ExecutionAuthorization,
        actuator_id: str,
        owner_identity: str,
        before_state: TargetObservation,
        prediction: PredictedEffect,
        undo_plan: UndoPlan,
        trace_id: str | None,
        ttl_ms: int,
    ) -> ActuatorDispatch:
        if ttl_ms < 1:
            raise ValueError("dispatch TTL must be positive")
        if authority.material.action_id != reservation.action_id:
            raise ValueError("dispatch authority does not own the reservation")
        dispatch_id = new_identifier("dsp")
        effect_receipt_id = new_identifier("aef")
        lease_token = uuid4()
        request_hash = canonical_json_hash(
            {
                "action_id": reservation.action_id,
                "actuator_id": actuator_id,
                "before_state_hash": before_state.content_hash,
                "connector_revision": prediction.connector_revision,
                "expected_effect_hash": authority.material.expected_effect_hash,
                "idempotency_key": authority.idempotency_key,
                "predicted_effect_hash": prediction.content_hash,
                "reservation_id": reservation.reservation_id,
            }
        )
        try:
            with (
                self._connection.transaction(),
                self._connection.cursor(row_factory=dict_row) as cursor,
            ):
                cursor.execute(
                    """SELECT policy_hash, customer_audit_sink_ref
                      FROM solvan.actuator_registrations
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(actuator_id)s AND status = 'ACTIVE'
                        AND posture = 'REMEDIATE' AND production_eligible
                        AND NOT kill_switch_engaged
                        AND policy_hash IS NOT NULL
                        AND customer_audit_sink_ref IS NOT NULL
                      FOR UPDATE""",
                    {**scope.canonical_dict(), "actuator_id": actuator_id},
                )
                registration = cursor.fetchone()
                if registration is None:
                    raise ReservationConflict("actuator is not active for remediation")
                cursor.execute(
                    """SELECT id FROM solvan.target_reservations
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(reservation_id)s AND action_id = %(action_id)s
                        AND owner_identity = %(owner_identity)s
                        AND lease_token = %(reservation_lease_token)s
                        AND released_at IS NULL AND expires_at >= now()
                      FOR UPDATE""",
                    {
                        **scope.canonical_dict(),
                        "reservation_id": reservation.reservation_id,
                        "action_id": reservation.action_id,
                        "owner_identity": reservation.owner_identity,
                        "reservation_lease_token": reservation.lease_token,
                    },
                )
                if cursor.fetchone() is None:
                    raise ReservationLost("reservation was lost before dispatch preparation")
                cursor.execute(
                    """INSERT INTO solvan.actuator_dispatches
                      (organization_id, project_id, environment_id, id,
                       actuator_id, action_id, reservation_id, lease_expires_at,
                       lease_owner, lease_token, dispatch_policy_hash,
                       expected_effect_hash, connector_revision, request_hash,
                       trace_id, status)
                      VALUES (%(organization_id)s, %(project_id)s,
                        %(environment_id)s, %(dispatch_id)s, %(actuator_id)s,
                        %(action_id)s, %(reservation_id)s,
                        now() + (%(ttl_ms)s * interval '1 millisecond'),
                        %(lease_owner)s, %(lease_token)s, %(policy_hash)s,
                        %(expected_effect_hash)s, %(connector_revision)s,
                        %(request_hash)s, %(trace_id)s, 'PREPARED')
                      RETURNING dispatched_at, lease_expires_at""",
                    {
                        **scope.canonical_dict(),
                        "dispatch_id": dispatch_id,
                        "actuator_id": actuator_id,
                        "action_id": reservation.action_id,
                        "reservation_id": reservation.reservation_id,
                        "ttl_ms": ttl_ms,
                        "lease_owner": owner_identity,
                        "lease_token": lease_token,
                        "policy_hash": registration["policy_hash"],
                        "expected_effect_hash": authority.material.expected_effect_hash,
                        "connector_revision": prediction.connector_revision,
                        "request_hash": request_hash,
                        "trace_id": trace_id,
                    },
                )
                dispatch_row = cursor.fetchone()
                assert dispatch_row is not None
                cursor.execute(
                    """INSERT INTO solvan.actuator_effect_receipts
                      (organization_id, project_id, environment_id, id,
                       dispatch_id, policy_hash, before_state_ref,
                       before_state_hash, predicted_effect_hash,
                       effect_matched_expectation, undo_plan_json, started_at)
                      VALUES (%(organization_id)s, %(project_id)s,
                        %(environment_id)s, %(effect_receipt_id)s,
                        %(dispatch_id)s, %(policy_hash)s, %(before_state_ref)s,
                        %(before_state_hash)s, %(predicted_effect_hash)s, true,
                        %(undo_plan)s, %(started_at)s)""",
                    {
                        **scope.canonical_dict(),
                        "effect_receipt_id": effect_receipt_id,
                        "dispatch_id": dispatch_id,
                        "policy_hash": registration["policy_hash"],
                        "before_state_ref": before_state.state_ref,
                        "before_state_hash": before_state.content_hash,
                        "predicted_effect_hash": prediction.content_hash,
                        "undo_plan": Jsonb(dict(undo_plan.descriptor)),
                        "started_at": dispatch_row["dispatched_at"],
                    },
                )
                cursor.execute(
                    """UPDATE solvan.target_reservations
                      SET expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(reservation_id)s
                        AND lease_token = %(reservation_lease_token)s
                        AND released_at IS NULL
                      RETURNING expires_at""",
                    {
                        **scope.canonical_dict(),
                        "ttl_ms": ttl_ms,
                        "reservation_id": reservation.reservation_id,
                        "reservation_lease_token": reservation.lease_token,
                    },
                )
                reservation_expiry = cursor.fetchone()
                if reservation_expiry is None:
                    raise ReservationLost("reservation was lost during dispatch preparation")
        except UniqueViolation as error:
            raise ReservationConflict("action or actuator already has a dispatch") from error
        return ActuatorDispatch(
            dispatch_id=dispatch_id,
            effect_receipt_id=effect_receipt_id,
            actuator_id=actuator_id,
            reservation=replace(reservation, expires_at=reservation_expiry["expires_at"]),
            material=authority.material,
            idempotency_key=authority.idempotency_key,
            phase=DispatchPhase.PREPARED,
            policy_hash=str(registration["policy_hash"]),
            request_hash=request_hash,
            expected_effect_hash=authority.material.expected_effect_hash,
            predicted_effect_hash=prediction.content_hash,
            connector_revision=prediction.connector_revision,
            before_state=before_state,
            customer_audit_sink_ref=str(registration["customer_audit_sink_ref"]),
            lease_token=lease_token,
            started_at=dispatch_row["dispatched_at"],
            connector_request_id=None,
            connector_returned_at=None,
            trace_id=trace_id,
        )

    def claim_recovery(
        self,
        *,
        scope: Scope,
        action_id: str,
        actuator_id: str,
        owner_identity: str,
        ttl_ms: int,
    ) -> ActuatorDispatch | None:
        if ttl_ms < 1:
            raise ValueError("dispatch TTL must be positive")
        dispatch_token = uuid4()
        reservation_token = uuid4()
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """SELECT a.*, p.policy_version, d.id AS dispatch_id,
                    d.reservation_id AS dispatch_reservation_id,
                    d.status AS dispatch_status,
                    d.lease_token AS dispatch_lease_token,
                    d.lease_expires_at AS dispatch_lease_expires_at,
                    d.dispatch_policy_hash, d.expected_effect_hash,
                    d.connector_revision,
                    d.request_hash, d.mutation_started_at,
                    d.connector_request_id, d.connector_returned_at, d.trace_id,
                    e.id AS effect_receipt_id, e.before_state_ref,
                    e.before_state_hash,
                    e.predicted_effect_hash, e.started_at,
                    ar.customer_audit_sink_ref
                  FROM solvan.actuator_dispatches d
                  JOIN solvan.actuator_effect_receipts e
                    ON e.organization_id = d.organization_id
                   AND e.project_id = d.project_id
                   AND e.environment_id = d.environment_id
                   AND e.dispatch_id = d.id
                  JOIN solvan.actuator_registrations ar
                    ON ar.organization_id = d.organization_id
                   AND ar.project_id = d.project_id
                   AND ar.environment_id = d.environment_id
                   AND ar.id = d.actuator_id
                  JOIN solvan.actions a
                    ON a.organization_id = d.organization_id
                   AND a.project_id = d.project_id
                   AND a.environment_id = d.environment_id
                   AND a.id = d.action_id
                  JOIN solvan.policy_decisions p
                    ON p.organization_id = a.organization_id
                   AND p.project_id = a.project_id
                   AND p.environment_id = a.environment_id
                   AND p.id = a.policy_decision_id
                  WHERE d.organization_id = %(organization_id)s
                    AND d.project_id = %(project_id)s
                    AND d.environment_id = %(environment_id)s
                    AND d.action_id = %(action_id)s
                    AND d.actuator_id = %(actuator_id)s
                    AND d.status IN ('PREPARED','MUTATION_ISSUED','RECONCILING')
                  FOR UPDATE OF d""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "actuator_id": actuator_id,
                },
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                """UPDATE solvan.actuator_dispatches
                  SET lease_owner = %(owner_identity)s,
                      lease_token = %(dispatch_token)s,
                      lease_expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(dispatch_id)s
                    AND lease_token = %(prior_token)s AND lease_expires_at < now()
                    AND status IN ('PREPARED','MUTATION_ISSUED','RECONCILING')
                  RETURNING lease_expires_at""",
                {
                    **scope.canonical_dict(),
                    "owner_identity": owner_identity,
                    "dispatch_token": dispatch_token,
                    "ttl_ms": ttl_ms,
                    "dispatch_id": row["dispatch_id"],
                    "prior_token": row["dispatch_lease_token"],
                },
            )
            claimed = cursor.fetchone()
            if claimed is None:
                raise ReservationConflict("dispatch recovery claim was lost")
            cursor.execute(
                """UPDATE solvan.target_reservations
                  SET owner_identity = %(owner_identity)s,
                      lease_token = %(reservation_token)s,
                      expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(reservation_id)s AND action_id = %(action_id)s
                    AND released_at IS NULL
                  RETURNING target_key, expected_target_epoch, reservation_epoch,
                    expires_at""",
                {
                    **scope.canonical_dict(),
                    "owner_identity": owner_identity,
                    "reservation_token": reservation_token,
                    "ttl_ms": ttl_ms,
                    "reservation_id": row["dispatch_reservation_id"],
                    "action_id": action_id,
                },
            )
            reserved = cursor.fetchone()
            if reserved is None:
                raise ReservationLost("recovery target reservation is not active")
        material = material_from_action(row, scope=scope)
        reservation = TargetReservation(
            reservation_id=str(row["dispatch_reservation_id"]),
            action_id=action_id,
            target_key=str(reserved["target_key"]),
            expected_target_epoch=int(reserved["expected_target_epoch"]),
            reservation_epoch=int(reserved["reservation_epoch"]),
            owner_identity=owner_identity,
            lease_token=reservation_token,
            expires_at=reserved["expires_at"],
        )
        before_state = TargetObservation(
            str(row["before_state_ref"]), material.expected_target_version
        )
        if before_state.content_hash != str(row["before_state_hash"]):
            raise ReservationConflict("dispatch before-state hash drifted")
        expected_request_hash = canonical_json_hash(
            {
                "action_id": action_id,
                "actuator_id": actuator_id,
                "before_state_hash": before_state.content_hash,
                "connector_revision": str(row["connector_revision"]),
                "expected_effect_hash": material.expected_effect_hash,
                "idempotency_key": str(row["idempotency_key"]),
                "predicted_effect_hash": str(row["predicted_effect_hash"]),
                "reservation_id": str(row["dispatch_reservation_id"]),
            }
        )
        if expected_request_hash != str(row["request_hash"]):
            raise ReservationConflict("dispatch request hash drifted")
        return ActuatorDispatch(
            dispatch_id=str(row["dispatch_id"]),
            effect_receipt_id=str(row["effect_receipt_id"]),
            actuator_id=actuator_id,
            reservation=reservation,
            material=material,
            idempotency_key=str(row["idempotency_key"]),
            phase=DispatchPhase(str(row["dispatch_status"])),
            policy_hash=str(row["dispatch_policy_hash"]),
            request_hash=str(row["request_hash"]),
            expected_effect_hash=str(row["expected_effect_hash"]),
            predicted_effect_hash=str(row["predicted_effect_hash"]),
            connector_revision=str(row["connector_revision"]),
            before_state=before_state,
            customer_audit_sink_ref=str(row["customer_audit_sink_ref"]),
            lease_token=dispatch_token,
            started_at=row["mutation_started_at"] or row["started_at"],
            connector_request_id=(
                str(row["connector_request_id"])
                if row["connector_request_id"] is not None
                else None
            ),
            connector_returned_at=row["connector_returned_at"],
            trace_id=str(row["trace_id"]) if row["trace_id"] is not None else None,
        )

    def claim_mutation(
        self, *, scope: Scope, dispatch: ActuatorDispatch, ttl_ms: int
    ) -> ActuatorDispatch:
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """UPDATE solvan.actuator_dispatches
                  SET status = 'MUTATION_ISSUED', mutation_started_at = now(),
                      lease_expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(dispatch_id)s AND status = 'PREPARED'
                    AND lease_token = %(lease_token)s AND lease_expires_at >= now()
                    AND EXISTS (
                      SELECT 1 FROM solvan.actuator_registrations ar
                      WHERE ar.organization_id = actuator_dispatches.organization_id
                        AND ar.project_id = actuator_dispatches.project_id
                        AND ar.environment_id = actuator_dispatches.environment_id
                        AND ar.id = actuator_dispatches.actuator_id
                        AND ar.status = 'ACTIVE' AND ar.posture = 'REMEDIATE'
                        AND ar.production_eligible AND NOT ar.kill_switch_engaged
                        AND ar.policy_hash = actuator_dispatches.dispatch_policy_hash)
                  RETURNING mutation_started_at, lease_expires_at""",
                {
                    **scope.canonical_dict(),
                    "ttl_ms": ttl_ms,
                    "dispatch_id": dispatch.dispatch_id,
                    "lease_token": dispatch.lease_token,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise ReservationLost("prepared mutation claim was lost")
            extend_reservation(cursor, scope, dispatch, ttl_ms)
        return replace(
            dispatch,
            phase=DispatchPhase.MUTATION_ISSUED,
            started_at=row["mutation_started_at"],
            reservation=replace(dispatch.reservation, expires_at=row["lease_expires_at"]),
        )

    def record_connector_ack(
        self,
        *,
        scope: Scope,
        dispatch: ActuatorDispatch,
        connector_request_id: str | None,
        connector_returned_at: Any,
        ttl_ms: int,
    ) -> ActuatorDispatch:
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """UPDATE solvan.actuator_dispatches
                  SET status = 'RECONCILING',
                      connector_request_id = COALESCE(
                        actuator_dispatches.connector_request_id,
                        %(connector_request_id)s),
                      connector_returned_at = COALESCE(
                        actuator_dispatches.connector_returned_at,
                        %(connector_returned_at)s),
                      lease_expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(dispatch_id)s
                    AND status IN ('MUTATION_ISSUED','RECONCILING')
                    AND lease_token = %(lease_token)s AND lease_expires_at >= now()
                  RETURNING connector_request_id, connector_returned_at,
                    lease_expires_at""",
                {
                    **scope.canonical_dict(),
                    "connector_request_id": connector_request_id,
                    "connector_returned_at": connector_returned_at,
                    "ttl_ms": ttl_ms,
                    "dispatch_id": dispatch.dispatch_id,
                    "lease_token": dispatch.lease_token,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise ReservationLost("connector acknowledgement lease was lost")
            extend_reservation(cursor, scope, dispatch, ttl_ms)
        return replace(
            dispatch,
            phase=DispatchPhase.RECONCILING,
            connector_request_id=(
                str(row["connector_request_id"])
                if row["connector_request_id"] is not None
                else None
            ),
            connector_returned_at=row["connector_returned_at"],
            reservation=replace(dispatch.reservation, expires_at=row["lease_expires_at"]),
        )

    def finalize_dispatch(
        self,
        *,
        scope: Scope,
        dispatch: ActuatorDispatch,
        receipt: ExecutionReceiptWrite,
        customer_audit_ref: str,
    ) -> str:
        if receipt.action_id != dispatch.material.action_id:
            raise ValueError("receipt action does not own dispatch")
        if receipt.attempt != 1:
            raise ValueError("dispatch recovery cannot create mutation attempt 2")
        receipt_id = new_identifier("rcp")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan.actuator_dispatches
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(dispatch_id)s AND status = 'RECONCILING'
                    AND lease_token = %(lease_token)s AND lease_expires_at >= now()
                  FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "dispatch_id": dispatch.dispatch_id,
                    "lease_token": dispatch.lease_token,
                },
            )
            if cursor.fetchone() is None:
                raise ReservationLost("dispatch finalization lease was lost")
            insert_execution_receipt(cursor, scope, receipt_id, receipt)
            cursor.execute(
                """UPDATE solvan.actuator_effect_receipts
                  SET execution_receipt_id = %(receipt_id)s,
                      after_state_ref = %(after_state_ref)s,
                      customer_audit_written = true,
                      customer_audit_ref = %(customer_audit_ref)s,
                      completed_at = now(), error_class = %(error_class)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(effect_receipt_id)s
                    AND dispatch_id = %(dispatch_id)s
                    AND execution_receipt_id IS NULL
                  RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "receipt_id": receipt_id,
                    "after_state_ref": receipt.after_state_ref,
                    "customer_audit_ref": customer_audit_ref,
                    "error_class": receipt.error_class,
                    "effect_receipt_id": dispatch.effect_receipt_id,
                    "dispatch_id": dispatch.dispatch_id,
                },
            )
            if cursor.fetchone() is None:
                raise ReservationLost("effect receipt was already finalized")
            terminal = "AMBIGUOUS" if receipt.result is ExecutionResult.AMBIGUOUS else "EXECUTED"
            cursor.execute(
                """UPDATE solvan.actuator_dispatches
                  SET status = %(terminal)s, settled_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(dispatch_id)s AND status = 'RECONCILING'
                    AND lease_token = %(lease_token)s
                  RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "terminal": terminal,
                    "dispatch_id": dispatch.dispatch_id,
                    "lease_token": dispatch.lease_token,
                },
            )
            if cursor.fetchone() is None:
                raise ReservationLost("dispatch settlement claim was lost")
            settle_action(cursor, scope, dispatch, receipt)
        return receipt_id
