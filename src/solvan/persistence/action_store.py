"""Target-epoch reservation and execution-receipt persistence."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row

from solvan.application.actions import (
    ApprovalAuthority,
    ExecutionAuthorization,
    StandingAuthority,
    authorize_approved_action,
    authorize_standing_action,
)
from solvan.application.actuator import (
    ActuatorDispatch,
    ExecutionReceiptWrite,
    ExecutionResult,
    ReservationConflict,
    ReservationLost,
    TargetReservation,
)
from solvan.domain import (
    ActionPolicyError,
    ActionType,
    ApprovalDecision,
    ApprovalRecord,
    ExecutionAuthoritySnapshot,
    PreauthorizationContext,
    PreauthorizationStatus,
    RiskClass,
    Scope,
    StandingPreauthorization,
    freeze_json,
    new_identifier,
)
from solvan.persistence.action_invocation import ActionInvocationMixin
from solvan.persistence.action_material import material_from_action
from solvan.persistence.action_release import ActionReservationReleaseMixin
from solvan.persistence.actuator_dispatch_store import ActuatorDispatchMixin


class PostgresActionStore(
    ActionInvocationMixin, ActionReservationReleaseMixin, ActuatorDispatchMixin
):
    """Serialize mutations by scoped target key and monotonically increasing epoch."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def acquire_reservation(
        self,
        *,
        scope: Scope,
        action_id: str,
        owner_identity: str,
        ttl_ms: int,
    ) -> TargetReservation:
        if ttl_ms < 1:
            raise ValueError("reservation TTL must be positive")
        reservation_id = new_identifier("rsv")
        lease_token = uuid4()
        conflict_reason: str | None = None
        reservation: dict[str, Any] | None = None
        try:
            with (
                self._connection.transaction(),
                self._connection.cursor(row_factory=dict_row) as cursor,
            ):
                cursor.execute(
                    """SELECT target_key, expected_target_epoch,
                        expected_target_version, status, expires_at
                      FROM solvan.actions
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(action_id)s
                        AND expires_at > now()
                      FOR UPDATE""",
                    {**scope.canonical_dict(), "action_id": action_id},
                )
                action = cursor.fetchone()
                if action is None:
                    raise ReservationConflict("authorized action does not exist")
                if action["status"] != "AUTHORIZED":
                    raise ReservationConflict("action is not authorized")
                target_key = str(action["target_key"])
                expected_target_epoch = int(action["expected_target_epoch"])
                expected_target_version = str(action["expected_target_version"])
                cursor.execute(
                    """SELECT epoch, last_observed_version
                      FROM solvan.target_epochs
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND target_key = %(target_key)s
                      FOR UPDATE""",
                    {**scope.canonical_dict(), "target_key": target_key},
                )
                target = cursor.fetchone()
                if target is None:
                    raise ReservationConflict("target epoch is not registered")
                if target["epoch"] != expected_target_epoch:
                    conflict_reason = "target epoch changed"
                elif target["last_observed_version"] != expected_target_version:
                    conflict_reason = "target version changed"
                if conflict_reason is not None:
                    cursor.execute(
                        """UPDATE solvan.actions SET status = 'INVALIDATED'
                          WHERE organization_id = %(organization_id)s
                            AND project_id = %(project_id)s
                            AND environment_id = %(environment_id)s
                            AND id = %(action_id)s AND status = 'AUTHORIZED'""",
                        {**scope.canonical_dict(), "action_id": action_id},
                    )
                else:
                    cursor.execute(
                        """INSERT INTO solvan.target_reservations
                          (organization_id, project_id, environment_id, id,
                           target_key, reservation_epoch, expected_target_epoch,
                           action_id, owner_identity, lease_token, expires_at)
                          VALUES (%(organization_id)s, %(project_id)s,
                            %(environment_id)s, %(reservation_id)s, %(target_key)s,
                            %(reservation_epoch)s, %(expected_target_epoch)s,
                            %(action_id)s, %(owner_identity)s, %(lease_token)s,
                            now() + (%(ttl_ms)s * interval '1 millisecond'))
                          RETURNING expires_at""",
                        {
                            **scope.canonical_dict(),
                            "reservation_id": reservation_id,
                            "target_key": target_key,
                            "reservation_epoch": expected_target_epoch + 1,
                            "expected_target_epoch": expected_target_epoch,
                            "action_id": action_id,
                            "owner_identity": owner_identity,
                            "lease_token": lease_token,
                            "ttl_ms": ttl_ms,
                        },
                    )
                    reservation = cursor.fetchone()
                    if reservation is None:  # pragma: no cover - INSERT always returns
                        raise RuntimeError("reservation insert returned no row")
                    cursor.execute(
                        """UPDATE solvan.target_epochs
                          SET epoch = epoch + 1, updated_at = now()
                          WHERE organization_id = %(organization_id)s
                            AND project_id = %(project_id)s
                            AND environment_id = %(environment_id)s
                            AND target_key = %(target_key)s
                            AND epoch = %(expected_target_epoch)s
                            AND last_observed_version = %(expected_target_version)s
                          RETURNING epoch""",
                        {
                            **scope.canonical_dict(),
                            "target_key": target_key,
                            "expected_target_epoch": expected_target_epoch,
                            "expected_target_version": expected_target_version,
                        },
                    )
                    advanced = cursor.fetchone()
                    if advanced is None:  # protected by FOR UPDATE; defensive only
                        raise ReservationConflict("target changed during reservation")
        except UniqueViolation as error:
            raise ReservationConflict("target already has an active reservation") from error
        if conflict_reason is not None:
            raise ReservationConflict(conflict_reason)
        assert reservation is not None  # successful INSERT always returns
        return TargetReservation(
            reservation_id=reservation_id,
            action_id=action_id,
            target_key=target_key,
            expected_target_epoch=expected_target_epoch,
            reservation_epoch=expected_target_epoch + 1,
            owner_identity=owner_identity,
            lease_token=lease_token,
            expires_at=reservation["expires_at"],
        )

    def heartbeat(self, *, scope: Scope, reservation: TargetReservation, ttl_ms: int) -> datetime:
        if ttl_ms < 1:
            raise ValueError("reservation TTL must be positive")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.target_reservations
                  SET expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(reservation_id)s
                    AND owner_identity = %(owner_identity)s
                    AND lease_token = %(lease_token)s
                    AND released_at IS NULL AND expires_at >= now()
                  RETURNING expires_at""",
                {
                    **scope.canonical_dict(),
                    "reservation_id": reservation.reservation_id,
                    "owner_identity": reservation.owner_identity,
                    "lease_token": reservation.lease_token,
                    "ttl_ms": ttl_ms,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ReservationLost("reservation is expired, released, or no longer owned")
        expires_at = row[0]
        if not isinstance(expires_at, datetime):  # pragma: no cover - database contract
            raise TypeError("reservation expiry is not a timestamp")
        return expires_at

    def _load_approval_authority(
        self,
        *,
        scope: Scope,
        reservation: TargetReservation,
        action_status: str = "AUTHORIZED",
    ) -> ExecutionAuthorization:
        """Load all live authorization inputs using database time and locked policy rows."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.*, p.policy_version,
                    COALESCE(i.workflow_version, c.workflow_version) AS current_workflow_version,
                    COALESCE(i.evidence_version, c.evidence_version) AS current_evidence_version,
                    i.primary_service_id AS current_service_id,
                    i.incident_class AS current_incident_class,
                    i.action_attempt_count, i.cooldown_until,
                    t.epoch AS current_target_epoch,
                    t.last_observed_version AS current_target_version,
                    r.expected_target_epoch AS reservation_expected_target_epoch,
                    r.reservation_epoch, now() AS database_now
                  FROM solvan.actions a
                  JOIN solvan.policy_decisions p
                    ON p.organization_id = a.organization_id
                   AND p.project_id = a.project_id
                   AND p.environment_id = a.environment_id
                   AND p.id = a.policy_decision_id
                  LEFT JOIN solvan.incidents i
                    ON i.organization_id = a.organization_id
                   AND i.project_id = a.project_id
                   AND i.environment_id = a.environment_id
                   AND i.id = a.incident_id
                  LEFT JOIN solvan.reliability_cases c
                    ON c.organization_id = a.organization_id
                   AND c.project_id = a.project_id
                   AND c.environment_id = a.environment_id
                   AND c.id = a.reliability_case_id
                  JOIN solvan.target_epochs t
                    ON t.organization_id = a.organization_id
                   AND t.project_id = a.project_id
                   AND t.environment_id = a.environment_id
                   AND t.target_key = a.target_key
                  JOIN solvan.target_reservations r
                    ON r.organization_id = a.organization_id
                   AND r.project_id = a.project_id
                   AND r.environment_id = a.environment_id
                   AND r.action_id = a.id
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.id = %(action_id)s AND a.status = %(action_status)s
                    AND a.expires_at > now()
                    AND r.id = %(reservation_id)s
                    AND r.owner_identity = %(owner_identity)s
                    AND r.lease_token = %(lease_token)s
                    AND r.released_at IS NULL AND r.expires_at >= now()
                  FOR UPDATE OF a, p, r""",
                {
                    **scope.canonical_dict(),
                    "action_id": reservation.action_id,
                    "reservation_id": reservation.reservation_id,
                    "action_status": action_status,
                    "owner_identity": reservation.owner_identity,
                    "lease_token": reservation.lease_token,
                },
            )
            action = cursor.fetchone()
            if action is None:
                raise ReservationLost("authorized action or live reservation is unavailable")
            material = material_from_action(action, scope)
            if not action["requires_approval"]:
                cursor.execute(
                    """SELECT * FROM solvan.standing_preauthorizations
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(preauthorization_id)s
                        AND version = %(preauthorization_version)s
                      FOR UPDATE""",
                    {
                        **scope.canonical_dict(),
                        "preauthorization_id": action["standing_preauthorization_id"],
                        "preauthorization_version": action["standing_preauthorization_version"],
                    },
                )
                standing = cursor.fetchone()
                if standing is None:
                    raise ActionPolicyError("standing_preauthorization_missing")
                return StandingAuthority(
                    material=material,
                    authority=StandingPreauthorization(
                        preauthorization_id=standing["id"],
                        version=standing["version"],
                        status=PreauthorizationStatus(standing["status"]),
                        action_type=ActionType(standing["action_type"]),
                        service_id=standing["service_id"],
                        incident_class=standing["incident_class"],
                        maximum_risk_class=RiskClass(standing["maximum_risk_class"]),
                        payload_constraints=freeze_json(dict(standing["payload_constraints_json"])),
                        maximum_attempts=standing["maximum_attempts"],
                        cooldown_ms=standing["cooldown_ms"],
                        valid_from=standing["valid_from"],
                        valid_until=standing["valid_until"],
                    ),
                    context=PreauthorizationContext(
                        service_id=action["current_service_id"],
                        incident_class=action["current_incident_class"],
                        action_attempt_count=action["action_attempt_count"],
                        cooldown_until=action["cooldown_until"],
                        now=action["database_now"],
                    ),
                    execution=ExecutionAuthoritySnapshot(
                        now=action["database_now"],
                        workflow_version=action["current_workflow_version"],
                        evidence_version=action["current_evidence_version"],
                        target_version=action["current_target_version"],
                        target_epoch=action["current_target_epoch"],
                        reservation_expected_target_epoch=action[
                            "reservation_expected_target_epoch"
                        ],
                        reservation_epoch=action["reservation_epoch"],
                        policy_version=action["policy_version"],
                        approver_role_active=False,
                        reservation_action_id=reservation.action_id,
                    ),
                    idempotency_key=action["idempotency_key"],
                )
            cursor.execute(
                """SELECT a.* FROM solvan.approvals a
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.action_id = %(action_id)s
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.approvals successor
                      WHERE successor.organization_id = a.organization_id
                        AND successor.project_id = a.project_id
                        AND successor.environment_id = a.environment_id
                        AND successor.supersedes_id = a.id)
                  FOR UPDATE""",
                {**scope.canonical_dict(), "action_id": reservation.action_id},
            )
            approval = cursor.fetchone()
            if approval is None:
                raise ActionPolicyError("exact_approval_missing")
            cursor.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND principal = %(principal)s AND role = 'APPROVER'
                      AND (expires_at IS NULL OR expires_at > now())
                  ) AS active""",
                {
                    **scope.canonical_dict(),
                    "principal": approval["approver_principal"],
                },
            )
            role = cursor.fetchone()
        approval_record = ApprovalRecord(
            action_id=approval["action_id"],
            action_digest=approval["action_digest"],
            target_key=approval["target_key"],
            expected_target_version=approval["expected_target_version"],
            expected_target_epoch=approval["expected_target_epoch"],
            evidence_version=approval["evidence_version"],
            policy_version=approval["policy_version"],
            approver_principal=approval["approver_principal"],
            decision=ApprovalDecision(approval["decision"]),
            decided_at=approval["decided_at"],
            expires_at=approval["expires_at"],
        )
        return ApprovalAuthority(
            material=material,
            approval=approval_record,
            execution=ExecutionAuthoritySnapshot(
                now=action["database_now"],
                workflow_version=action["current_workflow_version"],
                evidence_version=action["current_evidence_version"],
                target_version=action["current_target_version"],
                target_epoch=action["current_target_epoch"],
                reservation_expected_target_epoch=action["reservation_expected_target_epoch"],
                reservation_epoch=action["reservation_epoch"],
                policy_version=action["policy_version"],
                approver_role_active=bool(role and role["active"]),
                reservation_action_id=reservation.action_id,
            ),
            proposer_principal=action["proposer_principal"],
            idempotency_key=action["idempotency_key"],
        )

    def authorize_for_execution(
        self, *, scope: Scope, reservation: TargetReservation
    ) -> ExecutionAuthorization:
        """Validate and claim execution while approval/policy/action rows remain locked."""

        with self._connection.transaction():
            authority = self._load_approval_authority(scope=scope, reservation=reservation)
            if isinstance(authority, ApprovalAuthority):
                authorize_approved_action(authority)
            else:
                authorize_standing_action(authority)
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE solvan.actions SET status = 'EXECUTING'
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(action_id)s AND status = 'AUTHORIZED'
                      RETURNING id""",
                    {**scope.canonical_dict(), "action_id": reservation.action_id},
                )
                if cursor.fetchone() is None:
                    raise ActionPolicyError("action_execution_claim_lost")
        return authority

    def authorize_prepared_dispatch(
        self, *, scope: Scope, dispatch: ActuatorDispatch
    ) -> ExecutionAuthorization:
        """Revalidate a prepared, never-issued dispatch without creating attempt 2."""

        with self._connection.transaction():
            authority = self._load_approval_authority(
                scope=scope,
                reservation=dispatch.reservation,
                action_status="EXECUTING",
            )
            if isinstance(authority, ApprovalAuthority):
                authorize_approved_action(authority)
            else:
                authorize_standing_action(authority)
        return authority

    def record_execution(
        self,
        *,
        scope: Scope,
        reservation: TargetReservation,
        receipt: ExecutionReceiptWrite,
    ) -> str:
        """Append a receipt; conclusive results release, ambiguity remains exclusive."""

        if receipt.action_id != reservation.action_id:
            raise ValueError("receipt action does not own reservation")
        if receipt.attempt != 1:
            raise ValueError("one authorized action permits exactly one mutation attempt")
        receipt_id = new_identifier("rcp")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan.target_reservations
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(reservation_id)s AND action_id = %(action_id)s
                    AND owner_identity = %(owner_identity)s
                    AND lease_token = %(lease_token)s AND released_at IS NULL
                  FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "reservation_id": reservation.reservation_id,
                    "action_id": reservation.action_id,
                    "owner_identity": reservation.owner_identity,
                    "lease_token": reservation.lease_token,
                },
            )
            if cursor.fetchone() is None:
                raise ReservationLost("reservation is released or no longer owned")
            cursor.execute(
                """INSERT INTO solvan.execution_receipts
                  (organization_id, project_id, environment_id, id, action_id,
                   attempt, connector_request_id, idempotency_key,
                   before_state_ref, after_state_ref, observed_target_version,
                   started_at, connector_returned_at, reconciled_at, result,
                   error_class, actor_identity, trace_id)
                  VALUES (%(organization_id)s, %(project_id)s,
                    %(environment_id)s, %(receipt_id)s, %(action_id)s,
                    %(attempt)s, %(connector_request_id)s, %(idempotency_key)s,
                    %(before_state_ref)s, %(after_state_ref)s,
                    %(observed_target_version)s, %(started_at)s,
                    %(connector_returned_at)s, %(reconciled_at)s, %(result)s,
                    %(error_class)s, %(actor_identity)s, %(trace_id)s)""",
                {
                    **scope.canonical_dict(),
                    "receipt_id": receipt_id,
                    **asdict(receipt),
                    "result": receipt.result.value,
                },
            )
            action_status = {
                ExecutionResult.SUCCEEDED: "SUCCEEDED",
                ExecutionResult.FAILED: "FAILED",
                ExecutionResult.AMBIGUOUS: "AMBIGUOUS",
            }[receipt.result]
            cursor.execute(
                """UPDATE solvan.actions SET status = %(status)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(action_id)s""",
                {
                    **scope.canonical_dict(),
                    "action_id": receipt.action_id,
                    "status": action_status,
                },
            )
            cursor.execute(
                """UPDATE solvan.incidents i
                  SET action_attempt_count = i.action_attempt_count + 1,
                      cooldown_until = CASE
                        WHEN sp.cooldown_ms IS NULL THEN i.cooldown_until
                        ELSE GREATEST(
                          COALESCE(i.cooldown_until, now()),
                          now() + (sp.cooldown_ms * interval '1 millisecond'))
                      END,
                      last_action_signature = a.normalized_signature,
                      updated_at = now()
                  FROM solvan.actions a
                  LEFT JOIN solvan.standing_preauthorizations sp
                    ON sp.organization_id = a.organization_id
                   AND sp.project_id = a.project_id
                   AND sp.environment_id = a.environment_id
                   AND sp.id = a.standing_preauthorization_id
                   AND sp.version = a.standing_preauthorization_version
                  WHERE i.organization_id = %(organization_id)s
                    AND i.project_id = %(project_id)s
                    AND i.environment_id = %(environment_id)s
                    AND a.organization_id = i.organization_id
                    AND a.project_id = i.project_id
                    AND a.environment_id = i.environment_id
                    AND a.id = %(action_id)s AND i.id = a.incident_id""",
                {**scope.canonical_dict(), "action_id": receipt.action_id},
            )
            if receipt.result is not ExecutionResult.AMBIGUOUS:
                cursor.execute(
                    """UPDATE solvan.target_reservations
                      SET released_at = now(), release_reason = %(release_reason)s
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(reservation_id)s
                        AND lease_token = %(lease_token)s AND released_at IS NULL
                      RETURNING id""",
                    {
                        **scope.canonical_dict(),
                        "reservation_id": reservation.reservation_id,
                        "lease_token": reservation.lease_token,
                        "release_reason": f"EXECUTION_{receipt.result.value}",
                    },
                )
                if cursor.fetchone() is None:
                    raise ReservationLost("reservation was lost before release")
                if receipt.observed_target_version is not None:
                    cursor.execute(
                        """UPDATE solvan.target_epochs
                          SET last_observed_version = %(observed_target_version)s,
                              updated_at = now()
                          WHERE organization_id = %(organization_id)s
                            AND project_id = %(project_id)s
                            AND environment_id = %(environment_id)s
                            AND target_key = %(target_key)s
                            AND epoch = %(reservation_epoch)s""",
                        {
                            **scope.canonical_dict(),
                            "observed_target_version": receipt.observed_target_version,
                            "target_key": reservation.target_key,
                            "reservation_epoch": reservation.reservation_epoch,
                        },
                    )
        return receipt_id
