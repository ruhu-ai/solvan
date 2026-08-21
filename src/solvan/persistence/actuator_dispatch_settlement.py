"""Focused SQL helpers for actuator receipt and target settlement."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from solvan.application.actuator import (
    ActuatorDispatch,
    ExecutionReceiptWrite,
    ExecutionResult,
    ReservationLost,
)
from solvan.domain import Scope


def insert_execution_receipt(
    cursor: Any,
    scope: Scope,
    receipt_id: str,
    receipt: ExecutionReceiptWrite,
) -> None:
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


def settle_action(
    cursor: Any,
    scope: Scope,
    dispatch: ActuatorDispatch,
    receipt: ExecutionReceiptWrite,
) -> None:
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
            AND id = %(action_id)s AND status = 'EXECUTING'""",
        {**scope.canonical_dict(), "action_id": receipt.action_id, "status": action_status},
    )
    cursor.execute(
        """UPDATE solvan.incidents i
          SET action_attempt_count = i.action_attempt_count + 1,
              cooldown_until = CASE
                WHEN sp.cooldown_ms IS NULL THEN i.cooldown_until
                ELSE GREATEST(COALESCE(i.cooldown_until, now()),
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
    if receipt.result is ExecutionResult.AMBIGUOUS:
        return
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
            "reservation_id": dispatch.reservation.reservation_id,
            "lease_token": dispatch.reservation.lease_token,
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
                "target_key": dispatch.reservation.target_key,
                "reservation_epoch": dispatch.reservation.reservation_epoch,
            },
        )


def extend_reservation(
    cursor: Any,
    scope: Scope,
    dispatch: ActuatorDispatch,
    ttl_ms: int,
) -> None:
    cursor.execute(
        """UPDATE solvan.target_reservations
          SET expires_at = now() + (%(ttl_ms)s * interval '1 millisecond')
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND id = %(reservation_id)s
            AND lease_token = %(reservation_lease_token)s
            AND released_at IS NULL
          RETURNING id""",
        {
            **scope.canonical_dict(),
            "ttl_ms": ttl_ms,
            "reservation_id": dispatch.reservation.reservation_id,
            "reservation_lease_token": dispatch.reservation.lease_token,
        },
    )
    if cursor.fetchone() is None:
        raise ReservationLost("target reservation lease was lost")
