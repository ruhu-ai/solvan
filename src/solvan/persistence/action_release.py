"""No-mutation target-reservation release transitions."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.application.actuator import ReservationLost, TargetReservation
from solvan.domain import Scope


class ActionReservationReleaseMixin:
    _connection: Connection[Any]

    def release_before_mutation(
        self, *, scope: Scope, reservation: TargetReservation, reason: str
    ) -> None:
        """Release only when no connector attempt or receipt exists."""

        if reason not in {
            "AUTHORIZATION_FAILED",
            "DRY_RUN_MISMATCH",
            "PRECONDITION_FAILED",
        }:
            raise ValueError("unsupported no-mutation release reason")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.target_reservations r
                  SET released_at = now(), release_reason = %(reason)s
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.id = %(reservation_id)s
                    AND r.action_id = %(action_id)s
                    AND r.lease_token = %(lease_token)s
                    AND r.released_at IS NULL
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.execution_receipts e
                      WHERE e.organization_id = r.organization_id
                        AND e.project_id = r.project_id
                        AND e.environment_id = r.environment_id
                        AND e.action_id = r.action_id)
                  RETURNING r.id""",
                {
                    **scope.canonical_dict(),
                    "reason": reason,
                    "reservation_id": reservation.reservation_id,
                    "action_id": reservation.action_id,
                    "lease_token": reservation.lease_token,
                },
            )
            if cursor.fetchone() is None:
                raise ReservationLost("reservation cannot be released as no-mutation")
            action_status = "DRY_RUN_MISMATCH" if reason == "DRY_RUN_MISMATCH" else "INVALIDATED"
            cursor.execute(
                """UPDATE solvan.actions SET status = %(action_status)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(action_id)s AND status IN ('AUTHORIZED','EXECUTING')""",
                {
                    **scope.canonical_dict(),
                    "action_id": reservation.action_id,
                    "action_status": action_status,
                },
            )
