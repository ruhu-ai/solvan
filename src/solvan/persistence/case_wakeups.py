"""Recoverable scheduled-wakeup claims for Reliability Cases."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import ClaimedWakeup, ReliabilityCaseConflict
from solvan.domain import Scope, new_identifier
from solvan.persistence.postgres_types import AggregateType, LeaseHandle

# Bounded wakeup claim budget, mirroring the inbox budget in ``claim_sql``. A
# case step that dies on the same permanent fault every claim would otherwise
# be re-served forever, aborting the tick and skipping every later handler. The
# budget is deliberately small because a case wakeup is re-scheduled by its own
# handler: a step that cannot be processed in this many claims is a poison
# step, not a slow one.
WAKEUP_CLAIM_ATTEMPT_BUDGET = 5

_QUARANTINE_WAKEUPS = """
UPDATE solvan.scheduled_wakeups
SET status = 'QUARANTINED', quarantined_at = now(),
    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
WHERE organization_id = %(organization_id)s
  AND project_id = %(project_id)s
  AND environment_id = %(environment_id)s AND wake_at <= now()
  AND attempts >= %(max_attempts)s
  AND (status = 'PENDING'
    OR (status = 'CLAIMED' AND claim_expires_at < now()))
RETURNING id
"""


class ReliabilityCaseWakeupMixin:
    _connection: Connection[Any]

    def claim_due_wakeups(
        self,
        *,
        scope: Scope,
        owner: str,
        claim_ttl_ms: int,
        batch_size: int = 10,
    ) -> tuple[ClaimedWakeup, ...]:
        if claim_ttl_ms < 1 or batch_size < 1:
            raise ValueError("wakeup claim TTL and batch size must be positive")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                _QUARANTINE_WAKEUPS,
                {
                    **scope.canonical_dict(),
                    "max_attempts": WAKEUP_CLAIM_ATTEMPT_BUDGET,
                },
            )
            cursor.execute(
                """WITH candidate AS (
                    SELECT id FROM solvan.scheduled_wakeups
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND wake_at <= now()
                      AND attempts < %(max_attempts)s
                      AND (status = 'PENDING'
                        OR (status = 'CLAIMED' AND claim_expires_at < now()))
                    ORDER BY wake_at, id FOR UPDATE SKIP LOCKED LIMIT %(batch_size)s)
                  UPDATE solvan.scheduled_wakeups w
                  SET status = 'CLAIMED', claimed_at = now(), claim_owner = %(owner)s,
                    claim_token = %(token)s, attempts = w.attempts + 1,
                    claim_expires_at = now() + (%(claim_ttl_ms)s * interval '1 millisecond')
                  FROM candidate
                  WHERE w.organization_id = %(organization_id)s
                    AND w.project_id = %(project_id)s
                    AND w.environment_id = %(environment_id)s AND w.id = candidate.id
                  RETURNING w.id, w.case_id, w.logical_step_key, w.reason,
                    w.wake_at, w.claim_token, w.claim_expires_at""",
                {
                    **scope.canonical_dict(),
                    "owner": owner,
                    "token": token,
                    "claim_ttl_ms": claim_ttl_ms,
                    "batch_size": batch_size,
                    "max_attempts": WAKEUP_CLAIM_ATTEMPT_BUDGET,
                },
            )
            return tuple(
                ClaimedWakeup(
                    wakeup_id=str(row["id"]),
                    case_id=str(row["case_id"]),
                    logical_step_key=str(row["logical_step_key"]),
                    reason=str(row["reason"]),
                    wake_at=row["wake_at"],
                    claim_token=row["claim_token"],
                    claim_expires_at=row["claim_expires_at"],
                )
                for row in cursor.fetchall()
            )

    def release_claimed_wakeup(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedWakeup,
        refund_attempt: bool,
    ) -> None:
        """Hand one live wakeup claim back without completing its step.

        ``refund_attempt`` is for reasons that say nothing about the step: a
        contended case lease, or a state whose provider-specific handler owns
        completion. Those must not walk a healthy case into quarantine. A
        refund only ever undoes the increment made by the claim it is fenced
        to, so the budget can never drift upward.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.scheduled_wakeups w
                  SET status = 'PENDING', claimed_at = NULL, claim_owner = NULL,
                    claim_token = NULL, claim_expires_at = NULL,
                    attempts = CASE WHEN %(refund_attempt)s
                      THEN greatest(w.attempts - 1, 0) ELSE w.attempts END
                  WHERE w.organization_id = %(organization_id)s
                    AND w.project_id = %(project_id)s
                    AND w.environment_id = %(environment_id)s
                    AND w.id = %(wakeup_id)s AND w.status = 'CLAIMED'
                    AND w.claim_owner = %(owner)s AND w.claim_token = %(token)s
                    AND w.claim_expires_at >= now()
                  RETURNING w.id""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": claim.wakeup_id,
                    "owner": owner,
                    "token": claim.claim_token,
                    "refund_attempt": refund_attempt,
                },
            )
            if cursor.fetchone() is None:
                raise ReliabilityCaseConflict("wakeup claim is expired or stale")

    def heartbeat_wakeup(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedWakeup,
        claim_ttl_ms: int,
    ) -> datetime:
        if claim_ttl_ms < 1:
            raise ValueError("wakeup claim TTL must be positive")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.scheduled_wakeups
                  SET claim_expires_at = now() + (%(claim_ttl_ms)s * interval '1 millisecond')
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(wakeup_id)s
                    AND status = 'CLAIMED' AND claim_owner = %(owner)s
                    AND claim_token = %(token)s AND claim_expires_at >= now()
                  RETURNING claim_expires_at""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": claim.wakeup_id,
                    "owner": owner,
                    "token": claim.claim_token,
                    "claim_ttl_ms": claim_ttl_ms,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ReliabilityCaseConflict("wakeup claim is expired or stale")
        expires_at = row[0]
        if not isinstance(expires_at, datetime):  # pragma: no cover - database contract
            raise TypeError("wakeup claim expiry is not a timestamp")
        return expires_at

    def complete_wakeup(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedWakeup,
    ) -> str:
        outbox_id = new_identifier("evt")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key)
                  SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(outbox_id)s, 'RELIABILITY_CASE', c.id, c.workflow_version,
                    'case-wakeups', 'ReliabilityCaseWakeupDue', %(payload)s,
                    %(idempotency_key)s
                  FROM solvan.reliability_cases c
                  JOIN solvan.scheduled_wakeups w ON w.case_id = c.id
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND w.id = %(wakeup_id)s AND w.status = 'CLAIMED'
                    AND w.claim_owner = %(owner)s AND w.claim_token = %(token)s
                    AND w.claim_expires_at >= now()""",
                {
                    **scope.canonical_dict(),
                    "outbox_id": outbox_id,
                    "wakeup_id": claim.wakeup_id,
                    "owner": owner,
                    "token": claim.claim_token,
                    "payload": Jsonb(
                        {
                            "case_id": claim.case_id,
                            "wakeup_id": claim.wakeup_id,
                            "logical_step_key": claim.logical_step_key,
                            "reason": claim.reason,
                        }
                    ),
                    "idempotency_key": f"case-wakeup:{claim.wakeup_id}",
                },
            )
            if cursor.rowcount != 1:
                raise ReliabilityCaseConflict("wakeup claim is expired or stale")
            cursor.execute(
                """UPDATE solvan.scheduled_wakeups SET status = 'COMPLETED',
                    completed_at = now(), outbox_event_id = %(outbox_id)s,
                    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(wakeup_id)s
                    AND status = 'CLAIMED' AND claim_owner = %(owner)s
                    AND claim_token = %(token)s AND claim_expires_at >= now()
                  RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "outbox_id": outbox_id,
                    "wakeup_id": claim.wakeup_id,
                    "owner": owner,
                    "token": claim.claim_token,
                },
            )
            if cursor.fetchone() is None:
                raise ReliabilityCaseConflict("wakeup claim changed before completion")
        return outbox_id

    def complete_active_wakeup_for_transition(self, *, scope: Scope, lease: LeaseHandle) -> str:
        """Retire the case's pending continuation under the case lease.

        Runtime polling happens before due-wakeup claiming. This operation may
        consume a pending or abandoned-expired claim, but never steals a live
        claim from another coordinator.
        """

        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("active case wakeup completion requires a case lease")
        outbox_id = new_identifier("evt")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT w.id, w.logical_step_key FROM solvan.scheduled_wakeups w
                  JOIN solvan.reliability_cases c
                    ON (c.organization_id, c.project_id, c.environment_id, c.id)
                     = (w.organization_id, w.project_id, w.environment_id, w.case_id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()
                    AND (w.status = 'PENDING'
                      OR (w.status = 'CLAIMED' AND w.claim_expires_at < now()))
                  ORDER BY w.wake_at, w.id LIMIT 2 FOR UPDATE OF w""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            rows = cursor.fetchall()
            if len(rows) != 1:
                raise ReliabilityCaseConflict(
                    "case must have exactly one unclaimed active continuation"
                )
            wakeup_id = str(rows[0]["id"])
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(outbox_id)s, 'RELIABILITY_CASE', %(case_id)s,
                    %(workflow_version)s, 'case-wakeups',
                    'ReliabilityCaseRuntimeStepCompleted', %(payload)s,
                    %(idempotency_key)s)""",
                {
                    **scope.canonical_dict(),
                    "outbox_id": outbox_id,
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "payload": Jsonb(
                        {
                            "case_id": lease.entity_id,
                            "wakeup_id": wakeup_id,
                            "logical_step_key": str(rows[0]["logical_step_key"]),
                        }
                    ),
                    "idempotency_key": f"case-runtime-wakeup:{wakeup_id}",
                },
            )
            cursor.execute(
                """UPDATE solvan.scheduled_wakeups SET status = 'COMPLETED',
                    completed_at = now(), outbox_event_id = %(outbox_id)s,
                    claim_owner = NULL, claim_token = NULL, claim_expires_at = NULL
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(wakeup_id)s
                    AND (status = 'PENDING'
                      OR (status = 'CLAIMED' AND claim_expires_at < now()))""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": wakeup_id,
                    "outbox_id": outbox_id,
                },
            )
            if cursor.rowcount != 1:
                raise ReliabilityCaseConflict("case continuation changed before completion")
        return wakeup_id

    def defer_claimed_wakeup(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedWakeup,
        wake_at: datetime,
        reason: str,
    ) -> str:
        """Replace one due claimed continuation without changing case state.

        This is the bounded polling primitive for a recoverable BLOCKED case.
        It records the due event through ``complete_wakeup`` and installs exactly
        one future continuation in the same transaction.
        """

        if wake_at <= datetime.now(wake_at.tzinfo):
            raise ValueError("deferred wakeup must be in the future")
        self.complete_wakeup(scope=scope, owner=owner, claim=claim)
        wakeup_id = new_identifier("wak")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(wakeup_id)s, c.id, %(logical_step_key)s, %(wake_at)s, %(reason)s
                  FROM solvan.reliability_cases c
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'BLOCKED'
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.scheduled_wakeups w
                      WHERE w.organization_id = c.organization_id
                        AND w.project_id = c.project_id
                        AND w.environment_id = c.environment_id
                        AND w.case_id = c.id AND w.status IN ('PENDING','CLAIMED'))""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": wakeup_id,
                    "case_id": claim.case_id,
                    "logical_step_key": claim.logical_step_key,
                    "wake_at": wake_at,
                    "reason": reason,
                },
            )
            if cursor.rowcount != 1:
                raise ReliabilityCaseConflict(
                    "blocked case changed before continuation was deferred"
                )
            cursor.execute(
                """UPDATE solvan.reliability_cases
                  SET next_action_at = %(wake_at)s, last_progress_at = now(),
                      updated_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(case_id)s AND state = 'BLOCKED'""",
                {**scope.canonical_dict(), "case_id": claim.case_id, "wake_at": wake_at},
            )
        return wakeup_id
