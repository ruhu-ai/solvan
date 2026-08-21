"""Atomic Reliability Case opening and recoverable due-wakeup claims."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import (
    CaseSchedule,
    ClaimedWakeup,
    CoordinatorAuthority,
    ReliabilityCaseConflict,
    ReliabilityCaseRecord,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.case_wakeups import ReliabilityCaseWakeupMixin
from solvan.persistence.postgres_types import AggregateType, LeaseHandle, TransitionWrite


class PostgresReliabilityCaseStore(ReliabilityCaseWakeupMixin):
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._connection.transaction():
            yield

    def mitigated_incidents_without_case(
        self, *, scope: Scope, batch_size: int = 10
    ) -> tuple[str, ...]:
        """Return only incidents that still require a durable repair owner."""

        if batch_size < 1:
            raise ValueError("case opening batch size must be positive")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan.incidents
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND state = 'MITIGATED' AND reliability_case_id IS NULL
                  ORDER BY detected_at, id LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def claimed_case_state(
        self, *, scope: Scope, owner: str, claim: ClaimedWakeup
    ) -> tuple[str, int, str | None]:
        """Resolve the authoritative case step under the exact wakeup claim."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT c.state, c.workflow_version, c.next_action_kind
                  FROM solvan.reliability_cases c
                  JOIN solvan.scheduled_wakeups w
                    ON (w.organization_id, w.project_id, w.environment_id, w.case_id)
                     = (c.organization_id, c.project_id, c.environment_id, c.id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND w.id = %(wakeup_id)s
                    AND w.status = 'CLAIMED' AND w.claim_owner = %(owner)s
                    AND w.claim_token = %(token)s AND w.claim_expires_at >= now()""",
                {
                    **scope.canonical_dict(),
                    "case_id": claim.case_id,
                    "wakeup_id": claim.wakeup_id,
                    "owner": owner,
                    "token": claim.claim_token,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ReliabilityCaseConflict("wakeup claim is expired or stale")
        return str(row[0]), int(row[1]), None if row[2] is None else str(row[2])

    def open_for_mitigated_incident(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        schedule: CaseSchedule,
    ) -> ReliabilityCaseRecord:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT reliability_case_id FROM solvan.incidents
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(incident_id)s AND state = 'MITIGATED'
                    AND workflow_version = %(workflow_version)s
                    AND lease_owner = %(lease_owner)s
                    AND lease_token = %(lease_token)s
                    AND lease_expires_at >= now() FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "workflow_version": authority.workflow_version,
                    "lease_owner": authority.owner,
                    "lease_token": authority.lease_token,
                },
            )
            incident = cursor.fetchone()
            if incident is None:
                raise ReliabilityCaseConflict(
                    "incident is not mitigated or coordinator authority is stale"
                )
            existing_id = incident["reliability_case_id"]
            if existing_id is not None:
                return self._load_existing(cursor, scope, str(existing_id))
            cursor.execute(
                """INSERT INTO solvan.display_sequences
                  (organization_id, project_id, environment_id, entity_type, next_value)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s, 'REL', 2)
                  ON CONFLICT (organization_id, project_id, environment_id, entity_type)
                  DO UPDATE SET next_value = solvan.display_sequences.next_value + 1
                  RETURNING next_value - 1 AS allocated""",
                scope.canonical_dict(),
            )
            sequence = cursor.fetchone()
            if sequence is None:  # pragma: no cover - INSERT always returns
                raise RuntimeError("Reliability Case display sequence allocation failed")
            case_id = new_identifier("rel")
            wakeup_id = new_identifier("wak")
            display_id = f"REL-{int(sequence['allocated']):04d}"
            cursor.execute(
                """INSERT INTO solvan.reliability_cases
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, originating_incident_id,
                   next_action_kind, next_action_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(case_id)s, %(display_id)s, '1', 'OPEN', %(incident_id)s,
                    %(next_action_kind)s, %(wake_at)s)""",
                {
                    **scope.canonical_dict(),
                    "case_id": case_id,
                    "display_id": display_id,
                    "incident_id": incident_id,
                    "next_action_kind": schedule.next_action_kind,
                    "wake_at": schedule.wake_at,
                },
            )
            cursor.execute(
                """UPDATE solvan.incidents SET reliability_case_id = %(case_id)s,
                    updated_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(incident_id)s AND reliability_case_id IS NULL""",
                {**scope.canonical_dict(), "incident_id": incident_id, "case_id": case_id},
            )
            cursor.execute(
                """INSERT INTO solvan.case_incidents
                  (organization_id, project_id, environment_id, case_id,
                   incident_id, relationship)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(case_id)s, %(incident_id)s, 'ORIGINATING')""",
                {**scope.canonical_dict(), "incident_id": incident_id, "case_id": case_id},
            )
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(wakeup_id)s, %(case_id)s, %(logical_step_key)s,
                    %(wake_at)s, %(reason)s)""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": wakeup_id,
                    "case_id": case_id,
                    "logical_step_key": schedule.logical_step_key,
                    "wake_at": schedule.wake_at,
                    "reason": schedule.reason,
                },
            )
            self._append_case_outbox(
                cursor,
                scope,
                case_id=case_id,
                incident_id=incident_id,
                wakeup_id=wakeup_id,
                display_id=display_id,
            )
        return ReliabilityCaseRecord(case_id, display_id, 1, wakeup_id, True)

    def commit_progress_transition(
        self,
        *,
        scope: Scope,
        lease: LeaseHandle,
        transition: TransitionWrite,
        schedule: CaseSchedule,
        blocked_owner: str | None = None,
        next_review_at: datetime | None = None,
        recovery_plan: str | None = None,
    ) -> tuple[int, str]:
        """Advance one case and install its next durable wakeup atomically."""

        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("case transition requires a Reliability Case lease")
        blocked_values = (blocked_owner, next_review_at, recovery_plan)
        if transition.to_state == "BLOCKED":
            if any(value is None for value in blocked_values):
                raise ValueError("BLOCKED requires owner, review time, and recovery plan")
        elif any(value is not None for value in blocked_values):
            raise ValueError("blocked recovery fields are only valid for BLOCKED")
        wakeup_id = new_identifier("wak")
        transition_id = new_identifier("trn")
        outbox_id = new_identifier("evt")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.reliability_cases
                  SET state = %(to_state)s, workflow_version = workflow_version + 1,
                    next_action_kind = %(next_action_kind)s,
                    next_action_at = %(next_action_at)s,
                    blocked_owner = %(blocked_owner)s,
                    next_review_at = %(next_review_at)s,
                    recovery_plan = %(recovery_plan)s,
                    last_progress_at = now(), updated_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(case_id)s
                    AND state = %(from_state)s
                    AND workflow_version = %(workflow_version)s
                    AND lease_owner = %(lease_owner)s AND lease_token = %(lease_token)s
                    AND lease_expires_at >= now() RETURNING workflow_version""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "from_state": transition.from_state,
                    "to_state": transition.to_state,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                    "next_action_kind": schedule.next_action_kind,
                    "next_action_at": schedule.wake_at,
                    "blocked_owner": blocked_owner,
                    "next_review_at": next_review_at,
                    "recovery_plan": recovery_plan,
                },
            )
            version_row = cursor.fetchone()
            if version_row is None:
                raise ReliabilityCaseConflict("case workflow version or lease is stale")
            to_version = int(version_row[0])
            cursor.execute(
                """SELECT count(*) FROM solvan.scheduled_wakeups
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND case_id = %(case_id)s
                    AND status IN ('PENDING','CLAIMED')""",
                {**scope.canonical_dict(), "case_id": lease.entity_id},
            )
            active_count = cursor.fetchone()
            if active_count is None:  # pragma: no cover - aggregate always returns
                raise RuntimeError("active wakeup count returned no row")
            if active_count[0] != 0:
                raise ReliabilityCaseConflict(
                    "case already has an active continuation before transition"
                )
            cursor.execute(
                """INSERT INTO solvan.state_transitions
                  (organization_id, project_id, environment_id, id, entity_type,
                   entity_id, from_state, to_state, from_workflow_version,
                   to_workflow_version, transition_key, actor_type, actor_id,
                   policy_decision_id, reason_code, rationale_summary,
                   evidence_refs_json, trace_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(transition_id)s, 'RELIABILITY_CASE', %(case_id)s,
                    %(from_state)s, %(to_state)s, %(from_version)s, %(to_version)s,
                    %(transition_key)s, %(actor_type)s, %(actor_id)s,
                    %(policy_decision_id)s, %(reason_code)s, %(rationale_summary)s,
                    %(evidence_refs)s, %(trace_id)s)""",
                {
                    **scope.canonical_dict(),
                    "transition_id": transition_id,
                    "case_id": lease.entity_id,
                    "from_state": transition.from_state,
                    "to_state": transition.to_state,
                    "from_version": lease.workflow_version,
                    "to_version": to_version,
                    "transition_key": transition.transition_key,
                    "actor_type": transition.actor_type,
                    "actor_id": transition.actor_id,
                    "policy_decision_id": transition.policy_decision_id,
                    "reason_code": transition.reason_code,
                    "rationale_summary": transition.rationale_summary,
                    "evidence_refs": Jsonb(list(transition.evidence_refs)),
                    "trace_id": transition.trace_id,
                },
            )
            cursor.execute(
                """INSERT INTO solvan.scheduled_wakeups
                  (organization_id, project_id, environment_id, id, case_id,
                   logical_step_key, wake_at, reason)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(wakeup_id)s, %(case_id)s, %(logical_step_key)s,
                    %(wake_at)s, %(reason)s)""",
                {
                    **scope.canonical_dict(),
                    "wakeup_id": wakeup_id,
                    "case_id": lease.entity_id,
                    "logical_step_key": schedule.logical_step_key,
                    "wake_at": schedule.wake_at,
                    "reason": schedule.reason,
                },
            )
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(outbox_id)s, 'RELIABILITY_CASE', %(case_id)s, %(to_version)s,
                    'workflow-transitions', 'ReliabilityCaseTransitioned', %(payload)s,
                    %(idempotency_key)s)""",
                {
                    **scope.canonical_dict(),
                    "outbox_id": outbox_id,
                    "case_id": lease.entity_id,
                    "to_version": to_version,
                    "payload": Jsonb(
                        {
                            "case_id": lease.entity_id,
                            "from_state": transition.from_state,
                            "to_state": transition.to_state,
                            "workflow_version": to_version,
                            "wakeup_id": wakeup_id,
                        }
                    ),
                    "idempotency_key": (
                        f"case-transition:{lease.entity_id}:{transition.transition_key}"
                    ),
                },
            )
        return to_version, wakeup_id

    @staticmethod
    def _load_existing(cursor: Any, scope: Scope, case_id: str) -> ReliabilityCaseRecord:
        cursor.execute(
            """SELECT c.id, c.display_id, c.workflow_version, w.id AS wakeup_id
              FROM solvan.reliability_cases c
              JOIN solvan.scheduled_wakeups w ON w.case_id = c.id
              WHERE c.organization_id = %(organization_id)s
                AND c.project_id = %(project_id)s
                AND c.environment_id = %(environment_id)s AND c.id = %(case_id)s
                AND w.status IN ('PENDING','CLAIMED')
              ORDER BY w.wake_at LIMIT 1""",
            {**scope.canonical_dict(), "case_id": case_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise ReliabilityCaseConflict("linked case has no active scheduled continuation")
        return ReliabilityCaseRecord(
            str(row["id"]),
            str(row["display_id"]),
            int(row["workflow_version"]),
            str(row["wakeup_id"]),
            False,
        )

    @staticmethod
    def _append_case_outbox(
        cursor: Any,
        scope: Scope,
        *,
        case_id: str,
        incident_id: str,
        wakeup_id: str,
        display_id: str,
    ) -> None:
        cursor.execute(
            """INSERT INTO solvan.outbox_events
              (organization_id, project_id, environment_id, id, aggregate_type,
               aggregate_id, aggregate_version, topic, event_type, payload_json,
               idempotency_key)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(event_id)s, 'RELIABILITY_CASE', %(case_id)s, 1,
                'reliability-cases', 'ReliabilityCaseOpened', %(payload)s,
                %(idempotency_key)s)""",
            {
                **scope.canonical_dict(),
                "event_id": new_identifier("evt"),
                "case_id": case_id,
                "payload": Jsonb(
                    {
                        "case_id": case_id,
                        "display_id": display_id,
                        "originating_incident_id": incident_id,
                        "wakeup_id": wakeup_id,
                        "state": "OPEN",
                    }
                ),
                "idempotency_key": f"case-opened:{case_id}",
            },
        )
