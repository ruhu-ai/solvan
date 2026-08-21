"""Token-fenced PostgreSQL claims used by coordinator claimants."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.ports import ClaimedEvent
from solvan.domain import Scope, new_identifier
from solvan.persistence.claim_sql import (
    CLAIM_INBOX,
    CLAIM_OUTBOX,
    COMPLETE_INBOX,
    COMPLETE_OUTBOX,
    INBOX_CLAIM_ATTEMPT_BUDGET,
    OUTBOX_PUBLISH_ATTEMPT_BUDGET,
    QUARANTINE_INBOX,
    QUARANTINE_OUTBOX,
    RELEASE_INBOX,
)
from solvan.persistence.postgres_types import (
    AggregateType as AggregateType,
)
from solvan.persistence.postgres_types import (
    ClaimLost as ClaimLost,
)
from solvan.persistence.postgres_types import (
    IngressDisposition as IngressDisposition,
)
from solvan.persistence.postgres_types import (
    IngressResult as IngressResult,
)
from solvan.persistence.postgres_types import (
    LeaseHandle as LeaseHandle,
)
from solvan.persistence.postgres_types import (
    TransitionWrite as TransitionWrite,
)
from solvan.persistence.postgres_types import (
    WorkflowConflict as WorkflowConflict,
)
from solvan.persistence.workflow_ingress import WorkflowIngressMixin

_AGGREGATE_TABLES = {
    AggregateType.INCIDENT: ("incidents", "incident_id"),
    AggregateType.RELIABILITY_CASE: ("reliability_cases", "reliability_case_id"),
}


class PostgresWorkflowStore(WorkflowIngressMixin):
    """Small transaction-aware boundary around authoritative claim SQL."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit all ledger/projection writes together or roll them all back."""

        with self._connection.transaction():
            yield

    def claim_inbox(
        self, *, scope: Scope, owner: str, claim_ttl_ms: int, batch_size: int = 1
    ) -> tuple[ClaimedEvent, ...]:
        self._quarantine(QUARANTINE_INBOX, scope=scope, max_attempts=INBOX_CLAIM_ATTEMPT_BUDGET)
        return self._claim(
            CLAIM_INBOX,
            scope=scope,
            owner=owner,
            claim_ttl_ms=claim_ttl_ms,
            batch_size=batch_size,
            max_attempts=INBOX_CLAIM_ATTEMPT_BUDGET,
        )

    def complete_inbox(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedEvent,
        result_ref: str | None,
        error_class: str | None = None,
    ) -> None:
        terminal_state = "FAILED" if error_class is not None else "COMPLETED"
        self._complete(
            COMPLETE_INBOX,
            scope=scope,
            owner=owner,
            claim=claim,
            terminal_state=terminal_state,
            result_ref=result_ref,
            error_class=error_class,
        )

    def release_inbox(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedEvent,
        refund_attempt: bool,
    ) -> None:
        """Hand one live inbox claim back for a later tick.

        ``refund_attempt`` is reserved for contention that says nothing about
        the event itself. Genuine poison is never refunded, so it still walks
        its bounded budget into durable quarantine.
        """

        self._complete(
            RELEASE_INBOX,
            scope=scope,
            owner=owner,
            claim=claim,
            refund_attempt=refund_attempt,
        )

    def claim_outbox(
        self, *, scope: Scope, owner: str, claim_ttl_ms: int, batch_size: int = 1
    ) -> tuple[ClaimedEvent, ...]:
        self._quarantine(QUARANTINE_OUTBOX, scope=scope, max_attempts=OUTBOX_PUBLISH_ATTEMPT_BUDGET)
        return self._claim(
            CLAIM_OUTBOX,
            scope=scope,
            owner=owner,
            claim_ttl_ms=claim_ttl_ms,
            batch_size=batch_size,
            max_attempts=OUTBOX_PUBLISH_ATTEMPT_BUDGET,
        )

    def complete_outbox(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> None:
        self._complete(COMPLETE_OUTBOX, scope=scope, owner=owner, claim=claim)

    def acquire_lease(
        self,
        *,
        scope: Scope,
        aggregate_type: AggregateType,
        entity_id: str,
        owner: str,
        lease_ttl_ms: int = 60_000,
    ) -> LeaseHandle | None:
        if lease_ttl_ms < 1:
            raise ValueError("lease TTL must be positive")
        table, id_parameter = _AGGREGATE_TABLES[aggregate_type]
        token = uuid4()
        statement = f"""
UPDATE solvan.{table}
SET lease_owner = %(lease_owner)s, lease_token = %(lease_token)s,
    lease_expires_at = now() + (%(lease_ttl_ms)s * interval '1 millisecond')
WHERE organization_id = %(organization_id)s
  AND project_id = %(project_id)s
  AND environment_id = %(environment_id)s
  AND id = %({id_parameter})s
  AND (lease_owner IS NULL OR lease_expires_at < now())
RETURNING workflow_version, lease_token, lease_expires_at
"""
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                statement,
                {
                    **scope.canonical_dict(),
                    id_parameter: entity_id,
                    "lease_owner": owner,
                    "lease_token": token,
                    "lease_ttl_ms": lease_ttl_ms,
                },
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return LeaseHandle(
            aggregate_type=aggregate_type,
            entity_id=entity_id,
            owner=owner,
            token=row["lease_token"],
            workflow_version=row["workflow_version"],
            expires_at=row["lease_expires_at"],
        )

    def release_lease(self, *, scope: Scope, lease: LeaseHandle) -> None:
        table, id_parameter = _AGGREGATE_TABLES[lease.aggregate_type]
        statement = f"""
UPDATE solvan.{table}
SET lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE organization_id = %(organization_id)s
  AND project_id = %(project_id)s
  AND environment_id = %(environment_id)s
  AND id = %({id_parameter})s
  AND lease_owner = %(lease_owner)s
  AND lease_token = %(lease_token)s
RETURNING id
"""
        with self._connection.cursor() as cursor:
            cursor.execute(
                statement,
                {
                    **scope.canonical_dict(),
                    id_parameter: lease.entity_id,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            if cursor.fetchone() is None:
                raise ClaimLost(f"lease for {lease.entity_id} is stale or no longer owned")

    def incident_state_for_lease(self, *, scope: Scope, lease: LeaseHandle) -> str:
        if lease.aggregate_type is not AggregateType.INCIDENT:
            raise ValueError("incident state requires an incident lease")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT state FROM solvan.incidents
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(incident_id)s AND workflow_version = %(workflow_version)s
                    AND lease_owner = %(lease_owner)s AND lease_token = %(lease_token)s
                    AND lease_expires_at >= now()""",
                {
                    **scope.canonical_dict(),
                    "incident_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkflowConflict("incident workflow or coordinator lease is stale")
        return str(row[0])

    def commit_transition(
        self, *, scope: Scope, lease: LeaseHandle, transition: TransitionWrite
    ) -> int:
        """CAS the projection and append transition/outbox rows in one transaction."""

        if lease.aggregate_type is AggregateType.RELIABILITY_CASE:
            raise WorkflowConflict(
                "Reliability Case transitions require an atomic next-action schedule"
            )

        table, id_parameter = _AGGREGATE_TABLES[lease.aggregate_type]
        statement = f"""
UPDATE solvan.{table}
SET state = %(to_state)s, workflow_version = workflow_version + 1,
    last_progress_at = now(), updated_at = now()
WHERE organization_id = %(organization_id)s
  AND project_id = %(project_id)s
  AND environment_id = %(environment_id)s
  AND id = %({id_parameter})s
  AND state = %(from_state)s
  AND workflow_version = %(expected_workflow_version)s
  AND lease_owner = %(lease_owner)s
  AND lease_token = %(lease_token)s
  AND lease_expires_at >= now()
RETURNING workflow_version
"""
        parameters: dict[str, object] = {
            **scope.canonical_dict(),
            id_parameter: lease.entity_id,
            "from_state": transition.from_state,
            "to_state": transition.to_state,
            "expected_workflow_version": lease.workflow_version,
            "lease_owner": lease.owner,
            "lease_token": lease.token,
        }
        with self._connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            row = cursor.fetchone()
            if row is None:
                raise WorkflowConflict(
                    f"workflow or lease changed before transition {transition.transition_key}"
                )
            to_version = int(row[0])
            transition_id = new_identifier("trn")
            outbox_id = new_identifier("evt")
            cursor.execute(
                """INSERT INTO solvan.state_transitions
                  (organization_id, project_id, environment_id, id, entity_type,
                   entity_id, from_state, to_state, from_workflow_version,
                   to_workflow_version, transition_key, actor_type, actor_id,
                   policy_decision_id, reason_code, rationale_summary,
                   evidence_refs_json, trace_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(transition_id)s, %(entity_type)s, %(entity_id)s,
                    %(from_state)s, %(to_state)s, %(from_version)s, %(to_version)s,
                    %(transition_key)s, %(actor_type)s, %(actor_id)s,
                    %(policy_decision_id)s, %(reason_code)s, %(rationale_summary)s,
                    %(evidence_refs)s, %(trace_id)s)""",
                {
                    **scope.canonical_dict(),
                    "transition_id": transition_id,
                    "entity_type": lease.aggregate_type.value,
                    "entity_id": lease.entity_id,
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
                    "evidence_refs": Jsonb(transition.evidence_refs),
                    "trace_id": transition.trace_id,
                },
            )
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type, payload_json,
                   idempotency_key)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(outbox_id)s, %(entity_type)s, %(entity_id)s, %(to_version)s,
                    'workflow-transitions', %(event_type)s, %(payload)s,
                    %(idempotency_key)s)""",
                {
                    **scope.canonical_dict(),
                    "outbox_id": outbox_id,
                    "entity_type": lease.aggregate_type.value,
                    "entity_id": lease.entity_id,
                    "to_version": to_version,
                    "event_type": transition.transition_key,
                    "payload": Jsonb(
                        {
                            "entity_id": lease.entity_id,
                            "from_state": transition.from_state,
                            "to_state": transition.to_state,
                            "workflow_version": to_version,
                        }
                    ),
                    "idempotency_key": (
                        f"transition:{lease.aggregate_type.value}:"
                        f"{lease.entity_id}:{transition.transition_key}"
                    ),
                },
            )
        return to_version

    def _quarantine(self, statement: str, *, scope: Scope, max_attempts: int) -> None:
        """Durably park poison events that exhausted their bounded claim budget."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                statement,
                {**scope.canonical_dict(), "max_attempts": max_attempts},
            )

    def _claim(
        self,
        statement: str,
        *,
        scope: Scope,
        owner: str,
        claim_ttl_ms: int,
        batch_size: int,
        max_attempts: int,
    ) -> tuple[ClaimedEvent, ...]:
        if claim_ttl_ms < 1 or batch_size < 1:
            raise ValueError("claim TTL and batch size must be positive")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                statement,
                {
                    **scope.canonical_dict(),
                    "claim_owner": owner,
                    "claim_token": token,
                    "claim_ttl_ms": claim_ttl_ms,
                    "batch_size": batch_size,
                    "max_attempts": max_attempts,
                },
            )
            rows = cursor.fetchall()
        return tuple(
            ClaimedEvent(
                event_id=row["id"],
                event_type=row["event_type"],
                claim_token=row["claim_token"],
                claim_expires_at=row["claim_expires_at"],
            )
            for row in rows
        )

    def _complete(
        self,
        statement: str,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedEvent,
        **extra: object,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                statement,
                {
                    **scope.canonical_dict(),
                    "event_id": claim.event_id,
                    "claim_owner": owner,
                    "claim_token": claim.claim_token,
                    **extra,
                },
            )
            if cursor.fetchone() is None:
                raise ClaimLost(f"claim for {claim.event_id} is stale or no longer owned")
