"""Token-fenced durable outbox publication records."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.ports import ClaimedEvent, OutboxEnvelope
from solvan.domain import Scope
from solvan.persistence.postgres import PostgresWorkflowStore


class PostgresOutboxStore:
    """Load and complete only the outbox row held by the live claim token."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection
        self._workflow = PostgresWorkflowStore(connection)

    def claim(
        self, *, scope: Scope, owner: str, claim_ttl_ms: int, batch_size: int
    ) -> tuple[ClaimedEvent, ...]:
        return self._workflow.claim_outbox(
            scope=scope,
            owner=owner,
            claim_ttl_ms=claim_ttl_ms,
            batch_size=batch_size,
        )

    def load(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> OutboxEnvelope:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, aggregate_type, aggregate_id, aggregate_version,
                    topic, event_type, payload_json, idempotency_key
                  FROM solvan.outbox_events
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(event_id)s AND published_at IS NULL
                    AND claim_owner = %(claim_owner)s AND claim_token = %(claim_token)s
                    AND claim_expires_at >= now()""",
                {
                    **scope.canonical_dict(),
                    "event_id": claim.event_id,
                    "claim_owner": owner,
                    "claim_token": claim.claim_token,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError(f"outbox claim for {claim.event_id} is stale")
        payload = row["payload_json"]
        if not isinstance(payload, dict):
            raise RuntimeError(f"outbox payload for {claim.event_id} is not an object")
        return OutboxEnvelope(
            event_id=str(row["id"]),
            aggregate_type=str(row["aggregate_type"]),
            aggregate_id=str(row["aggregate_id"]),
            aggregate_version=int(row["aggregate_version"]),
            topic=str(row["topic"]),
            event_type=str(row["event_type"]),
            payload=dict(payload),
            idempotency_key=str(row["idempotency_key"]),
        )

    def complete(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> None:
        self._workflow.complete_outbox(scope=scope, owner=owner, claim=claim)
