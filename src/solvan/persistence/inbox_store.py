"""Token-fenced inbox claim metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.ports import ClaimedEvent
from solvan.domain import Scope
from solvan.persistence.postgres import PostgresWorkflowStore


@dataclass(frozen=True, slots=True)
class InboxEnvelope:
    event_id: str
    source: str
    source_event_id: str
    event_type: str
    payload_ref: str
    payload_hash: str


class PostgresInboxStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection
        self._workflow = PostgresWorkflowStore(connection)

    def claim(
        self, *, scope: Scope, owner: str, claim_ttl_ms: int, batch_size: int
    ) -> tuple[ClaimedEvent, ...]:
        return self._workflow.claim_inbox(
            scope=scope, owner=owner, claim_ttl_ms=claim_ttl_ms, batch_size=batch_size
        )

    def load(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> InboxEnvelope:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, source, source_event_id, event_type, payload_ref, payload_hash
                  FROM solvan.inbox_events
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(event_id)s AND processing_state = 'PROCESSING'
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
            raise RuntimeError(f"inbox claim for {claim.event_id} is stale")
        return InboxEnvelope(
            event_id=str(row["id"]),
            source=str(row["source"]),
            source_event_id=str(row["source_event_id"]),
            event_type=str(row["event_type"]),
            payload_ref=str(row["payload_ref"]),
            payload_hash=str(row["payload_hash"]),
        )
