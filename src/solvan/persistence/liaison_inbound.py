"""Reclaimable, channel-isolated Liaison inbound work queue."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope
from solvan.persistence.liaison_channels import (
    ActiveChannelBinding,
    ChannelBindingError,
    InboundEventClaim,
)


class LiaisonInboundStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def claim_due(
        self,
        *,
        scope: Scope,
        channel_kind: str,
        owner: str,
        now: datetime | None = None,
        lease_seconds: int = 60,
    ) -> InboundEventClaim | None:
        moment = now or datetime.now(UTC)
        if (
            moment.tzinfo is None
            or channel_kind not in {"SLACK", "EMAIL", "DISCORD"}
            or not owner
            or not 10 <= lease_seconds <= 300
        ):
            raise ChannelBindingError("inbound claim requires an owner and bounded aware lease")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT e.*,b.principal,b.classification_ceiling
                     FROM solvan_liaison.liaison_inbound_events e
                     JOIN solvan_liaison.liaison_channel_bindings b ON
                       (b.organization_id,b.project_id,b.environment_id,b.id)=
                       (e.organization_id,e.project_id,e.environment_id,e.binding_id)
                    WHERE e.organization_id=%(organization_id)s
                      AND e.project_id=%(project_id)s
                      AND e.environment_id=%(environment_id)s
                      AND b.channel_kind=%(channel_kind)s
                      AND ((e.status IN ('PENDING','FAILED')
                            AND coalesce(e.next_attempt_at,e.received_at) <= %(now)s)
                           OR (e.status='CLAIMED' AND e.claim_expires_at <= %(now)s))
                      AND b.status='ACTIVE' AND b.connection_epoch=e.binding_epoch
                    ORDER BY coalesce(e.next_attempt_at,e.received_at),e.external_event_id
                    FOR UPDATE OF e SKIP LOCKED LIMIT 1""",
                {**scope.canonical_dict(), "channel_kind": channel_kind, "now": moment},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                """UPDATE solvan_liaison.liaison_inbound_events
                      SET status='CLAIMED',attempts=attempts+1,claim_owner=%(owner)s,
                          claim_token=%(token)s,claim_expires_at=%(expires_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND binding_id=%(binding_id)s AND external_event_id=%(event_id)s""",
                {
                    **scope.canonical_dict(),
                    "binding_id": row["binding_id"],
                    "event_id": row["external_event_id"],
                    "owner": owner,
                    "token": token,
                    "expires_at": moment + timedelta(seconds=lease_seconds),
                },
            )
        return InboundEventClaim(
            binding=ActiveChannelBinding(
                binding_id=str(row["binding_id"]),
                principal=str(row["principal"]),
                epoch=int(row["binding_epoch"]),
                classification_ceiling=str(row["classification_ceiling"]),
            ),
            external_event_id=str(row["external_event_id"]),
            message_id=str(row["message_id"]),
            thread_id=str(row["thread_id"]),
            claim_token=token,
        )

    def complete(self, *, scope: Scope, claim: InboundEventClaim) -> bool:
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_inbound_events
                  SET status='COMPLETED',completed_at=now(),claim_owner=NULL,
                      claim_token=NULL,claim_expires_at=NULL,next_attempt_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND binding_id=%(binding_id)s AND external_event_id=%(event_id)s
                  AND status='CLAIMED' AND claim_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "binding_id": claim.binding.binding_id,
                "event_id": claim.external_event_id,
                "claim_token": claim.claim_token,
            },
        )
        return cursor.rowcount == 1

    def fail(
        self,
        *,
        scope: Scope,
        claim: InboundEventClaim,
        retry_at: datetime,
        reason: str,
    ) -> bool:
        if retry_at.tzinfo is None or not reason:
            raise ChannelBindingError("inbound retry requires an aware time and reason")
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_inbound_events
                  SET status='FAILED',terminal_reason=%(reason)s,next_attempt_at=%(retry_at)s,
                      claim_owner=NULL,claim_token=NULL,claim_expires_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND binding_id=%(binding_id)s AND external_event_id=%(event_id)s
                  AND status='CLAIMED' AND claim_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "binding_id": claim.binding.binding_id,
                "event_id": claim.external_event_id,
                "claim_token": claim.claim_token,
                "retry_at": retry_at,
                "reason": reason,
            },
        )
        return cursor.rowcount == 1
