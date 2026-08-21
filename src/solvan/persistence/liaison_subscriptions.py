"""Durable, consent-bound subscription scheduling for Liaison channels."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.liaison import Anchor
from solvan.application.liaison.anchors import anchor_from_mapping
from solvan.domain import Scope, new_identifier


class SubscriptionError(RuntimeError):
    pass


class Cadence(StrEnum):
    ON_EVENT = "ON_EVENT"
    DAILY_DIGEST = "DAILY_DIGEST"
    ON_CLOSE = "ON_CLOSE"


@dataclass(frozen=True, slots=True)
class SubscriptionClaim:
    subscription_id: str
    principal: str
    anchor: Anchor
    cadence: Cadence
    binding_id: str | None
    binding_epoch: int | None
    external_conversation_id: str | None
    classification_ceiling: str | None
    last_delivered_sequence: int
    policy_epoch: int
    claim_token: UUID


class LiaisonSubscriptionStore:
    """Claims are reclaimable; only the current token may advance a cursor."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def create(
        self,
        *,
        scope: Scope,
        principal: str,
        anchor: Anchor,
        cadence: Cadence,
        consent_kind: str,
        consent_ref: str,
        policy_epoch: int,
        channel_binding_id: str | None = None,
        external_conversation_id: str | None = None,
        expires_at: datetime | None = None,
        next_delivery_at: datetime | None = None,
    ) -> str:
        if not principal or consent_kind not in {"PARKED_REQUEST", "CONSOLE_ACTION"}:
            raise SubscriptionError("subscription requires a principal and explicit consent")
        if not consent_ref or policy_epoch < 1:
            raise SubscriptionError("subscription consent and policy epoch are required")
        if expires_at is not None and expires_at.tzinfo is None:
            raise SubscriptionError("subscription expiry must be timezone-aware")
        if anchor.kind.value != "RECORD" and expires_at is None:
            raise SubscriptionError("scope and service subscriptions require an expiry")
        if (channel_binding_id is None) != (external_conversation_id is None):
            raise SubscriptionError("external subscription requires an exact conversation")

        binding_kind: str | None = None
        if channel_binding_id is not None:
            row = self._connection.execute(
                """SELECT channel_kind,principal,status
                     FROM solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(binding_id)s
                    FOR SHARE""",
                {**scope.canonical_dict(), "binding_id": channel_binding_id},
            ).fetchone()
            if row is None or row[1] != principal or row[2] != "ACTIVE":
                raise SubscriptionError("channel binding is not active for this principal")
            binding_kind = str(row[0])
            if binding_kind == "MCP":
                raise SubscriptionError("MCP bindings are pull-only")

        payload = anchor.canonical_dict()
        subscription_id = new_identifier("sub")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_subscriptions
                     (organization_id,project_id,environment_id,id,principal,anchor_kind,
                      anchor_record_type,anchor_record_id,anchor_service_key,
                      anchor_window_start,anchor_window_end,channel_binding_id,channel_kind,
                      external_conversation_id,
                      cadence,consent_kind,consent_ref,policy_epoch,next_delivery_at,
                      expires_at,status)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(principal)s,%(anchor_kind)s,%(anchor_record_type)s,
                      %(anchor_record_id)s,%(anchor_service_key)s,%(anchor_window_start)s,
                      %(anchor_window_end)s,%(binding_id)s,%(channel_kind)s,
                      %(external_conversation_id)s,%(cadence)s,
                      %(consent_kind)s,%(consent_ref)s,%(policy_epoch)s,
                      %(next_delivery_at)s,%(expires_at)s,'ACTIVE')
                   ON CONFLICT DO NOTHING RETURNING id""",
                {
                    **scope.canonical_dict(),
                    **payload,
                    "id": subscription_id,
                    "principal": principal,
                    "binding_id": channel_binding_id,
                    "channel_kind": binding_kind,
                    "external_conversation_id": external_conversation_id,
                    "cadence": str(cadence),
                    "consent_kind": consent_kind,
                    "consent_ref": consent_ref,
                    "policy_epoch": policy_epoch,
                    "next_delivery_at": next_delivery_at or datetime.now(UTC),
                    "expires_at": expires_at,
                },
            )
            inserted = cursor.fetchone()
            if inserted is not None:
                return str(inserted[0])
        raise SubscriptionError("an active subscription already covers this anchor and channel")

    def end(self, *, scope: Scope, subscription_id: str, principal: str) -> bool:
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_subscriptions
                  SET status='ENDED',ended_at=now(),next_delivery_at=NULL,
                      claim_owner=NULL,claim_token=NULL,claim_expires_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(subscription_id)s AND principal=%(principal)s AND status='ACTIVE'""",
            {**scope.canonical_dict(), "subscription_id": subscription_id, "principal": principal},
        )
        return cursor.rowcount == 1

    def list_for_principal(self, *, scope: Scope, principal: str) -> list[dict[str, Any]]:
        """Return only the caller's own subscription metadata, never another audience."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,anchor_kind,anchor_record_type,anchor_record_id,
                          anchor_service_key,cadence,channel_kind,status,created_at,
                          next_delivery_at,expires_at,last_delivered_sequence
                     FROM solvan_liaison.liaison_subscriptions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND principal=%(principal)s
                    ORDER BY created_at DESC,id DESC""",
                {**scope.canonical_dict(), "principal": principal},
            )
            return [dict(row) for row in cursor.fetchall()]

    def claim_due(
        self,
        *,
        scope: Scope,
        owner: str,
        now: datetime | None = None,
        lease_seconds: int = 60,
        channel_kind: str | None = None,
    ) -> SubscriptionClaim | None:
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None or not owner or not 10 <= lease_seconds <= 300:
            raise SubscriptionError("subscription claim requires an owner and bounded aware lease")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT s.*,b.connection_epoch,b.classification_ceiling,b.status AS binding_status
                     FROM solvan_liaison.liaison_subscriptions s
                     LEFT JOIN solvan_liaison.liaison_channel_bindings b ON
                       (b.organization_id,b.project_id,b.environment_id,b.id)=
                       (s.organization_id,s.project_id,s.environment_id,s.channel_binding_id)
                    WHERE s.organization_id=%(organization_id)s
                      AND s.project_id=%(project_id)s
                      AND s.environment_id=%(environment_id)s AND s.status='ACTIVE'
                      AND (s.expires_at IS NULL OR s.expires_at > %(now)s)
                      AND coalesce(s.next_delivery_at,s.created_at) <= %(now)s
                      AND (s.claim_token IS NULL OR s.claim_expires_at <= %(now)s)
                      AND (s.channel_binding_id IS NULL OR b.status='ACTIVE')
                      AND (%(channel_kind)s::text IS NULL OR s.channel_kind=%(channel_kind)s)
                    ORDER BY coalesce(s.next_delivery_at,s.created_at),s.id
                    FOR UPDATE OF s SKIP LOCKED LIMIT 1""",
                {**scope.canonical_dict(), "now": moment, "channel_kind": channel_kind},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                """UPDATE solvan_liaison.liaison_subscriptions
                      SET delivery_attempts=delivery_attempts+1,claim_owner=%(owner)s,
                          claim_token=%(token)s,claim_expires_at=%(expires_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s""",
                {
                    **scope.canonical_dict(),
                    "id": row["id"],
                    "owner": owner,
                    "token": token,
                    "expires_at": moment + timedelta(seconds=lease_seconds),
                },
            )
        return SubscriptionClaim(
            subscription_id=str(row["id"]),
            principal=str(row["principal"]),
            anchor=anchor_from_mapping(row),
            cadence=Cadence(str(row["cadence"])),
            binding_id=(
                None if row["channel_binding_id"] is None else str(row["channel_binding_id"])
            ),
            binding_epoch=None if row["connection_epoch"] is None else int(row["connection_epoch"]),
            external_conversation_id=(
                None
                if row["external_conversation_id"] is None
                else str(row["external_conversation_id"])
            ),
            classification_ceiling=(
                None
                if row["classification_ceiling"] is None
                else str(row["classification_ceiling"])
            ),
            last_delivered_sequence=int(row["last_delivered_sequence"]),
            policy_epoch=int(row["policy_epoch"]),
            claim_token=token,
        )

    def complete_interval(
        self,
        *,
        scope: Scope,
        claim: SubscriptionClaim,
        to_sequence: int,
        next_delivery_at: datetime,
        policy_epoch: int,
        visible_delta_count: int,
        delivery_id: str | None,
    ) -> bool:
        if (
            next_delivery_at.tzinfo is None
            or to_sequence < claim.last_delivered_sequence
            or visible_delta_count < 0
            or (visible_delta_count == 0) != (delivery_id is None)
        ):
            raise SubscriptionError("subscription cursor advance is invalid")
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_subscriptions
                  SET last_delivered_sequence=%(to_sequence)s,policy_epoch=%(policy_epoch)s,
                      next_delivery_at=%(next_delivery_at)s,claim_owner=NULL,
                      claim_token=NULL,claim_expires_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(subscription_id)s AND status='ACTIVE'
                  AND claim_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "subscription_id": claim.subscription_id,
                "claim_token": claim.claim_token,
                "to_sequence": to_sequence,
                "policy_epoch": policy_epoch,
                "next_delivery_at": next_delivery_at,
            },
        )
        if cursor.rowcount != 1:
            return False
        self._connection.execute(
            """INSERT INTO solvan_liaison.liaison_subscription_scans
                 (organization_id,project_id,environment_id,id,subscription_id,
                  from_sequence,to_sequence,policy_epoch,visible_delta_count,
                  delivery_id,outcome)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(subscription_id)s,%(from_sequence)s,%(to_sequence)s,
                  %(policy_epoch)s,%(visible_delta_count)s,%(delivery_id)s,%(outcome)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("scn"),
                "subscription_id": claim.subscription_id,
                "from_sequence": claim.last_delivered_sequence,
                "to_sequence": to_sequence,
                "policy_epoch": policy_epoch,
                "visible_delta_count": visible_delta_count,
                "delivery_id": delivery_id,
                "outcome": "NO_VISIBLE_DELTA" if delivery_id is None else "DELIVERY_QUEUED",
            },
        )
        return True

    def retry(self, *, scope: Scope, claim: SubscriptionClaim, retry_at: datetime) -> bool:
        if retry_at.tzinfo is None:
            raise SubscriptionError("subscription retry time must be timezone-aware")
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_subscriptions
                  SET next_delivery_at=%(retry_at)s,claim_owner=NULL,
                      claim_token=NULL,claim_expires_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(subscription_id)s AND status='ACTIVE'
                  AND claim_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "subscription_id": claim.subscription_id,
                "claim_token": claim.claim_token,
                "retry_at": retry_at,
            },
        )
        return cursor.rowcount == 1
