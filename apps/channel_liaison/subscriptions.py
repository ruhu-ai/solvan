"""Freeze reader-filtered subscription intervals for one external adapter."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_catchup import catch_up
from solvan.persistence.liaison_delivery import LiaisonDeliveryStore
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_sequence import Cursor
from solvan.persistence.liaison_subscriptions import (
    Cadence,
    LiaisonSubscriptionStore,
    SubscriptionClaim,
)
from solvan.platform.evidence_objects import ObjectReceipt


class PayloadWriter(Protocol):
    def put_json(self, *, object_name: str, value: dict[str, Any]) -> ObjectReceipt: ...


@dataclass(frozen=True, slots=True)
class SubscriptionWorkReceipt:
    status: str
    delivery_id: str | None = None


class ExternalSubscriptionWorker:
    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        scope: Scope,
        channel_kind: str,
        writer: PayloadWriter,
        authority: Callable[[str], tuple[Sequence[tuple[str, str]], int]],
        render: Callable[[SubscriptionClaim, Sequence[Any], int, bool], dict[str, Any]],
    ) -> None:
        if channel_kind not in {"EMAIL", "DISCORD"}:
            raise ValueError("external subscription channel is unsupported")
        self._connect = connect
        self._scope = scope
        self._channel_kind = channel_kind
        self._writer = writer
        self._authority = authority
        self._render = render

    def process_one(self, *, owner: str) -> SubscriptionWorkReceipt:
        with self._connect() as connection, connection.transaction():
            claim = LiaisonSubscriptionStore(connection).claim_due(
                scope=self._scope, owner=owner, channel_kind=self._channel_kind
            )
        if claim is None:
            return SubscriptionWorkReceipt("IDLE")
        try:
            authorized_records, policy_epoch = self._authority(claim.principal)
            with (
                self._connect() as connection,
                connection.transaction(),
                projection_read(
                    connection,
                    scope=self._scope,
                    principal=claim.principal,
                    purpose="subscription-delivery",
                    classification_ceiling=claim.classification_ceiling or "PUBLIC",
                    method="catch_up",
                    operation_id=new_identifier("opr"),
                    anchor_label=claim.anchor.label(),
                    authorized_records=authorized_records,
                ),
            ):
                brief = catch_up(
                    connection,
                    scope=self._scope,
                    anchor=claim.anchor,
                    cursor=Cursor(claim.last_delivered_sequence, claim.policy_epoch),
                    authorized_records=authorized_records,
                    policy_epoch=policy_epoch,
                )
            next_delivery = _next_delivery(claim.cadence)
            if not brief.deltas:
                with self._connect() as connection, connection.transaction():
                    if not LiaisonSubscriptionStore(connection).complete_interval(
                        scope=self._scope,
                        claim=claim,
                        to_sequence=brief.cursor.scope_sequence,
                        next_delivery_at=next_delivery,
                        policy_epoch=policy_epoch,
                        visible_delta_count=0,
                        delivery_id=None,
                    ):
                        raise RuntimeError("subscription claim was replaced")
                return SubscriptionWorkReceipt("SCANNED")
            assert claim.binding_id is not None and claim.binding_epoch is not None
            assert claim.external_conversation_id is not None
            classification = max(
                (item.classification for item in brief.deltas), key=_classification_rank
            )
            ceiling = claim.classification_ceiling or "PUBLIC"
            over_ceiling = _classification_rank(classification) > _classification_rank(ceiling)
            receipt = self._writer.put_json(
                object_name=(
                    f"liaison/subscriptions/{claim.subscription_id}/"
                    f"{claim.last_delivered_sequence}-{brief.cursor.scope_sequence}.json"
                ),
                value=self._render(claim, brief.deltas, brief.remaining, over_ceiling),
            )
            if over_ceiling:
                classification = ceiling
            access_hash = canonical_sha256(
                {
                    "principal": claim.principal,
                    "subscription_id": claim.subscription_id,
                    "from": claim.last_delivered_sequence,
                    "to": brief.cursor.scope_sequence,
                    "records": [(item.record_type, item.record_id) for item in brief.deltas],
                }
            )
            with self._connect() as connection, connection.transaction():
                delivery_id = LiaisonDeliveryStore(connection).queue_subscription_delta(
                    scope=self._scope,
                    subscription_id=claim.subscription_id,
                    binding_id=claim.binding_id,
                    binding_epoch=claim.binding_epoch,
                    from_sequence=claim.last_delivered_sequence,
                    to_sequence=brief.cursor.scope_sequence,
                    payload_ref=receipt.uri,
                    payload_hash=receipt.content_hash,
                    classification=classification,
                    redaction_verdict_ref=(
                        f"redaction://over-ceiling/{claim.subscription_id}"
                        if over_ceiling
                        else f"redaction://subscription/{claim.subscription_id}"
                    ),
                    access_set_hash=access_hash,
                    policy_epoch=policy_epoch,
                    provider_idempotency_key=str(
                        uuid5(
                            NAMESPACE_URL,
                            f"{claim.subscription_id}:{claim.last_delivered_sequence}:"
                            f"{brief.cursor.scope_sequence}",
                        )
                    ),
                )
                if not LiaisonSubscriptionStore(connection).complete_interval(
                    scope=self._scope,
                    claim=claim,
                    to_sequence=brief.cursor.scope_sequence,
                    next_delivery_at=next_delivery,
                    policy_epoch=policy_epoch,
                    visible_delta_count=len(brief.deltas),
                    delivery_id=delivery_id,
                ):
                    raise RuntimeError("subscription claim was replaced before enqueue")
            return SubscriptionWorkReceipt("QUEUED", delivery_id)
        except Exception:
            with self._connect() as connection, connection.transaction():
                LiaisonSubscriptionStore(connection).retry(
                    scope=self._scope,
                    claim=claim,
                    retry_at=datetime.now(UTC) + timedelta(seconds=30),
                )
            return SubscriptionWorkReceipt("FAILED")


def _next_delivery(cadence: Cadence) -> datetime:
    return (
        datetime.now(UTC)
        + {
            Cadence.ON_EVENT: timedelta(seconds=30),
            Cadence.DAILY_DIGEST: timedelta(days=1),
            Cadence.ON_CLOSE: timedelta(minutes=5),
        }[cadence]
    )


def _classification_rank(value: str) -> int:
    return {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}[value]
