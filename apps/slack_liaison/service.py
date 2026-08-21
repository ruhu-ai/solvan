"""Ingress, queued answering, and delivery orchestration for Slack."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from apps.api.liaison_service import LiaisonService
from apps.slack_liaison.contracts import (
    SlackIngressReceipt,
    SlackInstallation,
    SlackWorkReceipt,
)
from solvan.application.liaison.parts import PartKind, user_part
from solvan.application.liaison.redaction import classify
from solvan.application.slack_channel import (
    SlackEventsEnvelope,
    slack_channel_identity,
    slack_conversation_id,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import new_identifier
from solvan.persistence.liaison_catchup import catch_up
from solvan.persistence.liaison_channels import (
    ChannelBindingError,
    InboundEventClaim,
    LiaisonChannelStore,
)
from solvan.persistence.liaison_delivery import LiaisonDeliveryStore
from solvan.persistence.liaison_inbound import LiaisonInboundStore
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_sequence import Cursor
from solvan.persistence.liaison_store import LiaisonStore, MessageRecord
from solvan.persistence.liaison_subscriptions import (
    Cadence,
    LiaisonSubscriptionStore,
    SubscriptionClaim,
)
from solvan.platform.evidence_objects import ObjectReceipt
from solvan.platform.slack import SlackDeliveryError, SlackPost, SlackWebClient


class PayloadWriter(Protocol):
    def put_json(self, *, object_name: str, value: dict[str, Any]) -> ObjectReceipt: ...


class PayloadReader(Protocol):
    def get_json(
        self, *, uri: str, expected_hash: str, max_bytes: int = 1_048_576
    ) -> dict[str, Any]: ...


class SecretReader(Protocol):
    def access(self, resource: str, *, max_bytes: int = 16_384) -> bytes: ...


class SlackIngressService:
    def __init__(self, *, connect: Callable[[], Any], installation: SlackInstallation) -> None:
        self._connect = connect
        self._installation = installation

    def ingest(self, envelope: SlackEventsEnvelope) -> SlackIngressReceipt:
        """Persist only a redacted user message, then return for the 3s Slack ACK."""

        if envelope.team_id != self._installation.team_id:
            return SlackIngressReceipt("UNKNOWN_INSTALLATION")
        scope = self._installation.scope
        identity = slack_channel_identity(team_id=envelope.team_id, user_id=envelope.event.user)
        enrollment_prefix = "solvan enroll "
        if envelope.event.text.casefold().startswith(enrollment_prefix):
            nonce = envelope.event.text[len(enrollment_prefix) :].strip()
            with self._connect() as connection, connection.transaction():
                try:
                    LiaisonChannelStore(connection).consume_enrollment(
                        scope=scope,
                        channel_kind="SLACK",
                        channel_identity=identity,
                        nonce=nonce,
                    )
                except ChannelBindingError:
                    # The store has incremented the bounded-attempt counter.
                    # Catch inside the transaction so the refusal is durable.
                    return SlackIngressReceipt("ENROLLMENT_REFUSED", event_id=envelope.event_id)
            return SlackIngressReceipt("ENROLLED", event_id=envelope.event_id, created=True)
        with self._connect() as connection, connection.transaction():
            channels = LiaisonChannelStore(connection)
            binding = channels.active_binding(
                scope=scope, channel_kind="SLACK", channel_identity=identity
            )
            if binding is None:
                return SlackIngressReceipt("UNBOUND")
            conversation_id = slack_conversation_id(envelope.event)
            normalized = envelope.event.text.strip()
            if normalized.casefold() == "solvan stop following":
                stopped = channels.stop_following(
                    scope=scope, binding=binding, external_conversation_id=conversation_id
                )
                return SlackIngressReceipt(
                    "STOPPED" if stopped else "NOT_ENROLLED",
                    event_id=envelope.event_id,
                    created=stopped,
                )
            ask_prefix = "solvan ask "
            if normalized.casefold().startswith(ask_prefix):
                question = normalized[len(ask_prefix) :].strip()
                if not question:
                    return SlackIngressReceipt("QUESTION_REQUIRED", event_id=envelope.event_id)
                mapped = channels.enroll_scope_thread(
                    scope=scope,
                    binding=binding,
                    external_conversation_id=conversation_id,
                )
            else:
                question = normalized
                try:
                    mapped = channels.mapped_thread(
                        scope=scope,
                        binding=binding,
                        external_conversation_id=conversation_id,
                    )
                except ChannelBindingError:
                    return SlackIngressReceipt("NOT_ENROLLED", event_id=envelope.event_id)
            verdict = classify(question)
            inbound = channels.record_inbound(
                scope=scope,
                binding=binding,
                external_event_id=envelope.event_id,
                payload_hash=verdict.digest,
            )
            if not inbound.created:
                return SlackIngressReceipt("DUPLICATE", event_id=envelope.event_id, created=False)
            ledger = LiaisonStore(connection)
            message_id = ledger.append_message(
                scope=scope,
                thread_id=mapped.thread_id,
                role="USER",
                classification=str(verdict.classification),
                author_principal=binding.principal,
                redaction_verdict_ref=verdict.verdict_ref,
                content_hash=verdict.digest,
            )
            ledger.append_parts(
                scope=scope,
                message_id=message_id,
                parts=[
                    user_part(
                        verdict.placeholder() if verdict.withheld else verdict.text,
                        sequence=0,
                        author_principal=binding.principal,
                        membership_epoch=ledger.current_membership_epoch(
                            scope=scope,
                            thread_id=mapped.thread_id,
                            principal=binding.principal,
                        ),
                        classification=str(verdict.classification),
                    )
                ],
            )
            if not channels.bind_inbound_message(
                scope=scope,
                binding=binding,
                external_event_id=envelope.event_id,
                thread_id=mapped.thread_id,
                message_id=message_id,
            ):
                raise RuntimeError("authenticated Slack event lost its message bind race")
        return SlackIngressReceipt("QUEUED", event_id=envelope.event_id, created=True)


class SlackAnswerWorker:
    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        installation: SlackInstallation,
        liaison: LiaisonService,
        writer: PayloadWriter,
    ) -> None:
        self._connect = connect
        self._installation = installation
        self._liaison = liaison
        self._writer = writer

    def process_one(self, *, owner: str) -> SlackWorkReceipt:
        scope = self._installation.scope
        with self._connect() as connection, connection.transaction():
            claim = LiaisonInboundStore(connection).claim_due(
                scope=scope, channel_kind="SLACK", owner=owner
            )
        if claim is None:
            return SlackWorkReceipt("IDLE")
        try:
            with self._connect() as connection:
                thread = LiaisonStore(connection).thread(scope=scope, thread_id=claim.thread_id)
                if thread is None:
                    raise RuntimeError("mapped channel thread disappeared")
            outcome = self._liaison.answer_persisted_channel_message(
                scope=scope,
                principal=claim.binding.principal,
                anchor=thread.anchor,
                thread_id=claim.thread_id,
                user_message_id=claim.message_id,
                idempotency_key=f"slack:{claim.binding.binding_id}:{claim.external_event_id}",
            )
            payload, classification, access_hash = self._render_payload(
                claim=claim, answer_message_id=outcome.answer_message_id
            )
            receipt = self._writer.put_json(
                object_name=f"liaison/deliveries/{outcome.answer_message_id}.json",
                value=payload,
            )
            with self._connect() as connection, connection.transaction():
                policy_epoch = current_policy_epoch(
                    connection, scope=scope, principal=claim.binding.principal
                )
                delivery_id = LiaisonDeliveryStore(connection).queue_direct(
                    scope=scope,
                    source_message_id=outcome.answer_message_id,
                    binding_id=claim.binding.binding_id,
                    binding_epoch=claim.binding.epoch,
                    payload_ref=receipt.uri,
                    payload_hash=receipt.content_hash,
                    classification=classification,
                    redaction_verdict_ref=f"redaction://egress/{outcome.answer_message_id}",
                    access_set_hash=access_hash,
                    policy_epoch=policy_epoch,
                    provider_idempotency_key=str(
                        uuid5(
                            NAMESPACE_URL,
                            f"{claim.binding.binding_id}:{outcome.answer_message_id}",
                        )
                    ),
                )
                if not LiaisonInboundStore(connection).complete(scope=scope, claim=claim):
                    raise RuntimeError("Slack inbound claim was lost before completion")
            return SlackWorkReceipt(
                "DELIVERY_QUEUED",
                event_id=claim.external_event_id,
                delivery_id=delivery_id,
            )
        except Exception:
            with self._connect() as connection, connection.transaction():
                LiaisonInboundStore(connection).fail(
                    scope=scope,
                    claim=claim,
                    retry_at=datetime.now(UTC) + timedelta(seconds=30),
                    reason="SAFE_PROCESSING_FAILURE",
                )
            return SlackWorkReceipt("FAILED", event_id=claim.external_event_id)

    def _render_payload(
        self, *, claim: InboundEventClaim, answer_message_id: str
    ) -> tuple[dict[str, Any], str, str]:
        scope = self._installation.scope
        with self._connect() as connection:
            channels = LiaisonChannelStore(connection)
            thread = LiaisonStore(connection).thread(scope=scope, thread_id=claim.thread_id)
            if thread is None:
                raise RuntimeError("mapped Slack thread disappeared")
            reader = self._liaison.reader(principal=claim.binding.principal, scope=scope)
            external = channels.external_conversation_for_thread(
                scope=scope,
                binding_id=claim.binding.binding_id,
                binding_epoch=claim.binding.epoch,
                thread_id=claim.thread_id,
            )
            messages = LiaisonStore(connection).transcript(
                scope=scope,
                thread_id=claim.thread_id,
                reader_principal=claim.binding.principal,
                authorized_records=list(reader.authorized_records_for_anchor(thread.anchor)),
            )
        answer = next((item for item in messages if item.id == answer_message_id), None)
        if answer is None:
            raise RuntimeError("Liaison answer is unavailable for delivery")
        text = _render_slack_text(answer, console_url=self._installation.console_base_url)
        _, channel, thread_ts = external.split(":", 2)
        payload = {
            "schema_version": 1,
            "channel": channel,
            "thread_ts": thread_ts,
            "text": text,
        }
        return (
            payload,
            answer.classification,
            canonical_sha256(
                {
                    "principal": claim.binding.principal,
                    "answer_message_id": answer_message_id,
                    "visible_parts": [part.payload for part in answer.parts],
                }
            ),
        )


def _render_slack_text(message: MessageRecord, *, console_url: str) -> str:
    lines: list[str] = []
    needs_console = False
    for part in message.parts:
        sentence = part.payload.get("sentence")
        if isinstance(sentence, str) and sentence.strip():
            lines.append(sentence.strip())
        elif part.kind is PartKind.STEER_DRAFT:
            lines.append("A bounded evidence read can be requested from the Solvan console.")
            needs_console = True
        elif part.kind is PartKind.CONTENT_WITHHELD:
            lines.append("Some content was withheld by the reader-authority filter.")
        elif part.kind in {PartKind.ERROR, PartKind.PARKED_REQUEST}:
            lines.append("This turn needs attention in the Solvan console.")
            needs_console = True
    if not lines:
        lines.append("Solvan recorded the request but has no channel-safe answer to show.")
        needs_console = True
    if needs_console:
        lines.append(f"Open Solvan: {console_url}/conversations/{message.thread_id}")
    return "\n\n".join(lines)[:4_000]


class SlackDeliveryWorker:
    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        installation: SlackInstallation,
        reader: PayloadReader,
        secrets: SecretReader,
        slack: SlackWebClient,
    ) -> None:
        self._connect = connect
        self._installation = installation
        self._reader = reader
        self._secrets = secrets
        self._slack = slack

    def process_one(self, *, owner: str) -> SlackWorkReceipt:
        scope = self._installation.scope
        with self._connect() as connection, connection.transaction():
            claim = LiaisonDeliveryStore(connection).claim_due(
                scope=scope, channel_kind="SLACK", owner=owner
            )
        if claim is None:
            return SlackWorkReceipt("IDLE")
        try:
            payload = self._reader.get_json(
                uri=claim.payload_ref, expected_hash=claim.payload_hash, max_bytes=16_384
            )
            post = SlackPost(
                channel=str(payload.get("channel", "")),
                thread_ts=str(payload.get("thread_ts", "")),
                text=str(payload.get("text", "")),
            )
            token = self._secrets.access(self._installation.bot_token_ref, max_bytes=4_096)
            # Hold the binding/delivery share lock from the final epoch check
            # through provider submission. Revocation therefore fences either
            # before the call or after this exact call, never between the two.
            with self._connect() as connection, connection.transaction():
                deliveries = LiaisonDeliveryStore(connection)
                deliveries.authorize_submission(scope=scope, claim=claim)
                provider_message_id = self._slack.post_message(
                    bot_token=token,
                    post=post,
                    client_message_id=claim.provider_idempotency_key,
                )
                if not deliveries.complete(
                    scope=scope,
                    claim=claim,
                    provider_message_id=provider_message_id,
                ):
                    raise RuntimeError("Slack delivery claim was lost after provider success")
            return SlackWorkReceipt("DELIVERED", delivery_id=claim.delivery_id)
        except SlackDeliveryError as error:
            with self._connect() as connection, connection.transaction():
                deliveries = LiaisonDeliveryStore(connection)
                if error.retryable:
                    deliveries.fail(
                        scope=scope,
                        claim=claim,
                        retry_at=datetime.now(UTC) + timedelta(seconds=30),
                    )
                else:
                    deliveries.fence(scope=scope, claim=claim)
            return SlackWorkReceipt(
                "RETRY_SCHEDULED" if error.retryable else "FENCED",
                delivery_id=claim.delivery_id,
            )
        except Exception:
            with self._connect() as connection, connection.transaction():
                LiaisonDeliveryStore(connection).fail(
                    scope=scope,
                    claim=claim,
                    retry_at=datetime.now(UTC) + timedelta(seconds=30),
                )
            return SlackWorkReceipt("FAILED", delivery_id=claim.delivery_id)


class SlackSubscriptionWorker:
    """Freeze deterministic catch-up deltas for one due Slack subscription."""

    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        installation: SlackInstallation,
        writer: PayloadWriter,
        authority: Callable[[str], tuple[Sequence[tuple[str, str]], int]],
    ) -> None:
        self._connect = connect
        self._installation = installation
        self._writer = writer
        self._authority = authority

    def process_one(self, *, owner: str) -> SlackWorkReceipt:
        scope = self._installation.scope
        with self._connect() as connection, connection.transaction():
            claim = LiaisonSubscriptionStore(connection).claim_due(
                scope=scope, owner=owner, channel_kind="SLACK"
            )
        if claim is None:
            return SlackWorkReceipt("IDLE")
        try:
            authorized_records, policy_epoch = self._authority(claim.principal)
            with (
                self._connect() as connection,
                connection.transaction(),
                projection_read(
                    connection,
                    scope=scope,
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
                    scope=scope,
                    anchor=claim.anchor,
                    cursor=Cursor(claim.last_delivered_sequence, claim.policy_epoch),
                    authorized_records=authorized_records,
                    policy_epoch=policy_epoch,
                )
            next_delivery = _next_subscription_delivery(claim.cadence)
            if not brief.deltas:
                with self._connect() as connection, connection.transaction():
                    completed = LiaisonSubscriptionStore(connection).complete_interval(
                        scope=scope,
                        claim=claim,
                        to_sequence=brief.cursor.scope_sequence,
                        next_delivery_at=next_delivery,
                        policy_epoch=policy_epoch,
                        visible_delta_count=0,
                        delivery_id=None,
                    )
                    if not completed:
                        raise RuntimeError("subscription claim was replaced before cursor advance")
                return SlackWorkReceipt("SUBSCRIPTION_SCANNED")

            assert claim.binding_id is not None and claim.binding_epoch is not None
            assert claim.external_conversation_id is not None
            _, channel, thread_ts = claim.external_conversation_id.split(":", 2)
            classification = max(
                (item.classification for item in brief.deltas), key=_classification_rank
            )
            ceiling = claim.classification_ceiling or "PUBLIC"
            over_ceiling = _classification_rank(classification) > _classification_rank(ceiling)
            payload = {
                "schema_version": 1,
                "channel": channel,
                "thread_ts": thread_ts,
                "text": (
                    "New updates exceed this channel's classification ceiling. "
                    f"Open Solvan: {self._installation.console_base_url}"
                    if over_ceiling
                    else _render_subscription_text(
                        claim,
                        brief.deltas,
                        brief.remaining,
                        console_base_url=self._installation.console_base_url,
                    )
                ),
            }
            receipt = self._writer.put_json(
                object_name=(
                    f"liaison/subscriptions/{claim.subscription_id}/"
                    f"{claim.last_delivered_sequence}-{brief.cursor.scope_sequence}.json"
                ),
                value=payload,
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
                    scope=scope,
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
                completed = LiaisonSubscriptionStore(connection).complete_interval(
                    scope=scope,
                    claim=claim,
                    to_sequence=brief.cursor.scope_sequence,
                    next_delivery_at=next_delivery,
                    policy_epoch=policy_epoch,
                    visible_delta_count=len(brief.deltas),
                    delivery_id=delivery_id,
                )
                if not completed:
                    raise RuntimeError("subscription claim was replaced before delivery enqueue")
            return SlackWorkReceipt("SUBSCRIPTION_QUEUED", delivery_id=delivery_id)
        except Exception:
            with self._connect() as connection, connection.transaction():
                LiaisonSubscriptionStore(connection).retry(
                    scope=scope,
                    claim=claim,
                    retry_at=datetime.now(UTC) + timedelta(seconds=30),
                )
            return SlackWorkReceipt("FAILED")


def _next_subscription_delivery(cadence: Cadence) -> datetime:
    delay = {
        Cadence.ON_EVENT: timedelta(seconds=30),
        Cadence.DAILY_DIGEST: timedelta(days=1),
        Cadence.ON_CLOSE: timedelta(minutes=5),
    }[cadence]
    return datetime.now(UTC) + delay


def _render_subscription_text(
    claim: SubscriptionClaim,
    deltas: Sequence[Any],
    remaining: int,
    *,
    console_base_url: str,
) -> str:
    lines = [f"Updates for {claim.anchor.label()}:"]
    lines.extend(f"• {item.phrase} [{item.authority_status.lower()}]" for item in deltas)
    if remaining:
        lines.append(f"• {remaining} more authorized update(s) remain for the next brief.")
    lines.append(f"Open Solvan for governed details and decisions: {console_base_url}")
    return "\n".join(lines)[:4_000]


def _classification_rank(value: str) -> int:
    return {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}[value]
