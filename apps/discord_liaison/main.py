"""Signed Discord ingress and private durable answer/delivery workers."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from apps.api.console_projection import live_console_snapshot
from apps.api.liaison import liaison_registry
from apps.api.liaison_service import LiaisonService
from apps.channel_liaison.subscriptions import ExternalSubscriptionWorker
from solvan.application.liaison.parts import PartKind, user_part
from solvan.application.liaison.redaction import classify
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.liaison_channels import ChannelBindingError, LiaisonChannelStore
from solvan.persistence.liaison_delivery import LiaisonDeliveryStore
from solvan.persistence.liaison_inbound import LiaisonInboundStore
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_store import LiaisonStore, MessageRecord
from solvan.persistence.liaison_subscriptions import SubscriptionClaim
from solvan.platform.database import connect_database
from solvan.platform.discord import (
    DiscordDeliveryError,
    DiscordError,
    DiscordPost,
    DiscordWebClient,
    verify_interaction,
)
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.secret_manager import SecretManagerReader


class TickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_jobs: int = Field(default=10, ge=1, le=25)


class TickResponse(BaseModel):
    answered: int
    subscriptions: int
    delivered: int
    failed: int


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required Discord setting {name} is missing")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


async def _body(request: Request) -> bytes:
    value = await request.body()
    if len(value) > 64 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
    return value


def _option(interaction: dict[str, Any], name: str) -> str | None:
    data = interaction.get("data")
    options = data.get("options", []) if isinstance(data, dict) else []
    for item in options if isinstance(options, list) else []:
        if (
            isinstance(item, dict)
            and item.get("name") == name
            and isinstance(item.get("value"), str)
        ):
            return str(item["value"])
    return None


def _worker_identity(authorization: str | None) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing worker identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "),
            GoogleRequest(),
            audience=_required("SOLVAN_DISCORD_LIAISON_AUDIENCE"),
        )
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid worker identity") from error
    if claims.get("email_verified") is not True or claims.get("email") != _required(
        "SOLVAN_DISCORD_LIAISON_SERVICE_ACCOUNT"
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the Discord worker")


def _render(message: MessageRecord) -> str:
    lines: list[str] = []
    for part in message.parts:
        sentence = part.payload.get("sentence")
        if isinstance(sentence, str) and sentence.strip():
            lines.append(sentence.strip())
        elif part.kind is PartKind.CONTENT_WITHHELD:
            lines.append("Some content was withheld by the reader-authority filter.")
        elif part.kind is PartKind.STEER_DRAFT:
            lines.append("A bounded evidence read can be requested from the Solvan console.")
        elif part.kind in {PartKind.ERROR, PartKind.PARKED_REQUEST}:
            lines.append("This turn needs attention in the Solvan console.")
    if not lines:
        lines.append("Solvan recorded the request but has no channel-safe answer to show.")
    lines.append(
        f"Open Solvan: {_required('SOLVAN_CONSOLE_BASE_URL')}/conversations/{message.thread_id}"
    )
    return "\n\n".join(lines)[:2_000]


def _render_subscription(
    claim: SubscriptionClaim, deltas: Any, remaining: int, over_ceiling: bool
) -> dict[str, Any]:
    assert claim.external_conversation_id is not None
    _, channel_id = claim.external_conversation_id.split(":", 1)
    if over_ceiling:
        content = "Updates exceed this channel's classification ceiling. Open Solvan."
    else:
        lines = [f"Updates for {claim.anchor.label()}:"]
        lines.extend(f"• {item.phrase} [{item.authority_status.lower()}]" for item in deltas)
        if remaining:
            lines.append(f"• {remaining} more authorized update(s) remain.")
        content = "\n".join(lines)
    return {"schema_version": 1, "channel_id": channel_id, "content": content[:2_000]}


def _answer_one(*, owner: str) -> bool:
    scope = _scope()
    with connect_database() as connection, connection.transaction():
        claim = LiaisonInboundStore(connection).claim_due(
            scope=scope, channel_kind="DISCORD", owner=owner
        )
    if claim is None:
        return False
    try:
        with connect_database() as connection:
            thread = LiaisonStore(connection).thread(scope=scope, thread_id=claim.thread_id)
            if thread is None:
                raise RuntimeError("mapped Discord thread disappeared")

        def snapshot() -> dict[str, Any]:
            with connect_database() as connection:
                return live_console_snapshot(connection, scope=scope)

        liaison = LiaisonService(
            connect=connect_database,
            snapshot_provider=snapshot,
            registry_provider=liaison_registry,
        )
        outcome = liaison.answer_persisted_channel_message(
            scope=scope,
            principal=claim.binding.principal,
            anchor=thread.anchor,
            thread_id=claim.thread_id,
            user_message_id=claim.message_id,
            idempotency_key=f"discord:{claim.binding.binding_id}:{claim.external_event_id}",
        )
        with connect_database() as connection:
            reader = liaison.reader(principal=claim.binding.principal, scope=scope)
            messages = LiaisonStore(connection).transcript(
                scope=scope,
                thread_id=claim.thread_id,
                reader_principal=claim.binding.principal,
                authorized_records=list(reader.authorized_records_for_anchor(thread.anchor)),
            )
            external = LiaisonChannelStore(connection).external_conversation_for_thread(
                scope=scope,
                binding_id=claim.binding.binding_id,
                binding_epoch=claim.binding.epoch,
                thread_id=claim.thread_id,
            )
        answer = next(item for item in messages if item.id == outcome.answer_message_id)
        _, channel_id = external.split(":", 1)
        payload = {"schema_version": 1, "channel_id": channel_id, "content": _render(answer)}
        receipt = GcsEvidenceWriter(
            bucket=_required("SOLVAN_LIAISON_PAYLOAD_BUCKET"), session=authorized_session()
        ).put_json(
            object_name=f"liaison/deliveries/{outcome.answer_message_id}.json", value=payload
        )
        with connect_database() as connection, connection.transaction():
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
                classification=answer.classification,
                redaction_verdict_ref=f"redaction://egress/{outcome.answer_message_id}",
                access_set_hash=canonical_sha256(
                    {"principal": claim.binding.principal, "message": outcome.answer_message_id}
                ),
                policy_epoch=policy_epoch,
                provider_idempotency_key=str(
                    uuid5(
                        NAMESPACE_URL,
                        f"discord:{claim.binding.binding_id}:{outcome.answer_message_id}",
                    )
                ),
            )
            if not LiaisonInboundStore(connection).complete(scope=scope, claim=claim):
                raise RuntimeError("Discord inbound claim was lost")
        return bool(delivery_id)
    except Exception:
        with connect_database() as connection, connection.transaction():
            LiaisonInboundStore(connection).fail(
                scope=scope,
                claim=claim,
                retry_at=datetime.now(UTC) + timedelta(seconds=30),
                reason="SAFE_PROCESSING_FAILURE",
            )
        raise


def _deliver_one(*, owner: str) -> bool:
    scope = _scope()
    with connect_database() as connection, connection.transaction():
        claim = LiaisonDeliveryStore(connection).claim_due(
            scope=scope, channel_kind="DISCORD", owner=owner
        )
    if claim is None:
        return False
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({_required("SOLVAN_LIAISON_PAYLOAD_BUCKET")}),
        session=authorized_session(),
    )
    payload = reader.get_json(
        uri=claim.payload_ref, expected_hash=claim.payload_hash, max_bytes=16_384
    )
    post = DiscordPost(
        channel_id=str(payload.get("channel_id", "")), content=str(payload.get("content", ""))
    )
    token = SecretManagerReader(authorized_session()).access(
        _required("SOLVAN_DISCORD_BOT_TOKEN_REF"), max_bytes=4_096
    )
    try:
        with httpx.Client() as client, connect_database() as connection, connection.transaction():
            deliveries = LiaisonDeliveryStore(connection)
            deliveries.authorize_submission(scope=scope, claim=claim)
            provider_id = DiscordWebClient(client).post_message(bot_token=token, post=post)
            if not deliveries.complete(scope=scope, claim=claim, provider_message_id=provider_id):
                raise RuntimeError("Discord delivery claim was lost")
        return True
    except DiscordDeliveryError as error:
        with connect_database() as connection, connection.transaction():
            deliveries = LiaisonDeliveryStore(connection)
            if error.retryable:
                deliveries.fail(
                    scope=scope,
                    claim=claim,
                    retry_at=datetime.now(UTC) + timedelta(seconds=30),
                )
            else:
                deliveries.fence(scope=scope, claim=claim)
        raise
    except Exception:
        with connect_database() as connection, connection.transaction():
            LiaisonDeliveryStore(connection).fail(
                scope=scope,
                claim=claim,
                retry_at=datetime.now(UTC) + timedelta(seconds=30),
            )
        raise


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Discord Liaison", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/discord/interactions")
    async def interactions(
        request: Request,
        signature: str | None = Header(default=None, alias="X-Signature-Ed25519"),
        timestamp: str | None = Header(default=None, alias="X-Signature-Timestamp"),
    ) -> dict[str, Any]:
        try:
            interaction = verify_interaction(
                public_key_hex=SecretManagerReader(authorized_session())
                .access(_required("SOLVAN_DISCORD_PUBLIC_KEY_REF"), max_bytes=256)
                .decode("ascii"),
                signature_hex=signature,
                timestamp=timestamp,
                body=await _body(request),
            )
        except DiscordError as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid Discord request") from error
        if interaction.get("type") == 1:
            return {"type": 1}
        member = interaction.get("member")
        user = member.get("user") if isinstance(member, dict) else interaction.get("user")
        user_id = user.get("id") if isinstance(user, dict) else None
        guild_id, channel_id, event_id = (
            interaction.get("guild_id"),
            interaction.get("channel_id"),
            interaction.get("id"),
        )
        if not all(
            isinstance(value, str) and value for value in (user_id, guild_id, channel_id, event_id)
        ):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Discord identity missing")
        assert isinstance(user_id, str)
        assert isinstance(guild_id, str)
        assert isinstance(channel_id, str)
        assert isinstance(event_id, str)
        identity = f"discord:{_required('SOLVAN_DISCORD_APPLICATION_ID')}:{guild_id}:{user_id}"
        action = _option(interaction, "action")
        if action == "enroll":
            with connect_database() as connection, connection.transaction():
                try:
                    LiaisonChannelStore(connection).consume_enrollment(
                        scope=_scope(),
                        channel_kind="DISCORD",
                        channel_identity=identity,
                        nonce=_option(interaction, "code") or "",
                    )
                except ChannelBindingError:
                    return {"type": 4, "data": {"content": "Enrollment refused.", "flags": 64}}
            return {"type": 4, "data": {"content": "Solvan channel enrolled.", "flags": 64}}
        question = _option(interaction, "question")
        if action != "ask" or not question:
            return {"type": 4, "data": {"content": "Use action=ask or action=enroll.", "flags": 64}}
        verdict, scope = classify(question), _scope()
        with connect_database() as connection, connection.transaction():
            channels = LiaisonChannelStore(connection)
            binding = channels.active_binding(
                scope=scope, channel_kind="DISCORD", channel_identity=identity
            )
            if binding is None:
                return {
                    "type": 4,
                    "data": {"content": "Enroll this Discord identity first.", "flags": 64},
                }
            mapped = channels.enroll_scope_thread(
                scope=scope, binding=binding, external_conversation_id=f"discord:{channel_id}"
            )
            inbound = channels.record_inbound(
                scope=scope,
                binding=binding,
                external_event_id=event_id,
                payload_hash=verdict.digest,
            )
            if inbound.created:
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
                                scope=scope, thread_id=mapped.thread_id, principal=binding.principal
                            ),
                            classification=str(verdict.classification),
                        )
                    ],
                )
                if not channels.bind_inbound_message(
                    scope=scope,
                    binding=binding,
                    external_event_id=event_id,
                    thread_id=mapped.thread_id,
                    message_id=message_id,
                ):
                    raise RuntimeError("Discord event lost its bind race")
        return {"type": 4, "data": {"content": "Solvan queued the request.", "flags": 64}}

    @app.post("/internal/tick", response_model=TickResponse)
    def tick(
        request: TickRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> TickResponse:
        _worker_identity(authorization)

        def authority(principal: str) -> tuple[tuple[tuple[str, str], ...], int]:
            def snapshot() -> dict[str, Any]:
                with connect_database() as connection:
                    return live_console_snapshot(connection, scope=_scope())

            liaison = LiaisonService(
                connect=connect_database,
                snapshot_provider=snapshot,
                registry_provider=liaison_registry,
            )
            with connect_database() as connection:
                epoch = current_policy_epoch(connection, scope=_scope(), principal=principal)
            return liaison.reader(principal=principal, scope=_scope()).authorized_records(), epoch

        subscription_worker = ExternalSubscriptionWorker(
            connect=connect_database,
            scope=_scope(),
            channel_kind="DISCORD",
            writer=GcsEvidenceWriter(
                bucket=_required("SOLVAN_LIAISON_PAYLOAD_BUCKET"), session=authorized_session()
            ),
            authority=authority,
            render=_render_subscription,
        )
        answered = subscriptions = delivered = failed = 0
        for index in range(request.maximum_jobs):
            did_work = False
            try:
                if _answer_one(owner=f"discord-answer:{index}"):
                    answered += 1
                    did_work = True
            except Exception:
                failed += 1
                did_work = True
            subscription = subscription_worker.process_one(owner=f"discord-subscription:{index}")
            if subscription.status == "QUEUED":
                subscriptions += 1
                did_work = True
            elif subscription.status == "FAILED":
                failed += 1
                did_work = True
            try:
                if _deliver_one(owner=f"discord-delivery:{index}"):
                    delivered += 1
                    did_work = True
            except Exception:
                failed += 1
                did_work = True
            if not did_work:
                break
        return TickResponse(
            answered=answered,
            subscriptions=subscriptions,
            delivered=delivered,
            failed=failed,
        )

    return app


app = instrument_fastapi(create_app(), service_name="discord-liaison")
