"""OIDC-authenticated email relay ingress and deterministic delivery."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx
from fastapi import FastAPI, Header, HTTPException, status
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
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session

_ADDRESS = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,190}$")


class RelayEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=128)
    from_address: str = Field(min_length=3, max_length=254)
    external_thread_id: str = Field(min_length=1, max_length=128)
    subject: str = Field(default="", max_length=500)
    plain_text: str = Field(min_length=1, max_length=16_000)


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
        raise RuntimeError(f"required email setting {name} is missing")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _relay_url() -> str:
    value = _required("SOLVAN_EMAIL_RELAY_URL")
    if not value.startswith("https://"):
        raise RuntimeError("email relay URL must use HTTPS")
    return value


def _post_to_relay(*, payload: Any, idempotency_key: str) -> httpx.Response:
    """Submit through the private relay with a Cloud Run audience token."""

    relay_url = _relay_url()
    token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
        GoogleRequest(), relay_url
    )
    return httpx.post(
        relay_url,
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": idempotency_key,
        },
        timeout=15,
    )


def _verified_service(authorization: str | None, *, audience: str, expected: str) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing relay identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "), GoogleRequest(), audience=audience
        )
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid relay identity") from error
    if claims.get("email_verified") is not True or claims.get("email") != expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "relay identity is not allowed")


def _render(message: MessageRecord) -> str:
    lines: list[str] = []
    for part in message.parts:
        sentence = part.payload.get("sentence")
        if isinstance(sentence, str) and sentence.strip():
            lines.append(sentence.strip())
        elif part.kind is PartKind.CONTENT_WITHHELD:
            lines.append("Some content was withheld by the reader-authority filter.")
        elif part.kind is PartKind.STEER_DRAFT:
            lines.append("Request the bounded evidence read from the authenticated Solvan console.")
        elif part.kind in {PartKind.ERROR, PartKind.PARKED_REQUEST}:
            lines.append("This turn needs attention in the authenticated Solvan console.")
    if not lines:
        lines.append("Solvan recorded the request but has no email-safe answer to show.")
    lines.append(
        f"Open Solvan: {_required('SOLVAN_CONSOLE_BASE_URL')}/conversations/{message.thread_id}"
    )
    return "\n\n".join(lines)[:16_000]


def _render_subscription(
    claim: SubscriptionClaim, deltas: Any, remaining: int, over_ceiling: bool
) -> dict[str, Any]:
    assert claim.external_conversation_id is not None
    _, address, relay_thread = claim.external_conversation_id.split(":", 2)
    if over_ceiling:
        content = "Updates exceed this email channel's classification ceiling. Open Solvan."
    else:
        lines = [f"Updates for {claim.anchor.label()}:"]
        lines.extend(f"- {item.phrase} [{item.authority_status.lower()}]" for item in deltas)
        if remaining:
            lines.append(f"- {remaining} more authorized update(s) remain.")
        content = "\n".join(lines)
    return {
        "schema_version": 1,
        "to_address": address,
        "external_thread_id": relay_thread,
        "subject": "Solvan incident updates",
        "plain_text": content[:16_000],
    }


def _answer_one(*, owner: str) -> bool:
    scope = _scope()
    with connect_database() as connection, connection.transaction():
        claim = LiaisonInboundStore(connection).claim_due(
            scope=scope, channel_kind="EMAIL", owner=owner
        )
    if claim is None:
        return False
    try:
        with connect_database() as connection:
            store = LiaisonStore(connection)
            thread = store.thread(scope=scope, thread_id=claim.thread_id)
            if thread is None:
                raise RuntimeError("mapped email thread disappeared")

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
            idempotency_key=f"email:{claim.binding.binding_id}:{claim.external_event_id}",
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
        _, address, relay_thread = external.split(":", 2)
        payload = {
            "schema_version": 1,
            "to_address": address,
            "external_thread_id": relay_thread,
            "subject": "Re: Solvan incident update",
            "plain_text": _render(answer),
        }
        receipt = GcsEvidenceWriter(
            bucket=_required("SOLVAN_LIAISON_PAYLOAD_BUCKET"), session=authorized_session()
        ).put_json(
            object_name=f"liaison/deliveries/{outcome.answer_message_id}.json", value=payload
        )
        with connect_database() as connection, connection.transaction():
            policy_epoch = current_policy_epoch(
                connection, scope=scope, principal=claim.binding.principal
            )
            LiaisonDeliveryStore(connection).queue_direct(
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
                        f"email:{claim.binding.binding_id}:{outcome.answer_message_id}",
                    )
                ),
            )
            if not LiaisonInboundStore(connection).complete(scope=scope, claim=claim):
                raise RuntimeError("email inbound claim was lost")
        return True
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
            scope=scope, channel_kind="EMAIL", owner=owner
        )
    if claim is None:
        return False
    try:
        payload = GcsEvidenceReader(
            allowed_buckets=frozenset({_required("SOLVAN_LIAISON_PAYLOAD_BUCKET")}),
            session=authorized_session(),
        ).get_json(uri=claim.payload_ref, expected_hash=claim.payload_hash, max_bytes=32_768)
        with connect_database() as connection, connection.transaction():
            deliveries = LiaisonDeliveryStore(connection)
            deliveries.authorize_submission(scope=scope, claim=claim)
            response = _post_to_relay(
                payload=payload,
                idempotency_key=claim.provider_idempotency_key,
            )
            response.raise_for_status()
            value = response.json()
            provider_id = value.get("message_id") if isinstance(value, dict) else None
            if not isinstance(provider_id, str) or not provider_id:
                raise RuntimeError("email relay returned no message id")
            if not deliveries.complete(scope=scope, claim=claim, provider_message_id=provider_id):
                raise RuntimeError("email delivery claim was lost")
        return True
    except Exception:
        with connect_database() as connection, connection.transaction():
            LiaisonDeliveryStore(connection).fail(
                scope=scope,
                claim=claim,
                retry_at=datetime.now(UTC) + timedelta(seconds=30),
            )
        raise


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Email Liaison", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/email/events")
    def email_event(
        event: RelayEvent,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, str]:
        _verified_service(
            authorization,
            audience=_required("SOLVAN_EMAIL_LIAISON_AUDIENCE"),
            expected=_required("SOLVAN_EMAIL_RELAY_SERVICE_ACCOUNT"),
        )
        address = event.from_address.casefold()
        if not _ADDRESS.fullmatch(address):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "email address is invalid")
        identity, scope = f"email:{address}", _scope()
        enrollment = re.fullmatch(r"\s*solvan\s+enroll\s+(\S+)\s*", event.plain_text, re.I)
        if enrollment:
            with connect_database() as connection, connection.transaction():
                try:
                    LiaisonChannelStore(connection).consume_enrollment(
                        scope=scope,
                        channel_kind="EMAIL",
                        channel_identity=identity,
                        nonce=enrollment.group(1),
                    )
                except ChannelBindingError:
                    return {"status": "ENROLLMENT_REFUSED"}
            return {"status": "ENROLLED"}
        verdict = classify(event.plain_text)
        with connect_database() as connection, connection.transaction():
            channels = LiaisonChannelStore(connection)
            binding = channels.active_binding(
                scope=scope, channel_kind="EMAIL", channel_identity=identity
            )
            if binding is None:
                return {"status": "UNBOUND"}
            mapped = channels.enroll_scope_thread(
                scope=scope,
                binding=binding,
                external_conversation_id=f"email:{address}:{event.external_thread_id}",
            )
            inbound = channels.record_inbound(
                scope=scope,
                binding=binding,
                external_event_id=event.event_id,
                payload_hash=verdict.digest,
            )
            if not inbound.created:
                return {"status": "DUPLICATE"}
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
                external_event_id=event.event_id,
                thread_id=mapped.thread_id,
                message_id=message_id,
            ):
                raise RuntimeError("email event lost its bind race")
        return {"status": "QUEUED"}

    @app.post("/internal/tick", response_model=TickResponse)
    def tick(
        request: TickRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> TickResponse:
        _verified_service(
            authorization,
            audience=_required("SOLVAN_EMAIL_LIAISON_AUDIENCE"),
            expected=_required("SOLVAN_EMAIL_LIAISON_SERVICE_ACCOUNT"),
        )

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
            channel_kind="EMAIL",
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
                if _answer_one(owner=f"email-answer:{index}"):
                    answered += 1
                    did_work = True
            except Exception:
                failed += 1
                did_work = True
            subscription = subscription_worker.process_one(owner=f"email-subscription:{index}")
            if subscription.status == "QUEUED":
                subscriptions += 1
                did_work = True
            elif subscription.status == "FAILED":
                failed += 1
                did_work = True
            try:
                if _deliver_one(owner=f"email-delivery:{index}"):
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


app = instrument_fastapi(create_app(), service_name="email-liaison")
