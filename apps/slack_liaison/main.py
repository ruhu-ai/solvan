"""Public signed webhook plus private durable Slack Liaison workers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol, cast

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from apps.api.console_projection import live_console_snapshot
from apps.api.liaison import liaison_registry
from apps.api.liaison_service import LiaisonService
from apps.slack_liaison.contracts import SlackInstallation, installation_from_environment
from apps.slack_liaison.service import (
    SlackAnswerWorker,
    SlackDeliveryWorker,
    SlackIngressService,
    SlackSubscriptionWorker,
)
from solvan.application.slack_channel import (
    SlackEventsEnvelope,
    SlackIngressError,
    SlackUrlVerification,
    peek_slack_team_id,
    verify_slack_request,
)
from solvan.observability import instrument_fastapi
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.secret_manager import SecretManagerReader
from solvan.platform.slack import SlackWebClient


class TokenVerifier(Protocol):
    def verify(self, token: str, *, audience: str) -> Mapping[str, Any]: ...


class GoogleTokenVerifier:
    def verify(self, token: str, *, audience: str) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
                token, GoogleRequest(), audience=audience
            ),
        )


class TickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_jobs: int = Field(default=10, ge=1, le=25)


class TickResponse(BaseModel):
    answered: int
    subscriptions: int
    delivered: int
    failed: int


async def _bounded_body(request: Request) -> bytes:
    content = bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content) > 64 * 1024:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
    return bytes(content)


def _require_worker(
    authorization: str | None,
    *,
    installation: SlackInstallation,
    verifier: TokenVerifier,
) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing worker identity")
    try:
        claims = verifier.verify(
            authorization.removeprefix("Bearer "), audience=installation.worker_audience
        )
    except (GoogleAuthError, ValueError) as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid worker identity") from error
    email = claims.get("email")
    if claims.get("email_verified") is not True or email != installation.worker_service_account:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the Slack worker")


def create_app(
    *,
    installation_provider: Callable[[], SlackInstallation] = installation_from_environment,
    token_verifier: TokenVerifier | None = None,
) -> FastAPI:
    app = FastAPI(title="Solvan Slack Liaison", version="0.1.0")
    verifier = token_verifier or GoogleTokenVerifier()

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/slack/events")
    async def slack_events(
        request: Request,
        slack_timestamp: str | None = Header(default=None, alias="X-Slack-Request-Timestamp"),
        slack_signature: str | None = Header(default=None, alias="X-Slack-Signature"),
    ) -> dict[str, object]:
        body = await _bounded_body(request)
        installation = installation_provider()
        try:
            if peek_slack_team_id(body) != installation.team_id:
                raise SlackIngressError("Slack installation is unknown")
            secret = SecretManagerReader(authorized_session()).access(
                installation.signing_secret_ref, max_bytes=4_096
            )
            verified = verify_slack_request(
                signing_secret=secret,
                timestamp=slack_timestamp,
                signature=slack_signature,
                body=body,
            )
        except SlackIngressError as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid Slack request") from error
        if isinstance(verified, SlackUrlVerification):
            return {"challenge": verified.challenge}
        assert isinstance(verified, SlackEventsEnvelope)
        SlackIngressService(connect=connect_database, installation=installation).ingest(verified)
        # Do not expose binding, thread, or policy state to the webhook caller.
        return {"ok": True}

    @app.post("/internal/tick", response_model=TickResponse)
    def tick(
        request: TickRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> TickResponse:
        installation = installation_provider()
        _require_worker(authorization, installation=installation, verifier=verifier)
        google = authorized_session()

        def snapshot() -> dict[str, Any]:
            with connect_database() as connection:
                return live_console_snapshot(connection, scope=installation.scope)

        liaison = LiaisonService(
            connect=connect_database,
            snapshot_provider=snapshot,
            registry_provider=liaison_registry,
        )
        writer = GcsEvidenceWriter(bucket=installation.payload_bucket, session=google)
        answerer = SlackAnswerWorker(
            connect=connect_database,
            installation=installation,
            liaison=liaison,
            writer=writer,
        )

        def subscription_authority(principal: str) -> tuple[tuple[tuple[str, str], ...], int]:
            reader = liaison.reader(principal=principal, scope=installation.scope)
            with connect_database() as connection:
                epoch = current_policy_epoch(
                    connection, scope=installation.scope, principal=principal
                )
            return reader.authorized_records(), epoch

        subscriptions = SlackSubscriptionWorker(
            connect=connect_database,
            installation=installation,
            writer=writer,
            authority=subscription_authority,
        )
        answered = subscription_runs = delivered = failed = 0
        with httpx.Client() as slack_http:
            sender = SlackDeliveryWorker(
                connect=connect_database,
                installation=installation,
                reader=GcsEvidenceReader(
                    allowed_buckets=frozenset({installation.payload_bucket}), session=google
                ),
                secrets=SecretManagerReader(google),
                slack=SlackWebClient(slack_http),
            )
            for _ in range(request.maximum_jobs):
                answer = answerer.process_one(owner="slack-liaison-answerer")
                subscription = subscriptions.process_one(owner="slack-liaison-subscriptions")
                delivery = sender.process_one(owner="slack-liaison-sender")
                if answer.status == "DELIVERY_QUEUED":
                    answered += 1
                elif answer.status == "FAILED":
                    failed += 1
                if subscription.status in {"SUBSCRIPTION_QUEUED", "SUBSCRIPTION_SCANNED"}:
                    subscription_runs += 1
                elif subscription.status == "FAILED":
                    failed += 1
                if delivery.status == "DELIVERED":
                    delivered += 1
                elif delivery.status in {"FAILED", "FENCED", "RETRY_SCHEDULED"}:
                    failed += 1
                if answer.status == subscription.status == delivery.status == "IDLE":
                    break
        return TickResponse(
            answered=answered,
            subscriptions=subscription_runs,
            delivered=delivered,
            failed=failed,
        )

    return app


app = instrument_fastapi(create_app(), service_name="slack-liaison")
