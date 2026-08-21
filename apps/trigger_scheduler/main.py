"""Private, identity-bound trigger ingress and restart-safe scheduler."""

from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, status
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.operational_guidance import GuidanceError, VerifiedTriggerEvent
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence import PostgresTriggerPolicyStore
from solvan.platform.database import connect_database


class TriggerSourceEvent(BaseModel):
    """Verified-adapter material; target state is always derived server-side."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_event_id: str = Field(min_length=1, max_length=240)
    source_sequence: int = Field(ge=0)
    source_event_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    connection_epoch: int = Field(ge=1)
    target_key: str = Field(min_length=1, max_length=300)
    region: str = Field(min_length=1, max_length=80)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    observed_at: datetime


class TriggerIngressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    policy_key: str = Field(pattern=r"^[a-z0-9]+([._-][a-z0-9]+)*$")
    policy_version: str = Field(min_length=1, max_length=120)
    event: TriggerSourceEvent


class TriggerTickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    maximum_items: int = Field(default=20, ge=1, le=100)


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


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required trigger scheduler setting {name} is missing")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _allowed_principals(name: str) -> frozenset[str]:
    values = frozenset(value.strip() for value in _required(name).split(",") if value.strip())
    if not values or any("@" not in value for value in values):
        raise RuntimeError(f"{name} must contain exact service-account emails")
    return values


def _authorize(
    authorization: str | None,
    *,
    audience: str,
    allowed_principals: frozenset[str],
    verifier: TokenVerifier,
) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer identity token")
    try:
        claims = verifier.verify(authorization.removeprefix("Bearer "), audience=audience)
    except Exception as error:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid bearer identity token"
        ) from error
    principal = claims.get("email")
    verified = claims.get("email_verified")
    if (
        not isinstance(principal, str)
        or verified is not True
        or principal not in allowed_principals
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller identity is not authorized")
    return principal


def create_app(*, token_verifier: TokenVerifier | None = None) -> FastAPI:
    app = FastAPI(title="Solvan Trigger Scheduler", version="0.1.0")
    verifier = token_verifier or GoogleTokenVerifier()

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/trigger-events", status_code=status.HTTP_202_ACCEPTED)
    def ingest(
        request: TriggerIngressRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        _authorize(
            authorization,
            audience=_required("SOLVAN_TRIGGER_SCHEDULER_AUDIENCE"),
            allowed_principals=_allowed_principals("SOLVAN_TRIGGER_SOURCE_PRINCIPALS"),
            verifier=verifier,
        )
        scope = _scope()
        try:
            with connect_database() as connection, connection.transaction():
                store = PostgresTriggerPolicyStore(connection)
                target_hash = store.current_target_snapshot_hash(
                    scope=scope, target_key=request.event.target_key
                )
                result = store.accept_event(
                    scope=scope,
                    policy_key=request.policy_key,
                    policy_version=request.policy_version,
                    event=VerifiedTriggerEvent(
                        **request.event.model_dump(), target_snapshot_hash=target_hash
                    ),
                )
        except GuidanceError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {
            "firing_id": result.firing_id,
            "status": result.status,
            "created": result.created,
        }

    @app.post("/internal/v1/tick")
    def tick(
        request: TriggerTickRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, int]:
        _authorize(
            authorization,
            audience=_required("SOLVAN_TRIGGER_SCHEDULER_AUDIENCE"),
            allowed_principals=_allowed_principals("SOLVAN_TRIGGER_SCHEDULER_PRINCIPALS"),
            verifier=verifier,
        )
        scope = _scope()
        owner = f"{socket.gethostname()}:{uuid4()}"
        claimed = enqueued = blocked = 0
        with connect_database() as connection:
            store = PostgresTriggerPolicyStore(connection)
            for _index in range(request.maximum_items):
                with connection.transaction():
                    claim = store.claim_due(
                        scope=scope, owner=owner, now=datetime.now(UTC), lease_seconds=60
                    )
                if claim is None:
                    break
                claimed += 1
                try:
                    with connection.transaction():
                        target_hash = store.current_target_snapshot_hash(
                            scope=scope, target_key=claim.target_key
                        )
                except GuidanceError:
                    connection.rollback()
                    with connection.transaction():
                        store.block_claim(scope=scope, claim=claim, reason="TARGET_UNRESOLVED")
                    blocked += 1
                    continue
                with connection.transaction():
                    result = store.enqueue_claim(
                        scope=scope,
                        claim=claim,
                        observed_target_snapshot_hash=target_hash,
                    )
                if result.status == "ENQUEUED":
                    enqueued += 1
                else:
                    blocked += 1
        return {"claimed": claimed, "enqueued": enqueued, "blocked": blocked}

    return app


app = instrument_fastapi(create_app(), service_name="trigger-scheduler")
