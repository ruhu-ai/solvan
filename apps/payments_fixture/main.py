"""Cloud Run payments fixture with isolated synthetic and private admin APIs."""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any, Literal, cast

from fastapi import FastAPI, Header, HTTPException, Request, status
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from psycopg.errors import UndefinedTable
from pydantic import BaseModel, ConfigDict, Field

from apps.payments_fixture.service import (
    PaymentsFixtureService,
    PaymentUnavailable,
    PoolPreconditionFailed,
)
from solvan.observability import instrument_fastapi
from solvan.platform.database import DatabaseSettings, connect_database

_LOGGER = logging.getLogger("solvan.telemetry")


class SyntheticPaymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    payment_id: str = Field(min_length=1, max_length=128)
    amount_minor: int = Field(gt=0, le=1_000_000)
    metadata: str | None = Field(default=None, min_length=1, max_length=500)


class SyntheticPaymentResponse(BaseModel):
    payment_id: str
    duplicate: bool
    revision: str


class PoolOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    admin_operation: Literal["RECYCLE_DB_POOL"]
    drain_timeout_ms: Literal[5000]


class RecyclePoolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    action_id: str
    expected_pool_generation: str
    operation: PoolOperation


class PoolStateResponse(BaseModel):
    pool_generation: str
    state_ref: str


class RecycleResponse(BaseModel):
    request_id: str
    returned_at: datetime


class RecycleStatusResponse(BaseModel):
    result: Literal["EFFECT_CONFIRMED", "NO_EFFECT_CONFIRMED", "UNKNOWN"]
    state_ref: str | None
    pool_generation: str | None
    reconciled_at: datetime


def _setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required payments fixture setting {name} is missing")
    return value


def _authorize_actuator(authorization: str | None) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer identity token")
    try:
        raw = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "),
            GoogleAuthRequest(),
            _setting("SOLVAN_PAYMENTS_AUDIENCE"),
        )
    except ValueError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid identity token") from error
    claims = cast(dict[str, Any], raw)
    if (
        claims.get("email") != _setting("SOLVAN_ACTUATOR_CALLER")
        or claims.get("email_verified") is not True
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the Actuator identity")


def create_app(
    service_factory: Callable[[], PaymentsFixtureService] | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        service = service_factory() if service_factory is not None else _production_service()
        # The migration creating solvan.fixture_runtime_state runs after this
        # service is deployed. A cold start before it lands must not kill the
        # container, or the revision never becomes ready and the release cannot
        # reach the migration phase. The read is retried on first use.
        with suppress(UndefinedTable):
            service.initialize_schema()
        app.state.payments = service
        try:
            yield
        finally:
            service.close()

    app = FastAPI(title="Solvan Payments Fixture", version="2.8.1", lifespan=lifespan)

    def service(request: Request) -> PaymentsFixtureService:
        return cast(PaymentsFixtureService, request.app.state.payments)

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/v1/synthetic/payments", response_model=SyntheticPaymentResponse)
    def create_payment(
        body: SyntheticPaymentRequest,
        request: Request,
        idempotency_key: str = Header(alias="idempotency-key"),
    ) -> SyntheticPaymentResponse:
        if body.metadata is not None:
            _LOGGER.info(
                "solvan.fixture.untrusted_payment_metadata",
                extra={
                    "solvan.trust_label": "UNTRUSTED_TOOL_DATA",
                    "solvan.synthetic_fixture": True,
                    "solvan.untrusted_metadata": body.metadata,
                },
            )
        try:
            result = service(request).create_synthetic_payment(
                idempotency_key=idempotency_key,
                payment_id=body.payment_id,
                amount_minor=body.amount_minor,
            )
        except PaymentUnavailable as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        return SyntheticPaymentResponse(
            payment_id=result.payment_id,
            duplicate=result.duplicate,
            revision=result.revision,
        )

    @app.get("/v1/admin/connection-pool", response_model=PoolStateResponse)
    def pool_state(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> PoolStateResponse:
        _authorize_actuator(authorization)
        generation = service(request).pool_generation
        return PoolStateResponse(
            pool_generation=generation,
            state_ref=f"payments://connection-pool/{generation}",
        )

    @app.post("/v1/admin/connection-pool:recycle", response_model=RecycleResponse)
    def recycle_pool(
        body: RecyclePoolRequest,
        request: Request,
        authorization: str | None = Header(default=None),
        idempotency_key: str = Header(alias="idempotency-key"),
    ) -> RecycleResponse:
        _authorize_actuator(authorization)
        try:
            result = service(request).recycle_pool(
                action_id=body.action_id,
                idempotency_key=idempotency_key,
                expected_generation=body.expected_pool_generation,
                request_id=f"pool-recycle-{uuid.uuid4().hex}",
            )
        except PoolPreconditionFailed as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return RecycleResponse(request_id=result.request_id, returned_at=datetime.now(UTC))

    @app.get("/v1/admin/actions/{action_id}", response_model=RecycleStatusResponse)
    def action_status(
        action_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> RecycleStatusResponse:
        _authorize_actuator(authorization)
        result = service(request).action_status(action_id)
        now = datetime.now(UTC)
        if result is None:
            return RecycleStatusResponse(
                result="UNKNOWN",
                state_ref=None,
                pool_generation=None,
                reconciled_at=now,
            )
        return RecycleStatusResponse(
            result="EFFECT_CONFIRMED",
            state_ref=f"payments://connection-pool/{result.after_generation}",
            pool_generation=result.after_generation,
            reconciled_at=now,
        )

    return app


def _production_service() -> PaymentsFixtureService:
    database_url = os.environ.get("PAYMENTS_DATABASE_URL")
    if database_url:
        return PaymentsFixtureService(
            database_url=database_url,
            revision=os.environ.get("PAYMENTS_REVISION", "v2.8.0"),
        )
    settings = DatabaseSettings.from_environment()
    return PaymentsFixtureService(
        database_url=None,
        revision=os.environ.get("PAYMENTS_REVISION", "v2.8.0"),
        connection_factory=lambda: connect_database(settings),
    )


app = instrument_fastapi(create_app(), service_name="payments-fixture")
