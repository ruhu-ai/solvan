"""Cloud Scheduler-triggered durable outbox publisher."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from psycopg import Connection
from pydantic import BaseModel, ConfigDict

from solvan.application.ports import ClaimedEvent, OutboxEnvelope
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.outbox_store import PostgresOutboxStore
from solvan.platform.database import connect_database
from solvan.platform.google_rest import authorized_session
from solvan.platform.pubsub import GooglePubSubPublisher, PublishReceipt


class TickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int


class TickResponse(BaseModel):
    claimed: int
    published: int


class OutboxRepository(Protocol):
    def claim(
        self, *, scope: Scope, owner: str, claim_ttl_ms: int, batch_size: int
    ) -> tuple[ClaimedEvent, ...]: ...

    def load(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> OutboxEnvelope: ...

    def complete(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> None: ...


class EventPublisher(Protocol):
    def publish(self, envelope: OutboxEnvelope) -> PublishReceipt: ...


@dataclass(frozen=True, slots=True)
class PublishStats:
    claimed: int
    published: int


class OutboxPublisherRunner:
    def __init__(
        self,
        *,
        scope: Scope,
        owner: str,
        repository: OutboxRepository,
        publisher: EventPublisher,
    ) -> None:
        self._scope = scope
        self._owner = owner
        self._repository = repository
        self._publisher = publisher

    def run(self, *, batch_size: int = 50) -> PublishStats:
        claims = self._repository.claim(
            scope=self._scope,
            owner=self._owner,
            claim_ttl_ms=120_000,
            batch_size=batch_size,
        )
        published = 0
        for claim in claims:
            envelope = self._repository.load(scope=self._scope, owner=self._owner, claim=claim)
            self._publisher.publish(envelope)
            self._repository.complete(scope=self._scope, owner=self._owner, claim=claim)
            published += 1
        return PublishStats(claimed=len(claims), published=published)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required publisher setting {name} is missing")
    return value


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Outbox Publisher", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/outbox/tick", response_model=TickResponse)
    def tick(request: TickRequest) -> TickResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        scope = Scope(
            _required("SOLVAN_ORGANIZATION_ID"),
            _required("SOLVAN_SCOPE_PROJECT_ID"),
            _required("SOLVAN_ENVIRONMENT_ID"),
        )
        owner = f"{socket.gethostname()}:{uuid4()}"
        with connect_database() as connection:
            repository = PostgresOutboxStore(connection)
            with connection.transaction():
                claims = repository.claim(
                    scope=scope, owner=owner, claim_ttl_ms=120_000, batch_size=50
                )
            runner = OutboxPublisherRunner(
                scope=scope,
                owner=owner,
                repository=_PreclaimedRepository(repository, claims, connection),
                publisher=GooglePubSubPublisher(
                    project_id=_required("SOLVAN_GCP_PROJECT"),
                    topic=_required("SOLVAN_WORKFLOW_TOPIC"),
                    session=authorized_session(),
                ),
            )
            stats = runner.run(batch_size=50)
        return TickResponse(claimed=stats.claimed, published=stats.published)

    return app


class _PreclaimedRepository:
    """Keep the initial claim commit separate from network publication."""

    def __init__(
        self,
        store: PostgresOutboxStore,
        claims: tuple[ClaimedEvent, ...],
        connection: Connection[object],
    ) -> None:
        self._store = store
        self._claims = claims
        self._connection = connection

    def claim(
        self, *, scope: Scope, owner: str, claim_ttl_ms: int, batch_size: int
    ) -> tuple[ClaimedEvent, ...]:
        return self._claims

    def load(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> OutboxEnvelope:
        envelope = self._store.load(scope=scope, owner=owner, claim=claim)
        self._connection.commit()
        return envelope

    def complete(self, *, scope: Scope, owner: str, claim: ClaimedEvent) -> None:
        with self._connection.transaction():
            self._store.complete(scope=scope, owner=owner, claim=claim)


app = instrument_fastapi(create_app(), service_name="outbox-publisher")
