"""Scheduler-driven promotion of approved facts into Agent Platform Memory Bank."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Literal, Protocol

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from solvan.application import (
    MemoryBankUnavailable,
    MemoryConflict,
    MemoryPromotionRecord,
    MemoryPromotionService,
)
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence import PostgresMemoryStore
from solvan.platform import GeminiMemoryBank, MemoryBankConfiguration, VertexMemoryAPI
from solvan.platform.database import connect_database


class TickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    limit: int = Field(default=20, ge=1, le=100)


class TickResponse(BaseModel):
    examined: int
    succeeded: int
    deferred: int


class Promoter(Protocol):
    def promote(
        self, *, candidate_id: str, promoter_identity: str, now: datetime
    ) -> MemoryPromotionRecord: ...


def run_tick(
    *,
    candidate_ids: tuple[str, ...],
    promoter: Promoter,
    promoter_identity: str,
    now: datetime,
) -> TickResponse:
    succeeded = 0
    deferred = 0
    for candidate_id in candidate_ids:
        try:
            receipt = promoter.promote(
                candidate_id=candidate_id,
                promoter_identity=promoter_identity,
                now=now,
            )
            if receipt.candidate_id != candidate_id:
                raise MemoryConflict("promotion receipt belongs to another candidate")
            if not receipt.promotion_id:  # pragma: no cover - protocol defense
                raise MemoryConflict("promotion returned no durable receipt")
            succeeded += 1
        except (MemoryBankUnavailable, MemoryConflict):
            deferred += 1
    return TickResponse(
        examined=len(candidate_ids),
        succeeded=succeeded,
        deferred=deferred,
    )


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value or value == "UNCONFIGURED":
        raise RuntimeError(f"required memory promoter setting {name} is missing")
    return value


def _engine_id(resource: str, *, project_id: str, location: str) -> str:
    prefix = f"projects/{project_id}/locations/{location}/reasoningEngines/"
    if not resource.startswith(prefix):
        raise RuntimeError("Memory Bank resource is outside the exact deployment scope")
    engine_id = resource.removeprefix(prefix)
    if not engine_id or "/" in engine_id:
        raise RuntimeError("Memory Bank reasoning engine resource is malformed")
    return engine_id


app = FastAPI(title="Solvan Memory Promoter", version="1.0.0", docs_url=None, redoc_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/internal/memory/promotions/tick", response_model=TickResponse)
def tick(request: TickRequest) -> TickResponse:
    project_id = _required("SOLVAN_GCP_PROJECT")
    location = _required("SOLVAN_GCP_REGION")
    resource = _required("SOLVAN_MEMORY_BANK_RESOURCE")
    scope = Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )
    promoter_identity = _required("SOLVAN_MEMORY_PROMOTER_IDENTITY")
    config = MemoryBankConfiguration(
        project_id=project_id,
        location=location,
        reasoning_engine_id=_engine_id(resource, project_id=project_id, location=location),
    )
    bank = GeminiMemoryBank(
        config=config,
        api=VertexMemoryAPI(project=project_id, location=location),
    )
    with connect_database() as connection:
        store = PostgresMemoryStore(connection, scope=scope)
        candidate_ids = store.promotable_candidate_ids(limit=request.limit)
        connection.commit()
        return run_tick(
            candidate_ids=candidate_ids,
            promoter=MemoryPromotionService(store, bank),
            promoter_identity=promoter_identity,
            now=datetime.now(UTC),
        )


instrument_fastapi(app, service_name="memory-promoter")
