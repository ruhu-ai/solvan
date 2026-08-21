"""Authenticated loopback worker for the local detection-to-incident path.

This is not a second workflow implementation. It asks the separate local
detector to evaluate its connection-bound rules, then applies the resulting
durable Cloud SQL inbox claims with the production coordinator's exact claim
handler. It intentionally starts no Agents and publishes no production work.
"""

from __future__ import annotations

import os
import socket
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from apps.coordinator.contracts import TickResponse
from apps.coordinator.main import _process_inbox_claim
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence import PostgresWorkflowStore
from solvan.persistence.inbox_store import PostgresInboxStore
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.google_rest import authorized_session_from_credentials
from solvan.platform.local_gcp_credentials import development_credentials
from solvan.platform.local_service_token import local_bearer_matches, read_local_service_token


class LocalPipelineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1)


class LocalPipelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluated_rules: int
    inserted_evaluations: int
    emitted_events: int
    inbox_claimed: int
    inbox_completed: int


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required local worker setting {name} is missing")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _authorize(authorization: str | None) -> None:
    try:
        valid = local_bearer_matches(authorization)
    except RuntimeError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid local worker identity token")


def _run_detector() -> dict[str, int]:
    response = httpx.post(
        f"{_required('SOLVAN_LOCAL_DETECTOR_URL').rstrip('/')}/internal/dev/detection/once",
        headers={"Authorization": f"Bearer {read_local_service_token()}"},
        timeout=90,
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict) or any(
        type(value.get(key)) is not int
        for key in ("evaluated_rules", "inserted_evaluations", "emitted_events")
    ):
        raise RuntimeError("local detector returned malformed progress material")
    return {
        "evaluated_rules": value["evaluated_rules"],
        "inserted_evaluations": value["inserted_evaluations"],
        "emitted_events": value["emitted_events"],
    }


def _run_inbox() -> TickResponse:
    scope = _scope()
    owner = f"local-cloud-worker:{socket.gethostname()}:{uuid4()}"
    credentials = development_credentials(
        service_account=_required("SOLVAN_READER_SERVICE_ACCOUNT")
    )
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset(
            {_required("SOLVAN_EVIDENCE_BUCKET"), _required("SOLVAN_RUNTIME_BUCKET")}
        ),
        session=authorized_session_from_credentials(credentials),
    )
    with connect_database() as connection:
        inbox = PostgresInboxStore(connection)
        workflow = PostgresWorkflowStore(connection)
        with connection.transaction():
            claims = inbox.claim(
                scope=scope,
                owner=owner,
                claim_ttl_ms=120_000,
                batch_size=20,
            )
        completed = sum(
            _process_inbox_claim(
                scope=scope,
                owner=owner,
                claim=claim,
                inbox=inbox,
                workflow=workflow,
                connection=connection,
                reader=reader,
            )
            for claim in claims
        )
    return TickResponse(claimed=len(claims), completed=completed)


app = FastAPI(
    title="Solvan Local Connected GCP Worker",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
instrument_fastapi(app, service_name="solvan-local-cloud-worker")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/internal/dev/pipeline:run", response_model=LocalPipelineResponse)
def run_pipeline(
    request: LocalPipelineRequest,
    authorization: str | None = Header(default=None),
) -> LocalPipelineResponse:
    del request
    _authorize(authorization)
    try:
        detection = _run_detector()
        inbox = _run_inbox()
    except (httpx.HTTPError, RuntimeError, ValueError) as error:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"local connected pipeline refused: {type(error).__name__}",
        ) from error
    return LocalPipelineResponse(
        **detection,
        inbox_claimed=inbox.claimed,
        inbox_completed=inbox.completed,
    )
