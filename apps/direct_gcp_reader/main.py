"""Private reader for the Direct GCP Alert Triage Pilot.

The general API never assumes a customer reader identity and never obtains a
customer access token.  This workload is the sole Solvan identity that may
impersonate an enrolled, customer-owned read-only service account.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from fastapi import FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.detection import Comparator, DetectionRule
from solvan.application.tenant_integration import ConnectionPolicyError
from solvan.application.tool_capability_evidence import ToolProbeTarget
from solvan.observability import instrument_fastapi
from solvan.platform.capability_probe import ProbeTarget, probe_connection
from solvan.platform.cloud_monitoring import CloudMonitoringReader
from solvan.platform.google_rest import GoogleRestSession, authorized_session
from solvan.platform.service_identity import ServiceIdentityError, verify_service_caller
from solvan.platform.tool_capability_probe import probe_tool_capability


class ProbeCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    connection_epoch: int = Field(ge=1)
    provider: str = Field(min_length=1, max_length=40)
    authentication_mode: Literal["GCP_SERVICE_ACCOUNT_IMPERSONATION"]
    solvan_delegator_principal: str = Field(min_length=1, max_length=320)
    customer_reader_principal: str = Field(min_length=1, max_length=320)
    token_lifetime_seconds: int = Field(ge=1, le=900)
    resource_kind: Literal["GCP_PROJECT"]
    resource_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,61}$")


class ProbeCapability(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str = Field(min_length=1, max_length=160)
    available: bool
    missing_grant: str | None
    probe_receipt_ref: str = Field(min_length=1, max_length=1024)
    outcome: Literal["GRANTED", "DENIED", "MISCONFIGURED", "UNREACHABLE", "NOT_PROBED"]


class ProbeResult(BaseModel):
    connection_id: str
    connection_epoch: int
    result: Literal["SUCCEEDED", "PARTIAL", "FAILED"]
    capabilities: list[ProbeCapability]


class SessionFactory(Protocol):
    def __call__(
        self,
        *,
        delegator_principal: str | None = None,
        target_principal: str | None = None,
        lifetime_seconds: int | None = None,
    ) -> GoogleRestSession: ...


def _authorize(authorization: str | None) -> None:
    try:
        caller = verify_service_caller(
            authorization, audience_variable="SOLVAN_DIRECT_GCP_READER_AUDIENCE"
        )
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
    raw_callers = os.environ.get("SOLVAN_DIRECT_GCP_READER_CALLERS_JSON")
    try:
        callers = json.loads(raw_callers or "")
    except json.JSONDecodeError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "reader caller policy is invalid"
        ) from error
    if (
        not isinstance(callers, list)
        or not callers
        or any(not isinstance(item, str) or not item for item in callers)
        or len(callers) != len(set(callers))
    ):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "reader caller policy is invalid")
    if caller.email not in callers:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the scoped control-plane API")


def _reader_principal() -> str:
    configured = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
    if not configured:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "reader identity is not configured"
        )
    return f"serviceAccount:{configured}"


def _probe(
    command: ProbeCommand, *, session_factory: SessionFactory = authorized_session
) -> ProbeResult:
    if command.solvan_delegator_principal != _reader_principal():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "connection is not an eligible direct GCP reader binding",
        )
    try:
        observations = probe_connection(
            session_factory(
                delegator_principal=command.solvan_delegator_principal,
                target_principal=command.customer_reader_principal,
                lifetime_seconds=command.token_lifetime_seconds,
            ),
            target=ProbeTarget(provider=command.provider, gcp_project_id=command.resource_id),
        )
    except ConnectionPolicyError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
    available = sum(observation.available for observation in observations)
    result: Literal["SUCCEEDED", "PARTIAL", "FAILED"]
    if available == len(observations):
        result = "SUCCEEDED"
    elif available:
        result = "PARTIAL"
    else:
        result = "FAILED"
    return ProbeResult(
        connection_id=command.connection_id,
        connection_epoch=command.connection_epoch,
        result=result,
        capabilities=[ProbeCapability.model_validate(asdict(item)) for item in observations],
    )


class ToolProbeCommand(ProbeCommand):
    """One Tool revision's declared capability, observed on this connection.

    The Tool's identity and declared capability are supplied by the caller
    because they are immutable catalog facts the API reads from Cloud SQL. This
    workload has no database identity and must not acquire one: it holds the
    customer credential, and the two authorities are kept apart.
    """

    tool_key: str = Field(pattern=r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
    tool_version: str = Field(min_length=1, max_length=32)
    capability: str = Field(min_length=1, max_length=160)


class ToolProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    connection_id: str
    connection_epoch: int
    tool_revision: str
    capability: str
    available: bool
    outcome: Literal["GRANTED", "DENIED", "MISCONFIGURED", "UNREACHABLE", "NOT_PROBED"]
    missing_grant: str | None
    reason_code: str | None
    receipt_ref: str
    receipt_hash: str
    observed_at: str
    expires_at: str


class DetectionObservationCommand(ProbeCommand):
    """One closed metric observation for one persisted detection rule."""

    rule_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    rule_version: int = Field(ge=1)
    signal_kind: Literal["HTTP_5XX_RATIO", "HTTP_P95_LATENCY", "SQL_CONNECTIONS"]
    resource_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    window_start: datetime
    window_end: datetime


class DetectionObservationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    connection_id: str
    connection_epoch: int
    rule_id: str
    rule_version: int
    observed_value: float
    request_ids: list[str]
    observed_project_id: str
    observed_resource_type: str
    observed_labels: dict[str, str]


def _observe_detection(
    command: DetectionObservationCommand,
    *,
    session_factory: SessionFactory = authorized_session,
) -> DetectionObservationResult:
    if command.provider != "CLOUD_MONITORING":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "detection observation requires Cloud Monitoring",
        )
    if command.window_start.tzinfo is None or command.window_end.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "detection window is naive")
    now = datetime.now(UTC)
    duration = command.window_end - command.window_start
    if not timedelta(seconds=1) <= duration <= timedelta(minutes=5):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "detection window is outside the bound"
        )
    if command.window_end > now + timedelta(seconds=5):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "detection window ends in the future"
        )
    rule = DetectionRule(
        rule_id=command.rule_id,
        version=command.rule_version,
        service_id="reader-bound-service",
        service_key="reader-bound-service",
        graph_snapshot_id="reader-bound-graph",
        incident_class="reader-bound-observation",
        signal_kind=command.signal_kind,
        query={
            "gcp_project_id": command.resource_id,
            "resource_name": command.resource_name,
        },
        evaluation_interval_ms=25_000,
        comparator=Comparator.GT,
        threshold=0,
        sustained_windows=1,
        severity="SEV4",
        deduplication_dimension="reader-bound-observation",
        action_budget=1,
        repeated_action_limit=1,
    )
    try:
        observation = CloudMonitoringReader(
            session_factory(
                delegator_principal=command.solvan_delegator_principal,
                target_principal=command.customer_reader_principal,
                lifetime_seconds=command.token_lifetime_seconds,
            )
        ).observe(rule, window_start=command.window_start, window_end=command.window_end)
    except (ConnectionPolicyError, RuntimeError, ValueError) as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "bounded detection observation was refused"
        ) from error
    return DetectionObservationResult(
        connection_id=command.connection_id,
        connection_epoch=command.connection_epoch,
        rule_id=command.rule_id,
        rule_version=command.rule_version,
        observed_value=observation.value,
        request_ids=list(observation.request_ids),
        observed_project_id=observation.resource.project_id,
        observed_resource_type=observation.resource.resource_type,
        observed_labels=dict(observation.resource.labels),
    )


def _probe_tool(
    command: ToolProbeCommand, *, session_factory: SessionFactory = authorized_session
) -> ToolProbeResult:
    if command.solvan_delegator_principal != _reader_principal():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "connection is not an eligible direct GCP reader binding",
        )
    try:
        observed = probe_tool_capability(
            session_factory(
                delegator_principal=command.solvan_delegator_principal,
                target_principal=command.customer_reader_principal,
                lifetime_seconds=command.token_lifetime_seconds,
            ),
            target=ToolProbeTarget(
                tool_key=command.tool_key,
                tool_version=command.tool_version,
                capability=command.capability,
                provider=command.provider,
                gcp_project_id=command.resource_id,
            ),
        )
    except ConnectionPolicyError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
    return ToolProbeResult(
        connection_id=command.connection_id,
        connection_epoch=command.connection_epoch,
        tool_revision=observed.tool_revision,
        capability=observed.capability,
        available=observed.available,
        outcome=observed.outcome,
        missing_grant=observed.missing_grant,
        reason_code=observed.reason_code,
        receipt_ref=observed.receipt_ref,
        receipt_hash=observed.receipt_hash,
        observed_at=observed.observed_at.isoformat(),
        expires_at=observed.expires_at.isoformat(),
    )


def create_app(
    *,
    authorize: Callable[[str | None], None] = _authorize,
    session_factory: SessionFactory = authorized_session,
    service_name: str = "solvan-direct-gcp-reader",
) -> FastAPI:
    """Create the closed reader surface with one fixed identity boundary.

    The deployed entry point uses the default Google OIDC verifier. The local
    development entry point supplies a Unix-socket-only authenticator from a
    separate module; no environment flag can weaken this production app.
    """

    application = FastAPI(
        title="Solvan Direct GCP Reader", docs_url=None, redoc_url=None, openapi_url=None
    )
    instrument_fastapi(application, service_name=service_name)

    @application.post("/internal/v1/connections:probe", response_model=ProbeResult)
    def probe(
        command: ProbeCommand, authorization: str | None = Header(default=None)
    ) -> ProbeResult:
        authorize(authorization)
        return _probe(command, session_factory=session_factory)

    @application.post("/internal/v1/tools:probe", response_model=ToolProbeResult)
    def probe_tool(
        command: ToolProbeCommand, authorization: str | None = Header(default=None)
    ) -> ToolProbeResult:
        authorize(authorization)
        return _probe_tool(command, session_factory=session_factory)

    @application.post("/internal/v1/detections:observe", response_model=DetectionObservationResult)
    def observe_detection(
        command: DetectionObservationCommand,
        authorization: str | None = Header(default=None),
    ) -> DetectionObservationResult:
        authorize(authorization)
        return _observe_detection(command, session_factory=session_factory)

    @application.get("/healthz", include_in_schema=False)
    def healthz() -> Response:
        return Response(
            status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"}
        )

    return application


app = create_app()
