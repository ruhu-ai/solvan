"""Private verifier invoked only by the Agent Identity-bound Verification Agent."""

from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict

from solvan.application.detection import Comparator as DetectionComparator
from solvan.application.detection import DetectionRule
from solvan.domain import (
    Comparator,
    Scope,
    SignalRequirement,
    SignalSample,
    SyntheticReceipt,
    VerificationError,
    evaluate_verification,
)
from solvan.observability import instrument_fastapi
from solvan.persistence import (
    PostgresVerificationStore,
    VerificationAuthorizationError,
    VerificationTask,
)
from solvan.platform.cloud_monitoring import CloudMonitoringReader
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.service_identity import (
    ServiceIdentityError,
    require_agent_principal,
    verify_service_caller,
)


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    invocation_id: str
    organization_id: str
    project_id: str
    environment_id: str
    action_id: str


class VerificationResponse(BaseModel):
    verification_id: str
    verdict: Literal["VERIFIED", "FAILED", "INCONCLUSIVE"]
    rationale_codes: tuple[str, ...]


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required verifier setting {name} is missing")
    return value


def _authorize(authorization: str | None) -> None:
    try:
        caller = verify_service_caller(authorization, audience_variable="SOLVAN_VERIFIER_AUDIENCE")
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
    if _required("SOLVAN_PLATFORM_AUTHORITY_MODE") != "AGENT_IDENTITY_IAM_GATEWAY":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "platform authority is disabled")
    principal = _required("SOLVAN_VERIFICATION_PRINCIPAL")
    if not principal.startswith("principal://agents.global."):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "agent principal is invalid")
    # The verified caller must be the exact attested Verification Agent
    # identity — a valid token for this audience from any other workload is
    # not admission.
    try:
        require_agent_principal(caller, admitted=frozenset({principal}))
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error


def _requirements(value: object) -> tuple[tuple[SignalRequirement, str], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise VerificationError("profile requires one to eight signals")
    parsed: list[tuple[SignalRequirement, str]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "signal_key",
            "provider_signal_kind",
            "comparator",
            "threshold",
            "sustained_samples",
        }:
            raise VerificationError("verification signal has an unsupported schema")
        threshold = item["threshold"]
        sustained = item["sustained_samples"]
        if (
            not isinstance(item["signal_key"], str)
            or item["provider_signal_kind"]
            not in {"HTTP_5XX_RATIO", "HTTP_P95_LATENCY", "SQL_CONNECTIONS"}
            or isinstance(threshold, bool)
            or not isinstance(threshold, int | float)
            or not math.isfinite(float(threshold))
            or type(sustained) is not int
            or not 1 <= sustained <= 6
        ):
            raise VerificationError("verification signal fields are invalid")
        parsed.append(
            (
                SignalRequirement(
                    signal_key=item["signal_key"],
                    comparator=Comparator(item["comparator"]),
                    threshold=float(threshold),
                    sustained_samples=sustained,
                ),
                str(item["provider_signal_kind"]),
            )
        )
    return tuple(parsed)


def _guardrail(value: object) -> tuple[int, bool]:
    if not isinstance(value, dict) or set(value) != {"synthetic_payment"}:
        raise VerificationError("verification guardrail has an unsupported schema")
    synthetic = value["synthetic_payment"]
    if not isinstance(synthetic, dict) or set(synthetic) != {"amount_minor", "required"}:
        raise VerificationError("synthetic guardrail has an unsupported schema")
    amount = synthetic["amount_minor"]
    required = synthetic["required"]
    if type(amount) is not int or not 1 <= amount <= 1_000_000 or required is not True:
        raise VerificationError("synthetic guardrail fields are invalid")
    return amount, required


def _sample_signals(
    task: VerificationTask,
    requirements: tuple[tuple[SignalRequirement, str], ...],
    *,
    window_start: datetime,
    telemetry_end: datetime,
) -> tuple[tuple[SignalSample, ...], list[dict[str, object]]]:
    reader = CloudMonitoringReader(authorized_session())
    samples: list[SignalSample] = []
    results: list[dict[str, object]] = []
    for requirement, provider_kind in requirements:
        width = (telemetry_end - window_start) / requirement.sustained_samples
        for index in range(requirement.sustained_samples):
            start = window_start + width * index
            end = window_start + width * (index + 1)
            rule = DetectionRule(
                rule_id="verification-read",
                version=1,
                service_id=task.service_id,
                service_key=task.service_key,
                graph_snapshot_id=task.graph_snapshot_id,
                incident_class=task.incident_class,
                signal_kind=provider_kind,
                query={
                    "gcp_project_id": task.service_project_id,
                    "resource_name": task.platform_resource.rsplit("/", 1)[-1],
                },
                evaluation_interval_ms=25_000,
                comparator=DetectionComparator.GT,
                threshold=0,
                sustained_windows=1,
                severity="SEV4",
                deduplication_dimension="verification",
                action_budget=1,
                repeated_action_limit=1,
            )
            observation = reader.observe(rule, window_start=start, window_end=end)
            sample = SignalSample(requirement.signal_key, end, observation.value)
            samples.append(sample)
            results.append(
                {
                    "signal_key": requirement.signal_key,
                    "provider_signal_kind": provider_kind,
                    "observed_at": end.isoformat(),
                    "value": observation.value,
                    "request_ids": list(observation.request_ids),
                }
            )
    return tuple(samples), results


def _synthetic(
    task: VerificationTask, *, amount_minor: int
) -> tuple[SyntheticReceipt, dict[str, Any]]:
    base_url = _required("SOLVAN_PAYMENTS_URL").rstrip("/")
    key = f"verify-{task.action_id}"
    payment_id = f"verification-{task.action_id}"
    token = id_token.fetch_id_token(GoogleAuthRequest(), base_url)  # type: ignore[no-untyped-call]
    response = httpx.post(
        f"{base_url}/v1/synthetic/payments",
        headers={"authorization": f"Bearer {token}", "idempotency-key": key},
        json={"schema_version": 1, "payment_id": payment_id, "amount_minor": amount_minor},
        timeout=30,
    )
    observed_at = datetime.now(UTC)
    succeeded = response.status_code == 200
    projection: dict[str, Any] = {
        "observed_at": observed_at.isoformat(),
        "succeeded": succeeded,
        "status_code": response.status_code,
        "idempotency_key": key,
        "payment_id": payment_id,
    }
    if succeeded:
        body = response.json()
        if isinstance(body, dict):
            projection["revision"] = body.get("revision")
            projection["duplicate"] = body.get("duplicate")
    return SyntheticReceipt(observed_at, succeeded, True, key), projection


def execute_verification(request: VerificationRequest) -> VerificationResponse:
    scope = Scope(request.organization_id, request.project_id, request.environment_id)
    with connect_database() as connection:
        store = PostgresVerificationStore(connection)
        with connection.transaction():
            task = store.reserve(
                scope=scope,
                invocation_id=request.invocation_id,
                action_id=request.action_id,
            )
        if task.existing_verification_id is not None:
            assert task.existing_verdict is not None
            return VerificationResponse(
                verification_id=task.existing_verification_id,
                verdict=cast(
                    Literal["VERIFIED", "FAILED", "INCONCLUSIVE"],
                    task.existing_verdict,
                ),
                rationale_codes=("DUPLICATE_TOOL_CALL",),
            )
        requirements = _requirements(task.required_signals)
        amount_minor, _synthetic_required = _guardrail(task.guardrails)
        window_start = task.reconciled_at + timedelta(milliseconds=task.warmup_ms)
        telemetry_end = window_start + timedelta(milliseconds=task.observation_ms)
        if datetime.now(UTC) < telemetry_end:
            raise VerificationAuthorizationError("approved observation window has not elapsed")
        samples, signal_results = _sample_signals(
            task,
            requirements,
            window_start=window_start,
            telemetry_end=telemetry_end,
        )
        synthetic, synthetic_projection = _synthetic(task, amount_minor=amount_minor)
        result = evaluate_verification(
            requirements=tuple(item[0] for item in requirements),
            samples=samples,
            window_start=window_start,
            window_end=datetime.now(UTC),
            synthetic_receipt=synthetic,
        )
        document = {
            "schema_version": 1,
            "action_id": task.action_id,
            "profile": {"id": task.profile_id, "version": task.profile_version},
            "signals": signal_results,
            "synthetic": synthetic_projection,
            "verdict": result.verdict.value,
            "rationale_codes": list(result.rationale_codes),
        }
        digest = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        receipt = GcsEvidenceWriter(
            bucket=_required("SOLVAN_RUNTIME_BUCKET"), session=authorized_session()
        ).put_json(
            object_name=(f"verification/{scope.environment_id}/{task.action_id}/{digest}.json"),
            value=document,
        )
        with connection.transaction():
            verification_id = store.complete(
                task=task,
                window_start=window_start,
                window_end=datetime.now(UTC),
                signal_results=signal_results,
                synthetic_receipt_ref=receipt.uri,
                result=result,
            )
        return VerificationResponse(
            verification_id=verification_id,
            verdict=result.verdict.value,
            rationale_codes=result.rationale_codes,
        )


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Independent Verifier", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/verifications:run", response_model=VerificationResponse)
    def run(
        request: VerificationRequest,
        authorization: str | None = Header(default=None),
    ) -> VerificationResponse:
        _authorize(authorization)
        try:
            return execute_verification(request)
        except VerificationAuthorizationError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except VerificationError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error

    return app


app = instrument_fastapi(create_app(), service_name="verifier")
