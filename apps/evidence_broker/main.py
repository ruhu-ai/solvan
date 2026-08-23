"""Run-bound broker for typed, read-only operational evidence tools."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from opentelemetry import trace
from psycopg import Connection
from pydantic import TypeAdapter, ValidationError

from apps.evidence_broker.contracts import (
    _ARGUMENT_MODELS,
    AuditLogArgs,
    ErrorReportingArgs,
    KubernetesMetadataArgs,
    LoggingArgs,
    ManagedPrometheusArgs,
    MonitoringArgs,
    QueryRequest,
    TraceArgs,
)
from apps.evidence_broker.helpers import (
    _required,
    cloud_build_trigger,
    cloud_sql_resource,
    github_repository_id,
    google_resource,
    payload_projection,
)
from apps.evidence_broker.projections import (
    bounded_summary,
    trace_ids,
)
from apps.evidence_broker.reader import TypedEvidenceReader
from solvan.agents.read_tools import EvidenceToolResult
from solvan.application.alert_predicates import compile_registered_predicate_provenance
from solvan.application.tool_output_security import secure_tool_output
from solvan.observability import instrument_fastapi
from solvan.persistence import (
    EvidenceWrite,
    PostgresEvidenceToolStore,
    ToolAuthorizationError,
    ToolCallBusy,
)
from solvan.persistence.evidence_types import EvidenceToolReservation, StoredEvidence
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_release import GoogleIdentityTokenProvider
from solvan.platform.google_rest import GoogleRestSession, authorized_session
from solvan.platform.service_identity import (
    ServiceIdentityError,
    require_agent_principal,
    verify_service_caller,
)

_AGENT_TOOLS = {
    "evidence-agent": frozenset(
        {
            "cloud_logging_query",
            "cloud_monitoring_query",
            "cloud_trace_read",
            "kubernetes_metadata_read",
            "cloud_audit_log_query",
            "error_reporting_query",
            "managed_prometheus_query",
            "metric_baseline_compare",
            "metric_change_point_detect",
            "metric_correlate",
            "log_pattern_summary",
            "log_sample_bounded",
        }
    ),
    "infrastructure-agent": frozenset(
        {
            "cloud_run_read",
            "cloud_run_revision_compare",
            "cloud_asset_inventory_search",
            "cloud_build_history_read",
            "github_commit_range_read",
            "github_pr_diff_read",
            "github_workflow_run_read",
            "cloud_sql_metadata_read",
            "production_graph_read",
        }
    ),
}


_DIRECT_GCP_AUTHENTICATION_MODE = "GCP_SERVICE_ACCOUNT_IMPERSONATION"


class RelayCollectionPending(ToolCallBusy):
    """A customer Relay job is durable but has not yet accepted evidence."""


class DirectReadBindingUnavailable(ToolAuthorizationError):
    """The frozen connection revision carries no complete customer reader binding."""


__all__ = [
    "AuditLogArgs",
    "DirectReadBindingUnavailable",
    "ErrorReportingArgs",
    "MonitoringArgs",
    "QueryRequest",
    "TypedEvidenceReader",
    "cloud_build_trigger",
    "cloud_sql_resource",
    "create_app",
    "github_repository_id",
    "google_resource",
]


def _customer_reader_session(
    *, connection: Connection[Any], reservation: EvidenceToolReservation
) -> GoogleRestSession:
    """Mint the direct read session from the frozen connection revision alone.

    Specification 13 §3.4. The customer reader principal, its Solvan delegator,
    the delegation condition digest, and the token ceiling are read from the
    exact connection epoch the reservation froze. Nothing here consults a
    request body, an environment-named customer identity, a model tool
    argument, or an operator-supplied identifier, and there is no ambient
    fallback: an absent or partial binding refuses the read.
    """

    configured = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
    if not configured:
        raise DirectReadBindingUnavailable("the Solvan reader identity is not configured")
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT authentication_mode,solvan_delegator_principal,
                      customer_reader_principal,delegation_condition_digest,
                      token_lifetime_seconds
                 FROM solvan.tenant_connections
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(connection_id)s
                  AND connection_epoch=%(connection_epoch)s""",
            {
                **reservation.scope.canonical_dict(),
                "connection_id": reservation.connection_id,
                "connection_epoch": reservation.connection_epoch,
            },
        )
        row = cursor.fetchone()
    if row is None:
        raise DirectReadBindingUnavailable("frozen evidence source connection is no longer current")
    mode, delegator, customer_reader, condition_digest, lifetime = row
    if (
        mode != _DIRECT_GCP_AUTHENTICATION_MODE
        or delegator != f"serviceAccount:{configured}"
        or not isinstance(customer_reader, str)
        or not isinstance(condition_digest, str)
        or not isinstance(lifetime, int)
    ):
        raise DirectReadBindingUnavailable(
            "frozen connection revision carries no complete customer reader binding"
        )
    return authorized_session(
        delegator_principal=str(delegator),
        target_principal=customer_reader,
        lifetime_seconds=lifetime,
        delegate_principals=(str(delegator),),
    )


def execute_query(*, agent_key: str, request: QueryRequest) -> EvidenceToolResult:
    if request.tool_name not in _AGENT_TOOLS.get(agent_key, frozenset()):
        raise ToolAuthorizationError("tool is outside the agent identity ceiling")
    model = _ARGUMENT_MODELS.get(request.tool_name)
    if model is None:
        raise ToolAuthorizationError("tool is not registered")
    arguments = TypeAdapter(model).validate_python(request.arguments)
    canonical = json.dumps(arguments.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    input_bytes = len(canonical.encode())
    arguments_hash = f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
    service_id = arguments.model_dump()["service_id"]
    if not isinstance(service_id, str):
        raise ToolAuthorizationError("service identifier is invalid")
    bucket = _required("SOLVAN_EVIDENCE_BUCKET")
    relay_bucket = os.environ.get("SOLVAN_RELAY_EVIDENCE_BUCKET")
    # The runtime identity reaches Solvan's own evidence objects and nothing
    # else. Every provider read below is minted for the customer reader service
    # account recorded on the frozen connection revision.
    object_session = authorized_session()
    with connect_database() as connection:
        store = PostgresEvidenceToolStore(connection)
        with connection.transaction():
            reservation = store.reserve(
                invocation_id=request.invocation_id,
                expected_agent_key=agent_key,
                tool_name=request.tool_name,
                service_id=service_id,
                arguments_hash=arguments_hash,
                input_bytes=input_bytes,
                otel_span_id=_current_span_id(),
            )
        if reservation.existing_evidence_id:
            existing = store.load_evidence(
                scope=reservation.scope, evidence_id=reservation.existing_evidence_id
            )
            return _existing_result(
                existing,
                session=object_session,
                buckets=frozenset({bucket, *([relay_bucket] if relay_bucket else [])}),
            )
        try:
            if store.requires_customer_relay(reservation=reservation):
                if not isinstance(
                    arguments,
                    MonitoringArgs
                    | ManagedPrometheusArgs
                    | LoggingArgs
                    | TraceArgs
                    | KubernetesMetadataArgs,
                ):
                    raise ToolAuthorizationError(
                        "customer-local source has no qualified Relay adapter for this Tool"
                    )
                _author_customer_relay_job(reservation=reservation, arguments=arguments)
                # Keep the Tool call RESERVED. Relay control alone completes it
                # with accepted evidence; the ordinary retry/cache path then
                # returns that evidence without a second provider read.
                raise RelayCollectionPending("customer Relay evidence is pending")
            value, request_ids, start, end, source_kind = TypedEvidenceReader(
                provider_session=lambda: _customer_reader_session(
                    connection=connection, reservation=reservation
                ),
                object_session=object_session,
                store=store,
                bucket=bucket,
            ).read(reservation, arguments)
            secured_output = secure_tool_output(value)
            value = secured_output.value
            predicate_context = (
                store.registered_alert_predicate_context(reservation=reservation)
                if isinstance(arguments, MonitoringArgs)
                else None
            )
            predicate_provenance = (
                compile_registered_predicate_provenance(
                    predicate_context,
                    signal_kind=arguments.signal_kind,
                    observed_value=value.get("value") if isinstance(value, dict) else None,
                    window_start=start,
                    window_end=end,
                )
                if isinstance(arguments, MonitoringArgs)
                else {}
            )
            classification = (
                "CONFIDENTIAL_REDACTED"
                if source_kind in {"CLOUD_LOGGING", "CLOUD_TRACE", "GITHUB"}
                else "INTERNAL"
            )
            document = {
                "schema_version": 1,
                "tool_name": request.tool_name,
                "arguments_hash": arguments_hash,
                "observed_at": datetime.now(UTC).isoformat(),
                "value": value,
                "provider_request_ids": list(request_ids),
                "classification": classification,
                "security_reason_codes": list(secured_output.reason_codes),
                **predicate_provenance,
            }
            discovered_trace_ids = trace_ids(value, reservation.service_project_id)
            digest = hashlib.sha256(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            output_bytes = len(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
            receipt = GcsEvidenceWriter(bucket=bucket, session=object_session).put_json(
                object_name=(
                    f"agent-evidence/{reservation.scope.environment_id}/"
                    f"{reservation.call_id}/{digest}.json"
                ),
                value=document,
            )
            now = datetime.now(UTC)
            with connection.transaction():
                if predicate_provenance:
                    if not isinstance(arguments, MonitoringArgs):
                        raise ToolAuthorizationError(
                            "non-monitoring Tool output cannot carry Alert predicate authority"
                        )
                    current_context = store.registered_alert_predicate_context(
                        reservation=reservation
                    )
                    current_provenance = compile_registered_predicate_provenance(
                        current_context,
                        signal_kind=arguments.signal_kind,
                        observed_value=value.get("value") if isinstance(value, dict) else None,
                        window_start=start,
                        window_end=end,
                    )
                    if (
                        current_context != predicate_context
                        or current_provenance != predicate_provenance
                    ):
                        raise ToolAuthorizationError(
                            "registered Alert predicate authority changed before commit"
                        )
                evidence_id = store.complete(
                    reservation=reservation,
                    write=EvidenceWrite(
                        source_kind=source_kind,
                        source_resource=reservation.platform_resource,
                        query_spec={
                            "tool_name": request.tool_name,
                            "arguments_hash": arguments_hash,
                            # Persist the already type-checked, allowlisted arguments so
                            # deterministic confirmation policy can match observations
                            # without reading model prose or opaque evidence objects.
                            "arguments": arguments.model_dump(mode="json"),
                        },
                        window_start=start,
                        window_end=end,
                        observed_at=now,
                        content_ref=receipt.uri,
                        content_hash=receipt.content_hash,
                        classification=classification,
                        residency=_required("SOLVAN_GCP_REGION"),
                        # The console reads Cloud SQL and never reads evidence
                        # objects, so a metric series is projected here or it
                        # does not reach an operator at all.
                        projection=payload_projection(value, source_kind),
                        redaction_manifest_ref="deterministic-solvan-v1",
                        provenance={
                            "request_ids": list(request_ids),
                            "generation": receipt.generation,
                            "trace_ids": list(discovered_trace_ids),
                            "security_reason_codes": list(secured_output.reason_codes),
                            **predicate_provenance,
                        },
                        freshness_expires_at=now + timedelta(minutes=5),
                    ),
                    output_bytes=output_bytes,
                )
            return EvidenceToolResult(
                evidence_ref=evidence_id,
                content_ref=receipt.uri,
                content_hash=receipt.content_hash,
                bounded_summary=bounded_summary(value),
                classification=cast(Any, classification),
                armor_verdict_ref=None,
            )
        except RelayCollectionPending:
            raise
        except Exception as error:
            with connection.transaction():
                store.fail(reservation=reservation, error_class=type(error).__name__)
            raise


def _author_customer_relay_job(
    *,
    reservation: Any,
    arguments: (
        MonitoringArgs | ManagedPrometheusArgs | LoggingArgs | TraceArgs | KubernetesMetadataArgs
    ),
) -> None:
    """Ask the coordinator to author one job; no provider fallback exists.

    A transport timeout is reported as pending rather than failing the Tool
    call: coordinator authorship is idempotent on this exact Tool call, so a
    subsequent bounded retry can discover an already-authored job.
    """

    base_url = _required("SOLVAN_COORDINATOR_URL").rstrip("/")
    audience = _required("SOLVAN_COORDINATOR_AUDIENCE")
    if not base_url.startswith("https://") or not audience.startswith("https://"):
        raise ToolAuthorizationError("Relay coordinator route is not an HTTPS private service")
    payload = {
        "schema_version": 1,
        "agent_run_id": reservation.run_id,
        "tool_call_id": reservation.call_id,
        "arguments": arguments.model_dump(mode="json"),
    }
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            response = client.post(
                f"{base_url}/internal/v1/relay/observability-jobs",
                headers={
                    "Authorization": (
                        "Bearer " + GoogleIdentityTokenProvider().token(audience=audience)
                    ),
                    "Content-Type": "application/json",
                },
                json=payload,
            )
    except (httpx.HTTPError, RuntimeError) as error:
        raise RelayCollectionPending("customer Relay job authoring outcome is pending") from error
    if response.status_code not in {200, 202}:
        raise ToolAuthorizationError("customer Relay job was refused by the coordinator")
    value = response.json()
    if not isinstance(value, dict) or not isinstance(value.get("collection_job_id"), str):
        raise RelayCollectionPending("customer Relay job authoring outcome is pending")


def _existing_result(
    evidence: StoredEvidence, *, session: GoogleRestSession, buckets: frozenset[str]
) -> EvidenceToolResult:
    document = GcsEvidenceReader(allowed_buckets=buckets, session=session).get_json(
        uri=evidence.content_ref, expected_hash=evidence.content_hash
    )
    value = document.get("value")
    if not isinstance(value, dict):
        raise RuntimeError("stored evidence has no result object")
    return EvidenceToolResult(
        evidence_ref=evidence.evidence_id,
        content_ref=evidence.content_ref,
        content_hash=evidence.content_hash,
        bounded_summary=bounded_summary(value),
        classification=cast(Any, evidence.classification),
        armor_verdict_ref=None,
    )


def _authorize(authorization: str | None, agent_key: str) -> None:
    try:
        caller = verify_service_caller(authorization, audience_variable="SOLVAN_EVIDENCE_AUDIENCE")
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
    if _required("SOLVAN_PLATFORM_AUTHORITY_MODE") != "AGENT_IDENTITY_IAM_GATEWAY":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "platform authority is disabled")
    # The path names an agent; the verified caller must be that exact attested
    # Agent identity. A valid token for this audience from any other workload —
    # including a sibling Agent — is not admission, and an agent_key with no
    # attested principal is refused rather than admitted by omission.
    principals = {
        "evidence-agent": os.environ.get("SOLVAN_EVIDENCE_AGENT_PRINCIPAL", ""),
        "infrastructure-agent": os.environ.get("SOLVAN_INFRASTRUCTURE_AGENT_PRINCIPAL", ""),
    }
    principal = principals.get(agent_key, "")
    if not principal.startswith("principal://agents.global."):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "agent principal is invalid")
    try:
        require_agent_principal(caller, admitted=frozenset({principal}))
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error


def _current_span_id() -> str:
    context = trace.get_current_span().get_span_context()
    if context.is_valid:
        return f"{context.span_id:016x}"
    if os.environ.get("SOLVAN_ENVIRONMENT") == "local":
        return "0000000000000001"
    raise RuntimeError("an active OpenTelemetry span is required for a Tool call")


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Evidence Broker", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post(
        "/internal/v1/evidence/{agent_key}:query",
        response_model=EvidenceToolResult,
    )
    def query(
        agent_key: str,
        request: QueryRequest,
        authorization: str | None = Header(default=None),
    ) -> EvidenceToolResult:
        _authorize(authorization, agent_key)
        try:
            return execute_query(agent_key=agent_key, request=request)
        except (ToolAuthorizationError, ValidationError, ValueError) as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        except ToolCallBusy as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, type(error).__name__) from error

    return app


app = instrument_fastapi(create_app(), service_name="evidence-broker")
