"""Coordinator Relay-job authorship is derived from a reserved Tool call."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from apps.coordinator.relay_job_authoring import (
    RelayJobAuthor,
    RelayJobAuthoringError,
    _relay_parameters,
    _relay_specification,
)
from apps.evidence_broker.contracts import (
    KubernetesMetadataArgs,
    LoggingArgs,
    ManagedPrometheusArgs,
    MonitoringArgs,
    TraceArgs,
)
from solvan.domain import Scope
from solvan.persistence.relay_store import PostgresRelayStore

HASH = "sha256:" + "a" * 64


def _id(prefix: str) -> str:
    return f"{prefix}_" + "0" * 26


class Cursor:
    def __init__(self, rows: list[dict[str, Any] | None]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: dict[str, Any] | None = None) -> None:
        self.calls.append((statement, params))

    def fetchone(self) -> dict[str, Any] | None:
        return self.rows.pop(0) if self.rows else None


class Connection:
    def __init__(self, rows: list[dict[str, Any] | None]) -> None:
        self.cursor_value = Cursor(rows)

    def transaction(self) -> Connection:
        return self

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self, **_kwargs: object) -> Cursor:
        return self.cursor_value


class Signer:
    def __init__(self) -> None:
        self.digests: list[bytes] = []

    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes:
        assert key_version.endswith("/cryptoKeyVersions/1")
        self.digests.append(digest)
        return b"signature"


def _scope() -> Scope:
    return Scope(_id("org"), _id("prj"), _id("env"))


def _arguments() -> MonitoringArgs:
    end = datetime.now(UTC) - timedelta(minutes=1)
    return MonitoringArgs(
        service_id=_id("svc"),
        signal_kind="HTTP_P95_LATENCY",
        window_start=end - timedelta(minutes=5),
        window_end=end,
    )


def _authority_row() -> dict[str, Any]:
    return {
        "agent_run_id": _id("run"),
        "incident_id": _id("inc"),
        "input_hash": HASH,
        "production_graph_snapshot_id": _id("pgs"),
        "tool_call_id": _id("tcl"),
        "arguments_hash": HASH,
        "profile_key": "evidence-read",
        "profile_version": "1",
        "profile_material_hash": HASH,
        "profile_ordinal": 1,
        "tool_key": "cloud_monitoring_query",
        "tool_version": "1",
        "connection_id": _id("con"),
        "connection_epoch": 3,
        "capability_receipt_id": "probe-monitoring",
        "capability_receipt_hash": HASH,
        "source_binding_id": _id("rsb"),
        "enrollment_id": _id("ren"),
        "enrollment_epoch": 2,
        "adapter_key": "cloud-monitoring.v1",
        "adapter_revision": "1",
        "relay_connection_id": _id("con"),
        "placement_epoch": 4,
        "cell_id": "cell-europe",
        "connector_catalog_digest": HASH,
        "redaction_revision": "relay-redaction-v1",
        "classification_ceiling": "INTERNAL",
        "region": "europe-west1",
        "relay_connection_epoch": 5,
        "service_key": "payments-api",
        "resource_binding_id": _id("pgn"),
        "resource_ref": "projects/customer/locations/europe-west1/services/payments-api",
        "external_project_id": "customer",
        "node_kind": "SERVICE",
        "resource_binding_hash": HASH,
    }


def _author(connection: Connection, signer: Signer) -> RelayJobAuthor:
    return RelayJobAuthor(
        connection=connection,  # type: ignore[arg-type]
        signer=signer,
        signing_key_id="relay-control-v1",
        signing_key_version=(
            "projects/test/locations/europe-west1/keyRings/relay/cryptoKeys/control/"
            "cryptoKeyVersions/1"
        ),
    )


def test_authoring_replay_returns_existing_job_without_resigning() -> None:
    connection = Connection([{"id": _id("rcj")}])
    signer = Signer()
    job_id = _author(connection, signer).author_observability_job(
        scope=_scope(), agent_run_id=_id("run"), tool_call_id=_id("tcl"), arguments=_arguments()
    )
    assert job_id == _id("rcj")
    assert signer.digests == []


def test_authoring_requires_every_current_authority_binding() -> None:
    connection = Connection([None, None])
    with pytest.raises(RelayJobAuthoringError, match="current qualified"):
        _author(connection, Signer()).author_observability_job(
            scope=_scope(),
            agent_run_id=_id("run"),
            tool_call_id=_id("tcl"),
            arguments=_arguments(),
        )


def test_authoring_signs_only_the_coordinator_derived_job(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = Connection([None, _authority_row()])
    signer = Signer()
    observed: dict[str, Any] = {}

    def create(self: PostgresRelayStore, *, scope: Scope, material: Any, **_kwargs: Any) -> str:
        del self
        observed["scope"] = scope
        observed["material"] = material
        return material.collection_job_id

    monkeypatch.setattr(PostgresRelayStore, "create_collection_job", create)
    job_id = _author(connection, signer).author_observability_job(
        scope=_scope(), agent_run_id=_id("run"), tool_call_id=_id("tcl"), arguments=_arguments()
    )
    material = observed["material"]
    assert job_id == material.collection_job_id
    assert material.operation == "monitoring.time-series.read.v1"
    assert material.typed_parameters["resource_name"] == "payments-api"
    assert material.typed_parameters["metric_key"] == "p95_latency_ms"
    assert material.signature_base64
    assert signer.digests == [bytes.fromhex(material.job_digest.removeprefix("sha256:"))]
    material.require_signed_digest(scope=observed["scope"])


def test_each_qualified_adapter_has_one_fixed_tool_provider_and_parameter_shape() -> None:
    end = datetime.now(UTC) - timedelta(minutes=1)
    arguments = (
        ManagedPrometheusArgs(
            service_id=_id("svc"),
            query_template_key="http_error_ratio",
            window_start=end - timedelta(minutes=5),
            window_end=end,
        ),
        LoggingArgs(
            service_id=_id("svc"),
            log_view_id="payments-errors",
            signature_key="service_errors",
            window_start=end - timedelta(minutes=5),
            window_end=end,
            maximum_entries=10,
        ),
        TraceArgs(service_id=_id("svc"), trace_id="a" * 32),
        KubernetesMetadataArgs(
            service_id=_id("svc"), namespace="payments", resource_kind="Deployment"
        ),
    )
    expected = {
        "managed_prometheus_query": ("MANAGED_PROMETHEUS", "prometheus.registered-range.read.v1"),
        "cloud_logging_query": ("CLOUD_LOGGING", "logging.entries.read.v1"),
        "cloud_trace_read": ("CLOUD_TRACE", "trace.spans.read.v1"),
        "kubernetes_metadata_read": ("KUBERNETES", "kubernetes.metadata.list.v1"),
    }
    for argument in arguments:
        specification = _relay_specification(argument)
        assert expected[specification["expected_tool_name"]] == (
            specification["expected_provider"],
            specification["operation"],
        )
        parameters = _relay_parameters(
            arguments=argument,
            resource_binding_id=_id("pgn"),
            resource_project_id="customer-project",
            resource_name="payments-api",
            window_start=end - timedelta(minutes=5),
            window_end=end,
        )
        assert "endpoint" not in parameters
        assert "credential" not in " ".join(parameters)
        assert "url" not in parameters
