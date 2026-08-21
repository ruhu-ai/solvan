"""Adversarial unit tests for the closed customer Relay observability adapters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from apps.solvant_relay.cloud_logging import CloudLoggingRelayAdapter
from apps.solvant_relay.cloud_trace import CloudTraceRelayAdapter
from apps.solvant_relay.kubernetes_metadata import KubernetesMetadataRelayAdapter
from apps.solvant_relay.managed_prometheus import ManagedPrometheusRelayAdapter
from apps.solvant_relay.runtime import RelayRuntimeError


class Response:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload


class Session:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> Response:
        self.calls.append(("GET", url, kwargs))
        return Response(self.payload)

    def post(self, url: str, **kwargs: Any) -> Response:
        self.calls.append(("POST", url, kwargs))
        return Response(self.payload)


NOW = datetime(2026, 8, 17, 10, tzinfo=UTC)


def test_prometheus_uses_one_registered_template_and_refuses_query_injection() -> None:
    session = Session({"data": {"result": [{"values": [[NOW.timestamp(), "4.5"]]}]}})
    adapter = ManagedPrometheusRelayAdapter(session=session)  # type: ignore[arg-type]
    records = adapter.read(
        adapter={
            "endpoint": {"host": "monitoring.googleapis.com"},
            "registered_query_keys": ["http_requests_total"],
        },
        parameters={
            "query_template_key": "http_requests_total",
            "resource_binding_id": "pgn_binding",
            "resource_project_id": "customer-project",
            "service_key": "payments-api",
            "window_start": (NOW - timedelta(minutes=5)).isoformat(),
            "window_end": NOW.isoformat(),
            "step_seconds": 60,
            "maximum_series": 1,
            "maximum_points": 10,
        },
        maximum_pages=1,
        maximum_items=10,
        maximum_bytes=10_000,
        maximum_calls=1,
    )
    assert records[0]["value"] == 4.5
    assert session.calls[0][0] == "GET"
    assert "sum(rate(http_requests_total" in str(session.calls[0][2]["params"])
    with pytest.raises(RelayRuntimeError, match="template or binding"):
        adapter.read(
            adapter={
                "endpoint": {"host": "monitoring.googleapis.com"},
                "registered_query_keys": ["http_requests_total"],
            },
            parameters={
                "query_template_key": "http_requests_total",
                "resource_binding_id": "pgn_binding",
                "resource_project_id": "customer-project",
                "service_key": 'payments"} or vector(1) or {service="',
                "window_start": (NOW - timedelta(minutes=5)).isoformat(),
                "window_end": NOW.isoformat(),
                "step_seconds": 60,
                "maximum_series": 1,
                "maximum_points": 10,
            },
            maximum_pages=1,
            maximum_items=10,
            maximum_bytes=10_000,
            maximum_calls=1,
        )


def test_logging_projects_only_registered_signature_and_refuses_untrusted_response() -> None:
    session = Session({"entries": [{"timestamp": NOW.isoformat(), "severity": "ERROR"}]})
    adapter = CloudLoggingRelayAdapter(session=session)  # type: ignore[arg-type]
    records = adapter.read(
        adapter={
            "endpoint": {"host": "logging.googleapis.com"},
            "approved_log_signatures": ["service_errors"],
        },
        parameters={
            "signature_key": "service_errors",
            "resource_binding_id": "pgn_binding",
            "resource_project_id": "customer-project",
            "service_name": "payments-api",
            "window_start": (NOW - timedelta(minutes=5)).isoformat(),
            "window_end": NOW.isoformat(),
            "maximum_entries": 10,
        },
        maximum_pages=1,
        maximum_items=10,
        maximum_bytes=10_000,
        maximum_calls=1,
    )
    assert records == (
        {
            "kind": "LOG_EVENT",
            "timestamp": NOW.isoformat(),
            "severity": "ERROR",
            "message_template_key": "service_errors",
            "safe_parameters": {},
            "attributes": {"service.name": "payments-api"},
        },
    )
    assert 'severity>="ERROR"' in str(session.calls[0][2]["json"]["filter"])
    with pytest.raises(RelayRuntimeError, match="signature is not locally authorized"):
        adapter.read(
            adapter={
                "endpoint": {"host": "logging.googleapis.com"},
                "approved_log_signatures": [],
            },
            parameters={
                "signature_key": "service_errors",
                "resource_binding_id": "pgn_binding",
                "resource_project_id": "customer-project",
                "service_name": "payments-api",
                "window_start": (NOW - timedelta(minutes=5)).isoformat(),
                "window_end": NOW.isoformat(),
                "maximum_entries": 10,
            },
            maximum_pages=1,
            maximum_items=10,
            maximum_bytes=10_000,
            maximum_calls=1,
        )


def test_trace_requires_incident_bound_identifier_and_strict_span_shape() -> None:
    trace_id = "a" * 32
    session = Session(
        {
            "traceId": trace_id,
            "spans": [
                {
                    "spanId": "1",
                    "startTime": NOW.isoformat(),
                    "endTime": (NOW + timedelta(seconds=1)).isoformat(),
                    "labels": {"error": "true"},
                }
            ],
        }
    )
    adapter = CloudTraceRelayAdapter(session=session)  # type: ignore[arg-type]
    records = adapter.read(
        adapter={"endpoint": {"host": "cloudtrace.googleapis.com"}},
        parameters={
            "trace_id": trace_id,
            "resource_binding_id": "pgn_binding",
            "resource_project_id": "customer-project",
            "service_name": "payments-api",
            "maximum_spans": 10,
        },
        maximum_pages=1,
        maximum_items=10,
        maximum_bytes=10_000,
        maximum_calls=1,
    )
    assert records[0]["status"] == "ERROR"
    with pytest.raises(RelayRuntimeError, match="parameters"):
        adapter.read(
            adapter={"endpoint": {"host": "cloudtrace.googleapis.com"}},
            parameters={
                "trace_id": "not-a-trace",
                "resource_binding_id": "pgn_binding",
                "resource_project_id": "customer-project",
                "service_name": "payments-api",
                "maximum_spans": 10,
            },
            maximum_pages=1,
            maximum_items=10,
            maximum_bytes=10_000,
            maximum_calls=1,
        )


def test_kubernetes_metadata_cannot_escape_the_policy_namespace_kind_or_selector() -> None:
    session = Session(
        {
            "items": [
                {
                    "metadata": {
                        "name": "payments-api-7d5d6c",
                        "namespace": "payments",
                        "uid": "uid-1",
                        "labels": {"app.kubernetes.io/name": "payments-api"},
                    }
                }
            ]
        }
    )
    adapter = KubernetesMetadataRelayAdapter(session=session)  # type: ignore[arg-type]
    records = adapter.read(
        adapter={
            "endpoint": {"host": "gke.customer.example"},
            "allowed_namespaces": ["payments"],
            "allowed_resource_kinds": ["Deployment"],
        },
        parameters={
            "resource_binding_id": "pgn_binding",
            "namespace": "payments",
            "resource_kind": "Deployment",
            "service_key": "payments-api",
            "maximum_items": 10,
        },
        maximum_pages=1,
        maximum_items=10,
        maximum_bytes=10_000,
        maximum_calls=1,
    )
    assert records[0]["namespace"] == "payments"
    assert session.calls[0][1].endswith("/apis/apps/v1/namespaces/payments/deployments")
    with pytest.raises(RelayRuntimeError, match="locally authorized"):
        adapter.read(
            adapter={
                "endpoint": {"host": "gke.customer.example"},
                "allowed_namespaces": ["other"],
                "allowed_resource_kinds": ["Deployment"],
            },
            parameters={
                "resource_binding_id": "pgn_binding",
                "namespace": "payments",
                "resource_kind": "Deployment",
                "service_key": "payments-api",
                "maximum_items": 10,
            },
            maximum_pages=1,
            maximum_items=10,
            maximum_bytes=10_000,
            maximum_calls=1,
        )
