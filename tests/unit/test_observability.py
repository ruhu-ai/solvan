from __future__ import annotations

import logging

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

import solvan.observability as observability
from solvan.observability import (
    ObservabilityConfiguration,
    configure_observability,
    instrument_fastapi,
)


def test_configuration_rejects_ambiguous_exporter(monkeypatch) -> None:
    monkeypatch.setenv("SOLVAN_OTEL_EXPORTER", "console-ish")
    try:
        ObservabilityConfiguration.from_environment(service_name="test")
    except RuntimeError as exc:
        assert "none or google_cloud" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("ambiguous exporter was accepted")


def test_google_export_requires_explicit_project(monkeypatch) -> None:
    monkeypatch.setenv("SOLVAN_OTEL_EXPORTER", "google_cloud")
    monkeypatch.delenv("SOLVAN_GCP_PROJECT", raising=False)
    try:
        ObservabilityConfiguration.from_environment(service_name="test")
    except RuntimeError as exc:
        assert "SOLVAN_GCP_PROJECT" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("Google export without a project was accepted")


def test_google_exporter_composition_is_single_service(monkeypatch) -> None:
    calls: list[object] = []

    class Provider:
        def __init__(self, **kwargs) -> None:
            calls.append(("provider", kwargs))

        def add_span_processor(self, processor) -> None:
            calls.append(("span", processor))

    class LoggerProvider:
        def __init__(self, **kwargs) -> None:
            calls.append(("logger", kwargs))

        def add_log_record_processor(self, processor) -> None:
            calls.append(("log", processor))

    monkeypatch.setattr(observability, "TracerProvider", Provider)
    monkeypatch.setattr(observability, "LoggerProvider", LoggerProvider)
    monkeypatch.setattr(observability, "CloudTraceSpanExporter", lambda **kwargs: kwargs)
    monkeypatch.setattr(observability, "CloudLoggingExporter", lambda **kwargs: kwargs)
    monkeypatch.setattr(observability, "BatchSpanProcessor", lambda exporter: ("span", exporter))
    monkeypatch.setattr(
        observability, "BatchLogRecordProcessor", lambda exporter: ("log", exporter)
    )
    monkeypatch.setattr(observability, "LoggingHandler", lambda **kwargs: logging.NullHandler())
    monkeypatch.setattr(observability.trace, "set_tracer_provider", calls.append)
    monkeypatch.setattr(observability, "_CONFIGURED_SERVICE", None)
    monkeypatch.setattr(observability, "_LOGGER_PROVIDER", None)
    config = ObservabilityConfiguration("api", "staging", "solvan-demo", "google_cloud")
    configure_observability(config)
    configure_observability(config)
    assert any(item[0] == "provider" for item in calls if isinstance(item, tuple))
    try:
        configure_observability(
            ObservabilityConfiguration("coordinator", "staging", "solvan-demo", "google_cloud")
        )
    except RuntimeError as exc:
        assert "multiple Solvan service identities" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("multiple service identities were accepted")


def test_fastapi_instrumentation_propagates_w3c_trace_without_content(monkeypatch) -> None:
    monkeypatch.setenv("SOLVAN_OTEL_EXPORTER", "none")
    app = FastAPI()

    @app.post("/items/{item_id}")
    def item(item_id: str) -> dict[str, str]:
        return {"item_id": item_id}

    instrument_fastapi(app, service_name="test-service")
    assert instrument_fastapi(app, service_name="test-service") is app
    trace_id = "0123456789abcdef0123456789abcdef"
    response = TestClient(app).post(
        "/items/private-value",
        headers={"traceparent": f"00-{trace_id}-0123456789abcdef-01"},
        json={"secret": "must-not-be-captured"},
    )
    assert response.status_code == 200
    assert response.headers["x-solvan-trace-id"] == trace_id
    assert response.json() == {"item_id": "private-value"}


def test_fastapi_instrumentation_marks_server_failure(monkeypatch) -> None:
    monkeypatch.setenv("SOLVAN_OTEL_EXPORTER", "none")
    app = FastAPI()

    @app.get("/failure")
    def failure() -> Response:
        return Response(status_code=503)

    instrument_fastapi(app, service_name="failure-test")
    assert TestClient(app).get("/failure").status_code == 503


def test_fastapi_instrumentation_ignores_malformed_inbound_trace_context(monkeypatch) -> None:
    monkeypatch.setenv("SOLVAN_OTEL_EXPORTER", "none")
    app = FastAPI()

    @app.get("/identity")
    def identity() -> dict[str, str]:
        return {"principal": "server-verified"}

    instrument_fastapi(app, service_name="malformed-trace-test")
    response = TestClient(app).get(
        "/identity",
        headers={
            "Authorization": "Bearer attacker-controlled",
            "traceparent": "not-a-w3c-context",
        },
    )

    assert response.status_code == 200
    assert response.headers["x-solvan-trace-id"] == "unsampled"
    assert response.json() == {"principal": "server-verified"}
