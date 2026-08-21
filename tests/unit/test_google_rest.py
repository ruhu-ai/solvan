from __future__ import annotations

from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

import solvan.platform.google_rest as google_rest
import solvan.platform.telemetry as telemetry
from solvan.platform.google_rest import TracePropagatingGoogleRestSession


class _Response:
    def __init__(self, status_code: int = 202) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.content = b""

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, str]:
        return {"status": "accepted"}


class _RecordingSession:
    def __init__(self, *, error: Exception | None = None, status_code: int = 202) -> None:
        self.error = error
        self.status_code = status_code
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _Response:
        self.calls.append((method, url, kwargs))
        if self.error is not None:
            raise self.error
        return _Response(self.status_code)


@pytest.fixture
def tracing(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("solvan-test")
    monkeypatch.setattr(telemetry.trace, "get_tracer", lambda *_args, **_kwargs: tracer)
    yield tracer, exporter
    provider.shutdown()


def test_authorized_rest_injects_child_context_without_changing_authorization(tracing) -> None:
    tracer, exporter = tracing
    delegate = _RecordingSession()
    session = TracePropagatingGoogleRestSession(delegate)

    with tracer.start_as_current_span("parent") as parent:
        parent_context = parent.get_span_context()
        response = session.post(
            "https://example.googleapis.com/v1/private/path?token=query-secret",
            headers={
                "Authorization": "Bearer credential-secret",
                "Traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
                "X-Solvan-Request": "request-1",
            },
            json={"prompt": "body-secret"},
        )

    assert response.status_code == 202
    method, _url, kwargs = delegate.calls[0]
    assert method == "POST"
    headers = kwargs["headers"]
    assert headers["Authorization"] == "Bearer credential-secret"
    assert headers["X-Solvan-Request"] == "request-1"
    assert "Traceparent" not in headers
    version, trace_id, span_id, flags = headers["traceparent"].split("-")
    assert version == "00"
    assert trace_id == format(parent_context.trace_id, "032x")
    assert span_id != "bbbbbbbbbbbbbbbb"
    assert int(flags, 16) & 1 == 1

    client_span = next(span for span in exporter.get_finished_spans() if span.name == "HTTP POST")
    assert format(client_span.context.span_id, "016x") == span_id
    assert client_span.parent is not None
    assert client_span.parent.span_id == parent_context.span_id
    assert client_span.attributes == {
        "http.request.method": "POST",
        "url.scheme": "https",
        "server.address": "example.googleapis.com",
        "http.response.status_code": 202,
    }
    serialized = repr((client_span.attributes, client_span.events))
    assert "private/path" not in serialized
    assert "query-secret" not in serialized
    assert "credential-secret" not in serialized
    assert "body-secret" not in serialized


def test_authorized_rest_records_only_bounded_error_class(tracing) -> None:
    _tracer, exporter = tracing

    class SensitiveTransportError(RuntimeError):
        pass

    delegate = _RecordingSession(error=SensitiveTransportError("raw-error-secret"))
    session = TracePropagatingGoogleRestSession(delegate)

    with pytest.raises(SensitiveTransportError, match="raw-error-secret"):
        session.get("https://example.googleapis.com/v1/private?secret=value")

    client_span = next(span for span in exporter.get_finished_spans() if span.name == "HTTP GET")
    assert client_span.status.status_code is StatusCode.ERROR
    assert client_span.attributes["error.type"] == "SensitiveTransportError"
    assert not client_span.events
    serialized = repr((client_span.attributes, client_span.events))
    assert "raw-error-secret" not in serialized
    assert "private" not in serialized
    assert "secret=value" not in serialized


def test_authorized_rest_classifies_error_response_without_capturing_body(tracing) -> None:
    _tracer, exporter = tracing
    session = TracePropagatingGoogleRestSession(_RecordingSession(status_code=503))

    response = session.patch(
        "https://example.googleapis.com/v1/private",
        json={"secret": "body-secret"},
    )

    assert response.status_code == 503
    client_span = next(span for span in exporter.get_finished_spans() if span.name == "HTTP PATCH")
    assert client_span.status.status_code is StatusCode.ERROR
    assert client_span.attributes["http.response.status_code"] == 503
    assert "body-secret" not in repr((client_span.attributes, client_span.events))


def test_authorized_session_composes_the_trace_wrapper(monkeypatch) -> None:
    delegate = _RecordingSession()
    monkeypatch.setattr(google_rest.google.auth, "default", lambda **_kwargs: (object(), "p"))
    monkeypatch.setattr(google_rest, "AuthorizedSession", lambda _credentials: delegate)

    session = google_rest.authorized_session()

    assert isinstance(session, TracePropagatingGoogleRestSession)
