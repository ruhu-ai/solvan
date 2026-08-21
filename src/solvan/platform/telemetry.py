"""Content-free outbound telemetry helpers for platform transports."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from urllib.parse import urlsplit

from opentelemetry import trace
from opentelemetry.propagate import inject
from opentelemetry.trace import Span, SpanKind, Status, StatusCode

_TRACE_HEADER_NAMES = frozenset({"traceparent", "tracestate"})


def inject_trace_context(headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """Copy headers and replace caller propagation with the active local context."""

    outbound = dict(headers or {})
    for name in tuple(outbound):
        if name.lower() in _TRACE_HEADER_NAMES:
            del outbound[name]

    propagated: dict[str, str] = {}
    inject(propagated)
    for name, value in propagated.items():
        if name.lower() in _TRACE_HEADER_NAMES:
            outbound[name] = value
    return outbound


@contextmanager
def outbound_http_span(*, method: str, url: str) -> Iterator[Span]:
    """Create a client span containing no path, query, body, or error message."""

    normalized_method = method.upper()
    scheme, destination = _safe_destination(url)
    tracer = trace.get_tracer("solvan.platform.http", "1.0.0")
    with tracer.start_as_current_span(
        f"HTTP {normalized_method}",
        kind=SpanKind.CLIENT,
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        span.set_attribute("http.request.method", normalized_method)
        span.set_attribute("url.scheme", scheme)
        span.set_attribute("server.address", destination)
        try:
            yield span
        except Exception as error:
            span.set_attribute("error.type", type(error).__name__)
            span.set_status(Status(StatusCode.ERROR))
            raise


def record_http_response(span: Span, *, status_code: int) -> None:
    """Record only the bounded HTTP result on an outbound client span."""

    span.set_attribute("http.response.status_code", status_code)
    if status_code >= 400:
        span.set_status(Status(StatusCode.ERROR))


def _safe_destination(url: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        destination = parsed.hostname or "unknown"
    except ValueError:
        return "unknown", "invalid"
    if scheme not in {"http", "https"}:
        scheme = "unknown"
    return scheme, destination
