"""Content-free OpenTelemetry instrumentation for Solvan Cloud Run services."""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from threading import Lock

from fastapi import FastAPI, Request, Response
from opentelemetry import trace
from opentelemetry.context import attach, detach
from opentelemetry.exporter.cloud_logging import CloudLoggingExporter
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.propagate import extract
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanKind, Status, StatusCode

_LOCK = Lock()
_CONFIGURED_SERVICE: str | None = None
_LOGGER_PROVIDER: LoggerProvider | None = None
_LOGGER = logging.getLogger("solvan.telemetry")
_LOGGER.propagate = False


@dataclass(frozen=True, slots=True)
class ObservabilityConfiguration:
    service_name: str
    environment: str
    project_id: str | None
    exporter: str

    @classmethod
    def from_environment(cls, *, service_name: str) -> ObservabilityConfiguration:
        exporter = os.environ.get("SOLVAN_OTEL_EXPORTER", "none")
        if exporter not in {"none", "google_cloud"}:
            raise RuntimeError("SOLVAN_OTEL_EXPORTER must be none or google_cloud")
        project_id = os.environ.get("SOLVAN_GCP_PROJECT")
        if exporter == "google_cloud" and not project_id:
            raise RuntimeError("SOLVAN_GCP_PROJECT is required for Google Cloud OTel export")
        return cls(
            service_name=service_name,
            environment=os.environ.get("SOLVAN_ENVIRONMENT", "local"),
            project_id=project_id,
            exporter=exporter,
        )


def configure_observability(config: ObservabilityConfiguration) -> None:
    """Configure one process-wide trace and content-free log pipeline."""

    global _CONFIGURED_SERVICE, _LOGGER_PROVIDER
    with _LOCK:
        if config.exporter == "none":
            if not _LOGGER.handlers:
                _LOGGER.addHandler(logging.NullHandler())
            return
        if _CONFIGURED_SERVICE is not None:
            if config.service_name != _CONFIGURED_SERVICE:
                raise RuntimeError("one process cannot host multiple Solvan service identities")
            return
        _CONFIGURED_SERVICE = config.service_name
        resource = Resource.create(
            {
                "service.name": config.service_name,
                "service.namespace": "solvan",
                "deployment.environment.name": config.environment,
            }
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(
            BatchSpanProcessor(
                CloudTraceSpanExporter(project_id=config.project_id)  # type: ignore[no-untyped-call]
            )
        )
        trace.set_tracer_provider(provider)

        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(
                CloudLoggingExporter(
                    project_id=config.project_id,
                    default_log_name="solvan-control-plane",
                )
            )
        )
        _LOGGER_PROVIDER = logger_provider
        _LOGGER.handlers.clear()
        _LOGGER.addHandler(LoggingHandler(level=logging.INFO, logger_provider=logger_provider))
        _LOGGER.setLevel(logging.INFO)


def instrument_fastapi(app: FastAPI, *, service_name: str) -> FastAPI:
    """Add W3C propagation and low-cardinality HTTP spans without content capture."""

    if getattr(app.state, "solvan_otel_instrumented", False):
        return app
    configure_observability(ObservabilityConfiguration.from_environment(service_name=service_name))
    app.state.solvan_otel_instrumented = True
    tracer = trace.get_tracer("solvan.http", "1.0.0")

    @app.middleware("http")
    async def telemetry(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        parent = extract(dict(request.headers))
        token = attach(parent)
        try:
            with tracer.start_as_current_span(request.method, kind=SpanKind.SERVER) as span:
                span.set_attribute("http.request.method", request.method)
                response = await call_next(request)
                route = request.scope.get("route")
                route_path = getattr(route, "path", None) or "unmatched"
                span.update_name(f"{request.method} {route_path}")
                span.set_attribute("http.route", route_path)
                span.set_attribute("http.response.status_code", response.status_code)
                if response.status_code >= 500:
                    span.set_status(Status(StatusCode.ERROR))
                context = span.get_span_context()
                trace_id = format(context.trace_id, "032x") if context.is_valid else "unsampled"
                response.headers["x-solvan-trace-id"] = trace_id
                _LOGGER.info(
                    "solvan.http.request",
                    extra={
                        "solvan.service": service_name,
                        "http.request.method": request.method,
                        "http.route": route_path,
                        "http.response.status_code": response.status_code,
                    },
                )
                return response
        finally:
            detach(token)

    return app
