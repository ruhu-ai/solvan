"""Dedicated authenticated Cloud Monitoring Alert Ingress service.

This process deliberately imports only the provider adapter and durable ingress
repository. It does not mount operator, connection-administration, coordinator,
console, model, or incident routes.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Response, status

from apps.api.alerts import alert_ingress_router
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.platform.database import connect_database


def _scope() -> Scope:
    try:
        return Scope(
            os.environ["SOLVAN_ORGANIZATION_ID"],
            os.environ["SOLVAN_SCOPE_PROJECT_ID"],
            os.environ["SOLVAN_ENVIRONMENT_ID"],
        )
    except KeyError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Alert Ingress scope is not configured",
        ) from error


app = FastAPI(title="Solvan Alert Ingress", docs_url=None, redoc_url=None, openapi_url=None)
instrument_fastapi(app, service_name="solvan-alert-ingress")
app.include_router(alert_ingress_router(scope_provider=_scope, connect=connect_database))


@app.get("/healthz", include_in_schema=False)
def healthz() -> Response:
    """Liveness only; readiness is established by a signed qualification receipt."""

    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
