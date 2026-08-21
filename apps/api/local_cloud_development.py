"""Local-only administration for exercising a real GCP read path.

These routes are registered only by ``scripts/start-cloud-dev``. They create
explicitly non-authoritative local rule material and ask the authenticated
loopback worker to run the normal detector/inbox transition. No route exists
in a deployed Solvan service and no mutation connector is reachable here.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Literal
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Header, HTTPException, Request, status
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field

from apps.api.session_authorization import (
    recorded_principal,
    require_administrator,
    require_csrf,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.detection_connection_store import (
    DetectionConnectionBindingError,
    PostgresDetectionConnectionStore,
)
from solvan.platform.database import connect_database
from solvan.platform.local_service_token import read_local_service_token


class LocalMonitoringRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    expected_connection_epoch: int = Field(ge=1)
    display_name: str = Field(min_length=1, max_length=120)
    resource_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    signal_kind: Literal["HTTP_5XX_RATIO", "HTTP_P95_LATENCY", "SQL_CONNECTIONS"]
    comparator: Literal["GT", "GTE", "LT", "LTE"]
    threshold: float
    sustained_windows: int = Field(ge=1, le=12)
    severity: Literal["SEV1", "SEV2", "SEV3", "SEV4"]


class LocalMonitoringRuleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_version: int
    service_id: str
    connection_id: str
    connection_epoch: int
    project_id: str
    resource_name: str
    signal_kind: str
    comparator: str
    threshold: float


class LocalPipelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluated_rules: int
    inserted_evaluations: int
    emitted_events: int
    inbox_claimed: int
    inbox_completed: int


def _worker_url() -> str:
    value = os.environ.get("SOLVAN_LOCAL_CLOUD_WORKER_URL", "")
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("local cloud worker is not bound to loopback")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        raise RuntimeError("local cloud worker URL is unsafe")
    return value.rstrip("/")


def _rule_key(request: LocalMonitoringRuleRequest, project_id: str) -> str:
    signal = {
        "HTTP_5XX_RATIO": "http-5xx",
        "HTTP_P95_LATENCY": "http-p95",
        "SQL_CONNECTIONS": "sql-connections",
    }[request.signal_kind]
    suffix = hashlib.sha256(
        f"local-monitoring-rule-v2\0{project_id}\0{request.resource_name}\0{request.signal_kind}".encode()
    ).hexdigest()[:12]
    return f"dev-{signal}-{suffix}"


def _deduplication_dimension(request: LocalMonitoringRuleRequest, project_id: str) -> str:
    """Bind the exact target without introducing the event key's `:` separator."""

    digest = hashlib.sha256(
        f"{project_id}\0{request.resource_name}\0{request.signal_kind}".encode()
    ).hexdigest()[:24]
    return f"target-{digest}"


def local_cloud_development_router(
    *,
    scope_provider: Callable[[], Scope],
) -> APIRouter:
    router = APIRouter()

    @router.get(
        "/api/v1/local-development/monitoring-rules",
        response_model=list[LocalMonitoringRuleResponse],
    )
    def list_rules(request: Request) -> list[LocalMonitoringRuleResponse]:
        scope = scope_provider()
        require_administrator(request, scope)
        with connect_database() as connection, connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id,r.version,r.service_id,b.connection_id,b.connection_epoch,
                          x.resource_id,r.query_json,r.signal_kind,r.comparator,r.threshold
                     FROM solvan.detection_rules r
                     JOIN solvan_onboarding.detection_rule_connection_bindings b
                       ON (b.organization_id,b.project_id,b.environment_id,
                           b.detection_rule_id,b.detection_rule_version)=
                          (r.organization_id,r.project_id,r.environment_id,r.id,r.version)
                     JOIN solvan_onboarding.connection_external_resource_scopes x
                       ON (x.organization_id,x.project_id,x.environment_id,x.connection_id)=
                          (b.organization_id,b.project_id,b.environment_id,b.connection_id)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s
                      AND r.status='APPROVED'
                      AND r.calibration_receipt_ref LIKE 'local-development://monitoring-rule/%%'
                    ORDER BY r.id""",
                scope.canonical_dict(),
            )
            rows = cursor.fetchall()
        return [
            LocalMonitoringRuleResponse(
                rule_id=str(row["id"]),
                rule_version=int(row["version"]),
                service_id=str(row["service_id"]),
                connection_id=str(row["connection_id"]),
                connection_epoch=int(row["connection_epoch"]),
                project_id=str(row["resource_id"]),
                resource_name=str(row["query_json"]["resource_name"]),
                signal_kind=str(row["signal_kind"]),
                comparator=str(row["comparator"]),
                threshold=float(row["threshold"]),
            )
            for row in rows
        ]

    @router.post(
        "/api/v1/local-development/monitoring-rules",
        response_model=LocalMonitoringRuleResponse,
    )
    def create_rule(
        request: LocalMonitoringRuleRequest,
        http_request: Request,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> LocalMonitoringRuleResponse:
        scope = scope_provider()
        require_csrf(http_request)
        actor_id = require_administrator(http_request, scope)
        if not idempotency_key or len(idempotency_key) > 128:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "idempotency key required")
        material = request.model_dump(mode="json")
        request_hash = canonical_sha256(material)
        try:
            with connect_database() as connection, connection.transaction():
                actor = recorded_principal(connection, actor_id)
                with connection.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        """SELECT c.connection_epoch,x.resource_id,x.workload_region
                             FROM solvan.tenant_connections c
                             JOIN solvan_onboarding.connection_external_resource_scopes x
                               ON (x.organization_id,x.project_id,x.environment_id,x.connection_id)=
                                  (c.organization_id,c.project_id,c.environment_id,c.id)
                            WHERE c.organization_id=%(organization_id)s
                              AND c.project_id=%(project_id)s
                              AND c.environment_id=%(environment_id)s
                              AND c.id=%(connection_id)s AND c.provider='CLOUD_MONITORING'
                              AND c.kind='GCP_NATIVE'
                              AND c.authentication_mode='GCP_SERVICE_ACCOUNT_IMPERSONATION'
                              AND c.lifecycle='ENABLED' AND c.availability='READY'
                              AND x.resource_kind='GCP_PROJECT'
                            FOR UPDATE OF c""",
                        {
                            **scope.canonical_dict(),
                            "connection_id": request.connection_id,
                        },
                    )
                    connection_row = cursor.fetchone()
                    if connection_row is None or int(connection_row["connection_epoch"]) != (
                        request.expected_connection_epoch
                    ):
                        raise ValueError("a current READY Cloud Monitoring connection is required")
                    external_project = str(connection_row["resource_id"])
                    workload_region = str(connection_row["workload_region"])
                    if request.signal_kind == "SQL_CONNECTIONS":
                        if not request.resource_name.startswith(f"{external_project}:"):
                            raise ValueError("a Cloud SQL metric resource must be PROJECT:INSTANCE")
                        platform_kind = "CLOUD_SQL_INSTANCE"
                        platform_resource = (
                            f"projects/{external_project}/instances/"
                            f"{request.resource_name.removeprefix(external_project + ':')}"
                        )
                    else:
                        platform_kind = "CLOUD_RUN_SERVICE"
                        platform_resource = (
                            f"projects/{external_project}/locations/{workload_region}/services/"
                            f"{request.resource_name}"
                        )
                    rule_id = _rule_key(request, external_project)
                    service_key = rule_id.removeprefix("dev-")
                    cursor.execute(
                        """SELECT id,display_name,platform_kind,platform_resource
                             FROM solvan.services
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND service_key=%(service_key)s FOR UPDATE""",
                        {**scope.canonical_dict(), "service_key": service_key},
                    )
                    existing_service = cursor.fetchone()
                    if existing_service is None:
                        service_id = new_identifier("svc")
                        cursor.execute(
                            """INSERT INTO solvan.services
                              (organization_id,project_id,environment_id,id,service_key,
                               display_name,platform_kind,platform_resource,owner_department)
                              VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(service_id)s,%(service_key)s,%(display_name)s,%(platform_kind)s,
                               %(platform_resource)s,'local-development')""",
                            {
                                **scope.canonical_dict(),
                                "service_id": service_id,
                                "service_key": service_key,
                                "display_name": request.display_name,
                                "platform_kind": platform_kind,
                                "platform_resource": platform_resource,
                            },
                        )
                    else:
                        service_id = str(existing_service["id"])
                        if (
                            existing_service["display_name"],
                            existing_service["platform_kind"],
                            existing_service["platform_resource"],
                        ) != (request.display_name, platform_kind, platform_resource):
                            raise ValueError("monitoring rule retry changed its service material")
                    cursor.execute(
                        """SELECT id FROM solvan.production_graph_snapshots
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND status='APPROVED' AND superseded_at IS NULL""",
                        scope.canonical_dict(),
                    )
                    graph = cursor.fetchone()
                    if graph is None:
                        raise ValueError("local development has no approved graph snapshot")
                    query = {
                        "gcp_project_id": external_project,
                        "resource_name": request.resource_name,
                        "window_ms": 60_000,
                    }
                    calibration_ref = f"local-development://monitoring-rule/{request_hash}"
                    cursor.execute(
                        """INSERT INTO solvan.detection_rules
                          (organization_id,project_id,environment_id,id,version,service_id,
                           incident_class,signal_kind,query_json,evaluation_interval_ms,
                           comparator,threshold,sustained_windows,severity,
                           deduplication_dimension,action_budget,repeated_action_limit,status,
                           calibration_receipt_ref,approved_by,approved_at)
                          VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(rule_id)s,1,%(service_id)s,'local_connected_gcp_observation',
                           %(signal_kind)s,%(query)s,25000,%(comparator)s,%(threshold)s,
                           %(sustained_windows)s,%(severity)s,%(dedupe)s,1,1,'APPROVED',
                           %(calibration_ref)s,%(actor)s,now())
                          ON CONFLICT DO NOTHING""",
                        {
                            **scope.canonical_dict(),
                            "rule_id": rule_id,
                            "service_id": service_id,
                            "signal_kind": request.signal_kind,
                            "query": Jsonb(query),
                            "comparator": request.comparator,
                            "threshold": request.threshold,
                            "sustained_windows": request.sustained_windows,
                            "severity": request.severity,
                            "dedupe": _deduplication_dimension(request, external_project),
                            "calibration_ref": calibration_ref,
                            "actor": actor,
                        },
                    )
                    cursor.execute(
                        """SELECT service_id,signal_kind,query_json,comparator,threshold,
                                  sustained_windows,severity,calibration_receipt_ref
                             FROM solvan.detection_rules
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND id=%(rule_id)s AND version=1""",
                        {**scope.canonical_dict(), "rule_id": rule_id},
                    )
                    stored = cursor.fetchone()
                    expected = (
                        service_id,
                        request.signal_kind,
                        query,
                        request.comparator,
                        float(request.threshold),
                        request.sustained_windows,
                        request.severity,
                        calibration_ref,
                    )
                    observed = (
                        None
                        if stored is None
                        else (
                            str(stored["service_id"]),
                            str(stored["signal_kind"]),
                            stored["query_json"],
                            str(stored["comparator"]),
                            float(stored["threshold"]),
                            int(stored["sustained_windows"]),
                            str(stored["severity"]),
                            str(stored["calibration_receipt_ref"]),
                        )
                    )
                    if observed != expected:
                        raise ValueError("monitoring rule retry changed immutable material")
                binding = PostgresDetectionConnectionStore(connection).bind(
                    scope=scope,
                    detection_rule_id=rule_id,
                    detection_rule_version=1,
                    connection_id=request.connection_id,
                    expected_connection_epoch=request.expected_connection_epoch,
                    actor=actor,
                    decision_ref="local-development://ui-configured-monitoring-rule",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                )
        except (DetectionConnectionBindingError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return LocalMonitoringRuleResponse(
            rule_id=rule_id,
            rule_version=1,
            service_id=service_id,
            connection_id=binding.connection_id,
            connection_epoch=binding.connection_epoch,
            project_id=external_project,
            resource_name=request.resource_name,
            signal_kind=request.signal_kind,
            comparator=request.comparator,
            threshold=request.threshold,
        )

    @router.post(
        "/api/v1/local-development/pipeline:run",
        response_model=LocalPipelineResponse,
    )
    def run_pipeline(
        request: Request,
    ) -> LocalPipelineResponse:
        scope = scope_provider()
        require_csrf(request)
        require_administrator(request, scope)
        try:
            response = httpx.post(
                f"{_worker_url()}/internal/dev/pipeline:run",
                json={"schema_version": 1},
                headers={"Authorization": f"Bearer {read_local_service_token()}"},
                timeout=120,
            )
            response.raise_for_status()
            return LocalPipelineResponse.model_validate(response.json())
        except (httpx.HTTPError, RuntimeError, ValueError) as error:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                f"local connected pipeline refused: {type(error).__name__}",
            ) from error

    return router
