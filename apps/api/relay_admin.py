"""Administrator-only, secret-free Solvant Relay enrollment routes."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.domain import (
    RelayAdapter,
    RelayContractError,
    RelaySourceBindingRegistration,
    Scope,
)
from solvan.persistence.relay_store import PostgresRelayStore, RelayConflict
from solvan.platform.database import connect_database


class _StrictCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RelayDeploymentProfileApprovalCommand(_StrictCommand):
    schema_version: Literal[1]
    deployment_profile_id: str = Field(pattern=r"^rdp_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    risk_acceptance_ref: str | None = Field(default=None, max_length=500)


_RELAY_SOURCE_REQUIREMENTS = {
    "cloud-monitoring.v1": (RelayAdapter.CLOUD_MONITORING, "CLOUD_MONITORING", "metrics.read"),
    "managed-prometheus.v1": (RelayAdapter.MANAGED_PROMETHEUS, "MANAGED_PROMETHEUS", "promql.read"),
    "cloud-logging.v1": (RelayAdapter.CLOUD_LOGGING, "CLOUD_LOGGING", "logs.read"),
    "cloud-trace.v1": (RelayAdapter.CLOUD_TRACE, "CLOUD_TRACE", "traces.read"),
    "kubernetes-metadata.v1": (
        RelayAdapter.KUBERNETES_METADATA,
        "KUBERNETES",
        "kubernetes.metadata.read",
    ),
}


class RelaySourceBindingCommand(_StrictCommand):
    schema_version: Literal[1]
    source_connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    adapter_key: Literal[
        "cloud-monitoring.v1",
        "managed-prometheus.v1",
        "cloud-logging.v1",
        "cloud-trace.v1",
        "kubernetes-metadata.v1",
    ]
    adapter_revision: str = Field(min_length=1, max_length=64)


class RelayEnrollmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enrollment_id: str
    lifecycle: str


class RelaySourceBindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_binding_id: str
    lifecycle: str


class RelayEnrollmentProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enrollment_id: str
    lifecycle: str
    enrollment_epoch: int
    host_kind: str
    region: str
    classification_ceiling: str
    relay_version: str
    safe_reason_code: str | None
    last_poll_at: datetime | None
    last_receipt_at: datetime | None


class RelayDeploymentProfileProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deployment_profile_id: str
    relay_connection_id: str
    host_kind: str
    region: str
    classification_ceiling: str
    image_attestation_id: str
    relay_version: str
    expires_at: datetime
    review_state: str


class EnrollmentLifecycleCommand(_StrictCommand):
    schema_version: Literal[1]


class RelayJobCancellationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    collection_job_id: str
    state: str


def relay_admin_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
) -> APIRouter:
    router = APIRouter()

    def administrator(token: str | None, scope: Scope) -> str:
        principal = principal_provider(token)
        with connect_database() as connection:
            row = connection.execute(
                """SELECT EXISTS (
                     SELECT 1 FROM solvan.actor_role_bindings
                      WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                        AND environment_id=%(environment_id)s AND principal=%(principal)s
                        AND role='ADMIN' AND (expires_at IS NULL OR expires_at > now()))""",
                {**scope.canonical_dict(), "principal": principal},
            ).fetchone()
        if row is None or not bool(row[0]):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role is required")
        return principal

    @router.post("/api/v1/relays", response_model=RelayEnrollmentResponse, status_code=201)
    def enroll(
        request: RelayDeploymentProfileApprovalCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RelayEnrollmentResponse:
        scope = scope_provider()
        principal = administrator(human_identity_token, scope)
        try:
            with connect_database() as connection, connection.transaction():
                enrollment_id = PostgresRelayStore(connection).approve_deployment_profile(
                    scope=scope,
                    deployment_profile_id=request.deployment_profile_id,
                    principal=principal,
                    approved_at=datetime.now(UTC),
                    risk_acceptance_ref=request.risk_acceptance_ref,
                )
        except (RelayContractError, RelayConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "ENROLLMENT_INELIGIBLE") from error
        return RelayEnrollmentResponse(enrollment_id=enrollment_id, lifecycle="REGISTERED")

    @router.post(
        "/api/v1/relays/{enrollment_id}/source-bindings",
        response_model=RelaySourceBindingResponse,
        status_code=201,
    )
    def bind_source(
        enrollment_id: str,
        request: RelaySourceBindingCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RelaySourceBindingResponse:
        scope = scope_provider()
        principal = administrator(human_identity_token, scope)
        adapter, provider, capability = _RELAY_SOURCE_REQUIREMENTS[request.adapter_key]
        try:
            with connect_database() as connection, connection.transaction():
                row = connection.execute(
                    """SELECT c.connection_epoch,c.residency_region,c.classification,
                              capability.probe_receipt_ref,profile.local_binding_digest
                         FROM solvan.tenant_connections c
                         JOIN solvan_relay.relay_enrollments enrollment
                           ON enrollment.organization_id=c.organization_id
                          AND enrollment.project_id=c.project_id
                          AND enrollment.environment_id=c.environment_id
                          AND enrollment.id=%(enrollment_id)s
                         JOIN solvan_relay.relay_deployment_profiles profile
                           ON (profile.organization_id,profile.project_id,
                               profile.environment_id,profile.id)=
                              (enrollment.organization_id,enrollment.project_id,
                               enrollment.environment_id,enrollment.deployment_profile_id)
                         JOIN solvan.connection_capabilities capability
                           ON (capability.organization_id,capability.project_id,
                               capability.environment_id,capability.connection_id)=
                              (c.organization_id,c.project_id,c.environment_id,c.id)
                        WHERE c.organization_id=%(organization_id)s
                          AND c.project_id=%(project_id)s AND c.environment_id=%(environment_id)s
                          AND c.id=%(connection_id)s AND c.provider=%(provider)s
                          AND capability.capability=%(capability)s
                          AND enrollment.lifecycle IN ('REGISTERED','READY','DEGRADED','STALE')
                          AND capability.available FOR SHARE OF c,capability""",
                    {
                        **scope.canonical_dict(),
                        "connection_id": request.source_connection_id,
                        "enrollment_id": enrollment_id,
                        "provider": provider,
                        "capability": capability,
                    },
                ).fetchone()
                if row is None:
                    raise RelayConflict("Relay source connection is ineligible or unprobed")
                receipt_ref = str(row[3])
                registration = RelaySourceBindingRegistration(
                    source_connection_id=request.source_connection_id,
                    source_connection_epoch=int(row[0]),
                    adapter_key=adapter,
                    adapter_revision=request.adapter_revision,
                    local_binding_digest=str(row[4]),
                    capability_receipt_id=(
                        "cap-" + hashlib.sha256(receipt_ref.encode("utf-8")).hexdigest()
                    ),
                    capability_receipt_hash="sha256:"
                    + hashlib.sha256(receipt_ref.encode("utf-8")).hexdigest(),
                    region=str(row[1]),
                    classification_ceiling=str(row[2]),
                )
                binding_id = PostgresRelayStore(connection).register_source_binding(
                    scope=scope,
                    enrollment_id=enrollment_id,
                    registration=registration,
                    principal=principal,
                    registered_at=datetime.now(UTC),
                )
        except (RelayContractError, RelayConflict) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "SOURCE_BINDING_INELIGIBLE") from error
        return RelaySourceBindingResponse(source_binding_id=binding_id, lifecycle="READY")

    def _transition_enrollment(
        enrollment_id: str,
        *,
        action: Literal["DISABLE", "REVOKE"],
        human_identity_token: str | None,
    ) -> RelayEnrollmentResponse:
        scope = scope_provider()
        principal = administrator(human_identity_token, scope)
        try:
            with connect_database() as connection, connection.transaction():
                lifecycle = PostgresRelayStore(connection).transition_enrollment_administratively(
                    scope=scope,
                    enrollment_id=enrollment_id,
                    action=action,
                    principal=principal,
                    occurred_at=datetime.now(UTC),
                )
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "LIFECYCLE_CONFLICT") from error
        return RelayEnrollmentResponse(enrollment_id=enrollment_id, lifecycle=lifecycle)

    @router.post("/api/v1/relays/{enrollment_id}:disable", response_model=RelayEnrollmentResponse)
    def disable(
        enrollment_id: str,
        _request: EnrollmentLifecycleCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RelayEnrollmentResponse:
        return _transition_enrollment(
            enrollment_id, action="DISABLE", human_identity_token=human_identity_token
        )

    @router.post("/api/v1/relays/{enrollment_id}:revoke", response_model=RelayEnrollmentResponse)
    def revoke(
        enrollment_id: str,
        _request: EnrollmentLifecycleCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RelayEnrollmentResponse:
        return _transition_enrollment(
            enrollment_id, action="REVOKE", human_identity_token=human_identity_token
        )

    @router.post(
        "/api/v1/relay-jobs/{collection_job_id}:cancel",
        response_model=RelayJobCancellationResponse,
    )
    def cancel_job(
        collection_job_id: str,
        _request: EnrollmentLifecycleCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RelayJobCancellationResponse:
        """Cancel only unclaimed work; in-flight reads are reconciled, never erased."""

        scope = scope_provider()
        principal = administrator(human_identity_token, scope)
        try:
            with connect_database() as connection, connection.transaction():
                state = PostgresRelayStore(connection).request_job_cancellation(
                    scope=scope,
                    collection_job_id=collection_job_id,
                    principal=principal,
                    requested_at=datetime.now(UTC),
                )
        except RelayConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "RELAY_JOB_CONFLICT") from error
        return RelayJobCancellationResponse(collection_job_id=collection_job_id, state=state)

    @router.get("/api/v1/relays", response_model=list[RelayEnrollmentProjection])
    def list_enrollments(
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[RelayEnrollmentProjection]:
        scope = scope_provider()
        administrator(human_identity_token, scope)
        with connect_database() as connection:
            rows = connection.execute(
                """SELECT id,lifecycle,enrollment_epoch,host_kind,region,classification_ceiling,
                          relay_version,safe_reason_code,last_poll_at,last_receipt_at
                     FROM solvan_relay.relay_enrollments
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s ORDER BY created_at DESC""",
                scope.canonical_dict(),
            ).fetchall()
        return [
            RelayEnrollmentProjection(
                enrollment_id=str(row[0]),
                lifecycle=str(row[1]),
                enrollment_epoch=int(row[2]),
                host_kind=str(row[3]),
                region=str(row[4]),
                classification_ceiling=str(row[5]),
                relay_version=str(row[6]),
                safe_reason_code=None if row[7] is None else str(row[7]),
                last_poll_at=row[8],
                last_receipt_at=row[9],
            )
            for row in rows
        ]

    @router.get(
        "/api/v1/relay-deployment-profiles",
        response_model=list[RelayDeploymentProfileProjection],
    )
    def list_deployment_profiles(
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[RelayDeploymentProfileProjection]:
        scope = scope_provider()
        administrator(human_identity_token, scope)
        with connect_database() as connection:
            rows = connection.execute(
                """SELECT id,relay_connection_id,host_kind,region,classification_ceiling,
                          image_attestation_id,relay_version,expires_at,review_state
                     FROM solvan_relay.relay_deployment_profiles
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY asserted_at DESC""",
                scope.canonical_dict(),
            ).fetchall()
        return [
            RelayDeploymentProfileProjection(
                deployment_profile_id=str(row[0]),
                relay_connection_id=str(row[1]),
                host_kind=str(row[2]),
                region=str(row[3]),
                classification_ceiling=str(row[4]),
                image_attestation_id=str(row[5]),
                relay_version=str(row[6]),
                expires_at=row[7],
                review_state=str(row[8]),
            )
            for row in rows
        ]

    return router
