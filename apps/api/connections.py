"""Authenticated tenant-connection and actuator registration routes.

Registration is an administrative act: it decides what Solvan may read from a
customer estate and which customer-deployed actuator may act. Every route
therefore requires a verified human identity holding the ADMIN role, and none
of them ever accepts a credential value — only a Secret Manager reference.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import asdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from apps.api.connection_contracts import (
    ConnectionEpochCommand,
    ConnectionEpochResponse,
    RegistrationResponse,
)
from apps.api.direct_gcp_probe import (
    DirectGcpAlertSourceRequest,
    DirectGcpAlertSourceResponse,
    DirectGcpPilotQualificationRequest,
    ProbeResponse,
)
from apps.api.direct_gcp_probe import (
    probe_direct_gcp_connection as _direct_gcp_probe,
)
from apps.api.direct_gcp_probe import (
    qualify_direct_gcp_pilot as _qualify_direct_gcp_pilot,
)
from apps.api.estate_onboarding_flow import (
    EstateConnectionRequest,
    EstateConnectionResponse,
    register_estate,
)
from apps.api.session_authorization import require_administrator, require_csrf
from apps.api.vendor_scope import VENDOR_SCOPE_HOSTS, VendorTransport
from solvan.application.alert_triage import AlertIngressError
from solvan.application.credential_scope_verification import (
    HttpVendorScopeInspector,
    unverifiable_scope,
    verify_read_only_scope,
)
from solvan.application.onboarding import (
    EstateSelectionError,
    estate_onboarding_plan,
    onboarding_plan,
)
from solvan.application.tenant_integration import (
    ActuatorPosture,
    ActuatorRegistration,
    ConnectionAuthenticationMode,
    ConnectionPolicyError,
    ConnectionRegistration,
    CredentialPosture,
    CredentialScopeVerdict,
    ExternalResourceScope,
    GcpResourceKind,
    HostKind,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.alert_triage import AlertTriageRepository, SourceRegistration
from solvan.persistence.connection_store import PostgresConnectionStore
from solvan.platform.database import connect_database
from solvan.platform.google_rest import authorized_session
from solvan.platform.secret_manager import SecretManagerReader

# A pinned numeric version, never an alias. A Secret Manager version's payload
# is immutable, so the key whose scope was proved read-only at registration is
# the key every later read resolves. An alias such as `versions/latest` follows
# whatever payload was added most recently, which would let a write-capable key
# replace a verified one with nothing in Solvan changing and nothing re-checked.
# A connection revision is immutable, so rotation is a new revision, and a new
# revision verifies its own key.
_SECRET_REF = r"^projects/[^/]+/secrets/[^/]+/versions/[0-9]+$"
_CONNECTION_ID = r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$"


class ConnectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    display_name: str = Field(min_length=1, max_length=120)
    kind: Literal["GCP_NATIVE", "VENDOR_API", "COLLECTOR", "RELAY"]
    provider: str = Field(min_length=1, max_length=40)
    credential_posture: Literal["FEDERATED_SHORT_LIVED", "STORED_LONG_LIVED", "CUSTOMER_SIDE_NONE"]
    #: Control-plane residency is selected by the deployed cell, never by the
    #: browser. Workload location is the separately scoped `workload_region`.
    residency_region: str | None = Field(default=None, min_length=1, max_length=40)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    authentication_mode: Literal[
        "GCP_SERVICE_ACCOUNT_IMPERSONATION",
        "STORED_SECRET_REFERENCE",
        "CUSTOMER_SIDE_NONE",
    ]
    solvan_delegator_principal: str | None = Field(default=None, min_length=16, max_length=320)
    customer_reader_principal: str | None = Field(default=None, min_length=16, max_length=320)
    delegation_condition_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    token_lifetime_seconds: int | None = Field(default=None, ge=1, le=900)
    gcp_resource_kind: Literal["GCP_PROJECT", "GCP_FOLDER", "GCP_ORGANIZATION"] | None = None
    gcp_resource_id: str | None = Field(default=None, min_length=1, max_length=160)
    workload_region: str | None = Field(
        default=None, pattern=r"^[a-z]+(?:-[a-z0-9]+)*$", max_length=40
    )
    metrics_scoping_project_id: str | None = Field(default=None, min_length=6, max_length=63)
    scope_decision_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    #: A reference, never a value. A key pasted here would be rejected by the
    #: pattern and would never reach the database.
    credential_secret_ref: str | None = Field(default=None, pattern=_SECRET_REF)
    credential_cmek_key_ref: str | None = None
    #: `read_only_scope_verified` is deliberately not a field. It was one, and
    #: being a request field is what made the schema's read-only constraint
    #: prove only that a caller had ticked a box. `extra="forbid"` now refuses
    #: the name outright rather than ignoring it, so a client that still sends
    #: it learns that its assertion carries no authority.


class ActuatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    connection_id: str = Field(pattern=_CONNECTION_ID)
    host_kind: Literal["CLOUD_RUN", "GKE", "ONPREM_FEDERATED", "ONPREM_KEYFILE", "DEV_LOCAL"]
    principal_email: str = Field(min_length=3, max_length=320)
    expected_audience: str = Field(min_length=8, max_length=300)
    posture: Literal["COLLECTOR", "REMEDIATE"]
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    actuator_version: str = Field(min_length=1, max_length=40)
    risk_acceptance_ref: str | None = None
    policy_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    policy_source_ref: str | None = None
    customer_audit_sink_ref: str | None = None
    #: Absent, eligibility is derived and a key-file host is not eligible. An
    #: operator raising a key-file host to production states it here, alongside
    #: the risk acceptance the host already requires.
    production_eligible: bool | None = None


def _stored_key_scope_verdict(
    *, provider: str, credential_secret_ref: str
) -> CredentialScopeVerdict:
    """Conclude a stored vendor key's scope here; the caller never asserts it.

    Every failure becomes an `UNVERIFIABLE` verdict rather than an exception, so
    an unreachable vendor or an unconfigured deployment refuses the registration
    with a reason an operator can act on instead of failing onboarding with an
    error that says nothing.
    """

    try:
        inspector = HttpVendorScopeInspector(
            VendorTransport(),
            hosts={
                provider_name: host
                for provider_name, variable in VENDOR_SCOPE_HOSTS.items()
                if (host := os.environ.get(variable))
            },
        )
        secrets = SecretManagerReader(authorized_session())
    except Exception:
        return unverifiable_scope(
            provider=provider,
            credential_secret_ref=credential_secret_ref,
            reason_code="VERIFIER_UNAVAILABLE",
        )
    return verify_read_only_scope(
        provider=provider,
        credential_secret_ref=credential_secret_ref,
        secrets=secrets,
        inspector=inspector,
    )


def connection_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
) -> APIRouter:
    router = APIRouter()

    def _admin(token: str | None, scope: Scope) -> str:
        principal = principal_provider(token)
        with connect_database() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND principal = %(principal)s AND role = 'ADMIN'
                      AND (expires_at IS NULL OR expires_at > now())) AS active""",
                {**scope.canonical_dict(), "principal": principal},
            )
            row = cursor.fetchone()
        if row is None or not row[0]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role is required")
        return principal

    @router.post("/api/v1/connections", response_model=RegistrationResponse)
    def register_connection(
        request: ConnectionRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RegistrationResponse:
        scope = scope_provider()
        principal = _admin(human_identity_token, scope)
        control_plane_region = os.environ.get("SOLVAN_REGION", "europe-west1")
        if (
            request.residency_region is not None
            and request.residency_region != control_plane_region
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "control-plane residency is selected by this deployment, not the request",
            )
        if request.gcp_resource_kind is None and any(
            (
                request.gcp_resource_id,
                request.workload_region,
                request.metrics_scoping_project_id,
                request.scope_decision_ref,
            )
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "an external resource kind is required with every external resource scope field",
            )
        registration = ConnectionRegistration(
            display_name=request.display_name,
            kind=request.kind,
            provider=request.provider,
            credential_posture=CredentialPosture(request.credential_posture),
            residency_region=control_plane_region,
            classification=request.classification,
            authentication_mode=ConnectionAuthenticationMode(request.authentication_mode),
            solvan_delegator_principal=request.solvan_delegator_principal,
            customer_reader_principal=request.customer_reader_principal,
            delegation_condition_digest=request.delegation_condition_digest,
            token_lifetime_seconds=request.token_lifetime_seconds,
            resource_scope=(
                ExternalResourceScope(
                    resource_kind=GcpResourceKind(request.gcp_resource_kind),
                    resource_id=request.gcp_resource_id or "",
                    workload_region=request.workload_region or "",
                    metrics_scoping_project_id=request.metrics_scoping_project_id,
                    decision_ref=request.scope_decision_ref or "",
                )
                if request.gcp_resource_kind is not None
                else None
            ),
            credential_secret_ref=request.credential_secret_ref,
            credential_cmek_key_ref=request.credential_cmek_key_ref,
            scope_verification=(
                _stored_key_scope_verdict(
                    provider=request.provider,
                    credential_secret_ref=request.credential_secret_ref or "",
                )
                if request.credential_posture == "STORED_LONG_LIVED"
                else None
            ),
        )
        try:
            if registration.credential_posture is CredentialPosture.FEDERATED_SHORT_LIVED:
                configured_delegator = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
                if not configured_delegator:
                    raise ConnectionPolicyError("the Solvan reader identity is not configured")
                if (
                    registration.solvan_delegator_principal
                    != f"serviceAccount:{configured_delegator}"
                ):
                    raise ConnectionPolicyError(
                        "the direct connection delegator is not this deployment's reader identity"
                    )
                assert registration.resource_scope is not None
                if registration.resource_scope.resource_kind is not GcpResourceKind.GCP_PROJECT:
                    raise ConnectionPolicyError(
                        "direct Cloud Monitoring requires an exact GCP project scope"
                    )
                plan = onboarding_plan(
                    provider=registration.provider,
                    posture=registration.credential_posture,
                    customer_project_id=registration.resource_scope.resource_id,
                    solvan_service_account=configured_delegator,
                    customer_reader_service_account=(
                        registration.customer_reader_principal or ""
                    ).removeprefix("serviceAccount:"),
                )
                if registration.delegation_condition_digest != plan.delegation_condition_digest:
                    raise ConnectionPolicyError(
                        "the direct connection condition does not match the generated grant plan"
                    )
            with connect_database() as connection, connection.transaction():
                connection_id = PostgresConnectionStore(connection).register_connection(
                    scope=scope, registration=registration, actor=principal
                )
        except ConnectionPolicyError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        return RegistrationResponse(id=connection_id, created=True)

    @router.post("/api/v1/connections/estates", response_model=EstateConnectionResponse)
    def connect_estate(
        http_request: Request,
        request: EstateConnectionRequest,
    ) -> EstateConnectionResponse:
        """Connect one estate, one connection per chosen capability.

        The flow itself lives in `apps.api.estate_onboarding_flow`: it is a
        distinct responsibility from the connection CRUD around it, and long
        enough to be read on its own.
        """

        return register_estate(
            http_request=http_request,
            request=request,
            scope=scope_provider(),
            probe=lambda scope, connection_id: _direct_gcp_probe(
                scope=scope, connection_id=connection_id
            ).result,
        )

    @router.post("/api/v1/connections/{connection_id}:probe", response_model=ProbeResponse)
    def probe(connection_id: str, request: Request) -> ProbeResponse:
        """Re-observe one connection under the signed-in administrator's session.

        A bounded read-only check that grants nothing, so the challenge
        registry records it as needing none — but it reveals what a customer
        delegation can reach, so it runs under the live session and a current
        ADMIN role. It previously took a pasted identity token, which carried
        no freshness, no session, and no CSRF binding.
        """
        scope = scope_provider()
        require_csrf(request)
        require_administrator(request, scope)
        return _direct_gcp_probe(scope=scope, connection_id=connection_id)

    @router.post("/api/v1/direct-gcp-alert-sources", response_model=DirectGcpAlertSourceResponse)
    def register_direct_gcp_alert_source(
        request: DirectGcpAlertSourceRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> DirectGcpAlertSourceResponse:
        scope = scope_provider()
        actor = _admin(human_identity_token, scope)
        if not idempotency_key or len(idempotency_key) > 128:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "an idempotency key is required"
            )
        registration = SourceRegistration(**request.model_dump(exclude={"schema_version"}))
        try:
            with connect_database() as connection, connection.transaction():
                repository = AlertTriageRepository(connection)
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT connection_epoch,authentication_mode,kind,provider,lifecycle,
                                  availability
                             FROM solvan.tenant_connections
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                              AND id=%(connection_id)s FOR UPDATE""",
                        {**scope.canonical_dict(), "connection_id": request.connection_id},
                    )
                    connection_row = cursor.fetchone()
                if connection_row != (
                    request.connection_epoch,
                    "GCP_SERVICE_ACCOUNT_IMPERSONATION",
                    "GCP_NATIVE",
                    "CLOUD_MONITORING",
                    "ENABLED",
                    "READY",
                ):
                    raise AlertIngressError("SOURCE_CONNECTION_INELIGIBLE")
                source_identity_id = repository.register_cloud_monitoring_source(
                    scope=scope,
                    registration=registration,
                    actor_principal=actor,
                    idempotency_key=idempotency_key,
                    request_hash=canonical_sha256(request.model_dump(mode="json")),
                )
                binding = repository.source_binding(
                    scope=scope, connection_id=request.connection_id, require_qualified=False
                )
        except AlertIngressError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, error.reason_code) from error
        return DirectGcpAlertSourceResponse(
            source_identity_id=source_identity_id,
            source_binding_id=binding.source_binding_id,
            source_binding_epoch=binding.binding_epoch,
            status="PENDING_CONFIGURATION",
        )

    @router.post("/api/v1/direct-gcp-pilot:qualify")
    def qualify_direct_gcp_pilot(
        request: DirectGcpPilotQualificationRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, object]:
        _admin(human_identity_token, scope_provider())
        return _qualify_direct_gcp_pilot(request)

    @router.post(
        "/api/v1/connections/{connection_id}:invalidate",
        response_model=ConnectionEpochResponse,
    )
    def invalidate_connection(
        connection_id: str,
        request: ConnectionEpochCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> ConnectionEpochResponse:
        """Fence prior proofs before credential, policy, or binding replacement."""

        scope = scope_provider()
        _admin(human_identity_token, scope)
        try:
            with connect_database() as connection, connection.transaction():
                epoch = PostgresConnectionStore(connection).invalidate_connection(
                    scope=scope,
                    connection_id=connection_id,
                    expected_epoch=request.expected_epoch,
                    revoke=False,
                )
        except ConnectionPolicyError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return ConnectionEpochResponse(
            connection_id=connection_id, connection_epoch=epoch, status="PENDING"
        )

    @router.post(
        "/api/v1/connections/{connection_id}:revoke",
        response_model=ConnectionEpochResponse,
    )
    def revoke_connection(
        connection_id: str,
        request: ConnectionEpochCommand,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> ConnectionEpochResponse:
        scope = scope_provider()
        _admin(human_identity_token, scope)
        try:
            with connect_database() as connection, connection.transaction():
                epoch = PostgresConnectionStore(connection).invalidate_connection(
                    scope=scope,
                    connection_id=connection_id,
                    expected_epoch=request.expected_epoch,
                    revoke=True,
                )
        except ConnectionPolicyError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return ConnectionEpochResponse(
            connection_id=connection_id, connection_epoch=epoch, status="REVOKED"
        )

    @router.post("/api/v1/actuators", response_model=RegistrationResponse)
    def register_actuator(
        request: ActuatorRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RegistrationResponse:
        scope = scope_provider()
        principal = _admin(human_identity_token, scope)
        registration = ActuatorRegistration(
            connection_id=request.connection_id,
            host_kind=HostKind(request.host_kind),
            principal_email=request.principal_email,
            expected_audience=request.expected_audience,
            posture=ActuatorPosture(request.posture),
            image_digest=request.image_digest,
            actuator_version=request.actuator_version,
            risk_acceptance_ref=request.risk_acceptance_ref,
            policy_hash=request.policy_hash,
            policy_source_ref=request.policy_source_ref,
            customer_audit_sink_ref=request.customer_audit_sink_ref,
            production_eligible_override=request.production_eligible,
        )
        try:
            with connect_database() as connection, connection.transaction():
                actuator_id = PostgresConnectionStore(connection).register_actuator(
                    scope=scope, registration=registration, actor=principal
                )
        except ConnectionPolicyError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        return RegistrationResponse(id=actuator_id, created=True)

    @router.get("/api/v1/connections/grant-plan")
    def grant_plan(
        provider: str,
        credential_posture: Literal[
            "FEDERATED_SHORT_LIVED", "STORED_LONG_LIVED", "CUSTOMER_SIDE_NONE"
        ],
        customer_project_id: str,
        customer_reader_service_account: str | None = None,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """Return the exact commands the customer runs. Reads nothing, grants nothing."""

        _admin(human_identity_token, scope_provider())
        solvan_principal = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
        if not solvan_principal:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "the Solvan reader identity is not configured",
            )
        try:
            plan = onboarding_plan(
                provider=provider,
                posture=CredentialPosture(credential_posture),
                customer_project_id=customer_project_id,
                solvan_service_account=solvan_principal,
                customer_reader_service_account=customer_reader_service_account,
            )
        except ConnectionPolicyError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        return {
            "posture": str(plan.posture),
            "summary": plan.summary,
            "secret_required": plan.secret_required,
            "delegation_condition_digest": plan.delegation_condition_digest,
            "solvan_delegator_principal": (
                f"serviceAccount:{solvan_principal}"
                if credential_posture == "FEDERATED_SHORT_LIVED"
                else None
            ),
            "steps": [asdict(step) for step in plan.steps],
        }

    @router.get("/api/v1/connections/estate-grant-plan")
    def estate_grant_plan(
        http_request: Request,
        customer_project_id: str,
        customer_reader_service_account: str,
        provider: Annotated[list[str] | None, Query()] = None,
    ) -> dict[str, Any]:
        """One plan for every chosen capability. Reads nothing, grants nothing.

        Authorized by the session rather than a pasted token: it grants nothing,
        so it needs no challenge, but it does describe a customer's project and
        the identity that will read it — which is not for anyone who happens to
        reach the console.
        """

        require_administrator(http_request, scope_provider())
        solvan_principal = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
        if not solvan_principal:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "the Solvan reader identity is not configured",
            )
        try:
            plan = estate_onboarding_plan(
                providers=provider or [],
                customer_project_id=customer_project_id,
                solvan_service_account=solvan_principal,
                customer_reader_service_account=customer_reader_service_account,
            )
        except EstateSelectionError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, error.reason_code) from error
        return {
            "posture": str(plan.posture),
            "providers": list(plan.providers),
            "roles": list(plan.roles),
            "summary": plan.summary,
            "secret_required": plan.secret_required,
            "delegation_condition_digest": plan.delegation_condition_digest,
            "solvan_delegator_principal": f"serviceAccount:{solvan_principal}",
            "steps": [asdict(step) for step in plan.steps],
        }

    return router
