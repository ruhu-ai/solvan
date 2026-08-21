"""Control-plane commit path for bounded Direct GCP connection probes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import httpx
from fastapi import HTTPException, status
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.tenant_integration import CapabilityObservation, ConnectionPolicyError
from solvan.domain import Scope
from solvan.persistence.connection_store import PostgresConnectionStore
from solvan.platform.database import connect_database
from solvan.platform.local_service_token import read_local_service_token


class ProbeCapability(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str = Field(min_length=1, max_length=160)
    available: bool
    missing_grant: str | None
    probe_receipt_ref: str = Field(min_length=1, max_length=1024)
    outcome: Literal["GRANTED", "DENIED", "MISCONFIGURED", "UNREACHABLE", "NOT_PROBED"]


class ProbeResponse(BaseModel):
    connection_id: str
    connection_epoch: int
    result: Literal["SUCCEEDED", "PARTIAL", "FAILED"]
    capabilities: list[ProbeCapability]


class DirectGcpAlertSourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    connection_epoch: int = Field(ge=1)
    scoping_project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,61}$")
    topic_name: str = Field(pattern=r"^projects/[^/]+/topics/[^/]+$")
    topic_binding_receipt_ref: str = Field(min_length=1, max_length=1024)
    subscription_name: str = Field(pattern=r"^projects/[^/]+/subscriptions/[^/]+$")
    push_principal: str = Field(pattern=r"^[^@ ]+@[^@ ]+$")
    oidc_audience: str = Field(pattern=r"^https://")
    source_material_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    configuration_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    pubsub_token_minting_receipt_ref: str = Field(min_length=1, max_length=1024)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    retention_policy_revision: str = Field(min_length=1, max_length=255)


class DirectGcpAlertSourceResponse(BaseModel):
    source_identity_id: str
    source_binding_id: str
    source_binding_epoch: int
    status: Literal["PENDING_CONFIGURATION", "QUALIFIED", "DISABLED", "REVOKED"]


class DirectGcpPilotQualificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    source_binding_id: str = Field(pattern=r"^asb_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    source_binding_epoch: int = Field(ge=1)


def probe_direct_gcp_connection(*, scope: Scope, connection_id: str) -> ProbeResponse:
    """Ask the reader to observe, then commit the epoch-fenced result in the API."""

    reader_url = os.environ.get("SOLVAN_DIRECT_GCP_READER_URL")
    reader_socket = os.environ.get("SOLVAN_LOCAL_DIRECT_GCP_READER_SOCKET")
    if bool(reader_url) == bool(reader_socket):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "exactly one direct GCP reader transport must be configured",
        )
    try:
        with connect_database() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT c.connection_epoch,c.provider,c.authentication_mode,
                          c.solvan_delegator_principal,c.customer_reader_principal,
                          c.token_lifetime_seconds,s.resource_kind,s.resource_id
                     FROM solvan.tenant_connections c
                     JOIN solvan_onboarding.connection_external_resource_scopes s
                       ON (s.organization_id,s.project_id,s.environment_id,s.connection_id)=
                          (c.organization_id,c.project_id,c.environment_id,c.id)
                    WHERE c.organization_id=%(organization_id)s AND c.project_id=%(project_id)s
                      AND c.environment_id=%(environment_id)s AND c.id=%(connection_id)s
                      AND c.lifecycle NOT IN ('REVOKED','DISABLED')""",
                {**scope.canonical_dict(), "connection_id": connection_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "connection is not registered")
        (
            connection_epoch,
            provider,
            authentication_mode,
            delegator,
            customer_reader,
            lifetime,
            resource_kind,
            resource_id,
        ) = row
        if (
            authentication_mode != "GCP_SERVICE_ACCOUNT_IMPERSONATION"
            or resource_kind != "GCP_PROJECT"
            or not isinstance(delegator, str)
            or not isinstance(customer_reader, str)
            or not isinstance(lifetime, int)
            or not isinstance(resource_id, str)
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "connection is not an eligible direct GCP reader binding",
            )
        body = {
            "schema_version": 1,
            "connection_id": connection_id,
            "connection_epoch": connection_epoch,
            "provider": provider,
            "authentication_mode": authentication_mode,
            "solvan_delegator_principal": delegator,
            "customer_reader_principal": customer_reader,
            "token_lifetime_seconds": lifetime,
            "resource_kind": resource_kind,
            "resource_id": resource_id,
        }
        if reader_socket:
            socket_path = Path(reader_socket)
            if not socket_path.is_absolute() or socket_path.is_symlink():
                raise ValueError("local direct GCP reader socket is unsafe")
            token = read_local_service_token()
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=str(socket_path)),
                base_url="http://solvan-local-reader",
                timeout=35,
            ) as client:
                response = client.post(
                    "/internal/v1/connections:probe",
                    json=body,
                    headers={"Authorization": f"Bearer {token}"},
                )
        else:
            assert reader_url is not None
            if not reader_url.startswith("https://"):
                raise ValueError("deployed direct GCP reader URL must use HTTPS")
            token = id_token.fetch_id_token(GoogleAuthRequest(), reader_url)  # type: ignore[no-untyped-call]
            response = httpx.post(
                f"{reader_url.rstrip('/')}/internal/v1/connections:probe",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
                timeout=35,
            )
        response.raise_for_status()
        observed = ProbeResponse.model_validate(response.json())
        if observed.connection_id != connection_id or observed.connection_epoch != connection_epoch:
            raise ValueError("reader response does not match the requested connection revision")
        observations = tuple(
            CapabilityObservation(
                capability=item.capability,
                available=item.available,
                missing_grant=item.missing_grant,
                probe_receipt_ref=item.probe_receipt_ref,
                outcome=item.outcome,
            ).validated()
            for item in observed.capabilities
        )
        with connect_database() as connection, connection.transaction():
            result = PostgresConnectionStore(connection).record_probe(
                scope=scope,
                connection_id=connection_id,
                observations=observations,
                expected_epoch=connection_epoch,
            )
        return ProbeResponse(
            connection_id=connection_id,
            connection_epoch=connection_epoch,
            result=result,  # type: ignore[arg-type]
            capabilities=observed.capabilities,
        )
    except ConnectionPolicyError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "direct GCP reader refused the probe"
        ) from error


def qualify_direct_gcp_pilot(request: DirectGcpPilotQualificationRequest) -> dict[str, object]:
    verifier_url = os.environ.get("SOLVAN_PILOT_QUALIFICATION_VERIFIER_URL")
    if not verifier_url or not verifier_url.startswith("https://"):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "pilot qualification verifier is not configured"
        )
    try:
        token = id_token.fetch_id_token(GoogleAuthRequest(), verifier_url)  # type: ignore[no-untyped-call]
        response = httpx.post(
            f"{verifier_url.rstrip('/')}/internal/v1/direct-gcp-pilot:qualify",
            json=request.model_dump(),
            headers={"Authorization": f"Bearer {token}"},
            timeout=45,
        )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise ValueError("qualification verifier returned an invalid result")
        return value
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "pilot qualification verifier refused"
        ) from error
