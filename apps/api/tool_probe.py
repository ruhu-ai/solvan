"""Control-plane commit path for bounded governed Tool capability probes.

The reader observes and the API commits, because the SQL grant model says so:
`api` is the only workload holding INSERT on `tool_probe_receipts` and
`connection_external_project_coverage`, and the reader — the sole identity that
may impersonate an enrolled customer service account — holds no database
identity at all. Neither is widened to make this path shorter.

Every fact written here comes from an authority that already exists. The Tool's
registry resource, network policy hash, Gateway destination, and declared
capability are immutable catalog columns. The Agent Identity comes only from the
attested deployment binding, which names a real Agent Runtime resource. Nothing
is defaulted: when an attestation is absent this route refuses, because a
receipt written with an invented identity would render the Tool `Available` in
the console while the coordinator still refused to bind it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Literal

import httpx
from fastapi import HTTPException, status
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from apps.coordinator.contracts import (
    governed_agent_bindings_from_environment,
    governed_agent_resources_from_environment,
)
from solvan.application.tool_capability_evidence import ToolCapabilityObservation
from solvan.application.tool_catalog import SOURCE_CONNECTION_PAIRS
from solvan.application.tool_catalog import ToolCatalogError as CatalogError
from solvan.domain import Scope
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore
from solvan.platform.database import connect_database


class ToolProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    tool_key: str = Field(pattern=r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
    tool_version: str = Field(min_length=1, max_length=32)
    agent_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    connection_id: str = Field(pattern=r"^con_[0-7][0-9A-HJKMNP-TV-Z]{25}$")


class ToolProbeReceiptResponse(BaseModel):
    receipt_id: str
    tool_revision: str
    agent_key: str
    connection_id: str
    outcome: Literal["PASSED", "FAILED"]
    reason_code: str | None
    missing_grant: str | None
    expires_at: str


def _attested_identity(agent_key: str) -> str:
    """The Agent Identity, from deployment attestation or not at all.

    `GovernedAgentBinding.from_json` requires the identity to match a deployed
    `reasoningEngines/…` principal and to agree with the Runtime resource for
    that Agent, so an unset or placeholder deployment cannot satisfy it. The
    refusal is the point: until the Agent is deployed there is no identity a
    receipt could honestly name.
    """

    try:
        bindings = governed_agent_bindings_from_environment(
            agent_resources=governed_agent_resources_from_environment()
        )
    except (RuntimeError, ValueError) as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "no attested Agent Identity is available for a Tool capability probe",
        ) from error
    binding = bindings.get(agent_key)
    if binding is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "agent holds no governed Tool binding"
        )
    return binding.identity_ref


def _attested_gateway_policy(destination: str) -> str:
    """The provisioned Gateway policy for one registered destination.

    Supplied by deployment for the same reason the Agent Identity is: Google
    mints it, this repository cannot derive it, and inventing one would put an
    unenforceable route on a durable receipt. Absent or unparsable refuses.
    """

    raw = os.environ.get("SOLVAN_GATEWAY_POLICY_REFS_JSON")
    if not raw:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "no attested Gateway policy is available for a Tool capability probe",
        )
    try:
        policies = json.loads(raw)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "attested Gateway policy map is unparsable"
        ) from error
    policy = policies.get(destination) if isinstance(policies, dict) else None
    if not isinstance(policy, str) or not policy:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Tool destination has no attested Gateway policy",
        )
    return policy


def _tool_revision(*, connection: Any, request: ToolProbeRequest) -> dict[str, Any]:
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT r.lifecycle, r.registry_resource, r.gateway_destination,
                      r.network_policy_hash, r.required_capabilities_json,
                      r.runtime_regions_json, r.data_classification_ceiling
                 FROM solvan_operability.tool_revisions r
                 JOIN solvan_operability.tool_revision_requesters q
                   ON (q.tool_key,q.tool_version)=(r.tool_key,r.version)
                WHERE r.tool_key=%(tool_key)s AND r.version=%(tool_version)s
                  AND q.requester_key=%(agent_key)s""",
            {
                "tool_key": request.tool_key,
                "tool_version": request.tool_version,
                "agent_key": request.agent_key,
            },
        )
        row = cursor.fetchone()
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "no such Tool revision names this Agent as a requester"
        )
    (
        lifecycle,
        registry_resource,
        gateway_destination,
        network_policy_hash,
        capabilities,
        regions,
        classification_ceiling,
    ) = row
    if str(lifecycle) != "APPROVED":
        raise HTTPException(
            status.HTTP_409_CONFLICT, "only an approved Tool revision may be probed"
        )
    declared = [str(value) for value in capabilities]
    if len(declared) != 1:
        # The receipt records one capability. A revision declaring several needs
        # one probe each, which is a contract change rather than a loop here.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "a Tool revision with multiple declared capabilities needs a probe per capability",
        )
    return {
        "capability": declared[0],
        "registry_resource": str(registry_resource),
        "gateway_destination": str(gateway_destination),
        "network_policy_hash": str(network_policy_hash),
        "regions": [str(value) for value in regions],
        "classification_ceiling": str(classification_ceiling),
    }


def _connection_revision(*, connection: Any, scope: Scope, connection_id: str) -> dict[str, Any]:
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT c.connection_epoch,c.provider,c.authentication_mode,
                      c.solvan_delegator_principal,c.customer_reader_principal,
                      c.token_lifetime_seconds,c.residency_region,
                      s.resource_kind,s.resource_id
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
        epoch,
        provider,
        mode,
        delegator,
        reader_principal,
        lifetime,
        residency_region,
        resource_kind,
        resource_id,
    ) = row
    if (
        mode != "GCP_SERVICE_ACCOUNT_IMPERSONATION"
        or resource_kind != "GCP_PROJECT"
        or not isinstance(delegator, str)
        or not isinstance(reader_principal, str)
        or not isinstance(lifetime, int)
        or not isinstance(resource_id, str)
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "connection is not an eligible direct GCP reader binding",
        )
    return {
        "connection_epoch": int(epoch),
        "provider": str(provider),
        "authentication_mode": str(mode),
        "solvan_delegator_principal": delegator,
        "customer_reader_principal": reader_principal,
        "token_lifetime_seconds": lifetime,
        "residency_region": str(residency_region),
        "resource_kind": str(resource_kind),
        "resource_id": resource_id,
    }


def probe_tool_capability_revision(
    *, scope: Scope, request: ToolProbeRequest
) -> ToolProbeReceiptResponse:
    """Ask the reader to observe one Tool capability, then commit what it saw."""

    reader_url = os.environ.get("SOLVAN_DIRECT_GCP_READER_URL")
    if not reader_url or not reader_url.startswith("https://"):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "direct GCP reader is not configured"
        )
    identity_ref = _attested_identity(request.agent_key)
    with connect_database() as connection:
        tool = _tool_revision(connection=connection, request=request)
        source = _connection_revision(
            connection=connection, scope=scope, connection_id=request.connection_id
        )
    gateway_policy_ref = _attested_gateway_policy(tool["gateway_destination"])
    capability_class = SOURCE_CONNECTION_PAIRS.get(source["provider"])
    if capability_class is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "connection provider is not a governed policy-source read provider",
        )
    if source["residency_region"] not in tool["regions"]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Tool revision is not approved in the connection's residency region",
        )
    try:
        token = id_token.fetch_id_token(GoogleAuthRequest(), reader_url)  # type: ignore[no-untyped-call]
        response = httpx.post(
            f"{reader_url.rstrip('/')}/internal/v1/tools:probe",
            json={
                "schema_version": 1,
                "connection_id": request.connection_id,
                "tool_key": request.tool_key,
                "tool_version": request.tool_version,
                "capability": tool["capability"],
                **{
                    key: source[key]
                    for key in (
                        "connection_epoch",
                        "provider",
                        "authentication_mode",
                        "solvan_delegator_principal",
                        "customer_reader_principal",
                        "token_lifetime_seconds",
                        "resource_kind",
                        "resource_id",
                    )
                },
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=35,
        )
        response.raise_for_status()
        payload = response.json()
        # The reader answers about the revision that was asked for, or its
        # answer is discarded. A response bound to another Tool or a rotated
        # connection is not evidence about this one.
        if (
            payload.get("connection_id") != request.connection_id
            or int(payload.get("connection_epoch", -1)) != source["connection_epoch"]
            or payload.get("tool_revision") != f"{request.tool_key}@{request.tool_version}"
            or payload.get("capability") != tool["capability"]
        ):
            raise ValueError("reader response does not match the requested Tool revision")
        observation = ToolCapabilityObservation(
            tool_revision=str(payload["tool_revision"]),
            capability=str(payload["capability"]),
            available=bool(payload["available"]),
            outcome=payload["outcome"],
            missing_grant=payload["missing_grant"],
            reason_code=payload["reason_code"],
            receipt_ref=str(payload["receipt_ref"]),
            receipt_hash=str(payload["receipt_hash"]),
            observed_at=_moment(payload["observed_at"]),
            expires_at=_moment(payload["expires_at"]),
        ).validated()
    except (httpx.HTTPError, KeyError, ValueError) as error:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "direct GCP reader refused the Tool probe"
        ) from error
    try:
        with connect_database() as connection, connection.transaction():
            receipt_id = PostgresToolCatalogStore(connection).record_observed_tool_capability(
                scope=scope,
                observation=observation,
                connection_id=request.connection_id,
                expected_connection_epoch=source["connection_epoch"],
                connection_provider=source["provider"],
                capability_class=capability_class,
                external_project_id=source["resource_id"],
                workload_region=source["residency_region"],
                agent_key=request.agent_key,
                identity_ref=identity_ref,
                registry_resource=tool["registry_resource"],
                gateway_policy_ref=gateway_policy_ref,
                network_policy_hash=tool["network_policy_hash"],
                classification_ceiling=tool["classification_ceiling"],
            )
    except CatalogError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return ToolProbeReceiptResponse(
        receipt_id=receipt_id,
        tool_revision=observation.tool_revision,
        agent_key=request.agent_key,
        connection_id=request.connection_id,
        outcome=observation.probe_outcome,
        reason_code=observation.reason_code,
        missing_grant=observation.missing_grant,
        expires_at=observation.expires_at.isoformat(),
    )


def _moment(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        raise ValueError("reader timestamps require timezones")
    return parsed
