"""Connecting one customer estate, one connection per capability (spec 13).

Separated from the connection CRUD around it because it is a different thing:
CRUD edits one record, and this binds Solvan to a customer's Google Cloud
project across several capabilities at once, under a re-authentication that
authorizes that exact estate.

Registration is one transaction and probing is deliberately outside it. A probe
is a call into another service, cannot be rolled back, and its result is what
makes a connection usable rather than what makes it exist.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from fastapi import HTTPException, Request, status
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field

from apps.api.session_authorization import recorded_principal, spend_challenge
from solvan.application.action_challenge import material_digest
from solvan.application.onboarding import EstateSelectionError, estate_onboarding_plan
from solvan.application.tenant_integration import (
    ConnectionAuthenticationMode,
    ConnectionPolicyError,
    ConnectionRegistration,
    CredentialPosture,
    ExternalResourceScope,
    GcpResourceKind,
)
from solvan.domain import Scope
from solvan.persistence.connection_store import PostgresConnectionStore
from solvan.platform.database import connect_database


class EstateConnectionRequest(BaseModel):
    """One estate, N per-capability connections, one set of grants.

    The Google project and the customer reader are stated once. Neither the
    principal nor the scope appears here: both come from the verified identity
    and this deployment's cell, exactly as they do for a single connection.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    display_name: str = Field(min_length=1, max_length=120)
    #: Duplicates are refused rather than collapsed, so a caller learns its
    #: selection was not what it thought instead of silently registering fewer
    #: connections than it asked for.
    providers: list[str] = Field(min_length=1, max_length=16)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    customer_project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,61}$")
    customer_reader_service_account: str = Field(min_length=16, max_length=320)
    workload_region: str = Field(pattern=r"^[a-z]+(?:-[a-z0-9]+)*$", max_length=40)
    scope_decision_ref: str = Field(min_length=1, max_length=1024)
    #: `solvan_delegator_principal` and `delegation_condition_digest` are
    #: deliberately not fields. The delegator is this deployment's recorded
    #: reader identity and the condition is derived from the generated plan, so
    #: accepting either here would let a caller name the identity that will be
    #: allowed to impersonate the customer reader.


class EstateConnectionOutcome(BaseModel):
    provider: str
    connection_id: str
    connection_epoch: int
    probe_result: Literal["SUCCEEDED", "PARTIAL", "FAILED"] | None
    probe_reason_code: Literal["PROBE_UNAVAILABLE", "PROBE_REFUSED"] | None


class EstateConnectionResponse(BaseModel):
    delegation_condition_digest: str
    registered: list[EstateConnectionOutcome]


def _estate_material(request: EstateConnectionRequest) -> str:
    """The exact estate a challenge authorizes, as both sides compute it.

    Every field that decides what is connected and to whom. Re-authenticating to
    connect one project must not return authority to connect another, which is
    what a page altered while the operator was away at the provider would
    attempt.
    """

    providers = ",".join(sorted(request.providers))
    return (
        f"estate:v1:{request.customer_project_id}:{request.customer_reader_service_account}"
        f":{request.workload_region}:{request.classification}:{providers}"
    )


def register_estate(
    *,
    http_request: Request,
    request: EstateConnectionRequest,
    scope: Scope,
    probe: Callable[[Scope, str], str],
) -> EstateConnectionResponse:
    """Register every chosen capability of one estate, then probe each one.

    Registration is one transaction: either every connection exists or none
    does. A half-registered estate would be reported as connected while
    missing the evidence an investigation needs, which is worse than a
    refusal the operator can retry. Probing is deliberately outside it — a
    probe is a call into another service, cannot be rolled back, and its
    result is what makes a connection usable rather than what makes it
    exist. Each connection is therefore reported with its own probe
    outcome, and one that could not be probed stays unproven.
    """

    configured_delegator = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
    if not configured_delegator:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "the Solvan reader identity is not configured",
        )
    try:
        plan = estate_onboarding_plan(
            providers=request.providers,
            customer_project_id=request.customer_project_id,
            solvan_service_account=configured_delegator,
            customer_reader_service_account=request.customer_reader_service_account,
        )
    except EstateSelectionError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, error.reason_code) from error
    registrations = tuple(
        ConnectionRegistration(
            display_name=request.display_name,
            kind="GCP_NATIVE",
            provider=provider,
            credential_posture=CredentialPosture.FEDERATED_SHORT_LIVED,
            residency_region=os.environ.get("SOLVAN_REGION", "europe-west1"),
            classification=request.classification,
            authentication_mode=(ConnectionAuthenticationMode.GCP_SERVICE_ACCOUNT_IMPERSONATION),
            solvan_delegator_principal=f"serviceAccount:{configured_delegator}",
            customer_reader_principal=(f"serviceAccount:{request.customer_reader_service_account}"),
            delegation_condition_digest=plan.delegation_condition_digest,
            token_lifetime_seconds=900,
            resource_scope=ExternalResourceScope(
                resource_kind=GcpResourceKind.GCP_PROJECT,
                resource_id=request.customer_project_id,
                workload_region=request.workload_region,
                metrics_scoping_project_id=None,
                decision_ref=request.scope_decision_ref,
            ),
        )
        for provider in plan.providers
    )
    registered: list[tuple[str, str, int]] = []
    try:
        with connect_database() as connection, connection.transaction():
            # Spent inside the transaction that registers what it
            # authorizes: spending without registering burns the
            # re-authentication and connects nothing, and registering
            # without spending leaves the challenge replayable against a
            # different estate. It replaces a pasted identity token, which
            # carried no freshness, no binding to the estate, and no single
            # use.
            consumed = spend_challenge(
                connection,
                http_request,
                scope=scope,
                operation="estate.connect",
                material_digest=material_digest(_estate_material(request)),
                now=datetime.now(UTC),
            )
            principal = recorded_principal(connection, consumed.actor_id)
            store = PostgresConnectionStore(connection)
            for registration in registrations:
                connection_id = store.register_connection(
                    scope=scope, registration=registration, actor=principal
                )
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT connection_epoch, lifecycle, availability
                             FROM solvan.tenant_connections
                            WHERE organization_id = %(organization_id)s
                              AND project_id = %(project_id)s
                              AND environment_id = %(environment_id)s
                              AND id = %(connection_id)s""",
                        {**scope.canonical_dict(), "connection_id": connection_id},
                    )
                    row = cursor.fetchone()
                # A connection exists unprobed and proven nothing. Reading
                # that back rather than assuming it means this route can
                # never report an estate as connected on the strength of
                # having inserted a row.
                if row is None or (row[1], row[2]) != ("PENDING", "NOT_CONFIGURED"):
                    raise ConnectionPolicyError(
                        "a newly registered connection must be unprobed and unproven"
                    )
                registered.append((registration.provider, connection_id, int(row[0])))
    except ConnectionPolicyError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
    except UniqueViolation as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "a connection with this provider and display name already exists; "
            "verify the existing connection",
        ) from error
    outcomes: list[EstateConnectionOutcome] = []
    for provider, connection_id, connection_epoch in registered:
        probe_result: str | None = None
        probe_reason: str | None = None
        try:
            probe_result = probe(scope, connection_id)
        except HTTPException as error:
            probe_reason = (
                "PROBE_UNAVAILABLE"
                if error.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
                else "PROBE_REFUSED"
            )
        outcomes.append(
            EstateConnectionOutcome(
                provider=provider,
                connection_id=connection_id,
                connection_epoch=connection_epoch,
                probe_result=probe_result,  # type: ignore[arg-type]
                probe_reason_code=probe_reason,  # type: ignore[arg-type]
            )
        )
    return EstateConnectionResponse(
        delegation_condition_digest=plan.delegation_condition_digest, registered=outcomes
    )
