"""Coordinator-owned Workspace Tool admission and durable Adapter dispatch."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Protocol, cast

import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from psycopg import Connection
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict

from apps.coordinator.contracts import CoordinatorSettings
from solvan.application.delivery_commands import (
    DeliveryCommandKind,
    DeliveryCommandStatus,
    PrivateCommandEnvelope,
    PrivateCommandRecord,
    payload_schema_hash,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import Scope, new_identifier
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.service_identity import (
    ServiceIdentityError,
    require_agent_principal,
    verify_service_caller,
)


class WorkspaceToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    request_id: str
    tool_input: dict[str, Any]


class AdapterTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
        timeout: httpx.Timeout,
    ) -> httpx.Response: ...


_REVISION_BY_OPERATION = {
    "read-artifact": "workspace.code-repair.read-artifact@1",
    "write-candidate-artifact": "workspace.code-repair.write-candidate-artifact@1",
    "run-in-sandbox": "workspace.code-repair.run-in-sandbox@1",
}


def authenticate_workspace_agent(
    authorization: str | None, *, settings: CoordinatorSettings
) -> None:
    """Verify signed transport claims; exact Agent admission is also Cloud Run IAM-bound."""

    try:
        caller = verify_service_caller(
            authorization,
            audience_variable="SOLVAN_WORKSPACE_TOOL_BROKER_AUDIENCE",
        )
    except ServiceIdentityError as error:
        raise ValueError("Workspace Agent transport identity is invalid") from error
    if not settings.workspace_agent_principal.startswith("principal://agents.global."):
        raise ValueError("Workspace Agent has no attested Agent Identity")
    # The verified caller must be the exact attested Workspace Agent identity —
    # a valid token for this audience from any other workload is not admission.
    try:
        require_agent_principal(caller, admitted=frozenset({settings.workspace_agent_principal}))
    except ServiceIdentityError as error:
        raise ValueError("Workspace Agent identity is not admitted") from error


def invoke_workspace_tool(
    *,
    settings: CoordinatorSettings,
    connection: Connection[Any],
    request: WorkspaceToolRequest,
    operation: str,
    transport: AdapterTransport,
) -> dict[str, Any]:
    """Persist one exact server-ordered command, then invoke the private Adapter."""

    try:
        revision = _REVISION_BY_OPERATION[operation]
    except KeyError as error:
        raise ValueError("Workspace Tool operation is not registered") from error
    request_fingerprint = canonical_sha256(
        {"tool_revision": revision, "tool_input": request.tool_input}
    ).removeprefix("sha256:")
    existing_command_id: str | None = None
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT id,organization_id,project_id,environment_id,provider_request_hash,
                      deadline,status
                 FROM solvan.agent_runs
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND provider_request_id=%(request_id)s
                  AND agent_key='workspace-agent'
                  AND workspace_task_kind='REPAIR'
                FOR UPDATE""",
            {**settings.scope.canonical_dict(), "request_id": request.request_id},
        )
        run = cursor.fetchone()
        if run is None or run["status"] not in {"DISPATCHED", "RUNNING"}:
            raise ValueError("Workspace Tool request has no live durable Agent run")
        scope = Scope(
            str(run["organization_id"]),
            str(run["project_id"]),
            str(run["environment_id"]),
        )
        idempotency_key = f"workspace-tool:{run['id']}:{request_fingerprint}"
        cursor.execute(
            """SELECT id FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind='WORKSPACE_TOOL_INVOKE'
                  AND subject_id=%(run_id)s AND idempotency_key=%(idempotency_key)s""",
            {
                **scope.canonical_dict(),
                "run_id": str(run["id"]),
                "idempotency_key": idempotency_key,
            },
        )
        existing = cursor.fetchone()
        if existing is not None:
            existing_command_id = str(existing["id"])
        cursor.execute(
            """SELECT count(*) AS call_count
                 FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind='WORKSPACE_TOOL_INVOKE'
                  AND subject_id=%(run_id)s""",
            {**scope.canonical_dict(), "run_id": str(run["id"])},
        )
        usage = cursor.fetchone()
        if usage is None:
            raise ValueError("Workspace Tool usage could not be derived")
        ordinal = int(usage["call_count"]) + 1

    session = authorized_session()
    if existing_command_id is not None:
        command = PostgresDeliveryCommandStore(connection).load(
            command_id=existing_command_id,
            payload_reader=GcsEvidenceReader(
                allowed_buckets=frozenset({settings.runtime_bucket}), session=session
            ),
        )
    else:
        payload = {
            "tool_revision": revision,
            "call_ordinal": ordinal,
            "tool_input": request.tool_input,
        }
        command_id = new_identifier("cmd")
        object_name = (
            f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
            f"workspace-tool-commands/{command_id}.json"
        )
        writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
        payload_receipt = writer.put_json(object_name=object_name, value=payload)
        command = PrivateCommandRecord(
            command_id=command_id,
            scope=scope,
            command_kind=DeliveryCommandKind.WORKSPACE_TOOL_INVOKE,
            subject_id=str(run["id"]),
            material_hash=canonical_sha256(
                {
                    "provider_request_hash": str(run["provider_request_hash"]),
                    "payload_hash": payload_receipt.content_hash,
                }
            ),
            idempotency_key=idempotency_key,
            payload_ref=payload_receipt.uri,
            payload=payload,
            payload_hash=payload_receipt.content_hash,
            payload_schema_hash=payload_schema_hash(DeliveryCommandKind.WORKSPACE_TOOL_INVOKE),
            admitted_caller_identity=settings.coordinator_principal,
            admitted_audience_hash=sha256_bytes(settings.workspace_adapter.audience.encode()),
            deadline=cast(datetime, run["deadline"]),
            status=DeliveryCommandStatus.PREPARED,
        )
        PostgresDeliveryCommandStore(connection).prepare_workspace_tool(command)
    token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
        GoogleRequest(), settings.workspace_adapter.audience
    )
    response = transport.post(
        f"{settings.workspace_adapter.base_url.rstrip('/')}/internal/v1/workspace-tools:invoke",
        headers={"Authorization": f"Bearer {token}"},
        json=PrivateCommandEnvelope(
            command_id=command.command_id, payload=command.payload
        ).model_dump(mode="json"),
        timeout=httpx.Timeout(5.0, read=330.0),
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError("Workspace Adapter returned a non-object response")
    return value
