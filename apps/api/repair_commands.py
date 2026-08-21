"""Authenticated administration of repository-bound repair commands."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.repair_commands import RepairCommandDefinition
from solvan.domain import Scope, new_identifier
from solvan.persistence.repair_command_registry import (
    PostgresRepairCommandRegistry,
    RepairCommandRegistryConflict,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session


class ApprovalReceiptWriter(Protocol):
    def __call__(self, *, scope: Scope, material: dict[str, Any]) -> str: ...


class RepairCommandProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    repository_binding_id: str
    command_kind: str
    argv: tuple[str, ...]
    working_directory: str
    declared_inputs: tuple[str, ...]
    declared_outputs: tuple[str, ...]
    timeout_ms: int
    cpu_millis: int
    memory_mib: int
    output_byte_limit: int
    command_hash: str
    catalog_hash: str
    lifecycle: str
    approved_ref: str
    created_at: datetime


class RepairCommandRegistrationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    definition_id: str
    command_hash: str
    lifecycle: str
    created: bool


class RevokeRepairCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str = Field(min_length=8, max_length=500)


def _write_approval_receipt(*, scope: Scope, material: dict[str, Any]) -> str:
    bucket = os.environ.get("SOLVAN_EVIDENCE_BUCKET", "").strip()
    if not bucket:
        raise RuntimeError("repair command approval evidence bucket is not configured")
    receipt = GcsEvidenceWriter(bucket=bucket, session=authorized_session()).put_json(
        object_name=(
            f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
            f"repair-command-approvals/{new_identifier('rca')}.json"
        ),
        value=material,
    )
    return receipt.uri


def repair_command_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any] = connect_database,
    receipt_writer: ApprovalReceiptWriter = _write_approval_receipt,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/repair-commands")

    def admin(token: str | None, scope: Scope) -> str:
        principal = principal_provider(token)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM solvan.actor_role_bindings
                     WHERE organization_id=%(organization_id)s
                       AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s
                       AND principal=%(principal)s AND role='ADMIN'
                       AND (expires_at IS NULL OR expires_at>now()))""",
                {**scope.canonical_dict(), "principal": principal},
            )
            row = cursor.fetchone()
        if row is None or row[0] is not True:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "REPAIR_COMMAND_ADMIN_REQUIRED")
        return principal

    @router.get("", response_model=list[RepairCommandProjection])
    def list_commands(
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> list[RepairCommandProjection]:
        scope = scope_provider()
        admin(human_identity_token, scope)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id,repository_binding_id,command_kind,argv_json,
                          working_directory,declared_inputs_json,declared_outputs_json,
                          timeout_ms,cpu_millis,memory_mib,output_byte_limit,
                          command_hash,catalog_hash,lifecycle,approved_ref,created_at
                     FROM solvan_delivery.repair_plan_command_definitions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY created_at DESC,id""",
                scope.canonical_dict(),
            )
            rows = cursor.fetchall()
        return [
            RepairCommandProjection(
                id=str(row[0]),
                repository_binding_id=str(row[1]),
                command_kind=str(row[2]),
                argv=tuple(str(item) for item in row[3]),
                working_directory=str(row[4]),
                declared_inputs=tuple(str(item) for item in row[5]),
                declared_outputs=tuple(str(item) for item in row[6]),
                timeout_ms=int(row[7]),
                cpu_millis=int(row[8]),
                memory_mib=int(row[9]),
                output_byte_limit=int(row[10]),
                command_hash=str(row[11]),
                catalog_hash=str(row[12]),
                lifecycle=str(row[13]),
                approved_ref=str(row[14]),
                created_at=row[15],
            )
            for row in rows
        ]

    @router.post("", response_model=RepairCommandRegistrationResponse)
    def register_command(
        request: RepairCommandDefinition,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> RepairCommandRegistrationResponse:
        scope = scope_provider()
        principal = admin(human_identity_token, scope)
        approved_at = datetime.now(UTC)
        approval_ref = receipt_writer(
            scope=scope,
            material={
                "schema_version": 1,
                "event_kind": "REPAIR_COMMAND_APPROVED",
                "principal": principal,
                "approved_at": approved_at.isoformat(),
                "definition": request.model_dump(mode="json"),
                "command_hash": request.command_hash,
                "catalog_hash": request.catalog_hash,
            },
        )
        try:
            with connect() as connection, connection.transaction():
                result = PostgresRepairCommandRegistry(connection).register(
                    scope=scope, definition=request, approved_ref=approval_ref
                )
        except RepairCommandRegistryConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "REPAIR_COMMAND_REFUSED") from error
        return RepairCommandRegistrationResponse(
            definition_id=result.definition_id,
            command_hash=result.command_hash,
            lifecycle=result.lifecycle,
            created=result.created,
        )

    @router.post("/{definition_id}:revoke", status_code=status.HTTP_204_NO_CONTENT)
    def revoke_command(
        definition_id: str,
        request: RevokeRepairCommandRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> None:
        scope = scope_provider()
        principal = admin(human_identity_token, scope)
        receipt_writer(
            scope=scope,
            material={
                "schema_version": 1,
                "event_kind": "REPAIR_COMMAND_REVOKED",
                "definition_id": definition_id,
                "principal": principal,
                "reason": request.reason,
                "revoked_at": datetime.now(UTC).isoformat(),
            },
        )
        try:
            with connect() as connection, connection.transaction():
                PostgresRepairCommandRegistry(connection).revoke(
                    scope=scope, definition_id=definition_id
                )
        except RepairCommandRegistryConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "REPAIR_COMMAND_REFUSED") from error

    return router
