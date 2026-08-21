"""Cloud SQL authority for approved repair command definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.repair_commands import RepairCommandDefinition
from solvan.domain import Scope, new_identifier


class RepairCommandRegistryConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RegisteredRepairCommand:
    definition_id: str
    repository_binding_id: str
    command_kind: str
    command_hash: str
    lifecycle: str
    created: bool


class PostgresRepairCommandRegistry:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def register(
        self,
        *,
        scope: Scope,
        definition: RepairCommandDefinition,
        approved_ref: str,
    ) -> RegisteredRepairCommand:
        if not approved_ref.startswith("gs://"):
            raise RepairCommandRegistryConflict(
                "repair command approval must be immutable evidence"
            )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT status FROM solvan.github_repositories
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(repository_binding_id)s FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "repository_binding_id": definition.repository_binding_id,
                },
            )
            repository = cursor.fetchone()
            if repository is None or repository["status"] != "ACTIVE":
                raise RepairCommandRegistryConflict(
                    "repair commands require one active GitHub repository binding"
                )
            cursor.execute(
                """SELECT id,repository_binding_id,command_kind,command_hash,lifecycle
                     FROM solvan_delivery.repair_plan_command_definitions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND repository_binding_id=%(repository_binding_id)s
                      AND command_hash=%(command_hash)s""",
                {
                    **scope.canonical_dict(),
                    "repository_binding_id": definition.repository_binding_id,
                    "command_hash": definition.command_hash,
                },
            )
            existing = cursor.fetchone()
            if existing is not None:
                return self._record(existing, created=False)
            definition_id = new_identifier("rcd")
            cursor.execute(
                """INSERT INTO solvan_delivery.repair_plan_command_definitions
                    (organization_id,project_id,environment_id,id,repository_binding_id,
                     command_hash,command_kind,argv_json,working_directory,
                     declared_inputs_hash,declared_outputs_hash,timeout_ms,cpu_millis,
                     memory_mib,output_byte_limit,network_mode,catalog_hash,lifecycle,
                     approved_ref,declared_inputs_json,declared_outputs_json)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(repository_binding_id)s,%(command_hash)s,%(command_kind)s,%(argv)s,
                     %(working_directory)s,%(declared_inputs_hash)s,%(declared_outputs_hash)s,
                     %(timeout_ms)s,%(cpu_millis)s,%(memory_mib)s,%(output_byte_limit)s,
                     'NONE',%(catalog_hash)s,'APPROVED',%(approved_ref)s,
                     %(declared_inputs)s,%(declared_outputs)s)
                   RETURNING id,repository_binding_id,command_kind,command_hash,lifecycle""",
                {
                    **scope.canonical_dict(),
                    "id": definition_id,
                    "repository_binding_id": definition.repository_binding_id,
                    "command_hash": definition.command_hash,
                    "command_kind": definition.command_kind,
                    "argv": Jsonb(list(definition.argv)),
                    "working_directory": definition.working_directory,
                    "declared_inputs_hash": definition.declared_inputs_hash,
                    "declared_outputs_hash": definition.declared_outputs_hash,
                    "timeout_ms": definition.timeout_ms,
                    "cpu_millis": definition.cpu_millis,
                    "memory_mib": definition.memory_mib,
                    "output_byte_limit": definition.output_byte_limit,
                    "catalog_hash": definition.catalog_hash,
                    "approved_ref": approved_ref,
                    "declared_inputs": Jsonb(list(definition.declared_inputs)),
                    "declared_outputs": Jsonb(list(definition.declared_outputs)),
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("repair command registration returned no row")
            return self._record(row, created=True)

    def revoke(self, *, scope: Scope, definition_id: str) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.repair_plan_command_definitions
                      SET lifecycle='REVOKED'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(definition_id)s AND lifecycle='APPROVED'""",
                {**scope.canonical_dict(), "definition_id": definition_id},
            )
            if cursor.rowcount != 1:
                raise RepairCommandRegistryConflict(
                    "approved repair command definition is unavailable"
                )

    @staticmethod
    def _record(row: dict[str, Any], *, created: bool) -> RegisteredRepairCommand:
        return RegisteredRepairCommand(
            definition_id=str(row["id"]),
            repository_binding_id=str(row["repository_binding_id"]),
            command_kind=str(row["command_kind"]),
            command_hash=str(row["command_hash"]),
            lifecycle=str(row["lifecycle"]),
            created=created,
        )
