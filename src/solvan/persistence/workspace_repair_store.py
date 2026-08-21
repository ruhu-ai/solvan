"""Cloud SQL authority for catalog-only Workspace repair attempts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.workspace_candidate import (
    CandidateTree,
    CatalogCommand,
    resolve_declared_inputs,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.workspace_repair_history import (
    WorkspaceRepairConflict,
    WorkspaceRepairHistoryStore,
)


@dataclass(frozen=True, slots=True)
class RepairGuidanceSelection:
    selection_set_id: str
    selection_set_hash: str
    selection_id: str
    guidance_key: str
    guidance_version: str
    content_ref: str
    content_hash: str
    revision_hash: str
    profile_material_hash: str


@dataclass(frozen=True, slots=True)
class CandidateMaterial:
    repair_plan_id: str
    repair_plan_version: int
    repository_snapshot_ref: str
    repository_snapshot_hash: str
    base_commit_sha: str
    base_tree_hash: str
    allowed_file_globs: tuple[str, ...]
    plan_content_hash: str
    input_manifest_ref: str
    input_manifest_hash: str
    parent_generation_id: str | None
    parent_manifest_ref: str | None
    parent_manifest_hash: str | None


@dataclass(frozen=True, slots=True)
class CandidateGenerationMaterial:
    generation_id: str
    base_tree_hash: str
    candidate_tree_hash: str
    manifest_ref: str
    manifest_hash: str


@dataclass(frozen=True, slots=True)
class MaterializedCommandCatalog:
    reproduction_command_id: str
    regression_command_id: str
    catalog_hash: str


class PostgresWorkspaceRepairStore(WorkspaceRepairHistoryStore):
    """Append-only candidates and experimental sandbox receipts under one scope."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def prepare_base_guidance(
        self,
        *,
        scope: Scope,
        repair_plan_id: str,
        repair_plan_version: int,
        runtime_region: str,
        selected_by_identity: str,
    ) -> RepairGuidanceSelection:
        """Freeze the required approved code-repair skill before run creation."""

        params: dict[str, object] = {
            **scope.canonical_dict(),
            "repair_plan_id": repair_plan_id,
            "repair_plan_version": repair_plan_version,
            "runtime_region": runtime_region,
            "selected_by_identity": selected_by_identity,
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """SELECT s.id AS selection_set_id,s.selection_set_hash,
                          i.id AS selection_id,i.guidance_key,i.guidance_version,
                          r.content_ref,r.content_hash,r.revision_hash,
                          i.profile_material_hash
                     FROM solvan_delivery.repair_plan_guidance_selection_sets s
                     JOIN solvan_delivery.repair_plan_guidance_selections i
                       ON (i.organization_id,i.project_id,i.environment_id,i.selection_set_id)=
                          (s.organization_id,s.project_id,s.environment_id,s.id)
                     JOIN solvan_operability.guidance_revisions r
                       ON (r.organization_id,r.project_id,r.environment_id,
                           r.guidance_key,r.version)=
                          (i.organization_id,i.project_id,i.environment_id,
                           i.guidance_key,i.guidance_version)
                    WHERE s.organization_id=%(organization_id)s
                      AND s.project_id=%(project_id)s
                      AND s.environment_id=%(environment_id)s
                      AND s.repair_plan_id=%(repair_plan_id)s
                      AND s.repair_plan_version=%(repair_plan_version)s
                      AND s.status IN ('PENDING_BIND','BOUND')
                    ORDER BY i.selection_ordinal""",
                params,
            )
            existing = cursor.fetchall()
            if existing:
                if len(existing) != 1 or existing[0]["guidance_key"] != "reliability.code-repair":
                    raise WorkspaceRepairConflict("repair plan has a different active guidance set")
                return self._guidance_selection(existing[0])
            cursor.execute(
                """SELECT r.guidance_key,r.version,r.content_ref,r.content_hash,r.revision_hash,
                          p.profile_material_hash
                     FROM solvan_operability.guidance_current_heads h
                     JOIN solvan_operability.guidance_revisions r
                       ON (r.organization_id,r.project_id,r.environment_id,
                           r.guidance_key,r.version)=
                          (h.organization_id,h.project_id,h.environment_id,
                           h.guidance_key,h.approved_version)
                     JOIN solvan_operability.guidance_revision_agents a
                       ON (a.organization_id,a.project_id,a.environment_id,
                           a.guidance_key,a.guidance_version)=
                          (r.organization_id,r.project_id,r.environment_id,
                           r.guidance_key,r.version)
                     JOIN solvan_operability.guidance_revision_profiles gp
                       ON (gp.organization_id,gp.project_id,gp.environment_id,
                           gp.guidance_key,gp.guidance_version)=
                          (r.organization_id,r.project_id,r.environment_id,
                           r.guidance_key,r.version)
                     JOIN solvan_operability.tool_profile_revisions p
                       ON (p.profile_key,p.version)=(gp.profile_key,gp.profile_version)
                    WHERE h.organization_id=%(organization_id)s
                      AND h.project_id=%(project_id)s
                      AND h.environment_id=%(environment_id)s
                      AND h.guidance_key='reliability.code-repair'
                      AND r.lifecycle='APPROVED' AND r.guidance_kind='SKILL'
                      AND r.purpose='INCIDENT_INVESTIGATION'
                      AND r.eligible_regions_json ? %(runtime_region)s
                      AND a.agent_key='workspace-agent'
                      AND gp.profile_key='workspace.code-repair.v1'
                      AND gp.profile_version='1' AND p.lifecycle='APPROVED'""",
                params,
            )
            revision = cursor.fetchone()
            if revision is None:
                raise WorkspaceRepairConflict("required approved code-repair skill is unavailable")
            selection_set_id = new_identifier("rgs")
            selection_id = new_identifier("rgi")
            selection_set_hash = canonical_sha256(
                {
                    "repair_plan_id": repair_plan_id,
                    "repair_plan_version": repair_plan_version,
                    "selections": [
                        {
                            "ordinal": 1,
                            "guidance_key": revision["guidance_key"],
                            "guidance_version": revision["version"],
                            "content_hash": revision["content_hash"],
                            "revision_hash": revision["revision_hash"],
                            "profile_material_hash": revision["profile_material_hash"],
                        }
                    ],
                }
            )
            cursor.execute(
                """INSERT INTO solvan_delivery.repair_plan_guidance_selection_sets
                    (organization_id,project_id,environment_id,id,repair_plan_id,
                     repair_plan_version,selection_set_hash,status)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(selection_set_id)s,%(repair_plan_id)s,%(repair_plan_version)s,
                     %(selection_set_hash)s,'PENDING_BIND')""",
                {
                    **params,
                    "selection_set_id": selection_set_id,
                    "selection_set_hash": selection_set_hash,
                },
            )
            cursor.execute(
                """INSERT INTO solvan_delivery.repair_plan_guidance_selections
                    (organization_id,project_id,environment_id,id,selection_set_id,
                     selection_ordinal,guidance_key,guidance_version,guidance_content_hash,
                     guidance_revision_hash,profile_material_hash,selection_reason,
                     selected_by_kind,selected_by_identity)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(selection_id)s,%(selection_set_id)s,1,%(guidance_key)s,%(version)s,
                     %(content_hash)s,%(revision_hash)s,%(profile_material_hash)s,
                     'Required base skill for the production code-repair profile.',
                     'DETERMINISTIC',%(selected_by_identity)s)""",
                {
                    **params,
                    **dict(revision),
                    "selection_id": selection_id,
                    "selection_set_id": selection_set_id,
                },
            )
            return RepairGuidanceSelection(
                selection_set_id,
                selection_set_hash,
                selection_id,
                str(revision["guidance_key"]),
                str(revision["version"]),
                str(revision["content_ref"]),
                str(revision["content_hash"]),
                str(revision["revision_hash"]),
                str(revision["profile_material_hash"]),
            )

    def materialize_command_catalog(
        self,
        *,
        scope: Scope,
        repair_plan_id: str,
        repair_plan_version: int,
        repository_node_id: str,
        base_tree: CandidateTree,
    ) -> MaterializedCommandCatalog:
        """Freeze the two approved repository-bound commands for one exact plan."""

        base_tree_hash = base_tree.tree_hash
        params: dict[str, object] = {
            **scope.canonical_dict(),
            "repair_plan_id": repair_plan_id,
            "repair_plan_version": repair_plan_version,
            "repository_node_id": repository_node_id,
            "base_tree_hash": base_tree_hash,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,command_ordinal,command_definition_id,command_hash,base_tree_hash,
                          argv_json,working_directory,timeout_ms,cpu_millis,memory_mib,
                          output_byte_limit,network_mode,catalog_hash,status,
                          resolved_inputs_hash
                     FROM solvan_delivery.repair_plan_command_catalogs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND repair_plan_id=%(repair_plan_id)s
                      AND repair_plan_version=%(repair_plan_version)s
                    ORDER BY command_ordinal""",
                params,
            )
            existing = cursor.fetchall()
            if existing:
                if len(existing) != 2 or any(
                    row["base_tree_hash"] != base_tree_hash
                    or row["status"] != "RESOLVED"
                    or not str(row["resolved_inputs_hash"]).startswith("sha256:")
                    for row in existing
                ):
                    raise WorkspaceRepairConflict("repair command catalog material drifted")
                return MaterializedCommandCatalog(
                    str(existing[0]["id"]),
                    str(existing[1]["id"]),
                    canonical_sha256([str(row["catalog_hash"]) for row in existing]),
                )
            cursor.execute(
                """SELECT n.attributes_json
                     FROM solvan.production_graph_nodes n
                    WHERE n.organization_id=%(organization_id)s
                      AND n.project_id=%(project_id)s
                      AND n.environment_id=%(environment_id)s
                      AND n.id=%(repository_node_id)s AND n.node_kind='REPOSITORY'""",
                params,
            )
            node = cursor.fetchone()
            attributes = None if node is None else node["attributes_json"]
            if not isinstance(attributes, dict):
                raise WorkspaceRepairConflict("repair repository policy is unavailable")
            definition_ids = [
                attributes.get("reproduction_command_definition_id"),
                attributes.get("regression_command_definition_id"),
            ]
            repository_binding_id = attributes.get("repository_binding_id")
            if not all(isinstance(item, str) for item in definition_ids) or not isinstance(
                repository_binding_id, str
            ):
                raise WorkspaceRepairConflict("repair repository command bindings are malformed")
            cursor.execute(
                """SELECT id,repository_binding_id,command_hash,command_kind,argv_json,
                          working_directory,declared_inputs_json,declared_inputs_hash,
                          timeout_ms,cpu_millis,
                          memory_mib,output_byte_limit,network_mode,catalog_hash
                     FROM solvan_delivery.repair_plan_command_definitions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND repository_binding_id=%(repository_binding_id)s
                      AND id = ANY(%(definition_ids)s) AND lifecycle='APPROVED'""",
                {
                    **params,
                    "repository_binding_id": repository_binding_id,
                    "definition_ids": definition_ids,
                },
            )
            by_id = {str(row["id"]): row for row in cursor.fetchall()}
            rows = [by_id.get(str(identifier)) for identifier in definition_ids]
            if (
                any(row is None for row in rows)
                or rows[0]["command_kind"] != "REPRODUCTION"  # type: ignore[index]
                or rows[1]["command_kind"] != "REGRESSION"  # type: ignore[index]
            ):
                raise WorkspaceRepairConflict("approved repair commands are unavailable")
            catalog_ids: list[str] = []
            catalog_hashes: list[str] = []
            for ordinal, untyped in enumerate(rows, start=1):
                assert untyped is not None
                row = untyped
                selectors = row["declared_inputs_json"]
                if (
                    not isinstance(selectors, list)
                    or not selectors
                    or canonical_sha256(selectors) != str(row["declared_inputs_hash"])
                ):
                    raise WorkspaceRepairConflict("repair command input selectors are malformed")
                try:
                    resolved_inputs = resolve_declared_inputs(tree=base_tree, selectors=selectors)
                except ValueError as error:
                    raise WorkspaceRepairConflict(str(error)) from error
                resolved_inputs_hash = canonical_sha256(resolved_inputs)
                command = CatalogCommand(
                    command_id=new_identifier("rcc"),
                    argv=tuple(str(item) for item in row["argv_json"]),
                    working_directory=str(row["working_directory"]),
                    timeout_ms=int(row["timeout_ms"]),
                    cpu_millis=int(row["cpu_millis"]),
                    memory_mib=int(row["memory_mib"]),
                    output_byte_limit=int(row["output_byte_limit"]),
                    network_mode=str(row["network_mode"]),
                )
                if command.working_directory != "." and not any(
                    item["path"].startswith(command.working_directory.rstrip("/") + "/")
                    for item in resolved_inputs
                ):
                    raise WorkspaceRepairConflict(
                        "repair command working directory does not resolve in the frozen base"
                    )
                catalog_hash = canonical_sha256(
                    {
                        "command_definition_id": str(row["id"]),
                        "command_hash": str(row["command_hash"]),
                        "base_tree_hash": base_tree_hash,
                        "argv": list(command.argv),
                        "working_directory": command.working_directory,
                        "declared_inputs_hash": str(row["declared_inputs_hash"]),
                        "resolved_inputs_hash": resolved_inputs_hash,
                        "limits": {
                            "timeout_ms": command.timeout_ms,
                            "cpu_millis": command.cpu_millis,
                            "memory_mib": command.memory_mib,
                            "output_byte_limit": command.output_byte_limit,
                        },
                        "network_mode": command.network_mode,
                    }
                )
                cursor.execute(
                    """INSERT INTO solvan_delivery.repair_plan_command_catalogs
                        (organization_id,project_id,environment_id,id,repair_plan_id,
                         repair_plan_version,command_ordinal,command_definition_id,
                         command_hash,base_tree_hash,argv_json,working_directory,
                         declared_inputs_hash,timeout_ms,cpu_millis,memory_mib,
                         output_byte_limit,network_mode,status,catalog_hash,
                         resolved_inputs_json,resolved_inputs_hash)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                         %(catalog_id)s,%(repair_plan_id)s,%(repair_plan_version)s,
                         %(ordinal)s,%(definition_id)s,%(command_hash)s,%(base_tree_hash)s,
                         %(argv)s,%(working_directory)s,%(declared_inputs_hash)s,
                         %(timeout_ms)s,%(cpu_millis)s,%(memory_mib)s,%(output_byte_limit)s,
                         'NONE','RESOLVED',%(catalog_hash)s,%(resolved_inputs)s,
                         %(resolved_inputs_hash)s)""",
                    {
                        **params,
                        "catalog_id": command.command_id,
                        "ordinal": ordinal,
                        "definition_id": str(row["id"]),
                        "command_hash": str(row["command_hash"]),
                        "argv": Jsonb(list(command.argv)),
                        "working_directory": command.working_directory,
                        "declared_inputs_hash": str(row["declared_inputs_hash"]),
                        "timeout_ms": command.timeout_ms,
                        "cpu_millis": command.cpu_millis,
                        "memory_mib": command.memory_mib,
                        "output_byte_limit": command.output_byte_limit,
                        "catalog_hash": catalog_hash,
                        "resolved_inputs": Jsonb(resolved_inputs),
                        "resolved_inputs_hash": resolved_inputs_hash,
                    },
                )
                catalog_ids.append(command.command_id)
                catalog_hashes.append(catalog_hash)
        return MaterializedCommandCatalog(
            catalog_ids[0], catalog_ids[1], canonical_sha256(catalog_hashes)
        )

    def bind_guidance_selection(
        self, *, scope: Scope, selection_set_id: str, agent_run_id: str
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.repair_plan_guidance_selection_sets
                      SET status='BOUND',bound_agent_run_id=%(agent_run_id)s,bound_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(selection_set_id)s AND status='PENDING_BIND'""",
                {
                    **scope.canonical_dict(),
                    "selection_set_id": selection_set_id,
                    "agent_run_id": agent_run_id,
                },
            )
            if cursor.rowcount != 1:
                cursor.execute(
                    """SELECT status,bound_agent_run_id
                         FROM solvan_delivery.repair_plan_guidance_selection_sets
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND id=%(selection_set_id)s""",
                    {
                        **scope.canonical_dict(),
                        "selection_set_id": selection_set_id,
                    },
                )
                replay = cursor.fetchone()
                if replay is None or replay != ("BOUND", agent_run_id):
                    raise WorkspaceRepairConflict("repair guidance selection could not bind to run")

    @staticmethod
    def _guidance_selection(row: dict[str, Any]) -> RepairGuidanceSelection:
        return RepairGuidanceSelection(
            str(row["selection_set_id"]),
            str(row["selection_set_hash"]),
            str(row["selection_id"]),
            str(row["guidance_key"]),
            str(row["guidance_version"]),
            str(row["content_ref"]),
            str(row["content_hash"]),
            str(row["revision_hash"]),
            str(row["profile_material_hash"]),
        )

    def load_catalog_command(
        self, *, scope: Scope, catalog_id: str, base_tree_hash: str
    ) -> CatalogCommand:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,argv_json,working_directory,timeout_ms,cpu_millis,memory_mib,
                           output_byte_limit,network_mode,base_tree_hash,status
                      FROM solvan_delivery.repair_plan_command_catalogs
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(catalog_id)s""",
                {**scope.canonical_dict(), "catalog_id": catalog_id},
            )
            row = cursor.fetchone()
        if row is None or row["status"] != "RESOLVED" or row["base_tree_hash"] != base_tree_hash:
            raise WorkspaceRepairConflict(
                "workspace command is not a resolved frozen catalog entry"
            )
        argv = row["argv_json"]
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise WorkspaceRepairConflict("workspace catalog argv is malformed")
        return CatalogCommand(
            command_id=str(row["id"]),
            argv=tuple(argv),
            working_directory=str(row["working_directory"]),
            timeout_ms=int(row["timeout_ms"]),
            cpu_millis=int(row["cpu_millis"]),
            memory_mib=int(row["memory_mib"]),
            output_byte_limit=int(row["output_byte_limit"]),
            network_mode=str(row["network_mode"]),
        )

    def load_command_definitions_hash(
        self, *, scope: Scope, repair_plan_id: str, repair_plan_version: int
    ) -> str:
        """Hash the exact two approved command definitions used for adjudication."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT command_ordinal,command_definition_id,command_hash,catalog_hash
                     FROM solvan_delivery.repair_plan_command_catalogs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND repair_plan_id=%(repair_plan_id)s
                      AND repair_plan_version=%(repair_plan_version)s AND status='RESOLVED'
                    ORDER BY command_ordinal""",
                {
                    **scope.canonical_dict(),
                    "repair_plan_id": repair_plan_id,
                    "repair_plan_version": repair_plan_version,
                },
            )
            rows = cursor.fetchall()
        if len(rows) != 2 or [int(row["command_ordinal"]) for row in rows] != [1, 2]:
            raise WorkspaceRepairConflict("adjudication command definitions are unavailable")
        return canonical_sha256(
            [
                {
                    "ordinal": int(row["command_ordinal"]),
                    "definition_id": str(row["command_definition_id"]),
                    "command_hash": str(row["command_hash"]),
                    "catalog_hash": str(row["catalog_hash"]),
                }
                for row in rows
            ]
        )

    def load_candidate_material(self, *, scope: Scope, agent_run_id: str) -> CandidateMaterial:
        """Load the exact live plan and current immutable candidate head."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.id AS repair_plan_id,p.plan_version,
                          p.repository_snapshot_uri,p.repository_snapshot_hash,
                          p.base_commit_sha,p.allowed_file_globs_json,p.content_hash,
                          w.input_manifest_ref,w.input_manifest_hash,
                          g.id AS generation_id,g.base_tree_hash,
                          g.candidate_manifest_ref,g.candidate_manifest_hash
                     FROM solvan.agent_runs a
                     JOIN solvan.repair_plans p
                       ON (p.organization_id,p.project_id,p.environment_id,p.id)=
                          (a.organization_id,a.project_id,a.environment_id,a.repair_plan_id)
                     JOIN solvan.workspaces w
                       ON (w.organization_id,w.project_id,w.environment_id,w.id)=
                          (a.organization_id,a.project_id,a.environment_id,a.workspace_id)
                     LEFT JOIN LATERAL (
                       SELECT id,base_tree_hash,candidate_manifest_ref,candidate_manifest_hash
                         FROM solvan_delivery.workspace_candidate_generations x
                        WHERE x.organization_id=a.organization_id
                          AND x.project_id=a.project_id
                          AND x.environment_id=a.environment_id
                          AND x.agent_run_id=a.id
                        ORDER BY generation_ordinal DESC LIMIT 1
                     ) g ON true
                    WHERE a.organization_id=%(organization_id)s
                      AND a.project_id=%(project_id)s
                      AND a.environment_id=%(environment_id)s
                      AND a.id=%(agent_run_id)s
                      AND a.agent_key='workspace-agent'
                      AND a.workspace_task_kind='REPAIR'
                      AND a.status IN ('DISPATCHED','RUNNING') AND a.deadline>now()
                      AND p.status='ACTIVE' AND p.plan_version=a.repair_plan_version
                      AND EXISTS (
                        SELECT 1 FROM solvan_delivery.repair_plan_guidance_selection_sets s
                         WHERE s.organization_id=a.organization_id
                           AND s.project_id=a.project_id
                           AND s.environment_id=a.environment_id
                           AND s.repair_plan_id=a.repair_plan_id
                           AND s.repair_plan_version=a.repair_plan_version
                           AND s.status='BOUND' AND s.bound_agent_run_id=a.id)""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkspaceRepairConflict("candidate material is not bound to a live repair run")
        globs = row["allowed_file_globs_json"]
        if not isinstance(globs, list) or not all(isinstance(item, str) for item in globs):
            raise WorkspaceRepairConflict("candidate path policy is malformed")
        return CandidateMaterial(
            repair_plan_id=str(row["repair_plan_id"]),
            repair_plan_version=int(row["plan_version"]),
            repository_snapshot_ref=str(row["repository_snapshot_uri"]),
            repository_snapshot_hash=str(row["repository_snapshot_hash"]),
            base_commit_sha=str(row["base_commit_sha"]),
            base_tree_hash=(
                str(row["base_tree_hash"]) if row["base_tree_hash"] is not None else ""
            ),
            allowed_file_globs=tuple(globs),
            plan_content_hash=str(row["content_hash"]),
            input_manifest_ref=str(row["input_manifest_ref"]),
            input_manifest_hash=str(row["input_manifest_hash"]),
            parent_generation_id=(
                str(row["generation_id"]) if row["generation_id"] is not None else None
            ),
            parent_manifest_ref=(
                str(row["candidate_manifest_ref"])
                if row["candidate_manifest_ref"] is not None
                else None
            ),
            parent_manifest_hash=(
                str(row["candidate_manifest_hash"])
                if row["candidate_manifest_hash"] is not None
                else None
            ),
        )

    def load_candidate_generation(
        self,
        *,
        scope: Scope,
        agent_run_id: str,
        generation_id: str,
        candidate_tree_hash: str,
    ) -> CandidateGenerationMaterial:
        """Load only the exact latest candidate bound to this run."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT g.id,g.base_tree_hash,g.candidate_tree_hash,
                          g.candidate_manifest_ref,g.candidate_manifest_hash
                     FROM solvan_delivery.workspace_candidate_generations g
                     JOIN solvan.agent_runs a
                       ON (a.organization_id,a.project_id,a.environment_id,a.id)=
                          (g.organization_id,g.project_id,g.environment_id,g.agent_run_id)
                    WHERE g.organization_id=%(organization_id)s
                      AND g.project_id=%(project_id)s
                      AND g.environment_id=%(environment_id)s
                      AND g.agent_run_id=%(agent_run_id)s
                      AND g.id=%(generation_id)s
                      AND g.candidate_tree_hash=%(candidate_tree_hash)s
                      AND a.agent_key='workspace-agent'
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.workspace_candidate_generations newer
                         WHERE newer.organization_id=g.organization_id
                           AND newer.project_id=g.project_id
                           AND newer.environment_id=g.environment_id
                           AND newer.agent_run_id=g.agent_run_id
                           AND newer.generation_ordinal>g.generation_ordinal)""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "generation_id": generation_id,
                    "candidate_tree_hash": candidate_tree_hash,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkspaceRepairConflict("candidate generation is stale or belongs to another run")
        return CandidateGenerationMaterial(
            generation_id=str(row["id"]),
            base_tree_hash=str(row["base_tree_hash"]),
            candidate_tree_hash=str(row["candidate_tree_hash"]),
            manifest_ref=str(row["candidate_manifest_ref"]),
            manifest_hash=str(row["candidate_manifest_hash"]),
        )
