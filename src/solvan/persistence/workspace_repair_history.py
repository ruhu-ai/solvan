"""Append-only candidate generations and exploratory repair receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.workspace_candidate import CandidateTree, CatalogCommand
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class WorkspaceRepairConflict(ValueError):
    """A workspace retry differs from the durable candidate/receipt history."""


@dataclass(frozen=True, slots=True)
class CandidateGeneration:
    generation_id: str
    generation_ordinal: int
    tree: CandidateTree
    manifest_ref: str
    manifest_hash: str


@dataclass(frozen=True, slots=True)
class ExploratorySandboxMaterial:
    agent_run_id: str
    candidate_generation_id: str
    candidate_manifest_ref: str
    candidate_manifest_hash: str
    candidate_tree_hash: str
    catalog_command: CatalogCommand
    command_hash: str
    resolved_input_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StoredExploratoryReceipt:
    receipt_id: str
    stdout_ref: str
    stdout_hash: str
    stderr_ref: str
    stderr_hash: str


class WorkspaceRepairHistoryStore:
    """Candidate/receipt portion of the repair authority store."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def load_exploratory_material(
        self,
        *,
        scope: Scope,
        agent_run_id: str,
        catalog_id: str,
        candidate_tree_hash: str,
    ) -> ExploratorySandboxMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT g.id AS candidate_generation_id,g.candidate_manifest_ref,
                          g.candidate_manifest_hash,g.candidate_tree_hash,
                          c.id AS catalog_id,c.command_hash,c.argv_json,c.working_directory,
                          c.timeout_ms,c.cpu_millis,c.memory_mib,c.output_byte_limit,
                          c.network_mode,c.base_tree_hash,c.status AS catalog_status,
                          c.resolved_inputs_json,c.resolved_inputs_hash
                     FROM solvan.agent_runs a
                     JOIN solvan.repair_plans p
                       ON (p.organization_id,p.project_id,p.environment_id,p.id)=
                          (a.organization_id,a.project_id,a.environment_id,a.repair_plan_id)
                     JOIN solvan_delivery.workspace_candidate_generations g
                       ON (g.organization_id,g.project_id,g.environment_id,g.agent_run_id)=
                          (a.organization_id,a.project_id,a.environment_id,a.id)
                     JOIN solvan_delivery.repair_plan_command_catalogs c
                       ON (c.organization_id,c.project_id,c.environment_id,c.repair_plan_id,
                           c.repair_plan_version)=
                          (a.organization_id,a.project_id,a.environment_id,a.repair_plan_id,
                           a.repair_plan_version)
                    WHERE a.organization_id=%(organization_id)s
                      AND a.project_id=%(project_id)s
                      AND a.environment_id=%(environment_id)s
                      AND a.id=%(agent_run_id)s
                      AND a.agent_key='workspace-agent'
                      AND a.workspace_task_kind='REPAIR'
                      AND a.status IN ('DISPATCHED','RUNNING') AND a.deadline>now()
                      AND p.status='ACTIVE' AND p.plan_version=a.repair_plan_version
                      AND g.candidate_tree_hash=%(candidate_tree_hash)s
                      AND c.id=%(catalog_id)s
                      AND c.base_tree_hash=g.base_tree_hash
                      AND EXISTS (
                        SELECT 1 FROM solvan_delivery.repair_plan_guidance_selection_sets s
                         WHERE s.organization_id=a.organization_id
                           AND s.project_id=a.project_id
                           AND s.environment_id=a.environment_id
                           AND s.repair_plan_id=a.repair_plan_id
                           AND s.repair_plan_version=a.repair_plan_version
                           AND s.status='BOUND' AND s.bound_agent_run_id=a.id)
                    ORDER BY g.generation_ordinal DESC LIMIT 1""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "catalog_id": catalog_id,
                    "candidate_tree_hash": candidate_tree_hash,
                },
            )
            row = cursor.fetchone()
        if row is None or row["catalog_status"] != "RESOLVED":
            raise WorkspaceRepairConflict("sandbox material is not bound to the live repair run")
        argv = row["argv_json"]
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise WorkspaceRepairConflict("workspace catalog argv is malformed")
        resolved_inputs = row["resolved_inputs_json"]
        if (
            not isinstance(resolved_inputs, list)
            or not resolved_inputs
            or canonical_sha256(resolved_inputs) != str(row["resolved_inputs_hash"])
            or any(
                not isinstance(item, dict)
                or set(item) != {"path", "content_hash"}
                or not isinstance(item["path"], str)
                or not isinstance(item["content_hash"], str)
                for item in resolved_inputs
            )
        ):
            raise WorkspaceRepairConflict("workspace catalog resolved inputs are malformed")
        command = CatalogCommand(
            command_id=str(row["catalog_id"]),
            argv=tuple(argv),
            working_directory=str(row["working_directory"]),
            timeout_ms=int(row["timeout_ms"]),
            cpu_millis=int(row["cpu_millis"]),
            memory_mib=int(row["memory_mib"]),
            output_byte_limit=int(row["output_byte_limit"]),
            network_mode=str(row["network_mode"]),
        )
        return ExploratorySandboxMaterial(
            agent_run_id=agent_run_id,
            candidate_generation_id=str(row["candidate_generation_id"]),
            candidate_manifest_ref=str(row["candidate_manifest_ref"]),
            candidate_manifest_hash=str(row["candidate_manifest_hash"]),
            candidate_tree_hash=str(row["candidate_tree_hash"]),
            catalog_command=command,
            command_hash=str(row["command_hash"]),
            resolved_input_paths=tuple(str(item["path"]) for item in resolved_inputs),
        )

    def record_exploratory_receipt(
        self,
        *,
        scope: Scope,
        material: ExploratorySandboxMaterial,
        sandbox_image_hash: str,
        request_hash: str,
        exit_code: int,
        stdout_ref: str,
        stdout_hash: str,
        stderr_ref: str,
        stderr_hash: str,
        output_bytes: int,
        started_at: datetime,
        completed_at: datetime,
    ) -> StoredExploratoryReceipt:
        receipt_id = new_identifier("esr")
        values: dict[str, object] = {
            **scope.canonical_dict(),
            "id": receipt_id,
            "agent_run_id": material.agent_run_id,
            "candidate_generation_id": material.candidate_generation_id,
            "command_catalog_id": material.catalog_command.command_id,
            "command_hash": material.command_hash,
            "sandbox_image_hash": sandbox_image_hash,
            "request_hash": request_hash,
            "exit_code": exit_code,
            "stdout_ref": stdout_ref,
            "stdout_hash": stdout_hash,
            "stderr_ref": stderr_ref,
            "stderr_hash": stderr_hash,
            "output_bytes": output_bytes,
            "started_at": started_at,
            "completed_at": completed_at,
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """INSERT INTO solvan_delivery.exploratory_sandbox_receipts
                    (organization_id,project_id,environment_id,id,agent_run_id,
                     candidate_generation_id,command_catalog_id,command_hash,
                     sandbox_image_hash,request_hash,exit_code,stdout_ref,stdout_hash,
                     stderr_ref,stderr_hash,output_bytes,trust_class,started_at,completed_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(agent_run_id)s,%(candidate_generation_id)s,%(command_catalog_id)s,
                     %(command_hash)s,%(sandbox_image_hash)s,%(request_hash)s,%(exit_code)s,
                     %(stdout_ref)s,%(stdout_hash)s,%(stderr_ref)s,%(stderr_hash)s,
                     %(output_bytes)s,'EXPERIMENTAL',%(started_at)s,%(completed_at)s)
                   ON CONFLICT DO NOTHING""",
                values,
            )
            if cursor.rowcount == 1:
                return StoredExploratoryReceipt(
                    receipt_id, stdout_ref, stdout_hash, stderr_ref, stderr_hash
                )
            cursor.execute(
                """SELECT id,stdout_ref,stdout_hash,stderr_ref,stderr_hash,exit_code,
                          command_catalog_id,command_hash,sandbox_image_hash,output_bytes,
                          started_at,completed_at
                     FROM solvan_delivery.exploratory_sandbox_receipts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND agent_run_id=%(agent_run_id)s
                      AND candidate_generation_id=%(candidate_generation_id)s
                      AND command_hash=%(command_hash)s AND request_hash=%(request_hash)s""",
                values,
            )
            replay = cursor.fetchone()
            expected = {
                "exit_code": exit_code,
                "command_catalog_id": material.catalog_command.command_id,
                "command_hash": material.command_hash,
                "sandbox_image_hash": sandbox_image_hash,
                "output_bytes": output_bytes,
                "started_at": started_at,
                "completed_at": completed_at,
                "stdout_ref": stdout_ref,
                "stdout_hash": stdout_hash,
                "stderr_ref": stderr_ref,
                "stderr_hash": stderr_hash,
            }
            if replay is None or {key: replay[key] for key in expected} != expected:
                raise WorkspaceRepairConflict("exploratory sandbox receipt replay conflicts")
            return StoredExploratoryReceipt(
                str(replay["id"]),
                str(replay["stdout_ref"]),
                str(replay["stdout_hash"]),
                str(replay["stderr_ref"]),
                str(replay["stderr_hash"]),
            )

    def append_generation(
        self,
        *,
        scope: Scope,
        repair_plan_id: str,
        repair_plan_version: int,
        agent_run_id: str,
        parent_generation_id: str | None,
        base_tree_hash: str,
        tree: CandidateTree,
        manifest_ref: str,
        manifest_hash: str,
        input_hash: str,
    ) -> CandidateGeneration:
        """CAS append a successor; no mutable candidate tree exists."""

        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """SELECT id,generation_ordinal,parent_generation_id,base_tree_hash,
                          candidate_tree_hash,candidate_manifest_ref,candidate_manifest_hash
                     FROM solvan_delivery.workspace_candidate_generations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND agent_run_id=%(agent_run_id)s AND input_hash=%(input_hash)s
                    FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "input_hash": input_hash,
                },
            )
            replay = cursor.fetchone()
            if replay is not None:
                if (
                    replay["parent_generation_id"] != parent_generation_id
                    or replay["base_tree_hash"] != base_tree_hash
                    or replay["candidate_tree_hash"] != tree.tree_hash
                    or replay["candidate_manifest_ref"] != manifest_ref
                    or replay["candidate_manifest_hash"] != manifest_hash
                ):
                    raise WorkspaceRepairConflict("candidate command replay material drifted")
                return CandidateGeneration(
                    str(replay["id"]),
                    int(replay["generation_ordinal"]),
                    tree,
                    manifest_ref,
                    manifest_hash,
                )
            cursor.execute(
                """SELECT id,generation_ordinal FROM solvan_delivery.workspace_candidate_generations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND agent_run_id=%(agent_run_id)s
                    ORDER BY generation_ordinal DESC LIMIT 1 FOR UPDATE""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            parent = cursor.fetchone()
            if parent is None:
                if parent_generation_id is not None:
                    raise WorkspaceRepairConflict("first candidate generation cannot name a parent")
                ordinal = 1
            else:
                if str(parent["id"]) != parent_generation_id:
                    raise WorkspaceRepairConflict(
                        "candidate parent no longer matches the current generation"
                    )
                ordinal = int(parent["generation_ordinal"]) + 1
            changed_paths_hash = canonical_sha256([item.path for item in tree.files])
            generation_id = new_identifier("wcg")
            cursor.execute(
                """INSERT INTO solvan_delivery.workspace_candidate_generations
                    (organization_id,project_id,environment_id,id,repair_plan_id,repair_plan_version,
                     agent_run_id,parent_generation_id,generation_ordinal,base_tree_hash,changed_paths_hash,
                     candidate_tree_hash,candidate_manifest_ref,candidate_manifest_hash,aggregate_bytes,
                     file_count,input_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(repair_plan_id)s,
                     %(repair_plan_version)s,%(agent_run_id)s,%(parent_generation_id)s,%(ordinal)s,
                     %(base_tree_hash)s,%(changed_paths_hash)s,%(tree_hash)s,%(manifest_ref)s,%(manifest_hash)s,
                     %(aggregate_bytes)s,%(file_count)s,%(input_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": generation_id,
                    "repair_plan_id": repair_plan_id,
                    "repair_plan_version": repair_plan_version,
                    "agent_run_id": agent_run_id,
                    "parent_generation_id": parent_generation_id,
                    "ordinal": ordinal,
                    "base_tree_hash": base_tree_hash,
                    "changed_paths_hash": changed_paths_hash,
                    "tree_hash": tree.tree_hash,
                    "manifest_ref": manifest_ref,
                    "manifest_hash": manifest_hash,
                    "aggregate_bytes": sum(len(item.content.encode()) for item in tree.files),
                    "file_count": len(tree.files),
                    "input_hash": input_hash,
                },
            )
        return CandidateGeneration(generation_id, ordinal, tree, manifest_ref, manifest_hash)
