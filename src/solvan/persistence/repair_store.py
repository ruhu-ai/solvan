"""PostgreSQL authority for exact immutable permanent-repair plans."""

from __future__ import annotations

import hashlib
import json
import shlex
from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import RepairPlanningError, RepairPlanRecord, WorkspaceAttemptMaterial
from solvan.domain import Scope, new_identifier
from solvan.persistence.postgres_types import AggregateType, LeaseHandle
from solvan.persistence.repair_policy import (
    REPOSITORY_KEYS,
    confirmed_evidence_refs,
    validate_repository_policy,
)


class PostgresRepairStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def define_exact_plan(self, *, scope: Scope, lease: LeaseHandle) -> RepairPlanRecord:
        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("repair planning requires a Reliability Case lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT c.id, c.workflow_version, i.confirmed_root_cause_id,
                    i.production_graph_snapshot_id
                  FROM solvan.reliability_cases c
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (c.organization_id, c.project_id, c.environment_id,
                        c.originating_incident_id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'ROOT_CAUSE_ANALYSIS'
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()
                    AND i.confirmed_root_cause_id IS NOT NULL FOR UPDATE OF c""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            case = cursor.fetchone()
            if case is None:
                raise RepairPlanningError(
                    "case is stale, not in root-cause analysis, or lacks a confirmed cause"
                )
            cursor.execute(
                """SELECT * FROM solvan.repair_plans
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND reliability_case_id = %(case_id)s AND status = 'ACTIVE'
                  ORDER BY plan_version DESC LIMIT 1""",
                {**scope.canonical_dict(), "case_id": lease.entity_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                return self._record(existing, created=False)
            cursor.execute(
                """SELECT n.id, n.attributes_json
                  FROM solvan.production_graph_nodes n
                  JOIN solvan.production_graph_snapshots g
                    ON (g.organization_id, g.project_id, g.environment_id, g.id)
                     = (n.organization_id, n.project_id, n.environment_id, n.snapshot_id)
                  WHERE n.organization_id = %(organization_id)s
                    AND n.project_id = %(project_id)s
                    AND n.environment_id = %(environment_id)s
                    AND n.snapshot_id = %(snapshot_id)s AND n.node_kind = 'REPOSITORY'
                    AND g.status = 'APPROVED' AND g.superseded_at IS NULL
                  ORDER BY n.id LIMIT 2""",
                {
                    **scope.canonical_dict(),
                    "snapshot_id": case["production_graph_snapshot_id"],
                },
            )
            repositories = cursor.fetchall()
            if len(repositories) != 1:
                raise RepairPlanningError("one exact approved repository policy is required")
            attributes = repositories[0]["attributes_json"]
            if not isinstance(attributes, dict) or set(attributes) != REPOSITORY_KEYS:
                raise RepairPlanningError("repository policy has an unsupported schema")
            policy = cast(dict[str, Any], attributes)
            validate_repository_policy(policy)
            cursor.execute(
                """SELECT d.id,d.command_kind,d.argv_json
                     FROM solvan_delivery.repair_plan_command_definitions d
                     JOIN solvan.github_repositories r
                       ON (r.organization_id,r.project_id,r.environment_id,r.id)=
                          (d.organization_id,d.project_id,d.environment_id,
                           d.repository_binding_id)
                    WHERE d.organization_id=%(organization_id)s
                      AND d.project_id=%(project_id)s
                      AND d.environment_id=%(environment_id)s
                      AND d.repository_binding_id=%(repository_binding_id)s
                      AND d.id = ANY(%(definition_ids)s)
                      AND d.lifecycle='APPROVED' AND r.status='ACTIVE'""",
                {
                    **scope.canonical_dict(),
                    "repository_binding_id": policy["repository_binding_id"],
                    "definition_ids": [
                        policy["reproduction_command_definition_id"],
                        policy["regression_command_definition_id"],
                    ],
                },
            )
            definitions = {str(row["id"]): row for row in cursor.fetchall()}
            reproduction = definitions.get(str(policy["reproduction_command_definition_id"]))
            regression = definitions.get(str(policy["regression_command_definition_id"]))
            if (
                reproduction is None
                or regression is None
                or reproduction["command_kind"] != "REPRODUCTION"
                or regression["command_kind"] != "REGRESSION"
            ):
                raise RepairPlanningError("approved registered repair commands are unavailable")
            reproduction_argv = reproduction["argv_json"]
            regression_argv = regression["argv_json"]
            if (
                not isinstance(reproduction_argv, list)
                or not all(isinstance(item, str) for item in reproduction_argv)
                or not isinstance(regression_argv, list)
                or not all(isinstance(item, str) for item in regression_argv)
            ):
                raise RepairPlanningError("registered repair command argv is malformed")
            reproduction_command = shlex.join(reproduction_argv)
            test_command = shlex.join(regression_argv)
            evidence_refs = confirmed_evidence_refs(
                cursor,
                scope,
                confirmed_root_cause_id=str(case["confirmed_root_cause_id"]),
            )
            plan_id = new_identifier("rep")
            canonical = {
                "reliability_case_id": lease.entity_id,
                "plan_version": 1,
                "repository_node_id": str(repositories[0]["id"]),
                **policy,
                "confirmed_root_cause_id": str(case["confirmed_root_cause_id"]),
                "evidence_refs": list(evidence_refs),
            }
            content_hash = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            cursor.execute(
                """INSERT INTO solvan.repair_plans
                  (organization_id, project_id, environment_id, id,
                   reliability_case_id, plan_version, repository_node_id,
                   repository_snapshot_uri, repository_snapshot_hash,
                   base_commit_sha, reproduction_command, allowed_file_globs_json,
                   test_command, artifact_output_uri, confirmed_root_cause_id,
                   evidence_refs_json, provider, content_hash, status)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(plan_id)s, %(case_id)s, 1, %(repository_node_id)s,
                    %(repository_snapshot_uri)s, %(repository_snapshot_hash)s,
                    %(base_commit_sha)s, %(reproduction_command)s, %(allowed_file_globs)s,
                    %(test_command)s, %(artifact_output_uri)s,
                    %(confirmed_root_cause_id)s, %(evidence_refs)s, %(provider)s,
                    %(content_hash)s, 'ACTIVE') RETURNING *""",
                {
                    **scope.canonical_dict(),
                    "plan_id": plan_id,
                    "case_id": lease.entity_id,
                    "repository_node_id": repositories[0]["id"],
                    "repository_snapshot_uri": policy["repository_snapshot_uri"],
                    "repository_snapshot_hash": policy["repository_snapshot_hash"],
                    "base_commit_sha": policy["base_commit_sha"],
                    "reproduction_command": reproduction_command,
                    "allowed_file_globs": Jsonb(policy["allowed_file_globs"]),
                    "test_command": test_command,
                    "artifact_output_uri": policy["artifact_output_uri"],
                    "confirmed_root_cause_id": case["confirmed_root_cause_id"],
                    "evidence_refs": Jsonb(list(evidence_refs)),
                    "provider": policy["provider"],
                    "content_hash": content_hash,
                },
            )
            row = cursor.fetchone()
            if row is None:  # pragma: no cover - INSERT always returns
                raise RuntimeError("repair plan insert returned no row")
            return self._record(row, created=True)

    def load_active_plan(
        self, *, scope: Scope, lease: LeaseHandle, required_state: str
    ) -> RepairPlanRecord:
        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("repair plan load requires a Reliability Case lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.* FROM solvan.repair_plans p
                  JOIN solvan.reliability_cases c
                    ON (c.organization_id, c.project_id, c.environment_id, c.id)
                     = (p.organization_id, p.project_id, p.environment_id,
                        p.reliability_case_id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = %(required_state)s
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now() AND p.status = 'ACTIVE'
                  ORDER BY p.plan_version DESC LIMIT 1""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "required_state": required_state,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RepairPlanningError("case has no exact active repair plan")
        return self._record(row, created=False)

    def replan_after_requested_changes(
        self, *, scope: Scope, lease: LeaseHandle
    ) -> RepairPlanRecord:
        """Create one immutable successor after an applied exact patch review.

        The reviewed patch is never edited in place. The successor preserves the
        approved repository boundary and adds the human decision as provenance;
        a later repository snapshot requires a separately approved Production
        Graph revision instead of being silently inferred here.
        """

        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("repair replanning requires a Reliability Case lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.*, r.id AS review_id
                  FROM solvan.repair_plans p
                  JOIN solvan.reliability_cases c
                    ON (c.organization_id, c.project_id, c.environment_id, c.id)
                     = (p.organization_id, p.project_id, p.environment_id,
                        p.reliability_case_id)
                  JOIN solvan.patch_artifacts pa
                    ON (pa.organization_id, pa.project_id, pa.environment_id,
                        pa.repair_plan_id)
                     = (p.organization_id, p.project_id, p.environment_id, p.id)
                  JOIN solvan.patch_reviews r
                    ON (r.organization_id, r.project_id, r.environment_id,
                        r.patch_artifact_id)
                     = (pa.organization_id, pa.project_id, pa.environment_id, pa.id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'REPAIR_IN_PROGRESS'
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now() AND p.status = 'ACTIVE'
                    AND r.decision = 'CHANGES_REQUESTED' AND r.applied_at IS NOT NULL
                  ORDER BY r.applied_at DESC, r.id DESC LIMIT 1 FOR UPDATE OF p, c""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            current = cursor.fetchone()
            if current is None:
                raise RepairPlanningError(
                    "no applied changes-requested review is bound to the active plan"
                )
            plan_version = int(current["plan_version"]) + 1
            review_ref = f"db://solvan/patch-reviews/{current['review_id']}"
            evidence_refs = tuple(str(item) for item in current["evidence_refs_json"])
            if review_ref not in evidence_refs:
                evidence_refs = (*evidence_refs, review_ref)
            plan_id = new_identifier("rep")
            canonical = {
                "reliability_case_id": lease.entity_id,
                "plan_version": plan_version,
                "repository_node_id": str(current["repository_node_id"]),
                "repository_snapshot_uri": str(current["repository_snapshot_uri"]),
                "repository_snapshot_hash": str(current["repository_snapshot_hash"]),
                "base_commit_sha": str(current["base_commit_sha"]),
                "reproduction_command": str(current["reproduction_command"]),
                "allowed_file_globs": list(current["allowed_file_globs_json"]),
                "test_command": str(current["test_command"]),
                "artifact_output_uri": str(current["artifact_output_uri"]),
                "provider": str(current["provider"]),
                "confirmed_root_cause_id": str(current["confirmed_root_cause_id"]),
                "evidence_refs": list(evidence_refs),
                "supersedes_id": str(current["id"]),
            }
            content_hash = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            cursor.execute(
                """UPDATE solvan.repair_plans SET status = 'SUPERSEDED'
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(current_id)s
                    AND status = 'ACTIVE'""",
                {**scope.canonical_dict(), "current_id": current["id"]},
            )
            if cursor.rowcount != 1:
                raise RepairPlanningError("active repair plan changed during replanning")
            cursor.execute(
                """INSERT INTO solvan.repair_plans
                  (organization_id, project_id, environment_id, id,
                   reliability_case_id, plan_version, repository_node_id,
                   repository_snapshot_uri, repository_snapshot_hash,
                   base_commit_sha, reproduction_command, allowed_file_globs_json,
                   test_command, artifact_output_uri, confirmed_root_cause_id,
                   evidence_refs_json, provider, content_hash, status, supersedes_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(plan_id)s, %(case_id)s, %(plan_version)s,
                    %(repository_node_id)s, %(repository_snapshot_uri)s,
                    %(repository_snapshot_hash)s, %(base_commit_sha)s,
                    %(reproduction_command)s, %(allowed_file_globs)s,
                    %(test_command)s, %(artifact_output_uri)s,
                    %(confirmed_root_cause_id)s, %(evidence_refs)s, %(provider)s,
                    %(content_hash)s, 'ACTIVE', %(supersedes_id)s) RETURNING *""",
                {
                    **scope.canonical_dict(),
                    "plan_id": plan_id,
                    "case_id": lease.entity_id,
                    "plan_version": plan_version,
                    "repository_node_id": current["repository_node_id"],
                    "repository_snapshot_uri": current["repository_snapshot_uri"],
                    "repository_snapshot_hash": current["repository_snapshot_hash"],
                    "base_commit_sha": current["base_commit_sha"],
                    "reproduction_command": current["reproduction_command"],
                    "allowed_file_globs": Jsonb(list(current["allowed_file_globs_json"])),
                    "test_command": current["test_command"],
                    "artifact_output_uri": current["artifact_output_uri"],
                    "confirmed_root_cause_id": current["confirmed_root_cause_id"],
                    "evidence_refs": Jsonb(list(evidence_refs)),
                    "provider": current["provider"],
                    "content_hash": content_hash,
                    "supersedes_id": current["id"],
                },
            )
            row = cursor.fetchone()
            if row is None:  # pragma: no cover - INSERT always returns
                raise RuntimeError("repair replan insert returned no row")
        return self._record(row, created=True)

    def workspace_attempt(
        self, *, scope: Scope, lease: LeaseHandle, run_id: str
    ) -> WorkspaceAttemptMaterial:
        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("Workspace Agent material requires a Reliability Case lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.*, r.id AS run_id, w.id AS workspace_id,
                    r.workspace_generation,
                    coalesce(r.output_ref, r.runtime_output_ref) AS provider_output_ref,
                    coalesce(r.runtime_operation_name, r.provider_request_id)
                      AS provider_operation_name,
                    r.agent_revision AS run_agent_revision,
                    r.provider_request_hash,
                    r.implementation_sdk_distribution_hash,
                    r.provider_artifact_digest, r.effective_tool_set_hash,
                    r.effective_network_policy_hash
                  FROM solvan.agent_runs r
                  JOIN solvan.workspaces w
                    ON (w.organization_id, w.project_id, w.environment_id, w.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.workspace_id)
                  JOIN solvan.repair_plans p
                    ON (p.organization_id, p.project_id, p.environment_id, p.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.repair_plan_id)
                  JOIN solvan.reliability_cases c
                    ON (c.organization_id, c.project_id, c.environment_id, c.id)
                     = (w.organization_id, w.project_id, w.environment_id,
                        w.reliability_case_id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'REPAIR_IN_PROGRESS'
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()
                    AND r.id = %(run_id)s AND r.agent_key = 'workspace-agent'
                    AND r.workflow_version = c.workflow_version
                    AND r.status IN ('DISPATCHED','RUNNING')
                    AND coalesce(r.output_ref, r.runtime_output_ref) IS NOT NULL
                    AND coalesce(r.runtime_operation_name, r.provider_request_id) IS NOT NULL
                    AND p.status = 'ACTIVE'
                    AND r.repair_plan_version = p.plan_version""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                    "run_id": run_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RepairPlanningError("Workspace Agent attempt is stale or not exact")
        return WorkspaceAttemptMaterial(
            run_id=str(row["run_id"]),
            workspace_id=str(row["workspace_id"]),
            workspace_generation=int(row["workspace_generation"]),
            reliability_case_id=lease.entity_id,
            repair_plan=self._record(row, created=False),
            provider_output_ref=str(row["provider_output_ref"]),
            provider_operation_name=str(row["provider_operation_name"]),
            provider_revision=str(row["run_agent_revision"]),
            provider_request_hash=str(row["provider_request_hash"]),
            implementation_sdk_distribution_hash=str(row["implementation_sdk_distribution_hash"]),
            provider_artifact_digest=str(row["provider_artifact_digest"]),
            effective_tool_set_hash=str(row["effective_tool_set_hash"]),
            effective_network_policy_hash=str(row["effective_network_policy_hash"]),
        )

    def persist_patch_artifact(
        self,
        *,
        scope: Scope,
        lease: LeaseHandle,
        material: WorkspaceAttemptMaterial,
        sandbox_resource: str,
        unified_diff_ref: str,
        unified_diff_hash: str,
        changed_paths: tuple[str, ...],
        cognition_ref: str,
        cognition_hash: str,
        mechanism: str,
        hypotheses: tuple[dict[str, Any], ...],
        reproduction_exit_code: int,
        reproduction_output_ref: str,
        reproduction_output_hash: str,
        test_exit_code: int,
        test_output_ref: str,
        test_output_hash: str,
        residual_risks: tuple[str, ...],
        provider_output_hash: str,
        provider_boot_hash: str,
        provider_service_revision: str,
    ) -> str:
        if not changed_paths:
            raise ValueError("patch artifact requires changed paths")
        if not mechanism or len(hypotheses) < 2:
            raise ValueError("patch artifact requires mechanism and competing hypotheses")
        artifact_id = new_identifier("pat")
        status = (
            "TESTS_PASSED"
            if reproduction_exit_code != 0 and test_exit_code == 0
            else "TESTS_FAILED"
        )
        plan = material.repair_plan
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.patch_artifacts
                  (organization_id, project_id, environment_id, id,
                   reliability_case_id, repair_plan_id, repair_plan_version,
                   agent_run_id, sandbox_resource, base_commit_sha,
                   unified_diff_ref, unified_diff_hash, changed_paths_json,
                   cognition_ref, cognition_hash, mechanism, hypotheses_json,
                   reproduction_command,
                   reproduction_exit_code, reproduction_output_ref,
                   reproduction_output_hash,
                   test_command, test_exit_code, test_output_ref, test_output_hash,
                   residual_risks_json, provider, status)
                  SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(artifact_id)s, c.id, %(repair_plan_id)s,
                    %(repair_plan_version)s, r.id, %(sandbox_resource)s,
                    %(base_commit_sha)s, %(unified_diff_ref)s,
                    %(unified_diff_hash)s, %(changed_paths)s, %(cognition_ref)s,
                    %(cognition_hash)s, %(mechanism)s, %(hypotheses)s,
                    %(reproduction_command)s,
                    %(reproduction_exit_code)s, %(reproduction_output_ref)s,
                    %(reproduction_output_hash)s, %(test_command)s,
                    %(test_exit_code)s, %(test_output_ref)s, %(test_output_hash)s,
                    %(residual_risks)s, %(provider)s, %(status)s
                  FROM solvan.reliability_cases c
                  JOIN solvan.workspaces w
                    ON (w.organization_id, w.project_id, w.environment_id,
                        w.reliability_case_id)
                     = (c.organization_id, c.project_id, c.environment_id, c.id)
                  JOIN solvan.agent_runs r
                    ON (r.organization_id, r.project_id, r.environment_id,
                        r.workspace_id)
                     = (w.organization_id, w.project_id, w.environment_id, w.id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'REPAIR_IN_PROGRESS'
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()
                    AND r.organization_id = c.organization_id
                    AND r.project_id = c.project_id
                    AND r.environment_id = c.environment_id
                    AND r.id = %(run_id)s AND r.status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "artifact_id": artifact_id,
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                    "run_id": material.run_id,
                    "repair_plan_id": plan.repair_plan_id,
                    "repair_plan_version": plan.plan_version,
                    "sandbox_resource": sandbox_resource,
                    "base_commit_sha": plan.base_commit_sha,
                    "unified_diff_ref": unified_diff_ref,
                    "unified_diff_hash": unified_diff_hash,
                    "changed_paths": Jsonb(list(changed_paths)),
                    "cognition_ref": cognition_ref,
                    "cognition_hash": cognition_hash,
                    "mechanism": mechanism,
                    "hypotheses": Jsonb(list(hypotheses)),
                    "reproduction_command": plan.reproduction_command,
                    "reproduction_exit_code": reproduction_exit_code,
                    "reproduction_output_ref": reproduction_output_ref,
                    "reproduction_output_hash": reproduction_output_hash,
                    "test_command": plan.test_command,
                    "test_exit_code": test_exit_code,
                    "test_output_ref": test_output_ref,
                    "test_output_hash": test_output_hash,
                    "residual_risks": Jsonb(list(residual_risks)),
                    "provider": plan.provider,
                    "status": status,
                },
            )
            if cursor.rowcount != 1:
                raise RepairPlanningError("patch artifact lost exact case authority")
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'SUCCEEDED',
                    output_ref = %(output_ref)s, output_hash = %(output_hash)s,
                    provider_boot_hash = %(provider_boot_hash)s,
                    provider_service_revision = %(provider_service_revision)s,
                    completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(run_id)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": material.run_id,
                    "output_ref": material.provider_output_ref,
                    "output_hash": provider_output_hash,
                    "provider_boot_hash": provider_boot_hash,
                    "provider_service_revision": provider_service_revision,
                },
            )
            if cursor.rowcount != 1:
                raise RepairPlanningError("Workspace Agent completion became stale")
        return artifact_id

    @staticmethod
    def _record(row: dict[str, Any], *, created: bool) -> RepairPlanRecord:
        return RepairPlanRecord(
            repair_plan_id=str(row["id"]),
            reliability_case_id=str(row["reliability_case_id"]),
            plan_version=int(row["plan_version"]),
            repository_node_id=str(row["repository_node_id"]),
            repository_snapshot_uri=str(row["repository_snapshot_uri"]),
            repository_snapshot_hash=str(row["repository_snapshot_hash"]),
            base_commit_sha=str(row["base_commit_sha"]),
            reproduction_command=str(row["reproduction_command"]),
            allowed_file_globs=tuple(str(item) for item in row["allowed_file_globs_json"]),
            test_command=str(row["test_command"]),
            artifact_output_uri=str(row["artifact_output_uri"]),
            confirmed_root_cause_id=str(row["confirmed_root_cause_id"]),
            evidence_refs=tuple(str(item) for item in row["evidence_refs_json"]),
            provider=str(row["provider"]),
            content_hash=str(row["content_hash"]),
            created=created,
        )
