"""Token-fenced creation of durable Agent Runtime attempts."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import (
    CoordinatorAuthority,
    RepairPlanRecord,
    RuntimeDispatch,
    WorkspaceArtifactDescriptor,
    WorkspaceInputMaterial,
    WorkspaceProviderKind,
    WorkspaceRef,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
    workspace_artifact_handle,
    workspace_repair_budget,
)
from solvan.application.effective_tool_set import EffectiveToolSetV1
from solvan.domain import Scope, StepBudget, new_identifier
from solvan.persistence.postgres_types import AggregateType, LeaseHandle
from solvan.persistence.runtime_dispatch_projection import execution_dispatch, verification_dispatch
from solvan.persistence.runtime_types import RuntimeRunConflict

#: A repository file inherits the snapshot it was cut from. Guidance does not
#: come from that snapshot, so specification 12 §8.1 material must state its own
#: object and provenance, and the shape refuses a pack that cannot.
_REPOSITORY_FILE_KEYS = frozenset({"path", "content", "content_hash"})
_GUIDANCE_FILE_KEYS = _REPOSITORY_FILE_KEYS | {"object_ref", "provenance_ref"}


def workspace_input_material(
    *,
    plan: RepairPlanRecord,
    repository_files: list[dict[str, str]],
    guidance_files: list[dict[str, str]] | None,
    repository_provenance: tuple[str, ...],
) -> tuple[tuple[WorkspaceInputMaterial, ...], tuple[WorkspaceArtifactDescriptor, ...]]:
    """Hash and manifest-bind every workspace input against its true source.

    A manifest entry names where a reviewer goes to read the bytes a digest
    commits to. Materialising approved guidance under the repository snapshot's
    object reference and provenance would make that entry a false statement
    about material the workspace was handed, which is exactly the kind of claim
    the manifest exists to prevent.
    """

    sources: list[tuple[dict[str, str], frozenset[str]]] = [
        (item, _REPOSITORY_FILE_KEYS) for item in repository_files
    ]
    sources.extend((item, _GUIDANCE_FILE_KEYS) for item in guidance_files or ())
    materials: list[WorkspaceInputMaterial] = []
    artifacts: list[WorkspaceArtifactDescriptor] = []
    for item, expected_keys in sources:
        if set(item) != expected_keys:
            raise ValueError("workspace prompt file has an unsupported shape")
        content = item["content"]
        encoded = content.encode("utf-8")
        digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        if digest != item["content_hash"]:
            raise ValueError("workspace prompt file hash does not match its content")
        material = WorkspaceInputMaterial(
            path=item["path"],
            content=content,
            content_hash=digest,
            media_type="text/plain; charset=utf-8",
        )
        materials.append(material)
        artifacts.append(
            WorkspaceArtifactDescriptor(
                artifact_handle=workspace_artifact_handle(item["path"], digest),
                path=item["path"],
                object_ref=item.get(
                    "object_ref",
                    f"{plan.repository_snapshot_uri}#path={quote(item['path'], safe='')}",
                ),
                content_hash=digest,
                size_bytes=len(encoded),
                media_type=material.media_type,
                provenance_refs=(
                    (item["provenance_ref"],) if "provenance_ref" in item else repository_provenance
                ),
            )
        )
    return tuple(materials), tuple(artifacts)


class RuntimeReservationMixin:
    _connection: Connection[Any]

    def reserve_workspace_repair(
        self,
        *,
        scope: Scope,
        lease: LeaseHandle,
        plan: RepairPlanRecord,
        workspace: WorkspaceRef,
        repository_files: list[dict[str, str]],
        guidance_files: list[dict[str, str]] | None = None,
        agent_resource: str,
        agent_revision: str,
        effective_tool_set_hash: str,
        effective_network_policy_hash: str,
        effective_tool_set: EffectiveToolSetV1 | None = None,
        command_catalog_ids: tuple[str, str] | None = None,
        command_catalog_hash: str | None = None,
    ) -> WorkspaceTaskInvocation | None:
        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("Workspace Agent reservation requires a Reliability Case lease")
        if workspace.status.value != "OPEN":
            raise ValueError("repair requires one open workspace")
        if plan.provider != workspace.provider.value:
            raise ValueError("repair plan and workspace provider do not match")
        if agent_revision != workspace.provider_revision:
            raise ValueError("repair dispatch revision does not match the workspace")
        antigravity = workspace.provider is WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN
        if not antigravity:
            if effective_tool_set is None:
                raise ValueError("production Workspace dispatch requires Tool-set material")
            if effective_tool_set.effective_tool_set_hash != effective_tool_set_hash:
                raise ValueError("Workspace Tool-set material differs from its digest")
            if (
                command_catalog_ids is None
                or command_catalog_ids[0] == command_catalog_ids[1]
                or command_catalog_hash is None
            ):
                raise ValueError("production Workspace dispatch requires two catalog commands")
        catalog_ids = command_catalog_ids or ("", "")
        budget = workspace_repair_budget(synthetic_provider=antigravity)
        runtime_seconds = budget.max_runtime_seconds
        future_version = lease.workflow_version + 1
        logical_step_key = (
            f"case:{lease.entity_id}:workspace-repair:{plan.repair_plan_id}:{plan.plan_version}"
        )
        # Specification 12 §8.1. Approved guidance is materialised alongside the
        # repository under the `guidance/` prefix the provider reads as skills.
        # It is hashed and manifest-bound exactly like every other input, so a
        # pack is signed material rather than trusted text, and a workspace with
        # no selected guidance simply gets none.
        input_materials, input_artifacts = workspace_input_material(
            plan=plan,
            repository_files=repository_files,
            guidance_files=guidance_files,
            repository_provenance=(
                (plan.repository_snapshot_hash,)
                if antigravity
                else (plan.repository_snapshot_hash, *plan.evidence_refs)
            ),
        )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT c.id FROM solvan.reliability_cases c
                  JOIN solvan.repair_plans p
                    ON (p.organization_id, p.project_id, p.environment_id,
                        p.reliability_case_id)
                     = (c.organization_id, c.project_id, c.environment_id, c.id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'REPAIR_PLANNED'
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()
                    AND p.id = %(repair_plan_id)s
                    AND p.plan_version = %(repair_plan_version)s
                    AND p.status = 'ACTIVE' FOR UPDATE OF c""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                    "repair_plan_id": plan.repair_plan_id,
                    "repair_plan_version": plan.plan_version,
                },
            )
            if cursor.fetchone() is None:
                raise RuntimeRunConflict("Workspace Agent reservation has stale case authority")
            cursor.execute(
                """SELECT * FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND logical_step_key = %(logical_step_key)s
                  ORDER BY attempt DESC LIMIT 1 FOR UPDATE""",
                {**scope.canonical_dict(), "logical_step_key": logical_step_key},
            )
            existing = cursor.fetchone()
            if existing is not None and existing["status"] in {
                "DISPATCHED",
                "RUNNING",
                "SUCCEEDED",
            }:
                return None
            attempt = 1 if existing is None else int(existing["attempt"]) + 1
            run_id = (
                str(existing["id"])
                if existing is not None and existing["status"] == "CREATED"
                else new_identifier("run")
            )
            invocation_id = (
                str(existing["invocation_id"])
                if existing is not None and existing["status"] == "CREATED"
                else new_identifier("inv")
            )
            request_id = (
                str(existing["provider_request_id"])
                if existing is not None and existing["status"] == "CREATED"
                else new_identifier("req")
            )
            trace_id = (
                str(existing["trace_id"])
                if existing is not None and existing["status"] == "CREATED"
                else secrets.token_hex(16)
            )
            span_id = (
                str(existing["span_id"])
                if existing is not None and existing["status"] == "CREATED"
                else secrets.token_hex(8)
            )
            deadline = (
                existing["deadline"]
                if existing is not None and existing["status"] == "CREATED"
                else datetime.now(UTC) + timedelta(seconds=runtime_seconds + 30)
            )
            invocation = WorkspaceTaskInvocation.build(
                schema_version=1,
                request_id=request_id,
                run_id=run_id,
                invocation_id=invocation_id,
                logical_step_key=logical_step_key,
                attempt=attempt,
                scope=scope,
                workspace_id=workspace.workspace_id,
                workspace_generation=workspace.generation,
                task_kind=WorkspaceTaskKind.REPAIR,
                provider=workspace.provider,
                provider_resource=agent_resource,
                provider_revision=agent_revision,
                implementation_sdk_distribution_hash=(
                    workspace.implementation_sdk_distribution_hash
                ),
                provider_artifact_digest=workspace.provider_artifact_digest,
                workflow_version=future_version,
                deadline=deadline,
                budget=budget,
                input_manifest_ref=workspace.input_manifest_ref,
                input_manifest_hash=workspace.input_manifest_hash,
                effective_tool_set_hash=effective_tool_set_hash,
                effective_tool_set=effective_tool_set,
                effective_network_policy_hash=effective_network_policy_hash,
                allowed_tool_names=(
                    ("read_workspace_artifact", "write_candidate_artifact")
                    if antigravity
                    else (
                        "read_workspace_artifact",
                        "write_candidate_artifact",
                        "run_in_exploratory_sandbox",
                    )
                ),
                input_artifacts=input_artifacts,
                input_materials=input_materials,
                objective=(
                    "Produce one minimal repair for the confirmed root cause "
                    f"{plan.confirmed_root_cause_id}; cite repository paths."
                ),
                task_parameters={
                    "base_commit_sha": plan.base_commit_sha,
                    "reproduction_command": plan.reproduction_command,
                    "test_command": plan.test_command,
                    "allowed_file_globs": list(plan.allowed_file_globs),
                    **(
                        {}
                        if antigravity
                        else {
                            "reproduction_command_id": catalog_ids[0],
                            "test_command_id": catalog_ids[1],
                            "command_catalog_hash": command_catalog_hash,
                        }
                    ),
                },
                trace_id=trace_id,
                span_id=span_id,
            )
            if existing is not None and existing["status"] == "CREATED":
                if existing["provider_request_hash"] != invocation.request_hash:
                    raise RuntimeRunConflict("created workspace request material drifted")
                return invocation
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id,
                   workspace_id, workspace_generation, workspace_task_kind,
                   provider_request_id, provider_request_hash,
                   implementation_sdk_distribution_hash, provider_artifact_digest,
                   effective_tool_set_hash, effective_network_policy_hash,
                   repair_plan_id, repair_plan_version,
                   logical_step_key, agent_key, agent_resource, agent_revision,
                   invocation_id, workflow_version, attempt, status, deadline,
                   budget_json, input_ref, input_hash, trace_id, span_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(run_id)s, %(workspace_id)s, %(workspace_generation)s, 'REPAIR',
                    %(request_id)s, %(request_hash)s,
                    %(implementation_sdk_distribution_hash)s,
                    %(provider_artifact_digest)s,
                    %(effective_tool_set_hash)s, %(effective_network_policy_hash)s,
                    %(repair_plan_id)s,
                    %(repair_plan_version)s, %(logical_step_key)s, 'workspace-agent',
                    %(agent_resource)s, %(agent_revision)s, %(invocation_id)s,
                    %(future_version)s, %(attempt)s, 'CREATED', %(deadline)s,
                    %(budget)s, %(input_ref)s, %(input_hash)s, %(trace_id)s,
                    %(span_id)s)""",
                {
                    **scope.canonical_dict(),
                    "run_id": invocation.run_id,
                    "workspace_id": invocation.workspace_id,
                    "workspace_generation": invocation.workspace_generation,
                    "request_id": invocation.request_id,
                    "request_hash": invocation.request_hash,
                    "implementation_sdk_distribution_hash": (
                        invocation.implementation_sdk_distribution_hash
                    ),
                    "provider_artifact_digest": invocation.provider_artifact_digest,
                    "effective_tool_set_hash": invocation.effective_tool_set_hash,
                    "effective_network_policy_hash": invocation.effective_network_policy_hash,
                    "repair_plan_id": plan.repair_plan_id,
                    "repair_plan_version": plan.plan_version,
                    "logical_step_key": logical_step_key,
                    "agent_resource": agent_resource,
                    "agent_revision": agent_revision,
                    "invocation_id": invocation.invocation_id,
                    "future_version": future_version,
                    "attempt": attempt,
                    "deadline": invocation.deadline,
                    "budget": Jsonb(invocation.budget.model_dump(mode="json")),
                    "input_ref": invocation.input_manifest_ref,
                    "input_hash": invocation.input_manifest_hash,
                    "trace_id": trace_id,
                    "span_id": span_id,
                },
            )
            return invocation

    def reserve_verification(
        self,
        *,
        scope: Scope,
        action_id: str,
        authority: CoordinatorAuthority,
        agent_resource: str,
        agent_revision: str,
    ) -> RuntimeDispatch | None:
        budget = StepBudget(
            deadline_ms=300_000,
            max_tool_calls=1,
            max_output_bytes=16_000,
            max_model_calls=1,
            max_replans=0,
        )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.id AS action_id, a.display_id, a.verification_profile_id,
                    a.verification_profile_version, i.id AS incident_id,
                    i.workflow_version, i.evidence_version
                  FROM solvan.actions a
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  JOIN solvan.verification_profiles vp
                    ON (vp.organization_id, vp.project_id, vp.environment_id,
                        vp.id, vp.version)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.verification_profile_id, a.verification_profile_version)
                  JOIN solvan.execution_receipts er
                    ON er.organization_id = a.organization_id
                   AND er.project_id = a.project_id
                   AND er.environment_id = a.environment_id
                   AND er.action_id = a.id AND er.result = 'SUCCEEDED'
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.id = %(action_id)s AND a.status = 'SUCCEEDED'
                    AND i.state = 'VERIFYING_MITIGATION'
                    AND i.workflow_version = %(workflow_version)s
                    AND i.lease_owner = %(lease_owner)s
                    AND i.lease_token = %(lease_token)s
                    AND i.lease_expires_at >= now()
                    AND vp.status = 'APPROVED'
                    AND er.reconciled_at
                      + ((vp.warmup_ms + vp.observation_ms) * interval '1 millisecond')
                      <= now()
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.agent_runs existing
                      WHERE existing.organization_id = a.organization_id
                        AND existing.project_id = a.project_id
                        AND existing.environment_id = a.environment_id
                        AND existing.action_id = a.id
                        AND existing.agent_key = 'verification-agent')
                  FOR UPDATE OF a, i""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "workflow_version": authority.workflow_version,
                    "lease_owner": authority.owner,
                    "lease_token": authority.lease_token,
                },
            )
            action = cursor.fetchone()
            if action is None:
                return None
            run_id = new_identifier("run")
            invocation_id = new_identifier("inv")
            trace_id = secrets.token_hex(16)
            span_id = secrets.token_hex(8)
            context = {
                "action_id": action_id,
                "action_display_id": str(action["display_id"]),
                "verification_profile_id": str(action["verification_profile_id"]),
                "verification_profile_version": int(action["verification_profile_version"]),
                "evidence_version": int(action["evidence_version"]),
            }
            logical_step_key = (
                f"incident:{action['incident_id']}:verify:{action_id}:"
                f"{action['verification_profile_id']}:v{action['verification_profile_version']}"
            )
            material = {
                "scope": scope.canonical_dict(),
                "incident_id": str(action["incident_id"]),
                "workflow_version": authority.workflow_version,
                "agent_resource": agent_resource,
                "agent_revision": agent_revision,
                "context": context,
                "budget": asdict(budget),
            }
            input_hash = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   action_id, logical_step_key, agent_key, agent_resource,
                   agent_revision, invocation_id, workflow_version, attempt,
                   status, deadline, budget_json, input_ref, input_hash,
                   trace_id, span_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(run_id)s, %(incident_id)s, %(action_id)s,
                    %(logical_step_key)s, 'verification-agent', %(agent_resource)s,
                    %(agent_revision)s, %(invocation_id)s, %(workflow_version)s, 1,
                    'CREATED', now() + interval '300 seconds', %(budget)s,
                    %(input_ref)s, %(input_hash)s, %(trace_id)s, %(span_id)s)
                  RETURNING *""",
                {
                    **scope.canonical_dict(),
                    "run_id": run_id,
                    "incident_id": action["incident_id"],
                    "action_id": action_id,
                    "logical_step_key": logical_step_key,
                    "agent_resource": agent_resource,
                    "agent_revision": agent_revision,
                    "invocation_id": invocation_id,
                    "workflow_version": authority.workflow_version,
                    "budget": Jsonb(asdict(budget)),
                    "input_ref": f"db://solvan/actions/{action_id}/verification",
                    "input_hash": input_hash,
                    "trace_id": trace_id,
                    "span_id": span_id,
                },
            )
            row = cursor.fetchone()
            assert row is not None
            return verification_dispatch(scope, row, context, budget)

    def reserve_execution(
        self,
        *,
        scope: Scope,
        action_id: str,
        authority: CoordinatorAuthority,
        agent_resource: str,
        agent_revision: str,
    ) -> RuntimeDispatch | None:
        budget = StepBudget(
            deadline_ms=300_000,
            max_tool_calls=1,
            max_output_bytes=16_000,
            max_model_calls=1,
            max_replans=0,
        )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.id AS action_id, a.action_type, a.display_id,
                    a.workflow_version, a.evidence_version, a.target_key,
                    a.expires_at, i.id AS incident_id
                  FROM solvan.actions a
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.id = %(action_id)s AND a.status = 'AUTHORIZED'
                    AND a.expires_at > now() AND i.state = 'MITIGATING'
                    AND i.workflow_version = %(workflow_version)s
                    AND a.workflow_version = i.workflow_version
                    AND i.lease_owner = %(lease_owner)s
                    AND i.lease_token = %(lease_token)s
                    AND i.lease_expires_at >= now()
                  FOR UPDATE OF a, i""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "workflow_version": authority.workflow_version,
                    "lease_owner": authority.owner,
                    "lease_token": authority.lease_token,
                },
            )
            action = cursor.fetchone()
            if action is None:
                raise RuntimeRunConflict("execution dispatch has no current action authority")
            logical_step_key = f"incident:{action['incident_id']}:execute:{action_id}"
            cursor.execute(
                """SELECT 1 FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND action_id = %(action_id)s LIMIT 1""",
                {**scope.canonical_dict(), "action_id": action_id},
            )
            if cursor.fetchone() is not None:
                return None
            run_id = new_identifier("run")
            invocation_id = new_identifier("inv")
            trace_id = secrets.token_hex(16)
            span_id = secrets.token_hex(8)
            context = {
                "action_id": action_id,
                "action_type": str(action["action_type"]),
                "action_display_id": str(action["display_id"]),
                "evidence_version": int(action["evidence_version"]),
                "target_key": str(action["target_key"]),
            }
            material = {
                "scope": scope.canonical_dict(),
                "incident_id": str(action["incident_id"]),
                "workflow_version": authority.workflow_version,
                "agent_resource": agent_resource,
                "agent_revision": agent_revision,
                "context": context,
                "budget": asdict(budget),
            }
            input_hash = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   action_id, logical_step_key, agent_key, agent_resource,
                   agent_revision, invocation_id, workflow_version, attempt,
                   status, deadline, budget_json, input_ref, input_hash,
                   trace_id, span_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(run_id)s, %(incident_id)s, %(action_id)s,
                    %(logical_step_key)s, 'execution-agent', %(agent_resource)s,
                    %(agent_revision)s, %(invocation_id)s, %(workflow_version)s, 1,
                    'CREATED', now() + interval '300 seconds', %(budget)s,
                    %(input_ref)s, %(input_hash)s, %(trace_id)s, %(span_id)s)
                  RETURNING *""",
                {
                    **scope.canonical_dict(),
                    "run_id": run_id,
                    "incident_id": action["incident_id"],
                    "action_id": action_id,
                    "logical_step_key": logical_step_key,
                    "agent_resource": agent_resource,
                    "agent_revision": agent_revision,
                    "invocation_id": invocation_id,
                    "workflow_version": authority.workflow_version,
                    "budget": Jsonb(asdict(budget)),
                    "input_ref": f"db://solvan/actions/{action_id}",
                    "input_hash": input_hash,
                    "trace_id": trace_id,
                    "span_id": span_id,
                },
            )
            row = cursor.fetchone()
            assert row is not None
            return execution_dispatch(scope, row, context, budget)
