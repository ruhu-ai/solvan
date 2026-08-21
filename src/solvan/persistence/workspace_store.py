"""Durable logical workspace lifecycle and provider-attempt fencing."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import (
    RuntimeInvocationReceipt,
    WorkspaceCheckpoint,
    WorkspaceCheckpointMaterial,
    WorkspaceRef,
    WorkspaceSpec,
    WorkspaceStatus,
    WorkspaceTaskInvocation,
    WorkspaceTaskResult,
    WorkspaceTerminalStatus,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.workspace_lineage import WorkspaceLineageMixin
from solvan.persistence.workspace_projection import (
    matches_workspace_invocation,
    matches_workspace_ref,
    matches_workspace_spec,
    project_workspace_checkpoint,
    project_workspace_ref,
    select_workspace_row,
)
from solvan.persistence.workspace_provider_results import (
    WorkspaceConflict,
    WorkspaceProviderResultMixin,
)


class PostgresWorkspaceStore(WorkspaceProviderResultMixin, WorkspaceLineageMixin):
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def open(self, spec: WorkspaceSpec) -> WorkspaceRef:
        values = {
            **spec.scope.canonical_dict(),
            **spec.model_dump(mode="python", exclude={"scope"}),
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """SELECT 1 FROM solvan.policy_decisions
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(provider_eligibility_decision_id)s
                    AND policy_kind = 'PROVIDER_ELIGIBILITY'
                    AND decision = 'ALLOW' FOR SHARE""",
                values,
            )
            if cursor.fetchone() is None:
                raise WorkspaceConflict("workspace requires a durable provider ALLOW decision")
            cursor.execute(
                """INSERT INTO solvan.workspaces
                  (organization_id, project_id, environment_id, id, kind, service_id,
                   reliability_case_id, generation, provider, implementation_sdk,
                   implementation_sdk_version, provider_revision, registry_agent_key,
                   provider_agent_resource, provider_service_identity,
                   implementation_sdk_distribution_hash, provider_artifact_digest,
                   effective_network_policy_hash, classification, synthetic,
                   synthetic_attestation_ref, synthetic_attestation_hash,
                   provider_eligibility_decision_id, artifact_prefix,
                   input_manifest_ref, input_manifest_hash, status,
                   created_by_principal)
                  VALUES
                  (%(organization_id)s, %(project_id)s, %(environment_id)s,
                   %(workspace_id)s, %(kind)s, %(service_id)s,
                   %(reliability_case_id)s, 1, %(provider)s, %(implementation_sdk)s,
                   %(implementation_sdk_version)s, %(provider_revision)s,
                   %(registry_agent_key)s, %(provider_agent_resource)s,
                   %(provider_service_identity)s,
                   %(implementation_sdk_distribution_hash)s,
                   %(provider_artifact_digest)s, %(effective_network_policy_hash)s,
                   %(classification)s, %(synthetic)s, %(synthetic_attestation_ref)s,
                   %(synthetic_attestation_hash)s,
                   %(provider_eligibility_decision_id)s, %(artifact_prefix)s,
                   %(input_manifest_ref)s, %(input_manifest_hash)s, 'OPEN',
                   %(created_by_principal)s)
                  ON CONFLICT DO NOTHING RETURNING *""",
                values,
            )
            row = cursor.fetchone()
            if row is None:
                row = select_workspace_row(cursor, spec.scope, spec.workspace_id, for_update=True)
                if row is None or not matches_workspace_spec(row, spec):
                    raise WorkspaceConflict("workspace identifier or active case already conflicts")
            return project_workspace_ref(row, spec.scope)

    def load(self, *, scope: Scope, workspace_id: str) -> WorkspaceRef:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            row = select_workspace_row(cursor, scope, workspace_id, for_update=False)
        if row is None:
            raise WorkspaceConflict("workspace does not exist")
        return project_workspace_ref(row, scope)

    def active_for_case(self, *, scope: Scope, case_id: str) -> WorkspaceRef | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan.workspaces
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND reliability_case_id = %(case_id)s
                    AND kind = 'INCIDENT'
                    AND status IN ('OPEN','HIBERNATED','BLOCKED')
                  ORDER BY created_at DESC LIMIT 2""",
                {**scope.canonical_dict(), "case_id": case_id},
            )
            rows = cursor.fetchall()
        if len(rows) > 1:
            raise WorkspaceConflict("case has more than one active workspace")
        return None if not rows else project_workspace_ref(rows[0], scope)

    def record_provider_eligibility(
        self,
        *,
        scope: Scope,
        decision_id: str,
        policy_version: str,
        input_ref: str,
        input_hash: str,
        decision: str,
        reason_code: str,
        receipt_ref: str,
        receipt_hash: str,
    ) -> None:
        if decision not in {"ALLOW", "DENY"}:
            raise ValueError("provider eligibility decision must be ALLOW or DENY")
        values = {
            **scope.canonical_dict(),
            "decision_id": decision_id,
            "policy_version": policy_version,
            "input_ref": input_ref,
            "input_hash": input_hash,
            "decision": decision,
            "reason_code": reason_code,
            "receipt_ref": receipt_ref,
            "receipt_hash": receipt_hash,
        }
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.policy_decisions
                  (organization_id, project_id, environment_id, id, policy_kind,
                   policy_version, input_ref, input_hash, decision, reason_code,
                   receipt_ref, receipt_hash)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                   %(decision_id)s, 'PROVIDER_ELIGIBILITY', %(policy_version)s,
                   %(input_ref)s, %(input_hash)s, %(decision)s, %(reason_code)s,
                   %(receipt_ref)s, %(receipt_hash)s)
                  ON CONFLICT DO NOTHING""",
                values,
            )
            if cursor.rowcount == 1:
                return
            cursor.execute(
                """SELECT policy_version, input_ref, input_hash, decision,
                    reason_code, receipt_ref, receipt_hash
                  FROM solvan.policy_decisions
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(decision_id)s AND policy_kind = 'PROVIDER_ELIGIBILITY'""",
                values,
            )
            row = cursor.fetchone()
            expected = (
                policy_version,
                input_ref,
                input_hash,
                decision,
                reason_code,
                receipt_ref,
                receipt_hash,
            )
            if row is None or tuple(row) != expected:
                raise WorkspaceConflict("provider eligibility decision identifier conflicts")

    def create_task(self, invocation: WorkspaceTaskInvocation) -> None:
        scope = invocation.scope
        values = {
            **scope.canonical_dict(),
            **invocation.model_dump(mode="python", exclude={"scope", "input_materials"}),
            "budget_json": Jsonb(invocation.budget.model_dump(mode="json")),
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, logical_step_key,
                   agent_key, agent_resource, agent_revision, invocation_id,
                   workspace_id, workspace_generation, workspace_task_kind,
                   provider_request_id, provider_request_hash,
                   implementation_sdk_distribution_hash, provider_artifact_digest,
                   effective_tool_set_hash, effective_network_policy_hash,
                   workflow_version, attempt, status, deadline, budget_json,
                   input_ref, input_hash, trace_id, span_id)
                  SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                   %(run_id)s, %(logical_step_key)s, 'workspace-agent',
                   %(provider_resource)s, %(provider_revision)s, %(invocation_id)s,
                   %(workspace_id)s, %(workspace_generation)s, %(task_kind)s,
                   %(request_id)s, %(request_hash)s,
                   %(implementation_sdk_distribution_hash)s,
                   %(provider_artifact_digest)s,
                   %(effective_tool_set_hash)s, %(effective_network_policy_hash)s,
                   %(workflow_version)s,
                   %(attempt)s, 'CREATED', %(deadline)s, %(budget_json)s,
                   %(input_manifest_ref)s, %(input_manifest_hash)s,
                   %(trace_id)s, %(span_id)s
                  FROM solvan.workspaces w
                  WHERE w.organization_id = %(organization_id)s
                    AND w.project_id = %(project_id)s
                    AND w.environment_id = %(environment_id)s
                    AND w.id = %(workspace_id)s
                    AND w.generation = %(workspace_generation)s
                    AND w.provider = %(provider)s
                    AND w.provider_revision = %(provider_revision)s
                    AND w.implementation_sdk_distribution_hash =
                        %(implementation_sdk_distribution_hash)s
                    AND w.provider_artifact_digest = %(provider_artifact_digest)s
                    AND w.input_manifest_hash = %(input_manifest_hash)s
                    AND w.status = 'OPEN'
                  ON CONFLICT DO NOTHING RETURNING id""",
                values,
            )
            created = cursor.fetchone()
            if created is not None:
                return
            cursor.execute(
                """SELECT id, invocation_id, provider_request_id,
                    provider_request_hash, workspace_id, workspace_generation,
                    implementation_sdk_distribution_hash, provider_artifact_digest,
                    workflow_version, attempt, status
                  FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND (id = %(run_id)s OR invocation_id = %(invocation_id)s OR
                      (logical_step_key = %(logical_step_key)s AND attempt = %(attempt)s))
                  ORDER BY id LIMIT 2""",
                values,
            )
            rows = cursor.fetchall()
            if len(rows) != 1 or not matches_workspace_invocation(rows[0], invocation):
                raise WorkspaceConflict("workspace run conflicts or workspace is not dispatchable")

    def mark_dispatched(self, invocation: WorkspaceTaskInvocation) -> None:
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'DISPATCHED', started_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND provider_request_id = %(request_id)s
                    AND provider_request_hash = %(request_hash)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                    AND workflow_version = %(workflow_version)s
                    AND agent_revision = %(provider_revision)s
                    AND status = 'CREATED'""",
                {**invocation.scope.canonical_dict(), **invocation.model_dump(mode="python")},
            )
            if cursor.rowcount != 1:
                cursor.execute(
                    """SELECT status FROM solvan.agent_runs
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                        AND provider_request_id = %(request_id)s
                        AND provider_request_hash = %(request_hash)s
                        AND workspace_id = %(workspace_id)s
                        AND workspace_generation = %(workspace_generation)s
                        AND workflow_version = %(workflow_version)s
                        AND agent_revision = %(provider_revision)s""",
                    {**invocation.scope.canonical_dict(), **invocation.model_dump(mode="python")},
                )
                row = cursor.fetchone()
                if row is None or str(row[0]) not in {"DISPATCHED", "RUNNING"}:
                    raise WorkspaceConflict("workspace dispatch attempt is stale")

    def record_runtime_dispatch(
        self,
        invocation: WorkspaceTaskInvocation,
        receipt: RuntimeInvocationReceipt,
    ) -> None:
        if (
            not receipt.runtime_operation_name
            or not receipt.runtime_input_ref
            or not receipt.runtime_output_ref
        ):
            raise ValueError("workspace Runtime dispatch receipt is incomplete")
        values = {
            **invocation.scope.canonical_dict(),
            **invocation.model_dump(mode="python"),
            "operation": receipt.runtime_operation_name,
            "runtime_input_ref": receipt.runtime_input_ref,
            "runtime_output_ref": receipt.runtime_output_ref,
        }
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'DISPATCHED',
                    runtime_operation_name = %(operation)s,
                    runtime_input_ref = %(runtime_input_ref)s,
                    runtime_output_ref = %(runtime_output_ref)s, started_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND provider_request_id = %(request_id)s
                    AND provider_request_hash = %(request_hash)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                    AND workflow_version = %(workflow_version)s
                    AND agent_revision = %(provider_revision)s
                    AND status = 'CREATED'""",
                values,
            )
            if cursor.rowcount != 1:
                raise WorkspaceConflict("workspace Runtime dispatch attempt is stale")

    def complete_task(
        self,
        *,
        invocation: WorkspaceTaskInvocation,
        result: WorkspaceTaskResult,
    ) -> None:
        result.assert_matches(invocation)
        run_status = (
            "SUCCEEDED" if result.terminal_status is WorkspaceTerminalStatus.SUCCEEDED else "FAILED"
        )
        error_class = (
            None if run_status == "SUCCEEDED" else f"WORKSPACE_{result.terminal_status.value}"
        )
        values = {
            **invocation.scope.canonical_dict(),
            **invocation.model_dump(mode="python"),
            "run_status": run_status,
            "error_class": error_class,
            "output_ref": result.output_ref,
            "output_hash": result.output_hash,
            "provider_boot_hash": result.provider_boot_hash,
            "provider_service_revision": result.provider_service_revision,
            "completed_at": result.completed_at,
        }
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = %(run_status)s,
                    output_ref = %(output_ref)s, output_hash = %(output_hash)s,
                    provider_boot_hash = %(provider_boot_hash)s,
                    provider_service_revision = %(provider_service_revision)s,
                    error_class = %(error_class)s, completed_at = %(completed_at)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND provider_request_id = %(request_id)s
                    AND provider_request_hash = %(request_hash)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                    AND workflow_version = %(workflow_version)s
                    AND agent_revision = %(provider_revision)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                values,
            )
            if cursor.rowcount != 1:
                cursor.execute(
                    """SELECT status, output_ref, output_hash, provider_boot_hash,
                        provider_service_revision
                      FROM solvan.agent_runs
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                        AND provider_request_id = %(request_id)s
                        AND provider_request_hash = %(request_hash)s
                        AND workspace_id = %(workspace_id)s
                        AND workspace_generation = %(workspace_generation)s
                        AND workflow_version = %(workflow_version)s
                        AND agent_revision = %(provider_revision)s""",
                    values,
                )
                row = cursor.fetchone()
                expected = (
                    run_status,
                    result.output_ref,
                    result.output_hash,
                    result.provider_boot_hash,
                    result.provider_service_revision,
                )
                if row is None or tuple(row) != expected:
                    raise WorkspaceConflict("workspace completion attempt is stale")

    def fail_task(self, invocation: WorkspaceTaskInvocation, *, error_class: str) -> None:
        if not error_class or len(error_class) > 128:
            raise ValueError("workspace error class must contain at most 128 characters")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'FAILED',
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND provider_request_id = %(request_id)s
                    AND provider_request_hash = %(request_hash)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                    AND workflow_version = %(workflow_version)s
                    AND status IN ('CREATED','DISPATCHED','RUNNING')""",
                {
                    **invocation.scope.canonical_dict(),
                    **invocation.model_dump(mode="python"),
                    "error_class": error_class,
                },
            )
            if cursor.rowcount != 1:
                raise WorkspaceConflict("workspace failure attempt is stale")

    def checkpoint(
        self,
        ref: WorkspaceRef,
        material: WorkspaceCheckpointMaterial,
        *,
        hibernate: bool = False,
    ) -> WorkspaceCheckpoint:
        expected_status = WorkspaceStatus.OPEN
        target_status = WorkspaceStatus.HIBERNATED if hibernate else None
        return self._append_checkpoint(
            ref,
            material,
            event_kind="CHECKPOINT",
            parent_checkpoint_id=None,
            expected_statuses=(expected_status,),
            target_status=target_status,
        )

    def resume(
        self,
        checkpoint: WorkspaceCheckpoint,
        material: WorkspaceCheckpointMaterial,
    ) -> WorkspaceRef:
        ref = self.load(scope=checkpoint.scope, workspace_id=checkpoint.workspace_id)
        self._append_checkpoint(
            ref,
            material,
            event_kind="REHYDRATION",
            parent_checkpoint_id=checkpoint.checkpoint_id,
            expected_statuses=(WorkspaceStatus.HIBERNATED, WorkspaceStatus.BLOCKED),
            target_status=WorkspaceStatus.OPEN,
        )
        return self.load(scope=checkpoint.scope, workspace_id=checkpoint.workspace_id)

    def close(self, ref: WorkspaceRef) -> None:
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.workspaces SET status = 'CLOSED', updated_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(workspace_id)s AND generation = %(generation)s
                    AND provider = %(provider)s
                    AND provider_revision = %(provider_revision)s
                    AND status IN ('OPEN','HIBERNATED','BLOCKED')""",
                {**ref.scope.canonical_dict(), **ref.model_dump(mode="python", exclude={"scope"})},
            )
            if cursor.rowcount != 1:
                raise WorkspaceConflict("workspace close reference is stale")

    def _append_checkpoint(
        self,
        ref: WorkspaceRef,
        material: WorkspaceCheckpointMaterial,
        *,
        event_kind: str,
        parent_checkpoint_id: str | None,
        expected_statuses: tuple[WorkspaceStatus, ...],
        target_status: WorkspaceStatus | None,
    ) -> WorkspaceCheckpoint:
        checkpoint_id = new_identifier("wck")
        values = {
            **ref.scope.canonical_dict(),
            **ref.model_dump(mode="python", exclude={"scope"}),
            **material.model_dump(mode="python"),
            "checkpoint_id": checkpoint_id,
            "workspace_generation": ref.generation,
            "event_kind": event_kind,
            "parent_checkpoint_id": parent_checkpoint_id,
            "expected_statuses": [status.value for status in expected_statuses],
            "target_status": None if target_status is None else target_status.value,
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            row = select_workspace_row(cursor, ref.scope, ref.workspace_id, for_update=True)
            if row is None or not matches_workspace_ref(row, ref):
                raise WorkspaceConflict("workspace checkpoint reference is stale")
            if str(row["status"]) not in values["expected_statuses"]:
                raise WorkspaceConflict("workspace status does not permit this checkpoint event")
            cursor.execute(
                """SELECT coalesce(max(sequence_no), 0) + 1 AS sequence_no
                  FROM solvan.workspace_checkpoints
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s""",
                values,
            )
            sequence = cursor.fetchone()
            if sequence is None:
                raise RuntimeError("workspace checkpoint sequence allocation failed")
            values["sequence_no"] = int(sequence["sequence_no"])
            cursor.execute(
                """INSERT INTO solvan.workspace_checkpoints
                  (organization_id, project_id, environment_id, id, workspace_id,
                   workspace_generation, sequence_no, event_kind, parent_checkpoint_id,
                   provider, implementation_sdk, implementation_sdk_version,
                   implementation_sdk_distribution_hash, provider_artifact_digest,
                   provider_revision, provider_request_hash, provider_boot_hash,
                   provider_receipt_ref, provider_receipt_hash,
                   provider_service_revision, input_manifest_ref, input_manifest_hash,
                   artifact_manifest_ref, artifact_manifest_hash,
                   effective_tool_set_hash, effective_network_policy_hash,
                   created_by_principal)
                  VALUES
                  (%(organization_id)s, %(project_id)s, %(environment_id)s,
                   %(checkpoint_id)s, %(workspace_id)s, %(workspace_generation)s,
                   %(sequence_no)s, %(event_kind)s, %(parent_checkpoint_id)s,
                   %(provider)s, %(implementation_sdk)s,
                   %(implementation_sdk_version)s,
                   %(implementation_sdk_distribution_hash)s,
                   %(provider_artifact_digest)s, %(provider_revision)s,
                   %(provider_request_hash)s, %(provider_boot_hash)s,
                   %(provider_receipt_ref)s, %(provider_receipt_hash)s,
                   %(provider_service_revision)s, %(input_manifest_ref)s,
                   %(input_manifest_hash)s, %(artifact_manifest_ref)s,
                   %(artifact_manifest_hash)s, %(effective_tool_set_hash)s,
                   %(effective_network_policy_hash)s, %(created_by_principal)s)
                  RETURNING *""",
                values,
            )
            checkpoint_row = cursor.fetchone()
            if checkpoint_row is None:
                raise RuntimeError("workspace checkpoint insert returned no row")
            if target_status is not None:
                cursor.execute(
                    """UPDATE solvan.workspaces SET status = %(target_status)s,
                        updated_at = now()
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(workspace_id)s AND generation = %(generation)s
                        AND status = ANY(%(expected_statuses)s)""",
                    values,
                )
                if cursor.rowcount != 1:
                    raise WorkspaceConflict("workspace status changed during checkpoint")
            else:
                cursor.execute(
                    """UPDATE solvan.workspaces SET updated_at = now()
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(workspace_id)s AND generation = %(generation)s""",
                    values,
                )
            return project_workspace_checkpoint(checkpoint_row, ref.scope)
