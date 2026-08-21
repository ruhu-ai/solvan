"""Durable Antigravity result fencing and security-event persistence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application import WorkspaceTaskInvocation, WorkspaceTaskResult
from solvan.domain import Scope, new_identifier


class WorkspaceConflict(RuntimeError):
    """A stale lifecycle reference or provider attempt tried to mutate state."""


@dataclass(frozen=True, slots=True)
class PendingWorkspaceProviderResult:
    run_id: str
    reliability_case_id: str
    workflow_version: int
    output_ref: str
    output_hash: str
    request_id: str
    request_hash: str
    invocation_id: str
    workspace_id: str
    workspace_generation: int
    provider_revision: str
    implementation_sdk_distribution_hash: str
    provider_artifact_digest: str
    input_manifest_hash: str
    effective_tool_set_hash: str
    effective_network_policy_hash: str
    provider_boot_hash: str
    provider_service_revision: str


class WorkspaceProviderResultMixin:
    _connection: Connection[Any]

    def pending_antigravity_results(
        self, *, scope: Scope, batch_size: int = 20
    ) -> tuple[PendingWorkspaceProviderResult, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id, w.reliability_case_id, r.workflow_version,
                    r.output_ref, r.output_hash, r.provider_request_id,
                    r.provider_request_hash, r.invocation_id, r.workspace_id,
                    r.workspace_generation, r.agent_revision, r.input_hash,
                    r.implementation_sdk_distribution_hash,
                    r.provider_artifact_digest,
                    r.effective_tool_set_hash, r.effective_network_policy_hash,
                    r.provider_boot_hash, r.provider_service_revision
                  FROM solvan.agent_runs r
                  JOIN solvan.workspaces w
                    ON (w.organization_id, w.project_id, w.environment_id, w.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.workspace_id)
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND w.provider = 'ANTIGRAVITY_SDK_CLOUD_RUN'
                    AND r.status = 'RUNNING' AND r.output_ref IS NOT NULL
                    AND r.output_hash IS NOT NULL AND r.provider_boot_hash IS NOT NULL
                    AND r.provider_service_revision IS NOT NULL
                  ORDER BY r.started_at, r.id LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            rows = cursor.fetchall()
        return tuple(self._pending_result(row) for row in rows)

    @staticmethod
    def _pending_result(row: dict[str, Any]) -> PendingWorkspaceProviderResult:
        return PendingWorkspaceProviderResult(
            run_id=str(row["id"]),
            reliability_case_id=str(row["reliability_case_id"]),
            workflow_version=int(row["workflow_version"]),
            output_ref=str(row["output_ref"]),
            output_hash=str(row["output_hash"]),
            request_id=str(row["provider_request_id"]),
            request_hash=str(row["provider_request_hash"]),
            invocation_id=str(row["invocation_id"]),
            workspace_id=str(row["workspace_id"]),
            workspace_generation=int(row["workspace_generation"]),
            provider_revision=str(row["agent_revision"]),
            implementation_sdk_distribution_hash=str(row["implementation_sdk_distribution_hash"]),
            provider_artifact_digest=str(row["provider_artifact_digest"]),
            input_manifest_hash=str(row["input_hash"]),
            effective_tool_set_hash=str(row["effective_tool_set_hash"]),
            effective_network_policy_hash=str(row["effective_network_policy_hash"]),
            provider_boot_hash=str(row["provider_boot_hash"]),
            provider_service_revision=str(row["provider_service_revision"]),
        )

    @staticmethod
    def assert_pending_result_matches(
        pending: PendingWorkspaceProviderResult, result: WorkspaceTaskResult
    ) -> None:
        pairs = (
            (result.run_id, pending.run_id),
            (result.output_ref, pending.output_ref),
            (result.output_hash, pending.output_hash),
            (result.request_id, pending.request_id),
            (result.request_hash, pending.request_hash),
            (result.invocation_id, pending.invocation_id),
            (result.workspace_id, pending.workspace_id),
            (result.workspace_generation, pending.workspace_generation),
            (result.provider_revision, pending.provider_revision),
            (
                result.implementation_sdk_distribution_hash,
                pending.implementation_sdk_distribution_hash,
            ),
            (result.provider_artifact_digest, pending.provider_artifact_digest),
            (result.input_manifest_hash, pending.input_manifest_hash),
            (result.effective_tool_set_hash, pending.effective_tool_set_hash),
            (result.effective_network_policy_hash, pending.effective_network_policy_hash),
            (result.provider_boot_hash, pending.provider_boot_hash),
            (result.provider_service_revision, pending.provider_service_revision),
        )
        if any(actual != expected for actual, expected in pairs):
            raise WorkspaceConflict("persisted provider result does not match its run fence")

    def record_provider_result(
        self, *, invocation: WorkspaceTaskInvocation, result: WorkspaceTaskResult
    ) -> bool:
        """Accept a provider result once; return false for an exact replay."""

        result.assert_matches(invocation)
        values = {
            **invocation.scope.canonical_dict(),
            **invocation.model_dump(mode="python"),
            "output_ref": result.output_ref,
            "output_hash": result.output_hash,
            "provider_boot_hash": result.provider_boot_hash,
            "provider_service_revision": result.provider_service_revision,
        }
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'RUNNING',
                    output_ref = %(output_ref)s, output_hash = %(output_hash)s,
                    provider_boot_hash = %(provider_boot_hash)s,
                    provider_service_revision = %(provider_service_revision)s
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
                    AND implementation_sdk_distribution_hash =
                        %(implementation_sdk_distribution_hash)s
                    AND provider_artifact_digest = %(provider_artifact_digest)s
                    AND status = 'DISPATCHED'""",
                values,
            )
            if cursor.rowcount == 1:
                return True
            cursor.execute(
                """SELECT status, output_ref, output_hash, provider_boot_hash,
                    provider_service_revision FROM solvan.agent_runs
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
                "RUNNING",
                result.output_ref,
                result.output_hash,
                result.provider_boot_hash,
                result.provider_service_revision,
            )
            if row is None or tuple(row) != expected:
                raise WorkspaceConflict("workspace provider result is stale or replayed")
            return False

    def record_provider_security_event(
        self,
        invocation: WorkspaceTaskInvocation,
        *,
        event_type: str,
        safe_summary: str,
    ) -> None:
        if not event_type or len(event_type) > 128:
            raise ValueError("workspace security event type is invalid")
        self._record_security_event(
            scope=invocation.scope,
            event_type=event_type,
            actor=f"workspace-provider:{invocation.provider.value}",
            destination=invocation.provider_resource,
            summary=safe_summary,
            payload_hash=invocation.request_hash,
            policy_ref=invocation.effective_tool_set_hash,
            trace_id=invocation.trace_id,
        )

    def record_pending_result_security_event(
        self,
        *,
        scope: Scope,
        pending: PendingWorkspaceProviderResult,
        event_type: str,
        safe_summary: str,
    ) -> None:
        self._record_security_event(
            scope=scope,
            event_type=event_type,
            actor="workspace-provider:ANTIGRAVITY_SDK_CLOUD_RUN",
            destination=pending.output_ref,
            summary=safe_summary,
            payload_hash=pending.request_hash,
            policy_ref=None,
            trace_id=None,
        )

    def _record_security_event(
        self,
        *,
        scope: Scope,
        event_type: str,
        actor: str,
        destination: str,
        summary: str,
        payload_hash: str,
        policy_ref: str | None,
        trace_id: str | None,
    ) -> None:
        values = {
            **scope.canonical_dict(),
            "event_id": new_identifier("sec"),
            "event_type": event_type[:128],
            "actor": actor,
            "destination": destination,
            "summary": summary[:500],
            "payload_hash": payload_hash,
            "policy_ref": policy_ref,
            "trace_id": trace_id,
        }
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.security_events
                  (organization_id, project_id, environment_id, id, event_type,
                   control, severity, actor_principal, destination_ref,
                   safe_summary, payload_hash, policy_ref, trace_id)
                  SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(event_id)s, %(event_type)s, 'INPUT_VALIDATOR', 'HIGH',
                    %(actor)s, %(destination)s, %(summary)s, %(payload_hash)s,
                    %(policy_ref)s, %(trace_id)s WHERE NOT EXISTS (
                    SELECT 1 FROM solvan.security_events
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND event_type = %(event_type)s
                      AND payload_hash = %(payload_hash)s)""",
                values,
            )

    def fail_run_result(
        self, *, scope: Scope, run_id: str, workflow_version: int, error_class: str
    ) -> None:
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'FAILED',
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND workflow_version = %(workflow_version)s
                    AND agent_key = 'workspace-agent'
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run_id,
                    "workflow_version": workflow_version,
                    "error_class": error_class[:128],
                },
            )
            if cursor.rowcount != 1:
                raise WorkspaceConflict("workspace result failure is stale")
