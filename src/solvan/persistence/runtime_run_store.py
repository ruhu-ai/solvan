"""Durable supervisor dispatch and Agent Runtime operation polling records."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application import (
    AgentRunMaterial,
    PartialRuntimeInvocationReceipt,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
)
from solvan.application.default_tool_catalog import AGENT_PROFILE_KEYS
from solvan.domain import Scope
from solvan.persistence.investigation_dispatch import DISPATCH_RETRY_BACKOFF_MS
from solvan.persistence.runtime_queues import RuntimeQueueMixin
from solvan.persistence.runtime_reservations import RuntimeReservationMixin
from solvan.persistence.runtime_supervisor_reservation import (
    RuntimeSupervisorReservationMixin,
)
from solvan.persistence.runtime_types import (
    ExecutionReceiptOutcome,
    ExpiredCreatedRuntimeRun,
    PendingRuntimeRun,
    RuntimeRunConflict,
)

# Agent kinds whose CREATED attempts are recovered end-to-end by a different,
# provider-fenced path and must therefore not be swept twice. Workspace repair
# attempts are reserved against a workspace generation and a provider request
# hash; their recovery lives in the workspace store, not in the Runtime reaper.
_PROVIDER_OWNED_CREATED_RECOVERY: frozenset[str] = frozenset({"workspace-agent"})


def _created_recovery_agent_keys() -> tuple[str, ...]:
    """Derive the reaped agent kinds from the one registered agent catalog.

    A newly registered agent kind is swept by default. Omitting a kind requires
    naming a registered key in ``_PROVIDER_OWNED_CREATED_RECOVERY``, so a
    renamed or removed agent fails loudly here instead of silently stranding a
    reserved step whose incident would otherwise never progress again.
    """

    registered = frozenset(AGENT_PROFILE_KEYS)
    unknown = _PROVIDER_OWNED_CREATED_RECOVERY - registered
    if unknown:
        raise RuntimeError(
            "created Runtime recovery excludes unregistered agent keys: "
            + ", ".join(sorted(unknown))
        )
    return tuple(sorted(registered - _PROVIDER_OWNED_CREATED_RECOVERY))


CREATED_RECOVERY_AGENT_KEYS: tuple[str, ...] = _created_recovery_agent_keys()


class PostgresRuntimeRunStore(
    RuntimeQueueMixin,
    RuntimeReservationMixin,
    RuntimeSupervisorReservationMixin,
):
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def record_dispatch(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        receipt: RuntimeInvocationReceipt,
    ) -> None:
        if not (
            receipt.runtime_operation_name
            and receipt.runtime_input_ref
            and receipt.runtime_output_ref
        ):
            raise ValueError("complete Runtime dispatch receipt is required")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'DISPATCHED',
                    runtime_operation_name = %(operation)s,
                    runtime_input_ref = %(input_ref)s,
                    runtime_output_ref = %(output_ref)s, started_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED'
                    AND workflow_version = %(workflow_version)s
                    AND input_hash = %(input_hash)s""",
                {
                    **scope.canonical_dict(),
                    "run_id": dispatch.run_id,
                    "invocation_id": dispatch.invocation_id,
                    "workflow_version": dispatch.workflow_version,
                    "input_hash": dispatch.input_hash,
                    "operation": receipt.runtime_operation_name,
                    "input_ref": receipt.runtime_input_ref,
                    "output_ref": receipt.runtime_output_ref,
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("supervisor Runtime dispatch is stale")

    def record_partial_receipt(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        receipt: PartialRuntimeInvocationReceipt,
    ) -> None:
        """Preserve every returned provider field without completing acknowledgement."""

        if not any(
            (
                receipt.runtime_operation_name,
                receipt.runtime_input_ref,
                receipt.runtime_output_ref,
            )
        ):
            return
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET
                    runtime_operation_name = coalesce(runtime_operation_name, %(operation)s),
                    runtime_input_ref = coalesce(runtime_input_ref, %(input_ref)s),
                    runtime_output_ref = coalesce(runtime_output_ref, %(output_ref)s)
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED'
                    AND workflow_version = %(workflow_version)s
                    AND input_hash = %(input_hash)s
                    AND (%(operation)s::text IS NULL OR runtime_operation_name IS NULL
                         OR runtime_operation_name = %(operation)s)
                    AND (%(input_ref)s::text IS NULL OR runtime_input_ref IS NULL
                         OR runtime_input_ref = %(input_ref)s)
                    AND (%(output_ref)s::text IS NULL OR runtime_output_ref IS NULL
                         OR runtime_output_ref = %(output_ref)s)""",
                {
                    **scope.canonical_dict(),
                    "run_id": dispatch.run_id,
                    "invocation_id": dispatch.invocation_id,
                    "workflow_version": dispatch.workflow_version,
                    "input_hash": dispatch.input_hash,
                    "operation": receipt.runtime_operation_name,
                    "input_ref": receipt.runtime_input_ref,
                    "output_ref": receipt.runtime_output_ref,
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("partial Runtime receipt is stale or conflicts")

    def expired_created(
        self,
        *,
        scope: Scope,
        receipt_grace_seconds: int = 60,
        batch_size: int = 20,
    ) -> tuple[ExpiredCreatedRuntimeRun, ...]:
        if receipt_grace_seconds < 0 or batch_size < 1:
            raise ValueError("Runtime recovery bounds are invalid")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, invocation_id, incident_id, alert_episode_id,
                    action_id, agent_key,
                    agent_resource, workflow_version, runtime_operation_name,
                    runtime_input_ref, runtime_output_ref, input_hash, deadline
                  FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND agent_key = ANY(%(agent_keys)s)
                    AND status = 'CREATED'
                    AND deadline
                      + (%(receipt_grace_seconds)s * interval '1 second') <= now()
                  ORDER BY deadline, id LIMIT %(batch_size)s""",
                {
                    **scope.canonical_dict(),
                    "agent_keys": list(CREATED_RECOVERY_AGENT_KEYS),
                    "receipt_grace_seconds": receipt_grace_seconds,
                    "batch_size": batch_size,
                },
            )
            rows = cursor.fetchall()
        return tuple(
            ExpiredCreatedRuntimeRun(
                run_id=str(row["id"]),
                invocation_id=str(row["invocation_id"]),
                incident_id=(None if row["incident_id"] is None else str(row["incident_id"])),
                alert_episode_id=(
                    None if row["alert_episode_id"] is None else str(row["alert_episode_id"])
                ),
                action_id=None if row["action_id"] is None else str(row["action_id"]),
                agent_key=str(row["agent_key"]),
                agent_resource=str(row["agent_resource"]),
                workflow_version=int(row["workflow_version"]),
                runtime_operation_name=(
                    None
                    if row["runtime_operation_name"] is None
                    else str(row["runtime_operation_name"])
                ),
                runtime_input_ref=(
                    None if row["runtime_input_ref"] is None else str(row["runtime_input_ref"])
                ),
                runtime_output_ref=(
                    None if row["runtime_output_ref"] is None else str(row["runtime_output_ref"])
                ),
                input_hash=str(row["input_hash"]),
                deadline=row["deadline"],
            )
            for row in rows
        )

    def adopt_created_dispatch(
        self,
        *,
        scope: Scope,
        run: ExpiredCreatedRuntimeRun,
        runtime_output_ref: str,
    ) -> bool:
        if run.runtime_operation_name is None or not runtime_output_ref.startswith("gs://"):
            raise ValueError("adopted Runtime dispatch requires operation and GCS output")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'DISPATCHED',
                    runtime_output_ref = coalesce(runtime_output_ref, %(output_ref)s),
                    started_at = coalesce(started_at, now())
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED'
                    AND workflow_version = %(workflow_version)s
                    AND input_hash = %(input_hash)s
                    AND runtime_operation_name = %(operation)s
                    AND (runtime_output_ref IS NULL
                         OR runtime_output_ref = %(output_ref)s)""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "invocation_id": run.invocation_id,
                    "workflow_version": run.workflow_version,
                    "input_hash": run.input_hash,
                    "operation": run.runtime_operation_name,
                    "output_ref": runtime_output_ref,
                },
            )
            return cursor.rowcount == 1

    def expire_created(
        self,
        *,
        scope: Scope,
        run: ExpiredCreatedRuntimeRun,
        error_class: str,
    ) -> bool:
        if error_class not in {
            "DISPATCH_ACCEPTANCE_UNKNOWN",
            "DISPATCH_RECEIPT_INCOMPLETE",
            "DISPATCH_OUTPUT_INVALID",
        }:
            raise ValueError("created Runtime expiry error class is not allowed")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'TIMED_OUT',
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED'
                    AND workflow_version = %(workflow_version)s
                    AND input_hash = %(input_hash)s""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "invocation_id": run.invocation_id,
                    "workflow_version": run.workflow_version,
                    "input_hash": run.input_hash,
                    "error_class": error_class,
                },
            )
            if cursor.rowcount != 1:
                return False
            # An investigation step still points at the attempt that was just
            # fenced. Releasing it in the same transaction is what turns a lost
            # provider acknowledgement into recoverable work: without it the
            # step keeps current_agent_run_id and no later reservation, sweep,
            # or plan completion can ever observe the step again.
            cursor.execute(
                """UPDATE solvan.investigation_steps s SET
                    status = CASE
                      WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                        THEN 'READY'
                      ELSE 'FAILED'
                    END,
                    current_agent_run_id = CASE
                      WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                        THEN NULL
                      ELSE s.current_agent_run_id
                    END,
                    started_at = CASE
                      WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                        THEN NULL
                      ELSE s.started_at
                    END,
                    completed_at = CASE
                      WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                        THEN NULL
                      ELSE now()
                    END,
                    retry_not_before = CASE
                      WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                        THEN now() + (%(retry_backoff_ms)s * interval '1 millisecond')
                      ELSE s.retry_not_before
                    END,
                    result_ref = %(result_ref)s
                  FROM solvan.agent_runs r
                  WHERE s.organization_id = %(organization_id)s
                    AND s.project_id = %(project_id)s
                    AND s.environment_id = %(environment_id)s
                    AND s.current_agent_run_id = %(run_id)s
                    AND s.status IN ('READY','DISPATCHED','RUNNING')
                    AND r.organization_id = s.organization_id
                    AND r.project_id = s.project_id
                    AND r.environment_id = s.environment_id
                    AND r.id = %(run_id)s AND r.status = 'TIMED_OUT'""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "result_ref": f"runtime-error:{error_class}",
                    "retry_backoff_ms": DISPATCH_RETRY_BACKOFF_MS,
                },
            )
            return True

    def fail_created(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        error_class: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'FAILED',
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED'
                    AND workflow_version = %(workflow_version)s
                    AND input_hash = %(input_hash)s""",
                {
                    **scope.canonical_dict(),
                    "run_id": dispatch.run_id,
                    "invocation_id": dispatch.invocation_id,
                    "workflow_version": dispatch.workflow_version,
                    "input_hash": dispatch.input_hash,
                    "error_class": error_class[:128],
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("supervisor dispatch failure is stale")

    def pending(self, *, scope: Scope, batch_size: int = 20) -> tuple[PendingRuntimeRun, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id, r.incident_id, r.alert_episode_id,
                    coalesce(r.reliability_case_id, w.reliability_case_id)
                      AS reliability_case_id,
                    r.agent_key, r.agent_resource,
                    runtime_operation_name,
                    runtime_output_ref, deadline, workflow_version,
                    investigation_step_id, action_id, repair_plan_id
                  FROM solvan.agent_runs r
                  LEFT JOIN solvan.workspaces w
                    ON (w.organization_id, w.project_id, w.environment_id, w.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.workspace_id)
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.status IN ('DISPATCHED','RUNNING')
                    AND r.runtime_operation_name IS NOT NULL
                    AND r.runtime_output_ref IS NOT NULL
                  ORDER BY r.started_at NULLS FIRST LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            rows = cursor.fetchall()
        return tuple(
            PendingRuntimeRun(
                run_id=str(row["id"]),
                incident_id=None if row["incident_id"] is None else str(row["incident_id"]),
                alert_episode_id=(
                    None if row["alert_episode_id"] is None else str(row["alert_episode_id"])
                ),
                reliability_case_id=(
                    None if row["reliability_case_id"] is None else str(row["reliability_case_id"])
                ),
                agent_key=str(row["agent_key"]),
                agent_resource=str(row["agent_resource"]),
                runtime_operation_name=str(row["runtime_operation_name"]),
                runtime_output_ref=str(row["runtime_output_ref"]),
                deadline=row["deadline"],
                workflow_version=int(row["workflow_version"]),
                investigation_step_id=(
                    None
                    if row["investigation_step_id"] is None
                    else str(row["investigation_step_id"])
                ),
                action_id=None if row["action_id"] is None else str(row["action_id"]),
                repair_plan_id=(
                    None if row["repair_plan_id"] is None else str(row["repair_plan_id"])
                ),
            )
            for row in rows
        )

    def complete_supervisor(
        self,
        *,
        scope: Scope,
        run: PendingRuntimeRun,
        output_hash: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'SUCCEEDED',
                    output_ref = runtime_output_ref, output_hash = %(output_hash)s,
                    completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(run_id)s
                    AND runtime_operation_name = %(operation)s
                    AND agent_key = 'incident-supervisor'
                    AND investigation_step_id IS NULL
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "operation": run.runtime_operation_name,
                    "output_hash": output_hash,
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("supervisor completion is stale")

    def execution_outcome(self, *, scope: Scope, run: PendingRuntimeRun) -> ExecutionReceiptOutcome:
        if run.action_id is None or run.agent_key != "execution-agent":
            raise RuntimeRunConflict("run is not an Execution Agent attempt")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.id AS action_id, a.status AS action_status,
                    e.id AS receipt_id, e.result AS receipt_result
                  FROM solvan.agent_runs r
                  JOIN solvan.actions a
                    ON (a.organization_id, a.project_id, a.environment_id, a.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.action_id)
                  LEFT JOIN solvan.execution_receipts e
                    ON (e.organization_id, e.project_id, e.environment_id,
                        e.action_id)
                     = (a.organization_id, a.project_id, a.environment_id, a.id)
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.id = %(run_id)s AND r.action_id = %(action_id)s
                    AND r.runtime_operation_name = %(operation)s
                    AND r.status IN ('DISPATCHED','RUNNING')
                  ORDER BY e.attempt DESC NULLS LAST LIMIT 1""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "action_id": run.action_id,
                    "operation": run.runtime_operation_name,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeRunConflict("Execution Agent outcome is stale")
        return ExecutionReceiptOutcome(
            action_id=str(row["action_id"]),
            action_status=str(row["action_status"]),
            receipt_id=None if row["receipt_id"] is None else str(row["receipt_id"]),
            receipt_result=(None if row["receipt_result"] is None else str(row["receipt_result"])),
        )

    def complete_execution(
        self,
        *,
        scope: Scope,
        run: PendingRuntimeRun,
        output_hash: str,
        outcome: ExecutionReceiptOutcome,
    ) -> None:
        if outcome.receipt_id is None or outcome.receipt_result is None:
            raise RuntimeRunConflict("execution completion has no durable receipt")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'SUCCEEDED',
                    output_ref = %(output_ref)s, output_hash = %(output_hash)s,
                    completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND action_id = %(action_id)s
                    AND agent_key = 'execution-agent'
                    AND runtime_operation_name = %(operation)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "action_id": outcome.action_id,
                    "operation": run.runtime_operation_name,
                    "output_ref": f"db://solvan/execution-receipts/{outcome.receipt_id}",
                    "output_hash": output_hash,
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("Execution Agent completion is stale")

    def complete_verification(
        self,
        *,
        scope: Scope,
        run: PendingRuntimeRun,
        verification_id: str,
        output_hash: str,
    ) -> None:
        if run.action_id is None or run.agent_key != "verification-agent":
            raise RuntimeRunConflict("run is not a Verification Agent attempt")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'SUCCEEDED',
                    output_ref = %(output_ref)s, output_hash = %(output_hash)s,
                    completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND action_id = %(action_id)s
                    AND agent_key = 'verification-agent'
                    AND runtime_operation_name = %(operation)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "action_id": run.action_id,
                    "operation": run.runtime_operation_name,
                    "output_ref": f"db://solvan/verification-runs/{verification_id}",
                    "output_hash": output_hash,
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("Verification Agent completion is stale")

    def agent_material(self, *, scope: Scope, run: PendingRuntimeRun) -> AgentRunMaterial:
        if run.investigation_step_id is None:
            raise RuntimeRunConflict("supervisor run has no agent material")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT agent_resource, agent_revision, invocation_id, incident_id,
                    workflow_version, input_hash, runtime_output_ref, trace_id
                  FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(run_id)s
                    AND runtime_operation_name = %(operation)s
                    AND investigation_step_id = %(step_id)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "operation": run.runtime_operation_name,
                    "step_id": run.investigation_step_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeRunConflict("agent Runtime material is stale")
        return AgentRunMaterial(
            agent_resource=str(row["agent_resource"]),
            agent_revision=str(row["agent_revision"]),
            invocation_id=str(row["invocation_id"]),
            incident_id=str(row["incident_id"]),
            workflow_version=int(row["workflow_version"]),
            input_hash=str(row["input_hash"]),
            output_ref=str(row["runtime_output_ref"]),
            trace_id=str(row["trace_id"]),
        )

    def fail(self, *, scope: Scope, run: PendingRuntimeRun, error_class: str) -> None:
        with self._connection.cursor() as cursor:
            terminal_status = (
                "TIMED_OUT" if error_class == "RUNTIME_DEADLINE_EXCEEDED" else "FAILED"
            )
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = %(terminal_status)s,
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(run_id)s
                    AND runtime_operation_name = %(operation)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run.run_id,
                    "operation": run.runtime_operation_name,
                    "error_class": error_class[:128],
                    "terminal_status": terminal_status,
                },
            )
            if cursor.rowcount != 1:
                raise RuntimeRunConflict("Runtime failure is stale")
            if run.investigation_step_id is not None:
                cursor.execute(
                    """UPDATE solvan.investigation_steps s SET
                        status = CASE
                          WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                            THEN 'READY'
                          ELSE 'FAILED'
                        END,
                        current_agent_run_id = CASE
                          WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                            THEN NULL
                          ELSE s.current_agent_run_id
                        END,
                        started_at = CASE
                          WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                            THEN NULL
                          ELSE s.started_at
                        END,
                        completed_at = CASE
                          WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                            THEN NULL
                          ELSE now()
                        END,
                        retry_not_before = CASE
                          WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL
                            THEN now() + (%(retry_backoff_ms)s * interval '1 millisecond')
                          ELSE s.retry_not_before
                        END,
                        result_ref = %(result_ref)s
                      FROM solvan.agent_runs r
                      WHERE s.organization_id = %(organization_id)s
                        AND s.project_id = %(project_id)s
                        AND s.environment_id = %(environment_id)s
                        AND s.id = %(step_id)s AND s.current_agent_run_id = %(run_id)s
                        AND s.status IN ('DISPATCHED','RUNNING')
                        AND r.organization_id = s.organization_id
                        AND r.project_id = s.project_id
                        AND r.environment_id = s.environment_id
                        AND r.id = %(run_id)s""",
                    {
                        **scope.canonical_dict(),
                        "step_id": run.investigation_step_id,
                        "run_id": run.run_id,
                        "result_ref": f"runtime-error:{error_class[:128]}",
                        "retry_backoff_ms": DISPATCH_RETRY_BACKOFF_MS,
                    },
                )
