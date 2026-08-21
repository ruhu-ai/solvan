"""Execution and independent-verification Runtime completion handlers."""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.persistence import (
    AggregateType,
    MitigationPolicyError,
    PendingRuntimeRun,
    PostgresMitigationPlanner,
    PostgresRuntimeRunStore,
    PostgresVerificationStore,
    PostgresWorkflowStore,
    TransitionWrite,
)
from solvan.platform.agent_runtime import (
    GeminiAgentRuntime,
)


def _poll_execution_run(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    runtime: GeminiAgentRuntime,
    run: PendingRuntimeRun,
    connection: Connection[Any],
) -> None:
    if run.incident_id is None:
        return
    terminal_error: str | None = None
    provider_output = b""
    if run.deadline <= datetime.now(UTC):
        with suppress(Exception):
            runtime.cancel(
                agent_resource=run.agent_resource,
                operation_name=run.runtime_operation_name,
            )
        terminal_error = "RUNTIME_DEADLINE_EXCEEDED"
    else:
        try:
            check = runtime.check(run.runtime_operation_name)
        except Exception:
            return
        if check.result is not None:
            provider_output = check.result.encode()
        if check.status == "RUNNING":
            return
        if check.status == "FAILED":
            terminal_error = "AGENT_RUNTIME_QUERY_FAILED"

    with workflow.transaction():
        outcome = runs.execution_outcome(scope=settings.scope, run=run)
    with workflow.transaction():
        lease = workflow.acquire_lease(
            scope=settings.scope,
            aggregate_type=AggregateType.INCIDENT,
            entity_id=run.incident_id,
            owner=owner,
            lease_ttl_ms=60_000,
        )
    if lease is None:
        return
    if lease.workflow_version != run.workflow_version:
        with workflow.transaction():
            workflow.release_lease(scope=settings.scope, lease=lease)
        return
    with workflow.transaction(), connection.cursor() as cursor:
        if outcome.receipt_id is not None and outcome.receipt_result is not None:
            output_hash = (
                f"sha256:{hashlib.sha256(provider_output).hexdigest()}"
                if provider_output
                else f"sha256:{hashlib.sha256(outcome.receipt_id.encode()).hexdigest()}"
            )
            runs.complete_execution(
                scope=settings.scope,
                run=run,
                output_hash=output_hash,
                outcome=outcome,
            )
            to_state, event, reason = {
                "SUCCEEDED": (
                    "VERIFYING_MITIGATION",
                    "MUTATION_RECONCILED",
                    "CONCLUSIVE_EXECUTION_RECEIPT",
                ),
                "FAILED": (
                    "MITIGATION_PROPOSED",
                    "MUTATION_FAILED_RETRYABLE",
                    "NO_EFFECT_CONFIRMED",
                ),
                "AMBIGUOUS": (
                    "ESCALATED",
                    "MUTATION_AMBIGUOUS",
                    "RECONCILIATION_INCONCLUSIVE",
                ),
            }[outcome.receipt_result]
            workflow.commit_transition(
                scope=settings.scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="MITIGATING",
                    to_state=to_state,
                    transition_key=f"{event}:{outcome.action_id}:{outcome.receipt_id}",
                    actor_type="AGENT",
                    actor_id="execution-agent",
                    reason_code=reason,
                    rationale_summary=(
                        "Workflow progression is derived from the durable actuator "
                        "receipt, not the Execution Agent model output."
                    ),
                    evidence_refs=(f"db://solvan/execution-receipts/{outcome.receipt_id}",),
                    trace_id=None,
                ),
            )
        else:
            if terminal_error is None:
                # A successful model response without a connector receipt means
                # the required tool did not produce an authoritative effect.
                terminal_error = "EXECUTION_RECEIPT_MISSING"
            runs.fail(scope=settings.scope, run=run, error_class=terminal_error)
            cursor.execute(
                """UPDATE solvan.actions SET status = 'AMBIGUOUS'
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(action_id)s
                    AND status IN ('AUTHORIZED','EXECUTING')""",
                {**settings.scope.canonical_dict(), "action_id": outcome.action_id},
            )
            workflow.commit_transition(
                scope=settings.scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="MITIGATING",
                    to_state="ESCALATED",
                    transition_key=f"MUTATION_AMBIGUOUS:{outcome.action_id}:{run.run_id}",
                    actor_type="COORDINATOR",
                    actor_id=owner,
                    reason_code=terminal_error,
                    rationale_summary=(
                        "Execution ended without an authoritative receipt; effect "
                        "status is unknown and blind retry is forbidden."
                    ),
                ),
            )
        workflow.release_lease(scope=settings.scope, lease=lease)


def _poll_verification_run(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    runtime: GeminiAgentRuntime,
    run: PendingRuntimeRun,
    connection: Connection[Any],
) -> None:
    if run.incident_id is None:
        return
    terminal_error: str | None = None
    provider_output = b""
    if run.deadline <= datetime.now(UTC):
        with suppress(Exception):
            runtime.cancel(
                agent_resource=run.agent_resource,
                operation_name=run.runtime_operation_name,
            )
        terminal_error = "RUNTIME_DEADLINE_EXCEEDED"
    else:
        try:
            check = runtime.check(run.runtime_operation_name)
        except Exception:
            return
        if check.result is not None:
            provider_output = check.result.encode()
        if check.status == "RUNNING":
            return
        if check.status == "FAILED":
            terminal_error = "AGENT_RUNTIME_QUERY_FAILED"
    if run.action_id is None:
        return
    verification_store = PostgresVerificationStore(connection)
    with workflow.transaction():
        result = verification_store.result_for_run(
            scope=settings.scope,
            run_id=run.run_id,
            action_id=run.action_id,
        )
    with workflow.transaction():
        lease = workflow.acquire_lease(
            scope=settings.scope,
            aggregate_type=AggregateType.INCIDENT,
            entity_id=run.incident_id,
            owner=owner,
            lease_ttl_ms=60_000,
        )
    if lease is None:
        return
    if lease.workflow_version != run.workflow_version:
        with workflow.transaction():
            workflow.release_lease(scope=settings.scope, lease=lease)
        return
    with workflow.transaction():
        if result is not None:
            verification_id, verdict = result
            output_hash = (
                f"sha256:{hashlib.sha256(provider_output).hexdigest()}"
                if provider_output
                else f"sha256:{hashlib.sha256(verification_id.encode()).hexdigest()}"
            )
            runs.complete_verification(
                scope=settings.scope,
                run=run,
                verification_id=verification_id,
                output_hash=output_hash,
            )
            if verdict == "VERIFIED":
                to_state = "MITIGATED"
                event = "VERIFICATION_PASSED"
                reason = "EXACT_BOUND_PROFILE_PASSED"
                workflow.commit_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="VERIFYING_MITIGATION",
                        to_state=to_state,
                        transition_key=f"{event}:{run.action_id}:{verification_id}",
                        actor_type="AGENT",
                        actor_id="verification-agent",
                        reason_code=reason,
                        rationale_summary=(
                            "Workflow progression uses the independent verifier row; "
                            "the model cannot calculate or choose the verdict."
                        ),
                        evidence_refs=(f"db://solvan/verification-runs/{verification_id}",),
                    ),
                )
            else:
                # One pool recycle is the complete autonomous budget. Partial
                # recovery may only produce the exact graph-bound rollback for a
                # separate human approval; it never authorizes a blind retry.
                try:
                    PostgresMitigationPlanner(connection).plan_approval_bound_rollback(
                        scope=settings.scope,
                        lease=lease,
                        failed_action_id=run.action_id,
                        verification_id=verification_id,
                        actor_id="coordinator:deterministic-rollback-policy",
                    )
                except MitigationPolicyError as error:
                    workflow.commit_transition(
                        scope=settings.scope,
                        lease=lease,
                        transition=TransitionWrite(
                            from_state="VERIFYING_MITIGATION",
                            to_state="ESCALATED",
                            transition_key=(
                                f"VERIFICATION_EXHAUSTED:{run.action_id}:{verification_id}"
                            ),
                            actor_type="COORDINATOR",
                            actor_id=owner,
                            reason_code=type(error).__name__,
                            rationale_summary=(
                                "Independent verification did not pass and no exact "
                                "approved fallback could be constructed."
                            ),
                            evidence_refs=(f"db://solvan/verification-runs/{verification_id}",),
                        ),
                    )
        else:
            runs.fail(
                scope=settings.scope,
                run=run,
                error_class=terminal_error or "VERIFICATION_RESULT_MISSING",
            )
            workflow.commit_transition(
                scope=settings.scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="VERIFYING_MITIGATION",
                    to_state="ESCALATED",
                    transition_key=f"VERIFICATION_EXHAUSTED:{run.action_id}:{run.run_id}",
                    actor_type="COORDINATOR",
                    actor_id=owner,
                    reason_code=terminal_error or "VERIFICATION_RESULT_MISSING",
                    rationale_summary=(
                        "Verification ended without an authoritative result; "
                        "recovery cannot be claimed."
                    ),
                ),
            )
        workflow.release_lease(scope=settings.scope, lease=lease)
