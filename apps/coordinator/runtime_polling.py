"""Durable Agent Runtime polling and workspace-agent completion handlers."""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from apps.coordinator.action_polling import _poll_execution_run, _poll_verification_run
from apps.coordinator.alert_triage import (
    fail_expired_alert_created_run,
    poll_alert_triage_run,
)
from apps.coordinator.contracts import (
    CoordinatorSettings,
    _investigation_policy,
    _runtime,
)
from apps.coordinator.memory_context import EvidenceMemoryContextEnricher
from apps.coordinator.tool_binding import PostgresAgentRunBinder
from apps.coordinator.workspace_adjudication import poll_antigravity_workspace_results
from apps.coordinator.workspace_runtime_polling import poll_workspace_run
from solvan.agents.result_adapter import (
    AgentResultParseError,
    parse_runtime_agent_output,
    parse_supervisor_plan,
)
from solvan.application import (
    AgentResultConflict,
    AgentResultCoordinator,
    CoordinatorAuthority,
    InvestigationConflict,
    InvestigationCoordinator,
)
from solvan.domain import (
    new_identifier,
    validate_investigation_plan,
)
from solvan.persistence import (
    AggregateType,
    PendingRuntimeRun,
    PostgresInvestigationResultStore,
    PostgresInvestigationStore,
    PostgresRuntimeRunStore,
    PostgresWorkflowStore,
    RuntimeRunConflict,
    TransitionWrite,
)
from solvan.platform.agent_runtime import (
    GeminiAgentRuntime,
    structured_query_output,
)
from solvan.platform.evidence_objects import GcsEvidenceReader

_CREATED_RECEIPT_GRACE_SECONDS = 60


def _recover_expired_created_runs(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    connection: Connection[Any],
) -> None:
    """Fence prepared Runtime requests whose provider acknowledgement was lost."""

    runtime = _runtime(settings)
    with workflow.transaction():
        candidates = runs.expired_created(
            scope=settings.scope,
            receipt_grace_seconds=_CREATED_RECEIPT_GRACE_SECONDS,
        )
    for run in candidates:
        recovered_output_ref = run.runtime_output_ref
        recovery_error_class: str | None = None
        if run.runtime_operation_name is not None and recovered_output_ref is None:
            try:
                check = runtime.check(run.runtime_operation_name)
            except Exception:
                check = None
            if check is not None:
                recovered_output_ref = check.output_gcs_uri
        expected_output_ref = runtime.output_uri(scope=settings.scope, run_id=run.run_id)
        if recovered_output_ref is not None and recovered_output_ref != expected_output_ref:
            recovery_error_class = "DISPATCH_OUTPUT_INVALID"
        if (
            recovery_error_class is None
            and run.runtime_operation_name is not None
            and recovered_output_ref is not None
        ):
            with workflow.transaction():
                adopted = runs.adopt_created_dispatch(
                    scope=settings.scope,
                    run=run,
                    runtime_output_ref=recovered_output_ref,
                )
            if adopted:
                continue
        if run.runtime_operation_name is not None:
            with suppress(Exception):
                runtime.cancel(
                    agent_resource=run.agent_resource,
                    operation_name=run.runtime_operation_name,
                )

        if run.alert_episode_id is not None:
            fail_expired_alert_created_run(
                settings=settings,
                run_id=run.run_id,
                connection=connection,
                error_class=(recovery_error_class or "DISPATCH_ACCEPTANCE_UNKNOWN"),
            )
            continue
        if run.incident_id is None:
            continue

        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=settings.scope,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=run.incident_id,
                owner=owner,
                lease_ttl_ms=60_000,
            )
        if lease is None:
            continue
        try:
            with workflow.transaction(), connection.cursor() as cursor:
                error_class = recovery_error_class or (
                    "DISPATCH_RECEIPT_INCOMPLETE"
                    if any(
                        (
                            run.runtime_operation_name,
                            run.runtime_input_ref,
                            run.runtime_output_ref,
                        )
                    )
                    else "DISPATCH_ACCEPTANCE_UNKNOWN"
                )
                expired = runs.expire_created(
                    scope=settings.scope,
                    run=run,
                    error_class=error_class,
                )
                if not expired:
                    workflow.release_lease(scope=settings.scope, lease=lease)
                    continue
                cursor.execute(
                    """INSERT INTO solvan.security_events
                      (organization_id, project_id, environment_id, id, event_type,
                       control, severity, actor_principal, destination_ref,
                       incident_id, safe_summary)
                      VALUES (%(organization_id)s, %(project_id)s,
                        %(environment_id)s, %(event_id)s,
                        'RUNTIME_DISPATCH_ACCEPTANCE_UNKNOWN', 'INPUT_VALIDATOR',
                        'HIGH', %(actor)s, %(run_id)s, %(incident_id)s,
                        %(safe_summary)s)""",
                    {
                        **settings.scope.canonical_dict(),
                        "event_id": new_identifier("sec"),
                        "actor": owner,
                        "run_id": run.run_id,
                        "incident_id": run.incident_id,
                        "safe_summary": (
                            f"{run.agent_key} Runtime acknowledgement was not durable; "
                            "the expired run was fenced without assuming provider absence."
                        ),
                    },
                )
                state = workflow.incident_state_for_lease(scope=settings.scope, lease=lease)
                if lease.workflow_version != run.workflow_version:
                    workflow.release_lease(scope=settings.scope, lease=lease)
                    continue
                if run.agent_key == "execution-agent" and state == "MITIGATING":
                    if run.action_id is None:
                        raise RuntimeError("Execution recovery run has no action")
                    cursor.execute(
                        """UPDATE solvan.actions SET status = 'AMBIGUOUS'
                          WHERE organization_id = %(organization_id)s
                            AND project_id = %(project_id)s
                            AND environment_id = %(environment_id)s
                            AND id = %(action_id)s AND status = 'AUTHORIZED'""",
                        {**settings.scope.canonical_dict(), "action_id": run.action_id},
                    )
                    workflow.commit_transition(
                        scope=settings.scope,
                        lease=lease,
                        transition=TransitionWrite(
                            from_state="MITIGATING",
                            to_state="ESCALATED",
                            transition_key=(f"MUTATION_AMBIGUOUS:{run.action_id}:CREATED_REAPER"),
                            actor_type="COORDINATOR",
                            actor_id=owner,
                            reason_code="EXECUTION_RUNTIME_DISPATCH_AMBIGUOUS",
                            rationale_summary=(
                                "Execution Runtime acceptance could not be proven; "
                                "automatic retry is forbidden and the action is ambiguous."
                            ),
                        ),
                    )
                elif run.agent_key == "verification-agent" and state == "VERIFYING_MITIGATION":
                    workflow.commit_transition(
                        scope=settings.scope,
                        lease=lease,
                        transition=TransitionWrite(
                            from_state="VERIFYING_MITIGATION",
                            to_state="ESCALATED",
                            transition_key=(
                                f"VERIFICATION_EXHAUSTED:{run.action_id}:CREATED_REAPER"
                            ),
                            actor_type="COORDINATOR",
                            actor_id=owner,
                            reason_code="VERIFICATION_RUNTIME_DISPATCH_AMBIGUOUS",
                            rationale_summary=(
                                "Verification Runtime acceptance could not be proven; "
                                "recovery remains unverified and no retry was authorized."
                            ),
                        ),
                    )
                workflow.release_lease(scope=settings.scope, lease=lease)
        except Exception:
            with suppress(Exception), workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue


def _poll_runtime_runs(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
) -> None:
    poll_antigravity_workspace_results(
        settings=settings,
        owner=owner,
        workflow=workflow,
        connection=connection,
        reader=reader,
    )
    runtime = _runtime(settings)
    policy = _investigation_policy(settings)
    investigation_store = PostgresInvestigationStore(connection)
    result_store = PostgresInvestigationResultStore(connection)
    with workflow.transaction():
        pending = runs.pending(scope=settings.scope)
    for run in pending:
        if run.alert_episode_id is not None:
            poll_alert_triage_run(
                settings=settings,
                run=run,
                runtime=runtime,
                connection=connection,
            )
            continue
        if run.agent_key == "workspace-agent":
            poll_workspace_run(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
                reader=reader,
            )
            continue
        if run.agent_key == "execution-agent":
            _poll_execution_run(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
            )
            continue
        if run.incident_id is None:
            with workflow.transaction():
                runs.fail(
                    scope=settings.scope,
                    run=run,
                    error_class="INCIDENT_OWNER_MISSING",
                )
            continue
        if run.agent_key == "verification-agent":
            _poll_verification_run(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
            )
            continue
        if run.deadline <= datetime.now(UTC):
            with suppress(Exception):
                runtime.cancel(
                    agent_resource=run.agent_resource,
                    operation_name=run.runtime_operation_name,
                )
            _fail_and_dispatch_fallback(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
                error_class="RUNTIME_DEADLINE_EXCEEDED",
            )
            continue
        try:
            result = runtime.check(run.runtime_operation_name)
        except Exception:
            # A transient control-plane/read failure leaves the durable operation
            # pending for the next scheduled tick; the deadline remains authoritative.
            continue
        if result.status == "RUNNING":
            continue
        if result.status == "FAILED" or result.result is None:
            _fail_and_dispatch_fallback(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
                error_class="AGENT_RUNTIME_QUERY_FAILED",
            )
            continue
        provider_output = result.result.encode()
        try:
            raw = structured_query_output(result.result)
        except ValueError:
            _fail_and_dispatch_fallback(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
                error_class="INVALID_AGENT_OUTPUT",
            )
            continue
        accepted_plan = None
        completion = None
        try:
            proposal = (
                parse_supervisor_plan(raw, policy=policy)
                if run.agent_key == "incident-supervisor"
                else None
            )
            if proposal is not None:
                accepted_plan = validate_investigation_plan(proposal, policy)
            else:
                with workflow.transaction():
                    material = runs.agent_material(scope=settings.scope, run=run)
                completion = parse_runtime_agent_output(
                    raw, material=material, provider_output=provider_output
                )
        except RuntimeRunConflict:
            # The attempt left DISPATCHED/RUNNING while this tick was reading
            # the provider: a concurrent tick already settled it. Failing it
            # here would overwrite that settlement, so skip only this run.
            continue
        except (ValueError, AgentResultParseError):
            _fail_and_dispatch_fallback(
                settings=settings,
                owner=owner,
                workflow=workflow,
                runs=runs,
                runtime=runtime,
                run=run,
                connection=connection,
                error_class="INVALID_AGENT_OUTPUT",
            )
            continue
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=settings.scope,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=run.incident_id,
                owner=owner,
                lease_ttl_ms=60_000,
            )
        if lease is None:
            continue
        if lease.workflow_version != run.workflow_version:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        authority = CoordinatorAuthority(owner, lease.token, lease.workflow_version)
        try:
            if proposal is not None:
                assert accepted_plan is not None
                digest = f"sha256:{hashlib.sha256(provider_output).hexdigest()}"
                with workflow.transaction():
                    runs.complete_supervisor(scope=settings.scope, run=run, output_hash=digest)
                    investigation_store.persist_accepted_plan(
                        scope=settings.scope,
                        incident_id=run.incident_id,
                        supervisor_run_id=run.run_id,
                        authority=authority,
                        plan=accepted_plan,
                    )
            else:
                assert completion is not None
                AgentResultCoordinator(result_store).complete(
                    scope=settings.scope,
                    authority=authority,
                    completion=completion,
                )
            InvestigationCoordinator(
                investigation_store,
                runtime,
                PostgresAgentRunBinder(
                    region=settings.gcp_region,
                    bindings=settings.governed_agent_bindings,
                    connection=connection,
                ),
                EvidenceMemoryContextEnricher(settings=settings, connection=connection),
            ).dispatch_ready_steps(
                scope=settings.scope,
                incident_id=run.incident_id,
                authority=authority,
            )
        except (AgentResultConflict, InvestigationConflict, RuntimeRunConflict):
            # A concurrent tick committed this same completion first. Its
            # transaction already rolled back here, so the durable record is
            # untouched; skip this run instead of aborting every later run,
            # sweep, and case handler in the tick.
            continue
        finally:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)


def _fail_and_dispatch_fallback(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    runtime: GeminiAgentRuntime,
    run: PendingRuntimeRun,
    connection: Connection[Any],
    error_class: str,
) -> None:
    """Persist one terminal attempt and launch only its policy-declared fallback."""

    with workflow.transaction():
        runs.fail(scope=settings.scope, run=run, error_class=error_class)
    if run.incident_id is None or run.investigation_step_id is None:
        return
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
    try:
        if lease.workflow_version != run.workflow_version:
            return
        InvestigationCoordinator(
            PostgresInvestigationStore(connection),
            runtime,
            PostgresAgentRunBinder(
                region=settings.gcp_region,
                bindings=settings.governed_agent_bindings,
                connection=connection,
            ),
            EvidenceMemoryContextEnricher(settings=settings, connection=connection),
        ).dispatch_ready_steps(
            scope=settings.scope,
            incident_id=run.incident_id,
            authority=CoordinatorAuthority(owner, lease.token, lease.workflow_version),
        )
    finally:
        with workflow.transaction():
            workflow.release_lease(scope=settings.scope, lease=lease)


def _dispatch_ready_investigation_steps(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
) -> None:
    """Re-dispatch every reservable investigation step with no live attempt.

    This is the idempotent recovery sweep for work committed by a tick that
    died before dispatching it: an accepted supervisor plan, an agent
    completion that unblocked its successors, or a declared fallback whose
    backoff has elapsed. Reservation remains the only writer, so a step that
    another coordinator already reserved is skipped rather than duplicated,
    and a lost incident lease simply defers the incident to a later tick.
    """

    store = PostgresInvestigationStore(connection)
    with workflow.transaction():
        incident_ids = store.incidents_with_dispatchable_steps(scope=settings.scope)
    if not incident_ids:
        return
    runtime = _runtime(settings)
    for incident_id in incident_ids:
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=settings.scope,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner=owner,
                lease_ttl_ms=60_000,
            )
        if lease is None:
            continue
        try:
            InvestigationCoordinator(
                store,
                runtime,
                PostgresAgentRunBinder(
                    region=settings.gcp_region,
                    bindings=settings.governed_agent_bindings,
                    connection=connection,
                ),
                EvidenceMemoryContextEnricher(settings=settings, connection=connection),
            ).dispatch_ready_steps(
                scope=settings.scope,
                incident_id=incident_id,
                authority=CoordinatorAuthority(owner, lease.token, lease.workflow_version),
            )
        except (AgentResultConflict, InvestigationConflict, RuntimeRunConflict):
            # Another coordinator won the same incident between listing and
            # reservation. The durable record is unchanged; a later sweep sees
            # whatever remains, and one contended incident never stops the rest.
            continue
        finally:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
