"""Durable reservation and dispatch of pending institutional-agent work."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings, _runtime
from apps.coordinator.tool_binding import PostgresAgentRunBinder
from solvan.application import (
    CoordinatorAuthority,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
)
from solvan.application.guidance_content import load_selected_guidance
from solvan.domain import new_identifier
from solvan.persistence import (
    AggregateType,
    PostgresOperationalGuidanceStore,
    PostgresRuntimeRunStore,
    PostgresWorkflowStore,
    RuntimeRunBudgetExhausted,
    TransitionWrite,
)
from solvan.platform.agent_runtime import GeminiAgentRuntime, IncompleteRuntimeReceiptError
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.google_rest import authorized_session


def _invoke_with_partial_receipt(
    *,
    runtime: GeminiAgentRuntime,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    dispatch: RuntimeDispatch,
) -> RuntimeInvocationReceipt:
    try:
        return runtime.invoke(dispatch)
    except IncompleteRuntimeReceiptError as error:
        with workflow.transaction():
            runs.record_partial_receipt(
                scope=dispatch.scope,
                dispatch=dispatch,
                receipt=error.receipt,
            )
        raise


def _runtime_error_class(error: Exception) -> str:
    if isinstance(error, IncompleteRuntimeReceiptError):
        return error.error_class
    return type(error).__name__


def _start_pending_supervisors(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    connection: Connection[Any],
) -> None:
    runtime = _runtime(settings)
    with workflow.transaction():
        incident_ids = runs.incidents_needing_supervisor(scope=settings.scope)
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
        authority = CoordinatorAuthority(owner, lease.token, lease.workflow_version)
        try:
            with workflow.transaction():
                dispatch = runs.reserve_supervisor(
                    scope=settings.scope,
                    incident_id=incident_id,
                    authority=authority,
                    agent_resource=settings.supervisor_resource,
                    agent_revision=settings.supervisor_revision,
                )
        except RuntimeRunBudgetExhausted as error:
            with workflow.transaction(), connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO solvan.security_events
                      (organization_id, project_id, environment_id, id, event_type,
                       control, severity, actor_principal, incident_id, safe_summary)
                      SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                        %(security_event_id)s, 'AGENT_BUDGET_EXHAUSTED',
                        'RUNTIME_BUDGET', 'HIGH', %(actor)s, %(incident_id)s,
                        %(safe_summary)s
                      WHERE NOT EXISTS (
                        SELECT 1 FROM solvan.security_events
                        WHERE organization_id = %(organization_id)s
                          AND project_id = %(project_id)s
                          AND environment_id = %(environment_id)s
                          AND incident_id = %(incident_id)s
                          AND event_type = 'AGENT_BUDGET_EXHAUSTED')""",
                    {
                        **settings.scope.canonical_dict(),
                        "security_event_id": new_identifier("sec"),
                        "actor": owner,
                        "incident_id": incident_id,
                        "safe_summary": str(error)[:500],
                    },
                )
                workflow.commit_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="INVESTIGATING",
                        to_state="ESCALATED",
                        transition_key="FAILURE_EXHAUSTED:SUPERVISOR_RUNTIME_BUDGET",
                        actor_type="COORDINATOR",
                        actor_id=owner,
                        reason_code="SUPERVISOR_RUNTIME_BUDGET_EXHAUSTED",
                        rationale_summary=(
                            "The incident Supervisor exhausted its immutable initial "
                            "attempt plus one replan; unbounded model retries are forbidden."
                        ),
                    ),
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        if dispatch is None:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        try:
            selected_guidance = None
            with workflow.transaction():
                binder = PostgresAgentRunBinder(
                    region=settings.gcp_region,
                    bindings=settings.governed_agent_bindings,
                    connection=connection,
                )
                effective_tool_set = binder.bind(dispatch)
                selected_guidance = binder.bind_trigger_guidance(dispatch=dispatch)
            enrichment: dict[str, Any] = {
                "effective_tool_set": effective_tool_set.canonical_dict(),
                "effective_tool_set_hash": effective_tool_set.effective_tool_set_hash,
            }
            if selected_guidance is not None:
                content_reader = GcsEvidenceReader(
                    allowed_buckets=frozenset({settings.guidance_bucket}),
                    session=authorized_session(),
                )

                def audit_fetch(
                    *,
                    selection_id: str,
                    content_hash: str,
                    outcome: str,
                    reason_codes: tuple[str, ...],
                ) -> None:
                    with workflow.transaction():
                        PostgresOperationalGuidanceStore(connection).record_fetch(
                            scope=settings.scope,
                            selection_id=selection_id,
                            content_hash=content_hash,
                            outcome=outcome,
                            reason_codes=reason_codes,
                        )

                loaded = load_selected_guidance(
                    selection=selected_guidance,
                    reader=content_reader,
                    audit=audit_fetch,
                )
                enrichment["operational_guidance"] = {
                    "selection_id": loaded.selection_id,
                    "content_hash": loaded.content_hash,
                    "content": loaded.value,
                    "trust": "UNTRUSTED_OPERATIONAL_GUIDANCE",
                }
            # One CAS re-hash covering everything this dispatch will actually
            # carry, exactly as the investigation path has always done: the
            # persisted input_hash names the bytes sent, not the bytes
            # reserved, and record_dispatch fences on the updated value.
            with workflow.transaction():
                dispatch = runs.attach_runtime_context(
                    scope=settings.scope,
                    dispatch=dispatch,
                    context=enrichment,
                )
            receipt = _invoke_with_partial_receipt(
                runtime=runtime,
                workflow=workflow,
                runs=runs,
                dispatch=dispatch,
            )
        except Exception as error:
            with workflow.transaction():
                runs.fail_created(
                    scope=settings.scope,
                    dispatch=dispatch,
                    error_class=_runtime_error_class(error),
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        with workflow.transaction():
            runs.record_dispatch(scope=settings.scope, dispatch=dispatch, receipt=receipt)
            workflow.release_lease(scope=settings.scope, lease=lease)


def _start_pending_executions(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    connection: Connection[Any],
) -> None:
    runtime = _runtime(settings)
    with workflow.transaction():
        actions = runs.actions_needing_execution(scope=settings.scope)
    for action_id, incident_id in actions:
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
        authority = CoordinatorAuthority(owner, lease.token, lease.workflow_version)
        with workflow.transaction():
            dispatch = runs.reserve_execution(
                scope=settings.scope,
                action_id=action_id,
                authority=authority,
                agent_resource=settings.execution_agent_resource,
                agent_revision=settings.execution_agent_revision,
            )
        if dispatch is None:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        try:
            with workflow.transaction():
                effective_tool_set = PostgresAgentRunBinder(
                    region=settings.gcp_region,
                    bindings=settings.governed_agent_bindings,
                    connection=connection,
                ).bind(dispatch)
            enrichment: dict[str, Any] = {
                "effective_tool_set": effective_tool_set.canonical_dict(),
                "effective_tool_set_hash": effective_tool_set.effective_tool_set_hash,
            }
        except Exception as error:
            with workflow.transaction(), connection.cursor() as cursor:
                runs.fail_created(
                    scope=settings.scope,
                    dispatch=dispatch,
                    error_class=_runtime_error_class(error),
                )
                cursor.execute(
                    """UPDATE solvan.actions SET status = 'INVALIDATED'
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(action_id)s AND status = 'AUTHORIZED'""",
                    {**settings.scope.canonical_dict(), "action_id": action_id},
                )
                workflow.commit_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="MITIGATING",
                        to_state="ESCALATED",
                        transition_key=f"EXECUTION_BINDING_REFUSED:{action_id}:DISPATCH",
                        actor_type="COORDINATOR",
                        actor_id=owner,
                        reason_code="EXECUTION_TOOL_BINDING_REFUSED",
                        rationale_summary=(
                            "The exact approved Tool profile could not be frozen before "
                            "dispatch; no mutation was attempted and the action was invalidated."
                        ),
                    ),
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        try:
            # One CAS re-hash covering everything this dispatch will actually
            # carry, exactly as the investigation path has always done: the
            # persisted input_hash names the bytes sent, not the bytes
            # reserved, and record_dispatch fences on the updated value.
            with workflow.transaction():
                dispatch = runs.attach_runtime_context(
                    scope=settings.scope,
                    dispatch=dispatch,
                    context=enrichment,
                )
            receipt = _invoke_with_partial_receipt(
                runtime=runtime,
                workflow=workflow,
                runs=runs,
                dispatch=dispatch,
            )
        except Exception as error:
            with workflow.transaction(), connection.cursor() as cursor:
                runs.fail_created(
                    scope=settings.scope,
                    dispatch=dispatch,
                    error_class=_runtime_error_class(error),
                )
                cursor.execute(
                    """UPDATE solvan.actions SET status = 'AMBIGUOUS'
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(action_id)s AND status = 'AUTHORIZED'""",
                    {**settings.scope.canonical_dict(), "action_id": action_id},
                )
                workflow.commit_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="MITIGATING",
                        to_state="ESCALATED",
                        transition_key=f"MUTATION_AMBIGUOUS:{action_id}:DISPATCH",
                        actor_type="COORDINATOR",
                        actor_id=owner,
                        reason_code="EXECUTION_RUNTIME_DISPATCH_AMBIGUOUS",
                        rationale_summary=(
                            "Execution Runtime dispatch did not return a durable "
                            "operation receipt; automatic retry is forbidden."
                        ),
                    ),
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        with workflow.transaction():
            runs.record_dispatch(scope=settings.scope, dispatch=dispatch, receipt=receipt)
            workflow.release_lease(scope=settings.scope, lease=lease)


def _start_pending_verifications(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    runs: PostgresRuntimeRunStore,
    connection: Connection[Any],
) -> None:
    runtime = _runtime(settings)
    with workflow.transaction():
        actions = runs.actions_needing_verification(scope=settings.scope)
    for action_id, incident_id in actions:
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
        authority = CoordinatorAuthority(owner, lease.token, lease.workflow_version)
        with workflow.transaction():
            dispatch = runs.reserve_verification(
                scope=settings.scope,
                action_id=action_id,
                authority=authority,
                agent_resource=settings.verification_agent_resource,
                agent_revision=settings.verification_agent_revision,
            )
        if dispatch is None:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        try:
            with workflow.transaction():
                effective_tool_set = PostgresAgentRunBinder(
                    region=settings.gcp_region,
                    bindings=settings.governed_agent_bindings,
                    connection=connection,
                ).bind(dispatch)
            enrichment: dict[str, Any] = {
                "effective_tool_set": effective_tool_set.canonical_dict(),
                "effective_tool_set_hash": effective_tool_set.effective_tool_set_hash,
            }
            # One CAS re-hash covering everything this dispatch will actually
            # carry, exactly as the investigation path has always done: the
            # persisted input_hash names the bytes sent, not the bytes
            # reserved, and record_dispatch fences on the updated value.
            with workflow.transaction():
                dispatch = runs.attach_runtime_context(
                    scope=settings.scope,
                    dispatch=dispatch,
                    context=enrichment,
                )
            receipt = _invoke_with_partial_receipt(
                runtime=runtime,
                workflow=workflow,
                runs=runs,
                dispatch=dispatch,
            )
        except Exception as error:
            with workflow.transaction():
                runs.fail_created(
                    scope=settings.scope,
                    dispatch=dispatch,
                    error_class=_runtime_error_class(error),
                )
                workflow.commit_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="VERIFYING_MITIGATION",
                        to_state="ESCALATED",
                        transition_key=f"VERIFICATION_EXHAUSTED:{action_id}:DISPATCH",
                        actor_type="COORDINATOR",
                        actor_id=owner,
                        reason_code="VERIFICATION_RUNTIME_DISPATCH_FAILED",
                        rationale_summary=(
                            "Independent verification could not be durably dispatched; "
                            "recovery remains unverified."
                        ),
                    ),
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
            continue
        with workflow.transaction():
            runs.record_dispatch(scope=settings.scope, dispatch=dispatch, receipt=receipt)
            workflow.release_lease(scope=settings.scope, lease=lease)
