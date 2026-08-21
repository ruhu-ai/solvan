"""Pure conversion from durable Runtime rows to typed dispatches."""

from __future__ import annotations

from typing import Any

from solvan.application import RuntimeDispatch
from solvan.domain import Scope, StepBudget


def supervisor_dispatch(
    scope: Scope,
    row: dict[str, Any],
    context: dict[str, Any],
    budget: StepBudget,
) -> RuntimeDispatch:
    return RuntimeDispatch(
        run_id=str(row["id"]),
        invocation_id=str(row["invocation_id"]),
        scope=scope,
        incident_id=str(row["incident_id"]),
        plan_id="supervisor-plan-pending",
        plan_version=1,
        step_id="supervisor-step",
        step_key="supervisor-plan",
        logical_step_key=str(row["logical_step_key"]),
        agent_key="incident-supervisor",
        agent_resource=str(row["agent_resource"]),
        agent_revision=str(row["agent_revision"]),
        scope_ref="scope:primary-service",
        purpose="Propose a bounded investigation DAG for this incident.",
        allowed_tool_names=(),
        workflow_version=int(row["workflow_version"]),
        deadline=row["deadline"],
        budget=budget,
        input_ref=str(row["input_ref"]),
        input_hash=str(row["input_hash"]),
        trace_id=str(row["trace_id"]),
        span_id=str(row["span_id"]),
        context=context,
    )


def execution_dispatch(
    scope: Scope,
    row: dict[str, Any],
    context: dict[str, Any],
    budget: StepBudget,
) -> RuntimeDispatch:
    action_id = str(row["action_id"])
    return RuntimeDispatch(
        run_id=str(row["id"]),
        invocation_id=str(row["invocation_id"]),
        scope=scope,
        incident_id=str(row["incident_id"]),
        plan_id="authorized-action-execution",
        plan_version=1,
        step_id=action_id,
        step_key="execute-authorized-action",
        logical_step_key=str(row["logical_step_key"]),
        agent_key="execution-agent",
        agent_resource=str(row["agent_resource"]),
        agent_revision=str(row["agent_revision"]),
        scope_ref="scope:authorized-action",
        purpose="Request execution of the one stored AuthorizedAction.",
        allowed_tool_names=("execute_authorized_action",),
        workflow_version=int(row["workflow_version"]),
        deadline=row["deadline"],
        budget=budget,
        input_ref=str(row["input_ref"]),
        input_hash=str(row["input_hash"]),
        trace_id=str(row["trace_id"]),
        span_id=str(row["span_id"]),
        context=context,
    )


def verification_dispatch(
    scope: Scope,
    row: dict[str, Any],
    context: dict[str, Any],
    budget: StepBudget,
) -> RuntimeDispatch:
    action_id = str(row["action_id"])
    return RuntimeDispatch(
        run_id=str(row["id"]),
        invocation_id=str(row["invocation_id"]),
        scope=scope,
        incident_id=str(row["incident_id"]),
        plan_id="independent-verification",
        plan_version=1,
        step_id=action_id,
        step_key="run-bound-verification",
        logical_step_key=str(row["logical_step_key"]),
        agent_key="verification-agent",
        agent_resource=str(row["agent_resource"]),
        agent_revision=str(row["agent_revision"]),
        scope_ref="scope:bound-verification-profile",
        purpose="Request the exact independent verification profile.",
        allowed_tool_names=("run_bound_verification",),
        workflow_version=int(row["workflow_version"]),
        deadline=row["deadline"],
        budget=budget,
        input_ref=str(row["input_ref"]),
        input_hash=str(row["input_hash"]),
        trace_id=str(row["trace_id"]),
        span_id=str(row["span_id"]),
        context=context,
    )
