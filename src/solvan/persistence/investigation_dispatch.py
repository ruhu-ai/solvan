"""Create one immutable, fenced investigation Runtime dispatch."""

from __future__ import annotations

import secrets
from dataclasses import asdict
from typing import Any

from psycopg.types.json import Jsonb

from solvan.application.investigation import CoordinatorAuthority, RuntimeDispatch
from solvan.domain import Scope, StepBudget, new_identifier
from solvan.persistence.investigation_material import input_hash
from solvan.persistence.investigation_projection import agent_context

# Durable deferral recorded on a step when a failed attempt returns it to READY
# for its declared fallback. Reservation never dispatches the fallback earlier,
# so a transient Runtime fault cannot burn the final attempt in the same
# instant, and the deferral survives coordinator restarts.
DISPATCH_RETRY_BACKOFF_MS = 30_000


def create_investigation_dispatch(
    cursor: Any,
    scope: Scope,
    incident_id: str,
    authority: CoordinatorAuthority,
    step: dict[str, Any],
) -> RuntimeDispatch:
    run_id = new_identifier("run")
    invocation_id = new_identifier("inv")
    trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    logical_step_key = (
        f"incident:{incident_id}:investigation:{step['plan_version']}:{step['step_key']}"
    )
    cursor.execute(
        """SELECT COALESCE(max(attempt), 0) + 1 AS next_attempt
          FROM solvan.agent_runs
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND logical_step_key = %(logical_step_key)s""",
        {**scope.canonical_dict(), "logical_step_key": logical_step_key},
    )
    attempt_row = cursor.fetchone()
    attempt = int(attempt_row["next_attempt"])
    budget = StepBudget(**step["budget_json"])
    input_ref = f"db://solvan/investigation-steps/{step['id']}"
    context = agent_context(cursor, scope, incident_id)
    resolved_input_hash = input_hash(scope, incident_id, authority, step, context)
    cursor.execute(
        """INSERT INTO solvan.agent_runs
          (organization_id, project_id, environment_id, id, incident_id,
           investigation_step_id,
           logical_step_key, agent_key, agent_resource, agent_revision,
           invocation_id, workflow_version, attempt, status, deadline,
           budget_json, input_ref, input_context_json, input_hash, trace_id, span_id)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(run_id)s, %(incident_id)s, %(step_id)s, %(logical_step_key)s,
            %(agent_key)s, %(agent_resource)s, %(agent_revision)s,
            %(invocation_id)s, %(workflow_version)s, %(attempt)s, 'CREATED',
            now() + (%(deadline_ms)s * interval '1 millisecond'), %(budget)s,
            %(input_ref)s, %(input_context)s, %(input_hash)s, %(trace_id)s, %(span_id)s)
          RETURNING deadline""",
        {
            **scope.canonical_dict(),
            "run_id": run_id,
            "incident_id": incident_id,
            "step_id": step["id"],
            "logical_step_key": logical_step_key,
            "agent_key": step["agent_key"],
            "agent_resource": step["agent_resource"],
            "agent_revision": step["agent_revision"],
            "invocation_id": invocation_id,
            "workflow_version": authority.workflow_version,
            "attempt": attempt,
            "deadline_ms": budget.deadline_ms,
            "budget": Jsonb(asdict(budget)),
            "input_ref": input_ref,
            "input_context": Jsonb(context),
            "input_hash": resolved_input_hash,
            "trace_id": trace_id,
            "span_id": span_id,
        },
    )
    deadline_row = cursor.fetchone()
    deadline = deadline_row["deadline"]
    cursor.execute(
        """UPDATE solvan.investigation_steps SET status = 'DISPATCHED',
            current_agent_run_id = %(run_id)s, started_at = now()
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND id = %(step_id)s AND status = 'READY'
            AND current_agent_run_id IS NULL""",
        {**scope.canonical_dict(), "step_id": step["id"], "run_id": run_id},
    )
    return RuntimeDispatch(
        run_id=run_id,
        invocation_id=invocation_id,
        scope=scope,
        incident_id=incident_id,
        plan_id=str(step["plan_id"]),
        plan_version=int(step["plan_version"]),
        step_id=str(step["id"]),
        step_key=str(step["step_key"]),
        logical_step_key=logical_step_key,
        agent_key=str(step["agent_key"]),
        agent_resource=str(step["agent_resource"]),
        agent_revision=str(step["agent_revision"]),
        scope_ref=str(step["scope_ref"]),
        purpose=str(step["purpose"]),
        allowed_tool_names=tuple(str(value) for value in step["allowed_tool_names_json"]),
        workflow_version=authority.workflow_version,
        deadline=deadline,
        budget=budget,
        input_ref=input_ref,
        input_hash=resolved_input_hash,
        trace_id=trace_id,
        span_id=span_id,
        context=context,
    )
