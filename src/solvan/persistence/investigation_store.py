"""Immutable investigation plans and coordinator-only agent dispatch attempts."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, replace
from typing import Any
from uuid import UUID

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.investigation import (
    AcceptedPlanRecord,
    CoordinatorAuthority,
    InvestigationConflict,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
)
from solvan.domain import AcceptedInvestigationPlan, Scope, new_identifier
from solvan.persistence.investigation_dispatch import (
    DISPATCH_RETRY_BACKOFF_MS,
    create_investigation_dispatch,
)
from solvan.persistence.investigation_material import input_hash, plan_content_hash
from solvan.persistence.investigation_projection import dispatch_from_row


class PostgresInvestigationStore:
    """Persist accepted plan versions before reserving any Runtime invocation."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._connection.transaction():
            yield

    def persist_accepted_plan(
        self,
        *,
        scope: Scope,
        incident_id: str,
        supervisor_run_id: str,
        authority: CoordinatorAuthority,
        plan: AcceptedInvestigationPlan,
    ) -> AcceptedPlanRecord:
        content_hash = plan_content_hash(plan)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._lock_incident(cursor, scope, incident_id, authority)
            cursor.execute(
                """SELECT id FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(supervisor_run_id)s
                    AND incident_id = %(incident_id)s
                    AND agent_key = 'incident-supervisor'
                    AND status = 'SUCCEEDED'
                    AND workflow_version = %(workflow_version)s""",
                {
                    **scope.canonical_dict(),
                    "supervisor_run_id": supervisor_run_id,
                    "incident_id": incident_id,
                    "workflow_version": authority.workflow_version,
                },
            )
            if cursor.fetchone() is None:
                raise InvestigationConflict(
                    "plan creator is not a successful, current incident supervisor run"
                )
            cursor.execute(
                """SELECT id, plan_version, content_hash
                  FROM solvan.investigation_plans
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND incident_id = %(incident_id)s
                    AND created_by_agent_run_id = %(supervisor_run_id)s""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "supervisor_run_id": supervisor_run_id,
                },
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["content_hash"] != content_hash:
                    raise InvestigationConflict(
                        "one supervisor run cannot create different plan contents"
                    )
                return self._load_plan_record(cursor, scope, existing)

            cursor.execute(
                """SELECT id, plan_version, status
                  FROM solvan.investigation_plans
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND incident_id = %(incident_id)s
                  ORDER BY plan_version DESC LIMIT 1 FOR UPDATE""",
                {**scope.canonical_dict(), "incident_id": incident_id},
            )
            previous = cursor.fetchone()
            plan_id = new_identifier("ipl")
            plan_version = 1 if previous is None else int(previous["plan_version"]) + 1
            supersedes_id = None if previous is None else str(previous["id"])
            if previous is not None and previous["status"] == "ACCEPTED":
                cursor.execute(
                    """UPDATE solvan.investigation_plans SET status = 'SUPERSEDED'
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(previous_id)s AND status = 'ACCEPTED'""",
                    {**scope.canonical_dict(), "previous_id": previous["id"]},
                )
                cursor.execute(
                    """UPDATE solvan.investigation_steps SET status = 'STALE',
                        completed_at = CASE
                          WHEN started_at IS NULL THEN NULL ELSE now() END
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND plan_id = %(previous_id)s
                        AND status IN ('PLANNED','READY','DISPATCHED','RUNNING')""",
                    {**scope.canonical_dict(), "previous_id": previous["id"]},
                )
                cursor.execute(
                    """UPDATE solvan.agent_runs SET status = 'STALE', completed_at = now(),
                        error_class = 'PLAN_SUPERSEDED'
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id IN (
                          SELECT current_agent_run_id FROM solvan.investigation_steps
                          WHERE organization_id = %(organization_id)s
                            AND project_id = %(project_id)s
                            AND environment_id = %(environment_id)s
                            AND plan_id = %(previous_id)s)
                        AND status IN ('CREATED','DISPATCHED','RUNNING')""",
                    {**scope.canonical_dict(), "previous_id": previous["id"]},
                )
            cursor.execute(
                """INSERT INTO solvan.investigation_plans
                  (organization_id, project_id, environment_id, id, incident_id,
                   plan_version, objective, completion_condition, uncertainties_json,
                   content_hash, status, created_by_agent_run_id, supersedes_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(plan_id)s, %(incident_id)s, %(plan_version)s, %(objective)s,
                    %(completion_condition)s, %(uncertainties)s, %(content_hash)s,
                    'ACCEPTED', %(supervisor_run_id)s, %(supersedes_id)s)""",
                {
                    **scope.canonical_dict(),
                    "plan_id": plan_id,
                    "incident_id": incident_id,
                    "plan_version": plan_version,
                    "objective": plan.objective,
                    "completion_condition": plan.completion_condition,
                    "uncertainties": Jsonb(list(plan.uncertainties)),
                    "content_hash": content_hash,
                    "supervisor_run_id": supervisor_run_id,
                    "supersedes_id": supersedes_id,
                },
            )
            step_ids: list[str] = []
            for accepted_step in plan.steps:
                step = accepted_step.proposal
                step_id = new_identifier("ist")
                step_ids.append(step_id)
                cursor.execute(
                    """INSERT INTO solvan.investigation_steps
                      (organization_id, project_id, environment_id, id, plan_id,
                       step_key, ordinal, kind, agent_key,
                       agent_resource, agent_revision, scope_ref,
                       purpose, required, depends_on_json, budget_json,
                       allowed_tool_names_json, status,
                       fallback_ref)
                      VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                        %(step_id)s, %(plan_id)s, %(step_key)s, %(ordinal)s,
                        %(kind)s, %(agent_key)s, %(agent_resource)s,
                        %(agent_revision)s, %(scope_ref)s, %(purpose)s,
                        %(required)s, %(depends_on)s, %(budget)s,
                        %(allowed_tool_names)s, %(status)s, %(fallback_ref)s)""",
                    {
                        **scope.canonical_dict(),
                        "step_id": step_id,
                        "plan_id": plan_id,
                        "step_key": step.step_key,
                        "ordinal": accepted_step.ordinal,
                        "kind": step.kind.value,
                        "agent_key": step.agent_key,
                        "agent_resource": accepted_step.agent_resource,
                        "agent_revision": accepted_step.agent_revision,
                        "scope_ref": step.scope_ref,
                        "purpose": step.purpose,
                        "required": step.required,
                        "depends_on": Jsonb(list(step.depends_on)),
                        "budget": Jsonb(asdict(step.budget)),
                        "allowed_tool_names": Jsonb(list(accepted_step.allowed_tool_names)),
                        "status": "READY" if not step.depends_on else "PLANNED",
                        "fallback_ref": step.fallback_ref,
                    },
                )
        return AcceptedPlanRecord(plan_id, plan_version, content_hash, tuple(step_ids))

    def reserve_ready_dispatches(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        batch_size: int,
    ) -> tuple[RuntimeDispatch, ...]:
        if batch_size < 1:
            raise ValueError("batch size must be positive")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._lock_incident(cursor, scope, incident_id, authority)
            self._expire_created_attempts(cursor, scope, incident_id)
            self._promote_unblocked_steps(cursor, scope, incident_id)
            cursor.execute(
                """SELECT r.*, p.id AS plan_id, p.plan_version,
                    s.id AS step_id, s.step_key, s.budget_json, s.scope_ref,
                    s.purpose, s.allowed_tool_names_json
                  FROM solvan.investigation_plans p
                  JOIN solvan.investigation_steps s
                    ON (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                     = (p.organization_id, p.project_id, p.environment_id, p.id)
                  JOIN solvan.agent_runs r
                    ON (r.organization_id, r.project_id, r.environment_id, r.id)
                     = (s.organization_id, s.project_id, s.environment_id,
                        s.current_agent_run_id)
                  WHERE p.organization_id = %(organization_id)s
                    AND p.project_id = %(project_id)s
                    AND p.environment_id = %(environment_id)s
                    AND p.incident_id = %(incident_id)s AND p.status = 'ACCEPTED'
                    AND r.status = 'CREATED' AND r.deadline > now()
                  ORDER BY s.ordinal LIMIT %(batch_size)s
                  FOR UPDATE OF r, s SKIP LOCKED""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "batch_size": batch_size,
                },
            )
            dispatches = [dispatch_from_row(row) for row in cursor.fetchall()]
            remaining = batch_size - len(dispatches)
            if remaining == 0:
                return tuple(dispatches)
            cursor.execute(
                """SELECT s.*, p.plan_version
                  FROM solvan.investigation_plans p
                  JOIN solvan.investigation_steps s
                    ON (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                     = (p.organization_id, p.project_id, p.environment_id, p.id)
                  WHERE p.organization_id = %(organization_id)s
                    AND p.project_id = %(project_id)s
                    AND p.environment_id = %(environment_id)s
                    AND p.incident_id = %(incident_id)s AND p.status = 'ACCEPTED'
                    AND s.status = 'READY' AND s.kind = 'INVOKE_AGENT'
                    AND s.current_agent_run_id IS NULL
                    AND (s.retry_not_before IS NULL OR s.retry_not_before <= now())
                  ORDER BY s.ordinal LIMIT %(batch_size)s
                  FOR UPDATE OF s SKIP LOCKED""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "batch_size": remaining,
                },
            )
            for step in cursor.fetchall():
                dispatches.append(
                    create_investigation_dispatch(cursor, scope, incident_id, authority, step)
                )
        return tuple(dispatches)

    def attach_dispatch_context(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        context: dict[str, Any],
    ) -> RuntimeDispatch:
        """CAS-bind trusted enrichment into the persisted Runtime request hash."""

        if scope != dispatch.scope:
            raise InvestigationConflict("dispatch enrichment scope is stale")
        if dispatch.incident_id is None:
            raise InvestigationConflict("incident dispatch enrichment requires an incident anchor")
        merged = {**dispatch.context, **context}
        step = {
            "plan_id": dispatch.plan_id,
            "id": dispatch.step_id,
            "step_key": dispatch.step_key,
            "scope_ref": dispatch.scope_ref,
            "purpose": dispatch.purpose,
            "agent_resource": dispatch.agent_resource,
            "agent_revision": dispatch.agent_revision,
            "allowed_tool_names_json": list(dispatch.allowed_tool_names),
            "budget_json": asdict(dispatch.budget),
        }
        resolved_hash = input_hash(
            scope,
            dispatch.incident_id,
            CoordinatorAuthority("context-enricher", UUID(int=0), dispatch.workflow_version),
            step,
            merged,
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs
                  SET input_context_json = %(context)s, input_hash = %(new_hash)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED' AND input_hash = %(old_hash)s
                  RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "run_id": dispatch.run_id,
                    "invocation_id": dispatch.invocation_id,
                    "context": Jsonb(merged),
                    "new_hash": resolved_hash,
                    "old_hash": dispatch.input_hash,
                },
            )
            if cursor.fetchone() is None:
                raise InvestigationConflict("dispatch enrichment attempt is stale")
        return replace(dispatch, context=merged, input_hash=resolved_hash)

    def record_runtime_dispatch(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        receipt: RuntimeInvocationReceipt,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs r
                  SET status = 'DISPATCHED',
                    runtime_operation_name = %(runtime_operation_name)s,
                    session_id = %(session_id)s,
                    runtime_input_ref = %(runtime_input_ref)s,
                    runtime_output_ref = %(runtime_output_ref)s
                  FROM solvan.investigation_steps s, solvan.investigation_plans p
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.id = %(run_id)s AND r.invocation_id = %(invocation_id)s
                    AND r.status = 'CREATED'
                    AND (s.organization_id, s.project_id, s.environment_id,
                         s.current_agent_run_id)
                      = (r.organization_id, r.project_id, r.environment_id, r.id)
                    AND (p.organization_id, p.project_id, p.environment_id, p.id)
                      = (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                    AND p.id = %(plan_id)s AND p.status = 'ACCEPTED'
                  RETURNING r.id""",
                {
                    **scope.canonical_dict(),
                    "run_id": dispatch.run_id,
                    "invocation_id": dispatch.invocation_id,
                    "plan_id": dispatch.plan_id,
                    "runtime_operation_name": receipt.runtime_operation_name,
                    "session_id": receipt.session_id,
                    "runtime_input_ref": receipt.runtime_input_ref,
                    "runtime_output_ref": receipt.runtime_output_ref,
                },
            )
            if cursor.fetchone() is None:
                raise InvestigationConflict("Runtime dispatch attempt is stale")

    def record_runtime_dispatch_failure(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        error_class: str,
    ) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'FAILED',
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND invocation_id = %(invocation_id)s
                    AND status = 'CREATED' RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "run_id": dispatch.run_id,
                    "invocation_id": dispatch.invocation_id,
                    "error_class": error_class,
                },
            )
            if cursor.fetchone() is None:
                raise InvestigationConflict("Runtime dispatch failure is stale")
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
                    result_ref = 'runtime-error:' || %(error_class)s
                  FROM solvan.investigation_plans p, solvan.agent_runs r
                  WHERE s.organization_id = %(organization_id)s
                    AND s.project_id = %(project_id)s
                    AND s.environment_id = %(environment_id)s
                    AND s.id = %(step_id)s
                    AND s.current_agent_run_id = %(run_id)s
                    AND (r.organization_id, r.project_id, r.environment_id, r.id)
                      = (s.organization_id, s.project_id, s.environment_id,
                         s.current_agent_run_id)
                    AND (p.organization_id, p.project_id, p.environment_id, p.id)
                      = (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                    AND p.status = 'ACCEPTED'
                  RETURNING s.status""",
                {
                    **scope.canonical_dict(),
                    "step_id": dispatch.step_id,
                    "run_id": dispatch.run_id,
                    "error_class": error_class[:128],
                    "retry_backoff_ms": DISPATCH_RETRY_BACKOFF_MS,
                },
            )
            step = cursor.fetchone()
        return step is not None and step[0] == "READY"

    def incidents_with_dispatchable_steps(
        self, *, scope: Scope, limit: int = 10
    ) -> tuple[str, ...]:
        """List incidents holding reservable investigation work with no live run.

        This covers both halves of the same stranding class. A deferred fallback
        carries ``retry_not_before`` and becomes visible when its backoff
        elapses. A freshly accepted plan step, or a step returned to READY by a
        superseding write, carries no backoff and no run at all: a crash between
        committing the plan and dispatching it would otherwise leave the step
        invisible to every other sweep, because the supervisor queue excludes
        incidents that already have a SUCCEEDED supervisor at the current
        workflow version. Reservation stays the only writer, so re-listing an
        incident cannot create a duplicate attempt.
        """

        if limit < 1:
            raise ValueError("limit must be positive")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT DISTINCT p.incident_id
                  FROM solvan.investigation_plans p
                  JOIN solvan.investigation_steps s
                    ON (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                     = (p.organization_id, p.project_id, p.environment_id, p.id)
                  WHERE p.organization_id = %(organization_id)s
                    AND p.project_id = %(project_id)s
                    AND p.environment_id = %(environment_id)s
                    AND p.status = 'ACCEPTED'
                    AND s.status = 'READY' AND s.kind = 'INVOKE_AGENT'
                    AND s.current_agent_run_id IS NULL
                    AND (s.retry_not_before IS NULL OR s.retry_not_before <= now())
                  LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(str(row["incident_id"]) for row in cursor.fetchall())

    def _lock_incident(
        self,
        cursor: Any,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
    ) -> None:
        cursor.execute(
            """SELECT id FROM solvan.incidents
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND id = %(incident_id)s
                AND workflow_version = %(workflow_version)s
                AND lease_owner = %(lease_owner)s
                AND lease_token = %(lease_token)s
                AND lease_expires_at >= now() FOR UPDATE""",
            {
                **scope.canonical_dict(),
                "incident_id": incident_id,
                "workflow_version": authority.workflow_version,
                "lease_owner": authority.owner,
                "lease_token": authority.lease_token,
            },
        )
        if cursor.fetchone() is None:
            raise InvestigationConflict("incident workflow version or coordinator lease is stale")

    def _load_plan_record(
        self, cursor: Any, scope: Scope, plan: dict[str, Any]
    ) -> AcceptedPlanRecord:
        cursor.execute(
            """SELECT id FROM solvan.investigation_steps
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND plan_id = %(plan_id)s ORDER BY ordinal""",
            {**scope.canonical_dict(), "plan_id": plan["id"]},
        )
        return AcceptedPlanRecord(
            str(plan["id"]),
            int(plan["plan_version"]),
            str(plan["content_hash"]),
            tuple(str(row["id"]) for row in cursor.fetchall()),
        )

    def _expire_created_attempts(self, cursor: Any, scope: Scope, incident_id: str) -> None:
        parameters = {**scope.canonical_dict(), "incident_id": incident_id}
        cursor.execute(
            """UPDATE solvan.agent_runs r SET status = 'TIMED_OUT',
                error_class = 'DISPATCH_DEADLINE_EXCEEDED', completed_at = now()
              FROM solvan.investigation_steps s, solvan.investigation_plans p
              WHERE r.organization_id = %(organization_id)s
                AND r.project_id = %(project_id)s
                AND r.environment_id = %(environment_id)s
                AND r.status = 'CREATED' AND r.deadline <= now()
                AND (s.organization_id, s.project_id, s.environment_id,
                     s.current_agent_run_id)
                  = (r.organization_id, r.project_id, r.environment_id, r.id)
                AND (p.organization_id, p.project_id, p.environment_id, p.id)
                  = (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                AND p.incident_id = %(incident_id)s AND p.status = 'ACCEPTED'""",
            parameters,
        )
        cursor.execute(
            """UPDATE solvan.investigation_steps s SET
                status = CASE
                  WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL THEN 'READY'
                  ELSE 'FAILED'
                END,
                current_agent_run_id = CASE
                  WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL THEN NULL
                  ELSE s.current_agent_run_id
                END,
                started_at = CASE
                  WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL THEN NULL
                  ELSE s.started_at
                END,
                completed_at = CASE
                  WHEN r.attempt = 1 AND s.fallback_ref IS NOT NULL THEN NULL
                  ELSE now()
                END,
                result_ref = 'runtime-error:DISPATCH_DEADLINE_EXCEEDED'
              FROM solvan.investigation_plans p, solvan.agent_runs r
              WHERE s.organization_id = %(organization_id)s
                AND s.project_id = %(project_id)s
                AND s.environment_id = %(environment_id)s
                AND (p.organization_id, p.project_id, p.environment_id, p.id)
                  = (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                AND p.incident_id = %(incident_id)s AND p.status = 'ACCEPTED'
                AND (r.organization_id, r.project_id, r.environment_id, r.id)
                  = (s.organization_id, s.project_id, s.environment_id,
                     s.current_agent_run_id)
                AND r.status = 'TIMED_OUT'
                AND r.error_class = 'DISPATCH_DEADLINE_EXCEEDED'""",
            parameters,
        )

    def _promote_unblocked_steps(self, cursor: Any, scope: Scope, incident_id: str) -> None:
        cursor.execute(
            """UPDATE solvan.investigation_steps s SET status = 'READY'
              FROM solvan.investigation_plans p
              WHERE s.organization_id = %(organization_id)s
                AND s.project_id = %(project_id)s
                AND s.environment_id = %(environment_id)s
                AND (p.organization_id, p.project_id, p.environment_id, p.id)
                  = (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                AND p.incident_id = %(incident_id)s AND p.status = 'ACCEPTED'
                AND s.status = 'PLANNED'
                AND NOT EXISTS (
                  SELECT 1 FROM jsonb_array_elements_text(s.depends_on_json) dep(step_key)
                  LEFT JOIN solvan.investigation_steps required_step
                    ON required_step.organization_id = s.organization_id
                   AND required_step.project_id = s.project_id
                   AND required_step.environment_id = s.environment_id
                   AND required_step.plan_id = s.plan_id
                   AND required_step.step_key = dep.step_key
                  WHERE required_step.id IS NULL
                    OR required_step.status NOT IN ('SUCCEEDED','SKIPPED'))""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
