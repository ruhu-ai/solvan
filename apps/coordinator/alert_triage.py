"""Coordinator-owned Alert admission, dispatch, and Runtime settlement."""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from apps.coordinator.contracts import CoordinatorSettings, _runtime
from apps.coordinator.runtime_starters import _runtime_error_class
from apps.coordinator.tool_binding import PostgresAgentRunBinder
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence import PendingRuntimeRun, PostgresRuntimeRunStore
from solvan.persistence.alert_triage import AlertTriageRepository
from solvan.persistence.alert_triage_scheduling_types import AlertSchedulingError
from solvan.platform.agent_runtime import (
    GeminiAgentRuntime,
    IncompleteRuntimeReceiptError,
)

_ALERT_PLAN: dict[str, Any] = {
    "schema_version": 1,
    "objective": "Collect bounded evidence for the frozen alert target.",
    "completion_condition": "Return only evidence references from allowed read tools.",
    "steps": [
        {
            "step_key": "collect-alert-evidence",
            "agent_key": "evidence-agent",
            "scope_ref": "scope:alert-target",
            "purpose": "Read bounded metrics and compare them with the frozen alert window.",
        }
    ],
}
_ALERT_PLAN_HASH = canonical_sha256(_ALERT_PLAN)


def run_alert_triage_tick(
    *,
    settings: CoordinatorSettings,
    owner: str,
    connection: Connection[Any],
    runs: PostgresRuntimeRunStore,
    batch_size: int = 20,
) -> None:
    """Advance target Alert work in bounded transactions and one Runtime dispatch."""

    repository = AlertTriageRepository(connection)
    _consume_operator_requests(
        repository=repository,
        scope=settings.scope,
        owner=owner,
        connection=connection,
        batch_size=batch_size,
    )
    _admit_ready_episodes(
        repository=repository,
        scope=settings.scope,
        connection=connection,
        batch_size=batch_size,
    )
    _retry_due_admissions(
        repository=repository,
        scope=settings.scope,
        connection=connection,
        batch_size=batch_size,
    )
    cell_id = _current_cell_or_none(connection, settings.scope)
    if cell_id is None:
        # A scope carrying the Alert schema but no ACTIVE placement has no cell
        # that may lease or dispatch triage. Admission above stays durable and
        # resumes when a placement becomes current. This is contained exactly
        # like the absent-schema case: one unplaced scope must never stop the
        # incident, Runtime, case, graph, and Relay work in the same tick.
        return
    with connection.transaction():
        repository.reclaim_expired_alert_triage(
            scope=settings.scope,
            cell_id=cell_id,
            lease_seconds=300,
        )
    _start_next_alert_triage(
        settings=settings,
        repository=repository,
        runs=runs,
        connection=connection,
        cell_id=cell_id,
    )


def poll_alert_triage_run(
    *,
    settings: CoordinatorSettings,
    run: PendingRuntimeRun,
    runtime: GeminiAgentRuntime,
    connection: Connection[Any],
) -> None:
    """Poll one Alert run; provider prose never becomes workflow authority."""

    repository = AlertTriageRepository(connection)
    if run.alert_episode_id is None:
        return
    if run.deadline <= datetime.now(UTC):
        with suppress(Exception):
            runtime.cancel(
                agent_resource=run.agent_resource,
                operation_name=run.runtime_operation_name,
            )
        with connection.transaction():
            repository.fail_alert_triage(
                scope=settings.scope,
                agent_run_id=run.run_id,
                error_class="RUNTIME_DEADLINE_EXCEEDED",
            )
        return
    try:
        result = runtime.check(run.runtime_operation_name)
    except Exception:
        return
    if result.status == "RUNNING":
        return
    if result.status == "FAILED" or result.result is None:
        with connection.transaction():
            repository.fail_alert_triage(
                scope=settings.scope,
                agent_run_id=run.run_id,
                error_class="AGENT_RUNTIME_QUERY_FAILED",
            )
        return
    output = result.result.encode()
    result_hash = "sha256:" + hashlib.sha256(output).hexdigest()
    # The durable citation is one pair: a reference and a digest. The digest
    # covers the in-band provider result, so the reference stored beside it
    # must be the object the same completed operation names, and the object
    # this coordinator reserved for this exact run. A drifted, absent, or
    # substituted reference is failed closed here rather than committed as an
    # unverifiable pair no later reader could ever check.
    expected_output_ref = runtime.output_uri(scope=settings.scope, run_id=run.run_id)
    if (
        run.runtime_output_ref != expected_output_ref
        or result.output_gcs_uri != expected_output_ref
    ):
        with connection.transaction():
            repository.fail_alert_triage(
                scope=settings.scope,
                agent_run_id=run.run_id,
                error_class="RUNTIME_OUTPUT_REF_MISMATCH",
            )
        return
    try:
        with connection.transaction():
            triage_run_id, claim_token, claim_epoch = repository.alert_completion_fence(
                scope=settings.scope, agent_run_id=run.run_id
            )
            repository.complete_alert_triage(
                scope=settings.scope,
                triage_run_id=triage_run_id,
                claim_token=claim_token,
                claim_epoch=claim_epoch,
                result_ref=run.runtime_output_ref,
                result_hash=result_hash,
            )
    except AlertSchedulingError as error:
        with connection.transaction():
            repository.fail_alert_triage(
                scope=settings.scope,
                agent_run_id=run.run_id,
                error_class=str(error).split(":", 1)[0],
            )


def fail_expired_alert_created_run(
    *, settings: CoordinatorSettings, run_id: str, connection: Connection[Any], error_class: str
) -> None:
    with connection.transaction():
        AlertTriageRepository(connection).fail_alert_triage(
            scope=settings.scope, agent_run_id=run_id, error_class=error_class
        )


def _start_next_alert_triage(
    *,
    settings: CoordinatorSettings,
    repository: AlertTriageRepository,
    runs: PostgresRuntimeRunStore,
    connection: Connection[Any],
    cell_id: str,
) -> None:
    input_manifest = {
        "schema_version": 1,
        "scope": settings.scope.canonical_dict(),
        "plan_hash": _ALERT_PLAN_HASH,
    }
    binder = PostgresAgentRunBinder(
        region=settings.gcp_region,
        bindings=settings.governed_agent_bindings,
        connection=connection,
    )

    def bind(scope: Scope, run_id: str, context: dict[str, Any]) -> str:
        return binder.bind_run(
            scope=scope,
            run_id=run_id,
            agent_key="evidence-agent",
            target_external_project_id=str(context["target_external_project_id"]),
            target_workload_region=str(context["target_workload_region"]),
            policy_head_activation_id=str(context["policy_head_activation_id"]),
            policy_head_epoch=int(context["policy_head_epoch"]),
            placement_epoch=int(context["placement_epoch"]),
        )

    with connection.transaction():
        claim = repository.claim_next_alert_triage(
            scope=settings.scope,
            cell_id=cell_id,
            lease_seconds=300,
            plan_json=_ALERT_PLAN,
            plan_hash=_ALERT_PLAN_HASH,
            input_manifest=input_manifest,
            effective_tool_set_hash=None,
            agent_resource=settings.evidence_agent_resource,
            agent_revision=settings.evidence_agent_revision,
            binding_resolver=bind,
        )
        if claim is None:
            return
        dispatch = repository.alert_runtime_dispatch(
            scope=settings.scope, agent_run_id=claim.agent_run_id
        )
    runtime = _runtime(settings)
    try:
        receipt = runtime.invoke(dispatch)
    except IncompleteRuntimeReceiptError as error:
        with connection.transaction():
            runs.record_partial_receipt(
                scope=settings.scope, dispatch=dispatch, receipt=error.receipt
            )
        return
    except Exception as error:
        with connection.transaction():
            repository.fail_alert_triage(
                scope=settings.scope,
                agent_run_id=dispatch.run_id,
                error_class=_runtime_error_class(error),
            )
        return
    with connection.transaction():
        runs.record_dispatch(scope=settings.scope, dispatch=dispatch, receipt=receipt)
        repository.mark_alert_runtime_dispatched(
            scope=settings.scope,
            agent_run_id=dispatch.run_id,
            runtime_operation_name=receipt.runtime_operation_name,
        )


def _consume_operator_requests(
    *,
    repository: AlertTriageRepository,
    scope: Scope,
    owner: str,
    connection: Connection[Any],
    batch_size: int,
) -> None:
    for _ in range(batch_size):
        with connection.transaction():
            if repository.consume_next_operator_request(scope=scope, owner=owner) is None:
                return


def _admit_ready_episodes(
    *, repository: AlertTriageRepository, scope: Scope, connection: Connection[Any], batch_size: int
) -> None:
    rows = connection.execute(
        """SELECT episode.id FROM solvan_alerts.alert_episodes episode
            WHERE episode.organization_id=%(organization_id)s
              AND episode.project_id=%(project_id)s
              AND episode.environment_id=%(environment_id)s
              AND episode.state='OPEN'
              AND NOT EXISTS (
                SELECT 1 FROM solvan_alerts.alert_admissions admission
                 WHERE admission.organization_id=episode.organization_id
                   AND admission.project_id=episode.project_id
                   AND admission.environment_id=episode.environment_id
                   AND admission.episode_id=episode.id)
            ORDER BY episode.first_source_time,episode.id LIMIT %(batch_size)s""",
        {**scope.canonical_dict(), "batch_size": batch_size},
    ).fetchall()
    connection.commit()
    for row in rows:
        with connection.transaction():
            repository.admit_episode(scope=scope, episode_id=str(row[0]))


def _retry_due_admissions(
    *, repository: AlertTriageRepository, scope: Scope, connection: Connection[Any], batch_size: int
) -> None:
    rows = connection.execute(
        """SELECT episode.id FROM solvan_alerts.alert_episodes episode
            JOIN solvan_alerts.alert_admission_current current
              ON (current.organization_id,current.project_id,current.environment_id,
                  current.provider_generation_id)=
                 (episode.organization_id,episode.project_id,episode.environment_id,
                  episode.provider_generation_id)
            JOIN solvan_alerts.alert_admissions admission
              ON (admission.organization_id,admission.project_id,
                  admission.environment_id,admission.id)=
                 (current.organization_id,current.project_id,
                  current.environment_id,current.admission_id)
           WHERE episode.organization_id=%(organization_id)s
             AND episode.project_id=%(project_id)s
             AND episode.environment_id=%(environment_id)s
             AND admission.decision='PENDING' AND admission.due_at<=clock_timestamp()
           ORDER BY admission.due_at,episode.id LIMIT %(batch_size)s""",
        {**scope.canonical_dict(), "batch_size": batch_size},
    ).fetchall()
    connection.commit()
    for row in rows:
        with connection.transaction():
            repository.retry_pending_admission(scope=scope, episode_id=str(row[0]))


def _current_cell_or_none(connection: Connection[Any], scope: Scope) -> str | None:
    """Resolve the one ACTIVE placement cell, or report that there is none."""

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT cell_id FROM solvan_scale.tenant_placements
                WHERE organization_id=%(organization_id)s
                  AND is_current AND lifecycle='ACTIVE'""",
            scope.canonical_dict(),
        )
        row = cursor.fetchone()
    return None if row is None else str(row["cell_id"])
