"""Deterministic mitigation planning after completed investigation."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.domain import (
    new_identifier,
)
from solvan.persistence import (
    AggregateType,
    MitigationPolicyError,
    PostgresMitigationPlanner,
    PostgresWorkflowStore,
    TransitionWrite,
)


def _advance_completed_investigations(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
) -> None:
    planner = PostgresMitigationPlanner(connection)
    with workflow.transaction():
        incident_ids = planner.ready_incident_ids(scope=settings.scope)
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
            with workflow.transaction():
                planner.plan_preauthorized_pool_recycle(
                    scope=settings.scope,
                    lease=lease,
                    actor_id="coordinator:deterministic-mitigation-policy",
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
        except MitigationPolicyError as error:
            # Invalid or ambiguous approved policy is a permanent, fail-closed
            # condition. Preserve a safe security event and use the explicit
            # INVESTIGATING escape hatch instead of leaving an immortal incident.
            reason = type(error).__name__
            with workflow.transaction(), connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO solvan.security_events
                      (organization_id, project_id, environment_id, id, event_type,
                       control, severity, actor_principal, incident_id, safe_summary)
                      SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                        %(security_event_id)s, 'MITIGATION_POLICY_REJECTED',
                        'INPUT_VALIDATOR', 'HIGH', %(actor)s, %(incident_id)s,
                        %(safe_summary)s
                      WHERE NOT EXISTS (
                        SELECT 1 FROM solvan.security_events
                        WHERE organization_id = %(organization_id)s
                          AND project_id = %(project_id)s
                          AND environment_id = %(environment_id)s
                          AND incident_id = %(incident_id)s
                          AND event_type = 'MITIGATION_POLICY_REJECTED')""",
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
                        transition_key="FAILURE_EXHAUSTED:MITIGATION_POLICY",
                        actor_type="POLICY_ENGINE",
                        actor_id=owner,
                        reason_code=reason,
                        rationale_summary=(
                            "Deterministic mitigation policy failed closed; operator "
                            "policy repair is required."
                        ),
                    ),
                )
                workflow.release_lease(scope=settings.scope, lease=lease)
