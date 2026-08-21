"""Turn one governed trigger firing into canonical coordinator incident input."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.incidents import (
    CanonicalTriggerIncidentEvent,
    DetectionContractError,
)
from solvan.domain import Scope


def canonical_trigger_firing(
    connection: Connection[Any], *, scope: Scope, firing_id: str
) -> CanonicalTriggerIncidentEvent:
    """Resolve incident material from the frozen policy and approved graph.

    No source payload or model supplies service identity, graph snapshot,
    severity, deduplication, or action budgets at coordinator time.
    """

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT f.source_observed_at,p.policy_key,p.version,p.incident_class,
                      p.severity,p.deduplication_dimension,p.action_budget,
                      p.repeated_action_limit,s.id AS graph_snapshot_id,
                      service.id AS service_id
                 FROM solvan_operability.trigger_firings f
                 JOIN solvan_operability.trigger_policy_revisions p ON
                   (p.organization_id,p.project_id,p.environment_id,p.policy_key,p.version)=
                   (f.organization_id,f.project_id,f.environment_id,
                    f.policy_key,f.policy_version)
                 JOIN solvan.production_graph_snapshots s ON
                   (s.organization_id,s.project_id,s.environment_id)=
                   (f.organization_id,f.project_id,f.environment_id)
                  AND s.status='APPROVED' AND s.superseded_at IS NULL
                 JOIN solvan.production_graph_nodes n ON
                   (n.organization_id,n.project_id,n.environment_id,n.snapshot_id)=
                   (s.organization_id,s.project_id,s.environment_id,s.id)
                  AND n.node_key=f.target_key
                 JOIN solvan.services service ON
                   (service.organization_id,service.project_id,service.environment_id)=
                   (n.organization_id,n.project_id,n.environment_id)
                  AND service.platform_resource=n.resource_ref
                WHERE f.organization_id=%(organization_id)s
                  AND f.project_id=%(project_id)s
                  AND f.environment_id=%(environment_id)s
                  AND f.id=%(firing_id)s AND f.status='ENQUEUED'
                  AND p.lifecycle='APPROVED'""",
            {**scope.canonical_dict(), "firing_id": firing_id},
        )
        row = cursor.fetchone()
    if row is None:
        raise DetectionContractError(
            "trigger firing lacks a current approved policy, graph target, or service binding"
        )
    observed_at = row["source_observed_at"]
    return CanonicalTriggerIncidentEvent(
        policy_key=str(row["policy_key"]),
        policy_version=str(row["version"]),
        service_id=str(row["service_id"]),
        graph_snapshot_id=str(row["graph_snapshot_id"]),
        incident_class=str(row["incident_class"]),
        deduplication_dimension=str(row["deduplication_dimension"]),
        observed_at=observed_at,
        severity=str(row["severity"]),
        action_budget=int(row["action_budget"]),
        repeated_action_limit=int(row["repeated_action_limit"]),
    )
