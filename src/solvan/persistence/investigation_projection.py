"""Typed agent context and durable Runtime dispatch projection helpers."""

from __future__ import annotations

from typing import Any

from solvan.application.investigation import InvestigationConflict, RuntimeDispatch
from solvan.domain import Scope, StepBudget


def agent_context(cursor: Any, scope: Scope, incident_id: str) -> dict[str, Any]:
    cursor.execute(
        """SELECT i.incident_class, i.severity, i.detected_at,
            i.production_graph_snapshot_id, s.id AS service_id,
            s.service_key, s.platform_kind, s.platform_resource,
            service_node.external_project_id AS target_external_project_id,
            service_node.attributes_json->>'region' AS target_workload_region,
            now() AS window_end,
            GREATEST(i.detected_at - interval '5 minutes',
                     now() - interval '15 minutes') AS window_start
          FROM solvan.incidents i
          JOIN solvan.services s
            ON (s.organization_id, s.project_id, s.environment_id, s.id)
             = (i.organization_id, i.project_id, i.environment_id,
                i.primary_service_id)
          LEFT JOIN solvan.production_graph_nodes service_node
            ON (service_node.organization_id, service_node.project_id,
                service_node.environment_id, service_node.snapshot_id)
             = (i.organization_id, i.project_id, i.environment_id,
                i.production_graph_snapshot_id)
           AND service_node.node_kind = 'SERVICE'
           AND service_node.resource_ref = s.platform_resource
          WHERE i.organization_id = %(organization_id)s
            AND i.project_id = %(project_id)s
            AND i.environment_id = %(environment_id)s
            AND i.id = %(incident_id)s""",
        {**scope.canonical_dict(), "incident_id": incident_id},
    )
    incident = cursor.fetchone()
    if incident is None:
        raise InvestigationConflict("agent input incident is unavailable")
    cursor.execute(
        """SELECT id FROM solvan.production_graph_nodes
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND snapshot_id = %(snapshot_id)s AND node_kind = 'DATABASE'
          ORDER BY id LIMIT 10""",
        {
            **scope.canonical_dict(),
            "snapshot_id": incident["production_graph_snapshot_id"],
        },
    )
    database_node_ids = [str(row["id"]) for row in cursor.fetchall()]
    cursor.execute(
        """SELECT id, content_ref, content_hash, classification
          FROM solvan.evidence_items
          WHERE organization_id = %(organization_id)s
            AND project_id = %(project_id)s
            AND environment_id = %(environment_id)s
            AND incident_id = %(incident_id)s
            AND freshness_expires_at > now()
          ORDER BY observed_at DESC, id DESC LIMIT 20""",
        {**scope.canonical_dict(), "incident_id": incident_id},
    )
    preserved_evidence = [
        {
            "evidence_ref": str(row["id"]),
            "content_ref": str(row["content_ref"]),
            "content_hash": str(row["content_hash"]),
            "classification": str(row["classification"]),
        }
        for row in cursor.fetchall()
    ]
    return {
        "incident_class": str(incident["incident_class"]),
        "severity": str(incident["severity"]),
        "service_id": str(incident["service_id"]),
        "service_key": str(incident["service_key"]),
        "platform_kind": str(incident["platform_kind"]),
        "platform_resource": str(incident["platform_resource"]),
        "target_external_project_id": (
            str(incident["target_external_project_id"])
            if incident["target_external_project_id"] is not None
            else None
        ),
        "target_workload_region": (
            str(incident["target_workload_region"])
            if incident["target_workload_region"] is not None
            else None
        ),
        "graph_snapshot_id": str(incident["production_graph_snapshot_id"]),
        "window_start": incident["window_start"].isoformat(),
        "window_end": incident["window_end"].isoformat(),
        "approved_log_view_id": "payments-errors",
        "approved_log_signature_key": "connection-exhaustion",
        "database_node_ids": database_node_ids,
        "preserved_evidence_refs": preserved_evidence,
        "approved_signal_kinds": [
            "HTTP_5XX_RATIO",
            "HTTP_P95_LATENCY",
            "SQL_CONNECTIONS",
        ],
    }


def dispatch_from_row(row: dict[str, Any]) -> RuntimeDispatch:
    return RuntimeDispatch(
        run_id=str(row["id"]),
        invocation_id=str(row["invocation_id"]),
        scope=Scope(
            str(row["organization_id"]),
            str(row["project_id"]),
            str(row["environment_id"]),
        ),
        incident_id=str(row["incident_id"]),
        plan_id=str(row["plan_id"]),
        plan_version=int(row["plan_version"]),
        step_id=str(row["step_id"]),
        step_key=str(row["step_key"]),
        logical_step_key=str(row["logical_step_key"]),
        agent_key=str(row["agent_key"]),
        agent_resource=str(row["agent_resource"]),
        agent_revision=str(row["agent_revision"]),
        scope_ref=str(row["scope_ref"]),
        purpose=str(row["purpose"]),
        allowed_tool_names=tuple(str(value) for value in row["allowed_tool_names_json"]),
        workflow_version=int(row["workflow_version"]),
        deadline=row["deadline"],
        budget=StepBudget(**row["budget_json"]),
        input_ref=str(row["input_ref"]),
        input_hash=str(row["input_hash"]),
        trace_id=str(row["trace_id"]),
        span_id=str(row["span_id"]),
        context=dict(row["input_context_json"]),
    )
