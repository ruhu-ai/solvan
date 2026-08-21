"""Alert-specific predicate context at the governed evidence boundary."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.alert_predicates import RegisteredAlertPredicateContext
from solvan.persistence.evidence_types import EvidenceToolReservation


class AlertPredicateEvidenceMixin:
    _connection: Connection[Any]

    def registered_alert_predicate_context(
        self, *, reservation: EvidenceToolReservation
    ) -> RegisteredAlertPredicateContext | None:
        """Resolve the one frozen Alert context allowed to mint an S1 fact."""

        if reservation.alert_episode_id is None:
            return None
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT run.environment_id,episode.provider_generation_id,
                          episode.provider_state_projection,run.graph_snapshot_id,
                          run.target_node_key,run.target_node_version,
                          subtype.escalation_expression_json,
                          subtype.calibration_receipt_refs_json,
                          rule.id AS rule_id,rule.version AS rule_version,
                          rule.signal_kind,rule.comparator,rule.threshold,
                          rule.query_json,rule.calibration_receipt_ref
                     FROM solvan_alerts.alert_triage_runs run
                     JOIN solvan_alerts.alert_episodes episode
                       ON (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.id)=
                          (run.organization_id,run.project_id,
                           run.environment_id,run.episode_id)
                     JOIN solvan_alerts.alert_policy_revisions subtype
                       ON (subtype.organization_id,subtype.project_id,
                           subtype.environment_id,subtype.policy_key,
                           subtype.policy_version,subtype.policy_hash)=
                          (run.organization_id,run.project_id,run.environment_id,
                           run.policy_key,run.policy_version,run.policy_hash)
                     JOIN solvan.detection_rules rule
                       ON (rule.organization_id,rule.project_id,rule.environment_id,
                           rule.service_id)=
                          (run.organization_id,run.project_id,run.environment_id,
                           %(service_id)s)
                      AND rule.id='payments-http-5xx-v1' AND rule.version=1
                     JOIN solvan_graph.graph_nodes target
                       ON (target.organization_id,target.project_id,
                           target.environment_id,target.cell_id,
                           target.placement_epoch,target.snapshot_id,target.node_key)=
                          (run.organization_id,run.project_id,run.environment_id,
                           run.cell_id,run.placement_epoch,run.graph_snapshot_id,
                           run.target_node_key)
                      AND target.node_kind='SERVICE'
                    WHERE run.organization_id=%(organization_id)s
                      AND run.project_id=%(project_id)s
                      AND run.environment_id=%(environment_id)s
                      AND run.agent_run_id=%(run_id)s
                      AND run.episode_id=%(alert_episode_id)s
                      AND run.graph_snapshot_id=%(graph_snapshot_id)s
                      AND target.resource_ref=%(platform_resource)s
                      AND target.external_project_id=%(service_project_id)s
                      AND run.status IN ('DISPATCHED','RUNNING')
                      AND subtype.mode='POLICY_ESCALATED'
                      AND rule.status='APPROVED'
                      AND rule.signal_kind='HTTP_5XX_RATIO'
                      AND rule.comparator='GT'
                      AND rule.calibration_receipt_ref IS NOT NULL
                      AND subtype.calibration_receipt_refs_json
                            ? rule.calibration_receipt_ref""",
                {
                    **reservation.scope.canonical_dict(),
                    "run_id": reservation.run_id,
                    "alert_episode_id": reservation.alert_episode_id,
                    "graph_snapshot_id": reservation.graph_snapshot_id,
                    "service_id": reservation.service_id,
                    "platform_resource": reservation.platform_resource,
                    "service_project_id": reservation.service_project_id,
                },
            )
            rows = cursor.fetchall()
        if len(rows) != 1:
            return None
        row = rows[0]
        query = row["query_json"]
        if not isinstance(query, dict):
            return None
        window_ms = query.get("window_ms")
        expected_resource = reservation.platform_resource.rstrip("/").rsplit("/", 1)[-1]
        if (
            type(window_ms) is not int
            or window_ms <= 0
            or query.get("synthetic_fixture") is not True
            or query.get("gcp_project_id") != reservation.service_project_id
            or query.get("resource_name") != expected_resource
        ):
            return None
        expression = row["escalation_expression_json"]
        calibration_ref = row["calibration_receipt_ref"]
        if not isinstance(expression, dict) or not isinstance(calibration_ref, str):
            return None
        return RegisteredAlertPredicateContext(
            environment_id=str(row["environment_id"]),
            provider_generation_id=str(row["provider_generation_id"]),
            provider_state=str(row["provider_state_projection"]),
            graph_snapshot_id=str(row["graph_snapshot_id"]),
            target_node_key=str(row["target_node_key"]),
            target_node_version=str(row["target_node_version"]),
            expression=expression,
            rule_ref=f"{row['rule_id']}@{row['rule_version']}",
            signal_kind=str(row["signal_kind"]),
            comparator=str(row["comparator"]),
            threshold=float(row["threshold"]),
            window_ms=window_ms,
            calibration_receipt_ref=calibration_ref,
            synthetic=True,
        )
