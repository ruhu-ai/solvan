"""Incident-related Alert projection and explicit verification associations."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_policy_errors import AlertPolicyProductError


class AlertRelatedProjectionMixin:
    _connection: Connection[Any]

    def get_incident_related_alerts(
        self, *, scope: Scope, incident_id: str
    ) -> dict[str, Any] | None:
        values = {**scope.canonical_dict(), "incident_id": incident_id}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT workflow_version,updated_at FROM solvan.incidents
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(incident_id)s""",
                values,
            )
            incident = cursor.fetchone()
            if incident is None:
                return None
            cursor.execute(
                """SELECT episode.id AS alert_episode_id,
                          episode.provider_incident_key,episode.target_node_key,
                          episode.provider_state_projection AS provider_state,
                          episode.last_source_time AS source_freshness_at,
                          severity.value->>'solvan_severity' AS severity,
                          disposition.disposition,disposition.reason_code,
                          link.link_kind AS relation,link.disposition_id AS link_disposition_ref,
                          link.linked_at,link.deduplication_decision,
                          verification.id AS verification_ref,verification.verdict
                     FROM solvan_alerts.alert_incident_links link
                     JOIN solvan_alerts.alert_episodes episode
                       ON (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.id)=(link.organization_id,link.project_id,
                           link.environment_id,link.episode_id)
                     JOIN solvan_alerts.alert_dispositions disposition
                       ON (disposition.organization_id,disposition.project_id,
                           disposition.environment_id,disposition.id)=
                          (link.organization_id,link.project_id,link.environment_id,
                           link.disposition_id)
                     JOIN solvan_alerts.alert_policy_revisions policy
                       ON (policy.organization_id,policy.project_id,policy.environment_id,
                           policy.policy_key,policy.policy_version,policy.policy_hash)=
                          (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.policy_key,episode.policy_version,episode.policy_hash)
                     JOIN solvan_alerts.alert_events event
                       ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                          (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.last_event_id)
                     JOIN LATERAL jsonb_array_elements(
                       policy.severity_mapping_json->'entries') severity
                       ON severity.value->>'provider_value'=event.provider_severity
                     LEFT JOIN LATERAL (
                       SELECT candidate.id,candidate.verdict
                         FROM solvan_alerts.alert_recovery_verification_links adjudication
                         JOIN solvan.verification_runs candidate
                           ON (candidate.organization_id,candidate.project_id,
                               candidate.environment_id,candidate.id)=
                              (adjudication.organization_id,adjudication.project_id,
                               adjudication.environment_id,adjudication.verification_run_id)
                        WHERE adjudication.organization_id=link.organization_id
                          AND adjudication.project_id=link.project_id
                          AND adjudication.environment_id=link.environment_id
                          AND adjudication.episode_id=link.episode_id
                          AND adjudication.incident_id=link.incident_id
                        ORDER BY adjudication.linked_at DESC,adjudication.id DESC LIMIT 1
                     ) verification ON true
                    WHERE link.organization_id=%(organization_id)s
                      AND link.project_id=%(project_id)s
                      AND link.environment_id=%(environment_id)s
                      AND link.incident_id=%(incident_id)s
                    ORDER BY link.linked_at,episode.id""",
                values,
            )
            rows = [self._related_alert_row(dict(row)) for row in cursor.fetchall()]
            cursor.execute("SELECT clock_timestamp() AS now")
            clock = cursor.fetchone()
        result = {
            "schema_version": 1,
            "incident_id": incident_id,
            "incident_row_version": int(incident["workflow_version"]),
            "rows": rows,
            "next_cursor": None,
            "freshness_at": clock["now"].isoformat() if clock is not None else None,
            "placement_epoch": 0,
            "membership_epoch": 0,
        }
        result["projection_digest"] = canonical_sha256(result)
        return result

    def record_alert_recovery_verification(
        self,
        *,
        scope: Scope,
        episode_id: str,
        incident_id: str,
        verification_run_id: str,
        projection_service_ref: str,
        retention_policy_revision: str,
    ) -> str:
        """Associate one committed verifier result with one related Alert."""

        link_id = new_identifier("arv")
        values = {
            **scope.canonical_dict(),
            "id": link_id,
            "episode_id": episode_id,
            "incident_id": incident_id,
            "verification_run_id": verification_run_id,
            "projection_service_ref": projection_service_ref,
            "retention_policy_revision": retention_policy_revision,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_recovery_verification_links
                    (organization_id,project_id,environment_id,id,episode_id,incident_id,
                     verification_run_id,cell_id,placement_epoch,projection_service_ref,
                     classification,retention_policy_revision)
                   SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                          link.episode_id,link.incident_id,%(verification_run_id)s,
                          episode.cell_id,episode.placement_epoch,%(projection_service_ref)s,
                          episode.classification,%(retention_policy_revision)s
                     FROM solvan_alerts.alert_incident_links link
                     JOIN solvan_alerts.alert_episodes episode
                       ON (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.id)=(link.organization_id,link.project_id,
                           link.environment_id,link.episode_id)
                     JOIN solvan.verification_runs verification
                       ON verification.organization_id=link.organization_id
                      AND verification.project_id=link.project_id
                      AND verification.environment_id=link.environment_id
                      AND verification.id=%(verification_run_id)s
                      AND verification.incident_id=link.incident_id
                    WHERE link.organization_id=%(organization_id)s
                      AND link.project_id=%(project_id)s
                      AND link.environment_id=%(environment_id)s
                      AND link.episode_id=%(episode_id)s
                      AND link.incident_id=%(incident_id)s
                   ON CONFLICT (organization_id,project_id,environment_id,
                                episode_id,verification_run_id) DO NOTHING
                   RETURNING id""",
                values,
            )
            row = cursor.fetchone()
            if row is not None:
                return str(row["id"])
            cursor.execute(
                """SELECT id FROM solvan_alerts.alert_recovery_verification_links
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND episode_id=%(episode_id)s
                      AND verification_run_id=%(verification_run_id)s""",
                values,
            )
            existing = cursor.fetchone()
            if existing is None:
                raise AlertPolicyProductError("ALERT_VERIFICATION_LINK_INELIGIBLE")
            return str(existing["id"])

    @staticmethod
    def _related_alert_row(row: dict[str, Any]) -> dict[str, Any]:
        verdict = row.get("verdict")
        recovery = {
            None: "NOT_ADJUDICATED",
            "VERIFIED": "INDEPENDENTLY_VERIFIED",
            "FAILED": "FAILED",
            "INCONCLUSIVE": "INCONCLUSIVE",
        }[verdict]
        return {
            "alert_episode_id": row["alert_episode_id"],
            "safe_title": f"{row['provider_incident_key']} on {row['target_node_key']}",
            "severity": row["severity"],
            "target_label": row["target_node_key"],
            "provider_state": row["provider_state"],
            "provider_status_label": (
                "PROVIDER_REPORTED_CLEARED"
                if row["provider_state"] == "CLOSED"
                else "ACTIVE_AT_SOURCE"
            ),
            "disposition": row["disposition"],
            "disposition_label": row["reason_code"],
            "source_freshness_at": row["source_freshness_at"].isoformat(),
            "relation": row["relation"],
            "link_disposition_ref": row["link_disposition_ref"],
            "linked_at": row["linked_at"].isoformat(),
            "deduplication_decision_ref": row["deduplication_decision"],
            "recovery_status": recovery,
            "verification_ref": row["verification_ref"],
        }
