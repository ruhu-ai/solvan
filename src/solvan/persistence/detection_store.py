"""PostgreSQL persistence for approved detection rules and evaluation streaks."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.detection import (
    Comparator,
    DetectionEvaluation,
    DetectionRule,
    DetectionSourceBinding,
    sustained_streak,
)
from solvan.domain import Scope


class PostgresDetectionStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def load_approved_rules(self, *, scope: Scope) -> tuple[DetectionRule, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id, r.version, r.service_id, s.service_key,
                    g.id AS graph_snapshot_id, r.incident_class, r.signal_kind,
                    r.query_json, r.evaluation_interval_ms, r.comparator,
                    r.threshold, r.sustained_windows, r.severity,
                    r.deduplication_dimension, r.action_budget,
                    r.repeated_action_limit,
                    b.connection_id AS bound_connection_id,
                    b.connection_epoch AS bound_connection_epoch,
                    c.provider AS bound_provider,c.kind AS bound_kind,
                    c.authentication_mode AS bound_authentication_mode,
                    c.connection_epoch AS current_connection_epoch,
                    c.lifecycle AS connection_lifecycle,
                    c.availability AS connection_availability,
                    c.solvan_delegator_principal,c.customer_reader_principal,
                    c.token_lifetime_seconds,x.resource_kind,x.resource_id,
                    x.workload_region
                  FROM solvan.detection_rules r
                  JOIN solvan.services s
                    ON s.organization_id = r.organization_id
                   AND s.project_id = r.project_id
                   AND s.environment_id = r.environment_id
                   AND s.id = r.service_id
                  JOIN solvan.production_graph_snapshots g
                    ON g.organization_id = r.organization_id
                   AND g.project_id = r.project_id
                   AND g.environment_id = r.environment_id
                   AND g.status = 'APPROVED' AND g.superseded_at IS NULL
                  LEFT JOIN solvan_onboarding.detection_rule_connection_bindings b
                    ON (b.organization_id,b.project_id,b.environment_id,
                        b.detection_rule_id,b.detection_rule_version)=
                       (r.organization_id,r.project_id,r.environment_id,r.id,r.version)
                  LEFT JOIN solvan.tenant_connections c
                    ON (c.organization_id,c.project_id,c.environment_id,c.id)=
                       (b.organization_id,b.project_id,b.environment_id,b.connection_id)
                  LEFT JOIN solvan_onboarding.connection_external_resource_scopes x
                    ON (x.organization_id,x.project_id,x.environment_id,x.connection_id)=
                       (c.organization_id,c.project_id,c.environment_id,c.id)
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.status = 'APPROVED'
                  ORDER BY r.id, r.version""",
                scope.canonical_dict(),
            )
            return tuple(self._rule(row) for row in cursor.fetchall())

    def record_evaluation(
        self,
        *,
        scope: Scope,
        rule: DetectionRule,
        window_start: datetime,
        window_end: datetime,
        observed_value: float,
        query_receipt_ref: str,
        query_receipt_hash: str,
    ) -> tuple[bool, bool]:
        """Return ``(inserted, sustained)`` after an idempotent evaluation write."""

        matched = rule.matches(observed_value)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan.detection_evaluations
                  (organization_id, project_id, environment_id, rule_id, rule_version,
                   window_start, window_end, observed_value, threshold_matched,
                   query_receipt_ref, query_receipt_hash)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(rule_id)s, %(rule_version)s, %(window_start)s, %(window_end)s,
                    %(observed_value)s, %(threshold_matched)s,
                    %(query_receipt_ref)s, %(query_receipt_hash)s)
                  ON CONFLICT DO NOTHING RETURNING window_end""",
                {
                    **scope.canonical_dict(),
                    "rule_id": rule.rule_id,
                    "rule_version": rule.version,
                    "window_start": window_start,
                    "window_end": window_end,
                    "observed_value": observed_value,
                    "threshold_matched": matched,
                    "query_receipt_ref": query_receipt_ref,
                    "query_receipt_hash": query_receipt_hash,
                },
            )
            inserted = cursor.fetchone() is not None
            cursor.execute(
                """SELECT window_start, window_end, observed_value, threshold_matched
                  FROM solvan.detection_evaluations
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND rule_id = %(rule_id)s AND rule_version = %(rule_version)s
                    AND window_end <= %(window_end)s
                  ORDER BY window_end DESC LIMIT %(window_count)s""",
                {
                    **scope.canonical_dict(),
                    "rule_id": rule.rule_id,
                    "rule_version": rule.version,
                    "window_end": window_end,
                    "window_count": rule.sustained_windows + 1,
                },
            )
            evaluations = tuple(
                DetectionEvaluation(
                    window_start=row["window_start"],
                    window_end=row["window_end"],
                    observed_value=float(row["observed_value"]),
                    threshold_matched=bool(row["threshold_matched"]),
                )
                for row in cursor.fetchall()
            )
        sustained = sustained_streak(rule, evaluations)
        prior_was_matched = (
            len(evaluations) > rule.sustained_windows
            and evaluations[rule.sustained_windows].threshold_matched
        )
        return inserted, sustained and not prior_was_matched

    @staticmethod
    def _rule(row: dict[str, Any]) -> DetectionRule:
        source_binding: DetectionSourceBinding | None = None
        if row["bound_connection_id"] is not None:
            expected = (
                "CLOUD_MONITORING",
                "GCP_NATIVE",
                "GCP_SERVICE_ACCOUNT_IMPERSONATION",
                int(row["bound_connection_epoch"]),
                "ENABLED",
                "READY",
                "GCP_PROJECT",
            )
            observed = (
                row["bound_provider"],
                row["bound_kind"],
                row["bound_authentication_mode"],
                int(row["current_connection_epoch"]),
                row["connection_lifecycle"],
                row["connection_availability"],
                row["resource_kind"],
            )
            if observed != expected:
                raise ValueError("approved detection rule has a stale or ineligible connection")
            query = dict(row["query_json"])
            if query.get("gcp_project_id") != row["resource_id"]:
                raise ValueError("detection rule project does not match its bound connection")
            source_binding = DetectionSourceBinding(
                connection_id=str(row["bound_connection_id"]),
                connection_epoch=int(row["bound_connection_epoch"]),
                external_project_id=str(row["resource_id"]),
                workload_region=str(row["workload_region"]),
                solvan_delegator_principal=str(row["solvan_delegator_principal"]),
                customer_reader_principal=str(row["customer_reader_principal"]),
                token_lifetime_seconds=int(row["token_lifetime_seconds"]),
            )
        return DetectionRule(
            rule_id=str(row["id"]),
            version=int(row["version"]),
            service_id=str(row["service_id"]),
            service_key=str(row["service_key"]),
            graph_snapshot_id=str(row["graph_snapshot_id"]),
            incident_class=str(row["incident_class"]),
            signal_kind=str(row["signal_kind"]),
            query=dict(row["query_json"]),
            evaluation_interval_ms=int(row["evaluation_interval_ms"]),
            comparator=Comparator(str(row["comparator"])),
            threshold=float(row["threshold"]),
            sustained_windows=int(row["sustained_windows"]),
            severity=str(row["severity"]),
            deduplication_dimension=str(row["deduplication_dimension"]),
            action_budget=int(row["action_budget"]),
            repeated_action_limit=int(row["repeated_action_limit"]),
            source_binding=source_binding,
        )
