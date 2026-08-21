"""Atomic Alert Triage completion, predicate ledger, and Incident linking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.alert_disposition import select_alert_disposition
from solvan.application.alert_predicates import (
    PredicateFact,
    evaluate_predicate_expression,
    validated_predicate_fact,
)
from solvan.application.alert_triage import PredicateExpressionV1, SeverityMappingV1
from solvan.application.ports import IncidentDisposition, IncidentOpenRequest
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_liaison import record_alert_disposition_event
from solvan.persistence.alert_triage_scheduling import _fence_failure
from solvan.persistence.alert_triage_scheduling_types import AlertSchedulingError
from solvan.persistence.postgres import PostgresWorkflowStore


@dataclass(frozen=True, slots=True)
class AlertTriageCompletion:
    triage_run_id: str
    disposition_id: str
    disposition: str
    incident_id: str | None
    incident_link_kind: str | None


class AlertTriageCompletionMixin:
    _connection: Connection[Any]

    def complete_alert_triage(
        self,
        *,
        scope: Scope,
        triage_run_id: str,
        claim_token: str,
        claim_epoch: int,
        result_ref: str,
        result_hash: str,
        completed_at: datetime | None = None,
    ) -> AlertTriageCompletion:
        """Commit a typed result once; model output cannot select the disposition."""

        moment = completed_at or datetime.now(UTC)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("Alert completion time must be timezone-aware")
        if not result_hash.startswith("sha256:") or len(result_hash) != 71:
            raise ValueError("Alert result hash must be typed")
        values = {
            **scope.canonical_dict(),
            "triage_run_id": triage_run_id,
            "claim_token": claim_token,
            "claim_epoch": claim_epoch,
            "result_ref": result_ref,
            "result_hash": result_hash,
            "completed_at": moment,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            run = self._locked_run(cursor=cursor, values=values)
            if run is None:
                prior = self._completed_run(cursor=cursor, values=values)
                if prior is not None:
                    return prior
                raise AlertSchedulingError("ALERT_CLAIM_STALE")
            fence = _fence_failure(run)
            if fence is not None:
                raise AlertSchedulingError(f"ALERT_COMPLETION_FENCE_FAILED:{fence}")
            facts = self._resolve_committed_facts(cursor=cursor, run=run, moment=moment)
            evaluation = self._evaluate(run=run, facts=facts, moment=moment)
            decision = select_alert_disposition(mode=run["mode"], evaluation=evaluation)
            self._persist_predicates(
                cursor=cursor, values=values, evaluation=evaluation, moment=moment
            )
            cursor.execute(
                """SELECT id FROM solvan.evidence_items
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND alert_episode_id=%(episode_id)s
                      AND created_by_agent_run_id=%(agent_run_id)s
                    ORDER BY ingested_at,id""",
                {**values, "episode_id": run["episode_id"], "agent_run_id": run["agent_run_id"]},
            )
            run_evidence_refs = tuple(str(row["id"]) for row in cursor.fetchall())
            incident_id: str | None = None
            link_kind: str | None = None
            if decision.should_open_incident:
                incident_id, link_kind = self._open_incident(cursor=cursor, scope=scope, run=run)
            disposition = "ESCALATED_ATTACHED" if link_kind == "ATTACHED" else decision.disposition
            disposition_id = new_identifier("ads")
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_dispositions
                    (organization_id,project_id,environment_id,id,episode_id,
                     triage_run_id,disposition,reason_code,explanation_template_ref,
                     explanation_variables_json,evidence_refs_json,next_owner,
                     next_review_at,created_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(disposition_id)s,%(episode_id)s,%(triage_run_id)s,%(disposition)s,
                     %(reason_code)s,%(template_ref)s,%(variables)s,%(evidence_refs)s,
                     %(next_owner)s,%(next_review_at)s,%(completed_at)s)""",
                {
                    **values,
                    "disposition_id": disposition_id,
                    "episode_id": run["episode_id"],
                    "disposition": disposition,
                    "reason_code": decision.reason_code,
                    "template_ref": f"alert-disposition:{decision.reason_code}@1",
                    "variables": Jsonb({"episode_id": run["episode_id"]}),
                    "evidence_refs": Jsonb(
                        sorted(
                            set(run_evidence_refs)
                            | {
                                ref
                                for node in (() if evaluation is None else evaluation.node_results)
                                for ref in node.input_refs
                            }
                        )
                    ),
                    "next_owner": ("incident-coordinator" if incident_id else "service-owner"),
                    "next_review_at": None,
                },
            )
            if incident_id is not None and link_kind is not None:
                cursor.execute(
                    """INSERT INTO solvan_alerts.alert_incident_links
                        (organization_id,project_id,environment_id,episode_id,
                         disposition_id,incident_id,link_kind,deduplication_decision)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                         %(episode_id)s,%(disposition_id)s,%(incident_id)s,
                         %(link_kind)s,%(deduplication_decision)s)""",
                    {
                        **values,
                        "episode_id": run["episode_id"],
                        "disposition_id": disposition_id,
                        "incident_id": incident_id,
                        "link_kind": link_kind,
                        "deduplication_decision": link_kind,
                    },
                )
            self._finish_runtime(
                cursor=cursor,
                values=values,
                run=run,
                disposition_id=disposition_id,
                disposition=disposition,
                incident_id=incident_id,
            )
            record_alert_disposition_event(
                self._connection,
                scope=scope,
                episode_id=str(run["episode_id"]),
                disposition_id=disposition_id,
                disposition=disposition,
                occurred_at=moment,
            )
        return AlertTriageCompletion(
            triage_run_id, disposition_id, disposition, incident_id, link_kind
        )

    @staticmethod
    def _locked_run(*, cursor: Any, values: dict[str, Any]) -> dict[str, Any] | None:
        cursor.execute(
            """SELECT run.*,episode.provider_generation_id,
                      episode.provider_state_projection,episode.first_source_time,
                      episode.last_source_time,event.provider_severity,event.lifecycle_state,
                      event.resource_type,event.normalized_labels_json,
                      subtype.mode,subtype.escalation_expression_json,
                      subtype.full_incident_admission_expression_json,
                      subtype.severity_mapping_json,subtype.incident_class,
                      subtype.calibration_receipt_refs_json,
                      policy.action_budget,policy.repeated_action_limit,
                      head.policy_hash AS current_policy_hash,
                      head.head_epoch AS current_head_epoch,
                      head.placement_epoch AS current_head_placement_epoch,
                      lifecycle.availability AS policy_availability,
                      graph.snapshot_id AS current_graph_snapshot_id,
                      graph.snapshot_version AS current_graph_snapshot_version,
                      graph.cell_id AS current_cell_id,
                      graph.placement_epoch AS current_placement_epoch
                 FROM solvan_alerts.alert_triage_runs run
                 JOIN solvan_alerts.alert_episodes episode
                   ON (episode.organization_id,episode.project_id,episode.environment_id,
                       episode.id)=(run.organization_id,run.project_id,
                       run.environment_id,run.episode_id)
                 JOIN solvan_alerts.alert_events event
                   ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                      (run.organization_id,run.project_id,run.environment_id,
                       run.semantic_event_id)
                 JOIN solvan_alerts.alert_policy_revisions subtype
                   ON (subtype.organization_id,subtype.project_id,subtype.environment_id,
                       subtype.policy_key,subtype.policy_version,subtype.policy_hash)=
                      (run.organization_id,run.project_id,run.environment_id,
                       run.policy_key,run.policy_version,run.policy_hash)
                 JOIN solvan_operability.trigger_policy_revisions policy
                   ON (policy.organization_id,policy.project_id,policy.environment_id,
                       policy.policy_key,policy.version,policy.policy_hash)=
                      (run.organization_id,run.project_id,run.environment_id,
                       run.policy_key,run.policy_version,run.policy_hash)
                 LEFT JOIN solvan_operability.trigger_policy_current_heads head
                   ON (head.organization_id,head.project_id,head.environment_id,
                       head.policy_key,head.policy_version)=
                      (run.organization_id,run.project_id,run.environment_id,
                       run.policy_key,run.policy_version) AND head.is_current
                 LEFT JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle
                   ON (lifecycle.organization_id,lifecycle.project_id,
                       lifecycle.environment_id,lifecycle.policy_key,
                       lifecycle.policy_version,lifecycle.policy_hash)=
                      (run.organization_id,run.project_id,run.environment_id,
                       run.policy_key,run.policy_version,run.policy_hash)
                 LEFT JOIN solvan_graph.graph_read_current(
                   run.organization_id,run.project_id,run.environment_id) graph ON true
                WHERE run.organization_id=%(organization_id)s
                  AND run.project_id=%(project_id)s
                  AND run.environment_id=%(environment_id)s
                  AND run.id=%(triage_run_id)s
                  AND run.claim_token=%(claim_token)s::uuid
                  AND run.claim_epoch=%(claim_epoch)s
                  AND run.status IN ('CLAIMED','DISPATCHED','RUNNING')
                  AND run.claim_expires_at>clock_timestamp()
                FOR UPDATE OF run,episode""",
            values,
        )
        row = cursor.fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _resolve_committed_facts(
        *, cursor: Any, run: dict[str, Any], moment: datetime
    ) -> dict[str, PredicateFact]:
        material = (
            run["escalation_expression_json"]
            if run["mode"] == "POLICY_ESCALATED"
            else run["full_incident_admission_expression_json"]
            if run["mode"] == "FULL_INCIDENT"
            else None
        )
        if material is None:
            return {}
        expression = PredicateExpressionV1.model_validate(material)
        application_nodes = tuple(
            node for node in expression.nodes if node.kind == "APPLICATION_FACT"
        )
        if not application_nodes:
            return {}
        cursor.execute(
            """SELECT id,content_hash,observed_at,freshness_expires_at,provenance_json
                 FROM solvan.evidence_items
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND alert_episode_id=%(episode_id)s
                  AND created_by_agent_run_id=%(agent_run_id)s
                  AND freshness_expires_at>%(evaluated_at)s
                ORDER BY observed_at DESC,id DESC""",
            {
                "organization_id": run["organization_id"],
                "project_id": run["project_id"],
                "environment_id": run["environment_id"],
                "episode_id": run["episode_id"],
                "agent_run_id": run["agent_run_id"],
                "evaluated_at": moment,
            },
        )
        evidence_rows = tuple(dict(row) for row in cursor.fetchall())
        facts: dict[str, PredicateFact] = {}
        for node in application_nodes:
            for evidence in evidence_rows:
                fact = validated_predicate_fact(
                    node,
                    evidence_record=evidence,
                    expected_environment_id=str(run["environment_id"]),
                    expected_provider_generation_id=str(run["provider_generation_id"]),
                    expected_graph_snapshot_id=str(run["graph_snapshot_id"]),
                    expected_target_node_key=str(run["target_node_key"]),
                    expected_target_node_version=str(run["target_node_version"]),
                    allowed_calibration_receipt_refs=tuple(
                        str(ref) for ref in run["calibration_receipt_refs_json"]
                    ),
                    evaluated_at=moment,
                )
                if fact is not None:
                    facts[node.node_id] = fact
                    break
        return facts

    @staticmethod
    def _completed_run(*, cursor: Any, values: dict[str, Any]) -> AlertTriageCompletion | None:
        cursor.execute(
            """SELECT run.id,disposition.id AS disposition_id,
                      disposition.disposition,link.incident_id,link.link_kind
                 FROM solvan_alerts.alert_triage_runs run
                 JOIN solvan_alerts.alert_dispositions disposition
                   ON (disposition.organization_id,disposition.project_id,
                       disposition.environment_id,disposition.triage_run_id)=
                      (run.organization_id,run.project_id,run.environment_id,run.id)
                 LEFT JOIN solvan_alerts.alert_incident_links link
                   ON (link.organization_id,link.project_id,link.environment_id,
                       link.disposition_id)=(disposition.organization_id,
                       disposition.project_id,disposition.environment_id,disposition.id)
                WHERE run.organization_id=%(organization_id)s
                  AND run.project_id=%(project_id)s
                  AND run.environment_id=%(environment_id)s
                  AND run.id=%(triage_run_id)s AND run.status='SUCCEEDED'
                  AND run.claim_epoch=%(claim_epoch)s
                  AND run.agent_run_id IN (
                    SELECT id FROM solvan.agent_runs
                     WHERE organization_id=%(organization_id)s
                       AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s
                       AND output_hash=%(result_hash)s)
                ORDER BY disposition.created_at,disposition.id LIMIT 1""",
            values,
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return AlertTriageCompletion(
            str(row["id"]),
            str(row["disposition_id"]),
            str(row["disposition"]),
            None if row["incident_id"] is None else str(row["incident_id"]),
            None if row["link_kind"] is None else str(row["link_kind"]),
        )

    @staticmethod
    def _evaluate(*, run: dict[str, Any], facts: dict[str, PredicateFact], moment: datetime) -> Any:
        material = (
            run["escalation_expression_json"]
            if run["mode"] == "POLICY_ESCALATED"
            else run["full_incident_admission_expression_json"]
            if run["mode"] == "FULL_INCIDENT"
            else None
        )
        if material is None:
            return None
        expression = PredicateExpressionV1.model_validate(material)
        return evaluate_predicate_expression(
            expression,
            source_fields={
                "source_state": run["provider_state_projection"],
                "provider_severity": run["provider_severity"],
                "lifecycle_state": run["lifecycle_state"],
                "resource_type": run["resource_type"],
                "normalized_labels": run["normalized_labels_json"],
                "first_source_at": run["first_source_time"],
                "last_source_at": run["last_source_time"],
            },
            committed_facts=facts,
            evaluated_at=moment,
        )

    @staticmethod
    def _persist_predicates(
        *, cursor: Any, values: dict[str, Any], evaluation: Any, moment: datetime
    ) -> None:
        if evaluation is None:
            return
        for node in evaluation.node_results:
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_predicate_results
                    (organization_id,project_id,environment_id,id,triage_run_id,
                     predicate_node_id,predicate_kind,input_refs_json,input_hash,
                     result,reason_code,evaluated_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(predicate_id)s,%(triage_run_id)s,%(node_id)s,%(kind)s,
                     %(input_refs)s,%(input_hash)s,%(result)s,%(reason_code)s,
                     %(evaluated_at)s)""",
                {
                    **values,
                    "predicate_id": new_identifier("apr"),
                    "node_id": node.node_id,
                    "kind": node.kind,
                    "input_refs": Jsonb(node.input_refs),
                    "input_hash": node.input_hash,
                    "result": str(node.verdict),
                    "reason_code": node.reason_code,
                    "evaluated_at": moment,
                },
            )

    def _open_incident(self, *, cursor: Any, scope: Scope, run: dict[str, Any]) -> tuple[str, str]:
        cursor.execute(
            """SELECT service.id
                 FROM solvan_graph.graph_nodes target
                 JOIN solvan.services service
                   ON (service.organization_id,service.project_id,
                       service.environment_id,service.platform_resource)=
                      (target.organization_id,target.project_id,
                       target.environment_id,target.resource_ref)
                  AND service.lifecycle='ACTIVE'
                WHERE target.organization_id=%(organization_id)s
                  AND target.project_id=%(project_id)s
                  AND target.environment_id=%(environment_id)s
                  AND target.cell_id=%(cell_id)s
                  AND target.placement_epoch=%(placement_epoch)s
                  AND target.snapshot_id=%(graph_snapshot_id)s
                  AND target.node_key=%(target_node_key)s
                  AND target.node_kind='SERVICE'""",
            {
                **scope.canonical_dict(),
                "cell_id": run["cell_id"],
                "placement_epoch": run["placement_epoch"],
                "graph_snapshot_id": run["graph_snapshot_id"],
                "target_node_key": run["target_node_key"],
            },
        )
        services = cursor.fetchall()
        if len(services) != 1:
            raise AlertSchedulingError("ALERT_TARGET_SERVICE_UNRESOLVED")
        service = services[0]
        severity = next(
            (
                entry.solvan_severity
                for entry in SeverityMappingV1.model_validate(run["severity_mapping_json"]).entries
                if entry.provider_value == run["provider_severity"]
            ),
            None,
        )
        if severity is None:
            raise AlertSchedulingError("ALERT_SEVERITY_UNMAPPED")
        result = PostgresWorkflowStore(self._connection).open_or_attach_incident(
            scope=scope,
            request=IncidentOpenRequest(
                state_machine_version="1",
                severity=severity,
                incident_class=str(run["incident_class"]),
                primary_service_id=str(service["id"]),
                production_graph_snapshot_id=str(run["graph_snapshot_id"]),
                detected_at=run["first_source_time"],
                detection_rule_id=None,
                detection_rule_version=None,
                deduplication_key=(
                    f"{run['policy_key']}:{run['target_node_key']}:"
                    f"{str(run['episode_id']).removeprefix('ale_')}"
                ),
                action_budget=int(run["action_budget"]),
                repeated_action_limit=int(run["repeated_action_limit"]),
                trigger_policy_key=str(run["policy_key"]),
                trigger_policy_version=str(run["policy_version"]),
            ),
        )
        return result.incident_id, (
            "CREATED" if result.disposition is IncidentDisposition.CREATED else "ATTACHED"
        )

    @staticmethod
    def _finish_runtime(
        *,
        cursor: Any,
        values: dict[str, Any],
        run: dict[str, Any],
        disposition_id: str,
        disposition: str,
        incident_id: str | None,
    ) -> None:
        cursor.execute(
            """UPDATE solvan_alerts.alert_triage_runs
                  SET status='SUCCEEDED',claim_token=NULL,claim_expires_at=NULL,
                      completed_at=%(completed_at)s,row_version=row_version+1
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND id=%(triage_run_id)s AND claim_epoch=%(claim_epoch)s""",
            values,
        )
        cursor.execute(
            """UPDATE solvan.agent_runs
                  SET status='SUCCEEDED',output_ref=%(result_ref)s,
                      output_hash=%(result_hash)s,completed_at=%(completed_at)s
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(agent_run_id)s
                  AND status IN ('CREATED','DISPATCHED','RUNNING')""",
            {**values, "agent_run_id": run["agent_run_id"]},
        )
        cursor.execute(
            """UPDATE solvan_alerts.alert_episodes
                  SET state=%(state)s,current_disposition=%(disposition)s,
                      row_version=row_version+1
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(episode_id)s""",
            {
                **values,
                "episode_id": run["episode_id"],
                "state": (
                    "ATTACHED"
                    if disposition == "ESCALATED_ATTACHED"
                    else "ESCALATED"
                    if incident_id is not None
                    else "TRIAGED"
                    if disposition == "TRIAGED_HOLD"
                    else "BLOCKED"
                ),
                "disposition": disposition,
            },
        )
        cursor.execute(
            """UPDATE solvan_scale.tenant_dispatch_queue
                  SET state='COMPLETED',claim_token=NULL,lease_expires_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND work_id=%(work_id)s
                  AND claim_token=%(claim_token)s::uuid""",
            {**values, "work_id": run["work_id"]},
        )
        cursor.execute(
            """UPDATE solvan_scale.tenant_work_registry SET state='TERMINAL'
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND work_kind='AGENT_RUN' AND work_id=%(work_id)s""",
            {**values, "work_id": run["work_id"]},
        )
        cursor.execute(
            """UPDATE solvan_scale.tenant_capacity_reservations
                  SET status='SETTLED',terminal_at=%(completed_at)s
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND reservation_id=%(reservation_id)s AND status='STARTED'
              RETURNING organization_id,policy_version,resource_kind""",
            {**values, "reservation_id": run["capacity_reservation_id"]},
        )
        reservation = cursor.fetchone()
        if reservation is None:
            raise AlertSchedulingError("ALERT_CAPACITY_SETTLEMENT_STALE")
        cursor.execute(
            """UPDATE solvan_scale.tenant_quota_counters
                  SET active_reservations=active_reservations-1,counter_epoch=counter_epoch+1
                WHERE organization_id=%(organization_id)s
                  AND policy_version=%(policy_version)s
                  AND resource_kind=%(resource_kind)s AND active_reservations>0""",
            reservation,
        )
        if cursor.rowcount != 1:
            raise AlertSchedulingError("ALERT_CAPACITY_COUNTER_STALE")
