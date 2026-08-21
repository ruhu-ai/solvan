"""Cloud SQL authority for Alert policy product surfaces."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.alert_policy_products import (
    AlertPolicyRecommendationDismissV1,
    AlertPolicySimulationCommandV1,
    AlertPolicyTemplateV1,
    operator_mode_explanation,
    operator_mode_label,
)
from solvan.application.alert_predicates import evaluate_predicate_expression
from solvan.application.alert_triage import PredicateExpressionV1
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_policy_errors import AlertPolicyProductError
from solvan.persistence.alert_related_projection import AlertRelatedProjectionMixin


class AlertPolicyProductMixin(AlertRelatedProjectionMixin):
    _connection: Connection[Any]

    def list_alert_policy_templates(self, *, scope: Scope) -> dict[str, Any]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT template_key,template_version AS version,publisher_ref,
                          policy_skeleton_json AS policy_skeleton,
                          calibration_slots_json AS calibration_slots,
                          example_values_json AS example_values,
                          compatibility_range AS compatibility,content_digest,lifecycle,
                          created_at,retired_at
                     FROM solvan_alerts.alert_policy_templates
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY template_key,template_version""",
                scope.canonical_dict(),
            )
            rows = [self._jsonable_row(dict(row)) for row in cursor.fetchall()]
        for row in rows:
            row["example_values_label"] = "EXAMPLE — NOT A DEFAULT"
            row["creates"] = "DRAFT_ONLY"
        return {"schema_version": 1, "rows": rows}

    def register_alert_policy_template(
        self,
        *,
        scope: Scope,
        template: AlertPolicyTemplateV1,
        classification: str,
        retention_policy_revision: str,
    ) -> bool:
        values = {
            **scope.canonical_dict(),
            **template.model_dump(mode="json"),
            "content_digest": template.content_digest,
            "classification": classification,
            "retention_policy_revision": retention_policy_revision,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_policy_templates
                    (organization_id,project_id,environment_id,template_key,
                     template_version,publisher_ref,policy_skeleton_json,
                     calibration_slots_json,example_values_json,compatibility_range,
                     content_digest,lifecycle,retired_at,classification,
                     retention_policy_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(template_key)s,%(version)s,%(publisher_ref)s,%(policy_skeleton)s,
                     %(calibration_slots)s,%(example_values)s,%(compatibility)s,
                     %(content_digest)s,%(lifecycle)s,NULL,%(classification)s,
                     %(retention_policy_revision)s)
                   ON CONFLICT (organization_id,project_id,environment_id,
                                template_key,template_version) DO NOTHING
                   RETURNING content_digest""",
                {
                    **values,
                    "policy_skeleton": Jsonb(template.policy_skeleton),
                    "calibration_slots": Jsonb(list(template.calibration_slots)),
                    "example_values": Jsonb(template.example_values),
                },
            )
            inserted = cursor.fetchone()
            if inserted is None:
                cursor.execute(
                    """SELECT content_digest FROM solvan_alerts.alert_policy_templates
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND template_key=%(template_key)s
                          AND template_version=%(version)s""",
                    values,
                )
                existing = cursor.fetchone()
                if existing is None or existing["content_digest"] != template.content_digest:
                    raise AlertPolicyProductError("ALERT_TEMPLATE_IMMUTABLE_CONFLICT")
        return inserted is not None

    def simulate_alert_policy(
        self,
        *,
        scope: Scope,
        principal: str,
        command: AlertPolicySimulationCommandV1,
    ) -> dict[str, Any]:
        values = {
            **scope.canonical_dict(),
            **command.model_dump(mode="json"),
            "principal": principal,
            "request_hash": command.request_hash,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,response_digest,draft_policy_key,draft_version,draft_digest,
                          sample_provider_generation_id,sample_digest,evaluator_key,
                          evaluator_version,expression_digest,result,summary_template_id,
                          typed_values_json,authorized_node_summaries_json,access_set_hash,
                          request_hash,created_at,retention_until
                     FROM solvan_alerts.alert_policy_simulation_receipts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND requesting_principal=%(principal)s
                      AND idempotency_key=%(idempotency_key)s""",
                values,
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay["request_hash"] != command.request_hash:
                    raise AlertPolicyProductError("SIMULATION_IDEMPOTENCY_CONFLICT")
                return self._simulation_response(dict(replay))

            cursor.execute(
                """SELECT policy.policy_hash,policy.mode,
                          policy.escalation_expression_json,
                          policy.full_incident_admission_expression_json,
                          policy.classification,revision.lifecycle
                     FROM solvan_alerts.alert_policy_revisions policy
                     JOIN solvan_operability.trigger_policy_revisions revision
                       ON (revision.organization_id,revision.project_id,
                           revision.environment_id,revision.policy_key,revision.version,
                           revision.policy_hash)=(policy.organization_id,policy.project_id,
                           policy.environment_id,policy.policy_key,policy.policy_version,
                           policy.policy_hash)
                    WHERE policy.organization_id=%(organization_id)s
                      AND policy.project_id=%(project_id)s
                      AND policy.environment_id=%(environment_id)s
                      AND policy.policy_key=%(draft_policy_key)s
                      AND policy.policy_version=%(draft_version)s""",
                values,
            )
            policy = cursor.fetchone()
            if policy is None or policy["lifecycle"] != "DRAFT":
                raise AlertPolicyProductError("SIMULATION_DRAFT_INELIGIBLE")
            if policy["policy_hash"] != command.expected_draft_digest:
                raise AlertPolicyProductError("SIMULATION_STALE_DIGEST")

            cursor.execute(
                """SELECT generation.*,event.lifecycle_state,event.provider_severity,
                          event.resource_type,event.normalized_labels_json,event.observed_at
                     FROM solvan_alerts.alert_provider_generations generation
                     JOIN solvan_alerts.alert_events event
                       ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                          (generation.organization_id,generation.project_id,
                           generation.environment_id,generation.last_semantic_event_id)
                    WHERE generation.organization_id=%(organization_id)s
                      AND generation.project_id=%(project_id)s
                      AND generation.environment_id=%(environment_id)s
                      AND generation.id=%(sample_provider_generation_id)s""",
                values,
            )
            sample = cursor.fetchone()
            if sample is None:
                raise AlertPolicyProductError("SIMULATION_SAMPLE_INELIGIBLE")
            sample_material = {
                key: sample[key]
                for key in (
                    "id",
                    "provider_source_identity_id",
                    "provider_incident_key",
                    "started_at",
                    "last_semantic_event_id",
                    "provider_state_projection",
                    "row_version",
                    "classification",
                )
            }
            sample_digest = canonical_sha256(self._jsonable_row(sample_material))
            if sample_digest != command.expected_sample_digest:
                raise AlertPolicyProductError("SIMULATION_STALE_DIGEST")

            expression_material = (
                policy["escalation_expression_json"]
                if policy["mode"] == "POLICY_ESCALATED"
                else policy["full_incident_admission_expression_json"]
                if policy["mode"] == "FULL_INCIDENT"
                else None
            )
            evaluation = (
                None
                if expression_material is None
                else evaluate_predicate_expression(
                    PredicateExpressionV1.model_validate(expression_material),
                    source_fields={
                        "source_state": sample["provider_state_projection"],
                        "provider_severity": sample["provider_severity"],
                        "lifecycle_state": sample["lifecycle_state"],
                        "resource_type": sample["resource_type"],
                        "normalized_labels": sample["normalized_labels_json"],
                        "first_source_at": sample["started_at"],
                        "last_source_at": sample["observed_at"],
                    },
                    committed_facts={},
                    evaluated_at=datetime.now(UTC),
                )
            )
            result = self._simulation_result(policy["mode"], evaluation)
            simulation_id = new_identifier("sim")
            created_at = datetime.now(UTC)
            retention_until = created_at + timedelta(days=30)
            nodes = (
                []
                if evaluation is None
                else [
                    {
                        "node_id": node.node_id,
                        "kind": node.kind,
                        "result": str(node.verdict),
                        "reason_code": node.reason_code,
                        "input_refs": list(node.input_refs),
                    }
                    for node in evaluation.node_results
                ]
            )
            response = {
                "schema_version": 1,
                "kind": "HYPOTHETICAL_NO_WORKFLOW_EFFECT",
                "simulation_id": simulation_id,
                "request_hash": command.request_hash,
                "draft_policy_key": command.draft_policy_key,
                "draft_version": command.draft_version,
                "draft_digest": command.expected_draft_digest,
                "sample_provider_generation_id": command.sample_provider_generation_id,
                "sample_digest": sample_digest,
                "evaluator_key": "alert-predicate-evaluator",
                "evaluator_version": "1",
                "expression_digest": (
                    canonical_sha256(expression_material)
                    if expression_material is not None
                    else None
                ),
                "result": result,
                "summary_template_id": f"ALERT_SIMULATION_{result}",
                "typed_values": {
                    "operator_mode_label": operator_mode_label(policy["mode"]),
                    "mode_explanation": operator_mode_explanation(policy["mode"]),
                },
                "authorized_node_summaries": nodes,
                "access_set_hash": canonical_sha256(
                    {"scope": scope.canonical_dict(), "principal": principal}
                ),
                "created_at": created_at.isoformat(),
                "retention_until": retention_until.isoformat(),
            }
            response_digest = canonical_sha256(response)
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_policy_simulation_receipts
                    (organization_id,project_id,environment_id,id,requesting_principal,
                     draft_policy_key,draft_version,draft_digest,
                     sample_provider_generation_id,sample_digest,evaluator_key,
                     evaluator_version,expression_digest,result,summary_template_id,
                     typed_values_json,authorized_node_summaries_json,input_refs_json,
                     access_set_hash,request_hash,idempotency_key,response_digest,
                     classification,retention_until,created_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(simulation_id)s,%(principal)s,%(draft_policy_key)s,%(draft_version)s,
                     %(expected_draft_digest)s,%(sample_provider_generation_id)s,
                     %(expected_sample_digest)s,'alert-predicate-evaluator','1',
                     %(expression_digest)s,%(result)s,%(summary_template_id)s,
                     %(typed_values)s,%(nodes)s,%(input_refs)s,%(access_set_hash)s,
                     %(request_hash)s,%(idempotency_key)s,%(response_digest)s,
                     %(classification)s,%(retention_until)s,%(created_at)s)""",
                {
                    **values,
                    **response,
                    "expression_digest": response["expression_digest"],
                    "typed_values": Jsonb(response["typed_values"]),
                    "nodes": Jsonb(nodes),
                    "input_refs": Jsonb(
                        sorted({ref for node in nodes for ref in node["input_refs"]})
                    ),
                    "response_digest": response_digest,
                    "classification": sample["classification"],
                    "retention_until": retention_until,
                    "created_at": created_at,
                },
            )
        return response

    def list_alert_policy_recommendations(self, *, scope: Scope) -> dict[str, Any]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT recommendation.*,decision.decision_kind,
                          coalesce(decision.decision_epoch,0) AS decision_epoch
                     FROM solvan_alerts.alert_policy_recommendations recommendation
                     LEFT JOIN LATERAL (
                       SELECT candidate.decision_kind,candidate.decision_epoch
                         FROM solvan_alerts.alert_policy_recommendation_decisions candidate
                        WHERE candidate.organization_id=recommendation.organization_id
                          AND candidate.project_id=recommendation.project_id
                          AND candidate.environment_id=recommendation.environment_id
                          AND candidate.recommendation_id=recommendation.id
                        ORDER BY candidate.decision_epoch DESC LIMIT 1
                     ) decision ON true
                    WHERE recommendation.organization_id=%(organization_id)s
                      AND recommendation.project_id=%(project_id)s
                      AND recommendation.environment_id=%(environment_id)s
                      AND recommendation.expires_at>clock_timestamp()
                      AND decision.decision_kind IS NULL
                    ORDER BY recommendation.created_at DESC,recommendation.id""",
                scope.canonical_dict(),
            )
            rows = [self._jsonable_row(dict(row)) for row in cursor.fetchall()]
        return {
            "schema_version": 1,
            "label": "Machine-proposed — requires author review",
            "rows": rows,
        }

    def dismiss_alert_policy_recommendation(
        self,
        *,
        scope: Scope,
        recommendation_id: str,
        principal: str,
        actor_role: str,
        command: AlertPolicyRecommendationDismissV1,
    ) -> dict[str, Any]:
        values = {
            **scope.canonical_dict(),
            "recommendation_id": recommendation_id,
            "principal": principal,
            "actor_role": actor_role,
            **command.model_dump(mode="json"),
            "request_hash": command.request_hash,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,request_hash,decision_epoch,decision_kind
                     FROM solvan_alerts.alert_policy_recommendation_decisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND actor_principal=%(principal)s
                      AND idempotency_key=%(idempotency_key)s""",
                values,
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay["request_hash"] != command.request_hash:
                    raise AlertPolicyProductError("RECOMMENDATION_IDEMPOTENCY_CONFLICT")
                return {"schema_version": 1, **self._jsonable_row(dict(replay)), "created": False}
            cursor.execute(
                """SELECT recommendation_digest,expires_at
                     FROM solvan_alerts.alert_policy_recommendations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(recommendation_id)s
                    FOR SHARE""",
                values,
            )
            recommendation = cursor.fetchone()
            if recommendation is None:
                raise AlertPolicyProductError("RECOMMENDATION_NOT_FOUND")
            if recommendation["recommendation_digest"] != command.expected_recommendation_digest:
                raise AlertPolicyProductError("RECOMMENDATION_STALE_DIGEST")
            cursor.execute(
                """SELECT coalesce(max(decision_epoch),0) AS decision_epoch
                     FROM solvan_alerts.alert_policy_recommendation_decisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND recommendation_id=%(recommendation_id)s""",
                values,
            )
            current = cursor.fetchone()
            epoch = int(current["decision_epoch"] if current is not None else 0)
            if epoch != command.expected_decision_epoch:
                raise AlertPolicyProductError("RECOMMENDATION_STALE_EPOCH")
            decision_id = new_identifier("ard")
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_policy_recommendation_decisions
                    (organization_id,project_id,environment_id,id,recommendation_id,
                     recommendation_digest,decision_epoch,decision_kind,actor_principal,
                     actor_role,idempotency_key,request_hash,reason_code)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(decision_id)s,%(recommendation_id)s,
                     %(expected_recommendation_digest)s,%(decision_epoch)s,'DISMISSED',
                     %(principal)s,%(actor_role)s,%(idempotency_key)s,%(request_hash)s,
                     %(reason_code)s)""",
                {**values, "decision_id": decision_id, "decision_epoch": epoch + 1},
            )
        return {
            "schema_version": 1,
            "id": decision_id,
            "decision_epoch": epoch + 1,
            "decision_kind": "DISMISSED",
            "created": True,
        }

    @staticmethod
    def _simulation_result(mode: str, evaluation: Any) -> str:
        if mode == "TRIAGE" or evaluation is None:
            return "WOULD_HOLD"
        verdict = str(evaluation.verdict)
        if verdict == "TRUE":
            return "WOULD_ESCALATE"
        if verdict == "FALSE":
            return "WOULD_NOT_ESCALATE"
        return {
            "HOLD": "WOULD_HOLD",
            "MANUAL_REVIEW": "WOULD_REQUIRE_REVIEW",
            "BLOCKED": "WOULD_BLOCK",
        }[evaluation.on_inconclusive]

    @staticmethod
    def _simulation_response(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "HYPOTHETICAL_NO_WORKFLOW_EFFECT",
            "simulation_id": row["id"],
            "request_hash": row["request_hash"],
            "draft_policy_key": row["draft_policy_key"],
            "draft_version": row["draft_version"],
            "draft_digest": row["draft_digest"],
            "sample_provider_generation_id": row["sample_provider_generation_id"],
            "sample_digest": row["sample_digest"],
            "evaluator_key": row["evaluator_key"],
            "evaluator_version": row["evaluator_version"],
            "expression_digest": row["expression_digest"],
            "result": row["result"],
            "summary_template_id": row["summary_template_id"],
            "typed_values": row["typed_values_json"],
            "authorized_node_summaries": row["authorized_node_summaries_json"],
            "access_set_hash": row["access_set_hash"],
            "created_at": row["created_at"].isoformat(),
            "retention_until": row["retention_until"].isoformat(),
        }

    @staticmethod
    def _jsonable_row(row: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in row.items()
        }
