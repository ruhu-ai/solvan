"""Deterministic confirmation and standing-authority mitigation planning."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.domain import ActionType, Scope, derive_expected_effect, freeze_json, new_identifier
from solvan.persistence.mitigation_policy import _digest, _parse_confirmation_spec
from solvan.persistence.mitigation_rollback import MitigationRollbackMixin
from solvan.persistence.mitigation_types import (
    MitigationPlanResult,
    MitigationPolicyError,
)
from solvan.persistence.postgres import PostgresWorkflowStore
from solvan.persistence.postgres_types import (
    AggregateType,
    LeaseHandle,
    TransitionWrite,
    WorkflowConflict,
)


class PostgresMitigationPlanner(MitigationRollbackMixin):
    """Turn completed investigation evidence into one policy-bound action.

    No model confidence, prose, or Agent-requested action is accepted here. The
    only authority inputs are approved versioned policy records and fresh typed
    evidence produced by successful, run-bound Agents.
    """

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection
        self._workflow = PostgresWorkflowStore(connection)

    def ready_incident_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("mitigation planning limit must be between 1 and 100")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT i.id FROM solvan.incidents i
                  WHERE i.organization_id = %(organization_id)s
                    AND i.project_id = %(project_id)s
                    AND i.environment_id = %(environment_id)s
                    AND i.state = 'INVESTIGATING'
                    AND EXISTS (
                      SELECT 1 FROM solvan.investigation_plans p
                      WHERE p.organization_id = i.organization_id
                        AND p.project_id = i.project_id
                        AND p.environment_id = i.environment_id
                        AND p.incident_id = i.id AND p.status = 'COMPLETED')
                  ORDER BY i.detected_at, i.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def plan_preauthorized_pool_recycle(
        self,
        *,
        scope: Scope,
        lease: LeaseHandle,
        actor_id: str,
    ) -> MitigationPlanResult | None:
        """Confirm the named cause and create the exact autonomous fixture action.

        The caller owns the transaction. Missing fresh observations return None
        because evidence collection may still be settling. Invalid or ambiguous
        approved policy fails closed with ``MitigationPolicyError``.
        """

        if lease.aggregate_type is not AggregateType.INCIDENT:
            raise ValueError("mitigation planning requires an incident lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            incident = self._locked_incident(cursor, scope, lease)
            if incident is None:
                raise WorkflowConflict("incident workflow or coordinator lease is stale")
            if incident["state"] != "INVESTIGATING":
                return None
            if not self._completed_plan_exists(cursor, scope, lease.entity_id):
                return None

            rule = self._single_confirmation_rule(cursor, scope, str(incident["incident_class"]))
            spec = _parse_confirmation_spec(rule["required_observations_json"])
            evidence_refs = self._matching_evidence(
                cursor, scope, lease.entity_id, spec.all_required
            )
            if evidence_refs is None:
                return None

            diagnosing_version = self._workflow.commit_transition(
                scope=scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="INVESTIGATING",
                    to_state="DIAGNOSING",
                    transition_key=(f"DIAGNOSIS_STARTED:{rule['id']}:{int(rule['version'])}"),
                    actor_type="COORDINATOR",
                    actor_id=actor_id,
                    reason_code="APPROVED_CONFIRMATION_RULE_READY",
                    rationale_summary=(
                        "All fresh typed observations required by the approved "
                        "confirmation rule are present."
                    ),
                    evidence_refs=evidence_refs,
                ),
            )
            current_lease = replace(lease, workflow_version=diagnosing_version)
            hypothesis_id = new_identifier("hyp")
            cursor.execute(
                """INSERT INTO solvan.hypotheses
                  (organization_id, project_id, environment_id, id, incident_id,
                   statement, normalized_cause_key, revision, status,
                   supporting_evidence_refs, contradicting_evidence_refs,
                   confirmation_rule_id, confirmation_rule_version, confirmed_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(hypothesis_id)s, %(incident_id)s, %(statement)s,
                    %(cause_key)s, 1, 'CONFIRMED', %(evidence_refs)s, '[]'::jsonb,
                    %(rule_id)s, %(rule_version)s, now())""",
                {
                    **scope.canonical_dict(),
                    "hypothesis_id": hypothesis_id,
                    "incident_id": lease.entity_id,
                    "statement": spec.statement,
                    "cause_key": spec.normalized_cause_key,
                    "evidence_refs": Jsonb(list(evidence_refs)),
                    "rule_id": rule["id"],
                    "rule_version": rule["version"],
                },
            )
            cursor.execute(
                """UPDATE solvan.incidents
                  SET suspected_root_cause_id = %(hypothesis_id)s,
                      confirmed_root_cause_id = %(hypothesis_id)s,
                      updated_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(incident_id)s
                    AND lease_owner = %(lease_owner)s AND lease_token = %(lease_token)s""",
                {
                    **scope.canonical_dict(),
                    "incident_id": lease.entity_id,
                    "hypothesis_id": hypothesis_id,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            if cursor.rowcount != 1:
                raise WorkflowConflict("incident lease changed during diagnosis")

            preauthorization = self._single_standing_authority(cursor, scope, incident)
            profile = self._verification_profile(cursor, scope, incident)
            payload = preauthorization["payload_constraints_json"]
            if not isinstance(payload, dict):
                raise MitigationPolicyError("standing preauthorization payload is not an object")
            target_key = (
                f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
                f"payments-admin/{incident['service_key']}/connection-pool"
            )
            target = self._target_epoch(cursor, scope, target_key)
            policy_material = {
                "action_type": "PAYMENTS_POOL_RECYCLE",
                "evidence_refs": list(evidence_refs),
                "evidence_version": int(incident["evidence_version"]),
                "hypothesis_id": hypothesis_id,
                "payload": payload,
                "preauthorization_id": preauthorization["id"],
                "preauthorization_version": int(preauthorization["version"]),
                "target_epoch": int(target["epoch"]),
                "target_key": target_key,
                "target_version": str(target["last_observed_version"]),
                "verification_profile_id": profile["id"],
                "verification_profile_version": int(profile["version"]),
            }
            policy_input_hash = _digest(policy_material)
            policy_id = new_identifier("pol")
            policy_version = (
                f"standing:{preauthorization['id']}:v{int(preauthorization['version'])}"
            )
            cursor.execute(
                """INSERT INTO solvan.policy_decisions
                  (organization_id, project_id, environment_id, id, policy_kind,
                   policy_version, input_hash, decision, reason_code)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(policy_id)s, 'ACTION', %(policy_version)s, %(input_hash)s,
                    'ALLOW', 'EXACT_STANDING_PREAUTHORIZATION_MATCH')""",
                {
                    **scope.canonical_dict(),
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "input_hash": policy_input_hash,
                },
            )
            proposed_version = self._workflow.commit_transition(
                scope=scope,
                lease=current_lease,
                transition=TransitionWrite(
                    from_state="DIAGNOSING",
                    to_state="MITIGATION_PROPOSED",
                    transition_key=f"MITIGATION_SELECTED:{hypothesis_id}",
                    actor_type="COORDINATOR",
                    actor_id=actor_id,
                    policy_decision_id=policy_id,
                    reason_code="CONFIRMED_CAUSE_HAS_ALLOWLISTED_ACTION",
                    rationale_summary=(
                        "The confirmed connection-exhaustion cause maps to the "
                        "single allowlisted pool-recycle action."
                    ),
                    evidence_refs=evidence_refs,
                ),
            )
            current_lease = replace(current_lease, workflow_version=proposed_version)
            action_id = new_identifier("act")
            display_id = self._allocate_action_display_id(cursor, scope)
            payload_digest = _digest(payload)
            signature = _digest(
                {
                    "action_type": "PAYMENTS_POOL_RECYCLE",
                    "payload_digest": payload_digest,
                    "target_key": target_key,
                }
            )
            final_workflow_version = proposed_version + 1
            expires_at = min(
                incident["database_now"] + timedelta(minutes=5),
                preauthorization["valid_until"],
            )
            expected_effect = derive_expected_effect(
                action_type=ActionType.PAYMENTS_POOL_RECYCLE,
                target_key=target_key,
                expected_target_version=target["last_observed_version"],
                payload=freeze_json(payload),
            )
            cursor.execute(
                """INSERT INTO solvan.actions
                  (organization_id, project_id, environment_id, id, display_id,
                   incident_id, workflow_version, evidence_version, action_type,
                   normalized_signature, target_key, expected_target_version,
                   expected_target_epoch, payload_json, payload_digest,
                   expected_effect_json, expected_effect_hash, risk_class,
                   reversible, rollback_plan_json, verification_profile_id,
                   verification_profile_version, policy_decision_id,
                   proposer_principal, standing_preauthorization_id,
                   standing_preauthorization_version, requires_approval, status,
                   idempotency_key, expires_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(action_id)s, %(display_id)s, %(incident_id)s,
                    %(workflow_version)s, %(evidence_version)s,
                    'PAYMENTS_POOL_RECYCLE', %(signature)s, %(target_key)s,
                    %(target_version)s, %(target_epoch)s, %(payload)s,
                    %(payload_digest)s, %(expected_effect)s,
                    %(expected_effect_hash)s, 'MEDIUM', false, %(rollback_plan)s,
                    %(profile_id)s, %(profile_version)s, %(policy_id)s,
                    %(actor_id)s, %(preauthorization_id)s,
                    %(preauthorization_version)s, false, 'AUTHORIZED',
                    %(idempotency_key)s, %(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "display_id": display_id,
                    "incident_id": lease.entity_id,
                    "workflow_version": final_workflow_version,
                    "evidence_version": incident["evidence_version"],
                    "signature": signature,
                    "target_key": target_key,
                    "target_version": target["last_observed_version"],
                    "target_epoch": target["epoch"],
                    "payload": Jsonb(payload),
                    "payload_digest": payload_digest,
                    "expected_effect": Jsonb(expected_effect.descriptor_object()),
                    "expected_effect_hash": expected_effect.content_hash,
                    "rollback_plan": Jsonb(
                        {
                            "fallback_action": "CLOUD_RUN_TRAFFIC_ROLLBACK",
                            "requires_approval": True,
                        }
                    ),
                    "profile_id": profile["id"],
                    "profile_version": profile["version"],
                    "policy_id": policy_id,
                    "actor_id": actor_id,
                    "preauthorization_id": preauthorization["id"],
                    "preauthorization_version": preauthorization["version"],
                    "idempotency_key": f"pool-recycle:{lease.entity_id}:{signature}",
                    "expires_at": expires_at,
                },
            )
            mitigating_version = self._workflow.commit_transition(
                scope=scope,
                lease=current_lease,
                transition=TransitionWrite(
                    from_state="MITIGATION_PROPOSED",
                    to_state="MITIGATING",
                    transition_key=f"PREAUTHORIZED:{action_id}",
                    actor_type="POLICY_ENGINE",
                    actor_id=actor_id,
                    policy_decision_id=policy_id,
                    reason_code="EXACT_STANDING_PREAUTHORIZATION_MATCH",
                    rationale_summary=(
                        "Action material exactly matches the live human-authored "
                        "standing preauthorization."
                    ),
                    evidence_refs=evidence_refs,
                ),
            )
            if mitigating_version != final_workflow_version:
                raise WorkflowConflict("authorized action workflow version was not final")
            return MitigationPlanResult(
                incident_id=lease.entity_id,
                hypothesis_id=hypothesis_id,
                action_id=action_id,
                display_id=display_id,
                workflow_version=mitigating_version,
                evidence_version=int(incident["evidence_version"]),
            )
