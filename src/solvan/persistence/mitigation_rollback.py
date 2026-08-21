"""Approval-bound rollback planning and shared policy lookups."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.domain import ActionType, Scope, derive_expected_effect, freeze_json, new_identifier
from solvan.persistence.mitigation_policy import (
    _digest,
    _mapping_contains,
    _ObservationRequirement,
)
from solvan.persistence.mitigation_types import (
    MitigationPolicyError,
    RollbackProposalResult,
)
from solvan.persistence.postgres import PostgresWorkflowStore
from solvan.persistence.postgres_types import (
    AggregateType,
    LeaseHandle,
    TransitionWrite,
    WorkflowConflict,
)


class MitigationRollbackMixin:
    _connection: Connection[Any]
    _workflow: PostgresWorkflowStore

    def plan_approval_bound_rollback(
        self,
        *,
        scope: Scope,
        lease: LeaseHandle,
        failed_action_id: str,
        verification_id: str,
        actor_id: str,
    ) -> RollbackProposalResult:
        """Convert partial recovery into an exact, reviewable Cloud Run rollback."""

        if lease.aggregate_type is not AggregateType.INCIDENT:
            raise ValueError("rollback planning requires an incident lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            incident = self._locked_incident(cursor, scope, lease)
            if incident is None or incident["state"] != "VERIFYING_MITIGATION":
                raise WorkflowConflict("rollback planning has no current incident authority")
            cursor.execute(
                """SELECT a.id
                  FROM solvan.actions a
                  JOIN solvan.verification_runs v
                    ON (v.organization_id, v.project_id, v.environment_id, v.action_id)
                     = (a.organization_id, a.project_id, a.environment_id, a.id)
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.id = %(action_id)s AND a.incident_id = %(incident_id)s
                    AND a.action_type = 'PAYMENTS_POOL_RECYCLE'
                    AND a.status = 'SUCCEEDED' AND v.id = %(verification_id)s
                    AND v.verdict IN ('FAILED','INCONCLUSIVE') FOR UPDATE OF a""",
                {
                    **scope.canonical_dict(),
                    "action_id": failed_action_id,
                    "incident_id": lease.entity_id,
                    "verification_id": verification_id,
                },
            )
            if cursor.fetchone() is None:
                raise MitigationPolicyError(
                    "rollback fallback requires one failed verified pool recycle"
                )
            if int(incident["action_attempt_count"]) >= int(incident["action_budget"]):
                raise MitigationPolicyError("incident action budget is exhausted")

            deployment = self._approved_deployment_policy(cursor, scope, incident)
            profile = self._verification_profile(cursor, scope, incident)
            target_key = str(deployment["target_key"])
            target = self._target_epoch(cursor, scope, target_key)
            if str(target["last_observed_version"]) != str(deployment["active_revision"]):
                raise MitigationPolicyError(
                    "approved deployment revision differs from the live target baseline"
                )
            payload = {
                "service_name": str(incident["platform_resource"]),
                "known_good_revision": str(deployment["known_good_revision"]),
                "percent": 100,
            }
            policy_material = {
                "action_type": "CLOUD_RUN_TRAFFIC_ROLLBACK",
                "failed_action_id": failed_action_id,
                "verification_id": verification_id,
                "evidence_version": int(incident["evidence_version"]),
                "payload": payload,
                "target_key": target_key,
                "target_epoch": int(target["epoch"]),
                "target_version": str(target["last_observed_version"]),
                "verification_profile_id": profile["id"],
                "verification_profile_version": int(profile["version"]),
            }
            policy_id = new_identifier("pol")
            policy_version = (
                f"production-graph:{incident['production_graph_snapshot_id']}:"
                "approval-bound-rollback-v1"
            )
            cursor.execute(
                """INSERT INTO solvan.policy_decisions
                  (organization_id, project_id, environment_id, id, policy_kind,
                   policy_version, input_hash, decision, reason_code)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(policy_id)s, 'ACTION', %(policy_version)s, %(input_hash)s,
                    'REQUIRE_APPROVAL', 'PARTIAL_RECOVERY_REQUIRES_EXACT_ROLLBACK')""",
                {
                    **scope.canonical_dict(),
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "input_hash": _digest(policy_material),
                },
            )
            proposed_version = self._workflow.commit_transition(
                scope=scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="VERIFYING_MITIGATION",
                    to_state="MITIGATION_PROPOSED",
                    transition_key=f"VERIFICATION_FAILED_RETRYABLE:{verification_id}",
                    actor_type="COORDINATOR",
                    actor_id=actor_id,
                    policy_decision_id=policy_id,
                    reason_code="PARTIAL_RECOVERY_HAS_APPROVED_FALLBACK",
                    rationale_summary=(
                        "The bounded autonomous action did not restore health; the "
                        "approved graph permits only an exact human-approved rollback."
                    ),
                    evidence_refs=(
                        f"db://solvan/verification-runs/{verification_id}",
                        f"db://solvan/actions/{failed_action_id}",
                    ),
                ),
            )
            current_lease = replace(lease, workflow_version=proposed_version)
            action_id = new_identifier("act")
            display_id = self._allocate_action_display_id(cursor, scope)
            payload_digest = _digest(payload)
            signature = _digest(
                {
                    "action_type": "CLOUD_RUN_TRAFFIC_ROLLBACK",
                    "payload_digest": payload_digest,
                    "target_key": target_key,
                }
            )
            # Human approval advances AWAITING_APPROVAL -> MITIGATING. Bind the
            # immutable action and its approval digest to that future execution
            # version so granting approval cannot invalidate its own material.
            action_workflow_version = proposed_version + 2
            awaiting_workflow_version = proposed_version + 1
            expected_effect = derive_expected_effect(
                action_type=ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK,
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
                   proposer_principal, requires_approval, status, idempotency_key,
                   expires_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(action_id)s, %(display_id)s, %(incident_id)s,
                    %(workflow_version)s, %(evidence_version)s,
                    'CLOUD_RUN_TRAFFIC_ROLLBACK', %(signature)s, %(target_key)s,
                    %(target_version)s, %(target_epoch)s, %(payload)s,
                    %(payload_digest)s, %(expected_effect)s,
                    %(expected_effect_hash)s, 'HIGH', true, %(rollback_plan)s,
                    %(profile_id)s, %(profile_version)s, %(policy_id)s,
                    %(actor_id)s, true, 'AWAITING_APPROVAL', %(idempotency_key)s,
                    now() + interval '15 minutes')""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "display_id": display_id,
                    "incident_id": lease.entity_id,
                    "workflow_version": action_workflow_version,
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
                            "restore_revision": deployment["active_revision"],
                            "requires_separate_approval": True,
                        }
                    ),
                    "profile_id": profile["id"],
                    "profile_version": profile["version"],
                    "policy_id": policy_id,
                    "actor_id": actor_id,
                    "idempotency_key": (
                        f"rollback:{lease.entity_id}:{verification_id}:{signature}"
                    ),
                },
            )
            awaiting_version = self._workflow.commit_transition(
                scope=scope,
                lease=current_lease,
                transition=TransitionWrite(
                    from_state="MITIGATION_PROPOSED",
                    to_state="AWAITING_APPROVAL",
                    transition_key=f"APPROVAL_REQUIRED:{action_id}",
                    actor_type="POLICY_ENGINE",
                    actor_id=actor_id,
                    policy_decision_id=policy_id,
                    reason_code="HIGH_RISK_TRAFFIC_CHANGE",
                    rationale_summary=(
                        "Cloud Run traffic movement is bound to exact immutable "
                        "material and requires a distinct authorized approver."
                    ),
                    evidence_refs=(f"db://solvan/actions/{action_id}",),
                ),
            )
            if awaiting_version != awaiting_workflow_version:
                raise WorkflowConflict("rollback waiting workflow version was not final")
            return RollbackProposalResult(
                lease.entity_id,
                failed_action_id,
                action_id,
                display_id,
                awaiting_version,
                int(incident["evidence_version"]),
            )

    @staticmethod
    def _locked_incident(cursor: Any, scope: Scope, lease: LeaseHandle) -> dict[str, Any] | None:
        cursor.execute(
            """SELECT i.*, s.service_key, s.platform_resource, now() AS database_now
              FROM solvan.incidents i
              JOIN solvan.services s
                ON (s.organization_id, s.project_id, s.environment_id, s.id)
                 = (i.organization_id, i.project_id, i.environment_id,
                    i.primary_service_id)
              WHERE i.organization_id = %(organization_id)s
                AND i.project_id = %(project_id)s
                AND i.environment_id = %(environment_id)s
                AND i.id = %(incident_id)s
                AND i.workflow_version = %(workflow_version)s
                AND i.lease_owner = %(lease_owner)s
                AND i.lease_token = %(lease_token)s
                AND i.lease_expires_at >= now()
              FOR UPDATE OF i""",
            {
                **scope.canonical_dict(),
                "incident_id": lease.entity_id,
                "workflow_version": lease.workflow_version,
                "lease_owner": lease.owner,
                "lease_token": lease.token,
            },
        )
        return cast(dict[str, Any] | None, cursor.fetchone())

    @staticmethod
    def _completed_plan_exists(cursor: Any, scope: Scope, incident_id: str) -> bool:
        cursor.execute(
            """SELECT EXISTS (
                SELECT 1 FROM solvan.investigation_plans
                WHERE organization_id = %(organization_id)s
                  AND project_id = %(project_id)s
                  AND environment_id = %(environment_id)s
                  AND incident_id = %(incident_id)s AND status = 'COMPLETED')""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
        row = cursor.fetchone()
        return bool(row and row["exists"])

    @staticmethod
    def _single_confirmation_rule(cursor: Any, scope: Scope, incident_class: str) -> dict[str, Any]:
        cursor.execute(
            """SELECT id, version, required_observations_json, contradiction_policy
              FROM solvan.confirmation_rules
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND incident_class = %(incident_class)s AND status = 'APPROVED'
              ORDER BY version DESC LIMIT 2""",
            {**scope.canonical_dict(), "incident_class": incident_class},
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise MitigationPolicyError("exactly one approved confirmation rule is required")
        return cast(dict[str, Any], rows[0])

    @staticmethod
    def _matching_evidence(
        cursor: Any,
        scope: Scope,
        incident_id: str,
        requirements: tuple[_ObservationRequirement, ...],
    ) -> tuple[str, ...] | None:
        cursor.execute(
            """SELECT e.id, e.source_kind, e.query_spec_json
              FROM solvan.evidence_items e
              JOIN solvan.agent_runs r
                ON (r.organization_id, r.project_id, r.environment_id, r.id)
                 = (e.organization_id, e.project_id, e.environment_id,
                    e.created_by_agent_run_id)
              WHERE e.organization_id = %(organization_id)s
                AND e.project_id = %(project_id)s
                AND e.environment_id = %(environment_id)s
                AND e.incident_id = %(incident_id)s
                AND e.freshness_expires_at > now() AND r.status = 'SUCCEEDED'
              ORDER BY e.observed_at DESC, e.id""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
        evidence = cursor.fetchall()
        matched: list[str] = []
        used: set[str] = set()
        for requirement in requirements:
            match = next(
                (
                    row
                    for row in evidence
                    if str(row["id"]) not in used
                    and row["source_kind"] == requirement.source_kind
                    and isinstance(row["query_spec_json"], dict)
                    and row["query_spec_json"].get("tool_name") == requirement.tool_name
                    and _mapping_contains(
                        row["query_spec_json"].get("arguments"),
                        requirement.argument_equals,
                    )
                ),
                None,
            )
            if match is None:
                return None
            evidence_id = str(match["id"])
            used.add(evidence_id)
            matched.append(evidence_id)
        return tuple(matched)

    @staticmethod
    def _single_standing_authority(
        cursor: Any, scope: Scope, incident: dict[str, Any]
    ) -> dict[str, Any]:
        cursor.execute(
            """SELECT * FROM solvan.standing_preauthorizations
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND action_type = 'PAYMENTS_POOL_RECYCLE'
                AND service_id = %(service_id)s
                AND incident_class = %(incident_class)s
                AND status = 'APPROVED' AND valid_from <= now() AND valid_until > now()
                AND maximum_risk_class IN ('MEDIUM')
                AND maximum_attempts = 1 AND cooldown_ms >= 600000
              ORDER BY version DESC LIMIT 2""",
            {
                **scope.canonical_dict(),
                "service_id": incident["primary_service_id"],
                "incident_class": incident["incident_class"],
            },
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise MitigationPolicyError("exactly one matching live standing authority is required")
        if int(incident["action_attempt_count"]) >= int(rows[0]["maximum_attempts"]):
            raise MitigationPolicyError("standing authority attempt budget is exhausted")
        cooldown = incident["cooldown_until"]
        if cooldown is not None and cooldown > incident["database_now"]:
            raise MitigationPolicyError("standing authority cooldown is active")
        return cast(dict[str, Any], rows[0])

    @staticmethod
    def _verification_profile(
        cursor: Any, scope: Scope, incident: dict[str, Any]
    ) -> dict[str, Any]:
        cursor.execute(
            """SELECT p.id, p.version
              FROM solvan.verification_profile_bindings b
              JOIN solvan.verification_profiles p
                ON (p.organization_id, p.project_id, p.environment_id,
                    p.id, p.version)
                 = (b.organization_id, b.project_id, b.environment_id,
                    b.profile_id, b.profile_version)
              WHERE b.organization_id = %(organization_id)s
                AND b.project_id = %(project_id)s
                AND b.environment_id = %(environment_id)s
                AND b.service_id = %(service_id)s
                AND b.incident_class = %(incident_class)s
                AND b.production_graph_snapshot_id = %(snapshot_id)s
                AND b.superseded_at IS NULL AND b.effective_at <= now()
                AND p.status = 'APPROVED' LIMIT 2""",
            {
                **scope.canonical_dict(),
                "service_id": incident["primary_service_id"],
                "incident_class": incident["incident_class"],
                "snapshot_id": incident["production_graph_snapshot_id"],
            },
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise MitigationPolicyError("one current approved verification profile is required")
        return cast(dict[str, Any], rows[0])

    @staticmethod
    def _target_epoch(cursor: Any, scope: Scope, target_key: str) -> dict[str, Any]:
        cursor.execute(
            """SELECT epoch, last_observed_version FROM solvan.target_epochs
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND target_key = %(target_key)s FOR UPDATE""",
            {**scope.canonical_dict(), "target_key": target_key},
        )
        row = cursor.fetchone()
        if row is None:
            raise MitigationPolicyError("the pool target has no approved epoch baseline")
        return cast(dict[str, Any], row)

    @staticmethod
    def _approved_deployment_policy(
        cursor: Any, scope: Scope, incident: dict[str, Any]
    ) -> dict[str, Any]:
        cursor.execute(
            """SELECT n.attributes_json
              FROM solvan.production_graph_nodes n
              JOIN solvan.production_graph_snapshots g
                ON (g.organization_id, g.project_id, g.environment_id, g.id)
                 = (n.organization_id, n.project_id, n.environment_id, n.snapshot_id)
              WHERE n.organization_id = %(organization_id)s
                AND n.project_id = %(project_id)s
                AND n.environment_id = %(environment_id)s
                AND n.snapshot_id = %(snapshot_id)s AND n.node_kind = 'DEPLOYMENT'
                AND n.resource_ref = %(platform_resource)s
                AND n.attributes_json ->> 'service_id' = %(service_id)s
                AND g.status = 'APPROVED' AND g.superseded_at IS NULL
              LIMIT 2""",
            {
                **scope.canonical_dict(),
                "snapshot_id": incident["production_graph_snapshot_id"],
                "platform_resource": incident["platform_resource"],
                "service_id": incident["primary_service_id"],
            },
        )
        rows = cursor.fetchall()
        if len(rows) != 1 or not isinstance(rows[0]["attributes_json"], dict):
            raise MitigationPolicyError("one approved deployment policy is required")
        attributes = cast(dict[str, Any], rows[0]["attributes_json"])
        required = {"service_id", "active_revision", "known_good_revision", "target_key"}
        if set(attributes) != required or any(
            not isinstance(attributes[key], str) or not attributes[key] for key in required
        ):
            raise MitigationPolicyError("deployment policy has an unsupported schema")
        if attributes["active_revision"] == attributes["known_good_revision"]:
            raise MitigationPolicyError("deployment rollback revisions must differ")
        return attributes

    @staticmethod
    def _allocate_action_display_id(cursor: Any, scope: Scope) -> str:
        cursor.execute(
            """INSERT INTO solvan.display_sequences
              (organization_id, project_id, environment_id, entity_type, next_value)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s, 'ACT', 2)
              ON CONFLICT (organization_id, project_id, environment_id, entity_type)
              DO UPDATE SET next_value = solvan.display_sequences.next_value + 1
              RETURNING next_value - 1 AS allocated""",
            scope.canonical_dict(),
        )
        row = cursor.fetchone()
        if row is None:  # pragma: no cover - INSERT always returns
            raise RuntimeError("action display sequence allocation failed")
        return f"ACT-{int(row['allocated']):04d}"
