"""Immutable trigger-policy authoring, evaluation, and approval."""

from __future__ import annotations

from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.operational_guidance import GuidanceError, TriggerPolicyRevision
from solvan.domain import Scope, new_identifier
from solvan.persistence.trigger_policy_lifecycle import TriggerPolicyLifecycleMixin
from solvan.persistence.trigger_policy_types import TriggerPolicyLifecycleCommit


class TriggerPolicyAuthoringMixin(TriggerPolicyLifecycleMixin):
    def create_draft(
        self,
        *,
        scope: Scope,
        policy: TriggerPolicyRevision,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        if str(policy.lifecycle) != "DRAFT":
            raise GuidanceError("a new trigger policy must enter as DRAFT")
        self._require_role(
            scope=scope,
            principal=policy.author_principal,
            roles=("TRIGGER_POLICY_AUTHOR", "OPERABILITY_ADMIN"),
            department=policy.owner_department,
        )
        guidance_key = guidance_version = None
        if policy.guidance_revision:
            guidance_key, guidance_version = policy.guidance_revision.split("@", 1)
        profile_key, profile_version = policy.investigation_profile_ref.split("@", 1)
        source_tool_key, source_tool_version = policy.source_capability_tool_ref.split("@", 1)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            entity_ref = f"trigger-policy:{policy.policy_key}@{policy.version}"
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=policy.policy_hash,
                    principal=policy.author_principal,
                    event_type="TRIGGER_POLICY_DRAFT_CREATED",
                )
                return TriggerPolicyLifecycleCommit(
                    policy.policy_key,
                    policy.version,
                    "DRAFT",
                    policy.policy_hash,
                    None,
                    False,
                )
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_revisions
                     (organization_id,project_id,environment_id,policy_key,version,
                      owner_department,trigger_kind,source_connection_id,
                      source_connection_epoch,source_tool_key,source_tool_version,
                      source_agent_key,source_identity_ref,source_capability_class,
                      target_selector_ref,incident_class,
                      severity,deduplication_dimension,action_budget,
                      repeated_action_limit,guidance_key,
                      guidance_version,profile_key,profile_version,delay_ms,cooldown_ms,
                      maximum_pending_per_target,supersession,region,
                      classification_ceiling,lifecycle,author_principal,
                      approved_by_principal,approval_ref,evaluation_ref,policy_hash,approved_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(policy_key)s,%(version)s,%(owner_department)s,%(trigger_kind)s,
                           %(source_connection_id)s,%(source_connection_epoch)s,
                           %(source_tool_key)s,%(source_tool_version)s,
                           %(source_agent_key)s,%(source_identity_ref)s,
                           %(source_capability_class)s,
                           %(target_selector_ref)s,%(incident_class)s,%(severity)s,
                           %(deduplication_dimension)s,%(action_budget)s,
                           %(repeated_action_limit)s,%(guidance_key)s,%(guidance_version)s,
                           %(profile_key)s,%(profile_version)s,%(delay_ms)s,%(cooldown_ms)s,
                           %(maximum_pending)s,%(supersession)s,%(region)s,
                           %(classification)s,%(lifecycle)s,%(author_principal)s,
                           %(approved_by_principal)s,%(approval_ref)s,
                           %(evaluation_ref)s,%(policy_hash)s,%(approved_at)s)
                   ON CONFLICT (organization_id,project_id,environment_id,policy_key,version)
                   DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy.policy_key,
                    "version": policy.version,
                    "owner_department": policy.owner_department,
                    "trigger_kind": str(policy.trigger_kind),
                    "source_connection_id": policy.source_connection_id,
                    "source_connection_epoch": policy.source_connection_epoch,
                    "source_tool_key": source_tool_key,
                    "source_tool_version": source_tool_version,
                    "source_agent_key": policy.source_capability_agent_key,
                    "source_identity_ref": policy.source_capability_identity_ref,
                    "source_capability_class": policy.source_capability_class,
                    "target_selector_ref": policy.target_selector_ref,
                    "incident_class": policy.incident_class,
                    "severity": policy.severity,
                    "deduplication_dimension": policy.deduplication_dimension,
                    "action_budget": policy.action_budget,
                    "repeated_action_limit": policy.repeated_action_limit,
                    "guidance_key": guidance_key,
                    "guidance_version": guidance_version,
                    "profile_key": profile_key,
                    "profile_version": profile_version,
                    "delay_ms": policy.delay_ms,
                    "cooldown_ms": policy.cooldown_ms,
                    "maximum_pending": policy.maximum_pending_per_target,
                    "supersession": policy.supersession,
                    "region": policy.region,
                    "classification": policy.classification_ceiling,
                    "lifecycle": str(policy.lifecycle),
                    "author_principal": policy.author_principal,
                    "approved_by_principal": policy.approved_by_principal,
                    "approval_ref": policy.approval_ref,
                    "evaluation_ref": policy.evaluation_ref,
                    "policy_hash": policy.policy_hash,
                    "approved_at": policy.approved_at,
                },
            )
            cursor.execute(
                """SELECT policy_hash FROM solvan_operability.trigger_policy_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND version=%(version)s""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy.policy_key,
                    "version": policy.version,
                },
            )
            row = cursor.fetchone()
            if row is None or row["policy_hash"] != policy.policy_hash:
                raise GuidanceError("a trigger policy revision already has different material")
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=policy.author_principal,
                event_type="TRIGGER_POLICY_DRAFT_CREATED",
                entity_ref=entity_ref,
                digest=policy.policy_hash,
                decision_request_id=decision_request_id,
                reason_code="AUTHORIZED_DRAFT_CREATED",
            )
        return TriggerPolicyLifecycleCommit(
            policy.policy_key,
            policy.version,
            "DRAFT",
            policy.policy_hash,
            None,
            True,
        )

    def policy_projection(
        self, *, scope: Scope, policy_key: str, version: str
    ) -> dict[str, Any] | None:
        """Return one reader-safe policy projection with independent health facts."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT policy_key,version,owner_department,trigger_kind,
                          source_connection_id,source_connection_epoch,source_tool_key,
                          source_tool_version,source_agent_key,source_identity_ref,
                          source_capability_class,
                          target_selector_ref,
                          guidance_key,guidance_version,profile_key,profile_version,
                          delay_ms,cooldown_ms,maximum_pending_per_target,supersession,
                          region,classification_ceiling,lifecycle,policy_hash,
                          evaluation_ref,approval_ref,created_at,approved_at
                     FROM solvan_operability.trigger_policy_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND version=%(version)s""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            row = cursor.fetchone()
            return None if row is None else dict(row)

    def record_evaluation(
        self,
        *,
        scope: Scope,
        policy_key: str,
        version: str,
        expected_digest: str,
        principal: str,
        suite_version: str,
        passed_cases: int,
        failed_cases: int,
        receipt_ref: str,
        receipt_hash: str,
        reason_codes: tuple[str, ...],
        decision_request_id: str,
    ) -> str:
        if not suite_version.strip() or not receipt_ref.strip() or not reason_codes:
            raise GuidanceError("trigger evaluation material is incomplete")
        if not receipt_hash.startswith("sha256:") or len(receipt_hash) != 71:
            raise GuidanceError("trigger evaluation receipt hash is invalid")
        if passed_cases < 0 or failed_cases < 0 or passed_cases + failed_cases == 0:
            raise GuidanceError("trigger evaluation case counts are invalid")
        evaluation_id = new_identifier("tev")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            entity_ref = f"trigger-policy-evaluation:{policy_key}@{version}"
            cursor.execute(
                """SELECT author_principal,owner_department,policy_hash,lifecycle
                     FROM solvan_operability.trigger_policy_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND version=%(version)s FOR UPDATE""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            policy_row = cursor.fetchone()
            if policy_row is None:
                raise GuidanceError("trigger policy is not eligible for evaluation")
            if policy_row["policy_hash"] != expected_digest:
                raise GuidanceError("trigger policy evaluation digest is stale")
            if policy_row["author_principal"] == principal:
                raise GuidanceError("a trigger policy author cannot evaluate their revision")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("TRIGGER_POLICY_EVALUATOR", "OPERABILITY_ADMIN"),
                department=str(policy_row["owner_department"]),
            )
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=expected_digest,
                    principal=principal,
                    event_type="TRIGGER_POLICY_EVALUATED",
                )
                cursor.execute(
                    """SELECT id,decision,passed_cases,failed_cases,receipt_ref,
                              receipt_hash,evaluator_principal,reason_codes_json
                         FROM solvan_operability.trigger_policy_evaluations
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s AND policy_version=%(version)s
                          AND policy_hash=%(digest)s AND suite_version=%(suite)s""",
                    {
                        **scope.canonical_dict(),
                        "policy_key": policy_key,
                        "version": version,
                        "digest": expected_digest,
                        "suite": suite_version,
                    },
                )
                evaluation = cursor.fetchone()
                expected_decision = "PASS" if failed_cases == 0 else "FAIL"
                if evaluation is None:
                    raise GuidanceError("trigger evaluation idempotency record is inconsistent")
                if (
                    evaluation["decision"] != expected_decision
                    or int(evaluation["passed_cases"]) != passed_cases
                    or int(evaluation["failed_cases"]) != failed_cases
                    or evaluation["receipt_ref"] != receipt_ref
                    or evaluation["receipt_hash"] != receipt_hash
                    or evaluation["evaluator_principal"] != principal
                    or tuple(evaluation["reason_codes_json"]) != reason_codes
                ):
                    raise GuidanceError(
                        "trigger evaluation request ID was reused with changed material"
                    )
                return str(evaluation["id"])
            if policy_row["lifecycle"] != "DRAFT":
                raise GuidanceError("trigger policy is not eligible for evaluation")
            decision = "PASS" if failed_cases == 0 else "FAIL"
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_evaluations
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,suite_version,decision,passed_cases,
                      failed_cases,receipt_ref,receipt_hash,evaluator_principal,
                      reason_codes_json)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(version)s,%(digest)s,%(suite)s,%(decision)s,
                           %(passed)s,%(failed)s,%(receipt_ref)s,%(receipt_hash)s,
                           %(principal)s,%(reasons)s)""",
                {
                    **scope.canonical_dict(),
                    "id": evaluation_id,
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "suite": suite_version,
                    "decision": decision,
                    "passed": passed_cases,
                    "failed": failed_cases,
                    "receipt_ref": receipt_ref,
                    "receipt_hash": receipt_hash,
                    "principal": principal,
                    "reasons": Jsonb(list(reason_codes)),
                },
            )
            if decision == "PASS":
                cursor.execute(
                    """UPDATE solvan_operability.trigger_policy_revisions
                          SET evaluation_ref=%(evaluation_id)s
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND policy_key=%(policy_key)s AND version=%(version)s""",
                    {
                        **scope.canonical_dict(),
                        "evaluation_id": evaluation_id,
                        "policy_key": policy_key,
                        "version": version,
                    },
                )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="TRIGGER_POLICY_EVALUATED",
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code=reason_codes[0],
            )
        return evaluation_id

    def approve(
        self,
        *,
        scope: Scope,
        policy_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        reason: str,
        decision_request_id: str,
    ) -> TriggerPolicyLifecycleCommit:
        if not reason.strip():
            raise GuidanceError("trigger policy approval reason is required")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            entity_ref = f"trigger-policy:{policy_key}@{version}"
            cursor.execute(
                """SELECT p.*,e.decision AS evaluation_decision,
                          e.policy_hash AS evaluation_digest,e.evaluator_principal
                     FROM solvan_operability.trigger_policy_revisions p
                     LEFT JOIN solvan_operability.trigger_policy_evaluations e ON
                       (e.organization_id,e.project_id,e.environment_id,e.id)=
                       (p.organization_id,p.project_id,p.environment_id,p.evaluation_ref)
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s AND p.environment_id=%(environment_id)s
                      AND p.policy_key=%(policy_key)s AND p.version=%(version)s
                    FOR UPDATE OF p""",
                {**scope.canonical_dict(), "policy_key": policy_key, "version": version},
            )
            row = cursor.fetchone()
            if row is None:
                raise GuidanceError("trigger policy is not awaiting approval")
            if row["policy_hash"] != expected_digest:
                raise GuidanceError("trigger policy approval digest is stale")
            if row["author_principal"] == principal:
                raise GuidanceError("a trigger policy author cannot approve their revision")
            if row["evaluation_decision"] != "PASS" or row["evaluation_digest"] != expected_digest:
                raise GuidanceError("trigger policy evaluation is absent, failed, or stale")
            if row["evaluator_principal"] in {row["author_principal"], principal}:
                raise GuidanceError("trigger author, evaluator, and approver must be distinct")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("TRIGGER_POLICY_APPROVER", "OPERABILITY_ADMIN"),
                department=str(row["owner_department"]),
            )
            self._require_policy_dependencies(cursor=cursor, scope=scope, row=row)
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=expected_digest,
                    principal=principal,
                    event_type="TRIGGER_POLICY_APPROVED",
                )
                cursor.execute(
                    """SELECT id,evaluation_ref,approver_principal,reason
                         FROM solvan_operability.trigger_policy_approvals
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND decision_request_id=%(request_id)s""",
                    {**scope.canonical_dict(), "request_id": decision_request_id},
                )
                approval = cursor.fetchone()
                if (
                    approval is None
                    or approval["evaluation_ref"] != row["evaluation_ref"]
                    or approval["approver_principal"] != principal
                    or approval["reason"] != reason.strip()
                ):
                    raise GuidanceError(
                        "trigger approval request ID was reused with changed material"
                    )
                return TriggerPolicyLifecycleCommit(
                    policy_key,
                    version,
                    "APPROVED",
                    expected_digest,
                    str(approval["id"]),
                    False,
                )
            if row["lifecycle"] != "DRAFT":
                raise GuidanceError("trigger policy is not awaiting approval")
            approval_id = new_identifier("tap")
            cursor.execute(
                """INSERT INTO solvan_operability.trigger_policy_approvals
                     (organization_id,project_id,environment_id,id,policy_key,
                      policy_version,policy_hash,evaluation_ref,approver_principal,
                      decision,reason,decision_request_id)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(policy_key)s,%(version)s,%(digest)s,%(evaluation_ref)s,
                           %(principal)s,'APPROVE',%(reason)s,%(request_id)s)""",
                {
                    **scope.canonical_dict(),
                    "id": approval_id,
                    "policy_key": policy_key,
                    "version": version,
                    "digest": expected_digest,
                    "evaluation_ref": row["evaluation_ref"],
                    "principal": principal,
                    "reason": reason.strip(),
                    "request_id": decision_request_id,
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.trigger_policy_revisions
                      SET lifecycle='APPROVED',approval_ref=%(approval_id)s,
                          approved_by_principal=%(principal)s,approved_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND policy_key=%(policy_key)s AND version=%(version)s""",
                {
                    **scope.canonical_dict(),
                    "approval_id": approval_id,
                    "principal": principal,
                    "policy_key": policy_key,
                    "version": version,
                },
            )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="TRIGGER_POLICY_APPROVED",
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code="INDEPENDENT_APPROVAL_RECORDED",
            )
        return TriggerPolicyLifecycleCommit(
            policy_key, version, "APPROVED", expected_digest, approval_id, True
        )
