"""Exact human approval recording with workflow and target TOCTOU fences."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import ActionPolicyError, Scope, new_identifier
from solvan.persistence.action_material import material_from_action
from solvan.persistence.postgres import PostgresWorkflowStore
from solvan.persistence.postgres_types import (
    AggregateType,
    LeaseHandle,
    TransitionWrite,
    WorkflowConflict,
)


@dataclass(frozen=True, slots=True)
class ApprovalCommit:
    approval_id: str
    action_id: str
    action_digest: str
    workflow_version: int
    created: bool


@dataclass(frozen=True, slots=True)
class ApprovalReview:
    action_id: str
    display_id: str
    incident_id: str
    action_type: str
    action_digest: str
    target_key: str
    expected_target_version: str
    expected_target_epoch: int
    evidence_version: int
    workflow_version: int
    policy_version: str
    verification_profile_id: str
    verification_profile_version: int
    risk_class: str
    payload: dict[str, object]
    expected_effect: dict[str, object]
    expected_effect_hash: str
    rollback_plan: dict[str, object]
    expires_at: datetime
    status: str


class PostgresApprovalStore:
    """Persist a distinct approver's exact decision and authorize one action."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection
        self._workflow = PostgresWorkflowStore(connection)

    def review(self, *, scope: Scope, action_id: str) -> ApprovalReview:
        """Return exactly the immutable material a human must inspect."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.*, p.policy_version
                  FROM solvan.actions a
                  JOIN solvan.policy_decisions p
                    ON (p.organization_id, p.project_id, p.environment_id, p.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.policy_decision_id)
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.id = %(action_id)s AND a.requires_approval
                    AND a.status IN ('AWAITING_APPROVAL','AUTHORIZED')""",
                {**scope.canonical_dict(), "action_id": action_id},
            )
            action = cursor.fetchone()
        if action is None or action["incident_id"] is None:
            raise ActionPolicyError("approval_action_not_reviewable")
        material = material_from_action(action, scope)
        return ApprovalReview(
            action_id=str(action["id"]),
            display_id=str(action["display_id"]),
            incident_id=str(action["incident_id"]),
            action_type=str(action["action_type"]),
            action_digest=material.approval_digest(),
            target_key=str(action["target_key"]),
            expected_target_version=str(action["expected_target_version"]),
            expected_target_epoch=int(action["expected_target_epoch"]),
            evidence_version=int(action["evidence_version"]),
            workflow_version=int(action["workflow_version"]),
            policy_version=str(action["policy_version"]),
            verification_profile_id=str(action["verification_profile_id"]),
            verification_profile_version=int(action["verification_profile_version"]),
            risk_class=str(action["risk_class"]),
            payload=dict(action["payload_json"]),
            expected_effect=dict(action["expected_effect_json"]),
            expected_effect_hash=str(action["expected_effect_hash"]),
            rollback_plan=dict(action["rollback_plan_json"]),
            expires_at=action["expires_at"],
            status=str(action["status"]),
        )

    def approve(
        self,
        *,
        scope: Scope,
        lease: LeaseHandle,
        action_id: str,
        approver_principal: str,
        expected_action_digest: str,
        decision_request_id: str,
        reason: str,
    ) -> ApprovalCommit:
        if lease.aggregate_type is not AggregateType.INCIDENT:
            raise ValueError("action approval requires an incident lease")
        if not approver_principal or not reason.strip() or not decision_request_id.strip():
            raise ValueError("approver, reason, and decision request ID are required")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT ap.id, ap.action_id, ap.action_digest,
                    ap.approver_principal, i.workflow_version
                  FROM solvan.approvals ap
                  JOIN solvan.actions a
                    ON (a.organization_id, a.project_id, a.environment_id, a.id)
                     = (ap.organization_id, ap.project_id, ap.environment_id,
                        ap.action_id)
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  WHERE ap.organization_id = %(organization_id)s
                    AND ap.project_id = %(project_id)s
                    AND ap.environment_id = %(environment_id)s
                    AND ap.decision_request_id = %(request_id)s FOR UPDATE OF ap""",
                {**scope.canonical_dict(), "request_id": decision_request_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if (
                    existing["action_id"] != action_id
                    or existing["action_digest"] != expected_action_digest
                    or existing["approver_principal"] != approver_principal
                ):
                    raise ActionPolicyError("approval_idempotency_material_mismatch")
                return ApprovalCommit(
                    str(existing["id"]),
                    action_id,
                    expected_action_digest,
                    int(existing["workflow_version"]),
                    False,
                )

            cursor.execute(
                """SELECT a.*, p.policy_version, p.decision AS policy_decision,
                    i.workflow_version AS current_workflow_version,
                    i.evidence_version AS current_evidence_version,
                    i.state AS incident_state, t.epoch AS current_target_epoch,
                    t.last_observed_version AS current_target_version,
                    now() AS database_now
                  FROM solvan.actions a
                  JOIN solvan.policy_decisions p
                    ON (p.organization_id, p.project_id, p.environment_id, p.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.policy_decision_id)
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  JOIN solvan.target_epochs t
                    ON (t.organization_id, t.project_id, t.environment_id, t.target_key)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.target_key)
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.id = %(action_id)s AND a.incident_id = %(incident_id)s
                    AND i.workflow_version = %(workflow_version)s
                    AND i.lease_owner = %(lease_owner)s
                    AND i.lease_token = %(lease_token)s
                    AND i.lease_expires_at >= now()
                  FOR UPDATE OF a, p, i, t""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "incident_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            action = cursor.fetchone()
            if action is None:
                raise WorkflowConflict("approval action or incident lease is stale")
            material = material_from_action(action, scope)
            checks = (
                (action["incident_state"] == "AWAITING_APPROVAL", "incident_not_waiting"),
                (action["status"] == "AWAITING_APPROVAL", "action_not_waiting"),
                (action["requires_approval"] is True, "approval_not_required"),
                (action["policy_decision"] == "REQUIRE_APPROVAL", "policy_not_approval"),
                (
                    int(action["workflow_version"]) == int(action["current_workflow_version"]) + 1,
                    "approval_future_workflow_mismatch",
                ),
                (
                    int(action["evidence_version"]) == int(action["current_evidence_version"]),
                    "approval_evidence_stale",
                ),
                (
                    int(action["expected_target_epoch"]) == int(action["current_target_epoch"]),
                    "approval_target_epoch_stale",
                ),
                (
                    action["expected_target_version"] == action["current_target_version"],
                    "approval_target_version_stale",
                ),
                (action["expires_at"] > action["database_now"], "approval_action_expired"),
                (
                    action["proposer_principal"] != approver_principal,
                    "proposer_approver_separation_failed",
                ),
                (
                    material.approval_digest() == expected_action_digest,
                    "approval_digest_mismatch",
                ),
            )
            for passed, reason_code in checks:
                if not passed:
                    raise ActionPolicyError(reason_code)
            cursor.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND principal = %(principal)s AND role = 'APPROVER'
                      AND (expires_at IS NULL OR expires_at > now())) AS active""",
                {**scope.canonical_dict(), "principal": approver_principal},
            )
            role = cursor.fetchone()
            if role is None or not role["active"]:
                raise ActionPolicyError("approver_role_inactive")

            approval_id = new_identifier("apr")
            approval_expires_at = min(
                action["expires_at"], action["database_now"] + timedelta(minutes=5)
            )
            cursor.execute(
                """INSERT INTO solvan.approvals
                  (organization_id, project_id, environment_id, id, action_id,
                   sequence_no, action_digest, target_key, expected_target_version,
                   expected_target_epoch, evidence_version, policy_version,
                   approver_principal, decision, reason, decision_request_id,
                   expires_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(approval_id)s, %(action_id)s, 1, %(action_digest)s,
                    %(target_key)s, %(target_version)s, %(target_epoch)s,
                    %(evidence_version)s, %(policy_version)s, %(principal)s,
                    'APPROVE', %(reason)s, %(request_id)s, %(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "approval_id": approval_id,
                    "action_id": action_id,
                    "action_digest": expected_action_digest,
                    "target_key": action["target_key"],
                    "target_version": action["expected_target_version"],
                    "target_epoch": action["expected_target_epoch"],
                    "evidence_version": action["evidence_version"],
                    "policy_version": action["policy_version"],
                    "principal": approver_principal,
                    "reason": reason.strip(),
                    "request_id": decision_request_id,
                    "expires_at": approval_expires_at,
                },
            )
            cursor.execute(
                """UPDATE solvan.actions SET status = 'AUTHORIZED'
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(action_id)s AND status = 'AWAITING_APPROVAL'
                  RETURNING id""",
                {**scope.canonical_dict(), "action_id": action_id},
            )
            if cursor.fetchone() is None:
                raise WorkflowConflict("action changed while approval was recorded")
            workflow_version = self._workflow.commit_transition(
                scope=scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="AWAITING_APPROVAL",
                    to_state="MITIGATING",
                    transition_key=f"APPROVAL_GRANTED:{approval_id}",
                    actor_type="HUMAN",
                    actor_id=approver_principal,
                    policy_decision_id=str(action["policy_decision_id"]),
                    reason_code="EXACT_UNEXPIRED_APPROVAL",
                    rationale_summary=reason.strip(),
                    evidence_refs=(f"db://solvan/approvals/{approval_id}",),
                ),
            )
            if workflow_version != int(action["workflow_version"]):
                raise WorkflowConflict("approval transition did not reach bound version")
            return ApprovalCommit(
                approval_id,
                action_id,
                expected_action_digest,
                workflow_version,
                True,
            )
