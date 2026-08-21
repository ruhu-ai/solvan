"""Exact human patch-review intent and coordinator application fences."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import ActionPolicyError, Scope, new_identifier
from solvan.persistence.postgres_types import AggregateType, LeaseHandle, WorkflowConflict


@dataclass(frozen=True, slots=True)
class PatchReviewMaterial:
    reliability_case_id: str
    patch_artifact_id: str
    repair_plan_id: str
    base_commit_sha: str
    changed_paths: tuple[str, ...]
    unified_diff_ref: str
    unified_diff_hash: str
    test_command: str
    test_output_ref: str
    test_output_hash: str
    residual_risks: tuple[str, ...]
    patch_digest: str
    state: str


@dataclass(frozen=True, slots=True)
class PatchReviewCommit:
    review_id: str
    patch_artifact_id: str
    patch_digest: str
    decision: str
    created: bool


@dataclass(frozen=True, slots=True)
class PendingPatchReview:
    review_id: str
    reliability_case_id: str


@dataclass(frozen=True, slots=True)
class PatchReviewDecision:
    review_id: str
    patch_artifact_id: str
    decision: str
    reviewer_principal: str
    patch_digest: str


class PostgresPatchReviewStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def review(self, *, scope: Scope, patch_artifact_id: str) -> PatchReviewMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT pa.*, p.id AS exact_repair_plan_id, c.state AS case_state
                  FROM solvan.patch_artifacts pa
                  JOIN solvan.repair_plans p
                    ON (p.organization_id, p.project_id, p.environment_id, p.id)
                     = (pa.organization_id, pa.project_id, pa.environment_id,
                        pa.repair_plan_id)
                  JOIN solvan.reliability_cases c
                    ON (c.organization_id, c.project_id, c.environment_id, c.id)
                     = (pa.organization_id, pa.project_id, pa.environment_id,
                        pa.reliability_case_id)
                  WHERE pa.organization_id = %(organization_id)s
                    AND pa.project_id = %(project_id)s
                    AND pa.environment_id = %(environment_id)s
                    AND pa.id = %(patch_artifact_id)s
                    AND pa.status = 'TESTS_PASSED' AND p.status = 'ACTIVE'
                    AND c.state IN ('AWAITING_REVIEW','READY_FOR_CANARY')""",
                {**scope.canonical_dict(), "patch_artifact_id": patch_artifact_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise ActionPolicyError("patch_artifact_not_reviewable")
        changed_paths = tuple(str(item) for item in row["changed_paths_json"])
        residual_risks = tuple(str(item) for item in row["residual_risks_json"])
        digest = _patch_digest(
            patch_artifact_id=str(row["id"]),
            repair_plan_id=str(row["exact_repair_plan_id"]),
            base_commit_sha=str(row["base_commit_sha"]),
            changed_paths=changed_paths,
            unified_diff_hash=str(row["unified_diff_hash"]),
            test_command=str(row["test_command"]),
            test_output_hash=str(row["test_output_hash"]),
        )
        return PatchReviewMaterial(
            reliability_case_id=str(row["reliability_case_id"]),
            patch_artifact_id=str(row["id"]),
            repair_plan_id=str(row["exact_repair_plan_id"]),
            base_commit_sha=str(row["base_commit_sha"]),
            changed_paths=changed_paths,
            unified_diff_ref=str(row["unified_diff_ref"]),
            unified_diff_hash=str(row["unified_diff_hash"]),
            test_command=str(row["test_command"]),
            test_output_ref=str(row["test_output_ref"]),
            test_output_hash=str(row["test_output_hash"]),
            residual_risks=residual_risks,
            patch_digest=digest,
            state=str(row["case_state"]),
        )

    def decide(
        self,
        *,
        scope: Scope,
        patch_artifact_id: str,
        reviewer_principal: str,
        expected_patch_digest: str,
        decision: str,
        reason: str,
        decision_request_id: str,
    ) -> PatchReviewCommit:
        if decision not in {"APPROVE", "CHANGES_REQUESTED"}:
            raise ValueError("patch review decision is unsupported")
        if not reason.strip() or not decision_request_id.strip():
            raise ValueError("patch review reason and request ID are required")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan.patch_reviews
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND decision_request_id = %(request_id)s FOR UPDATE""",
                {**scope.canonical_dict(), "request_id": decision_request_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if (
                    existing["patch_artifact_id"] != patch_artifact_id
                    or existing["patch_digest"] != expected_patch_digest
                    or existing["reviewer_principal"] != reviewer_principal
                    or existing["decision"] != decision
                ):
                    raise ActionPolicyError("patch_review_idempotency_material_mismatch")
                return PatchReviewCommit(
                    str(existing["id"]),
                    patch_artifact_id,
                    expected_patch_digest,
                    decision,
                    False,
                )
            material = self.review(scope=scope, patch_artifact_id=patch_artifact_id)
            if material.state != "AWAITING_REVIEW":
                raise ActionPolicyError("patch_case_not_waiting_for_review")
            if material.patch_digest != expected_patch_digest:
                raise ActionPolicyError("patch_review_digest_mismatch")
            cursor.execute(
                """SELECT 1 FROM solvan.actor_role_bindings
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND principal = %(principal)s AND role='CODE_CHANGE_APPROVER'
                    AND (expires_at IS NULL OR expires_at > now())""",
                {**scope.canonical_dict(), "principal": reviewer_principal},
            )
            if cursor.fetchone() is None:
                raise ActionPolicyError("code_change_approver_role_required")
            review_id = new_identifier("prv")
            cursor.execute(
                """INSERT INTO solvan.patch_reviews
                  (organization_id, project_id, environment_id, id,
                   reliability_case_id, patch_artifact_id, decision_request_id,
                   patch_digest, reviewer_principal, decision, reason)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(review_id)s, %(case_id)s, %(patch_artifact_id)s,
                    %(request_id)s, %(patch_digest)s, %(reviewer)s,
                    %(decision)s, %(reason)s)""",
                {
                    **scope.canonical_dict(),
                    "review_id": review_id,
                    "case_id": material.reliability_case_id,
                    "patch_artifact_id": patch_artifact_id,
                    "request_id": decision_request_id,
                    "patch_digest": expected_patch_digest,
                    "reviewer": reviewer_principal,
                    "decision": decision,
                    "reason": reason.strip(),
                },
            )
            cursor.execute(
                """INSERT INTO solvan.outbox_events
                  (organization_id, project_id, environment_id, id, aggregate_type,
                   aggregate_id, aggregate_version, topic, event_type,
                   payload_json, idempotency_key)
                  SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(event_id)s, 'RELIABILITY_CASE', c.id, c.workflow_version,
                    'patch-reviews', 'PatchReviewRecorded',
                    jsonb_build_object('review_id', %(review_id)s::text,
                      'patch_artifact_id', %(patch_artifact_id)s::text,
                      'decision', %(decision)s::text), %(idempotency_key)s
                  FROM solvan.reliability_cases c
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'AWAITING_REVIEW'""",
                {
                    **scope.canonical_dict(),
                    "event_id": new_identifier("evt"),
                    "case_id": material.reliability_case_id,
                    "review_id": review_id,
                    "patch_artifact_id": patch_artifact_id,
                    "decision": decision,
                    "idempotency_key": f"patch-review:{review_id}",
                },
            )
            if cursor.rowcount != 1:
                raise WorkflowConflict("patch review case changed before outbox commit")
        return PatchReviewCommit(
            review_id, patch_artifact_id, expected_patch_digest, decision, True
        )

    def pending(self, *, scope: Scope, batch_size: int = 20) -> tuple[PendingPatchReview, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, reliability_case_id FROM solvan.patch_reviews
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND applied_at IS NULL
                  ORDER BY decided_at, id LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            return tuple(PendingPatchReview(str(row[0]), str(row[1])) for row in cursor.fetchall())

    def decision_for_apply(
        self, *, scope: Scope, lease: LeaseHandle, review_id: str
    ) -> PatchReviewDecision:
        if lease.aggregate_type is not AggregateType.RELIABILITY_CASE:
            raise ValueError("patch review application requires a Reliability Case lease")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.* FROM solvan.patch_reviews r
                  JOIN solvan.reliability_cases c
                    ON (c.organization_id, c.project_id, c.environment_id, c.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.reliability_case_id)
                  WHERE c.organization_id = %(organization_id)s
                    AND c.project_id = %(project_id)s
                    AND c.environment_id = %(environment_id)s
                    AND c.id = %(case_id)s AND c.state = 'AWAITING_REVIEW'
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()
                    AND r.id = %(review_id)s AND r.applied_at IS NULL
                  FOR UPDATE OF r, c""",
                {
                    **scope.canonical_dict(),
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                    "review_id": review_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkflowConflict("patch review or case lease is stale")
        return PatchReviewDecision(
            str(row["id"]),
            str(row["patch_artifact_id"]),
            str(row["decision"]),
            str(row["reviewer_principal"]),
            str(row["patch_digest"]),
        )

    def mark_applied(self, *, scope: Scope, lease: LeaseHandle, review_id: str) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.patch_reviews r SET applied_at = now()
                  FROM solvan.reliability_cases c
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.id = %(review_id)s AND r.applied_at IS NULL
                    AND c.organization_id = r.organization_id
                    AND c.project_id = r.project_id
                    AND c.environment_id = r.environment_id
                    AND c.id = r.reliability_case_id AND c.id = %(case_id)s
                    AND c.workflow_version = %(workflow_version)s
                    AND c.lease_owner = %(lease_owner)s
                    AND c.lease_token = %(lease_token)s
                    AND c.lease_expires_at >= now()""",
                {
                    **scope.canonical_dict(),
                    "review_id": review_id,
                    "case_id": lease.entity_id,
                    "workflow_version": lease.workflow_version,
                    "lease_owner": lease.owner,
                    "lease_token": lease.token,
                },
            )
            if cursor.rowcount != 1:
                raise WorkflowConflict("patch review application became stale")


def _patch_digest(
    *,
    patch_artifact_id: str,
    repair_plan_id: str,
    base_commit_sha: str,
    changed_paths: tuple[str, ...],
    unified_diff_hash: str,
    test_command: str,
    test_output_hash: str,
) -> str:
    value = {
        "schema_version": 1,
        "patch_artifact_id": patch_artifact_id,
        "repair_plan_id": repair_plan_id,
        "base_commit_sha": base_commit_sha,
        "changed_paths": list(changed_paths),
        "unified_diff_hash": unified_diff_hash,
        "test_command": test_command,
        "test_output_hash": test_output_hash,
    }
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
