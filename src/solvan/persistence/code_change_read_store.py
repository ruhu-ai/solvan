"""Secret-free, scope- and role-checked Code Change Request projections."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope


class CodeChangeReadConflict(ValueError):
    """The principal cannot read the requested governed change."""


class PostgresCodeChangeReadStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def current_for_case(
        self, *, scope: Scope, case_id: str, principal: str, now: datetime
    ) -> dict[str, object] | None:
        """Return the newest request and its immutable audit timeline."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._assert_reader_role(cursor, scope=scope, principal=principal, now=now)
            cursor.execute(
                """SELECT r.id
                     FROM solvan_delivery.code_change_requests r
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s
                      AND r.reliability_case_id=%(case_id)s
                    ORDER BY r.created_at DESC,r.id DESC LIMIT 1""",
                {**scope.canonical_dict(), "case_id": case_id},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._projection(cursor, scope=scope, request_id=str(row["id"]))

    def by_id(
        self, *, scope: Scope, request_id: str, principal: str, now: datetime
    ) -> dict[str, object]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._assert_reader_role(cursor, scope=scope, principal=principal, now=now)
            projection = self._projection(cursor, scope=scope, request_id=request_id)
        if projection is None:
            raise CodeChangeReadConflict("code-change request does not exist")
        return projection

    @staticmethod
    def _assert_reader_role(cursor: Any, *, scope: Scope, principal: str, now: datetime) -> None:
        cursor.execute(
            """SELECT 1 FROM solvan.actor_role_bindings
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND principal=%(principal)s
                  AND role IN ('CODE_CHANGE_APPROVER','RELEASE_APPROVER')
                  AND (expires_at IS NULL OR expires_at>%(now)s) LIMIT 1""",
            {**scope.canonical_dict(), "principal": principal, "now": now},
        )
        if cursor.fetchone() is None:
            raise CodeChangeReadConflict("current code-change or release role is required")

    @staticmethod
    def _projection(cursor: Any, *, scope: Scope, request_id: str) -> dict[str, object] | None:
        cursor.execute(
            """SELECT r.id,r.reliability_case_id,r.patch_artifact_id,r.patch_digest,
                      r.patch_transform_version,r.patch_transform_ref,
                      r.patch_transform_hash,r.proposed_tree_hash,
                      r.repository_binding_id,repository.owner,repository.name,
                      r.default_branch,r.base_commit_sha,r.base_tree_hash,
                      r.adjudication_receipt_ref,r.adjudication_receipt_hash,
                      r.base_required_check_definitions_ref,
                      r.base_required_check_definitions_hash,
                      r.required_checks_policy_hash,r.reviewer_policy_hash,
                      r.pr_creation_policy_hash,r.merge_policy_hash,
                      r.deployment_policy_hash,r.immutable_request_hash,
                      r.state,r.sequence_no,r.expires_at,r.created_by_principal,r.created_at
                 FROM solvan_delivery.code_change_requests r
                 JOIN solvan.github_repositories repository
                   ON (repository.organization_id,repository.project_id,
                       repository.environment_id,repository.id)=
                      (r.organization_id,r.project_id,r.environment_id,
                       r.repository_binding_id)
                WHERE r.organization_id=%(organization_id)s
                  AND r.project_id=%(project_id)s
                  AND r.environment_id=%(environment_id)s AND r.id=%(request_id)s""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        request = cursor.fetchone()
        if request is None:
            return None
        cursor.execute(
            """SELECT sequence_no,from_state,to_state,actor_kind,actor_identity,
                      receipt_ref,receipt_hash,decision_id,decision_digest,occurred_at
                 FROM solvan_delivery.code_change_transitions
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY sequence_no""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        transitions = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT id,stage,sequence_no,decision_digest,principal,
                      github_reviewer_binding_id,github_review_state_hash,
                      decision,reason,decided_at,expires_at,supersedes_id,
                      authorization_snapshot_hash,step_up_receipt_hash
                 FROM solvan_delivery.code_change_decisions
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY stage,sequence_no""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        decisions = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT operation_kind,material_hash,status,response_ref,response_hash,
                      error_class,prepared_at,issued_at,reconciled_at,completed_at
                 FROM solvan_delivery.code_change_operations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY prepared_at,id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        operations = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT sequence_no,observation_kind,pull_request_number,pull_request_url,
                      branch_name,base_commit_sha,head_commit_sha,merge_commit_sha,
                      head_tree_hash,diff_hash,required_check_state,
                      required_checks_ref,required_checks_hash,branch_rule_ref,
                      branch_rule_hash,review_state,review_state_ref,review_state_hash,
                      approved_account_node_ids,required_check_definitions_ref,
                      required_check_definitions_hash,repository_policy_hash,
                      provider_service_revision,observation_ref,observation_hash,observed_at
                 FROM solvan_delivery.code_change_github_observations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY sequence_no""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        github_observations = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT id,merged_commit_sha,source_tree_hash,build_artifact_ref,
                      build_artifact_hash,sbom_hash,provenance_hash,
                      release_signature_hash,signer_identity,signer_key_version,
                      deployment_manifest_hash,release_policy_hash,created_at
                 FROM solvan_delivery.release_candidates
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY created_at,id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        release_candidates = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT id,release_candidate_id,release_target_profile_id,target_key,
                      target_version,target_epoch,current_revision,assignment_hash,
                      observation_ref,observation_hash,observer_identity,
                      observer_service_revision,observed_at
                 FROM solvan_delivery.release_target_observations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY observed_at,id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        target_observations = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT id,release_candidate_id,release_target_profile_id,
                      target_observation_hash,verification_profile_hash,target_version,
                      target_assignment_hash,window_start,window_end,signal_results_hash,
                      baseline_ref,baseline_hash,verifier_identity,verifier_key_version,
                      signature_hash,observed_at
                 FROM solvan_delivery.release_health_baselines
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND code_change_request_id=%(request_id)s
                ORDER BY observed_at,id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        release_baselines = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT rollout.id,rollout.release_candidate_id,rollout.target_key,
                      rollout.target_provider,rollout.expected_target_version,
                      rollout.expected_target_epoch,rollout.target_reservation_id,
                      rollout.rollout_policy_hash,rollout.approval_digest,
                      rollout.predeploy_snapshot_hash,rollout.intended_effect_hash,
                      rollout.verification_profile_hash,
                      rollout.release_health_baseline_hash,rollout.status,
                      reservation.status AS reservation_status,
                      reservation.lease_expires_at,rollout.created_at
                 FROM solvan_delivery.deployment_rollouts rollout
                 JOIN solvan_delivery.release_candidates candidate
                   ON (candidate.organization_id,candidate.project_id,
                       candidate.environment_id,candidate.id)=
                      (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.release_candidate_id)
                 JOIN solvan_delivery.release_target_reservations reservation
                   ON (reservation.organization_id,reservation.project_id,
                       reservation.environment_id,reservation.id)=
                      (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.target_reservation_id)
                WHERE rollout.organization_id=%(organization_id)s
                  AND rollout.project_id=%(project_id)s
                  AND rollout.environment_id=%(environment_id)s
                  AND candidate.code_change_request_id=%(request_id)s
                ORDER BY rollout.created_at,rollout.id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        rollouts = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT operation.id,operation.deployment_rollout_id,
                      operation.operation_kind,operation.stage_ordinal,
                      operation.material_hash,operation.status,
                      operation.provider_request_id,operation.response_ref,
                      operation.response_hash,operation.error_class,
                      operation.prepared_at,operation.issued_at,
                      operation.reconciled_at,operation.completed_at
                 FROM solvan_delivery.deployment_rollout_operations operation
                 JOIN solvan_delivery.deployment_rollouts rollout
                   ON (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.id)=
                      (operation.organization_id,operation.project_id,
                       operation.environment_id,operation.deployment_rollout_id)
                 JOIN solvan_delivery.release_candidates candidate
                   ON (candidate.organization_id,candidate.project_id,
                       candidate.environment_id,candidate.id)=
                      (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.release_candidate_id)
                WHERE operation.organization_id=%(organization_id)s
                  AND operation.project_id=%(project_id)s
                  AND operation.environment_id=%(environment_id)s
                  AND candidate.code_change_request_id=%(request_id)s
                ORDER BY operation.prepared_at,operation.id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        rollout_operations = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT receipt.id,receipt.deployment_rollout_id,
                      receipt.stage_ordinal,receipt.observation_window_generation,
                      receipt.result,receipt.receipt_envelope_ref,
                      receipt.receipt_envelope_hash,receipt.signature_hash,
                      receipt.observed_target_version,receipt.observed_assignment_hash,
                      receipt.verifier_identity,receipt.verifier_key_version,
                      receipt.window_start,receipt.window_end,receipt.observed_at
                 FROM solvan_delivery.release_verification_receipts receipt
                 JOIN solvan_delivery.deployment_rollouts rollout
                   ON (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.id)=
                      (receipt.organization_id,receipt.project_id,
                       receipt.environment_id,receipt.deployment_rollout_id)
                 JOIN solvan_delivery.release_candidates candidate
                   ON (candidate.organization_id,candidate.project_id,
                       candidate.environment_id,candidate.id)=
                      (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.release_candidate_id)
                WHERE receipt.organization_id=%(organization_id)s
                  AND receipt.project_id=%(project_id)s
                  AND receipt.environment_id=%(environment_id)s
                  AND candidate.code_change_request_id=%(request_id)s
                ORDER BY receipt.stage_ordinal,receipt.observation_window_generation""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        release_verifications = [dict(row) for row in cursor.fetchall()]
        cursor.execute(
            """SELECT receipt.id,receipt.deployment_rollout_id,
                      receipt.expected_revision,receipt.observed_target_version,
                      receipt.observed_assignment_hash,receipt.result,
                      receipt.receipt_envelope_ref,receipt.receipt_envelope_hash,
                      receipt.signature_hash,receipt.verifier_identity,
                      receipt.verifier_key_version,receipt.observed_at
                 FROM solvan_delivery.release_rollback_verification_receipts receipt
                 JOIN solvan_delivery.deployment_rollouts rollout
                   ON (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.id)=
                      (receipt.organization_id,receipt.project_id,
                       receipt.environment_id,receipt.deployment_rollout_id)
                 JOIN solvan_delivery.release_candidates candidate
                   ON (candidate.organization_id,candidate.project_id,
                       candidate.environment_id,candidate.id)=
                      (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.release_candidate_id)
                WHERE receipt.organization_id=%(organization_id)s
                  AND receipt.project_id=%(project_id)s
                  AND receipt.environment_id=%(environment_id)s
                  AND candidate.code_change_request_id=%(request_id)s
                ORDER BY receipt.observed_at,receipt.id""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        rollback_verifications = [dict(row) for row in cursor.fetchall()]
        return {
            "request": cast("dict[str, object]", dict(request)),
            "transitions": transitions,
            "decisions": decisions,
            "operations": operations,
            "github_observations": github_observations,
            "release_candidates": release_candidates,
            "target_observations": target_observations,
            "release_baselines": release_baselines,
            "rollouts": rollouts,
            "rollout_operations": rollout_operations,
            "release_verifications": release_verifications,
            "rollback_verifications": rollback_verifications,
        }
