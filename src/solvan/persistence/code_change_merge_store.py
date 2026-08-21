"""Durable command and effect fences for one governed GitHub merge."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.code_change_operation_store import CodeChangeOperationConflict


@dataclass(frozen=True, slots=True)
class MergeCommandCandidate:
    request_id: str
    decision_id: str
    decision_digest: str
    material_hash: str
    github_observation_hash: str
    sequence_no: int
    deadline: datetime


@dataclass(frozen=True, slots=True)
class MergeProviderMaterial:
    request_id: str
    repository_binding_id: str
    repository_policy_hash: str
    installation_id: int
    owner: str
    name: str
    default_branch: str
    base_commit_sha: str
    proposed_tree_hash: str
    patch_transform_ref: str
    patch_transform_hash: str
    required_checks_policy_ref: str
    required_checks_policy_hash: str
    reviewer_policy_ref: str
    reviewer_policy_hash: str
    merge_policy_ref: str
    merge_policy_hash: str
    required_check_definition_paths: tuple[str, ...]
    base_required_check_definitions_hash: str
    branch_name: str
    pull_request_number: int
    pull_request_url: str
    expected_head_commit_sha: str
    github_reviewer_binding_id: str
    github_account_node_id: str
    github_review_state_hash: str
    diff_hash: str
    required_checks_ref: str
    required_checks_hash: str
    branch_rule_ref: str
    branch_rule_hash: str
    review_state_ref: str
    required_check_definitions_ref: str
    decision_id: str
    decision_digest: str
    expires_at: datetime
    operation_status: str


class PostgresCodeChangeMergeStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def candidates(self, *, scope: Scope, limit: int = 20) -> tuple[MergeCommandCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id,r.sequence_no,r.expires_at,r.immutable_request_hash,
                          decision.id AS decision_id,decision.decision_digest,
                          observation.observation_hash
                     FROM solvan_delivery.code_change_requests r
                     JOIN solvan_delivery.code_change_decisions decision
                       ON decision.organization_id=r.organization_id
                      AND decision.project_id=r.project_id
                      AND decision.environment_id=r.environment_id
                      AND decision.code_change_request_id=r.id
                      AND decision.stage='MERGE' AND decision.decision='APPROVED'
                      AND decision.expires_at>now()
                     JOIN LATERAL (
                       SELECT observation_hash,review_state_hash
                         FROM solvan_delivery.code_change_github_observations item
                        WHERE item.organization_id=r.organization_id
                          AND item.project_id=r.project_id
                          AND item.environment_id=r.environment_id
                          AND item.code_change_request_id=r.id
                        ORDER BY item.sequence_no DESC LIMIT 1
                     ) observation ON observation.review_state_hash=
                       decision.github_review_state_hash
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.state='MERGE_APPROVAL_PENDING' AND r.expires_at>now()
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.code_change_decisions child
                         WHERE child.organization_id=decision.organization_id
                           AND child.project_id=decision.project_id
                           AND child.environment_id=decision.environment_id
                           AND child.supersedes_id=decision.id)
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=r.organization_id
                           AND command.project_id=r.project_id
                           AND command.environment_id=r.environment_id
                           AND command.command_kind='MERGE_PR' AND command.subject_id=r.id)
                    ORDER BY decision.decided_at,decision.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(self._candidate(row) for row in cursor.fetchall())

    @staticmethod
    def _candidate(row: Mapping[str, Any]) -> MergeCommandCandidate:
        material_hash = canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "MERGE_PR",
                "code_change_request_id": str(row["id"]),
                "immutable_request_hash": str(row["immutable_request_hash"]),
                "decision_id": str(row["decision_id"]),
                "decision_digest": str(row["decision_digest"]),
                "github_observation_hash": str(row["observation_hash"]),
                "transition_sequence_no": int(row["sequence_no"]),
            }
        )
        return MergeCommandCandidate(
            request_id=str(row["id"]),
            decision_id=str(row["decision_id"]),
            decision_digest=str(row["decision_digest"]),
            material_hash=material_hash,
            github_observation_hash=str(row["observation_hash"]),
            sequence_no=int(row["sequence_no"]),
            deadline=row["expires_at"],
        )

    def prepare(
        self,
        *,
        scope: Scope,
        candidate: MergeCommandCandidate,
        request_ref: str,
        request_hash: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_operations
                    (organization_id,project_id,environment_id,id,
                     code_change_request_id,transition_sequence_no,operation_kind,
                     material_hash,idempotency_key,status,request_ref,request_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(sequence)s,'MERGE_PR',%(material_hash)s,
                     %(idempotency_key)s,'PREPARED',%(request_ref)s,%(request_hash)s)
                   ON CONFLICT DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("cco"),
                    "request_id": candidate.request_id,
                    "sequence": candidate.sequence_no,
                    "material_hash": candidate.material_hash,
                    "idempotency_key": f"merge-pr:{candidate.request_id}",
                    "request_ref": request_ref,
                    "request_hash": request_hash,
                },
            )
            if cursor.rowcount != 1:
                raise CodeChangeOperationConflict("merge operation already exists")

    def dispatchable_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan_delivery.private_command_dispatches
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND command_kind='MERGE_PR'
                      AND status IN ('PREPARED','ISSUED','RECONCILING')
                      AND deadline>now() ORDER BY created_at,id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def load(
        self,
        *,
        scope: Scope,
        request_id: str,
        command_material_hash: str,
        github_observation_hash: str,
        now: datetime,
    ) -> MergeProviderMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.*,repository.installation_id,repository.owner,repository.name,
                          repository.policy_hash AS active_repository_policy_hash,
                          repository.status AS repository_status,
                          profile.required_check_definition_paths_json,
                          observation.pull_request_number,observation.pull_request_url,
                          observation.branch_name,observation.head_commit_sha,
                          observation.review_state_hash,
                          decision.id AS decision_id,decision.decision_digest,
                          decision.github_reviewer_binding_id,
                          decision.expires_at AS decision_expires_at,
                          binding.github_account_node_id,binding.status AS binding_status,
                          binding.expires_at AS binding_expires_at,
                          operation.status AS operation_status
                     FROM solvan_delivery.code_change_requests r
                     JOIN solvan.github_repositories repository
                       ON (repository.organization_id,repository.project_id,
                           repository.environment_id,repository.id)=
                          (r.organization_id,r.project_id,r.environment_id,
                           r.repository_binding_id)
                     JOIN solvan_delivery.code_delivery_profiles profile
                       ON (profile.organization_id,profile.project_id,
                           profile.environment_id,profile.id)=
                          (r.organization_id,r.project_id,r.environment_id,
                           r.code_delivery_profile_id)
                     JOIN solvan_delivery.code_change_decisions decision
                       ON decision.organization_id=r.organization_id
                      AND decision.project_id=r.project_id
                      AND decision.environment_id=r.environment_id
                      AND decision.code_change_request_id=r.id
                      AND decision.stage='MERGE' AND decision.decision='APPROVED'
                     JOIN solvan_delivery.github_reviewer_bindings binding
                       ON binding.organization_id=decision.organization_id
                      AND binding.project_id=decision.project_id
                      AND binding.environment_id=decision.environment_id
                      AND binding.id=decision.github_reviewer_binding_id
                     JOIN LATERAL (
                       SELECT * FROM solvan_delivery.code_change_github_observations item
                        WHERE item.organization_id=r.organization_id
                          AND item.project_id=r.project_id
                          AND item.environment_id=r.environment_id
                          AND item.code_change_request_id=r.id
                        ORDER BY item.sequence_no DESC LIMIT 1
                     ) observation ON observation.review_state_hash=
                       decision.github_review_state_hash
                       AND observation.observation_hash=%(github_observation_hash)s
                     JOIN solvan_delivery.code_change_operations operation
                       ON operation.organization_id=r.organization_id
                      AND operation.project_id=r.project_id
                      AND operation.environment_id=r.environment_id
                      AND operation.code_change_request_id=r.id
                      AND operation.operation_kind='MERGE_PR'
                      AND operation.material_hash=%(material_hash)s
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.id=%(request_id)s AND r.state='MERGE_APPROVAL_PENDING'
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.code_change_decisions child
                         WHERE child.organization_id=decision.organization_id
                           AND child.project_id=decision.project_id
                           AND child.environment_id=decision.environment_id
                           AND child.supersedes_id=decision.id)
                    FOR UPDATE OF r,repository,decision,binding,operation""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": command_material_hash,
                    "github_observation_hash": github_observation_hash,
                },
            )
            row = cursor.fetchone()
        paths = row["required_check_definition_paths_json"] if row is not None else None
        if (
            row is None
            or row["repository_status"] != "ACTIVE"
            or row["active_repository_policy_hash"] != row["repository_policy_hash"]
            or row["binding_status"] != "ACTIVE"
            or row["expires_at"] <= now
            or row["decision_expires_at"] <= now
            or row["binding_expires_at"] <= now
            or row["operation_status"] not in {"PREPARED", "ISSUED", "RECONCILING"}
            or not isinstance(paths, list)
            or any(not isinstance(item, str) for item in paths)
        ):
            raise CodeChangeOperationConflict("merge authority is stale or unavailable")
        return MergeProviderMaterial(
            request_id=str(row["id"]),
            repository_binding_id=str(row["repository_binding_id"]),
            repository_policy_hash=str(row["repository_policy_hash"]),
            installation_id=int(row["installation_id"]),
            owner=str(row["owner"]),
            name=str(row["name"]),
            default_branch=str(row["default_branch"]),
            base_commit_sha=str(row["base_commit_sha"]),
            proposed_tree_hash=str(row["proposed_tree_hash"]),
            patch_transform_ref=str(row["patch_transform_ref"]),
            patch_transform_hash=str(row["patch_transform_hash"]),
            required_checks_policy_ref=str(row["required_checks_policy_ref"]),
            required_checks_policy_hash=str(row["required_checks_policy_hash"]),
            reviewer_policy_ref=str(row["reviewer_policy_ref"]),
            reviewer_policy_hash=str(row["reviewer_policy_hash"]),
            merge_policy_ref=str(row["merge_policy_ref"]),
            merge_policy_hash=str(row["merge_policy_hash"]),
            required_check_definition_paths=tuple(paths),
            base_required_check_definitions_hash=str(row["base_required_check_definitions_hash"]),
            branch_name=str(row["branch_name"]),
            pull_request_number=int(row["pull_request_number"]),
            pull_request_url=str(row["pull_request_url"]),
            expected_head_commit_sha=str(row["head_commit_sha"]),
            github_reviewer_binding_id=str(row["github_reviewer_binding_id"]),
            github_account_node_id=str(row["github_account_node_id"]),
            github_review_state_hash=str(row["review_state_hash"]),
            diff_hash=str(row["diff_hash"]),
            required_checks_ref=str(row["required_checks_ref"]),
            required_checks_hash=str(row["required_checks_hash"]),
            branch_rule_ref=str(row["branch_rule_ref"]),
            branch_rule_hash=str(row["branch_rule_hash"]),
            review_state_ref=str(row["review_state_ref"]),
            required_check_definitions_ref=str(row["required_check_definitions_ref"]),
            decision_id=str(row["decision_id"]),
            decision_digest=str(row["decision_digest"]),
            expires_at=row["expires_at"],
            operation_status=str(row["operation_status"]),
        )

    def claim(self, *, scope: Scope, request_id: str, material_hash: str) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.code_change_operations
                      SET status='ISSUED',issued_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind='MERGE_PR' AND material_hash=%(material_hash)s
                      AND status='PREPARED'""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": material_hash,
                },
            )
            return cursor.rowcount == 1

    def complete(
        self,
        *,
        scope: Scope,
        request_id: str,
        material_hash: str,
        response_ref: str,
        response_hash: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.code_change_operations
                      SET status='SUCCEEDED',response_ref=%(response_ref)s,
                          response_hash=%(response_hash)s,reconciled_at=now(),completed_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind='MERGE_PR' AND material_hash=%(material_hash)s
                      AND status IN ('ISSUED','RECONCILING')""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": material_hash,
                    "response_ref": response_ref,
                    "response_hash": response_hash,
                },
            )
            if cursor.rowcount != 1:
                raise CodeChangeOperationConflict("merge operation completion is stale")

    def terminal_receipt(
        self, *, scope: Scope, request_id: str, material_hash: str
    ) -> tuple[str, str] | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT response_ref,response_hash
                     FROM solvan_delivery.code_change_operations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind='MERGE_PR' AND material_hash=%(material_hash)s
                      AND status='SUCCEEDED'""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": material_hash,
                },
            )
            row = cursor.fetchone()
        if row is None:
            return None
        if not isinstance(row[0], str) or not isinstance(row[1], str):
            raise CodeChangeOperationConflict("merge terminal receipt is malformed")
        return row[0], row[1]
