"""Durable coordinator/provider fences for governed GitHub code-change effects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.code_change_decisions import reserved_branch_name
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.code_change_sync_types import (
    PullRequestSyncCandidate,
    PullRequestSyncMaterial,
)


class CodeChangeOperationConflict(ValueError):
    """A GitHub operation cannot be prepared or reconciled safely."""


@dataclass(frozen=True, slots=True)
class PullRequestCommandCandidate:
    request_id: str
    decision_id: str
    decision_digest: str
    sequence_no: int
    expires_at: datetime
    material_hash: str


@dataclass(frozen=True, slots=True)
class PullRequestProviderMaterial:
    request_id: str
    immutable_request_hash: str
    repository_binding_id: str
    repository_policy_hash: str
    installation_id: int
    owner: str
    name: str
    default_branch: str
    base_commit_sha: str
    base_tree_hash: str
    proposed_tree_hash: str
    patch_transform_ref: str
    patch_transform_hash: str
    required_check_definition_paths_hash: str
    base_required_check_definitions_ref: str
    base_required_check_definitions_hash: str
    decision_id: str
    decision_digest: str
    branch_name: str
    created_at: datetime
    expires_at: datetime


class PostgresCodeChangeOperationStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def advance_approved_pr_creations(
        self, *, scope: Scope, coordinator_identity: str, limit: int = 20
    ) -> tuple[str, ...]:
        """Project approved PR decisions to PR_REQUESTED exactly once."""

        advanced: list[str] = []
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id,r.sequence_no,r.immutable_request_hash,
                          d.id AS decision_id,d.decision_digest
                     FROM solvan_delivery.code_change_requests r
                     JOIN solvan_delivery.code_change_decisions d
                       ON (d.organization_id,d.project_id,d.environment_id,
                           d.code_change_request_id)=
                          (r.organization_id,r.project_id,r.environment_id,r.id)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.state='PR_CREATION_APPROVAL_PENDING' AND r.expires_at>now()
                      AND d.stage='PR_CREATION' AND d.decision='APPROVED'
                      AND d.expires_at>now()
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.code_change_decisions child
                         WHERE child.organization_id=d.organization_id
                           AND child.project_id=d.project_id
                           AND child.environment_id=d.environment_id
                           AND child.supersedes_id=d.id)
                    ORDER BY d.decided_at,d.id LIMIT %(limit)s
                    FOR UPDATE OF r,d""",
                {**scope.canonical_dict(), "limit": limit},
            )
            for row in cursor.fetchall():
                sequence = int(row["sequence_no"])
                material = {
                    "schema_version": 1,
                    "code_change_request_id": str(row["id"]),
                    "immutable_request_hash": str(row["immutable_request_hash"]),
                    "decision_id": str(row["decision_id"]),
                    "decision_digest": str(row["decision_digest"]),
                    "from_state": "PR_CREATION_APPROVAL_PENDING",
                    "to_state": "PR_REQUESTED",
                    "expected_sequence_no": sequence,
                }
                cursor.execute(
                    """INSERT INTO solvan_delivery.code_change_transitions
                        (organization_id,project_id,environment_id,id,
                         code_change_request_id,sequence_no,from_state,to_state,
                         expected_sequence_no,input_hash,idempotency_key,actor_kind,
                         actor_identity,decision_id,decision_digest)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                         %(id)s,%(request_id)s,%(next_sequence)s,
                         'PR_CREATION_APPROVAL_PENDING','PR_REQUESTED',%(sequence)s,
                         %(input_hash)s,%(idempotency_key)s,'COORDINATOR',%(actor)s,
                         %(decision_id)s,%(decision_digest)s)""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("cct"),
                        "request_id": row["id"],
                        "next_sequence": sequence + 1,
                        "sequence": sequence,
                        "input_hash": canonical_sha256(material),
                        "idempotency_key": f"request-pr:{row['id']}:{row['decision_id']}",
                        "actor": coordinator_identity,
                        "decision_id": row["decision_id"],
                        "decision_digest": row["decision_digest"],
                    },
                )
                advanced.append(str(row["id"]))
        return tuple(advanced)

    def pr_command_candidates(
        self, *, scope: Scope, limit: int = 20
    ) -> tuple[PullRequestCommandCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id,r.sequence_no,r.expires_at,r.immutable_request_hash,
                          d.id AS decision_id,d.decision_digest
                     FROM solvan_delivery.code_change_requests r
                     JOIN solvan_delivery.code_change_decisions d
                       ON (d.organization_id,d.project_id,d.environment_id,
                           d.code_change_request_id)=
                          (r.organization_id,r.project_id,r.environment_id,r.id)
                     LEFT JOIN solvan_delivery.private_command_dispatches command
                       ON command.organization_id=r.organization_id
                      AND command.project_id=r.project_id
                      AND command.environment_id=r.environment_id
                      AND command.command_kind='CREATE_PR' AND command.subject_id=r.id
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.state='PR_REQUESTED' AND r.expires_at>now()
                      AND d.stage='PR_CREATION' AND d.decision='APPROVED'
                      AND d.expires_at>now() AND command.id IS NULL
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.code_change_decisions child
                         WHERE child.organization_id=d.organization_id
                           AND child.project_id=d.project_id
                           AND child.environment_id=d.environment_id
                           AND child.supersedes_id=d.id)
                    ORDER BY r.created_at,r.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(
                PullRequestCommandCandidate(
                    request_id=str(row["id"]),
                    decision_id=str(row["decision_id"]),
                    decision_digest=str(row["decision_digest"]),
                    sequence_no=int(row["sequence_no"]),
                    expires_at=row["expires_at"],
                    material_hash=canonical_sha256(
                        {
                            "schema_version": 1,
                            "command_kind": "CREATE_PR",
                            "code_change_request_id": str(row["id"]),
                            "immutable_request_hash": str(row["immutable_request_hash"]),
                            "decision_id": str(row["decision_id"]),
                            "decision_digest": str(row["decision_digest"]),
                            "transition_sequence_no": int(row["sequence_no"]),
                        }
                    ),
                )
                for row in cursor.fetchall()
            )

    def dispatchable_pr_command_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan_delivery.private_command_dispatches
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND command_kind='CREATE_PR'
                      AND status IN ('PREPARED','ISSUED','RECONCILING')
                      AND deadline>now() ORDER BY created_at,id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def sync_command_candidates(
        self,
        *,
        scope: Scope,
        generation: int,
        deadline: datetime,
        limit: int = 20,
    ) -> tuple[PullRequestSyncCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id,r.sequence_no,r.expires_at,r.immutable_request_hash,
                          observation.observation_hash
                     FROM solvan_delivery.code_change_requests r
                     JOIN LATERAL (
                       SELECT observation_hash
                         FROM solvan_delivery.code_change_github_observations o
                        WHERE o.organization_id=r.organization_id
                          AND o.project_id=r.project_id
                          AND o.environment_id=r.environment_id
                          AND o.code_change_request_id=r.id
                        ORDER BY o.sequence_no DESC LIMIT 1
                     ) observation ON true
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.state IN ('PR_CREATED','CI_PENDING','CI_PASSED',
                        'GITHUB_REVIEW_PENDING','MERGE_APPROVAL_PENDING')
                      AND r.expires_at>now()
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=r.organization_id
                           AND command.project_id=r.project_id
                           AND command.environment_id=r.environment_id
                           AND command.command_kind='SYNC_PR' AND command.subject_id=r.id
                           AND command.idempotency_key=
                             'sync-pr:'||r.id||':'||%(generation)s::text)
                    ORDER BY r.created_at,r.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "generation": generation, "limit": limit},
            )
            result: list[PullRequestSyncCandidate] = []
            for row in cursor.fetchall():
                material_hash = canonical_sha256(
                    {
                        "schema_version": 1,
                        "command_kind": "SYNC_PR",
                        "code_change_request_id": str(row["id"]),
                        "immutable_request_hash": str(row["immutable_request_hash"]),
                        "previous_observation_hash": str(row["observation_hash"]),
                        "generation": generation,
                        "transition_sequence_no": int(row["sequence_no"]),
                    }
                )
                result.append(
                    PullRequestSyncCandidate(
                        request_id=str(row["id"]),
                        material_hash=material_hash,
                        generation=generation,
                        sequence_no=int(row["sequence_no"]),
                        deadline=min(row["expires_at"], deadline),
                    )
                )
            return tuple(result)

    def prepare_sync_operation(
        self,
        *,
        scope: Scope,
        candidate: PullRequestSyncCandidate,
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
                     %(request_id)s,%(sequence)s,'SYNC_PR',%(material_hash)s,
                     %(idempotency_key)s,'PREPARED',%(request_ref)s,%(request_hash)s)
                   ON CONFLICT DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("cco"),
                    "request_id": candidate.request_id,
                    "sequence": candidate.sequence_no,
                    "material_hash": candidate.material_hash,
                    "idempotency_key": f"sync-pr:{candidate.request_id}:{candidate.generation}",
                    "request_ref": request_ref,
                    "request_hash": request_hash,
                },
            )
            if cursor.rowcount != 1:
                cursor.execute(
                    """SELECT material_hash,status,request_ref,request_hash
                         FROM solvan_delivery.code_change_operations
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND code_change_request_id=%(request_id)s
                          AND idempotency_key=%(idempotency_key)s""",
                    {
                        **scope.canonical_dict(),
                        "request_id": candidate.request_id,
                        "idempotency_key": (
                            f"sync-pr:{candidate.request_id}:{candidate.generation}"
                        ),
                    },
                )
                existing = cursor.fetchone()
                if existing is None or tuple(existing) != (
                    candidate.material_hash,
                    "PREPARED",
                    request_ref,
                    request_hash,
                ):
                    raise CodeChangeOperationConflict("existing PR sync operation differs")

    def dispatchable_sync_command_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan_delivery.private_command_dispatches
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND command_kind='SYNC_PR'
                      AND status IN ('PREPARED','ISSUED','RECONCILING')
                      AND deadline>now() ORDER BY created_at,id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def prepare_pr_operations(
        self,
        *,
        scope: Scope,
        candidate: PullRequestCommandCandidate,
        request_ref: str,
        request_hash: str,
    ) -> None:
        """Create separate durable fences for branch and pull-request effects."""

        with self._connection.cursor() as cursor:
            for kind in ("CREATE_BRANCH", "CREATE_PR", "MARK_PR_READY"):
                material_hash = canonical_sha256(
                    {
                        "command_material_hash": candidate.material_hash,
                        "operation_kind": kind,
                        "reserved_branch": reserved_branch_name(candidate.request_id),
                    }
                )
                cursor.execute(
                    """INSERT INTO solvan_delivery.code_change_operations
                        (organization_id,project_id,environment_id,id,
                         code_change_request_id,transition_sequence_no,operation_kind,
                         material_hash,idempotency_key,status,request_ref,request_hash)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                         %(id)s,%(request_id)s,%(sequence)s,%(kind)s,%(material_hash)s,
                         %(idempotency_key)s,'PREPARED',%(request_ref)s,%(request_hash)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("cco"),
                        "request_id": candidate.request_id,
                        "sequence": candidate.sequence_no,
                        "kind": kind,
                        "material_hash": material_hash,
                        "idempotency_key": f"{kind.lower()}:{candidate.request_id}",
                        "request_ref": request_ref,
                        "request_hash": request_hash,
                    },
                )
                if cursor.rowcount == 0:
                    cursor.execute(
                        """SELECT transition_sequence_no,material_hash,idempotency_key,
                                  status,request_ref,request_hash
                             FROM solvan_delivery.code_change_operations
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND code_change_request_id=%(request_id)s
                              AND operation_kind=%(kind)s""",
                        {
                            **scope.canonical_dict(),
                            "request_id": candidate.request_id,
                            "kind": kind,
                        },
                    )
                    existing = cursor.fetchone()
                    expected = (
                        candidate.sequence_no,
                        material_hash,
                        f"{kind.lower()}:{candidate.request_id}",
                        "PREPARED",
                        request_ref,
                        request_hash,
                    )
                    if existing is None or tuple(existing) != expected:
                        raise CodeChangeOperationConflict(
                            "existing GitHub operation does not match exact replay"
                        )

    def load_pr_material(
        self, *, scope: Scope, request_id: str, now: datetime
    ) -> PullRequestProviderMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.*,repository.installation_id,repository.owner,repository.name,
                          repository.policy_hash AS active_repository_policy_hash,
                          repository.status AS repository_status,
                          d.id AS decision_id,d.decision_digest,d.expires_at AS decision_expires_at
                     FROM solvan_delivery.code_change_requests r
                     JOIN solvan.github_repositories repository
                       ON (repository.organization_id,repository.project_id,
                           repository.environment_id,repository.id)=
                          (r.organization_id,r.project_id,r.environment_id,
                           r.repository_binding_id)
                     JOIN solvan_delivery.code_change_decisions d
                       ON (d.organization_id,d.project_id,d.environment_id,
                           d.code_change_request_id)=
                          (r.organization_id,r.project_id,r.environment_id,r.id)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.id=%(request_id)s AND r.state='PR_REQUESTED'
                      AND d.stage='PR_CREATION' AND d.decision='APPROVED'
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.code_change_decisions child
                         WHERE child.organization_id=d.organization_id
                           AND child.project_id=d.project_id
                           AND child.environment_id=d.environment_id
                           AND child.supersedes_id=d.id)
                    FOR UPDATE OF r,repository,d""",
                {**scope.canonical_dict(), "request_id": request_id},
            )
            row = cursor.fetchone()
        if (
            row is None
            or row["repository_status"] != "ACTIVE"
            or row["active_repository_policy_hash"] != row["repository_policy_hash"]
            or row["expires_at"] <= now
            or row["decision_expires_at"] <= now
        ):
            raise CodeChangeOperationConflict("PR creation authority is stale or unavailable")
        return PullRequestProviderMaterial(
            request_id=str(row["id"]),
            immutable_request_hash=str(row["immutable_request_hash"]),
            repository_binding_id=str(row["repository_binding_id"]),
            repository_policy_hash=str(row["repository_policy_hash"]),
            installation_id=int(row["installation_id"]),
            owner=str(row["owner"]),
            name=str(row["name"]),
            default_branch=str(row["default_branch"]),
            base_commit_sha=str(row["base_commit_sha"]),
            base_tree_hash=str(row["base_tree_hash"]),
            proposed_tree_hash=str(row["proposed_tree_hash"]),
            patch_transform_ref=str(row["patch_transform_ref"]),
            patch_transform_hash=str(row["patch_transform_hash"]),
            required_check_definition_paths_hash=str(row["required_check_definition_paths_hash"]),
            base_required_check_definitions_ref=str(row["base_required_check_definitions_ref"]),
            base_required_check_definitions_hash=str(row["base_required_check_definitions_hash"]),
            decision_id=str(row["decision_id"]),
            decision_digest=str(row["decision_digest"]),
            branch_name=reserved_branch_name(str(row["id"])),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def load_sync_material(
        self,
        *,
        scope: Scope,
        request_id: str,
        command_material_hash: str,
        now: datetime,
    ) -> PullRequestSyncMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.*,repository.installation_id,repository.owner,repository.name,
                          repository.policy_hash AS active_repository_policy_hash,
                          repository.status AS repository_status,
                          profile.required_check_definition_paths_json,
                          observation.pull_request_number,observation.pull_request_url,
                          observation.branch_name,
                          observation.head_commit_sha AS expected_head_commit_sha,
                          observation.observation_hash AS previous_observation_hash,
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
                     JOIN LATERAL (
                       SELECT * FROM solvan_delivery.code_change_github_observations o
                        WHERE o.organization_id=r.organization_id
                          AND o.project_id=r.project_id
                          AND o.environment_id=r.environment_id
                          AND o.code_change_request_id=r.id
                        ORDER BY o.sequence_no DESC LIMIT 1
                     ) observation ON true
                     JOIN solvan_delivery.code_change_operations operation
                       ON operation.organization_id=r.organization_id
                      AND operation.project_id=r.project_id
                      AND operation.environment_id=r.environment_id
                      AND operation.code_change_request_id=r.id
                      AND operation.operation_kind='SYNC_PR'
                      AND operation.material_hash=%(material_hash)s
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.id=%(request_id)s
                      AND r.state IN ('PR_CREATED','CI_PENDING','CI_PASSED',
                        'GITHUB_REVIEW_PENDING','MERGE_APPROVAL_PENDING')
                    FOR UPDATE OF r,repository,operation""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": command_material_hash,
                },
            )
            row = cursor.fetchone()
        paths = row["required_check_definition_paths_json"] if row is not None else None
        if (
            row is None
            or row["repository_status"] != "ACTIVE"
            or row["active_repository_policy_hash"] != row["repository_policy_hash"]
            or row["expires_at"] <= now
            or row["operation_status"] not in {"PREPARED", "ISSUED", "RECONCILING"}
            or not isinstance(paths, list)
            or not paths
            or any(not isinstance(item, str) for item in paths)
        ):
            raise CodeChangeOperationConflict("PR sync authority is stale or unavailable")
        return PullRequestSyncMaterial(
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
            required_check_definition_paths=tuple(paths),
            base_required_check_definitions_hash=str(row["base_required_check_definitions_hash"]),
            branch_name=str(row["branch_name"]),
            pull_request_number=int(row["pull_request_number"]),
            pull_request_url=str(row["pull_request_url"]),
            expected_head_commit_sha=str(row["expected_head_commit_sha"]),
            previous_observation_hash=str(row["previous_observation_hash"]),
            request_state=str(row["state"]),
            request_sequence_no=int(row["sequence_no"]),
            expires_at=row["expires_at"],
        )

    def claim_sync_operation(self, *, scope: Scope, request_id: str, material_hash: str) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.code_change_operations
                      SET status='ISSUED',issued_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind='SYNC_PR' AND material_hash=%(material_hash)s
                      AND status='PREPARED'""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": material_hash,
                },
            )
            return cursor.rowcount == 1

    def complete_sync_operation(
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
                      AND operation_kind='SYNC_PR' AND material_hash=%(material_hash)s
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
                raise CodeChangeOperationConflict("PR sync operation completion is stale")

    def sync_operation_terminal_receipt(
        self, *, scope: Scope, request_id: str, material_hash: str
    ) -> tuple[str, str] | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT response_ref,response_hash
                     FROM solvan_delivery.code_change_operations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind='SYNC_PR' AND material_hash=%(material_hash)s
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
            raise CodeChangeOperationConflict("PR sync terminal receipt is malformed")
        return row[0], row[1]

    def operation_statuses(self, *, scope: Scope, request_id: str) -> dict[str, str]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT operation_kind,status FROM solvan_delivery.code_change_operations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind IN ('CREATE_BRANCH','CREATE_PR','MARK_PR_READY')""",
                {**scope.canonical_dict(), "request_id": request_id},
            )
            return {str(row[0]): str(row[1]) for row in cursor.fetchall()}

    def claim_operation(self, *, scope: Scope, request_id: str, kind: str) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.code_change_operations
                      SET status='ISSUED',issued_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind=%(kind)s AND status='PREPARED'""",
                {**scope.canonical_dict(), "request_id": request_id, "kind": kind},
            )
            return cursor.rowcount == 1

    def complete_operation(
        self,
        *,
        scope: Scope,
        request_id: str,
        kind: str,
        response_ref: str,
        response_hash: str,
        status: str,
        error_class: str | None = None,
    ) -> None:
        if status not in {"SUCCEEDED", "REFUSED", "AMBIGUOUS"}:
            raise CodeChangeOperationConflict("operation terminal status is invalid")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_delivery.code_change_operations
                      SET status=%(status)s,response_ref=%(response_ref)s,
                          response_hash=%(response_hash)s,error_class=%(error_class)s,
                          reconciled_at=now(),completed_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s
                      AND operation_kind=%(kind)s
                      AND status IN ('PREPARED','ISSUED','RECONCILING')""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "kind": kind,
                    "status": status,
                    "response_ref": response_ref,
                    "response_hash": response_hash,
                    "error_class": error_class,
                },
            )
            if cursor.rowcount != 1:
                raise CodeChangeOperationConflict("operation cannot be completed from its state")
