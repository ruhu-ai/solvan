"""Cloud SQL authority for GitHub repository bindings and release operations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.github import (
    CreatePullRequestCommand,
    GitHubContractError,
    GitHubOperationReceipt,
    GitHubOperationStatus,
    GitHubPullRequestStatus,
    GitHubRepositoryBinding,
    MergePullRequestCommand,
    operation_hash,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.github_binding_store import GitHubBindingStore
from solvan.persistence.github_operation_failure_store import GitHubOperationFailureStore
from solvan.persistence.github_projection_store import GitHubProjectionStore
from solvan.persistence.github_webhook_store import GitHubWebhookStore


@dataclass(frozen=True, slots=True)
class StartedGitHubOperation:
    operation_id: str
    repository_id: str
    owner: str
    name: str
    installation_id: int
    api_base_url: str
    default_branch: str
    external_number: int | None
    pull_request_id: str | None
    expected_head_commit_sha: str | None


class GitHubStore(
    GitHubBindingStore,
    GitHubOperationFailureStore,
    GitHubProjectionStore,
    GitHubWebhookStore,
):
    """Every query is scope-bound and every external mutation is idempotent."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def register_repository(
        self,
        *,
        binding: GitHubRepositoryBinding,
        credential_secret_ref: str,
        webhook_secret_ref: str,
        actor: str,
    ) -> str:
        if not credential_secret_ref.startswith("projects/") or not webhook_secret_ref.startswith(
            "projects/"
        ):
            raise GitHubContractError("GitHub credentials must be Secret Manager references")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.github_repositories (
                    organization_id, project_id, environment_id, id, installation_id,
                    owner, name, default_branch, api_base_url, classification,
                    credential_secret_ref, webhook_secret_ref, policy_hash,
                    allowed_operations_json, status, created_by_principal)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(id)s, %(installation_id)s, %(owner)s, %(name)s,
                    %(default_branch)s, %(api_base_url)s, %(classification)s,
                    %(credential_secret_ref)s, %(webhook_secret_ref)s, %(policy_hash)s,
                    %(allowed_operations_json)s::jsonb, %(status)s, %(actor)s)""",
                {
                    **binding.scope.canonical_dict(),
                    "id": binding.repository_id,
                    "installation_id": binding.installation_id,
                    "owner": binding.owner,
                    "name": binding.name,
                    "default_branch": binding.default_branch,
                    "api_base_url": binding.api_base_url,
                    "classification": binding.classification,
                    "credential_secret_ref": credential_secret_ref,
                    "webhook_secret_ref": webhook_secret_ref,
                    "policy_hash": binding.policy_hash,
                    "allowed_operations_json": json.dumps(binding.allowed_operations),
                    "status": binding.status,
                    "actor": actor,
                },
            )
        return binding.repository_id

    def record_probe(
        self,
        *,
        scope: Scope,
        repository_id: str,
        success: bool,
        result: str,
    ) -> None:
        """Promote a pending binding only after the provider observed GitHub."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.github_repositories
                   SET status = CASE WHEN %(success)s THEN 'ACTIVE' ELSE 'DEGRADED' END,
                       last_probe_at = now(), last_probe_result = %(result)s,
                       updated_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                   AND id = %(repository_id)s""",
                {
                    **scope.canonical_dict(),
                    "repository_id": repository_id,
                    "success": success,
                    "result": "SUCCEEDED" if success else "FAILED",
                },
            )
            if cursor.rowcount != 1:
                raise GitHubContractError("GitHub repository binding is absent")

    def start_create_pull_request(
        self, *, command: CreatePullRequestCommand
    ) -> StartedGitHubOperation:
        request_hash = operation_hash(command.model_dump(mode="json"))
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT o.id, o.status, o.request_hash, o.repository_id, r.owner, r.name,
                          r.installation_id, r.api_base_url, r.default_branch, o.external_number,
                          o.pull_request_id, o.expected_head_commit_sha
                   FROM solvan.github_operations o
                   JOIN solvan.github_repositories r
                     ON (r.organization_id, r.project_id, r.environment_id, r.id)
                      = (o.organization_id, o.project_id, o.environment_id, o.repository_id)
                  WHERE o.organization_id = %(organization_id)s
                    AND o.project_id = %(project_id)s
                    AND o.environment_id = %(environment_id)s
                    AND o.idempotency_key = %(idempotency_key)s""",
                {**command.scope.canonical_dict(), "idempotency_key": command.idempotency_key},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if str(existing["request_hash"]) != request_hash:
                    raise GitHubContractError(
                        "GitHub idempotency key was reused with another request"
                    )
                return StartedGitHubOperation(
                    operation_id=str(existing["id"]),
                    repository_id=str(existing["repository_id"]),
                    owner=str(existing["owner"]),
                    name=str(existing["name"]),
                    installation_id=int(existing["installation_id"]),
                    api_base_url=str(existing["api_base_url"]),
                    default_branch=str(existing["default_branch"]),
                    external_number=(
                        int(existing["external_number"]) if existing["external_number"] else None
                    ),
                    pull_request_id=(
                        str(existing["pull_request_id"]) if existing["pull_request_id"] else None
                    ),
                    expected_head_commit_sha=(
                        str(existing["expected_head_commit_sha"])
                        if existing["expected_head_commit_sha"]
                        else None
                    ),
                )
            cursor.execute(
                """SELECT r.owner, r.name, r.installation_id, r.api_base_url, r.default_branch,
                          r.status, r.allowed_operations_json,
                          pa.status AS patch_status, pr.decision, pr.patch_digest
                   FROM solvan.github_repositories r
                   JOIN solvan.patch_artifacts pa
                     ON (pa.organization_id, pa.project_id, pa.environment_id, pa.id)
                      = (%(organization_id)s, %(project_id)s, %(environment_id)s,
                         %(patch_artifact_id)s)
                   LEFT JOIN solvan.patch_reviews pr
                     ON (pr.organization_id, pr.project_id, pr.environment_id,
                         pr.patch_artifact_id)
                      = (pa.organization_id, pa.project_id, pa.environment_id, pa.id)
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s AND r.environment_id = %(environment_id)s
                    AND r.id = %(repository_id)s""",
                {**command.scope.canonical_dict(), **command.model_dump(exclude={"scope"})},
            )
            repository = cursor.fetchone()
            if repository is None:
                raise GitHubContractError("GitHub repository binding is absent")
            allowed = repository["allowed_operations_json"]
            if repository["status"] != "ACTIVE" or "CREATE_PULL_REQUEST" not in allowed:
                raise GitHubContractError("GitHub repository is not active for PR creation")
            if repository["patch_status"] != "TESTS_PASSED" or repository["decision"] != "APPROVE":
                raise GitHubContractError(
                    "an approved, passing patch is required before PR creation"
                )
            if repository["patch_digest"] != command.patch_digest:
                raise GitHubContractError("patch review digest does not match the command")
            operation_id = new_identifier("gho")
            cursor.execute(
                """INSERT INTO solvan.github_operations (
                    organization_id, project_id, environment_id, id, repository_id,
                    operation, status, idempotency_key, request_hash,
                    expected_head_commit_sha, actor_principal)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(id)s, %(repository_id)s, 'CREATE_PULL_REQUEST', 'CREATED',
                    %(idempotency_key)s, %(request_hash)s, %(head)s, %(actor)s)""",
                {
                    **command.scope.canonical_dict(),
                    "id": operation_id,
                    "repository_id": command.repository_id,
                    "idempotency_key": command.idempotency_key,
                    "request_hash": request_hash,
                    "head": command.head_commit_sha,
                    "actor": command.actor_principal,
                },
            )
            return StartedGitHubOperation(
                operation_id,
                command.repository_id,
                str(repository["owner"]),
                str(repository["name"]),
                int(repository["installation_id"]),
                str(repository["api_base_url"]),
                str(repository["default_branch"]),
                None,
                None,
                command.head_commit_sha,
            )

    def record_pull_request(
        self,
        *,
        scope: Scope,
        operation_id: str,
        patch_artifact_id: str,
        patch_digest: str,
        branch_name: str,
        base_commit_sha: str,
        title: str,
        actor_principal: str,
        external_number: int,
        html_url: str,
        head_commit_sha: str,
        mergeable_state: str | None,
    ) -> GitHubOperationReceipt:
        pr_id = new_identifier("ghp")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.github_pull_requests (
                    organization_id, project_id, environment_id, id, repository_id,
                    patch_artifact_id, patch_digest, external_number, html_url,
                    branch_name, base_commit_sha, head_commit_sha, title, status,
                    mergeable_state, created_by_principal)
                   SELECT o.organization_id, o.project_id, o.environment_id, %(pr_id)s,
                          o.repository_id, %(patch_artifact_id)s, %(patch_digest)s,
                          %(external_number)s, %(html_url)s, %(branch_name)s,
                          %(base_commit_sha)s, %(head_commit_sha)s, %(title)s, 'OPEN',
                          %(mergeable_state)s, %(actor)s
                     FROM solvan.github_operations o
                    WHERE o.organization_id = %(organization_id)s
                      AND o.project_id = %(project_id)s AND o.environment_id = %(environment_id)s
                      AND o.id = %(operation_id)s""",
                {
                    **scope.canonical_dict(),
                    "pr_id": pr_id,
                    "operation_id": operation_id,
                    "patch_artifact_id": patch_artifact_id,
                    "patch_digest": patch_digest,
                    "external_number": external_number,
                    "html_url": html_url,
                    "branch_name": branch_name,
                    "base_commit_sha": base_commit_sha,
                    "head_commit_sha": head_commit_sha,
                    "title": title,
                    "mergeable_state": mergeable_state,
                    "actor": actor_principal,
                },
            )
            if cursor.rowcount != 1:
                raise GitHubContractError("GitHub create operation is absent")
            response_hash = operation_hash(
                {"number": external_number, "url": html_url, "head": head_commit_sha}
            )
            cursor.execute(
                """UPDATE solvan.github_operations
                   SET status = 'SUCCEEDED', pull_request_id = %(pr_id)s,
                       external_number = %(number)s, response_hash = %(response_hash)s,
                       completed_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                   AND id = %(operation_id)s""",
                {
                    **scope.canonical_dict(),
                    "operation_id": operation_id,
                    "pr_id": pr_id,
                    "number": external_number,
                    "response_hash": response_hash,
                },
            )
        return GitHubOperationReceipt(
            operation_id,
            "SUCCEEDED",
            "CREATE_PULL_REQUEST",
            pr_id,
            external_number,
            head_commit_sha,
            response_hash,
            html_url,
            None,
        )

    def start_merge_pull_request(
        self, *, command: MergePullRequestCommand
    ) -> StartedGitHubOperation:
        request_hash = operation_hash(command.model_dump(mode="json"))
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT o.id, o.status, o.request_hash, o.repository_id,
                          o.external_number, o.pull_request_id, o.expected_head_commit_sha,
                          r.owner, r.name, r.installation_id, r.api_base_url, r.default_branch
                     FROM solvan.github_operations o
                     JOIN solvan.github_repositories r
                       ON (r.organization_id, r.project_id, r.environment_id, r.id)
                        = (o.organization_id, o.project_id, o.environment_id, o.repository_id)
                    WHERE o.organization_id = %(organization_id)s
                      AND o.project_id = %(project_id)s AND o.environment_id = %(environment_id)s
                      AND o.idempotency_key = %(idempotency_key)s""",
                {**command.scope.canonical_dict(), "idempotency_key": command.idempotency_key},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if str(existing["request_hash"]) != request_hash:
                    raise GitHubContractError(
                        "GitHub idempotency key was reused with another request"
                    )
                return StartedGitHubOperation(
                    str(existing["id"]),
                    str(existing["repository_id"]),
                    str(existing["owner"]),
                    str(existing["name"]),
                    int(existing["installation_id"]),
                    str(existing["api_base_url"]),
                    str(existing["default_branch"]),
                    int(existing["external_number"]) if existing["external_number"] else None,
                    str(existing["pull_request_id"]) if existing["pull_request_id"] else None,
                    str(existing["expected_head_commit_sha"])
                    if existing["expected_head_commit_sha"]
                    else None,
                )
            cursor.execute(
                """SELECT p.repository_id, p.external_number, p.head_commit_sha,
                          p.status, p.latest_checks_state, r.owner, r.name,
                          r.installation_id, r.api_base_url, r.default_branch,
                          r.status AS repository_status,
                          r.allowed_operations_json, pr.decision, pr.patch_digest
                     FROM solvan.github_pull_requests p
                     JOIN solvan.github_repositories r
                       ON (r.organization_id, r.project_id, r.environment_id, r.id)
                        = (p.organization_id, p.project_id, p.environment_id, p.repository_id)
                     JOIN solvan.patch_reviews pr
                       ON (pr.organization_id, pr.project_id, pr.environment_id,
                           pr.patch_artifact_id)
                        = (p.organization_id, p.project_id, p.environment_id,
                           p.patch_artifact_id)
                    WHERE p.organization_id = %(organization_id)s
                      AND p.project_id = %(project_id)s AND p.environment_id = %(environment_id)s
                      AND p.id = %(pull_request_id)s
                      AND pr.id = %(patch_review_id)s""",
                {**command.scope.canonical_dict(), **command.model_dump(exclude={"scope"})},
            )
            row = cursor.fetchone()
            if row is None:
                raise GitHubContractError("GitHub PR or exact patch review is absent")
            if (
                row["repository_status"] != "ACTIVE"
                or "MERGE_PULL_REQUEST" not in row["allowed_operations_json"]
            ):
                raise GitHubContractError("GitHub repository is not active for merge")
            if row["decision"] != "APPROVE":
                raise GitHubContractError("an exact approved patch review is required before merge")
            if row["status"] not in {"OPEN", "APPROVED"}:
                raise GitHubContractError("GitHub PR is not open for merge")
            if row["head_commit_sha"] != command.expected_head_commit_sha:
                raise GitHubContractError("GitHub PR head changed; re-review is required")
            if row["latest_checks_state"] != "PASSING":
                raise GitHubContractError("required GitHub checks are not passing")
            operation_id = new_identifier("gho")
            cursor.execute(
                """INSERT INTO solvan.github_operations (
                    organization_id, project_id, environment_id, id, repository_id,
                    pull_request_id, patch_review_id, operation, status,
                    idempotency_key, request_hash, expected_head_commit_sha,
                    external_number, actor_principal)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(id)s, %(repository_id)s, %(pull_request_id)s, %(patch_review_id)s,
                    'MERGE_PULL_REQUEST', 'CREATED', %(idempotency_key)s,
                    %(request_hash)s, %(expected_head)s, %(number)s, %(actor)s)""",
                {
                    **command.scope.canonical_dict(),
                    "id": operation_id,
                    "repository_id": row["repository_id"],
                    "pull_request_id": command.pull_request_id,
                    "patch_review_id": command.patch_review_id,
                    "idempotency_key": command.idempotency_key,
                    "request_hash": request_hash,
                    "expected_head": command.expected_head_commit_sha,
                    "number": row["external_number"],
                    "actor": command.actor_principal,
                },
            )
            return StartedGitHubOperation(
                operation_id,
                str(row["repository_id"]),
                str(row["owner"]),
                str(row["name"]),
                int(row["installation_id"]),
                str(row["api_base_url"]),
                str(row["default_branch"]),
                int(row["external_number"]),
                command.pull_request_id,
                command.expected_head_commit_sha,
            )

    def complete_merge(
        self,
        *,
        scope: Scope,
        operation_id: str,
        merged: bool,
        response: dict[str, Any],
    ) -> GitHubOperationReceipt:
        response_hash = operation_hash(response)
        status: GitHubOperationStatus = "SUCCEEDED" if merged else "REJECTED"
        error_class = None if merged else "GITHUB_MERGE_NOT_ACCEPTED"
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT operation, pull_request_id, external_number,
                          expected_head_commit_sha
                     FROM solvan.github_operations
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                      AND id = %(id)s FOR UPDATE""",
                {**scope.canonical_dict(), "id": operation_id},
            )
            operation = cursor.fetchone()
            if operation is None or operation["operation"] != "MERGE_PULL_REQUEST":
                raise GitHubContractError("GitHub merge operation is absent")
            cursor.execute(
                """UPDATE solvan.github_operations
                   SET status = %(status)s, response_hash = %(response_hash)s,
                       error_class = %(error_class)s, completed_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                   AND id = %(id)s""",
                {
                    **scope.canonical_dict(),
                    "id": operation_id,
                    "status": status,
                    "response_hash": response_hash,
                    "error_class": error_class,
                },
            )
            if merged:
                cursor.execute(
                    """UPDATE solvan.github_pull_requests
                       SET status = 'MERGED',
                           merge_commit_sha = CASE WHEN %(merge_sha)s ~ '^[0-9a-f]{40}$'
                             THEN %(merge_sha)s ELSE merge_commit_sha END,
                           updated_at = now()
                     WHERE organization_id = %(organization_id)s
                       AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                       AND id = %(pull_request_id)s""",
                    {
                        **scope.canonical_dict(),
                        "pull_request_id": operation["pull_request_id"],
                        "merge_sha": str(response.get("sha", "")),
                    },
                )
        return GitHubOperationReceipt(
            operation_id,
            status,
            "MERGE_PULL_REQUEST",
            str(operation["pull_request_id"]),
            int(operation["external_number"]) if operation["external_number"] else None,
            str(operation["expected_head_commit_sha"])
            if operation["expected_head_commit_sha"]
            else None,
            response_hash,
            None,
            error_class,
        )

    def update_checks(
        self, *, scope: Scope, pull_request_id: str, checks: tuple[dict[str, Any], ...]
    ) -> None:
        passing = bool(checks) and all(
            item.get("status") == "COMPLETED" and item.get("conclusion") == "SUCCESS"
            for item in checks
        )
        state = (
            "PASSING"
            if passing
            else (
                "FAILING"
                if any(
                    item.get("conclusion") in {"FAILURE", "CANCELLED", "TIMED_OUT"}
                    for item in checks
                )
                else "PENDING"
                if checks
                else "UNKNOWN"
            )
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.github_pull_requests SET latest_checks_state = %(state)s,
                       updated_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                   AND id = %(pull_request_id)s""",
                {**scope.canonical_dict(), "pull_request_id": pull_request_id, "state": state},
            )

    def sync_pull_request(
        self,
        *,
        scope: Scope,
        pull_request_id: str,
        external_number: int,
        html_url: str,
        head_commit_sha: str,
        base_commit_sha: str,
        state: str,
        merged: bool,
        mergeable_state: str | None,
        checks: tuple[dict[str, Any], ...],
    ) -> None:
        status: GitHubPullRequestStatus = (
            "MERGED" if merged else "CLOSED" if state == "closed" else "OPEN"
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.github_pull_requests
                   SET external_number = %(external_number)s, html_url = %(html_url)s,
                       head_commit_sha = %(head)s, base_commit_sha = %(base)s,
                       status = %(status)s, mergeable_state = %(mergeable_state)s,
                       updated_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                   AND id = %(pull_request_id)s""",
                {
                    **scope.canonical_dict(),
                    "pull_request_id": pull_request_id,
                    "external_number": external_number,
                    "html_url": html_url,
                    "head": head_commit_sha,
                    "base": base_commit_sha,
                    "status": status,
                    "mergeable_state": mergeable_state,
                },
            )
            for item in checks:
                cursor.execute(
                    """INSERT INTO solvan.github_check_runs (
                        organization_id, project_id, environment_id, id, pull_request_id,
                        external_id, name, status, conclusion, head_commit_sha, details_url)
                      VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                        %(id)s, %(pull_request_id)s, %(external_id)s, %(name)s,
                        %(status)s, %(conclusion)s, %(head)s, %(details_url)s)
                     ON CONFLICT (organization_id, project_id, environment_id,
                                  pull_request_id, external_id)
                     DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status,
                        conclusion = EXCLUDED.conclusion,
                        head_commit_sha = EXCLUDED.head_commit_sha,
                        details_url = EXCLUDED.details_url, observed_at = now()""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("ghc"),
                        "pull_request_id": pull_request_id,
                        **item,
                        "external_id": int(item["external_id"]),
                        "head": str(item["head_sha"]),
                    },
                )
        self.update_checks(scope=scope, pull_request_id=pull_request_id, checks=checks)
