"""Read-only GitHub console projections kept apart from mutation workflows."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope


class GitHubProjectionStore:
    """Projection mixin; the concrete store supplies the scoped connection."""

    _connection: Connection[Any]

    def project(self, *, scope: Scope) -> dict[str, Any]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            parameters = scope.canonical_dict()
            cursor.execute(
                """SELECT id, owner, name, default_branch, classification, status,
                          last_probe_at, last_probe_result, policy_hash,
                          allowed_operations_json
                     FROM solvan.github_repositories
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                    ORDER BY owner, name""",
                parameters,
            )
            repositories = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT p.id, p.repository_id, r.owner, r.name, p.external_number,
                          p.html_url, p.branch_name, p.base_commit_sha, p.head_commit_sha,
                          p.title, p.status, p.latest_checks_state, p.mergeable_state,
                          p.merge_commit_sha, p.patch_artifact_id, p.patch_digest,
                          p.created_at, p.updated_at
                     FROM solvan.github_pull_requests p
                     JOIN solvan.github_repositories r
                       ON (r.organization_id, r.project_id, r.environment_id, r.id)
                        = (p.organization_id, p.project_id, p.environment_id, p.repository_id)
                    WHERE p.organization_id = %(organization_id)s
                      AND p.project_id = %(project_id)s AND p.environment_id = %(environment_id)s
                    ORDER BY p.updated_at DESC LIMIT 50""",
                parameters,
            )
            pull_requests = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT id, repository_id, pull_request_id, operation, status,
                          external_number, response_hash, receipt_ref, error_class,
                          actor_principal, created_at, completed_at
                     FROM solvan.github_operations
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                    ORDER BY created_at DESC LIMIT 50""",
                parameters,
            )
            operations = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT event_name, action, processing_status, received_at, processed_at
                     FROM solvan.github_webhook_events
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                    ORDER BY received_at DESC LIMIT 20""",
                parameters,
            )
            webhooks = [dict(row) for row in cursor.fetchall()]
        return {
            "repositories": repositories,
            "pull_requests": pull_requests,
            "operations": operations,
            "webhooks": webhooks,
        }
