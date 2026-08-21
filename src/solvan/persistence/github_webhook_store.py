"""Cloud SQL authority for inbound GitHub webhook deliveries.

Split from the operation store because this is the ingest side: the code an
outsider can cause to run by opening a pull request, and the code that has to
answer "which of the repositories an operator connected is this?" before
anything else can proceed. One GitHub App has one webhook URL and delivers
every bound repository to it, so that question is answered from the delivery
and checked against the binding — never taken from deployment configuration.

Specification 24 §8 governs.
"""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.github import (
    GitHubContractError,
    GitHubPullRequestStatus,
    GitHubWebhookEnvelope,
)
from solvan.domain import Scope, new_identifier


class GitHubWebhookStore:
    """Ingest-side mixin; the concrete store supplies the scoped connection."""

    _connection: Connection[Any]

    def binding_for_delivery(self, *, scope: Scope, owner: str, name: str) -> str:
        """Resolve which bound repository a delivery belongs to.

        One GitHub App sends every repository's deliveries to one URL, so the
        binding cannot come from deployment configuration — a deployment
        configured with one repository would reject the deliveries of every
        other repository an operator connected, and GitHub disables a webhook
        that keeps failing.

        Status is deliberately not filtered. A binding is written PENDING and
        promoted by the provider's own observation, and refusing its deliveries
        until then would drop exactly the events that arrive first.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan.github_repositories
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND owner = %(owner)s AND name = %(name)s""",
                {**scope.canonical_dict(), "owner": owner, "name": name},
            )
            row = cursor.fetchone()
        if row is None:
            raise GitHubContractError("GitHub webhook repository binding is absent")
        return str(row[0])

    def accept_webhook(self, *, scope: Scope, envelope: GitHubWebhookEnvelope) -> tuple[str, bool]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT owner, name, installation_id
                     FROM solvan.github_repositories
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                      AND id = %(repository_id)s""",
                {
                    **scope.canonical_dict(),
                    "repository_id": envelope.repository_id,
                },
            )
            binding = cursor.fetchone()
            if binding is None:
                raise GitHubContractError("GitHub webhook repository binding is absent")
            if str(binding[0]) != envelope.owner or str(binding[1]) != envelope.name:
                raise GitHubContractError(
                    "GitHub webhook repository identity does not match binding"
                )
            if envelope.installation_id is not None and int(binding[2]) != envelope.installation_id:
                raise GitHubContractError("GitHub webhook installation does not match binding")
            cursor.execute(
                """SELECT id FROM solvan.github_webhook_events
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND delivery_id = %(delivery_id)s""",
                {**scope.canonical_dict(), "delivery_id": envelope.delivery_id},
            )
            existing = cursor.fetchone()
            if existing is not None:
                return str(existing[0]), False
            event_id = new_identifier("ghe")
            cursor.execute(
                """INSERT INTO solvan.github_webhook_events (
                    organization_id, project_id, environment_id, id, repository_id,
                    delivery_id, event_name, action, sender_login, installation_id,
                    payload_hash, signature_verified, pull_request_number,
                    pull_request_head_sha, pull_request_base_sha, pull_request_merged)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(id)s, %(repository_id)s, %(delivery_id)s, %(event_name)s,
                    %(action)s, %(sender_login)s, %(installation_id)s, %(payload_hash)s,
                    %(signature_verified)s, %(pull_request_number)s,
                    %(pull_request_head_sha)s, %(pull_request_base_sha)s,
                    %(pull_request_merged)s)""",
                {**scope.canonical_dict(), "id": event_id, **envelope.model_dump()},
            )
        return event_id, True

    def process_webhook(self, *, scope: Scope, event_id: str) -> None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan.github_webhook_events
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s AND id = %(id)s
                   FOR UPDATE""",
                {**scope.canonical_dict(), "id": event_id},
            )
            event = cursor.fetchone()
            if event is None:
                raise GitHubContractError("GitHub webhook event is not present")
            if event["processing_status"] != "RECEIVED":
                return
            if event["event_name"] == "pull_request" and event["pull_request_number"] is not None:
                status: GitHubPullRequestStatus | None = None
                action = str(event["action"] or "")
                if event["pull_request_merged"] is True or (
                    action == "closed" and event["pull_request_merged"]
                ):
                    status = "MERGED"
                elif action in {"opened", "reopened", "synchronize", "ready_for_review"}:
                    status = "OPEN"
                elif action in {"closed", "converted_to_draft"}:
                    status = "CLOSED"
                if status is not None:
                    cursor.execute(
                        """UPDATE solvan.github_pull_requests
                           SET status = %(status)s,
                               head_commit_sha = COALESCE(%(head)s, head_commit_sha),
                               base_commit_sha = COALESCE(%(base)s, base_commit_sha),
                               merge_commit_sha = CASE WHEN %(status)s = 'MERGED'
                                 THEN merge_commit_sha ELSE merge_commit_sha END,
                               updated_at = now()
                         WHERE organization_id = %(organization_id)s
                           AND project_id = %(project_id)s
                           AND environment_id = %(environment_id)s
                           AND repository_id = %(repository_id)s
                           AND external_number = %(number)s""",
                        {
                            **scope.canonical_dict(),
                            "status": status,
                            "head": event["pull_request_head_sha"],
                            "base": event["pull_request_base_sha"],
                            "repository_id": event["repository_id"],
                            "number": event["pull_request_number"],
                        },
                    )
            cursor.execute(
                """UPDATE solvan.github_webhook_events
                   SET processing_status = 'PROCESSED', processed_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s
                   AND environment_id = %(environment_id)s AND id = %(id)s""",
                {**scope.canonical_dict(), "id": event_id},
            )
