"""Cloud SQL authority for approved GitHub publications.

The store never decides whether a publication is *wise* — that is the human
approval recorded in `github_conversation_actions`. It decides whether a
publication is *possible*: that the binding grants the operation, that the
approval names the exact body being sent, and that a claimed action cannot be
claimed twice.

Participant admission and thread projection live in
`github_conversation_participant_store`, mixed in here so a caller still holds
one store across one transaction. Specification 24 §5 governs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.github_conversation import (
    ConversationActionState,
    ConversationOperation,
    ConversationProposal,
    GitHubConversationError,
    ReviewEvent,
    ThreadState,
    conversation_decision_material,
    require_conversation_authority,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.github_conversation_participant_store import (
    GitHubConversationParticipantStore,
)


@dataclass(frozen=True, slots=True)
class ClaimedConversationAction:
    """One approved action, loaded with everything a publication needs.

    Assembled from the durable record rather than from a request body, so a
    dispatcher cannot substitute a different thread or a different body after
    the approval was given.
    """

    action_id: str
    repository_id: str
    owner: str
    name: str
    installation_id: int
    api_base_url: str
    operation: ConversationOperation
    external_number: int | None
    title: str | None
    body: str
    body_hash: str
    template_registry_digest: str
    review_event: ReviewEvent | None
    expected_thread_state: ThreadState | None
    expected_head_commit_sha: str | None
    decision_digest: str
    operation_id: str


class GitHubConversationStore(GitHubConversationParticipantStore):
    """Every query is scope-bound; every publication is fenced exactly once."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    # -- actions -------------------------------------------------------------

    def propose_action(
        self,
        *,
        scope: Scope,
        proposal: ConversationProposal,
        expires_at: datetime,
    ) -> tuple[str, str, Mapping[str, object]]:
        """Record one proposed publication awaiting a human decision.

        The binding's own allowlist is checked here rather than at the API edge,
        because this is the last point before the proposal becomes something an
        operator can approve — and an operator approving an action the binding
        never granted would be an approval that cannot lawfully be executed.
        """

        binding = self._binding(scope, proposal.repository_id)
        require_conversation_authority(
            allowed_operations=tuple(binding["allowed_operations"]),
            operation=proposal.operation,
        )
        thread_url: str | None = None
        external_number: int | None = None
        if proposal.thread_id is not None:
            thread = self.thread(scope=scope, thread_id=proposal.thread_id)
            if thread is None:
                raise GitHubConversationError("GitHub conversation thread is not present")
            if str(thread["repository_id"]) != proposal.repository_id:
                raise GitHubConversationError("thread belongs to another repository binding")
            if bool(thread["locked"]):
                raise GitHubConversationError("thread is locked")
            thread_url = str(thread["html_url"])
            external_number = int(thread["external_number"])

        action_id = new_identifier("gha")
        material, digest = conversation_decision_material(
            action_id=action_id,
            repository_id=proposal.repository_id,
            repository_policy_hash=str(binding["policy_hash"]),
            operation=proposal.operation,
            body=proposal.body.text,
            body_hash=proposal.body.body_hash,
            template_registry_digest=proposal.body.template_registry_digest,
            template_ids=proposal.body.template_ids,
            thread_url=thread_url,
            external_number=external_number,
            review_event=proposal.review_event,
            expected_thread_state=proposal.expected_thread_state,
            expected_head_commit_sha=proposal.expected_head_commit_sha,
            trigger_login=None,
            expires_at=expires_at,
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_conversation.github_conversation_actions (
                     organization_id, project_id, environment_id, id, repository_id,
                     thread_id, operation, review_event, title, body, body_hash,
                     template_registry_digest, template_ids_json, proposal_hash,
                     agent_run_id, expected_thread_state, expected_head_commit_sha,
                     state, expires_at)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                     %(id)s, %(repository_id)s, %(thread_id)s, %(operation)s,
                     %(review_event)s, %(title)s, %(body)s, %(body_hash)s,
                     %(template_registry_digest)s, %(template_ids)s::jsonb,
                     %(proposal_hash)s, %(agent_run_id)s, %(expected_thread_state)s,
                     %(expected_head_commit_sha)s, 'APPROVAL_PENDING', %(expires_at)s)
                   ON CONFLICT (organization_id, project_id, environment_id, proposal_hash)
                   DO NOTHING
                   RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": action_id,
                    "repository_id": proposal.repository_id,
                    "thread_id": proposal.thread_id,
                    "operation": proposal.operation.value,
                    "review_event": (
                        None if proposal.review_event is None else proposal.review_event.value
                    ),
                    "title": proposal.title,
                    "body": proposal.body.text,
                    "body_hash": proposal.body.body_hash,
                    "template_registry_digest": proposal.body.template_registry_digest,
                    "template_ids": json.dumps(sorted(proposal.body.template_ids)),
                    "proposal_hash": proposal.proposal_hash,
                    "agent_run_id": proposal.agent_run_id,
                    "expected_thread_state": (
                        None
                        if proposal.expected_thread_state is None
                        else proposal.expected_thread_state.value
                    ),
                    "expected_head_commit_sha": proposal.expected_head_commit_sha,
                    "expires_at": expires_at,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise GitHubConversationError(
                "this proposal already has an action; it is not proposed twice"
            )
        return action_id, digest, material

    def decide_action(
        self,
        *,
        scope: Scope,
        action_id: str,
        approved: bool,
        decision_digest: str,
        actor: str,
        now: datetime,
    ) -> None:
        """Record one human decision, bound to the exact material presented.

        The digest is compared rather than trusted: an operator who was shown
        one body and whose client submits another has not approved the second.

        The role is checked first and in this transaction. A publication is
        text the world reads under Solvan's identity, so establishing who is
        deciding is not the same as establishing that they may.
        """

        self.require_decision_role(scope=scope, principal=actor)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, state, expires_at, body, body_hash, template_registry_digest,
                          template_ids_json, repository_id, thread_id, operation,
                          review_event, expected_thread_state, expected_head_commit_sha
                     FROM solvan_conversation.github_conversation_actions
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "id": action_id},
            )
            action = cursor.fetchone()
            if action is None:
                raise GitHubConversationError("GitHub conversation action is not present")
            if str(action["state"]) != ConversationActionState.APPROVAL_PENDING.value:
                raise GitHubConversationError(
                    "GitHub conversation action is not awaiting a decision"
                )
            expires_at = action["expires_at"]
            if isinstance(expires_at, datetime) and now >= expires_at:
                cursor.execute(
                    """UPDATE solvan_conversation.github_conversation_actions
                          SET state = 'EXPIRED', error_class = 'DECISION_EXPIRED',
                              updated_at = now()
                        WHERE organization_id = %(organization_id)s
                          AND project_id = %(project_id)s
                          AND environment_id = %(environment_id)s AND id = %(id)s""",
                    {**scope.canonical_dict(), "id": action_id},
                )
                raise GitHubConversationError("GitHub conversation decision has expired")
            expected = self._decision_digest(scope, action)
            if decision_digest != expected:
                raise GitHubConversationError(
                    "decision digest does not match the material presented"
                )
            cursor.execute(
                """UPDATE solvan_conversation.github_conversation_actions
                      SET state = %(state)s, decision_digest = %(digest)s,
                          decided_by_principal = %(actor)s, decided_at = now(),
                          updated_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(id)s""",
                {
                    **scope.canonical_dict(),
                    "id": action_id,
                    "state": (
                        ConversationActionState.APPROVED.value
                        if approved
                        else ConversationActionState.REJECTED.value
                    ),
                    "digest": decision_digest,
                    "actor": actor,
                },
            )

    def claim_for_publication(
        self, *, scope: Scope, action_id: str, idempotency_key: str, actor: str
    ) -> ClaimedConversationAction:
        """Move one approved action to DISPATCHED and open its operation row.

        The state transition and the operation insert share this transaction, so
        a crash between them cannot leave an action that looks dispatchable but
        has no operation to reconcile against.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.*, r.owner, r.name, r.installation_id, r.api_base_url,
                          r.allowed_operations_json, r.status AS binding_status
                     FROM solvan_conversation.github_conversation_actions a
                     JOIN solvan.github_repositories r
                       ON r.organization_id = a.organization_id
                      AND r.project_id = a.project_id
                      AND r.environment_id = a.environment_id
                      AND r.id = a.repository_id
                    WHERE a.organization_id = %(organization_id)s
                      AND a.project_id = %(project_id)s
                      AND a.environment_id = %(environment_id)s AND a.id = %(id)s
                    FOR UPDATE OF a""",
                {**scope.canonical_dict(), "id": action_id},
            )
            action = cursor.fetchone()
            if action is None:
                raise GitHubConversationError("GitHub conversation action is not present")
            if str(action["state"]) != ConversationActionState.APPROVED.value:
                raise GitHubConversationError("GitHub conversation action is not approved")
            if str(action["binding_status"]) != "ACTIVE":
                raise GitHubConversationError("GitHub repository binding is not active")
            operation = ConversationOperation(str(action["operation"]))
            require_conversation_authority(
                allowed_operations=tuple(action["allowed_operations_json"] or ()),
                operation=operation,
            )
            external_number: int | None = None
            if action["thread_id"] is not None:
                cursor.execute(
                    """SELECT external_number FROM solvan_conversation.github_conversation_threads
                        WHERE organization_id = %(organization_id)s
                          AND project_id = %(project_id)s
                          AND environment_id = %(environment_id)s AND id = %(id)s""",
                    {**scope.canonical_dict(), "id": str(action["thread_id"])},
                )
                thread = cursor.fetchone()
                if thread is None:
                    raise GitHubConversationError("GitHub conversation thread is not present")
                external_number = int(thread["external_number"])

            operation_id = new_identifier("gho")
            cursor.execute(
                """INSERT INTO solvan.github_operations (
                     organization_id, project_id, environment_id, id, repository_id,
                     operation, status, idempotency_key, request_hash, actor_principal)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                     %(id)s, %(repository_id)s, %(operation)s, 'DISPATCHED',
                     %(idempotency_key)s, %(request_hash)s, %(actor)s)
                   ON CONFLICT (organization_id, project_id, environment_id, idempotency_key)
                   DO NOTHING
                   RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": operation_id,
                    "repository_id": str(action["repository_id"]),
                    "operation": operation.value,
                    "idempotency_key": idempotency_key,
                    "request_hash": str(action["body_hash"]),
                    "actor": actor,
                },
            )
            claimed = cursor.fetchone()
            if claimed is None:
                raise GitHubConversationError(
                    "this publication was already claimed under the same idempotency key"
                )
            cursor.execute(
                """UPDATE solvan_conversation.github_conversation_actions
                      SET state = 'DISPATCHED', operation_id = %(operation_id)s,
                          updated_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(id)s""",
                {
                    **scope.canonical_dict(),
                    "id": action_id,
                    "operation_id": operation_id,
                },
            )

        review_event = action["review_event"]
        expected_state = action["expected_thread_state"]
        return ClaimedConversationAction(
            action_id=action_id,
            repository_id=str(action["repository_id"]),
            owner=str(action["owner"]),
            name=str(action["name"]),
            installation_id=int(action["installation_id"]),
            api_base_url=str(action["api_base_url"]),
            operation=operation,
            external_number=external_number,
            title=None if action["title"] is None else str(action["title"]),
            body=str(action["body"]),
            body_hash=str(action["body_hash"]),
            template_registry_digest=str(action["template_registry_digest"]),
            review_event=None if review_event is None else ReviewEvent(str(review_event)),
            expected_thread_state=(
                None if expected_state is None else ThreadState(str(expected_state))
            ),
            expected_head_commit_sha=(
                None
                if action["expected_head_commit_sha"] is None
                else str(action["expected_head_commit_sha"])
            ),
            decision_digest=str(action["decision_digest"]),
            operation_id=operation_id,
        )

    def record_publication(
        self,
        *,
        scope: Scope,
        action_id: str,
        external_id: int,
        external_url: str,
        response_hash: str,
    ) -> None:
        """Close one publication with the external identity it produced."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_conversation.github_conversation_actions
                      SET state = 'PUBLISHED', external_id = %(external_id)s,
                          external_url = %(external_url)s, updated_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND id = %(id)s AND state = 'DISPATCHED'
                  RETURNING operation_id""",
                {
                    **scope.canonical_dict(),
                    "id": action_id,
                    "external_id": external_id,
                    "external_url": external_url,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise GitHubConversationError(
                    "GitHub conversation action is not dispatched; it cannot be completed"
                )
            cursor.execute(
                """UPDATE solvan.github_operations
                      SET status = 'SUCCEEDED', response_hash = %(response_hash)s,
                          external_number = %(external_number)s, completed_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(operation_id)s""",
                {
                    **scope.canonical_dict(),
                    "operation_id": str(row[0]),
                    "response_hash": response_hash,
                    "external_number": None,
                },
            )

    def record_refusal(self, *, scope: Scope, action_id: str, error_class: str) -> None:
        """Close one publication that could not proceed, naming why."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_conversation.github_conversation_actions
                      SET state = 'REFUSED', error_class = %(error_class)s, updated_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND id = %(id)s AND state IN ('APPROVED','DISPATCHED')
                  RETURNING operation_id""",
                {
                    **scope.canonical_dict(),
                    "id": action_id,
                    "error_class": error_class[:100],
                },
            )
            row = cursor.fetchone()
            if row is not None and row[0] is not None:
                cursor.execute(
                    """UPDATE solvan.github_operations
                          SET status = 'FAILED', error_class = %(error_class)s,
                              completed_at = now()
                        WHERE organization_id = %(organization_id)s
                          AND project_id = %(project_id)s
                          AND environment_id = %(environment_id)s
                          AND id = %(operation_id)s""",
                    {
                        **scope.canonical_dict(),
                        "operation_id": str(row[0]),
                        "error_class": error_class[:100],
                    },
                )

    def list_actions(
        self,
        *,
        scope: Scope,
        repository_id: str | None = None,
        states: tuple[str, ...] = (),
        limit: int = 100,
    ) -> tuple[Mapping[str, Any], ...]:
        clauses = [
            "organization_id = %(organization_id)s",
            "project_id = %(project_id)s",
            "environment_id = %(environment_id)s",
        ]
        parameters: dict[str, Any] = {
            **scope.canonical_dict(),
            "limit": min(max(limit, 1), 500),
        }
        if repository_id is not None:
            clauses.append("repository_id = %(repository_id)s")
            parameters["repository_id"] = repository_id
        if states:
            clauses.append("state = ANY(%(states)s)")
            parameters["states"] = list(states)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                "SELECT id, repository_id, thread_id, operation, review_event, title, "
                "body, body_hash, template_registry_digest, template_ids_json, state, "
                "external_url, error_class, decided_by_principal, decided_at, "
                "expires_at, created_at FROM solvan_conversation.github_conversation_actions "
                f"WHERE {' AND '.join(clauses)} "
                "ORDER BY created_at DESC LIMIT %(limit)s",
                parameters,
            )
            return tuple(cursor.fetchall())

    def action_decision_material(
        self, *, scope: Scope, action_id: str
    ) -> tuple[Mapping[str, object], str]:
        """Rebuild what an operator must decide against, and its digest."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_conversation.github_conversation_actions
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(id)s""",
                {**scope.canonical_dict(), "id": action_id},
            )
            action = cursor.fetchone()
        if action is None:
            raise GitHubConversationError("GitHub conversation action is not present")
        return self._decision_material(scope, action)

    # -- internals -----------------------------------------------------------

    def _binding(self, scope: Scope, repository_id: str) -> dict[str, Any]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, owner, name, installation_id, api_base_url, policy_hash,
                          allowed_operations_json, status
                     FROM solvan.github_repositories
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(id)s""",
                {**scope.canonical_dict(), "id": repository_id},
            )
            binding = cursor.fetchone()
        if binding is None:
            raise GitHubConversationError("GitHub repository binding is not present")
        if str(binding["status"]) != "ACTIVE":
            raise GitHubConversationError("GitHub repository binding is not active")
        return {
            **binding,
            "allowed_operations": tuple(binding["allowed_operations_json"] or ()),
        }

    def _decision_material(
        self, scope: Scope, action: Mapping[str, Any]
    ) -> tuple[Mapping[str, object], str]:
        binding = self._binding(scope, str(action["repository_id"]))
        thread_url: str | None = None
        external_number: int | None = None
        if action["thread_id"] is not None:
            thread = self.thread(scope=scope, thread_id=str(action["thread_id"]))
            if thread is None:
                raise GitHubConversationError("GitHub conversation thread is not present")
            thread_url = str(thread["html_url"])
            external_number = int(thread["external_number"])
        review_event = action["review_event"]
        expected_state = action["expected_thread_state"]
        return conversation_decision_material(
            action_id=str(action["id"]),
            repository_id=str(action["repository_id"]),
            repository_policy_hash=str(binding["policy_hash"]),
            operation=ConversationOperation(str(action["operation"])),
            body=str(action["body"]),
            body_hash=str(action["body_hash"]),
            template_registry_digest=str(action["template_registry_digest"]),
            template_ids=tuple(action["template_ids_json"] or ()),
            thread_url=thread_url,
            external_number=external_number,
            review_event=None if review_event is None else ReviewEvent(str(review_event)),
            expected_thread_state=(
                None if expected_state is None else ThreadState(str(expected_state))
            ),
            expected_head_commit_sha=(
                None
                if action["expected_head_commit_sha"] is None
                else str(action["expected_head_commit_sha"])
            ),
            trigger_login=None,
            expires_at=action["expires_at"],
        )

    def _decision_digest(self, scope: Scope, action: Mapping[str, Any]) -> str:
        return self._decision_material(scope, action)[1]
