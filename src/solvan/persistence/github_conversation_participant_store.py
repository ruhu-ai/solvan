"""Cloud SQL authority for who may address Solvan, and what threads it saw.

Split from the action store because these two answer different questions on
different timescales. Participants and threads are written by inbound webhook
traffic — frequently, from outside, by anyone who can comment on the repository.
Actions are written by the approval path. Keeping the ingest side in its own
module means the code that an outsider can cause to run is small enough to read
in one sitting.

Nothing here grants authority. A recorded participant is a sighting, a recorded
thread is a projection, and both exist so an operator can decide. Specification
24 §4 governs.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.github_conversation import (
    GitHubConversationError,
    ParticipantAdmission,
    ThreadKind,
    ThreadState,
    TriggerKind,
    thread_observation_hash,
)
from solvan.domain import Scope, new_identifier

#: Deciding a publication and admitting a login are the same class of decision
#: as deciding a pull request: both settle what Solvan may do under its own
#: identity on somebody else's repository. They therefore take the same role
#: rather than a weaker conversational one.
CONVERSATION_DECISION_ROLE = "CODE_CHANGE_APPROVER"


class GitHubConversationParticipantStore:
    """Ingest-side mixin; the concrete store supplies the scoped connection."""

    _connection: Connection[Any]

    def require_decision_role(self, *, scope: Scope, principal: str) -> None:
        """Refuse a decision from a principal who does not hold the role.

        A verified Google identity establishes *who* is asking; it does not
        establish that they may decide. Checked here rather than at the API
        edge, and inside the deciding transaction, so a role revoked while an
        operator had the page open cannot still land a decision — and so no
        future caller of these store methods can reach them without it.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT 1 FROM solvan.actor_role_bindings
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND principal = %(principal)s
                      AND role = %(role)s
                      AND (expires_at IS NULL OR expires_at > now())""",
                {
                    **scope.canonical_dict(),
                    "principal": principal,
                    "role": CONVERSATION_DECISION_ROLE,
                },
            )
            if cursor.fetchone() is None:
                raise GitHubConversationError(
                    f"deciding a GitHub conversation action requires {CONVERSATION_DECISION_ROLE}"
                )

    def record_sighting(
        self, *, scope: Scope, repository_id: str, login: str, account_node_id: str
    ) -> ParticipantAdmission:
        """Record that a login addressed this repository, and report its standing.

        A first sighting is PARKED, never ADMITTED: the row exists so an
        operator can see who is asking, and its existence grants nothing. An
        existing row is left exactly as it is — a dismissed sender does not
        return to parked by asking again, which would let anyone reset their own
        standing through repetition.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT admission FROM solvan_conversation.github_conversation_participants
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND repository_id = %(repository_id)s AND login = %(login)s""",
                {**scope.canonical_dict(), "repository_id": repository_id, "login": login},
            )
            existing = cursor.fetchone()
            if existing is not None:
                return ParticipantAdmission(str(existing[0]))
            cursor.execute(
                """INSERT INTO solvan_conversation.github_conversation_participants (
                     organization_id, project_id, environment_id, id, repository_id,
                     login, account_node_id, admission)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                     %(id)s, %(repository_id)s, %(login)s, %(account_node_id)s, 'PARKED')""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("ghm"),
                    "repository_id": repository_id,
                    "login": login,
                    "account_node_id": account_node_id or "unknown",
                },
            )
        return ParticipantAdmission.PARKED

    def decide_participant(
        self,
        *,
        scope: Scope,
        repository_id: str,
        login: str,
        admission: ParticipantAdmission,
        actor: str,
    ) -> None:
        """Admit or dismiss one login on one repository."""

        if admission is ParticipantAdmission.PARKED:
            raise GitHubConversationError("parking is an observation, not a decision")
        self.require_decision_role(scope=scope, principal=actor)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_conversation.github_conversation_participants
                      SET admission = %(admission)s,
                          admitted_by_principal = %(actor)s,
                          admitted_at = now(),
                          updated_at = now()
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND repository_id = %(repository_id)s AND login = %(login)s""",
                {
                    **scope.canonical_dict(),
                    "repository_id": repository_id,
                    "login": login,
                    "admission": admission.value,
                    "actor": actor,
                },
            )
            if cursor.rowcount != 1:
                raise GitHubConversationError("GitHub conversation participant is not present")

    def list_participants(
        self, *, scope: Scope, repository_id: str, limit: int = 200
    ) -> tuple[Mapping[str, Any], ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, login, account_node_id, admission, admitted_by_principal,
                          admitted_at, first_seen_at
                     FROM solvan_conversation.github_conversation_participants
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND repository_id = %(repository_id)s
                    ORDER BY first_seen_at DESC LIMIT %(limit)s""",
                {
                    **scope.canonical_dict(),
                    "repository_id": repository_id,
                    "limit": min(max(limit, 1), 500),
                },
            )
            return tuple(cursor.fetchall())

    def upsert_thread(
        self,
        *,
        scope: Scope,
        repository_id: str,
        thread_kind: ThreadKind,
        external_number: int,
        title: str,
        state: ThreadState,
        locked: bool,
        html_url: str,
        author_login: str | None,
        head_commit_sha: str | None,
        trigger_kind: TriggerKind | None,
        event_id: str | None,
    ) -> str:
        """Record or refresh one observed thread and return its identifier."""

        if thread_kind is ThreadKind.ISSUE and head_commit_sha is not None:
            raise GitHubConversationError("an issue thread carries no head commit")
        observation = thread_observation_hash(
            thread_kind=thread_kind,
            external_number=external_number,
            state=state,
            locked=locked,
            head_commit_sha=head_commit_sha,
            title=title,
        )
        parameters = {
            **scope.canonical_dict(),
            "repository_id": repository_id,
            "thread_kind": thread_kind.value,
            "external_number": external_number,
            "title": title[:256] or "(untitled)",
            "state": state.value,
            "locked": locked,
            "html_url": html_url,
            "author_login": author_login or None,
            "head_commit_sha": head_commit_sha,
            "trigger_kind": None if trigger_kind is None else trigger_kind.value,
            "event_id": event_id,
            "observation_hash": observation,
        }
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_conversation.github_conversation_threads (
                     organization_id, project_id, environment_id, id, repository_id,
                     thread_kind, external_number, html_url, title, state, locked,
                     head_commit_sha, author_login, trigger_kind, last_event_id,
                     observation_hash)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                     %(id)s, %(repository_id)s, %(thread_kind)s, %(external_number)s,
                     %(html_url)s, %(title)s, %(state)s, %(locked)s, %(head_commit_sha)s,
                     %(author_login)s, %(trigger_kind)s, %(event_id)s, %(observation_hash)s)
                   ON CONFLICT (organization_id, project_id, environment_id,
                                repository_id, thread_kind, external_number)
                   DO UPDATE SET title = EXCLUDED.title, state = EXCLUDED.state,
                     locked = EXCLUDED.locked,
                     head_commit_sha = EXCLUDED.head_commit_sha,
                     trigger_kind = COALESCE(EXCLUDED.trigger_kind,
                                             github_conversation_threads.trigger_kind),
                     last_event_id = COALESCE(EXCLUDED.last_event_id,
                                              github_conversation_threads.last_event_id),
                     observation_hash = EXCLUDED.observation_hash,
                     observed_at = now()
                   RETURNING id""",
                {**parameters, "id": new_identifier("ght")},
            )
            row = cursor.fetchone()
        if row is None:
            raise GitHubConversationError("GitHub conversation thread was not recorded")
        return str(row[0])

    def thread(self, *, scope: Scope, thread_id: str) -> Mapping[str, Any] | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_conversation.github_conversation_threads
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s AND id = %(id)s""",
                {**scope.canonical_dict(), "id": thread_id},
            )
            return cursor.fetchone()
