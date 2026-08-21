"""Step-up transactions and one-use action challenges (specification 05 §4.2).

The step-up transaction and the challenge are separate records because session
rotation happens between them. The transaction freezes what was requested
against the session that requested it; the challenge binds the rotated session
that will carry it out.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.action_challenge import (
    CHALLENGE_LIFETIME,
    ActionChallengeError,
    IssuedChallenge,
    TerminalReason,
    operation,
)
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier


class ActionChallengeStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def freeze(
        self,
        *,
        scope: Scope,
        session_id: str,
        actor_id: str,
        operation_key: str,
        material_digest: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        """Record what a presence proof will authorize before it is sent.

        Freezing first is what makes the material immune to change while the
        operator is proving presence: what succeeds authorizes what was shown,
        not whatever the page holds when the code is submitted.
        """

        operation(operation_key)
        transaction_id = new_identifier("stu")
        self._connection.execute(
            """INSERT INTO solvan_identity.step_up_transactions
                 (id,requesting_session_id,actor_id,operation,organization_id,project_id,
                  environment_id,material_digest,created_at,expires_at)
               VALUES (%(id)s,%(session)s,%(actor)s,%(operation)s,%(organization_id)s,
                       %(project_id)s,%(environment_id)s,%(digest)s,%(now)s,
                       %(expires_at)s)""",
            {
                **scope.canonical_dict(),
                "id": transaction_id,
                "session": session_id,
                "actor": actor_id,
                "operation": operation_key,
                "digest": material_digest,
                "now": now,
                "expires_at": expires_at,
            },
        )
        return transaction_id

    def issue(
        self,
        *,
        scope: Scope,
        step_up_transaction_id: str,
        session_id: str,
        actor_id: str,
        presence_event_id: str,
        csrf_token_hash: str,
        now: datetime,
    ) -> str:
        """Grant one challenge for a frozen transaction after presence proof.

        The transaction's own material and operation are used rather than
        anything supplied here, so a caller cannot widen what was frozen.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT operation, material_digest, expires_at, actor_id
                     FROM solvan_identity.step_up_transactions
                    WHERE id=%(id)s AND organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "id": step_up_transaction_id},
            )
            frozen = cursor.fetchone()
            if frozen is None:
                raise ActionChallengeError("no step-up transaction matches this presence proof")
            if frozen["expires_at"] <= now:
                raise ActionChallengeError("the requested action expired during verification")
            if str(frozen["actor_id"]) != actor_id:
                raise ActionChallengeError(
                    "a different actor proved presence than requested this action"
                )
            challenge_id = new_identifier("chl")
            cursor.execute(
                """INSERT INTO solvan_identity.action_challenges
                     (id,step_up_transaction_id,session_id,actor_id,presence_event_id,
                      operation,organization_id,project_id,environment_id,material_digest,
                      csrf_token_hash,created_at,expires_at)
                   VALUES (%(id)s,%(step_up)s,%(session)s,%(actor)s,%(event)s,%(operation)s,
                           %(organization_id)s,%(project_id)s,%(environment_id)s,%(digest)s,
                           %(csrf)s,%(now)s,%(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "id": challenge_id,
                    "step_up": step_up_transaction_id,
                    "session": session_id,
                    "actor": actor_id,
                    "event": presence_event_id,
                    "operation": str(frozen["operation"]),
                    "digest": str(frozen["material_digest"]),
                    "csrf": csrf_token_hash,
                    "now": now,
                    "expires_at": now + CHALLENGE_LIFETIME,
                },
            )
            return challenge_id

    def lock(self, *, scope: Scope, challenge_id: str) -> IssuedChallenge | None:
        """Read a challenge under a row lock, for consumption in this transaction."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,actor_id,session_id,operation,material_digest,csrf_token_hash,
                          expires_at,status
                     FROM solvan_identity.action_challenges
                    WHERE id=%(id)s AND organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "id": challenge_id},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return IssuedChallenge(
                challenge_id=str(row["id"]),
                actor_id=str(row["actor_id"]),
                session_id=str(row["session_id"]),
                operation=str(row["operation"]),
                material_digest=str(row["material_digest"]),
                csrf_token_hash=str(row["csrf_token_hash"]),
                expires_at=row["expires_at"],
                status=str(row["status"]),
            )

    def consume(self, *, scope: Scope, challenge_id: str, now: datetime) -> None:
        """Spend the challenge inside the caller's transaction.

        The caller records the decision in the same transaction. Separating them
        either burns authority without recording the operation, or records the
        operation while leaving its challenge replayable.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_identity.action_challenges
                      SET status='CONSUMED', consumed_at=%(now)s
                    WHERE id=%(id)s AND status='ISSUED'
                      AND organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s""",
                {**scope.canonical_dict(), "id": challenge_id, "now": now},
            )
            if cursor.rowcount != 1:
                raise ActionChallengeError("this challenge was already used or ended")

    def end(self, *, scope: Scope, challenge_id: str, reason: TerminalReason) -> None:
        """Close a challenge that can never be used, naming why."""

        self._connection.execute(
            """UPDATE solvan_identity.action_challenges
                  SET status='TERMINAL', terminal_reason=%(reason)s
                WHERE id=%(id)s AND status='ISSUED'
                  AND organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s""",
            {**scope.canonical_dict(), "id": challenge_id, "reason": str(reason)},
        )
