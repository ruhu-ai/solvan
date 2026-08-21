"""Pending sign-ins, authentication events, and sessions (spec 05 §4.2).

A session is authenticated identity and nothing else. It is server-side so it
can be revoked at once, and it stores a hash of its credential so that reading
this table cannot impersonate its holder.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.oauth_login import PendingLogin
from solvan.domain.identifiers import new_identifier

#: A session ends after this long idle, and after this long regardless. The
#: ceiling is what bounds a session someone keeps warm by using it.
IDLE_LIFETIME = timedelta(minutes=30)
ABSOLUTE_LIFETIME = timedelta(hours=8)


@dataclass(frozen=True, slots=True)
class LiveSession:
    session_id: str
    actor_id: str
    authentication_event_id: str
    absolute_expires_at: datetime


class OperatorSessionStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def start_login(
        self,
        *,
        state_hash: str,
        nonce_hash: str,
        pkce_verifier: str,
        audience: str,
        return_path: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        transaction_id = new_identifier("lgn")
        self._connection.execute(
            """INSERT INTO solvan_identity.login_transactions
                 (id,state_hash,nonce_hash,pkce_verifier,audience,return_path,
                  created_at,expires_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                transaction_id,
                state_hash,
                nonce_hash,
                pkce_verifier,
                audience,
                return_path,
                now,
                expires_at,
            ),
        )
        return transaction_id

    def claim_login(self, *, state_hash: str, now: datetime) -> tuple[str, PendingLogin] | None:
        """Take a pending sign-in and mark it used in one statement.

        Claiming and reading are the same statement so two callbacks racing the
        same authorization code cannot both proceed; the loser sees nothing
        pending rather than a second valid flow.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """UPDATE solvan_identity.login_transactions
                      SET consumed_at=%(now)s
                    WHERE state_hash=%(state_hash)s AND consumed_at IS NULL
                RETURNING id,state_hash,nonce_hash,pkce_verifier,audience,
                          return_path,expires_at,consumed_at""",
                {"state_hash": state_hash, "now": now},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return str(row["id"]), PendingLogin(
                state_hash=str(row["state_hash"]),
                nonce_hash=str(row["nonce_hash"]),
                pkce_verifier=str(row["pkce_verifier"]),
                audience=str(row["audience"]),
                return_path=str(row["return_path"]),
                expires_at=row["expires_at"],
                # The row this statement just claimed was unconsumed; reporting
                # the timestamp it now carries would refuse every callback.
                consumed_at=None,
            )

    def record_authentication(
        self,
        *,
        actor_id: str,
        canonical_issuer: str,
        subject: str,
        audience: str,
        authenticated_at: datetime,
        hosted_domain: str | None,
        now: datetime,
    ) -> str:
        event_id = new_identifier("aev")
        self._connection.execute(
            """INSERT INTO solvan_identity.authentication_events
                 (id,actor_id,canonical_issuer,subject,audience,authenticated_at,
                  observed_at,hosted_domain)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                event_id,
                actor_id,
                canonical_issuer,
                subject,
                audience,
                authenticated_at,
                now,
                hosted_domain,
            ),
        )
        return event_id

    def create_session(
        self,
        *,
        actor_id: str,
        credential_hash: str,
        authentication_event_id: str,
        now: datetime,
        rotated_from_session_id: str | None = None,
        absolute_expires_at: datetime | None = None,
    ) -> str:
        """Open a session, or continue one across a rotation.

        A rotation keeps the original absolute ceiling. Minting a fresh one each
        time would let a session be extended indefinitely by stepping up, which
        is the ceiling failing to bound anything.
        """

        session_id = new_identifier("ses")
        resolved_absolute_expiry = absolute_expires_at or (now + ABSOLUTE_LIFETIME)
        self._connection.execute(
            """INSERT INTO solvan_identity.operator_sessions
                 (id,actor_id,credential_hash,authentication_event_id,created_at,
                  last_seen_at,idle_expires_at,absolute_expires_at,rotated_from_session_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                session_id,
                actor_id,
                credential_hash,
                authentication_event_id,
                now,
                now,
                min(now + IDLE_LIFETIME, resolved_absolute_expiry),
                resolved_absolute_expiry,
                rotated_from_session_id,
            ),
        )
        return session_id

    def touch(self, *, credential_hash: str, now: datetime) -> LiveSession | None:
        """Return a live session and extend its idle window, or nothing.

        Expiry and revocation are evaluated in the statement rather than after
        it, so a revoked session cannot be observed as live by a reader that
        checks a moment later.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """UPDATE solvan_identity.operator_sessions
                      SET last_seen_at=%(now)s,
                          idle_expires_at=LEAST(%(idle)s, absolute_expires_at)
                    WHERE credential_hash=%(credential_hash)s
                      AND revoked_at IS NULL
                      AND idle_expires_at > %(now)s
                      AND absolute_expires_at > %(now)s
                RETURNING id,actor_id,authentication_event_id,absolute_expires_at""",
                {
                    "credential_hash": credential_hash,
                    "now": now,
                    "idle": now + IDLE_LIFETIME,
                },
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return LiveSession(
                session_id=str(row["id"]),
                actor_id=str(row["actor_id"]),
                authentication_event_id=str(row["authentication_event_id"]),
                absolute_expires_at=row["absolute_expires_at"],
            )

    def revoke(self, *, session_id: str, now: datetime) -> None:
        self._connection.execute(
            """UPDATE solvan_identity.operator_sessions SET revoked_at=%s
                WHERE id=%s AND revoked_at IS NULL""",
            (now, session_id),
        )

    def revoke_actor(self, *, actor_id: str, now: datetime) -> int:
        """End every session an actor holds, for offboarding or compromise."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_identity.operator_sessions SET revoked_at=%s
                    WHERE actor_id=%s AND revoked_at IS NULL""",
                (now, actor_id),
            )
            return cursor.rowcount
