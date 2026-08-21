"""The authority an operator carries with them to GitHub and back.

GitHub can redirect an operator back to us after they install the App, which is
what makes connecting one continuous flow instead of "go do something over
there and return knowing to press a button". But that redirect arrives as an
ordinary browser GET. It carries no session guarantee of its own, no CSRF
header, and no step-up challenge, and its only interesting parameter —
`installation_id` — is a number anybody can type.

So the authority is established before the operator leaves and carried across
as an opaque state. This store mints one, and spends it exactly once — at the
moment the redirect presents it, not at the moment the installation it started
finishes, because everything between those two points is network.

Only the digest of the state is stored. The state itself is a bearer value for
the few minutes it lives, and a table holding it would let anyone who can read
the table finish somebody else's installation. Specification 24 §9 governs.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope, new_identifier

#: Long enough that guessing is not a strategy, short-lived enough that a
#: leaked link in a browser history is not either.
_STATE_BYTES = 32
#: An operator who has left for GitHub either returns promptly or starts again.
DEFAULT_INTENT_LIFETIME = timedelta(minutes=15)


class GitHubInstallationIntentError(RuntimeError):
    """An install intent is absent, expired, already used, or not this actor's."""


@dataclass(frozen=True, slots=True)
class MintedIntent:
    """What the caller needs to send the operator to GitHub."""

    intent_id: str
    #: Returned once and never stored. It travels in the install URL and comes
    #: back in GitHub's redirect.
    state: str
    classification: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ClaimedIntent:
    """One intent, verified and now spent."""

    intent_id: str
    classification: str
    actor_principal: str


def state_digest(state: str) -> str:
    return "sha256:" + hashlib.sha256(state.encode("utf-8")).hexdigest()


class GitHubInstallationIntentStore:
    """Mint and consume the state that carries install authority."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def mint(
        self,
        *,
        scope: Scope,
        classification: str,
        actor_principal: str,
        challenge_id: str,
        now: datetime,
        lifetime: timedelta = DEFAULT_INTENT_LIFETIME,
    ) -> MintedIntent:
        """Record that this operator, having re-authenticated, may install once."""

        if classification not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}:
            raise GitHubInstallationIntentError("a bulk install is not classified RESTRICTED")
        state = secrets.token_urlsafe(_STATE_BYTES)
        intent_id = new_identifier("ghi")
        expires_at = now + lifetime
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_conversation.github_installation_intents (
                     organization_id, project_id, environment_id, id, state_hash,
                     classification, actor_principal, challenge_id, expires_at)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                     %(id)s, %(state_hash)s, %(classification)s, %(actor)s,
                     %(challenge_id)s, %(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "id": intent_id,
                    "state_hash": state_digest(state),
                    "classification": classification,
                    "actor": actor_principal,
                    "challenge_id": challenge_id,
                    "expires_at": expires_at,
                },
            )
        return MintedIntent(
            intent_id=intent_id,
            state=state,
            classification=classification,
            expires_at=expires_at,
        )

    def claim(self, *, scope: Scope, state: str, now: datetime) -> ClaimedIntent:
        """Spend one intent, or refuse.

        The status moves to CLAIMED here, in a single conditional UPDATE, and
        that is the whole point. The caller's transaction ends the moment this
        returns, because what follows is two network calls to GitHub — so an
        intent left PENDING across them would still look usable, and a second
        delivery of the same redirect (a double click, a link prefetch, a
        GitHub retry) would claim it too and race the first to create the same
        bindings.

        One UPDATE settles it. Under READ COMMITTED a concurrent second
        statement blocks on the row, then re-reads it and finds a status its
        WHERE no longer matches, so exactly one caller is handed the intent.
        An intent claimed by a request that then dies stays CLAIMED and is
        never replayable, which is the direction to fail in: the operator
        starts again, and no unattended link survives.
        """

        if not state or len(state) > 512:
            raise GitHubInstallationIntentError("install state is missing or malformed")
        digest = state_digest(state)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """UPDATE solvan_conversation.github_installation_intents
                      SET status='CLAIMED', claimed_at=%(now)s
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND state_hash = %(state_hash)s
                      AND status='PENDING'
                      AND expires_at > %(now)s
                RETURNING id, classification, actor_principal""",
                {**scope.canonical_dict(), "state_hash": digest, "now": now},
            )
            intent = cursor.fetchone()
            if intent is None:
                # Absent, expired, and already-spent are one refusal to the
                # caller. The expiry is still recorded when there is a pending
                # row that was merely late, so the operator-facing record says
                # what happened even though the redirect is told nothing.
                cursor.execute(
                    """UPDATE solvan_conversation.github_installation_intents
                          SET status='REFUSED', error_class='INTENT_EXPIRED'
                        WHERE organization_id = %(organization_id)s
                          AND project_id = %(project_id)s
                          AND environment_id = %(environment_id)s
                          AND state_hash = %(state_hash)s
                          AND status='PENDING'
                          AND expires_at <= %(now)s""",
                    {**scope.canonical_dict(), "state_hash": digest, "now": now},
                )
                raise GitHubInstallationIntentError("this install link is not usable")
        return ClaimedIntent(
            intent_id=str(intent["id"]),
            classification=str(intent["classification"]),
            actor_principal=str(intent["actor_principal"]),
        )

    def complete(
        self,
        *,
        scope: Scope,
        intent_id: str,
        installation_id: int,
        bound_count: int,
        now: datetime,
    ) -> None:
        """Close the intent with what it actually produced."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_conversation.github_installation_intents
                      SET status='CONSUMED', installation_id=%(installation_id)s,
                          bound_count=%(bound_count)s, consumed_at=%(now)s
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND id = %(id)s AND status='CLAIMED'""",
                {
                    **scope.canonical_dict(),
                    "id": intent_id,
                    "installation_id": installation_id,
                    "bound_count": bound_count,
                    "now": now,
                },
            )
            if cursor.rowcount != 1:
                raise GitHubInstallationIntentError("install intent was no longer claimable")

    def refuse(self, *, scope: Scope, intent_id: str, error_class: str) -> None:
        """Close the intent without bindings, naming why."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_conversation.github_installation_intents
                      SET status='REFUSED', error_class=%(error_class)s
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND id = %(id)s AND status IN ('PENDING','CLAIMED')""",
                {**scope.canonical_dict(), "id": intent_id, "error_class": error_class[:100]},
            )
