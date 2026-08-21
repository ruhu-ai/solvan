"""What a request carrying a signed-in session is allowed to do (spec 05 §4.2).

Separated from the sign-in flow on purpose. `auth_routes` establishes who
somebody is; this module is what every other router imports to decide whether
the session in front of it authorizes the operation being asked for. They were
one file until the size ceiling objected, which was the first thing to point out
that the file had two jobs.

Nothing here trusts a header, a body, or a model argument for principal or
scope. A session proves identity; a spent challenge proves authority for one
exact operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request, status
from psycopg import Connection

from solvan.application.action_challenge import (
    ActionChallengeError,
    authorize_consumption,
)
from solvan.application.oauth_login import credential_hash
from solvan.domain import Scope
from solvan.persistence.action_challenge_store import ActionChallengeStore
from solvan.persistence.operator_identity_store import OperatorIdentityStore
from solvan.persistence.operator_session_store import OperatorSessionStore
from solvan.platform.database import connect_database

#: `__Host-` requires Secure and a root path and forbids a Domain attribute, so
#: a cookie carrying it cannot have been set by a sibling host or a subdomain.
#: It is always set, including locally: browsers treat loopback as a trustworthy
#: origin, and a deployment that cannot set it should fail to sign anyone in
#: rather than fall back to a weaker cookie.
SESSION_COOKIE = "__Host-solvan_session"
#: Readable by JavaScript on purpose: the console echoes it in a header, which a
#: cross-site page cannot do. Holding it is not authority; matching it is.
CSRF_COOKIE = "__Host-solvan_csrf"
CSRF_HEADER = "X-Solvan-CSRF"


def _now() -> datetime:
    return datetime.now(UTC)


def require_administrator(request: Request, scope: Scope) -> str:
    """The signed-in actor, refused unless they hold ADMIN in this scope now.

    For reads that grant nothing but disclose something — a customer's project,
    the identity that will read it — where a challenge would be ceremony and an
    open door would be a leak. Roles are read per request, so removing somebody's
    administration takes effect immediately rather than at their next sign-in.
    """

    credential = request.cookies.get(SESSION_COOKIE)
    if not credential:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
    now = _now()
    with connect_database() as connection:
        live = OperatorSessionStore(connection).touch(
            credential_hash=credential_hash(credential), now=now
        )
        if live is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
        roles = OperatorIdentityStore(connection).roles(
            scope=scope, actor_id=live.actor_id, now=now
        )
    if "ADMIN" not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role is required")
    return live.actor_id


def recorded_principal(connection: Connection[Any], actor_id: str) -> str:
    """The actor, in the principal form every durable record already uses.

    Records name `user:{email}`, so anything written as `actor:{id}` becomes the
    one row an operator cannot match to a person while reading an audit trail.
    Falls back to the actor identifier rather than inventing an address.
    """

    row = connection.execute(
        """SELECT email FROM solvan_identity.external_identities
            WHERE actor_id=%s ORDER BY last_seen_at DESC LIMIT 1""",
        (actor_id,),
    ).fetchone()
    return f"user:{row[0]}" if row is not None else f"actor:{actor_id}"


def session_reader_principal(connection: Connection[Any], request: Request) -> str | None:
    """The signed-in reader's principal, or None when no live session is held.

    This is the read-side consumption of the §4.2 session: identity only. What
    the principal may see remains checked per route against current grants, so
    a revoked session or membership stops admitting at once. `None` rather
    than a refusal lets the caller fall back to the audience-bound identity
    grant a non-browser caller presents; a browser holding neither meets the
    same 401 from that path as it would have met here.

    The connection is the caller's, so the read shares the route's transaction
    and test fixture rather than opening a second, uncoordinated one.
    """

    credential = request.cookies.get(SESSION_COOKIE)
    if not credential:
        return None
    live = OperatorSessionStore(connection).touch(
        credential_hash=credential_hash(credential), now=_now()
    )
    if live is None:
        return None
    return recorded_principal(connection, live.actor_id)


@dataclass(frozen=True, slots=True)
class ConsumedChallenge:
    """Proof that one exact operation is authorized, spent by the caller's transaction."""

    challenge_id: str
    actor_id: str
    session_id: str
    operation: str


def spend_challenge(
    connection: Connection[Any],
    request: Request,
    *,
    scope: Scope,
    operation: str,
    material_digest: str,
    now: datetime,
) -> ConsumedChallenge:
    """Authorize one decision and spend its challenge, inside the caller's transaction.

    The caller records the decision in the same transaction. Separating them
    either burns authority without recording the operation, or records the
    operation while leaving its challenge replayable.
    """

    require_csrf(request)
    credential = request.cookies.get(SESSION_COOKIE)
    challenge_id = request.headers.get("X-Solvan-Challenge", "")
    if not credential or not challenge_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "this action requires a challenge")
    sessions = OperatorSessionStore(connection)
    live = sessions.touch(credential_hash=credential_hash(credential), now=now)
    if live is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
    store = ActionChallengeStore(connection)
    locked = store.lock(scope=scope, challenge_id=challenge_id)
    if locked is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no such challenge")
    csrf = request.headers.get(CSRF_HEADER, "")
    roles = OperatorIdentityStore(connection).roles(scope=scope, actor_id=live.actor_id, now=now)
    try:
        authorize_consumption(
            challenge=locked,
            actor_id=live.actor_id,
            session_id=live.session_id,
            operation_key=operation,
            material_digest=material_digest,
            csrf_token_hash=credential_hash(csrf),
            current_roles=roles,
            now=now,
        )
        store.consume(scope=scope, challenge_id=challenge_id, now=now)
    except ActionChallengeError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
    return ConsumedChallenge(
        challenge_id=challenge_id,
        actor_id=live.actor_id,
        session_id=live.session_id,
        operation=operation,
    )


def require_csrf(request: Request) -> None:
    """Double submit: a cross-site page can neither read the cookie nor set the header."""

    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not cookie or not header or cookie != header:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-site request refused")


__all__ = [
    "CSRF_COOKIE",
    "CSRF_HEADER",
    "SESSION_COOKIE",
    "ConsumedChallenge",
    "recorded_principal",
    "require_administrator",
    "require_csrf",
    "session_reader_principal",
    "spend_challenge",
]
