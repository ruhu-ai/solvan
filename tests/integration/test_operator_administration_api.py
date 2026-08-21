"""Authoring access to an environment, over HTTP, against real PostgreSQL 16.

Governing record: specification 05 §4.2.

These are the first routes in the system that consume an action challenge, so
what they must prove is not that an invitation can be written — it is that one
cannot be written without a re-authentication bound to that exact grant.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.operator_administration import (
    invitation_material,
    material_digest,
    operator_administration_router,
)
from apps.api.session_authorization import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
from solvan.application.oauth_login import credential_hash, session_credential
from solvan.application.operator_identity import VerifiedAssertion
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier
from solvan.persistence.action_challenge_store import ActionChallengeStore
from solvan.persistence.operator_identity_store import OperatorIdentityStore
from solvan.persistence.operator_session_store import OperatorSessionStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
ADMITTED = frozenset({"ruhu.ai"})
CSRF_TOKEN = "double-submit-token"


@pytest.fixture
def connection() -> Iterator[psycopg.Connection[Any]]:
    assert DATABASE_URL is not None
    with (
        psycopg.connect(DATABASE_URL) as database,
        database.transaction(force_rollback=True),
    ):
        database.execute(
            "INSERT INTO solvan.organizations(id,display_name) VALUES (%s,'T') "
            "ON CONFLICT DO NOTHING",
            (SCOPE.organization_id,),
        )
        database.execute(
            "INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id) "
            "VALUES (%s,%s,'T','solvan-test') ON CONFLICT DO NOTHING",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            "INSERT INTO solvan.environments"
            "(organization_id,project_id,id,display_name,region,classification) "
            "VALUES (%s,%s,%s,'T','europe-west1','INTERNAL') ON CONFLICT DO NOTHING",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        yield database


def _client(connection: psycopg.Connection[Any]) -> TestClient:
    app = FastAPI()
    app.include_router(
        operator_administration_router(
            # The route opens its own transaction against this same connection;
            # the fixture rolls the whole thing back.
            connect=lambda: _NonClosing(connection),  # type: ignore[arg-type]
            scope_provider=lambda: SCOPE,
            admitted_domains_provider=lambda _scope: ADMITTED,
        )
    )
    return TestClient(app)


class _NonClosing:
    """The test's connection, lent to a route without letting it be closed."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection

    def __enter__(self) -> psycopg.Connection[Any]:
        return self._connection

    def __exit__(self, *_exc: object) -> None:
        return None


def _signed_in(
    connection: psycopg.Connection[Any], *, roles: tuple[str, ...], now: datetime
) -> tuple[str, str, str]:
    """An actor holding `roles`, and the credential their browser carries."""

    identity = OperatorIdentityStore(connection)
    sessions = OperatorSessionStore(connection)
    actor = identity.resolve_actor(
        VerifiedAssertion(
            provider="GOOGLE",
            issuer="https://accounts.google.com",
            subject="108000000000000000001",
            email="founder@ruhu.ai",
            email_verified=True,
            hosted_domain="ruhu.ai",
            authenticated_at_epoch=int(now.timestamp()),
        ).resolved(),
        now=now,
    )
    for role in roles:
        connection.execute(
            """INSERT INTO solvan_identity.actor_memberships
                 (organization_id,project_id,environment_id,actor_id,role,granted_by_actor_id)
               VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, actor, role, actor),
        )
    event = sessions.record_authentication(
        actor_id=actor,
        canonical_issuer="accounts.google.com",
        subject="108000000000000000001",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=now,
        hosted_domain="ruhu.ai",
        now=now,
    )
    credential, stored = session_credential()
    session = sessions.create_session(
        actor_id=actor, credential_hash=stored, authentication_event_id=event, now=now
    )
    return actor, session, credential


def _challenge_for(
    connection: psycopg.Connection[Any],
    *,
    actor: str,
    session: str,
    digest: str,
    now: datetime,
) -> tuple[str, str]:
    """A live `role.grant` challenge frozen against one exact grant."""

    store = ActionChallengeStore(connection)
    event = connection.execute(
        "SELECT id FROM solvan_identity.authentication_events WHERE actor_id=%s "
        "ORDER BY authenticated_at DESC LIMIT 1",
        (actor,),
    ).fetchone()
    assert event is not None
    frozen = store.freeze(
        scope=SCOPE,
        session_id=session,
        actor_id=actor,
        operation_key="role.grant",
        material_digest=digest,
        expires_at=now + timedelta(minutes=5),
        now=now,
    )
    resulting_credential, stored = session_credential()
    resulting_session = OperatorSessionStore(connection).create_session(
        actor_id=actor,
        credential_hash=stored,
        authentication_event_id=str(event[0]),
        now=now,
        rotated_from_session_id=session,
        absolute_expires_at=now + timedelta(hours=8),
    )
    code_id = new_identifier("sup")
    connection.execute(
        """INSERT INTO solvan_identity.operator_step_up_codes
             (id,step_up_transaction_id,requesting_session_id,actor_id,
              organization_id,project_id,environment_id,email,verifier_hmac,
              delivery_status,delivery_receipt,delivered_at,created_at,expires_at,
              status,consumed_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,'admin@ruhu.ai',%s,
              'DELIVERED','test:delivery',%s,%s,%s,'CONSUMED',%s)""",
        (
            code_id,
            frozen,
            session,
            actor,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            "hmac-sha256:" + "d" * 64,
            now,
            now,
            now + timedelta(minutes=5),
            now,
        ),
    )
    presence = new_identifier("pev")
    connection.execute(
        """INSERT INTO solvan_identity.step_up_presence_events
             (id,step_up_transaction_id,code_id,actor_id,requesting_session_id,
              resulting_session_id,method,proven_at)
           VALUES (%s,%s,%s,%s,%s,%s,'EMAIL_OTP',%s)""",
        (presence, frozen, code_id, actor, session, resulting_session, now),
    )
    challenge = store.issue(
        scope=SCOPE,
        step_up_transaction_id=frozen,
        session_id=resulting_session,
        actor_id=actor,
        presence_event_id=presence,
        csrf_token_hash=credential_hash(CSRF_TOKEN),
        now=now,
    )
    return challenge, resulting_credential


def _invitation_count(connection: psycopg.Connection[Any]) -> int:
    row = connection.execute("SELECT count(*) FROM solvan_identity.actor_invitations").fetchone()
    assert row is not None
    return int(row[0])


def _cookies(credential: str) -> dict[str, str]:
    return {SESSION_COOKIE: credential, CSRF_COOKIE: CSRF_TOKEN}


def test_the_roster_is_refused_without_a_session_and_without_admin(
    connection: psycopg.Connection[Any],
) -> None:
    """Reading who has access is itself administration."""

    now = datetime.now(UTC)
    client = _client(connection)

    assert client.get("/api/admin/operators").status_code == 401

    _actor, _session, credential = _signed_in(connection, roles=("OPERATOR",), now=now)
    refused = client.get("/api/admin/operators", cookies=_cookies(credential))
    assert refused.status_code == 403
    assert "ADMIN" in refused.json()["detail"]


def test_an_administrator_reads_members_and_outstanding_invitations(
    connection: psycopg.Connection[Any],
) -> None:
    now = datetime.now(UTC)
    client = _client(connection)
    actor, _session, credential = _signed_in(connection, roles=("ADMIN",), now=now)

    roster = client.get("/api/admin/operators", cookies=_cookies(credential))

    assert roster.status_code == 200
    body = roster.json()
    assert body["admitted_domains"] == ["ruhu.ai"]
    assert [member["actor_id"] for member in body["members"]] == [actor]
    assert body["members"][0]["email"] == "founder@ruhu.ai"
    assert body["invitations"] == []


def test_an_invitation_cannot_be_written_without_a_challenge(
    connection: psycopg.Connection[Any],
) -> None:
    """The re-authentication is what authorizes the grant, not the ADMIN role.

    Holding ADMIN is necessary and not sufficient: a page that could invite on a
    session alone would let a stolen tab grant somebody access silently.
    """

    now = datetime.now(UTC)
    client = _client(connection)
    _actor, _session, credential = _signed_in(connection, roles=("ADMIN",), now=now)

    refused = client.post(
        "/api/admin/operators/invitations",
        json={"schema_version": 1, "email": "colleague@ruhu.ai", "role": "OPERATOR"},
        cookies=_cookies(credential),
        headers={CSRF_HEADER: CSRF_TOKEN},
    )

    assert refused.status_code == 401
    assert connection.execute(
        "SELECT count(*) FROM solvan_identity.actor_invitations"
    ).fetchone() == (0,)


def test_a_challenge_for_one_grant_cannot_author_another(
    connection: psycopg.Connection[Any],
) -> None:
    """The material binding is the point of freezing the grant before leaving.

    Re-authenticating for "invite as OPERATOR" must not return authority to
    invite as ADMIN, which is exactly what a page altered while the operator was
    away at the provider would attempt.
    """

    now = datetime.now(UTC)
    client = _client(connection)
    actor, session, credential = _signed_in(connection, roles=("ADMIN",), now=now)
    challenge, credential = _challenge_for(
        connection,
        actor=actor,
        session=session,
        digest=material_digest(invitation_material(email="colleague@ruhu.ai", role="OPERATOR")),
        now=now,
    )

    escalated = client.post(
        "/api/admin/operators/invitations",
        json={"schema_version": 1, "email": "colleague@ruhu.ai", "role": "ADMIN"},
        cookies=_cookies(credential),
        headers={CSRF_HEADER: CSRF_TOKEN, "X-Solvan-Challenge": challenge},
    )

    assert escalated.status_code == 403
    assert "authorizes what was shown" in escalated.json()["detail"]
    assert connection.execute(
        "SELECT count(*) FROM solvan_identity.actor_invitations"
    ).fetchone() == (0,)


def test_an_invitation_is_written_once_and_its_challenge_is_spent(
    connection: psycopg.Connection[Any],
) -> None:
    now = datetime.now(UTC)
    client = _client(connection)
    actor, session, credential = _signed_in(connection, roles=("ADMIN",), now=now)
    digest = material_digest(invitation_material(email="colleague@ruhu.ai", role="OPERATOR"))
    challenge, credential = _challenge_for(
        connection, actor=actor, session=session, digest=digest, now=now
    )
    headers = {CSRF_HEADER: CSRF_TOKEN, "X-Solvan-Challenge": challenge}
    command = {"schema_version": 1, "email": "Colleague@Ruhu.ai", "role": "OPERATOR"}

    created = client.post(
        "/api/admin/operators/invitations",
        json=command,
        cookies=_cookies(credential),
        headers=headers,
    )

    assert created.status_code == 201
    # Stored lowercased, as the redemption path and the unique index require.
    assert created.json()["email"] == "colleague@ruhu.ai"
    stored = connection.execute(
        "SELECT email, role, invited_by_actor_id FROM solvan_identity.actor_invitations"
    ).fetchall()
    assert stored == [("colleague@ruhu.ai", "OPERATOR", actor)]

    # The same challenge, replayed. One use means one grant.
    replayed = client.post(
        "/api/admin/operators/invitations",
        json=command,
        cookies=_cookies(credential),
        headers=headers,
    )
    assert replayed.status_code == 403
    assert connection.execute(
        "SELECT count(*) FROM solvan_identity.actor_invitations"
    ).fetchone() == (1,)


def test_a_domain_this_environment_does_not_admit_is_refused_when_authored(
    connection: psycopg.Connection[Any],
) -> None:
    """Refused here rather than at redemption.

    The person who meets the refusal otherwise is the invitee, for a mistake the
    administrator made — and they have no way to tell a typo from a decision.
    """

    now = datetime.now(UTC)
    client = _client(connection)
    actor, session, credential = _signed_in(connection, roles=("ADMIN",), now=now)
    challenge, credential = _challenge_for(
        connection,
        actor=actor,
        session=session,
        digest=material_digest(invitation_material(email="someone@example.com", role="OPERATOR")),
        now=now,
    )

    refused = client.post(
        "/api/admin/operators/invitations",
        json={"schema_version": 1, "email": "someone@example.com", "role": "OPERATOR"},
        cookies=_cookies(credential),
        headers={CSRF_HEADER: CSRF_TOKEN, "X-Solvan-Challenge": challenge},
    )

    assert refused.status_code == 400
    assert "not an admitted domain" in refused.json()["detail"]
