"""Alert reader identity over HTTP, against real PostgreSQL 16.

Governing records: specification 21 §8, specification 05 §4.2.

The connected-reader path had no coverage at this level: every router test
stubbed `principal_provider`, so a deployment demanding a verified identity
answered every Alert read 401 — the console never sends the token header — and
the suite stayed green. These exercise the seam as the browser reaches it: a
session cookie, a live grant, and the refusals on either side.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from apps.api.alert_console import alert_console_router
from apps.api.session_authorization import SESSION_COOKIE
from solvan.application.oauth_login import session_credential
from solvan.application.operator_identity import VerifiedAssertion
from solvan.domain import Scope
from solvan.persistence.operator_identity_store import OperatorIdentityStore
from solvan.persistence.operator_session_store import OperatorSessionStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
PRINCIPAL = "user:reader@ruhu.ai"


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


class _NonClosing:
    """The test's connection, lent to a route without letting it be closed."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection

    def __enter__(self) -> psycopg.Connection[Any]:
        return self._connection

    def __exit__(self, *_exc: object) -> None:
        return None


def _connected_reader(token: str | None) -> str:
    """What `_reader_principal` does on a connected host when no grant arrives."""

    raise HTTPException(401, "missing Google identity token")


def _client(connection: psycopg.Connection[Any]) -> TestClient:
    app = FastAPI()
    app.include_router(
        alert_console_router(
            scope_provider=lambda: SCOPE,
            principal_provider=_connected_reader,
            connect=lambda: _NonClosing(connection),  # type: ignore[arg-type]
            local_mode_provider=lambda: False,
            cursor_signing_key_provider=lambda: b"test-alert-cursor-signing-key-0001",
        )
    )
    return TestClient(app)


def _signed_in(connection: psycopg.Connection[Any], *, now: datetime) -> str:
    """An actor with a live session; returns the credential the browser holds."""

    identity = OperatorIdentityStore(connection)
    sessions = OperatorSessionStore(connection)
    actor = identity.resolve_actor(
        VerifiedAssertion(
            provider="GOOGLE",
            issuer="https://accounts.google.com",
            subject="108000000000000000002",
            email="reader@ruhu.ai",
            email_verified=True,
            hosted_domain="ruhu.ai",
            authenticated_at_epoch=int(now.timestamp()),
        ).resolved(),
        now=now,
    )
    event = sessions.record_authentication(
        actor_id=actor,
        canonical_issuer="accounts.google.com",
        subject="108000000000000000002",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=now,
        hosted_domain="ruhu.ai",
        now=now,
    )
    credential, stored = session_credential()
    sessions.create_session(
        actor_id=actor, credential_hash=stored, authentication_event_id=event, now=now
    )
    return credential


def _grant_reader(connection: psycopg.Connection[Any]) -> None:
    connection.execute(
        """INSERT INTO solvan.actor_role_bindings
             (organization_id,project_id,environment_id,principal,role,granted_by)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   %(principal)s,'OPERATOR',%(principal)s)
           ON CONFLICT DO NOTHING""",
        {**SCOPE.canonical_dict(), "principal": PRINCIPAL},
    )


def test_a_signed_in_reader_with_a_grant_reads_the_live_queue(
    connection: psycopg.Connection[Any],
) -> None:
    credential = _signed_in(connection, now=datetime.now(UTC))
    _grant_reader(connection)

    response = _client(connection).get("/api/alerts", cookies={SESSION_COOKIE: credential})

    assert response.status_code == 200
    assert response.json()["schema_version"] == 1
    assert response.json()["rows"] == []
    assert response.headers["cache-control"] == "private, no-store"


def test_no_session_and_no_grant_is_refused_as_unauthenticated(
    connection: psycopg.Connection[Any],
) -> None:
    response = _client(connection).get("/api/alerts")

    assert response.status_code == 401


def test_a_session_without_a_reader_grant_is_refused_as_forbidden(
    connection: psycopg.Connection[Any],
) -> None:
    """A session establishes who you are; it never substitutes for the grant."""

    credential = _signed_in(connection, now=datetime.now(UTC))

    response = _client(connection).get("/api/alerts", cookies={SESSION_COOKIE: credential})

    assert response.status_code == 403
    assert response.json()["detail"] == "ALERT_READER_GRANT_INACTIVE"


def test_an_unknown_session_credential_falls_back_to_the_grant_path(
    connection: psycopg.Connection[Any],
) -> None:
    response = _client(connection).get("/api/alerts", cookies={SESSION_COOKIE: "fabricated"})

    assert response.status_code == 401
