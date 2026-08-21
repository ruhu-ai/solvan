"""Step-up and one-use challenges against real PostgreSQL 16.

Governing record: specification 05 §4.2 (action challenge).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from solvan.application.action_challenge import (
    ActionChallengeError,
    TerminalReason,
    authorize_consumption,
)
from solvan.application.oauth_login import session_credential
from solvan.application.operator_identity import VerifiedAssertion
from solvan.application.operator_step_up import issue_code
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier
from solvan.persistence.action_challenge_store import ActionChallengeStore
from solvan.persistence.operator_identity_store import OperatorIdentityStore
from solvan.persistence.operator_session_store import OperatorSessionStore
from solvan.persistence.operator_step_up_store import OperatorStepUpStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "b" * 64
CSRF = "sha256:" + "c" * 64


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


def _actor_and_session(connection: psycopg.Connection[Any]) -> tuple[str, str, str]:
    identity = OperatorIdentityStore(connection)
    sessions = OperatorSessionStore(connection)
    actor = identity.resolve_actor(
        VerifiedAssertion(
            provider="GOOGLE",
            issuer="https://accounts.google.com",
            subject="108000000000000000001",
            email="operator@example.com",
            email_verified=True,
            hosted_domain="example.com",
            authenticated_at_epoch=1_760_000_000,
        ).resolved(),
        now=NOW,
    )
    event = sessions.record_authentication(
        actor_id=actor,
        canonical_issuer="accounts.google.com",
        subject="108000000000000000001",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=NOW,
        hosted_domain="example.com",
        now=NOW,
    )
    _credential, stored = session_credential()
    session = sessions.create_session(
        actor_id=actor, credential_hash=stored, authentication_event_id=event, now=NOW
    )
    return actor, session, event


def _issued(connection: psycopg.Connection[Any]) -> tuple[ActionChallengeStore, str, str, str]:
    actor, session, event = _actor_and_session(connection)
    store = ActionChallengeStore(connection)
    frozen = store.freeze(
        scope=SCOPE,
        session_id=session,
        actor_id=actor,
        operation_key="estate.connect",
        material_digest=DIGEST,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    session, presence = _presence(connection, frozen, actor, session, event)
    challenge = store.issue(
        scope=SCOPE,
        step_up_transaction_id=frozen,
        session_id=session,
        actor_id=actor,
        presence_event_id=presence,
        csrf_token_hash=CSRF,
        now=NOW,
    )
    return store, challenge, actor, session


def _presence(
    connection: psycopg.Connection[Any],
    frozen: str,
    actor: str,
    requesting_session: str,
    event: str,
) -> tuple[str, str]:
    """Persist the completed presence and rotation that challenge issuance requires."""

    sessions = OperatorSessionStore(connection)
    _credential, stored = session_credential()
    resulting_session = sessions.create_session(
        actor_id=actor,
        credential_hash=stored,
        authentication_event_id=event,
        now=NOW,
        rotated_from_session_id=requesting_session,
        absolute_expires_at=NOW + timedelta(hours=8),
    )
    code_id = new_identifier("sup")
    connection.execute(
        """INSERT INTO solvan_identity.operator_step_up_codes
             (id,step_up_transaction_id,requesting_session_id,actor_id,
              organization_id,project_id,environment_id,email,verifier_hmac,attempts,
              delivery_status,delivery_receipt,delivered_at,created_at,expires_at,
              status,consumed_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,'operator@example.com',%s,0,
              'DELIVERED','test:delivery',%s,%s,%s,'CONSUMED',%s)""",
        (
            code_id,
            frozen,
            requesting_session,
            actor,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            "hmac-sha256:" + "d" * 64,
            NOW,
            NOW,
            NOW + timedelta(minutes=5),
            NOW,
        ),
    )
    presence = new_identifier("pev")
    connection.execute(
        """INSERT INTO solvan_identity.step_up_presence_events
             (id,step_up_transaction_id,code_id,actor_id,requesting_session_id,
              resulting_session_id,method,proven_at)
           VALUES (%s,%s,%s,%s,%s,%s,'EMAIL_OTP',%s)""",
        (presence, frozen, code_id, actor, requesting_session, resulting_session, NOW),
    )
    return resulting_session, presence


def test_a_challenge_is_issued_from_the_frozen_transaction(
    connection: psycopg.Connection[Any],
) -> None:
    store, challenge, actor, session = _issued(connection)
    locked = store.lock(scope=SCOPE, challenge_id=challenge)
    assert locked is not None
    # The operation and material come from what was frozen, not from the caller,
    # so a callback cannot widen what the operator was shown.
    assert locked.operation == "estate.connect"
    assert locked.material_digest == DIGEST
    assert locked.actor_id == actor and locked.session_id == session


def test_a_challenge_is_consumed_exactly_once(connection: psycopg.Connection[Any]) -> None:
    store, challenge, _actor, _session = _issued(connection)
    store.consume(scope=SCOPE, challenge_id=challenge, now=NOW)
    with pytest.raises(ActionChallengeError, match="already used"):
        store.consume(scope=SCOPE, challenge_id=challenge, now=NOW)


def test_a_consumed_challenge_no_longer_authorizes(
    connection: psycopg.Connection[Any],
) -> None:
    store, challenge, actor, session = _issued(connection)
    store.consume(scope=SCOPE, challenge_id=challenge, now=NOW)
    locked = store.lock(scope=SCOPE, challenge_id=challenge)
    assert locked is not None
    with pytest.raises(ActionChallengeError, match="already been used"):
        authorize_consumption(
            challenge=locked,
            actor_id=actor,
            session_id=session,
            operation_key="estate.connect",
            material_digest=DIGEST,
            csrf_token_hash=CSRF,
            current_roles=frozenset({"ADMIN"}),
            now=NOW,
        )


def test_an_ended_challenge_records_why(connection: psycopg.Connection[Any]) -> None:
    store, challenge, _actor, _session = _issued(connection)
    store.end(scope=SCOPE, challenge_id=challenge, reason=TerminalReason.MATERIAL_CHANGED)
    row = connection.execute(
        "SELECT status, terminal_reason FROM solvan_identity.action_challenges WHERE id=%s",
        (challenge,),
    ).fetchone()
    assert row == ("TERMINAL", "MATERIAL_CHANGED")
    with pytest.raises(ActionChallengeError):
        store.consume(scope=SCOPE, challenge_id=challenge, now=NOW)


def test_a_step_up_yields_one_challenge(connection: psycopg.Connection[Any]) -> None:
    """A second challenge on one frozen action is the replay this refuses."""

    actor, session, event = _actor_and_session(connection)
    store = ActionChallengeStore(connection)
    frozen = store.freeze(
        scope=SCOPE,
        session_id=session,
        actor_id=actor,
        operation_key="estate.connect",
        material_digest=DIGEST,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    session, presence = _presence(connection, frozen, actor, session, event)
    store.issue(
        scope=SCOPE,
        step_up_transaction_id=frozen,
        session_id=session,
        actor_id=actor,
        presence_event_id=presence,
        csrf_token_hash=CSRF,
        now=NOW,
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        store.issue(
            scope=SCOPE,
            step_up_transaction_id=frozen,
            session_id=session,
            actor_id=actor,
            presence_event_id=presence,
            csrf_token_hash=CSRF,
            now=NOW,
        )


def test_a_different_person_cannot_complete_someone_elses_step_up(
    connection: psycopg.Connection[Any],
) -> None:
    """Signing in as somebody else must not collect the action they froze."""

    actor, session, event = _actor_and_session(connection)
    store = ActionChallengeStore(connection)
    frozen = store.freeze(
        scope=SCOPE,
        session_id=session,
        actor_id=actor,
        operation_key="estate.connect",
        material_digest=DIGEST,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    other = OperatorIdentityStore(connection).resolve_actor(
        VerifiedAssertion(
            provider="GOOGLE",
            issuer="accounts.google.com",
            subject="208000000000000000002",
            email="other@example.com",
            email_verified=True,
            hosted_domain="example.com",
            authenticated_at_epoch=1_760_000_000,
        ).resolved(),
        now=NOW,
    )
    session, presence = _presence(connection, frozen, actor, session, event)
    with pytest.raises(ActionChallengeError, match="different actor"):
        store.issue(
            scope=SCOPE,
            step_up_transaction_id=frozen,
            session_id=session,
            actor_id=other,
            presence_event_id=presence,
            csrf_token_hash=CSRF,
            now=NOW,
        )


def test_an_action_that_expired_during_sign_in_is_not_granted(
    connection: psycopg.Connection[Any],
) -> None:
    actor, session, event = _actor_and_session(connection)
    store = ActionChallengeStore(connection)
    frozen = store.freeze(
        scope=SCOPE,
        session_id=session,
        actor_id=actor,
        operation_key="estate.connect",
        material_digest=DIGEST,
        expires_at=NOW + timedelta(minutes=1),
        now=NOW,
    )
    session, presence = _presence(connection, frozen, actor, session, event)
    with pytest.raises(ActionChallengeError, match="expired during verification"):
        store.issue(
            scope=SCOPE,
            step_up_transaction_id=frozen,
            session_id=session,
            actor_id=actor,
            presence_event_id=presence,
            csrf_token_hash=CSRF,
            now=NOW + timedelta(minutes=2),
        )


def test_an_unregistered_operation_cannot_be_frozen(
    connection: psycopg.Connection[Any],
) -> None:
    actor, session, _event = _actor_and_session(connection)
    with pytest.raises(ActionChallengeError, match="not a registered"):
        ActionChallengeStore(connection).freeze(
            scope=SCOPE,
            session_id=session,
            actor_id=actor,
            operation_key="something.invented",
            material_digest=DIGEST,
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )


def test_a_wrong_presence_code_attempt_is_recorded_without_erasing_the_request(
    connection: psycopg.Connection[Any],
) -> None:
    actor, session, _event = _actor_and_session(connection)
    frozen = ActionChallengeStore(connection).freeze(
        scope=SCOPE,
        session_id=session,
        actor_id=actor,
        operation_key="estate.connect",
        material_digest=DIGEST,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    pepper = "test-only-step-up-pepper-is-at-least-32-bytes"
    issued = issue_code(now=NOW, step_up_transaction_id=frozen, pepper=pepper)
    store = OperatorStepUpStore(connection)
    code_id = store.start(
        scope=SCOPE,
        step_up_transaction_id=frozen,
        requesting_session_id=session,
        actor_id=actor,
        email="operator@example.com",
        issued=issued,
        now=NOW,
    )
    store.mark_delivered(code_id=code_id, receipt="test:delivery", now=NOW)
    store.record_wrong_attempt(code_id=code_id, now=NOW)

    pending = store.lock(scope=SCOPE, code_id=code_id)
    assert pending is not None
    assert pending.attempts == 1
    assert pending.status == "PENDING"
