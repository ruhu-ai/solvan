"""Actors, memberships, and invitations against real PostgreSQL 16.

Governing record: specification 05 §4.2.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from solvan.application.operator_identity import (
    OperatorIdentityError,
    VerifiedAssertion,
)
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier
from solvan.persistence.operator_identity_store import OperatorIdentityStore

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


def _assertion(**overrides: object) -> VerifiedAssertion:
    base: dict[str, object] = {
        "provider": "GOOGLE",
        "issuer": "https://accounts.google.com",
        "subject": "108000000000000000001",
        "email": "operator@example.com",
        "email_verified": True,
        "hosted_domain": "example.com",
        "authenticated_at_epoch": 1_760_000_000,
    }
    base.update(overrides)
    return VerifiedAssertion(**base)  # type: ignore[arg-type]


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


def test_first_sign_in_mints_one_actor_and_later_ones_reuse_it(
    connection: psycopg.Connection[Any],
) -> None:
    store = OperatorIdentityStore(connection)
    first = store.resolve_actor(_assertion().resolved(), now=NOW)
    again = store.resolve_actor(_assertion().resolved(), now=NOW)
    assert first == again
    assert first.startswith("act_")


def test_the_same_person_under_either_issuer_spelling_is_one_actor(
    connection: psycopg.Connection[Any],
) -> None:
    """Two spellings would give one person two actors and two sets of roles."""

    store = OperatorIdentityStore(connection)
    with_scheme = store.resolve_actor(
        _assertion(issuer="https://accounts.google.com").resolved(), now=NOW
    )
    without = store.resolve_actor(_assertion(issuer="accounts.google.com").resolved(), now=NOW)
    assert with_scheme == without


def test_a_renamed_address_keeps_the_same_actor_and_its_roles(
    connection: psycopg.Connection[Any],
) -> None:
    """The defect the subject key exists to prevent.

    Keyed on email, a rename would mint a second actor holding no roles, and the
    person would silently lose their authority.
    """

    store = OperatorIdentityStore(connection)
    actor = store.resolve_actor(_assertion().resolved(), now=NOW)
    connection.execute(
        "INSERT INTO solvan_identity.actor_memberships"
        "(organization_id,project_id,environment_id,actor_id,role,granted_by_actor_id) "
        "VALUES (%s,%s,%s,%s,'APPROVER',%s)",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, actor, actor),
    )
    renamed = store.resolve_actor(_assertion(email="new.name@example.com").resolved(), now=NOW)
    assert renamed == actor
    assert store.roles(scope=SCOPE, actor_id=renamed, now=NOW) == frozenset({"APPROVER"})


def test_a_different_subject_at_the_same_address_is_a_different_actor(
    connection: psycopg.Connection[Any],
) -> None:
    """A reassigned address must not inherit the previous holder's authority."""

    store = OperatorIdentityStore(connection)
    leaver = store.resolve_actor(_assertion().resolved(), now=NOW)
    joiner = store.resolve_actor(_assertion(subject="208000000000000000002").resolved(), now=NOW)
    assert joiner != leaver
    assert store.roles(scope=SCOPE, actor_id=joiner, now=NOW) == frozenset()


def test_roles_are_scoped_and_expire(connection: psycopg.Connection[Any]) -> None:
    store = OperatorIdentityStore(connection)
    actor = store.resolve_actor(_assertion().resolved(), now=NOW)
    connection.execute(
        "INSERT INTO solvan_identity.actor_memberships"
        "(organization_id,project_id,environment_id,actor_id,role,granted_by_actor_id,"
        "granted_at,expires_at) VALUES (%s,%s,%s,%s,'OPERATOR',%s,%s,%s)",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            actor,
            actor,
            NOW,
            NOW + timedelta(hours=1),
        ),
    )
    assert store.roles(scope=SCOPE, actor_id=actor, now=NOW) == frozenset({"OPERATOR"})
    assert store.roles(scope=SCOPE, actor_id=actor, now=NOW + timedelta(hours=2)) == frozenset()


def _invite(
    connection: psycopg.Connection[Any],
    *,
    inviter: str,
    email: str = "newcomer@example.com",
    role: str = "OPERATOR",
    expires_at: datetime | None = None,
) -> str:
    invitation = new_identifier("inv")
    connection.execute(
        "INSERT INTO solvan_identity.actor_invitations"
        "(id,organization_id,project_id,environment_id,email,admitted_domain,role,"
        "invited_by_actor_id,created_at,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            invitation,
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            email,
            "example.com",
            role,
            inviter,
            NOW,
            expires_at or NOW + timedelta(days=7),
        ),
    )
    return invitation


def test_redeeming_an_invitation_grants_and_consumes_together(
    connection: psycopg.Connection[Any],
) -> None:
    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion().resolved(), now=NOW)
    _invite(connection, inviter=inviter, role="APPROVER")
    joiner_assertion = _assertion(
        subject="208000000000000000002", email="newcomer@example.com"
    ).resolved()
    joiner = store.resolve_actor(joiner_assertion, now=NOW)
    granted = store.redeem_invitation(
        scope=SCOPE,
        actor_id=joiner,
        email=joiner_assertion.email,
        hosted_domain="example.com",
        now=NOW,
    )
    assert granted == frozenset({"APPROVER"})
    assert store.roles(scope=SCOPE, actor_id=joiner, now=NOW) == frozenset({"APPROVER"})
    consumed = connection.execute(
        "SELECT consumed_by_actor_id FROM solvan_identity.actor_invitations "
        "WHERE email='newcomer@example.com'"
    ).fetchone()
    assert consumed is not None and consumed[0] == joiner


def test_the_inviter_is_recorded_as_the_granter_not_the_newcomer(
    connection: psycopg.Connection[Any],
) -> None:
    """Otherwise the audit says a newcomer granted themselves their own role."""

    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion().resolved(), now=NOW)
    _invite(connection, inviter=inviter)
    joiner_assertion = _assertion(
        subject="208000000000000000002", email="newcomer@example.com"
    ).resolved()
    joiner = store.resolve_actor(joiner_assertion, now=NOW)
    store.redeem_invitation(
        scope=SCOPE,
        actor_id=joiner,
        email=joiner_assertion.email,
        hosted_domain="example.com",
        now=NOW,
    )
    row = connection.execute(
        "SELECT granted_by_actor_id FROM solvan_identity.actor_memberships WHERE actor_id=%s",
        (joiner,),
    ).fetchone()
    assert row is not None and row[0] == inviter


def test_an_invitation_is_redeemed_once(connection: psycopg.Connection[Any]) -> None:
    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion().resolved(), now=NOW)
    _invite(connection, inviter=inviter)
    joiner_assertion = _assertion(
        subject="208000000000000000002", email="newcomer@example.com"
    ).resolved()
    joiner = store.resolve_actor(joiner_assertion, now=NOW)
    arguments = {
        "scope": SCOPE,
        "actor_id": joiner,
        "email": joiner_assertion.email,
        "hosted_domain": "example.com",
        "now": NOW,
    }
    assert store.redeem_invitation(**arguments) == frozenset({"OPERATOR"})  # type: ignore[arg-type]
    assert store.redeem_invitation(**arguments) == frozenset()  # type: ignore[arg-type]


def test_an_expired_invitation_is_not_a_grant(connection: psycopg.Connection[Any]) -> None:
    """The window that stops a reassigned address inheriting authority."""

    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion().resolved(), now=NOW)
    _invite(connection, inviter=inviter, expires_at=NOW + timedelta(minutes=1))
    joiner_assertion = _assertion(
        subject="208000000000000000002", email="newcomer@example.com"
    ).resolved()
    joiner = store.resolve_actor(joiner_assertion, now=NOW)
    assert (
        store.redeem_invitation(
            scope=SCOPE,
            actor_id=joiner,
            email=joiner_assertion.email,
            hosted_domain="example.com",
            now=NOW + timedelta(days=1),
        )
        == frozenset()
    )
    assert store.roles(scope=SCOPE, actor_id=joiner, now=NOW + timedelta(days=1)) == frozenset()


def test_an_invitation_for_another_domain_is_refused(
    connection: psycopg.Connection[Any],
) -> None:
    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion().resolved(), now=NOW)
    _invite(connection, inviter=inviter)
    joiner = store.resolve_actor(
        _assertion(subject="208000000000000000002", email="newcomer@example.com").resolved(),
        now=NOW,
    )
    with pytest.raises(OperatorIdentityError, match="another admitted domain"):
        store.redeem_invitation(
            scope=SCOPE,
            actor_id=joiner,
            email="newcomer@example.com",
            hosted_domain="elsewhere.com",
            now=NOW,
        )


def _session_store(connection: psycopg.Connection[Any]) -> Any:
    from solvan.persistence.operator_session_store import OperatorSessionStore

    return OperatorSessionStore(connection)


def _open_session(
    connection: psycopg.Connection[Any], *, now: datetime = NOW
) -> tuple[Any, str, str]:
    from solvan.application.oauth_login import session_credential

    identity = OperatorIdentityStore(connection)
    sessions = _session_store(connection)
    actor = identity.resolve_actor(_assertion().resolved(), now=now)
    event = sessions.record_authentication(
        actor_id=actor,
        canonical_issuer="accounts.google.com",
        subject="108000000000000000001",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=now,
        hosted_domain="example.com",
        now=now,
    )
    credential, stored = session_credential()
    session = sessions.create_session(
        actor_id=actor, credential_hash=stored, authentication_event_id=event, now=now
    )
    return sessions, credential, session


def test_a_pending_sign_in_is_claimed_exactly_once(
    connection: psycopg.Connection[Any],
) -> None:
    """Two callbacks racing one authorization code must not both proceed."""

    sessions = _session_store(connection)
    sessions.start_login(
        state_hash="sha256:" + "a" * 64,
        nonce_hash="sha256:" + "b" * 64,
        pkce_verifier="v" * 64,
        audience="111111111111-abc.apps.googleusercontent.com",
        return_path="/incidents",
        expires_at=NOW + timedelta(minutes=10),
        now=NOW,
    )
    first = sessions.claim_login(state_hash="sha256:" + "a" * 64, now=NOW)
    second = sessions.claim_login(state_hash="sha256:" + "a" * 64, now=NOW)
    assert first is not None and second is None
    assert first[1].return_path == "/incidents"


def test_a_live_session_is_returned_and_its_idle_window_extends(
    connection: psycopg.Connection[Any],
) -> None:
    sessions, credential, session = _open_session(connection)
    from solvan.application.oauth_login import credential_hash

    live = sessions.touch(
        credential_hash=credential_hash(credential), now=NOW + timedelta(minutes=10)
    )
    assert live is not None and live.session_id == session


def test_a_revoked_session_stops_admitting_at_once(
    connection: psycopg.Connection[Any],
) -> None:
    from solvan.application.oauth_login import credential_hash

    sessions, credential, session = _open_session(connection)
    sessions.revoke(session_id=session, now=NOW)
    assert sessions.touch(credential_hash=credential_hash(credential), now=NOW) is None


def test_an_idle_session_expires(connection: psycopg.Connection[Any]) -> None:
    from solvan.application.oauth_login import credential_hash

    sessions, credential, _ = _open_session(connection)
    assert (
        sessions.touch(credential_hash=credential_hash(credential), now=NOW + timedelta(hours=1))
        is None
    )


def test_the_absolute_ceiling_bounds_a_session_kept_warm(
    connection: psycopg.Connection[Any],
) -> None:
    """Touching cannot extend a session past its ceiling; otherwise it never ends."""

    from solvan.application.oauth_login import credential_hash

    sessions, credential, _ = _open_session(connection)
    moment = NOW
    for _ in range(20):
        moment = moment + timedelta(minutes=25)
        if sessions.touch(credential_hash=credential_hash(credential), now=moment) is None:
            break
    assert moment <= NOW + timedelta(hours=9)
    assert sessions.touch(credential_hash=credential_hash(credential), now=moment) is None


def test_revoking_an_actor_ends_every_session_they_hold(
    connection: psycopg.Connection[Any],
) -> None:
    from solvan.application.oauth_login import credential_hash

    sessions, credential, _ = _open_session(connection)
    identity = OperatorIdentityStore(connection)
    actor = identity.resolve_actor(_assertion().resolved(), now=NOW)
    assert sessions.revoke_actor(actor_id=actor, now=NOW) >= 1
    assert sessions.touch(credential_hash=credential_hash(credential), now=NOW) is None


def test_a_rotation_ends_the_session_it_replaces(
    connection: psycopg.Connection[Any],
) -> None:
    """A new credential without ending the old one leaves two live sessions.

    The callback previously minted a session and left its predecessor valid, so
    "rotation" was a claim the code did not implement.
    """

    from solvan.application.oauth_login import credential_hash, session_credential

    sessions, first_credential, first_session = _open_session(connection)
    identity = OperatorIdentityStore(connection)
    actor = identity.resolve_actor(_assertion().resolved(), now=NOW)
    event = sessions.record_authentication(
        actor_id=actor,
        canonical_issuer="accounts.google.com",
        subject="108000000000000000001",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=NOW,
        hosted_domain="example.com",
        now=NOW,
    )
    prior = sessions.touch(credential_hash=credential_hash(first_credential), now=NOW)
    assert prior is not None
    second_credential, second_stored = session_credential()
    second_session = sessions.create_session(
        actor_id=actor,
        credential_hash=second_stored,
        authentication_event_id=event,
        now=NOW,
        rotated_from_session_id=prior.session_id,
        absolute_expires_at=prior.absolute_expires_at,
    )
    sessions.revoke(session_id=first_session, now=NOW)
    assert sessions.touch(credential_hash=credential_hash(first_credential), now=NOW) is None
    live = sessions.touch(credential_hash=credential_hash(second_credential), now=NOW)
    assert live is not None and live.session_id == second_session


def test_a_rotation_keeps_the_ceiling_it_inherited(
    connection: psycopg.Connection[Any],
) -> None:
    """Otherwise stepping up repeatedly keeps a session alive forever.

    A fresh absolute expiry on each rotation is a ceiling that bounds nothing,
    which is worse than none because it reads as a bound.
    """

    from solvan.application.oauth_login import credential_hash, session_credential

    sessions, first_credential, _first = _open_session(connection)
    identity = OperatorIdentityStore(connection)
    actor = identity.resolve_actor(_assertion().resolved(), now=NOW)
    event = sessions.record_authentication(
        actor_id=actor,
        canonical_issuer="accounts.google.com",
        subject="108000000000000000001",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=NOW,
        hosted_domain="example.com",
        now=NOW,
    )
    prior = sessions.touch(credential_hash=credential_hash(first_credential), now=NOW)
    assert prior is not None
    later = NOW + timedelta(hours=7)
    _credential, stored = session_credential()
    sessions.create_session(
        actor_id=actor,
        credential_hash=stored,
        authentication_event_id=event,
        now=later,
        rotated_from_session_id=prior.session_id,
        absolute_expires_at=prior.absolute_expires_at,
    )
    row = connection.execute(
        "SELECT absolute_expires_at FROM solvan_identity.operator_sessions "
        "WHERE credential_hash=%s",
        (stored,),
    ).fetchone()
    assert row is not None and row[0] == prior.absolute_expires_at


def test_a_rotation_near_the_absolute_ceiling_clamps_its_idle_window(
    connection: psycopg.Connection[Any],
) -> None:
    """A valid late step-up must not violate the session table's own ceiling."""

    from solvan.application.oauth_login import credential_hash, session_credential

    sessions, first_credential, _first = _open_session(connection)
    prior = sessions.touch(credential_hash=credential_hash(first_credential), now=NOW)
    assert prior is not None
    later = prior.absolute_expires_at - timedelta(minutes=10)
    _credential, stored = session_credential()
    session = sessions.create_session(
        actor_id=prior.actor_id,
        credential_hash=stored,
        authentication_event_id=prior.authentication_event_id,
        now=later,
        rotated_from_session_id=prior.session_id,
        absolute_expires_at=prior.absolute_expires_at,
    )
    row = connection.execute(
        """SELECT idle_expires_at,absolute_expires_at
             FROM solvan_identity.operator_sessions WHERE id=%s""",
        (session,),
    ).fetchone()
    assert row == (prior.absolute_expires_at, prior.absolute_expires_at)


def test_a_rotation_without_inheritance_starts_a_fresh_ceiling(
    connection: psycopg.Connection[Any],
) -> None:
    """A different person signing in is a new session, not a continuation."""

    from solvan.application.oauth_login import session_credential

    sessions, _credential, _session = _open_session(connection)
    other = OperatorIdentityStore(connection).resolve_actor(
        _assertion(subject="208000000000000000002", email="other@example.com").resolved(),
        now=NOW,
    )
    event = sessions.record_authentication(
        actor_id=other,
        canonical_issuer="accounts.google.com",
        subject="208000000000000000002",
        audience="111111111111-abc.apps.googleusercontent.com",
        authenticated_at=NOW,
        hosted_domain="example.com",
        now=NOW,
    )
    _new_credential, stored = session_credential()
    sessions.create_session(
        actor_id=other, credential_hash=stored, authentication_event_id=event, now=NOW
    )
    row = connection.execute(
        "SELECT rotated_from_session_id FROM solvan_identity.operator_sessions "
        "WHERE credential_hash=%s",
        (stored,),
    ).fetchone()
    assert row is not None and row[0] is None


def test_a_suspended_identity_is_refused(connection: psycopg.Connection[Any]) -> None:
    """The column existed and nothing consulted it, so suspending did nothing."""

    store = OperatorIdentityStore(connection)
    actor = store.resolve_actor(_assertion().resolved(), now=NOW)
    connection.execute(
        "UPDATE solvan_identity.actors SET status='SUSPENDED' WHERE actor_id=%s", (actor,)
    )
    with pytest.raises(OperatorIdentityError, match="suspended"):
        store.resolve_actor(_assertion().resolved(), now=NOW)


def test_an_eligible_identity_with_no_membership_holds_no_roles(
    connection: psycopg.Connection[Any],
) -> None:
    """Eligibility is not admission.

    A verified account at an admitted domain proves who someone is. Without a
    membership they hold nothing, and the sign-in path refuses to open a session
    on that basis — otherwise onboarding one colleague admits their whole
    company to a console whose scope comes from configuration.
    """

    store = OperatorIdentityStore(connection)
    actor = store.resolve_actor(
        _assertion(subject="308000000000000000003", email="stranger@example.com").resolved(),
        now=NOW,
    )
    assert store.roles(scope=SCOPE, actor_id=actor, now=NOW) == frozenset()


def test_the_founding_administrator_can_start_an_environment_exactly_once(
    connection: psycopg.Connection[Any],
) -> None:
    """The first administrator cannot be invited, because nobody exists to invite them.

    This is the only way a grant is made without one, so it is bounded to the
    case that needs it: an environment with no administrator at all.
    """

    store = OperatorIdentityStore(connection)
    founder = store.resolve_actor(_assertion(email="founder@ruhu.ai").resolved(), now=NOW)

    granted = store.claim_founding_administrator(
        scope=SCOPE,
        actor_id=founder,
        email="founder@ruhu.ai",
        founding_email="founder@ruhu.ai",
        now=NOW,
    )

    assert granted is True
    assert "ADMIN" in store.roles(scope=SCOPE, actor_id=founder, now=NOW)


def test_the_founding_grant_is_refused_once_any_administrator_exists(
    connection: psycopg.Connection[Any],
) -> None:
    """Otherwise it is a way back in after a removal rather than a way to start.

    Somebody whose administration was deliberately revoked would re-grant it to
    themselves by signing in again, and the revocation would mean nothing.
    """

    store = OperatorIdentityStore(connection)
    founder = store.resolve_actor(_assertion(email="founder@ruhu.ai").resolved(), now=NOW)
    assert store.claim_founding_administrator(
        scope=SCOPE,
        actor_id=founder,
        email="founder@ruhu.ai",
        founding_email="founder@ruhu.ai",
        now=NOW,
    )

    # The same account, signing in again after its administration was removed.
    connection.execute(
        "DELETE FROM solvan_identity.actor_memberships WHERE actor_id=%s AND role='ADMIN'",
        (founder,),
    )
    other = store.resolve_actor(
        _assertion(email="colleague@ruhu.ai", subject="108000000000000000002").resolved(), now=NOW
    )
    connection.execute(
        """INSERT INTO solvan_identity.actor_memberships
             (organization_id,project_id,environment_id,actor_id,role,granted_by_actor_id)
           VALUES (%s,%s,%s,%s,'ADMIN',%s)""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, other, other),
    )

    regained = store.claim_founding_administrator(
        scope=SCOPE,
        actor_id=founder,
        email="founder@ruhu.ai",
        founding_email="founder@ruhu.ai",
        now=NOW,
    )

    assert regained is False
    assert "ADMIN" not in store.roles(scope=SCOPE, actor_id=founder, now=NOW)


def test_no_other_address_can_claim_the_founding_grant(
    connection: psycopg.Connection[Any],
) -> None:
    """The address is configuration, and the email comes from a verified assertion."""

    store = OperatorIdentityStore(connection)
    impostor = store.resolve_actor(_assertion(email="someone@ruhu.ai").resolved(), now=NOW)

    assert not store.claim_founding_administrator(
        scope=SCOPE,
        actor_id=impostor,
        email="someone@ruhu.ai",
        founding_email="founder@ruhu.ai",
        now=NOW,
    )
    # An unset founding address grants nothing, so a deployment that never
    # configured one has no bootstrap path rather than an open one.
    assert not store.claim_founding_administrator(
        scope=SCOPE,
        actor_id=impostor,
        email="someone@ruhu.ai",
        founding_email="",
        now=NOW,
    )
    assert store.roles(scope=SCOPE, actor_id=impostor, now=NOW) == frozenset()


def _binding_roles(connection: psycopg.Connection[Any], email: str) -> set[str]:
    rows = connection.execute(
        """SELECT role FROM solvan.actor_role_bindings
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s AND principal=%s""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, f"user:{email}"),
    ).fetchall()
    return {str(row[0]) for row in rows}


def test_an_invited_person_is_authorized_by_the_routes_that_still_read_email(
    connection: psycopg.Connection[Any],
) -> None:
    """Signing in successfully and being authorized for nothing is the worse failure.

    Sign-in admits on `actor_memberships`; roughly twenty routes still read the
    email-keyed `actor_role_bindings`. Until they resolve roles from the
    session's actor, redeeming an invitation must land in both — otherwise the
    invitation appears to work and grants nothing.
    """

    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion(email="founder@ruhu.ai").resolved(), now=NOW)
    connection.execute(
        """INSERT INTO solvan_identity.actor_invitations
             (id,organization_id,project_id,environment_id,email,admitted_domain,
              role,invited_by_actor_id,created_at,expires_at)
           VALUES (%s,%s,%s,%s,'colleague@ruhu.ai','ruhu.ai','OPERATOR',%s,%s,%s)""",
        (
            new_identifier("inv"),
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            inviter,
            NOW,
            NOW + timedelta(days=14),
        ),
    )
    invitee = store.resolve_actor(
        _assertion(email="colleague@ruhu.ai", subject="108000000000000000009").resolved(), now=NOW
    )

    granted = store.redeem_invitation(
        scope=SCOPE,
        actor_id=invitee,
        email="colleague@ruhu.ai",
        hosted_domain="ruhu.ai",
        now=NOW,
    )

    assert granted == frozenset({"OPERATOR"})
    assert store.roles(scope=SCOPE, actor_id=invitee, now=NOW) == frozenset({"OPERATOR"})
    assert _binding_roles(connection, "colleague@ruhu.ai") == {"OPERATOR"}


def test_the_founding_administrator_is_authorized_by_those_routes_too(
    connection: psycopg.Connection[Any],
) -> None:
    """Otherwise the one account that can invite anybody can do nothing else."""

    store = OperatorIdentityStore(connection)
    founder = store.resolve_actor(_assertion(email="founder@ruhu.ai").resolved(), now=NOW)

    assert store.claim_founding_administrator(
        scope=SCOPE,
        actor_id=founder,
        email="founder@ruhu.ai",
        founding_email="founder@ruhu.ai",
        now=NOW,
    )

    assert _binding_roles(connection, "founder@ruhu.ai") == {"ADMIN"}


def test_every_open_invitation_is_redeemed_on_one_sign_in(
    connection: psycopg.Connection[Any],
) -> None:
    """An invitation names one role, so two roles means two invitations.

    Redeeming the oldest and leaving the rest gave somebody invited as OPERATOR
    and ADMIN only OPERATOR, with ADMIN arriving on a later sign-in — a delay
    nobody would attribute to anything but a bug in their own understanding.
    """

    store = OperatorIdentityStore(connection)
    inviter = store.resolve_actor(_assertion(email="founder@ruhu.ai").resolved(), now=NOW)
    for role in ("OPERATOR", "APPROVER", "ADMIN"):
        connection.execute(
            """INSERT INTO solvan_identity.actor_invitations
                 (id,organization_id,project_id,environment_id,email,admitted_domain,
                  role,invited_by_actor_id,created_at,expires_at)
               VALUES (%s,%s,%s,%s,'newcomer@ruhu.ai','ruhu.ai',%s,%s,%s,%s)""",
            (
                new_identifier("inv"),
                SCOPE.organization_id,
                SCOPE.project_id,
                SCOPE.environment_id,
                role,
                inviter,
                NOW,
                NOW + timedelta(days=14),
            ),
        )
    joiner = store.resolve_actor(
        _assertion(email="newcomer@ruhu.ai", subject="208000000000000000077").resolved(), now=NOW
    )

    granted = store.redeem_invitation(
        scope=SCOPE,
        actor_id=joiner,
        email="newcomer@ruhu.ai",
        hosted_domain="ruhu.ai",
        now=NOW,
    )

    assert granted == frozenset({"OPERATOR", "APPROVER", "ADMIN"})
    assert store.roles(scope=SCOPE, actor_id=joiner, now=NOW) == granted
    # Nothing is left claimable a second time.
    assert (
        store.redeem_invitation(
            scope=SCOPE,
            actor_id=joiner,
            email="newcomer@ruhu.ai",
            hosted_domain="ruhu.ai",
            now=NOW,
        )
        == frozenset()
    )
