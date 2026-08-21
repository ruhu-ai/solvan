"""What a challenge authorizes, and what it refuses (specification 05 §4.2).

A challenge authorizes one decision: one actor, one session, one operation, one
material, once. Every binding is rechecked at consumption rather than trusted
from issuance.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.action_challenge import (
    CHALLENGE_OPERATIONS,
    ActionChallengeError,
    ChallengeState,
    IssuedChallenge,
    authorize_consumption,
    operation,
)

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "b" * 64
CSRF = "sha256:" + "c" * 64


def _challenge(**overrides: object) -> IssuedChallenge:
    base: dict[str, object] = {
        "challenge_id": "chl_1",
        "actor_id": "act_1",
        "session_id": "ses_1",
        "operation": "estate.connect",
        "material_digest": DIGEST,
        "csrf_token_hash": CSRF,
        "expires_at": NOW + timedelta(minutes=5),
        "status": ChallengeState.ISSUED,
    }
    base.update(overrides)
    return IssuedChallenge(**base)  # type: ignore[arg-type]


def _consume(**overrides: object):  # type: ignore[no-untyped-def]
    arguments: dict[str, object] = {
        "challenge": _challenge(),
        "actor_id": "act_1",
        "session_id": "ses_1",
        "operation_key": "estate.connect",
        "material_digest": DIGEST,
        "csrf_token_hash": CSRF,
        "current_roles": frozenset({"ADMIN"}),
        "now": NOW,
    }
    arguments.update(overrides)
    return authorize_consumption(**arguments)  # type: ignore[arg-type]


def test_a_matching_challenge_authorizes_its_operation() -> None:
    assert _consume().key == "estate.connect"


def test_an_unregistered_operation_cannot_be_authorized() -> None:
    """Registering is how an operation becomes describable, and testable."""

    with pytest.raises(ActionChallengeError, match="not a registered"):
        operation("something.invented")


def test_every_registered_operation_names_a_role() -> None:
    assert CHALLENGE_OPERATIONS
    for registered in CHALLENGE_OPERATIONS.values():
        assert registered.required_role in {"OPERATOR", "APPROVER", "ADMIN"}
        assert registered.summary


def test_a_used_challenge_cannot_be_used_again() -> None:
    with pytest.raises(ActionChallengeError, match="already been used"):
        _consume(challenge=_challenge(status=ChallengeState.CONSUMED))


def test_an_expired_challenge_is_refused() -> None:
    with pytest.raises(ActionChallengeError, match="expired"):
        _consume(now=NOW + timedelta(minutes=6))


def test_a_challenge_does_not_travel_between_actors() -> None:
    with pytest.raises(ActionChallengeError, match="another actor"):
        _consume(actor_id="act_2")


def test_a_challenge_does_not_survive_a_session_rotation() -> None:
    """Rebinding would let a challenge outlive the session it was granted in."""

    with pytest.raises(ActionChallengeError, match="another session"):
        _consume(session_id="ses_2")


def test_a_challenge_authorizes_one_operation() -> None:
    with pytest.raises(ActionChallengeError, match="different operation"):
        _consume(operation_key="relay.disable")


def test_changed_material_is_refused() -> None:
    """It authorizes what was shown, not what is being submitted."""

    with pytest.raises(ActionChallengeError, match="material changed"):
        _consume(material_digest="sha256:" + "d" * 64)


def test_a_mismatched_csrf_token_is_refused() -> None:
    with pytest.raises(ActionChallengeError, match="cross-site"):
        _consume(csrf_token_hash="sha256:" + "e" * 64)


def test_a_role_removed_after_issuance_stops_the_action() -> None:
    """The reason roles are never carried in the challenge.

    Issuance proved authority at a moment. Consumption is when it is used, and
    an offboarded operator must not spend a challenge granted before they left.
    """

    with pytest.raises(ActionChallengeError, match="ADMIN is required"):
        _consume(current_roles=frozenset({"OPERATOR"}))


def test_holding_a_lesser_role_does_not_authorize_a_greater_operation() -> None:
    with pytest.raises(ActionChallengeError, match="APPROVER is required"):
        _consume(
            challenge=_challenge(operation="action.approve"),
            operation_key="action.approve",
            current_roles=frozenset({"OPERATOR", "ADMIN"}),
        )
