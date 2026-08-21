"""The authorization request Solvan builds, and what it accepts back.

Governing record: specification 05 §4.2 (sign-in, session).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest

from solvan.application.oauth_login import (
    GOOGLE_AUTHORIZATION_ENDPOINT,
    OAuthLoginError,
    PendingLogin,
    begin_login,
    credential_hash,
    session_credential,
    verify_callback,
    verify_nonce,
)

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
CLIENT = "111111111111-abc123.apps.googleusercontent.com"


def _start(**overrides: object):  # type: ignore[no-untyped-def]
    arguments: dict[str, object] = {
        "client_id": CLIENT,
        "redirect_uri": "https://console.example/api/auth/callback",
        "return_path": "/incidents",
        "now": NOW,
    }
    arguments.update(overrides)
    return begin_login(**arguments)  # type: ignore[arg-type]


def _parameters(url: str) -> dict[str, str]:
    return {key: value[0] for key, value in parse_qs(urlparse(url).query).items()}


def test_the_request_asks_only_for_identity() -> None:
    """No offline access and no Google API scope.

    A session stolen from Solvan then cannot be exchanged for the person's mail,
    drive, or calendar; widening this changes what a compromise costs.
    """

    parameters = _parameters(_start().authorization_url)
    assert parameters["scope"] == "openid email profile"
    assert parameters["access_type"] == "online"
    assert "offline" not in parameters.values()


def test_the_request_goes_to_google_with_pkce() -> None:
    start = _start()
    assert start.authorization_url.startswith(GOOGLE_AUTHORIZATION_ENDPOINT)
    parameters = _parameters(start.authorization_url)
    assert parameters["code_challenge_method"] == "S256"
    assert parameters["code_challenge"] != start.pkce_verifier
    assert "=" not in parameters["code_challenge"]


def test_state_and_nonce_are_different_values() -> None:
    """They do different jobs, and one field cannot do both.

    `state` proves the callback belongs to a flow we started; `nonce` proves the
    identity token was minted for that same flow, which `state` cannot show
    because it never enters the token.
    """

    start = _start()
    parameters = _parameters(start.authorization_url)
    assert parameters["state"] != parameters["nonce"]
    assert start.state_hash != start.nonce_hash


def test_only_hashes_are_offered_for_storage() -> None:
    start = _start()
    assert start.state_hash == credential_hash(start.state)
    assert start.state_hash.startswith("sha256:")
    assert start.pkce_verifier_hash == credential_hash(start.pkce_verifier)


def test_sign_in_does_not_pretend_to_be_step_up() -> None:
    parameters = _parameters(_start().authorization_url)
    assert "prompt" not in parameters
    assert "max_age" not in parameters


def test_a_hosted_domain_is_only_a_hint() -> None:
    """Google states `hd` here influences account selection, not the result."""

    parameters = _parameters(_start(hosted_domain_hint="example.com").authorization_url)
    assert parameters["hd"] == "example.com"


@pytest.mark.parametrize(
    "target", ["https://elsewhere.example/steal", "//elsewhere.example", "http://x"]
)
def test_an_absolute_return_target_is_refused(target: str) -> None:
    """Otherwise sign-in becomes an open redirect wearing this deployment's name."""

    with pytest.raises(OAuthLoginError, match="relative"):
        _start(return_path=target)


def _pending(start, **overrides: object) -> PendingLogin:  # type: ignore[no-untyped-def]
    arguments: dict[str, object] = {
        "state_hash": start.state_hash,
        "nonce_hash": start.nonce_hash,
        "pkce_verifier": start.pkce_verifier,
        "audience": CLIENT,
        "return_path": "/incidents",
        "expires_at": start.expires_at,
        "consumed_at": None,
    }
    arguments.update(overrides)
    return PendingLogin(**arguments)  # type: ignore[arg-type]


def test_a_matching_callback_is_accepted() -> None:
    start = _start()
    verify_callback(returned_state=start.state, pending=_pending(start), now=NOW)


def test_a_callback_with_no_pending_sign_in_is_refused() -> None:
    with pytest.raises(OAuthLoginError, match="no pending sign-in"):
        verify_callback(returned_state="anything", pending=None, now=NOW)


def test_a_foreign_state_is_refused() -> None:
    start = _start()
    with pytest.raises(OAuthLoginError, match="does not belong"):
        verify_callback(returned_state="attacker-state", pending=_pending(start), now=NOW)


def test_a_completed_sign_in_cannot_be_completed_twice() -> None:
    start = _start()
    with pytest.raises(OAuthLoginError, match="already completed"):
        verify_callback(
            returned_state=start.state, pending=_pending(start, consumed_at=NOW), now=NOW
        )


def test_an_expired_sign_in_is_refused() -> None:
    start = _start()
    with pytest.raises(OAuthLoginError, match="expired"):
        verify_callback(
            returned_state=start.state,
            pending=_pending(start),
            now=start.expires_at + timedelta(seconds=1),
        )


def test_the_identity_token_must_carry_this_flows_nonce() -> None:
    start = _start()
    verify_nonce(claimed_nonce=start.nonce, pending=_pending(start))
    with pytest.raises(OAuthLoginError, match="another sign-in"):
        verify_nonce(claimed_nonce="someone-elses-nonce", pending=_pending(start))


@pytest.mark.parametrize("value", [None, "", 12345])
def test_a_token_without_a_nonce_is_refused(value: object) -> None:
    start = _start()
    with pytest.raises(OAuthLoginError, match="no nonce"):
        verify_nonce(claimed_nonce=value, pending=_pending(start))


def test_a_session_credential_is_stored_only_as_a_hash() -> None:
    credential, stored = session_credential()
    assert stored == credential_hash(credential)
    assert credential not in stored
    assert len(credential) >= 40
