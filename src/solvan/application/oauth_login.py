"""The authorization-code flow Solvan runs, reduced to rules (spec 05 §4.2).

The browser never holds an authorization code, a token, or the values that
protect the flow. It holds one opaque reference; everything it protects lives
server-side. This module builds the request and checks what comes back. It
performs no I/O, so every rule below is testable without a network or a browser.

`state` and `nonce` are different values doing different jobs and are never one
field. `state` proves the callback belongs to a flow this deployment started.
`nonce` is carried inside the identity token and proves the token was minted for
that same flow, which `state` cannot show because `state` never enters the
token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlencode

GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

#: Identity only. No offline access, no refresh token, and no Google API scope,
#: so a stolen session cannot be exchanged for access to the person's mail,
#: drive, or calendar. Widening this is a change to what a compromise costs.
SCOPES = ("openid", "email", "profile")


class OAuthLoginError(RuntimeError):
    """A login or callback cannot be trusted."""


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _challenge(verifier: str) -> str:
    raw = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class LoginStart:
    """What to store and where to send the browser."""

    authorization_url: str
    state: str
    state_hash: str
    nonce: str
    nonce_hash: str
    pkce_verifier: str
    pkce_verifier_hash: str
    expires_at: datetime


def begin_login(
    *,
    client_id: str,
    redirect_uri: str,
    return_path: str,
    now: datetime,
    lifetime: timedelta | None = None,
    hosted_domain_hint: str | None = None,
    authorization_endpoint: str = GOOGLE_AUTHORIZATION_ENDPOINT,
    state: str | None = None,
    nonce: str | None = None,
    pkce_verifier: str | None = None,
) -> LoginStart:
    """Build one authorization request.

    PKCE is used even though the backend client is confidential. Current OAuth
    guidance recommends it for web clients too: it binds the redemption of a
    code to the process that requested it, so an intercepted code is not enough.

    This starts sign-in only. Consequential-action presence is deliberately not
    multiplexed onto OAuth because Google cannot be asked to reauthenticate an
    account; specification 05 §4.2 defines the separate step-up proof.
    """

    if not return_path.startswith("/") or return_path.startswith("//"):
        # An absolute or protocol-relative target turns the sign-in into an open
        # redirect that borrows this deployment's name.
        raise OAuthLoginError("a return path must be relative to this deployment")
    resolved_lifetime = lifetime or timedelta(minutes=10)
    resolved_state = state or secrets.token_urlsafe(32)
    resolved_nonce = nonce or secrets.token_urlsafe(32)
    resolved_verifier = pkce_verifier or secrets.token_urlsafe(64)
    parameters = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": resolved_state,
        "nonce": resolved_nonce,
        "code_challenge": _challenge(resolved_verifier),
        "code_challenge_method": "S256",
        # Online only: an offline grant would mint a refresh token Solvan has no
        # use for and would then have to protect for as long as it lived.
        "access_type": "online",
    }
    if hosted_domain_hint:
        # A hint to the account chooser, never evidence. The returned `hd` claim
        # is what the callback checks.
        parameters["hd"] = hosted_domain_hint
    return LoginStart(
        authorization_url=f"{authorization_endpoint}?{urlencode(parameters)}",
        state=resolved_state,
        state_hash=_digest(resolved_state),
        nonce=resolved_nonce,
        nonce_hash=_digest(resolved_nonce),
        pkce_verifier=resolved_verifier,
        pkce_verifier_hash=_digest(resolved_verifier),
        expires_at=now + resolved_lifetime,
    )


@dataclass(frozen=True, slots=True)
class PendingLogin:
    """The stored half of a flow, as the callback reads it back."""

    state_hash: str
    nonce_hash: str
    #: The value itself, because it is replayed to the token endpoint when the
    #: authorization code is redeemed. A digest cannot complete that exchange.
    pkce_verifier: str
    audience: str
    return_path: str
    expires_at: datetime
    consumed_at: datetime | None


def verify_callback(
    *,
    returned_state: str,
    pending: PendingLogin | None,
    now: datetime,
) -> None:
    """Accept a callback only from a flow this deployment started and still holds.

    Comparison is constant-time. A timing-visible comparison of a value an
    attacker supplies is a way to learn the value one byte at a time.
    """

    if pending is None:
        raise OAuthLoginError("no pending sign-in matches this callback")
    if pending.consumed_at is not None:
        raise OAuthLoginError("this sign-in was already completed")
    if now >= pending.expires_at:
        raise OAuthLoginError("this sign-in expired before it completed")
    if not hmac.compare_digest(_digest(returned_state), pending.state_hash):
        raise OAuthLoginError("the callback does not belong to this sign-in")


def verify_nonce(*, claimed_nonce: object, pending: PendingLogin) -> None:
    """The identity token must carry the nonce this flow asked for.

    Without it a token minted for a different flow — including one an attacker
    started — would satisfy every other check.
    """

    if not isinstance(claimed_nonce, str) or not claimed_nonce:
        raise OAuthLoginError("the identity token carries no nonce")
    if not hmac.compare_digest(_digest(claimed_nonce), pending.nonce_hash):
        raise OAuthLoginError("the identity token was minted for another sign-in")


def session_credential() -> tuple[str, str]:
    """A session credential and the hash stored in its place."""

    credential = secrets.token_urlsafe(48)
    return credential, _digest(credential)


def credential_hash(credential: str) -> str:
    return _digest(credential)
