"""Closed contracts for linking a Solvan principal to a GitHub reviewer identity."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

from solvan.application.workspace_hashing import canonical_sha256


class GitHubIdentityError(RuntimeError):
    """A reviewer link cannot be established without weakening its contract."""


@dataclass(frozen=True, slots=True)
class OAuthClientProfile:
    id: str
    client_id: str
    client_secret_ref: str
    authorization_endpoint: str
    token_endpoint: str
    api_base_url: str
    callback_uri: str
    protocol_version: str
    configuration_hash: str


@dataclass(frozen=True, slots=True)
class LinkChallenge:
    state: str
    state_hash: str
    verifier: str
    challenge: str


def new_link_challenge() -> LinkChallenge:
    """Generate independent 256-bit state and RFC 7636 verifier material."""

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return LinkChallenge(
        state=state,
        state_hash=f"sha256:{hashlib.sha256(state.encode()).hexdigest()}",
        verifier=verifier,
        challenge=challenge.decode("ascii"),
    )


def authorization_url(*, profile: OAuthClientProfile, challenge: LinkChallenge) -> str:
    if not profile.authorization_endpoint.startswith("https://"):
        raise GitHubIdentityError("GITHUB_OAUTH_AUTHORIZATION_ENDPOINT_INVALID")
    query = urlencode(
        {
            "client_id": profile.client_id,
            "redirect_uri": profile.callback_uri,
            "state": challenge.state,
            "code_challenge": challenge.challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{profile.authorization_endpoint}?{query}"


def session_binding_hash(*, principal: str, subject: str, issued_at: int) -> str:
    return canonical_sha256(
        {"schema_version": 1, "principal": principal, "subject": subject, "issued_at": issued_at}
    )


def requested_permission_hash(*, repository_binding_id: str, reviewer_policy_hash: str) -> str:
    return canonical_sha256(
        {
            "schema_version": 1,
            "repository_binding_id": repository_binding_id,
            "role": "CODE_CHANGE_APPROVER",
            "reviewer_policy_hash": reviewer_policy_hash,
        }
    )
