"""In-process verification of a caller's Google-signed identity token.

Cloud Run IAM authenticates the caller at the service boundary. That is a
network-position control, and the engineering invariants forbid a platform
feature being the *sole* control protecting a consequential action: anything
that reaches the service directly — an SSRF, a compromised same-project
workload, one ingress misconfiguration — would otherwise face no application
identity check at all.

These services previously accepted any string beginning ``Bearer `` and then
read the caller's principal from their own environment, which is a constant
about themselves rather than a claim about the caller. This module verifies the
token's signature, issuer, expiry and audience, and returns the verified
subject.

Absent configuration refuses. An unset audience is a missing control, never a
reason to skip the check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol


class ServiceIdentityError(Exception):
    """The caller's identity could not be established from verified claims."""


@dataclass(frozen=True, slots=True)
class VerifiedCaller:
    """The verified claims of one calling workload."""

    subject: str
    email: str | None
    audience: str
    issuer: str


class TokenVerifier(Protocol):
    """Verifies a Google-signed ID token and returns its claims."""

    def __call__(self, token: str, *, audience: str) -> dict[str, Any]: ...


def _google_verifier(token: str, *, audience: str) -> dict[str, Any]:
    from google.auth.exceptions import GoogleAuthError
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2 import id_token

    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            token, GoogleRequest(), audience=audience
        )
    except (GoogleAuthError, ValueError) as error:
        raise ServiceIdentityError("invalid caller identity token") from error
    return dict(claims)


_ACCEPTED_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})


def verify_service_caller(
    authorization: str | None,
    *,
    audience_variable: str,
    verifier: TokenVerifier | None = None,
) -> VerifiedCaller:
    """Establish the caller from verified cryptographic claims, or refuse.

    `audience_variable` names the environment variable holding this service's
    exact expected audience. It is required: without it the token could have
    been minted for any other service and replayed here.
    """

    if authorization is None or not authorization.startswith("Bearer "):
        raise ServiceIdentityError("missing bearer identity token")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise ServiceIdentityError("missing bearer identity token")
    audience = os.environ.get(audience_variable)
    if not audience:
        raise ServiceIdentityError(f"{audience_variable} is not configured")

    claims = (verifier or _google_verifier)(token, audience=audience)

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ServiceIdentityError("identity token carries no subject")
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or issuer not in _ACCEPTED_ISSUERS:
        raise ServiceIdentityError("identity token issuer is not accepted")
    presented = claims.get("aud")
    if presented != audience:
        raise ServiceIdentityError("identity token audience does not match this service")
    email = claims.get("email")
    return VerifiedCaller(
        subject=subject,
        email=email if isinstance(email, str) and email else None,
        audience=audience,
        issuer=issuer,
    )


def require_agent_principal(caller: VerifiedCaller, *, admitted: frozenset[str]) -> str:
    """Refuse unless the verified caller *is* one of the admitted principals.

    Verifying a token and then discarding who it belongs to is how a private
    route ends up admitting any workload that can mint a token for its
    audience. Google attests one Agent Identity in two spellings — the
    SPIFFE URI alone and the same URI with the `principal://` scheme — so
    both forms of each admitted principal are accepted, and nothing else is.
    """

    candidates = set(admitted)
    candidates.update(principal.removeprefix("principal://") for principal in admitted)
    if caller.subject in candidates:
        return caller.subject
    if caller.email is not None and caller.email in candidates:
        return caller.email
    raise ServiceIdentityError("caller is not an admitted agent identity")
