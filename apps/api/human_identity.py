"""Verified Google human identity and fresh step-up session derivation."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token

from apps.api.code_change_decisions import VerifiedHumanSession
from solvan.application.approval_audience import (
    ApprovalAudienceError,
    accepted_audiences,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.platform.google_oauth import google_is_the_issuer


def approval_principal(human_identity_token: str | None) -> str:
    claims = verified_human_claims(human_identity_token)
    return f"user:{str(claims['email']).lower()}"


def verified_human_claims(human_identity_token: str | None) -> dict[str, Any]:
    cloud_deployment = os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"
    local_connected = os.environ.get("SOLVAN_LOCAL_CONNECTED_GCP") == "true"
    if not cloud_deployment and not local_connected:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "approval authority is disabled outside the Google Cloud deployment",
        )
    if human_identity_token is None or not human_identity_token.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing Google identity token")
    try:
        audiences = accepted_audiences(
            os.environ.get("SOLVAN_APPROVAL_AUDIENCE"),
            rotating_to=os.environ.get("SOLVAN_APPROVAL_AUDIENCE_SUCCESSOR"),
            google_issuer=google_is_the_issuer(),
        )
    except ApprovalAudienceError as error:
        # Refusing to serve is the only safe response: a deployment that cannot
        # name the client it trusts cannot tell a token minted for itself from
        # one minted for any other application.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
    claims = _verified_against_any(human_identity_token.removeprefix("Bearer "), audiences)
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str) or not email:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "verified Google email identity is required")
    return claims


def _verified_against_any(token: str, audiences: tuple[str, ...]) -> dict[str, Any]:
    """Verify the assertion against each accepted audience in turn.

    Each attempt is a complete verification. Verifying once with the audience
    check disabled and comparing `aud` afterwards would be cheaper and would
    leave a path where removing one line silently accepts every audience.
    """

    for audience in audiences:
        try:
            return id_token.verify_oauth2_token(  # type: ignore[no-untyped-call,no-any-return]
                token, GoogleRequest(), audience=audience
            )
        except (GoogleAuthError, ValueError):
            continue
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid Google identity token")


def fresh_approval_session(human_identity_token: str | None) -> VerifiedHumanSession:
    """Verify an interactive sign-in no more than five minutes old."""

    claims = verified_human_claims(human_identity_token)
    email = str(claims["email"]).lower()
    subject = claims.get("sub")
    authenticated_at_value = claims.get("auth_time")
    if not isinstance(subject, str) or not subject or type(authenticated_at_value) is not int:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "fresh step-up authentication is required",
        )
    authenticated_at = datetime.fromtimestamp(authenticated_at_value, tz=UTC)
    now = datetime.now(UTC)
    if authenticated_at > now or now - authenticated_at > timedelta(minutes=5):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "fresh step-up authentication is required",
        )
    principal = f"user:{email}"
    return VerifiedHumanSession(
        principal=principal,
        session_hash=canonical_sha256(
            {
                "schema_version": 1,
                "principal": principal,
                "subject": subject,
                "authenticated_at": authenticated_at.isoformat(),
                "audience": claims.get("aud"),
                "issuer": claims.get("iss"),
            }
        ),
        authenticated_at=authenticated_at,
    )
