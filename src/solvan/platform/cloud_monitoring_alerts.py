"""Verified OIDC boundary for Cloud Monitoring Pub/Sub push."""

from __future__ import annotations

from typing import Any, Protocol

from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token

from solvan.application.alert_triage import (
    AlertIngressError,
    CloudMonitoringSourceBinding,
    VerifiedPushIdentity,
)


class PushIdentityVerifier(Protocol):
    def verify(
        self, *, authorization: str | None, binding: CloudMonitoringSourceBinding
    ) -> VerifiedPushIdentity: ...


class GooglePubSubPushIdentityVerifier:
    """Verify Google-signed push identity against one stored source binding."""

    def verify(
        self, *, authorization: str | None, binding: CloudMonitoringSourceBinding
    ) -> VerifiedPushIdentity:
        if authorization is None or not authorization.startswith("Bearer "):
            raise AlertIngressError("PUSH_IDENTITY_MISSING")
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise AlertIngressError("PUSH_IDENTITY_MISSING")
        try:
            claims: dict[str, Any] = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
                token, GoogleRequest(), audience=binding.oidc_audience
            )
        except (GoogleAuthError, ValueError) as error:
            raise AlertIngressError("PUSH_IDENTITY_INVALID") from error
        issuer = claims.get("iss")
        subject = claims.get("sub")
        email = claims.get("email")
        audience = claims.get("aud")
        if (
            issuer not in {"accounts.google.com", "https://accounts.google.com"}
            or not isinstance(subject, str)
            or not subject
            or not isinstance(email, str)
            or not email
            or claims.get("email_verified") is not True
            or audience != binding.oidc_audience
            or email.lower() != binding.push_principal.lower()
        ):
            raise AlertIngressError("PUSH_IDENTITY_INVALID")
        return VerifiedPushIdentity(
            issuer=issuer,
            subject=subject,
            email=email.lower(),
            audience=audience,
        )
