"""Audience-bound identity tokens for private Agent tool destinations.

Tool wrappers never forward a model-provided credential.  The runtime mints a
short-lived Google ID token for the exact configured service audience; an unset
or non-HTTPS audience refuses before a request can leave the Agent process.
"""

from __future__ import annotations

import os

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token


def private_service_headers(*, audience_variable: str) -> dict[str, str]:
    """Return one verified-service Authorization header or refuse closed."""

    audience = os.environ.get(audience_variable)
    if not audience or not audience.startswith("https://"):
        raise RuntimeError(f"{audience_variable} must name an HTTPS service audience")
    try:
        token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
            GoogleRequest(), audience
        )
    except Exception as error:
        raise RuntimeError("could not mint private-service identity token") from error
    if not token:
        raise RuntimeError("could not mint private-service identity token")
    return {"Authorization": f"Bearer {token}"}
