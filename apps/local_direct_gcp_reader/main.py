"""Unix-socket-only Direct GCP Reader for local-connected development.

This entry point is deliberately separate from the Cloud Run reader. It keeps
the credential-bearing reader out of the API process while avoiding a network
listener and never adds a permissive mode to the deployed identity boundary.
"""

from __future__ import annotations

import os

from fastapi import HTTPException, status

from apps.direct_gcp_reader.main import create_app
from solvan.platform.google_rest import GoogleRestSession, authorized_session_from_credentials
from solvan.platform.local_gcp_credentials import development_credentials
from solvan.platform.local_service_token import local_bearer_matches


def _authorize_local(authorization: str | None) -> None:
    try:
        valid = local_bearer_matches(authorization)
    except RuntimeError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid local reader identity token")


def _development_session(
    *,
    delegator_principal: str | None = None,
    target_principal: str | None = None,
    lifetime_seconds: int | None = None,
) -> GoogleRestSession:
    service_account = os.environ.get("SOLVAN_READER_SERVICE_ACCOUNT")
    if not service_account:
        raise RuntimeError("SOLVAN_READER_SERVICE_ACCOUNT is required")
    credentials = development_credentials(service_account=service_account)
    return authorized_session_from_credentials(
        credentials,
        delegator_principal=delegator_principal,
        target_principal=target_principal,
        lifetime_seconds=lifetime_seconds,
    )


app = create_app(
    authorize=_authorize_local,
    session_factory=_development_session,
    service_name="solvan-local-direct-gcp-reader",
)
