"""Loopback-only detector with per-start local service authentication."""

from __future__ import annotations

from fastapi import HTTPException, status

from apps.detector.main import create_app
from solvan.platform.local_service_token import local_bearer_matches


def _authorize(authorization: str | None) -> None:
    try:
        valid = local_bearer_matches(authorization)
    except RuntimeError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid local scheduler identity")


app = create_app(local_authorize=_authorize)
