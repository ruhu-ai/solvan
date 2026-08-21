"""Bounded Secret Manager access returning bytes without logging material."""

from __future__ import annotations

import base64
import re
from typing import Protocol


class RestResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> object: ...


class RestSession(Protocol):
    def get(self, url: str, *, timeout: int) -> RestResponse: ...


_RESOURCE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/secrets/[A-Za-z0-9_-]{1,255}/versions/"
    r"(?:[1-9][0-9]*|latest)$"
)


class SecretManagerReader:
    def __init__(self, session: RestSession) -> None:
        self._session = session

    def access(self, resource: str, *, max_bytes: int = 16_384) -> bytes:
        if not _RESOURCE.fullmatch(resource):
            raise ValueError("Secret Manager resource name is invalid")
        if not 1 <= max_bytes <= 65_536:
            raise ValueError("secret byte ceiling is invalid")
        response = self._session.get(
            f"https://secretmanager.googleapis.com/v1/{resource}:access", timeout=10
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("payload"), dict):
            raise RuntimeError("Secret Manager returned no payload")
        encoded = body["payload"].get("data")
        if not isinstance(encoded, str):
            raise RuntimeError("Secret Manager returned no secret bytes")
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise RuntimeError("Secret Manager payload is not valid base64") from error
        if not value or len(value) > max_bytes:
            raise RuntimeError("Secret Manager payload is empty or exceeds its byte ceiling")
        return value
