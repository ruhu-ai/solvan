"""Authenticated private client for the independent Release Verifier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class IdentityTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


@dataclass(frozen=True, slots=True)
class ReleaseVerifierConfiguration:
    base_url: str
    audience: str
    service_principal: str

    def __post_init__(self) -> None:
        if (
            not self.base_url.startswith("https://")
            or self.base_url.endswith("/")
            or not self.audience.startswith("https://")
            or not self.service_principal.startswith("serviceAccount:")
        ):
            raise ValueError("Release Verifier endpoint must be one HTTPS origin")


class ReleaseVerifierClient:
    def __init__(
        self,
        *,
        config: ReleaseVerifierConfiguration,
        client: httpx.Client,
        token_provider: IdentityTokenProvider,
    ) -> None:
        self._config = config
        self._client = client
        self._tokens = token_provider

    def execute_private_command(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(
            f"{self._config.base_url}/internal/v1/commands:execute",
            headers={
                "Authorization": f"Bearer {self._tokens.token(audience=self._config.audience)}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=60,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Release Verifier returned HTTP {response.status_code}")
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError("Release Verifier returned a non-object response")
        return value
