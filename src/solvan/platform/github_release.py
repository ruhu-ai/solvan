"""Coordinator client for the private GitHub release-provider service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token


class IdentityTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


class GoogleIdentityTokenProvider:
    def token(self, *, audience: str) -> str:
        return cast(
            str,
            id_token.fetch_id_token(  # type: ignore[no-untyped-call]
                GoogleAuthRequest(), audience
            ),
        )


@dataclass(frozen=True, slots=True)
class GitHubReleaseProviderConfiguration:
    base_url: str
    audience: str
    repository_id: str

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError("GitHub provider URL must be one HTTPS origin")
        if not self.audience.startswith("https://"):
            raise ValueError("GitHub provider audience must be HTTPS")
        if not self.repository_id.startswith("ghr_"):
            raise ValueError("GitHub provider repository binding is invalid")


class GitHubReleaseProviderClient:
    """Coordinator-only HTTP client; browser and agents never use this class."""

    def __init__(
        self,
        *,
        config: GitHubReleaseProviderConfiguration,
        client: httpx.Client,
        token_provider: IdentityTokenProvider,
    ) -> None:
        self._config = config
        self._client = client
        self._tokens = token_provider

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._tokens.token(audience=self._config.audience)}",
            "Content-Type": "application/json",
        }

    def probe_repository(self, repository_id: str | None = None) -> dict[str, Any]:
        """Ask the provider to observe one binding and record what it saw.

        Naming the binding is what lets a newly connected repository reach
        ACTIVE. Without it the provider probed only the repository this
        deployment was configured with, so every other binding stayed PENDING
        and the schema correctly refused to promote it.
        """

        suffix = f"?repository_id={repository_id}" if repository_id else ""
        return self._post(f"/internal/github/repositories:probe{suffix}", {"schema_version": 1})

    def execute_private_command(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/internal/v1/commands:execute", payload)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(
            f"{self._config.base_url}{path}", headers=self._headers(), json=payload, timeout=60
        )
        if response.status_code >= 400:
            raise RuntimeError(f"GitHub release provider returned HTTP {response.status_code}")
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError("GitHub release provider returned a non-object response")
        return value
