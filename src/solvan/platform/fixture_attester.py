"""Coordinator client for the private synthetic fixture-attester service."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from solvan.application import SyntheticAttestationReceipt, SyntheticAttestationRequest
from solvan.platform.antigravity_workspace import IdentityTokenProvider


class FixtureAttesterError(RuntimeError):
    """The isolated fixture attester rejected or failed the exact request."""


@dataclass(frozen=True, slots=True)
class FixtureAttesterConfiguration:
    base_url: str
    audience: str

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError("fixture-attester URL must be one HTTPS origin")
        if not self.audience.startswith("https://"):
            raise ValueError("fixture-attester audience must be HTTPS")


class FixtureAttesterClient:
    def __init__(
        self,
        *,
        config: FixtureAttesterConfiguration,
        client: httpx.Client,
        token_provider: IdentityTokenProvider,
    ) -> None:
        self._config = config
        self._client = client
        self._token_provider = token_provider

    def attest(self, request: SyntheticAttestationRequest) -> SyntheticAttestationReceipt:
        token = self._token_provider.token(audience=self._config.audience)
        try:
            response = self._client.post(
                f"{self._config.base_url}/internal/v1/synthetic-attestations",
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=60,
            )
            response.raise_for_status()
            return SyntheticAttestationReceipt.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as error:
            raise FixtureAttesterError("synthetic fixture attestation failed") from error
