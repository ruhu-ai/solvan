"""Strict private provider preflight request and receipt contracts."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ProviderPreflightRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{16,128}$")
    expected_sdk_distribution_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_network_policy_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ProviderPreflightReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    nonce: str
    provider_revision: str
    provider_service_revision: str
    provider_boot_hash: str
    sdk_version: str
    sdk_distribution_hash: str
    enabled_builtin_tools: tuple[str, ...]
    enabled_custom_tools: tuple[str, ...]
    observations: dict[str, bool]
