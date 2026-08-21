"""Strict deployed-path qualification receipts for conversational providers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.domain import Scope

_REQUIRED_AVAILABLE_RESULTS = (
    "authenticated_ingress_accepted",
    "forged_ingress_denied",
    "provider_identity_bound",
    "reader_filtered_delivery_succeeded",
    "duplicate_delivery_suppressed",
    "revocation_fenced",
    "pii_redaction_verified",
)


class ChannelProviderQualificationReceipt(BaseModel):
    """An immutable, externally produced result bound to one deployed path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    kind: Literal["SOLVAN_CHANNEL_PROVIDER_QUALIFICATION"]
    project_id: str = Field(min_length=1, max_length=128)
    release_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    deployment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    service_revision: str = Field(min_length=1, max_length=128)
    organization_id: str = Field(min_length=1, max_length=64)
    scope_project_id: str = Field(min_length=1, max_length=64)
    environment_id: str = Field(min_length=1, max_length=64)
    channel_kind: Literal["SLACK", "DISCORD", "EMAIL"]
    status: Literal["AVAILABLE", "NEEDS_ATTENTION", "DISABLED"]
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,79}$")
    next_step_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,79}$")
    checked_at: datetime
    validity_seconds: int = Field(ge=60, le=86_400)
    results: dict[str, bool]
    content_capture: Literal["NO_PROVIDER_CONTENT_RECORDED"]

    @model_validator(mode="after")
    def validate_results(self) -> ChannelProviderQualificationReceipt:
        if set(self.results) != set(_REQUIRED_AVAILABLE_RESULTS):
            raise ValueError("qualification receipt has an unknown result set")
        if self.status == "AVAILABLE" and not all(self.results.values()):
            raise ValueError("AVAILABLE requires every deployed-path result to pass")
        if self.checked_at.tzinfo is None:
            raise ValueError("checked_at must be timezone-aware")
        return self

    @property
    def scope(self) -> Scope:
        return Scope(self.organization_id, self.scope_project_id, self.environment_id)

    def assert_current(
        self,
        *,
        expected_project_id: str,
        expected_release_commit: str,
        expected_deployment_id: str,
        expected_channel_kind: str,
        expected_scope: Scope,
        now: datetime | None = None,
    ) -> None:
        checked_now = now or datetime.now(UTC)
        if checked_now.tzinfo is None:
            raise ValueError("qualification comparison time must be timezone-aware")
        if self.project_id != expected_project_id:
            raise ValueError("qualification receipt belongs to another GCP project")
        if self.release_commit != expected_release_commit:
            raise ValueError("qualification receipt belongs to another release")
        if self.deployment_id != expected_deployment_id:
            raise ValueError("qualification receipt belongs to another deployment")
        if self.channel_kind != expected_channel_kind:
            raise ValueError("qualification receipt belongs to another provider")
        if self.scope != expected_scope:
            raise ValueError("qualification receipt belongs to another tenant scope")
        checked_at = self.checked_at.astimezone(UTC)
        if checked_at > checked_now + timedelta(minutes=5):
            raise ValueError("qualification receipt is dated in the future")
        if checked_at + timedelta(seconds=self.validity_seconds) <= checked_now:
            raise ValueError("qualification receipt is already expired")


def parse_channel_provider_qualification(
    raw: bytes, *, expected_hash: str
) -> tuple[ChannelProviderQualificationReceipt, str]:
    """Parse exact JSON bytes and bind them to the approved object digest."""

    actual_hash = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if actual_hash != expected_hash:
        raise ValueError("qualification receipt hash does not match the approved input")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("qualification receipt is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("qualification receipt must be one JSON object")
    return ChannelProviderQualificationReceipt.model_validate(payload), actual_hash
