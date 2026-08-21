"""Single-purpose tool for an Agent Identity-bound Verification Agent."""

from __future__ import annotations

import os
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from solvan.agents.private_service_auth import private_service_headers


class VerificationToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verification_id: str = Field(pattern=r"^ver_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    verdict: Literal["VERIFIED", "FAILED", "INCONCLUSIVE"]
    rationale_codes: tuple[str, ...]


def run_bound_verification(
    invocation_id: str,
    action_id: str,
    organization_id: str,
    project_id: str,
    environment_id: str,
) -> dict[str, object]:
    """Run the exact policy-bound verification; callers cannot pass a profile."""

    base_url = os.environ.get("SOLVAN_VERIFIER_URL")
    if not base_url:
        raise RuntimeError("SOLVAN_VERIFIER_URL is required")
    if not base_url.startswith("https://") and os.environ.get("SOLVAN_ENVIRONMENT") != "local":
        raise RuntimeError("the verifier must use HTTPS outside the local harness")
    response = httpx.post(
        f"{base_url.rstrip('/')}/internal/v1/verifications:run",
        headers=private_service_headers(audience_variable="SOLVAN_VERIFIER_AUDIENCE"),
        json={
            "schema_version": 1,
            "invocation_id": invocation_id,
            "organization_id": organization_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "action_id": action_id,
        },
        timeout=httpx.Timeout(5.0, read=240.0),
    )
    response.raise_for_status()
    return VerificationToolResult.model_validate(response.json()).model_dump(mode="json")
