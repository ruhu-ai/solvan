"""Single-purpose tool for an Agent Identity-bound Execution Agent."""

from __future__ import annotations

import os
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from solvan.agents.private_service_auth import private_service_headers


class ExecutionToolReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_id: str = Field(pattern=r"^rcp_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    result: Literal["SUCCEEDED", "FAILED", "AMBIGUOUS"]
    reservation_id: str = Field(pattern=r"^rsv_[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def execute_authorized_action(
    invocation_id: str,
    action_id: str,
    trace_id: str,
) -> dict[str, object]:
    """Request one exact stored action; no mutation material crosses this tool.

    The payload names only the invocation and the action. Scope is the
    actuator's to derive from its durable role binding: a scope triple here
    would be a model tool argument, which is never authority, and the
    actuator's closed request model refuses one outright.
    """

    base_url = os.environ.get("SOLVAN_ACTUATOR_URL")
    if not base_url:
        raise RuntimeError("SOLVAN_ACTUATOR_URL is required")
    if not base_url.startswith("https://") and os.environ.get("SOLVAN_ENVIRONMENT") != "local":
        raise RuntimeError("the actuator must use HTTPS outside the local harness")
    response = httpx.post(
        f"{base_url.rstrip('/')}/internal/v1/actions/{action_id}:execute",
        headers=private_service_headers(audience_variable="SOLVAN_ACTUATOR_AUDIENCE"),
        json={
            "schema_version": 1,
            "invocation_id": invocation_id,
            "trace_id": trace_id,
        },
        timeout=httpx.Timeout(5.0, read=210.0),
    )
    response.raise_for_status()
    return ExecutionToolReceipt.model_validate(response.json()).model_dump(mode="json")
