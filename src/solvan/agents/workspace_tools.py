"""Bounded Workspace Agent tools routed through the Coordinator authority boundary."""

from __future__ import annotations

import os
from typing import Any

import httpx

from solvan.agents.private_service_auth import private_service_headers


def _invoke(*, request_id: str, operation: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    base_url = os.environ.get("SOLVAN_WORKSPACE_TOOL_BROKER_URL")
    if not base_url:
        raise RuntimeError("SOLVAN_WORKSPACE_TOOL_BROKER_URL is required")
    if not base_url.startswith("https://") and os.environ.get("SOLVAN_ENVIRONMENT") != "local":
        raise RuntimeError("the Workspace Tool broker must use HTTPS outside the local harness")
    response = httpx.post(
        f"{base_url.rstrip('/')}/internal/v1/workspace-tools/{operation}",
        headers=private_service_headers(audience_variable="SOLVAN_WORKSPACE_TOOL_BROKER_AUDIENCE"),
        json={"schema_version": 1, "request_id": request_id, "tool_input": tool_input},
        timeout=httpx.Timeout(5.0, read=330.0),
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("Workspace Tool broker returned a non-object response")
    return value


def read_workspace_artifact(
    request_id: str, artifact_handle: str, offset_bytes: int, limit_bytes: int
) -> dict[str, Any]:
    """Read one bounded slice from a manifest-bound workspace artifact."""

    return _invoke(
        request_id=request_id,
        operation="read-artifact",
        tool_input={
            "schema_version": 1,
            "artifact_handle": artifact_handle,
            "offset_bytes": offset_bytes,
            "limit_bytes": limit_bytes,
        },
    )


def write_candidate_artifact(
    request_id: str,
    operation: str,
    relative_path: str,
    expected_prior_hash: str | None,
    content_utf8: str | None,
) -> dict[str, Any]:
    """Append one candidate-tree operation without altering the input snapshot."""

    return _invoke(
        request_id=request_id,
        operation="write-candidate-artifact",
        tool_input={
            "schema_version": 1,
            "operation": operation,
            "relative_path": relative_path,
            "expected_prior_hash": expected_prior_hash,
            "content_utf8": content_utf8,
        },
    )


def run_in_exploratory_sandbox(
    request_id: str, test_command_id: str, candidate_tree_hash: str
) -> dict[str, Any]:
    """Run one catalog command in the exploratory, non-adjudicating sandbox lane."""

    return _invoke(
        request_id=request_id,
        operation="run-in-sandbox",
        tool_input={
            "schema_version": 1,
            "test_command_id": test_command_id,
            "candidate_tree_hash": candidate_tree_hash,
        },
    )
