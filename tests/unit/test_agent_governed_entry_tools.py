from __future__ import annotations

from typing import Any

import pytest

from solvan.agents.execution_tools import execute_authorized_action
from solvan.agents.verification_tools import run_bound_verification
from solvan.agents.workspace_tools import run_in_exploratory_sandbox

_ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


class _Response:
    def __init__(self, value: dict[str, object]) -> None:
        self.value = value
        self.raised = False

    def raise_for_status(self) -> None:
        self.raised = True

    def json(self) -> dict[str, object]:
        return self.value


def test_execution_tool_sends_only_stored_action_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _Response(
        {"receipt_id": f"rcp_{_ULID}", "result": "SUCCEEDED", "reservation_id": f"rsv_{_ULID}"}
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setenv("SOLVAN_ACTUATOR_URL", "https://actuator.example")
    monkeypatch.setattr(
        "solvan.agents.execution_tools.private_service_headers",
        lambda *, audience_variable: {"Authorization": "Bearer runtime-token"},
    )
    monkeypatch.setattr(
        "solvan.agents.execution_tools.httpx.post",
        lambda url, **kwargs: calls.append({"url": url, **kwargs}) or response,
    )
    result = execute_authorized_action("inv", "act", "trace")
    assert result["result"] == "SUCCEEDED"
    assert set(calls[0]["json"]) == {
        "schema_version",
        "invocation_id",
        "trace_id",
    }
    assert calls[0]["url"].endswith("/actions/act:execute")
    assert calls[0]["headers"] == {"Authorization": "Bearer runtime-token"}
    assert response.raised


def test_execution_tool_payload_is_exactly_what_the_actuator_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two contracts are validated against each other, not just themselves.

    The tool used to send a caller-supplied scope triple while the actuator's
    closed request model refused it — both suites green, the boundary dead.
    Validating the captured payload against the actuator's own model makes a
    drift on either side fail here first.
    """

    from apps.actuator.main import ExecuteActionRequest

    response = _Response(
        {"receipt_id": f"rcp_{_ULID}", "result": "SUCCEEDED", "reservation_id": f"rsv_{_ULID}"}
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setenv("SOLVAN_ACTUATOR_URL", "https://actuator.example")
    monkeypatch.setattr(
        "solvan.agents.execution_tools.private_service_headers",
        lambda *, audience_variable: {"Authorization": "Bearer runtime-token"},
    )
    monkeypatch.setattr(
        "solvan.agents.execution_tools.httpx.post",
        lambda url, **kwargs: calls.append({"url": url, **kwargs}) or response,
    )
    execute_authorized_action("inv", "act", "trace")

    accepted = ExecuteActionRequest.model_validate(calls[0]["json"])
    assert accepted.invocation_id == "inv"
    assert accepted.trace_id == "trace"


def test_verification_tool_cannot_select_a_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _Response(
        {"verification_id": f"ver_{_ULID}", "verdict": "VERIFIED", "rationale_codes": []}
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setenv("SOLVAN_VERIFIER_URL", "https://verifier.example")
    monkeypatch.setattr(
        "solvan.agents.verification_tools.private_service_headers",
        lambda *, audience_variable: {"Authorization": "Bearer runtime-token"},
    )
    monkeypatch.setattr(
        "solvan.agents.verification_tools.httpx.post",
        lambda url, **kwargs: calls.append({"url": url, **kwargs}) or response,
    )
    result = run_bound_verification("inv", "act", "org", "prj", "env")
    assert result["verdict"] == "VERIFIED"
    assert "profile" not in calls[0]["json"]
    assert calls[0]["headers"] == {"Authorization": "Bearer runtime-token"}
    assert response.raised


def test_workspace_tool_sends_only_request_identity_and_closed_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response({"command": {"outcome": "ACCEPTED"}, "result": {"exit_code": 0}})
    calls: list[dict[str, Any]] = []
    monkeypatch.setenv("SOLVAN_WORKSPACE_TOOL_BROKER_URL", "https://coordinator.example")
    monkeypatch.setattr(
        "solvan.agents.workspace_tools.private_service_headers",
        lambda *, audience_variable: {"Authorization": "Bearer runtime-token"},
    )
    monkeypatch.setattr(
        "solvan.agents.workspace_tools.httpx.post",
        lambda url, **kwargs: calls.append({"url": url, **kwargs}) or response,
    )
    result = run_in_exploratory_sandbox("req_123", "rcc_123", "sha256:" + "a" * 64)
    assert result["result"] == {"exit_code": 0}
    assert calls[0]["json"] == {
        "schema_version": 1,
        "request_id": "req_123",
        "tool_input": {
            "schema_version": 1,
            "test_command_id": "rcc_123",
            "candidate_tree_hash": "sha256:" + "a" * 64,
        },
    }
    assert set(calls[0]["headers"]) == {"Authorization"}


@pytest.mark.parametrize(
    ("target", "environment"),
    [
        ("solvan.agents.execution_tools", "SOLVAN_ACTUATOR_URL"),
        ("solvan.agents.verification_tools", "SOLVAN_VERIFIER_URL"),
    ],
)
def test_governed_entry_tools_require_configured_https(
    monkeypatch: pytest.MonkeyPatch, target: str, environment: str
) -> None:
    monkeypatch.delenv(environment, raising=False)
    function = execute_authorized_action if "execution" in target else run_bound_verification
    arguments = (
        ("inv", "act", "trace") if "execution" in target else ("inv", "act", "org", "prj", "env")
    )
    with pytest.raises(RuntimeError, match="required"):
        function(*arguments)
    monkeypatch.setenv(environment, "http://unsafe")
    monkeypatch.delenv("SOLVAN_ENVIRONMENT", raising=False)
    with pytest.raises(RuntimeError, match="HTTPS"):
        function(*arguments)
