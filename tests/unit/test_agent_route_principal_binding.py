"""Private Agent-facing routes admit the exact attested caller, nothing else.

Token verification alone proves the caller is *some* Google workload that can
mint for this audience. These cases prove the four consequential routes
(actuator, verifier, evidence broker, workspace tool broker) also compare the
verified claims against the exact configured Agent principal — the check that
used to be computed and discarded.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from apps.coordinator.workspace_tool_broker import authenticate_workspace_agent

EXECUTION_PRINCIPAL = (
    "principal://agents.global.project-123.system.id.goog/resources/aiplatform/"
    "projects/123/locations/europe-west1/reasoningEngines/execution-1"
)
VERIFICATION_PRINCIPAL = EXECUTION_PRINCIPAL.replace("execution-1", "verification-1")
EVIDENCE_PRINCIPAL = EXECUTION_PRINCIPAL.replace("execution-1", "evidence-1")
WORKSPACE_PRINCIPAL = EXECUTION_PRINCIPAL.replace("execution-1", "workspace-1")

_AUDIENCES = {
    "SOLVAN_ACTUATOR_AUDIENCE": "https://actuator.example.invalid",
    "SOLVAN_VERIFIER_AUDIENCE": "https://verifier.example.invalid",
    "SOLVAN_EVIDENCE_AUDIENCE": "https://evidence.example.invalid",
    "SOLVAN_WORKSPACE_TOOL_BROKER_AUDIENCE": "https://broker.example.invalid",
}


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in _AUDIENCES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "AGENT_IDENTITY_IAM_GATEWAY")
    monkeypatch.setenv("SOLVAN_EXECUTION_PRINCIPAL", EXECUTION_PRINCIPAL)
    monkeypatch.setenv("SOLVAN_VERIFICATION_PRINCIPAL", VERIFICATION_PRINCIPAL)
    monkeypatch.setenv("SOLVAN_EVIDENCE_AGENT_PRINCIPAL", EVIDENCE_PRINCIPAL)
    monkeypatch.setenv("SOLVAN_INFRASTRUCTURE_AGENT_PRINCIPAL", "UNCONFIGURED")


def _stub_claims(monkeypatch: pytest.MonkeyPatch, *, subject: str) -> None:
    def verify(token: str, *, audience: str) -> dict[str, Any]:
        return {
            "sub": subject,
            "iss": "https://accounts.google.com",
            "aud": audience,
        }

    monkeypatch.setattr("solvan.platform.service_identity._google_verifier", verify)


def _client() -> TestClient:
    from apps.actuator.main import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


def test_the_actuator_refuses_a_verified_caller_that_is_not_the_execution_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_claims(monkeypatch, subject=VERIFICATION_PRINCIPAL)

    response = _client().post(
        "/internal/v1/actions/act_00000000000000000000000000:execute",
        headers={"Authorization": "Bearer verified-wrong-caller"},
        json={"schema_version": 1, "invocation_id": "inv_00000000000000000000000000"},
    )

    assert response.status_code == 403
    assert "not an admitted agent identity" in response.json()["detail"]


def test_the_actuator_passes_identity_for_the_exact_execution_agent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Identity passes; the request then meets the remaining guards, not a 401/403."""

    _stub_claims(monkeypatch, subject=EXECUTION_PRINCIPAL)
    # Local customer-side controls configured disengaged, so the request
    # proceeds past them and fails later (no database in this harness).
    monkeypatch.setenv("SOLVAN_ACTUATOR_KILL_SWITCH_FILE", str(tmp_path / "absent-kill-switch"))
    monkeypatch.setenv("SOLVAN_ACTUATOR_MAX_MUTATIONS_PER_HOUR", "5")
    monkeypatch.setenv("SOLVAN_PAYMENTS_ADMIN_URL", "https://payments.example.invalid")
    monkeypatch.setenv("SOLVAN_ACTUATOR_IDENTITY", "serviceAccount:actuator@example.invalid")
    monkeypatch.setenv("SOLVAN_ACTUATOR_ID", "actuator-test")

    response = _client().post(
        "/internal/v1/actions/act_00000000000000000000000000:execute",
        headers={"Authorization": "Bearer verified-execution-agent"},
        json={"schema_version": 1, "invocation_id": "inv_00000000000000000000000000"},
    )

    assert response.status_code not in {401, 403}


def test_the_verifier_refuses_a_verified_caller_that_is_not_the_verification_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.verifier.main import create_app

    _stub_claims(monkeypatch, subject=EXECUTION_PRINCIPAL)

    response = TestClient(create_app(), raise_server_exceptions=False).post(
        "/internal/v1/verifications:run",
        headers={"Authorization": "Bearer verified-wrong-caller"},
        json={
            "schema_version": 1,
            "invocation_id": "inv_00000000000000000000000000",
            "organization_id": "org_00000000000000000000000000",
            "project_id": "prj_00000000000000000000000000",
            "environment_id": "env_00000000000000000000000000",
            "action_id": "act_00000000000000000000000000",
        },
    )

    assert response.status_code == 403
    assert "not an admitted agent identity" in response.json()["detail"]


def test_the_evidence_broker_binds_the_path_agent_to_the_verified_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The infrastructure agent cannot read as the evidence agent, or at all."""

    from apps.evidence_broker.main import create_app

    _stub_claims(monkeypatch, subject=EVIDENCE_PRINCIPAL.replace("evidence-1", "infrastructure-1"))
    client = TestClient(create_app(), raise_server_exceptions=False)

    as_evidence = client.post(
        "/internal/v1/evidence/evidence-agent:query",
        headers={"Authorization": "Bearer verified-infrastructure-agent"},
        json={
            "schema_version": 1,
            "invocation_id": "inv_00000000000000000000000000",
            "tool_name": "cloud_logging_query",
            "arguments": {},
        },
    )
    assert as_evidence.status_code == 403

    unconfigured = client.post(
        "/internal/v1/evidence/infrastructure-agent:query",
        headers={"Authorization": "Bearer verified-infrastructure-agent"},
        json={
            "schema_version": 1,
            "invocation_id": "inv_00000000000000000000000000",
            "tool_name": "cloud_run_read",
            "arguments": {},
        },
    )
    assert unconfigured.status_code == 503


def test_the_workspace_broker_refuses_a_verified_caller_that_is_not_the_workspace_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    _stub_claims(monkeypatch, subject=EXECUTION_PRINCIPAL)
    settings = SimpleNamespace(workspace_agent_principal=WORKSPACE_PRINCIPAL)

    with pytest.raises(ValueError, match="not admitted"):
        authenticate_workspace_agent("Bearer verified-wrong-caller", settings=settings)  # type: ignore[arg-type]

    _stub_claims(monkeypatch, subject=WORKSPACE_PRINCIPAL)
    authenticate_workspace_agent("Bearer verified-workspace-agent", settings=settings)  # type: ignore[arg-type]
