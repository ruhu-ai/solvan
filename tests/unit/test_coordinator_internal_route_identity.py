"""The coordinator's internal routes admit only their exact workload callers.

Every route here persists or triggers consequential work. Cloud Run IAM is the
network control; these cases prove the application layer binds each route to
the exact service account of its one legitimate caller, and that absent
configuration refuses rather than admits.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

SCHEDULER = "solvan-scheduler@example.iam.gserviceaccount.com"
PUBSUB = "solvan-pubsub@example.iam.gserviceaccount.com"
EVIDENCE = "solvan-evidence@example.iam.gserviceaccount.com"
COORDINATOR = "solvan-coordinator@example.iam.gserviceaccount.com"
INJECTOR = "solvan-injector@example.iam.gserviceaccount.com"
STRANGER = "stranger@example.iam.gserviceaccount.com"


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_COORDINATOR_AUDIENCE", "https://coordinator.example.invalid")
    monkeypatch.setenv("SOLVAN_SCHEDULER_SERVICE_ACCOUNT", SCHEDULER)
    monkeypatch.setenv("SOLVAN_PUBSUB_PUSH_SERVICE_ACCOUNT", PUBSUB)
    monkeypatch.setenv("SOLVAN_EVIDENCE_SERVICE_ACCOUNT", EVIDENCE)
    monkeypatch.setenv("SOLVAN_COORDINATOR_SERVICE_ACCOUNT", COORDINATOR)
    monkeypatch.delenv("SOLVAN_SCENARIO_INJECTOR_SERVICE_ACCOUNT", raising=False)


def _stub_claims(monkeypatch: pytest.MonkeyPatch, *, email: str) -> None:
    def verify(token: str, *, audience: str) -> dict[str, Any]:
        return {
            "sub": f"subject-for-{email}",
            "iss": "https://accounts.google.com",
            "aud": audience,
            "email": email,
            "email_verified": True,
        }

    monkeypatch.setattr("solvan.platform.service_identity._google_verifier", verify)


def _client() -> TestClient:
    from apps.coordinator.main import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


def _tick(client: TestClient, token: str | None) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(
        "/internal/wakeups/tick", headers=headers, json={"schema_version": 1}
    ).status_code


def test_a_missing_token_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_claims(monkeypatch, email=SCHEDULER)
    assert _tick(_client(), None) == 401


def test_a_verified_stranger_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_claims(monkeypatch, email=STRANGER)
    assert _tick(_client(), "verified") == 403


def test_the_scheduler_identity_is_admitted_past_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identity passes; the tick then meets durable work, not a 401/403."""

    _stub_claims(monkeypatch, email=SCHEDULER)
    assert _tick(_client(), "verified") not in {401, 403}


def test_the_scenario_injector_is_admitted_only_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fault drill ticks as its own identity; production configures none."""

    _stub_claims(monkeypatch, email=INJECTOR)
    assert _tick(_client(), "verified") == 403
    monkeypatch.setenv("SOLVAN_SCENARIO_INJECTOR_SERVICE_ACCOUNT", INJECTOR)
    assert _tick(_client(), "verified") not in {401, 403}


def test_an_unconfigured_route_refuses_rather_than_admitting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOLVAN_SCHEDULER_SERVICE_ACCOUNT")
    monkeypatch.delenv("SOLVAN_SCENARIO_INJECTOR_SERVICE_ACCOUNT", raising=False)
    _stub_claims(monkeypatch, email=SCHEDULER)
    assert _tick(_client(), "verified") == 503


def test_pubsub_push_requires_the_push_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_claims(monkeypatch, email=STRANGER)
    refused = _client().post(
        "/internal/pubsub/workflow",
        headers={"Authorization": "Bearer verified"},
        json={"message": {"data": "", "messageId": "m1"}, "subscription": "s"},
    )
    assert refused.status_code == 403

    _stub_claims(monkeypatch, email=PUBSUB)
    # Past identity; the malformed envelope is the next refusal, not a 401/403.
    admitted = _client().post(
        "/internal/pubsub/workflow",
        headers={"Authorization": "Bearer verified"},
        json={"message": {"data": "", "messageId": "m1"}, "subscription": "s"},
    )
    assert admitted.status_code not in {401, 403}


def test_relay_job_authorship_requires_the_evidence_broker_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_claims(monkeypatch, email=STRANGER)
    refused = _client().post(
        "/internal/v1/relay/observability-jobs",
        headers={"Authorization": "Bearer verified"},
        json={
            "schema_version": 1,
            "agent_run_id": "run_00000000000000000000000000",
            "tool_call_id": "call_00000000000000000000000000",
            "arguments": {
                "service_id": "svc_00000000000000000000000000",
                "window_start": "2026-08-19T00:00:00Z",
                "window_end": "2026-08-19T00:10:00Z",
                "log_view_id": "payments-errors",
                "signature_key": "connection-exhaustion",
                "maximum_entries": 5,
            },
        },
    )
    assert refused.status_code == 403


def test_workspace_rehydration_requires_the_coordinator_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_claims(monkeypatch, email=STRANGER)
    refused = _client().post(
        "/internal/v1/workspaces:rehydrate",
        headers={"Authorization": "Bearer verified"},
        json={
            "schema_version": 1,
            "workspace_id": "wks_00000000000000000000000000",
            "expected_checkpoint_id": "ckp_00000000000000000000000000",
        },
    )
    assert refused.status_code == 403


def test_github_probe_requires_the_coordinator_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_claims(monkeypatch, email=STRANGER)
    refused = _client().post(
        "/internal/v1/github/repositories:probe",
        headers={"Authorization": "Bearer verified"},
    )
    assert refused.status_code == 403
