import json
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError
from pytest import MonkeyPatch

from apps.api import human_identity
from apps.api import main as api_main
from apps.api.console_fixture import console_snapshot
from apps.api.main import create_app
from apps.api.operational_guidance_admin import TriggerActivationCommand


def _fixture_app():
    return create_app(enable_local_maintenance=False, snapshot_provider=console_snapshot)


def test_harness_is_explicitly_local(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    monkeypatch.setenv("SOLVAN_WORKTREE_ID", "test-worktree")  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        response = client.get("/api/harness")
    assert response.status_code == 200
    assert response.json()["authority"] == "NO_PRODUCTION_AUTHORITY"
    assert response.json()["worktree_id"] == "test-worktree"
    assert response.headers["x-trace-id"]


def test_the_api_grants_no_cross_origin_credentialed_access(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """One origin serves the console and proxies this API, so there is no CORS.

    The middleware this replaces allowed one configured origin to send
    credentialed requests, and defaulted that origin to `127.0.0.1:5173`. A
    deployment that did not set the variable therefore shipped a credentialed
    allowance for a loopback origin and refused its own console — and the
    variable was not set anywhere in Terraform.

    Removing the grant is the fix, not narrowing it: a console served from the
    same origin never makes a cross-origin request in the first place.
    """

    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))
    with TestClient(create_app()) as client:
        preflight = client.options(
            "/api/v1/liaison:ask",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        read = client.get("/ready", headers={"Origin": "https://attacker.example"})

    # No preflight is answered, and no response tells a foreign origin that its
    # credentialed read was permitted.
    assert "access-control-allow-origin" not in preflight.headers
    assert "access-control-allow-credentials" not in preflight.headers
    assert "access-control-allow-origin" not in read.headers


def test_observability_records_no_request_content(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        client.get("/ready?secret=must-not-be-recorded")
    lines = (tmp_path / "observability/traces.ndjson").read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    assert event["path"] == "/ready"
    assert event["content_captured"] is False
    assert "must-not-be-recorded" not in lines[-1]


def test_local_metrics_are_queryable(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        client.get("/live")
        response = client.get("/internal/dev/metrics")
    assert response.status_code == 200
    assert "solvan_harness_http_requests_total" in response.text


def test_console_snapshot_is_explicitly_scripted_and_non_authoritative(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(_fixture_app()) as client:
        response = client.get("/api/console/snapshot")
    assert response.status_code == 200
    body = response.json()
    assert body["data_status"] == "SCRIPTED_RELEASE_FIXTURE"
    assert body["authority"] == "NO_PRODUCTION_AUTHORITY"
    assert body["incidents"][0]["actions"][0]["phase"] == "Verified"
    assert body["incidents"][0]["actions"][1]["phase"] == "Awaiting approval"
    assert body["release"]["cloud"] == "No cloud release receipt yet"


def test_tool_catalog_read_api_separates_discovery_from_authorization(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(_fixture_app()) as client:
        response = client.get("/api/fleet/tools")
        detail = client.get("/api/fleet/tools/managed_prometheus_query")
        effective = client.get("/api/fleet/agents/evidence-agent/effective-tools")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json()["status_definitions"]["availability"].startswith("Whether policy")
    assert detail.status_code == 200
    assert detail.json()["availability"] == "Not configured"
    assert detail.json()["next_step"].startswith("Connect Ruhu metrics")
    assert effective.status_code == 200
    assert "Discovery is not authorization" in effective.json()["notice"]


def test_tool_catalog_unknown_revision_is_not_inferred(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(_fixture_app()) as client:
        response = client.get("/api/fleet/tools/managed_prometheus_query/revisions/latest")
    assert response.status_code == 404


def test_guidance_api_exposes_metadata_without_content_or_authority(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(_fixture_app()) as client:
        response = client.get("/api/fleet/guidance")
        detail = client.get("/api/fleet/guidance/payments.connection-exhaustion/revisions/1")
        policies = client.get("/api/fleet/trigger-policies")
    assert response.status_code == detail.status_code == policies.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert "content_ref" not in detail.json()
    assert detail.json()["availability"] == "Unavailable"
    assert policies.json() == {"trigger_policies": []}


def test_trigger_policy_admin_exposes_the_closed_lifecycle_commands(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        openapi = client.get("/openapi.json").json()["paths"]
    implemented = {
        path
        for path, operations in openapi.items()
        if path.startswith("/api/admin/trigger-policies/") and "post" in operations
    }
    contract = {
        line.removeprefix("POST ")
        for line in Path("specs/17-governed-operational-guidance.md").read_text().splitlines()
        if line.startswith("POST /api/admin/trigger-policies/")
    }
    assert implemented == contract
    assert not any(path.startswith("/admin/alert-policies/") for path in openapi)


def test_trigger_activation_command_requires_an_exact_prior_head_pair() -> None:
    valid = {
        "schema_version": 1,
        "expected_digest": f"sha256:{'a' * 64}",
        "candidate_version": "2",
        "expected_prior_head_epoch": 0,
        "expected_activation_id": None,
        "placement_epoch": 1,
    }
    assert TriggerActivationCommand.model_validate(valid).expected_prior_head_epoch == 0
    for changed in (
        {**valid, "expected_activation_id": "tpa_existing"},
        {**valid, "expected_prior_head_epoch": 1},
        {**valid, "principal": "user:injected@example.com"},
    ):
        try:
            TriggerActivationCommand.model_validate(changed)
        except ValidationError:
            pass
        else:
            raise AssertionError("malformed or identity-bearing activation body was accepted")


def test_local_approval_route_fails_closed_before_database(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/actions/act_00000000000000000000000000:approve",
            headers={"idempotency-key": "approval-request-1"},
            json={
                "schema_version": 1,
                "action_digest": f"sha256:{'0' * 64}",
                "reason": "test only",
            },
        )
    assert response.status_code == 503


def test_local_agent_skills_mutation_route_fails_closed_before_database(
    tmp_path: Path, monkeypatch: object
) -> None:
    """Local development cannot impersonate the Google approval boundary."""
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/skills/import",
            headers={"idempotency-key": "skills-local-refusal"},
            json={
                "schema_version": 1,
                "command_id": "cmd_local_refusal",
                "purpose": "incident-investigation",
                "classification": "PUBLIC",
                "region": "europe-west1",
                "source_kind": "ARCHIVE",
                "source_ref": "fixture://skill.zip",
                "archive_base64": "UEsDBAoAAAAA",
            },
        )
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "approval authority is disabled outside the Google Cloud deployment"
    )


def test_google_identity_claim_maps_only_verified_email(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")
    # A service URL is what specification 05 §9 names as the wrong audience;
    # it was configured here as though it were valid.
    monkeypatch.setenv("SOLVAN_APPROVAL_AUDIENCE", "111111111111-abc123.apps.googleusercontent.com")
    monkeypatch.setattr(
        human_identity.id_token,
        "verify_oauth2_token",
        lambda *_args, **_kwargs: {
            "email": "Approver@Example.com",
            "email_verified": True,
        },
    )
    assert api_main._approval_principal("Bearer signed") == "user:approver@example.com"


def test_local_patch_review_fails_closed_before_database(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))  # type: ignore[attr-defined]
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/patches/pat_00000000000000000000000000:review",
            headers={"idempotency-key": "patch-review-request-1"},
            json={
                "schema_version": 1,
                "patch_digest": f"sha256:{'0' * 64}",
                "decision": "APPROVE",
                "reason": "test only",
            },
        )
    assert response.status_code == 503
