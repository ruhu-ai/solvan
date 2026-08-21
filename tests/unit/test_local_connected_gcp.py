from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from apps.api import human_identity
from apps.api.local_cloud_development import (
    LocalMonitoringRuleRequest,
    _deduplication_dimension,
    _rule_key,
    _worker_url,
)
from apps.api.main import create_app
from apps.direct_gcp_reader import main as direct_reader
from apps.local_cloud_worker import main as local_worker
from solvan.application.detection import Comparator, DetectionRule, DetectionSourceBinding
from solvan.platform import local_gcp_credentials
from solvan.platform.direct_gcp_detection_client import DirectGcpDetectionClient
from solvan.platform.local_service_token import local_bearer_matches, read_local_service_token
from solvan.platform.service_identity import VerifiedCaller


def _write_token(path: Path, *, mode: int = 0o600) -> str:
    token = "local-development-token-" + "x" * 48
    path.write_text(token, encoding="ascii")
    path.chmod(mode)
    return token


def test_local_service_token_requires_an_absolute_private_regular_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "reader.token"
    token = _write_token(path)
    monkeypatch.setenv("SOLVAN_LOCAL_READER_TOKEN_PATH", str(path))
    assert read_local_service_token() == token
    assert local_bearer_matches(f"Bearer {token}")
    assert not local_bearer_matches("Bearer wrong")

    path.chmod(0o640)
    with pytest.raises(RuntimeError, match="outside the security bound"):
        read_local_service_token()

    link = tmp_path / "reader-link.token"
    link.symlink_to(path)
    monkeypatch.setenv("SOLVAN_LOCAL_READER_TOKEN_PATH", str(link))
    with pytest.raises(RuntimeError, match="unsafe"):
        read_local_service_token()


def test_local_gcp_credentials_mint_only_the_exact_development_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = SimpleNamespace()
    minted = SimpleNamespace(
        service_account_email="solvan-probe@solvan-dev.iam.gserviceaccount.com",
        refresh=lambda _request: None,
    )
    monkeypatch.setattr(
        local_gcp_credentials.google.auth, "default", lambda **_kwargs: (source, None)
    )
    monkeypatch.setattr(
        local_gcp_credentials.impersonated_credentials,
        "Credentials",
        lambda **kwargs: minted
        if kwargs["target_principal"] == "solvan-probe@solvan-dev.iam.gserviceaccount.com"
        else None,
    )
    result = local_gcp_credentials.development_credentials(
        service_account="solvan-probe@solvan-dev.iam.gserviceaccount.com"
    )
    assert result is minted

    key_credential = SimpleNamespace(
        service_account_email="other@solvan-dev.iam.gserviceaccount.com"
    )
    monkeypatch.setattr(
        local_gcp_credentials.google.auth,
        "default",
        lambda **_kwargs: (key_credential, None),
    )
    with pytest.raises(RuntimeError, match="service-account key"):
        local_gcp_credentials.development_credentials(
            service_account="solvan-probe@solvan-dev.iam.gserviceaccount.com",
            refresh=False,
        )


def test_direct_reader_accepts_only_a_caller_in_the_closed_json_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        direct_reader,
        "verify_service_caller",
        lambda *_args, **_kwargs: VerifiedCaller(
            "subject", "detector@solvan.example", "https://reader", "accounts.google.com"
        ),
    )
    monkeypatch.setenv(
        "SOLVAN_DIRECT_GCP_READER_CALLERS_JSON",
        '["api@solvan.example","detector@solvan.example"]',
    )
    direct_reader._authorize("Bearer signed")

    monkeypatch.setenv("SOLVAN_DIRECT_GCP_READER_CALLERS_JSON", '["api@solvan.example"]')
    with pytest.raises(HTTPException) as denied:
        direct_reader._authorize("Bearer signed")
    assert denied.value.status_code == 403

    monkeypatch.setenv("SOLVAN_DIRECT_GCP_READER_CALLERS_JSON", "not-json")
    with pytest.raises(HTTPException) as invalid:
        direct_reader._authorize("Bearer signed")
    assert invalid.value.status_code == 503


def test_detection_client_rejects_response_replay_from_another_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = DetectionSourceBinding(
        connection_id="con_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
        connection_epoch=4,
        external_project_id="ruhu-dev",
        workload_region="europe-west2",
        solvan_delegator_principal=(
            "serviceAccount:solvan-probe@solvan-dev.iam.gserviceaccount.com"
        ),
        customer_reader_principal=("serviceAccount:solvan-reader@ruhu-dev.iam.gserviceaccount.com"),
        token_lifetime_seconds=900,
    )
    rule = DetectionRule(
        rule_id="ruhu-http-5xx",
        version=1,
        service_id="svc_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
        service_key="ruhu-atlas",
        graph_snapshot_id="pgs_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
        incident_class="http_errors",
        signal_kind="HTTP_5XX_RATIO",
        query={"gcp_project_id": "ruhu-dev", "resource_name": "ruhu-atlas-challenge"},
        evaluation_interval_ms=25_000,
        comparator=Comparator.GT,
        threshold=0.05,
        sustained_windows=1,
        severity="SEV3",
        deduplication_dimension="ruhu-http-5xx",
        action_budget=1,
        repeated_action_limit=1,
        source_binding=binding,
    )
    client = DirectGcpDetectionClient()
    response = {
        "connection_id": binding.connection_id,
        "connection_epoch": 3,
        "rule_id": rule.rule_id,
        "rule_version": rule.version,
        "observed_project_id": binding.external_project_id,
        "observed_value": 0.1,
        "request_ids": ["request-1"],
        "observed_resource_type": "cloud_run_revision",
        "observed_labels": {"service_name": "ruhu-atlas-challenge"},
    }
    monkeypatch.setattr(client, "_post", lambda _body: response)
    now = datetime.now(UTC)
    with pytest.raises(RuntimeError, match="frozen request"):
        client.observe(rule, window_start=now - timedelta(minutes=1), window_end=now)

    response["connection_epoch"] = 4
    observation = client.observe(rule, window_start=now - timedelta(minutes=1), window_end=now)
    assert observation.value == 0.1
    assert observation.resource.project_id == "ruhu-dev"


def test_local_monitoring_rule_key_is_stable_and_material_bound() -> None:
    request = LocalMonitoringRuleRequest(
        schema_version=1,
        connection_id="con_01H8Z1P5RF9Q3AVBVSG3Y2NZ8Q",
        expected_connection_epoch=1,
        display_name="Ruhu Atlas",
        resource_name="ruhu-atlas-challenge",
        signal_kind="HTTP_5XX_RATIO",
        comparator="GT",
        threshold=0.05,
        sustained_windows=1,
        severity="SEV3",
    )
    key = _rule_key(request, "ruhu-dev")
    assert key == _rule_key(request, "ruhu-dev")
    assert key.startswith("dev-http-5xx-")
    assert key != _rule_key(request.model_copy(update={"resource_name": "other"}), "ruhu-dev")
    dimension = _deduplication_dimension(request, "ruhu-dev")
    assert dimension == _deduplication_dimension(request, "ruhu-dev")
    assert ":" not in dimension
    assert dimension != _deduplication_dimension(
        request.model_copy(update={"resource_name": "ruhu-dev:database"}), "ruhu-dev"
    )


def test_local_worker_url_can_never_be_an_external_egress_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_LOCAL_CLOUD_WORKER_URL", "http://127.0.0.1:21005")
    assert _worker_url() == "http://127.0.0.1:21005"
    for unsafe in (
        "https://127.0.0.1:21005",
        "http://example.com:21005",
        "http://127.0.0.1:21005/path",
    ):
        monkeypatch.setenv("SOLVAN_LOCAL_CLOUD_WORKER_URL", unsafe)
        with pytest.raises(RuntimeError):
            _worker_url()


def test_local_worker_requires_its_per_start_token_before_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "reader.token"
    token = _write_token(path)
    monkeypatch.setenv("SOLVAN_LOCAL_READER_TOKEN_PATH", str(path))
    monkeypatch.setattr(
        local_worker,
        "_run_detector",
        lambda: {
            "evaluated_rules": 1,
            "inserted_evaluations": 1,
            "emitted_events": 1,
        },
    )
    monkeypatch.setattr(
        local_worker,
        "_run_inbox",
        lambda: SimpleNamespace(claimed=1, completed=1),
    )
    with TestClient(local_worker.app) as client:
        refused = client.post("/internal/dev/pipeline:run", json={"schema_version": 1})
        accepted = client.post(
            "/internal/dev/pipeline:run",
            headers={"Authorization": f"Bearer {token}"},
            json={"schema_version": 1},
        )
    assert refused.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json()["inbox_completed"] == 1


def test_local_connected_routes_exist_only_in_explicit_cloud_development_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOLVAN_LOCAL_CONNECTED_GCP", raising=False)
    ordinary = set(create_app(enable_local_maintenance=False).openapi()["paths"])
    assert "/api/v1/local-development/monitoring-rules" not in ordinary

    monkeypatch.setenv("SOLVAN_LOCAL_CONNECTED_GCP", "true")
    connected = set(create_app(enable_local_maintenance=False).openapi()["paths"])
    assert "/api/v1/local-development/monitoring-rules" in connected
    assert "/api/v1/local-development/pipeline:run" in connected


def test_local_connected_admin_identity_still_requires_verified_google_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_LOCAL_CONNECTED_GCP", "true")
    monkeypatch.setenv("SOLVAN_APPROVAL_AUDIENCE", "111111111111-abc123.apps.googleusercontent.com")
    monkeypatch.setattr(
        "apps.api.human_identity.id_token.verify_oauth2_token",
        lambda *_args, **_kwargs: {
            "sub": "google-subject",
            "email": "Operator@Example.com",
            "email_verified": True,
        },
    )
    assert human_identity.approval_principal("Bearer signed") == "user:operator@example.com"
    with pytest.raises(HTTPException) as missing:
        human_identity.approval_principal(None)
    assert missing.value.status_code == 401


def test_cloud_development_launcher_has_no_target_project_argument() -> None:
    wrapper = Path("scripts/start-cloud-dev").read_text(encoding="utf-8")
    launcher = Path("scripts/start").read_text(encoding="utf-8")
    assert "--target-project" not in wrapper
    assert "Target estates: selected only through Integrations" in wrapper
    assert "SOLVAN_LOCAL_ADMIN_PRINCIPAL" in wrapper
    assert "exec scripts/start" in wrapper
    assert "secrets.token_urlsafe" not in wrapper
    assert "secrets.token_urlsafe" in launcher
    assert launcher.index("scripts/stop >/dev/null") < launcher.index("secrets.token_urlsafe")


def test_production_detector_uses_reader_identity_instead_of_monitoring_role() -> None:
    iam = Path("infra/terraform/environments/gcp/iam.tf").read_text(encoding="utf-8")
    cloud_run = Path("infra/terraform/environments/gcp/cloud_run.tf").read_text(encoding="utf-8")
    assert 'resource "google_project_iam_member" "detector_monitoring"' not in iam
    assert 'resource "google_cloud_run_v2_service_iam_member" "detector_direct_gcp_reader"' in iam
    assert "SOLVAN_DIRECT_GCP_READER_CALLERS_JSON" in cloud_run
    assert 'google_service_account.workload["detector"].email' in cloud_run


def test_local_panel_mutations_require_the_double_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pasted token is gone: panel writes run under the session plus CSRF."""

    monkeypatch.setenv("SOLVAN_LOCAL_CONNECTED_GCP", "true")
    client = TestClient(create_app(enable_local_maintenance=False))
    rule = {
        "schema_version": 1,
        "connection_id": "con_01J00000000000000000000000",
        "expected_connection_epoch": 1,
        "display_name": "x",
        "resource_name": "svc",
        "signal_kind": "HTTP_5XX_RATIO",
        "comparator": "GT",
        "threshold": 0.5,
        "sustained_windows": 1,
        "severity": "SEV3",
    }
    for path, body in (
        ("/api/v1/local-development/monitoring-rules", rule),
        ("/api/v1/local-development/pipeline:run", None),
    ):
        response = client.post(path, json=body)
        assert response.status_code == 403, path


def test_local_panel_reads_require_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_LOCAL_CONNECTED_GCP", "true")
    client = TestClient(create_app(enable_local_maintenance=False))
    response = client.get("/api/v1/local-development/monitoring-rules")
    assert response.status_code == 401
