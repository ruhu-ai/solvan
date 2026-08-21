from __future__ import annotations

import json

from fastapi.testclient import TestClient

from apps.api.console_fixture import console_snapshot
from apps.api.console_settings import console_settings_projection
from apps.api.main import create_app


def test_local_settings_are_truthful_and_secret_free() -> None:
    settings = console_settings_projection(console_snapshot(), api_version="0.1.0")

    assert settings["schema_version"] == 1
    assert settings["operator"]["state"] == "LOCAL_DEVELOPMENT"
    assert settings["operator"]["initials"] == "LD"
    assert settings["environment"]["name"] == "development"
    assert settings["environment"]["authority"] == "NO_PRODUCTION_AUTHORITY"
    assert settings["runtime"]["model_resource"] == "gemini-3.6-flash"
    assert settings["runtime"]["model_location"] == "eu"
    assert settings["runtime"]["source"] == "LOCAL_FIXTURE"
    assert settings["governance"]["autonomy_state"] == "UNAVAILABLE"
    assert "no production authority" in settings["governance"]["autonomy_reason"].lower()
    assert settings["capabilities"]["manage_runtime"] is False

    rendered = json.dumps(settings).lower()
    for forbidden in (
        "api_key",
        "access_token",
        "refresh_token",
        "password",
        "private_key",
        "connection_string",
    ):
        assert forbidden not in rendered


def test_cloud_settings_do_not_invent_a_browser_identity(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    snapshot = console_snapshot()
    snapshot["authority"] = "GOOGLE_CLOUD_IAM"
    snapshot["data_status"] = "LIVE_CLOUD_SQL_PROJECTION"
    snapshot["release"] = {
        "cloud": "BOUND_GCP_EVIDENCE_COMPLETE",
        "commit": "abc123",
        "deployment_id": "deploy-42",
    }
    monkeypatch.setenv("SOLVAN_GCP_PROJECT", "solvan-staging")
    monkeypatch.setenv("SOLVAN_ENVIRONMENT_ID", "staging")

    settings = console_settings_projection(snapshot, api_version="0.1.0")

    assert settings["operator"]["state"] == "AUTHENTICATION_REQUIRED"
    assert settings["operator"]["principal"] is None
    assert settings["operator"]["roles"] == []
    assert settings["runtime"]["source"] == "BOUND_RELEASE"
    assert settings["runtime"]["deployment_id"] == "deploy-42"
    assert settings["environment"]["project_id"] == "solvan-staging"


def test_console_snapshot_embeds_settings_and_private_endpoints_do_not_cache(
    monkeypatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SOLVAN_STATE_DIR", str(tmp_path))
    with TestClient(
        create_app(enable_local_maintenance=False, snapshot_provider=console_snapshot)
    ) as client:
        snapshot = client.get("/api/console/snapshot")
        settings = client.get("/api/console/settings")
        operator = client.get("/api/console/me")
        environments = client.get("/api/console/environments")

    assert snapshot.status_code == 200
    assert snapshot.json()["settings"]["schema_version"] == 1
    assert settings.status_code == 200
    assert settings.headers["cache-control"] == "private, no-store"
    assert operator.headers["cache-control"] == "private, no-store"
    assert environments.headers["cache-control"] == "private, no-store"
    assert operator.json()["initials"] == "LD"
    assert environments.json()[0]["classification"] == "LOCAL"
