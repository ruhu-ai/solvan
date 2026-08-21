from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.api.agent_skills import (
    RegisteredExportDestination,
    SkillExportDestinationHttpRequest,
    _UnavailableRepositoryConnector,
    _UnavailableRevisionProvider,
    _UnavailableSkillObjectReader,
    _UnavailableSkillObjectWriter,
    _write_registered_export,
    agent_skills_router,
)
from solvan.application.skills_governance import SkillCompileCommand, skill_name_from_key
from solvan.application.skills_security import UnavailableModelArmor
from solvan.domain import Scope, new_identifier


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.status_code = 200
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


class _Session:
    def __init__(self, location: str = "europe-west1") -> None:
        self.location = location
        self.writes: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        assert url == "https://storage.googleapis.com/storage/v1/b/tenant-skills"
        assert kwargs["params"] == {"fields": "location"}
        return _Response({"location": self.location})

    def post(self, url: str, **kwargs: Any) -> _Response:
        self.writes.append((url, kwargs))
        return _Response({"generation": "23"})


def test_registered_export_writes_exact_scope_under_exact_gcs_binding(monkeypatch) -> None:
    session = _Session()
    monkeypatch.setattr("apps.api.agent_skills.authorized_session", lambda: session)
    scope = Scope(new_identifier("org"), new_identifier("prj"), new_identifier("env"))
    result = _write_registered_export(
        destination=RegisteredExportDestination(
            "tenant-default",
            "GCS",
            "gs://tenant-skills/approved-exports",
            "europe-west1",
            "INTERNAL",
        ),
        scope=scope,
        export_id="sea_01J4QZK8Q4J8Q6B95KQY4M9R2S",
        content=b"deterministic-export",
    )
    assert result.generation == "23"
    assert result.uri == (
        f"gs://tenant-skills/approved-exports/{scope.organization_id}/"
        f"{scope.project_id}/{scope.environment_id}/sea_01J4QZK8Q4J8Q6B95KQY4M9R2S.zip"
    )
    assert session.writes[0][1]["params"]["ifGenerationMatch"] == "0"


def test_registered_export_refuses_bucket_outside_exact_region(monkeypatch) -> None:
    monkeypatch.setattr("apps.api.agent_skills.authorized_session", lambda: _Session("us-central1"))
    with pytest.raises(ValueError, match="DESTINATION_REGION_MISMATCH"):
        _write_registered_export(
            destination=RegisteredExportDestination(
                "tenant-default",
                "GCS",
                "gs://tenant-skills/exports",
                "europe-west1",
                "INTERNAL",
            ),
            scope=Scope(new_identifier("org"), new_identifier("prj"), new_identifier("env")),
            export_id="sea_01J4QZK8Q4J8Q6B95KQY4M9R2S",
            content=b"deterministic-export",
        )


def test_governance_destination_contract_exposes_only_implemented_gcs_kind() -> None:
    with pytest.raises(ValidationError):
        SkillExportDestinationHttpRequest(
            destination_id="unsupported",
            destination_kind="GITHUB",
            binding_ref="gs://tenant-skills/exports",
            region="europe-west1",
            classification_ceiling="INTERNAL",
            purpose="SKILL_GOVERNANCE",
        )


class _RecordingCursor:
    def __init__(self, statements: list[str]) -> None:
        self._statements = statements

    def __enter__(self) -> _RecordingCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: object = None) -> None:
        del params
        self._statements.append(statement)

    def fetchone(self) -> object:
        return None

    def fetchall(self) -> list[object]:
        return []


class _RecordingConnection:
    autocommit = False

    def __init__(self, statements: list[str]) -> None:
        self._statements = statements

    def __enter__(self) -> _RecordingConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self, **_kwargs: object) -> _RecordingCursor:
        return _RecordingCursor(self._statements)

    def transaction(self) -> _RecordingConnection:
        return self


def test_refresh_authorizes_before_any_lineage_read() -> None:
    statements: list[str] = []
    app = FastAPI()
    app.include_router(
        agent_skills_router(
            principal_provider=lambda _token: "user:probe@example.com",
            scope_provider=lambda: Scope(
                new_identifier("org"), new_identifier("prj"), new_identifier("env")
            ),
            connect=lambda: _RecordingConnection(statements),
            object_writer=_UnavailableSkillObjectWriter(),
            object_reader=_UnavailableSkillObjectReader(),
            armor=UnavailableModelArmor(),
            repository_connector=_UnavailableRepositoryConnector(),
            revision_provider=_UnavailableRevisionProvider(),
        )
    )
    response = TestClient(app).post(
        "/api/v1/skills/payments.demo/refresh",
        headers={"Idempotency-Key": "refresh-probe-0001"},
        json={
            "schema_version": 1,
            "command_id": "cmd_refresh_probe",
            "purpose": "GUIDANCE_REFRESH",
            "expected_head_epoch": 1,
        },
    )
    assert response.status_code == 403
    assert any("operability_role_bindings" in statement for statement in statements)
    assert all("guidance_current_heads" not in statement for statement in statements)
    assert all("skill_refresh" not in statement for statement in statements)


def _compile_command(guidance_key: str) -> SkillCompileCommand:
    return SkillCompileCommand(
        guidance_key=guidance_key,
        version="1",
        display_name="Demo skill",
        description="A safe demo skill",
        owner_department="Payments SRE",
        discoverable_departments=("Payments",),
        applicable_service_kinds=("payments",),
        applicable_incident_classes=("availability",),
        symptom_tags=("errors",),
        purpose="incident-investigation",
        classification="INTERNAL",
        eligible_regions=("europe-west1",),
        allowed_agent_keys=("supervisor-agent",),
        required_profile_revisions=("evidence@1",),
        normalized_license_identifier="Apache-2.0",
        author_principal="user:author@example.com",
    )


def test_skill_guidance_keys_require_one_owner_dot_name() -> None:
    assert _compile_command("payments.connection-exhaustion").guidance_key == (
        "payments.connection-exhaustion"
    )
    for invalid in (
        "payments",
        "payments.checkout.retry",
        "payments_checkout",
        "payments..checkout",
        "payments.checkout_retry",
    ):
        with pytest.raises(ValidationError):
            _compile_command(invalid)
        with pytest.raises(ValueError, match="GUIDANCE_KEY_INVALID"):
            skill_name_from_key(invalid)
    assert skill_name_from_key("payments.connection-exhaustion") == "connection-exhaustion"
