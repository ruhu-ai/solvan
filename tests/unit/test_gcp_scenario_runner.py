from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.unit.test_platform_preflight import COMMIT, PROJECT
from tools.run_gcp_scenarios import _execute_job, _human_token, _scenario_run_id, build_plan
from tools.scripted_scenario_contracts import SCRIPTED_ASSERTIONS, validate_scenario_run_id


def _token(*, audience: str, expires_at: int | None = None) -> str:
    def encoded(value: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return ".".join(
        (
            encoded({"alg": "RS256", "typ": "JWT"}),
            encoded(
                {
                    "aud": audience,
                    "exp": expires_at or int(time.time()) + 3600,
                    "email": "approver@example.com",
                    "email_verified": True,
                }
            ),
            "signature",
        )
    )


def test_cloud_scenario_plan_is_non_mutating_and_s1_only_by_default(tmp_path: Path) -> None:
    plan = build_plan(
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
        terraform_output=tmp_path / "missing-output.json",
        preflight_receipt=tmp_path / "missing-preflight.json",
        human_identity_token_file=None,
        output_dir=tmp_path / "evidence",
        scenarios=("S1",),
        apply=False,
    )
    assert plan.mutation_mode == "PLAN_ONLY"
    assert plan.scenarios == ("S1",)
    assert "execute_non_agent_fault_injector_job" in plan.phases


def test_human_token_is_bound_to_exact_deployed_oauth_audience(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text(_token(audience="client.apps.googleusercontent.com"), encoding="utf-8")
    assert _human_token(path, expected_audience="client.apps.googleusercontent.com").count(".") == 2
    with pytest.raises(ValueError, match="audience differs"):
        _human_token(path, expected_audience="other.apps.googleusercontent.com")


def test_s1_apply_requires_out_of_band_human_token_file(tmp_path: Path) -> None:
    terraform = tmp_path / "terraform.json"
    preflight = tmp_path / "preflight.json"
    terraform.write_text("{}", encoding="utf-8")
    preflight.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="one-time human identity token"):
        build_plan(
            project_id=PROJECT,
            release_commit=COMMIT,
            deployment_id="deploy-20260808",
            terraform_output=terraform,
            preflight_receipt=preflight,
            human_identity_token_file=None,
            output_dir=tmp_path / "evidence",
            scenarios=("S1",),
            apply=True,
        )


def test_scripted_apply_does_not_require_an_unrelated_s1_human_token(tmp_path: Path) -> None:
    terraform = tmp_path / "terraform.json"
    preflight = tmp_path / "preflight.json"
    terraform.write_text("{}", encoding="utf-8")
    preflight.write_text("{}", encoding="utf-8")
    plan = build_plan(
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
        terraform_output=terraform,
        preflight_receipt=preflight,
        human_identity_token_file=None,
        output_dir=tmp_path / "evidence",
        scenarios=("S2", "S3", "S4"),
        apply=True,
    )
    assert plan.scenarios == ("S2", "S3", "S4")
    assert "execute_isolated_scripted_gcp_fixture_jobs" in plan.phases
    assert "pause_at_exact_human_approval" not in plan.phases


def test_scripted_job_execution_binds_operation_and_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[str] = []

    def run(command: list[str], **_kwargs: object):  # type: ignore[no-untyped-def]
        captured.extend(command)
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("tools.run_gcp_scenarios.subprocess.run", run)
    assert _execute_job(
        job_name="solvan-scenario",
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
        object_name="scenarios/deploy/S2/fixture.json",
        args_override="scenario-inject-s2",
        scenario_run_id="deploy-20260808-s2",
    )
    assert "--args=scenario-inject-s2" in captured
    environment = next(item for item in captured if item.startswith("--update-env-vars="))
    assert "SOLVAN_SCENARIO_RUN_ID=deploy-20260808-s2" in environment


def test_scripted_cloud_oracles_have_stable_fail_closed_contracts() -> None:
    assert set(SCRIPTED_ASSERTIONS) == {"S2", "S3", "S4", "S5", "S6"}
    assert all(
        len(names) >= 3 and len(names) == len(set(names)) for names in SCRIPTED_ASSERTIONS.values()
    )
    assert validate_scenario_run_id("deploy-20260808-s2") == "deploy-20260808-s2"
    with pytest.raises(RuntimeError, match="not canonical"):
        validate_scenario_run_id("../foreign")


def test_scripted_run_id_remains_canonical_for_maximum_deployment_id() -> None:
    value = _scenario_run_id(
        deployment_id="d" + "a" * 62,
        scenario_id="S6",
        started_at=datetime(2026, 8, 8, 12, tzinfo=UTC),
    )
    assert len(value) <= 64
    assert validate_scenario_run_id(value) == value
