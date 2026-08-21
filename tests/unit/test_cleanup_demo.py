from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.test_platform_preflight import COMMIT, PROJECT
from tools.cleanup_demo import _pause_schedulers, apply, build_plan


def test_cleanup_is_plan_only_without_existing_cloud_artifacts(tmp_path: Path) -> None:
    plan = build_plan(
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
        terraform_output=tmp_path / "missing.json",
        output=tmp_path / "cleanup.json",
        apply=False,
    )
    assert plan.mutation_mode == "PLAN_ONLY"
    assert plan.phases[-1] == "leave_schedulers_paused_for_operator_reconciliation"


def test_cleanup_apply_requires_exact_deployment_acknowledgement(tmp_path: Path) -> None:
    plan = build_plan(
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
        terraform_output=tmp_path / "terraform.json",
        output=tmp_path / "cleanup.json",
        apply=False,
    )
    with pytest.raises(ValueError, match="exactly equal"):
        apply(plan, acknowledgement="another-deployment")


def test_cleanup_pauses_only_the_exact_terraform_scheduler_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def run(arguments: list[str], **_kwargs: object) -> str:
        commands.append(arguments)
        return "PAUSED\n" if "describe" in arguments else ""

    monkeypatch.setattr("tools.cleanup_demo._run", run)
    schedulers = {f"job-{index}": f"solvan-job-{index}" for index in range(4)}
    states = _pause_schedulers(schedulers=schedulers, project_id=PROJECT)
    assert set(states.values()) == {"PAUSED"}
    paused = [command for command in commands if "pause" in command]
    assert {command[4] for command in paused} == set(schedulers.values())
