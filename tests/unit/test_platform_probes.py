from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from solvan.platform.preflight import _REQUIRED_PROOFS
from tools.run_platform_probes import (
    _cloud_run_health,
    _members,
    _workspace_sandbox_launcher,
    build_plan,
)


def test_platform_probe_plan_is_non_mutating_by_default(tmp_path: Path) -> None:
    plan = build_plan(
        project_id="solvan-demo",
        release_commit="a" * 40,
        deployment_id="deploy-20260808",
        terraform_output=tmp_path / "missing.json",
        output=tmp_path / "proofs.json",
        apply=False,
    )
    assert plan.mutation_mode == "PLAN_ONLY"
    assert set(plan.required_proofs) == _REQUIRED_PROOFS


def test_platform_probe_apply_requires_real_terraform_output(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        build_plan(
            project_id="solvan-demo",
            release_commit="a" * 40,
            deployment_id="deploy-20260808",
            terraform_output=tmp_path / "missing.json",
            output=tmp_path / "proofs.json",
            apply=True,
        )


def test_iap_policy_members_extracts_only_egressors() -> None:
    assert _members(
        {
            "policy": {
                "bindings": [
                    {"role": "roles/iap.egressor", "members": ["principal://agent"]},
                    {"role": "roles/viewer", "members": ["user:owner@example.com"]},
                ]
            }
        }
    ) == {"principal://agent"}


def test_cloud_run_health_accepts_google_generated_alias_for_canonical_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "tools.run_platform_probes._gcloud_json",
        lambda arguments: [
            {
                "metadata": {"name": "solvan-staging-api"},
                "status": {
                    "url": "https://solvan-staging-api-vlhy2vgmeq-ew.a.run.app",
                    "latestReadyRevisionName": "solvan-staging-api-00002-abc",
                    "latestCreatedRevisionName": "solvan-staging-api-00002-abc",
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            }
        ],
    )
    topology = SimpleNamespace(
        service_uris=(
            (
                "api",
                "https://solvan-staging-api-599862894051.europe-west1.run.app",
            ),
        )
    )

    passed, detail = _cloud_run_health(topology, "solvan-staging")  # type: ignore[arg-type]

    assert passed is True
    assert detail["services"]["api"] == {
        "ready": True,
        "uri_matches": True,
        "latest_revision_ready": True,
    }


@pytest.mark.parametrize(("observed", "passed"), [(True, True), (False, False)])
def test_workspace_sandbox_probe_observes_live_launcher_field(
    monkeypatch: pytest.MonkeyPatch, observed: bool, passed: bool
) -> None:
    seen: list[list[str]] = []

    def describe(arguments: list[str], *, timeout: int = 600) -> object:
        assert timeout == 600
        seen.append(arguments)
        return {"spec": {"template": {"containers": [{"sandboxLauncher": observed}]}}}

    monkeypatch.setattr("tools.run_platform_probes._gcloud_json", describe)
    topology = SimpleNamespace(
        service_uris=(
            (
                "workspace_sandbox",
                "https://solvan-staging-workspace-sandbox-123456789012.europe-west1.run.app",
            ),
        )
    )
    result, detail = _workspace_sandbox_launcher(topology, "solvan-demo")  # type: ignore[arg-type]
    assert result is passed
    assert detail == {
        "service": "solvan-staging-workspace-sandbox",
        "sandbox_launcher": observed,
    }
    assert seen[0][:5] == [
        "beta",
        "run",
        "services",
        "describe",
        "solvan-staging-workspace-sandbox",
    ]
