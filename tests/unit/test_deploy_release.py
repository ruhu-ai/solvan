from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import tools.deploy_release as deploy_release
from tools.deploy_release import (
    AGENT_KEYS,
    IMAGE_NAMES,
    CommandFailure,
    build_plan,
    initial_release_variables,
    parse_fully_qualified_digest,
    runtime_bindings,
    scheduler_pause_targets,
    validate_staging_configuration,
)


def test_release_plan_is_non_mutating_by_default(tmp_path: Path) -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260808",
        release_version="0.1.0",
        backend_config=tmp_path / "missing.backend",
        base_tfvars=tmp_path / "missing.tfvars",
        work_dir=tmp_path / "release",
        remote="origin",
        calibration_receipt_uri=None,
        calibration_receipt_hash=None,
        apply=False,
    )
    assert plan.mutation_mode == "PLAN_ONLY"
    assert len(IMAGE_NAMES) == 30
    assert "build_release_images" in plan.phases
    assert plan.phases[-1] == "emit_deployed_unverified_receipt"
    generated = initial_release_variables(plan, commit="a" * 40)
    assert generated["release_commit"] == "a" * 40
    assert generated["deployment_id"] == "demo-20260808"
    assert generated["scheduler_paused"] is True
    assert generated["fault_drill_enabled"] is True
    assert set(generated["images"]) == set(IMAGE_NAMES)


def test_every_running_tick_is_paused_before_any_image_rolls(tmp_path: Path) -> None:
    """A scheduler job depends on the service URI it calls, so Terraform updates
    the service first and pauses the job second. On an in-place upgrade that
    would let a live tick drive one revision against another across the strict
    sandbox contract, so the release quiesces the ticks in its own phase before
    the platform apply. A tick already running still finishes, so this bounds
    the exposure by one attempt deadline; it does not remove it.
    """

    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260808",
        release_version="0.1.0",
        backend_config=tmp_path / "missing.backend",
        base_tfvars=tmp_path / "missing.tfvars",
        work_dir=tmp_path / "release",
        remote="origin",
        calibration_receipt_uri=None,
        calibration_receipt_hash=None,
        apply=False,
    )
    phases = list(plan.phases)
    assert phases.index("pause_automated_work_before_any_image_rolls") < phases.index(
        "apply_platform_with_schedulers_paused"
    )

    location = "projects/solvan-demo/locations/europe-west1/jobs"
    assert scheduler_pause_targets(
        [
            {"name": f"{location}/solvan-case-wakeups", "state": "ENABLED"},
            {"name": f"{location}/solvan-outbox-publisher", "state": "PAUSED"},
            {"name": f"{location}/solvan-detector-burst", "state": "UPDATE_FAILED"},
            {"name": f"{location}/solvan-trigger-tick"},
        ]
    ) == ("solvan-case-wakeups", "solvan-detector-burst", "solvan-trigger-tick")

    assert scheduler_pause_targets([]) == ()
    with pytest.raises(CommandFailure, match="unnamed job"):
        scheduler_pause_targets([{"state": "ENABLED"}])
    with pytest.raises(CommandFailure, match="not a list"):
        scheduler_pause_targets({"jobs": []})


def test_release_plan_requires_paired_calibration_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="supplied together"):
        build_plan(
            project_id="solvan-demo",
            deployment_id="demo-20260808",
            release_version="0.1.0",
            backend_config=tmp_path / "backend",
            base_tfvars=tmp_path / "tfvars",
            work_dir=tmp_path,
            remote="origin",
            calibration_receipt_uri="gs://evidence/calibration.json",
            calibration_receipt_hash=None,
            apply=False,
        )


def test_release_apply_rejects_dev_backend_and_tfvars(tmp_path: Path) -> None:
    backend = tmp_path / "dev.tfbackend"
    backend.write_text('bucket = "state"\nprefix = "solvan/dev"\n', encoding="utf-8")
    variables = tmp_path / "dev.tfvars"
    variables.write_text('project_id = "solvan-demo"\nenvironment = "dev"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="backend prefix must be solvan/staging"):
        build_plan(
            project_id="solvan-demo",
            deployment_id="demo-20260808",
            release_version="0.1.0",
            backend_config=backend,
            base_tfvars=variables,
            work_dir=tmp_path,
            remote="origin",
            calibration_receipt_uri=None,
            calibration_receipt_hash=None,
            apply=True,
        )


def test_release_apply_refuses_unconfigured_catalog_policy_before_cloud_work(
    tmp_path: Path,
) -> None:
    backend = tmp_path / "staging.backend.hcl"
    backend.write_text('prefix = "solvan/staging"\n', encoding="utf-8")
    variables = tmp_path / "staging.tfvars"
    variables.write_text(
        "\n".join(
            (
                'project_id = "solvan-demo"',
                'environment = "staging"',
                'catalog_network_policy_hash = "UNCONFIGURED"',
                'approver_principals = ["user:approver@example.com"]',
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="catalog_network_policy_hash"):
        validate_staging_configuration(
            backend_config=backend,
            base_tfvars=variables,
            project_id="solvan-demo",
        )


def test_release_apply_accepts_checked_in_policy_and_human_approver(tmp_path: Path) -> None:
    backend = tmp_path / "staging.backend.hcl"
    backend.write_text('prefix = "solvan/staging"\n', encoding="utf-8")
    variables = tmp_path / "staging.tfvars"
    variables.write_text(
        "\n".join(
            (
                'project_id = "solvan-demo"',
                'environment = "staging"',
                'catalog_network_policy_hash = "sha256:'
                + hashlib.sha256(
                    (
                        deploy_release.ROOT / "specs/artifacts/catalog-network-policy.v1.json"
                    ).read_bytes()
                ).hexdigest()
                + '"',
                'approver_principals = ["user:approver@example.com"]',
            )
        ),
        encoding="utf-8",
    )

    validate_staging_configuration(
        backend_config=backend,
        base_tfvars=variables,
        project_id="solvan-demo",
    )


def test_artifact_response_resolves_only_expected_digest() -> None:
    repository = "europe-west1-docker.pkg.dev/solvan-demo/solvan/api"
    digest = "sha256:" + "a" * 64
    assert (
        parse_fully_qualified_digest(
            {"image_summary": {"digest": digest}}, expected_repository=repository
        )
        == f"{repository}@{digest}"
    )
    with pytest.raises(ValueError, match="matching immutable"):
        parse_fully_qualified_digest(
            {"image_summary": {"fully_qualified_digest": f"elsewhere/api@{digest}"}},
            expected_repository=repository,
        )


def test_build_supply_chain_requires_verified_provenance_and_project_attestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "europe-west1-docker.pkg.dev/solvan-demo/solvan/api@sha256:" + "a" * 64
    calls: list[list[str]] = []

    def fake_run(arguments: list[str]) -> str:
        calls.append(arguments)
        if arguments[1:3] == ["builds", "describe"]:
            return json.dumps(
                {
                    "status": "SUCCESS",
                    "options": {"requestedVerifyOption": "VERIFIED"},
                    "results": {
                        "images": [
                            {
                                "name": image.split("@", 1)[0] + ":build-1",
                                "digest": image.split("@", 1)[1],
                            }
                        ]
                    },
                }
            )
        return "{}"

    monkeypatch.setattr(deploy_release, "_run", fake_run)
    deploy_release.verify_build_supply_chain(
        project_id="solvan-demo", build_id="build-1", images={"api": image}
    )
    assert calls[-1][1:5] == ["container", "binauthz", "attestors", "describe"]


def test_build_supply_chain_refuses_unverified_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deploy_release,
        "_run",
        lambda _arguments: '{"status":"SUCCESS","options":{},"results":{"images":[]}}',
    )
    with pytest.raises(CommandFailure, match="verified-provenance"):
        deploy_release.verify_build_supply_chain(
            project_id="solvan-demo", build_id="build-1", images={}
        )


def test_runtime_receipt_binds_exact_six_agents() -> None:
    resources = [
        {
            "agent_key": external,
            "immutable_resource_name": (
                f"projects/123/locations/europe-west1/reasoningEngines/{internal}"
            ),
            "iam_principal": (
                "principal://agents.global.project-123.system.id.goog/resources/"
                f"aiplatform/projects/123/locations/europe-west1/reasoningEngines/{internal}"
            ),
        }
        for external, internal in AGENT_KEYS.items()
    ]
    bindings = runtime_bindings(
        {
            "status": "DEPLOYED_UNVERIFIED",
            "plan": {
                "location": "europe-west1",
                "model_location": "eu",
                "model_endpoint": "https://aiplatform.eu.rep.googleapis.com",
                "release_version": "0.1.0",
                "targets": [
                    {"agent_key": external, "model_resource": "gemini-3.6-flash"}
                    for external in AGENT_KEYS
                ],
            },
            "resources": resources,
        },
        release_version="0.1.0",
    )
    assert set(bindings["agent_runtime_resources"]) == set(AGENT_KEYS.values())
    assert bindings["agent_runtime_revisions"]["workspace_agent"] == "0.1.0"
    assert bindings["execution_agent_principal"].startswith("principal://")
    assert bindings["incident_supervisor_agent_principal"].startswith("principal://")
    assert bindings["workspace_agent_principal"].startswith("principal://")


def test_runtime_deploy_binds_workspace_agent_to_coordinator_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260821",
        release_version="0.1.0",
        backend_config=tmp_path / "backend",
        base_tfvars=tmp_path / "tfvars",
        work_dir=tmp_path / "release",
        remote="origin",
        calibration_receipt_uri=None,
        calibration_receipt_hash=None,
        apply=False,
    )
    receipt_path = tmp_path / "agent-runtime-deployment.json"
    commands: list[list[str]] = []

    def fake_run(command: list[str], *, timeout: int = 600) -> str:
        del timeout
        commands.append(command)
        receipt_path.write_text('{"status":"DEPLOYED_UNVERIFIED"}', encoding="utf-8")
        return ""

    monkeypatch.setattr(deploy_release, "_run", fake_run)
    result = deploy_release._deploy_agents(
        plan=plan,
        outputs={
            "agent_gateway_resources": {
                "value": {
                    "egress": "projects/solvan-demo/locations/europe-west1/gateways/egress",
                    "ingress": "projects/solvan-demo/locations/europe-west1/gateways/ingress",
                }
            },
            "runtime_bucket": {"value": "solvan-runtime"},
            "service_uris": {
                "value": {
                    "actuator": "https://actuator.example",
                    "coordinator": "https://coordinator.example",
                    "evidence": "https://evidence.example",
                    "verifier": "https://verifier.example",
                }
            },
        },
        receipt_path=receipt_path,
    )

    assert result["status"] == "DEPLOYED_UNVERIFIED"
    assert "--workspace-tool-broker-url=https://coordinator.example" in commands[0]


def test_runtime_receipt_rejects_model_location_drift() -> None:
    with pytest.raises(ValueError, match="model routing"):
        runtime_bindings(
            {
                "status": "DEPLOYED_UNVERIFIED",
                "plan": {
                    "location": "europe-west1",
                    "model_location": "global",
                    "model_endpoint": "https://aiplatform.googleapis.com",
                    "release_version": "0.1.0",
                },
            },
            release_version="0.1.0",
        )


def test_catalog_release_supplies_minimal_skaffold_for_custom_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260821",
        release_version="0.1.0",
        backend_config=tmp_path / "backend",
        base_tfvars=tmp_path / "tfvars",
        work_dir=tmp_path / "release",
        remote="origin",
        calibration_receipt_uri=None,
        calibration_receipt_hash=None,
        apply=False,
    )
    publication_target = "solvan-demo-catalog-publication"
    rollout_calls = 0

    monkeypatch.setattr(deploy_release, "_run_allowing", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        deploy_release,
        "_wait_catalog_evaluation",
        lambda **_kwargs: {"name": "evaluation-rollout"},
    )

    def fake_rollouts(**_kwargs: object) -> list[dict[str, str]]:
        nonlocal rollout_calls
        rollout_calls += 1
        if rollout_calls == 1:
            return []
        return [
            {
                "targetId": publication_target,
                "approvalState": "NEEDS_APPROVAL",
                "name": "projects/solvan-demo/locations/europe-west1/rollouts/publication",
            }
        ]

    monkeypatch.setattr(deploy_release, "_catalog_rollouts", fake_rollouts)

    def fake_run(arguments: list[str], **_kwargs: object) -> str:
        if arguments[1:4] == ["deploy", "releases", "create"]:
            release_id = arguments[4]
            assert release_id == "cat-bbbbbbbbbb-a36dc"
            assert "--enable-initial-rollout" in arguments
            assert len(f"{release_id}-to-solvan-demo-catalog-evaluation-0001") <= 63
            assert len(f"{release_id}-to-{publication_target}-0001") <= 63
            source_argument = next(item for item in arguments if item.startswith("--source="))
            source = Path(source_argument.split("=", maxsplit=1)[1])
            assert (source / "skaffold.yaml").read_text(encoding="utf-8") == (
                "apiVersion: skaffold/v4beta7\nkind: Config\n"
            )
            assert json.loads((source / "release.json").read_text(encoding="utf-8")) == {
                "catalog_subject_hash": "sha256:" + "a" * 64,
                "schema_version": 1,
            }
        return ""

    monkeypatch.setattr(deploy_release, "_run", fake_run)
    result = deploy_release.start_catalog_delivery(
        plan=plan,
        commit="b" * 40,
        outputs={
            "catalog_delivery": {
                "value": {
                    "delivery_pipeline": "solvan-demo-catalog",
                    "evaluation_target": "solvan-demo-catalog-evaluation",
                    "publication_target": publication_target,
                    "catalog_subject_hash": "sha256:" + "a" * 64,
                    "network_policy_hash": "sha256:" + "c" * 64,
                }
            }
        },
    )

    assert result["publication_approval_state"] == "NEEDS_APPROVAL"


def test_catalog_release_refuses_automatic_rollout_id_over_google_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260821",
        release_version="0.1.0",
        backend_config=tmp_path / "backend",
        base_tfvars=tmp_path / "tfvars",
        work_dir=tmp_path / "release",
        remote="origin",
        calibration_receipt_uri=None,
        calibration_receipt_hash=None,
        apply=False,
    )
    monkeypatch.setattr(
        deploy_release,
        "_run_allowing",
        lambda *_args, **_kwargs: pytest.fail("release lookup must not run"),
    )

    with pytest.raises(deploy_release.CommandFailure, match="63-character limit"):
        deploy_release.start_catalog_delivery(
            plan=plan,
            commit="b" * 40,
            outputs={
                "catalog_delivery": {
                    "value": {
                        "delivery_pipeline": "solvan-demo-catalog",
                        "evaluation_target": "evaluation-" + "x" * 50,
                        "publication_target": "solvan-demo-catalog-publication",
                        "catalog_subject_hash": "sha256:" + "a" * 64,
                        "network_policy_hash": "sha256:" + "c" * 64,
                    }
                }
            },
        )
