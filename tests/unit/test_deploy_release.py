from __future__ import annotations

import hashlib
import json
from dataclasses import replace
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


def _apply_plan(tmp_path: Path) -> deploy_release.ReleasePlan:
    return replace(
        build_plan(
            project_id="solvan-demo",
            deployment_id="demo-20260822",
            release_version="0.1.0",
            backend_config=tmp_path / "staging.backend.hcl",
            base_tfvars=tmp_path / "staging.tfvars",
            work_dir=tmp_path / "release",
            remote="origin",
            calibration_receipt_uri=None,
            calibration_receipt_hash=None,
            apply=False,
        ),
        mutation_mode="APPLY",
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
    assert "accept_managed_cloud_build" in plan.phases
    assert "build_release_images" not in plan.phases
    assert plan.phases[-1] == "emit_deployed_unverified_receipt"
    generated = initial_release_variables(plan, commit="a" * 40)
    assert generated["release_commit"] == "a" * 40
    assert generated["deployment_id"] == "demo-20260808"
    assert generated["scheduler_paused"] is True
    assert generated["fault_drill_enabled"] is True
    assert set(generated["images"]) == set(IMAGE_NAMES)


def test_release_stops_at_managed_build_boundary_with_durable_checkpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _apply_plan(tmp_path)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        deploy_release,
        "verify_release_source",
        lambda **_kwargs: ("b" * 40, "https://github.com/ruhu-ai/solvan.git"),
    )
    monkeypatch.setattr(
        deploy_release,
        "_run",
        lambda arguments, **_kwargs: commands.append(list(arguments)) or "",
    )
    monkeypatch.setattr(deploy_release, "_terraform", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(
        deploy_release,
        "describe_managed_build_trigger",
        lambda **_kwargs: {
            "trigger_id": "11111111-1111-1111-1111-111111111111",
            "trigger_name": "solvan-staging-release-images",
            "repository_uri": "https://github.com/ruhu-ai/solvan.git",
            "service_account": (
                "projects/solvan-demo/serviceAccounts/"
                "solvan-build@solvan-demo.iam.gserviceaccount.com"
            ),
        },
    )
    receipt = deploy_release.apply_release(
        plan,
        acknowledgement="solvan-demo",
        managed_build_id=None,
        resume=False,
    )

    assert receipt["status"] == "AWAITING_MANAGED_BUILD"
    assert receipt["phases_completed"] == list(plan.phases[:4])
    assert all(arguments[1:3] != ["builds", "submit"] for arguments in commands)
    persisted = json.loads(
        (Path(plan.work_dir) / "deployment-receipt.json").read_text(encoding="utf-8")
    )
    assert persisted["receipt_sha256"].startswith("sha256:")
    assert persisted["phases_completed"] == list(plan.phases[:4])


def test_release_interruption_preserves_last_completed_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _apply_plan(tmp_path)
    monkeypatch.setattr(
        deploy_release,
        "verify_release_source",
        lambda **_kwargs: ("b" * 40, "https://github.com/ruhu-ai/solvan.git"),
    )
    monkeypatch.setattr(deploy_release, "_run", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(
        deploy_release,
        "_terraform",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        deploy_release.apply_release(
            plan,
            acknowledgement="solvan-demo",
            managed_build_id=None,
            resume=False,
        )

    persisted = json.loads(
        (Path(plan.work_dir) / "deployment-receipt.json").read_text(encoding="utf-8")
    )
    assert persisted["status"] == "INTERRUPTED"
    assert persisted["phases_completed"] == list(plan.phases[:2])
    assert persisted["error"] == "KeyboardInterrupt: operator interrupted release"


def test_managed_build_resume_does_not_replay_completed_bootstrap_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _apply_plan(tmp_path)
    work_dir = Path(plan.work_dir)
    receipt_path = work_dir / "deployment-receipt.json"
    trigger = {
        "trigger_id": "11111111-1111-1111-1111-111111111111",
        "trigger_name": "solvan-staging-release-images",
        "repository_uri": "https://github.com/ruhu-ai/solvan.git",
        "service_account": (
            "projects/solvan-demo/serviceAccounts/solvan-build@solvan-demo.iam.gserviceaccount.com"
        ),
    }
    receipt = deploy_release._new_release_receipt(plan)
    for phase in plan.phases[:4]:
        updates = None
        if phase == "verify_clean_published_commit":
            updates = {
                "release_commit": "b" * 40,
                "remote_url": "https://github.com/ruhu-ai/solvan.git",
            }
        elif phase == "create_managed_cloud_build_trigger_identity_and_exact_iam":
            updates = {"managed_build_trigger": trigger}
        deploy_release._complete_release_phase(
            receipt=receipt,
            receipt_path=receipt_path,
            phase=phase,
            updates=updates,
        )
    receipt["status"] = "AWAITING_MANAGED_BUILD"
    deploy_release._write_release_receipt(receipt_path, receipt)
    deploy_release._atomic_json(
        work_dir / "release.auto.tfvars.json",
        deploy_release.initial_release_variables(plan, commit="b" * 40),
    )
    monkeypatch.setattr(
        deploy_release,
        "verify_release_source",
        lambda **_kwargs: ("b" * 40, "https://github.com/ruhu-ai/solvan.git"),
    )
    monkeypatch.setattr(deploy_release, "_run", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(
        deploy_release,
        "_terraform",
        lambda *_args, **_kwargs: pytest.fail("completed Terraform bootstrap replayed"),
    )
    monkeypatch.setattr(deploy_release, "describe_managed_build_trigger", lambda **_kwargs: trigger)
    monkeypatch.setattr(
        deploy_release,
        "resolve_images",
        lambda **_kwargs: (_ for _ in ()).throw(CommandFailure("stop after build handoff")),
    )

    with pytest.raises(CommandFailure, match="stop after build handoff"):
        deploy_release.apply_release(
            plan,
            acknowledgement="solvan-demo",
            managed_build_id="22222222-2222-2222-2222-222222222222",
            resume=True,
        )

    persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert persisted["status"] == "FAILED"
    assert persisted["build_id"] == "22222222-2222-2222-2222-222222222222"
    assert persisted["phases_completed"] == list(plan.phases[:5])


def test_resume_refuses_tampered_checkpoint(tmp_path: Path) -> None:
    plan = _apply_plan(tmp_path)
    receipt_path = Path(plan.work_dir) / "deployment-receipt.json"
    receipt = deploy_release._new_release_receipt(plan)
    deploy_release._complete_release_phase(
        receipt=receipt,
        receipt_path=receipt_path,
        phase=plan.phases[0],
    )
    receipt["status"] = "INTERRUPTED"
    deploy_release._write_release_receipt(receipt_path, receipt)

    resumed = deploy_release._resume_release_receipt(receipt_path, plan=plan)
    assert resumed["attempts"] == 2
    persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
    persisted["phases_completed"] = []
    receipt_path.write_text(json.dumps(persisted), encoding="utf-8")
    with pytest.raises(CommandFailure, match="digest"):
        deploy_release._resume_release_receipt(receipt_path, plan=plan)


def test_catalog_approval_resume_finishes_the_same_ordered_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _apply_plan(tmp_path)
    work_dir = Path(plan.work_dir)
    receipt_path = work_dir / "deployment-receipt.json"
    outputs = {"release_jobs": {"value": {"seed": None}}}
    (work_dir / "terraform-output.json").parent.mkdir(parents=True, exist_ok=True)
    (work_dir / "terraform-output.json").write_text(json.dumps(outputs), encoding="utf-8")
    receipt = deploy_release._new_release_receipt(plan)
    gate_index = plan.phases.index("request_human_catalog_publication_approval")
    for phase in plan.phases[: gate_index + 1]:
        updates = None
        if phase == "verify_clean_published_commit":
            updates = {
                "release_commit": "b" * 40,
                "remote_url": "https://github.com/ruhu-ai/solvan.git",
            }
        elif phase == "bind_runtime_resources_revisions_and_principals":
            updates = {"terraform_output_sha256": deploy_release._canonical_sha256(outputs)}
        elif phase == "evaluate_catalog_with_cloud_deploy":
            updates = {
                "catalog_delivery": {
                    "delivery_pipeline": "solvan-demo-catalog",
                    "release": "cat-bbbbbbbbbb-1111",
                    "publication_rollout": (
                        "projects/solvan-demo/locations/europe-west1/"
                        "deliveryPipelines/solvan-demo-catalog/releases/release/"
                        "rollouts/publication"
                    ),
                }
            }
        deploy_release._complete_release_phase(
            receipt=receipt,
            receipt_path=receipt_path,
            phase=phase,
            updates=updates,
        )
    receipt["status"] = "AWAITING_HUMAN_CATALOG_PUBLICATION_APPROVAL"
    deploy_release._write_release_receipt(receipt_path, receipt)
    monkeypatch.setattr(
        deploy_release,
        "verify_release_source",
        lambda **_kwargs: ("b" * 40, "https://github.com/ruhu-ai/solvan.git"),
    )
    monkeypatch.setattr(deploy_release, "quiesce_schedulers", lambda **_kwargs: ())
    monkeypatch.setattr(
        deploy_release,
        "_catalog_rollouts",
        lambda **_kwargs: [
            {
                "name": "rollouts/publication",
                "approvalState": "APPROVED",
                "state": "SUCCEEDED",
            }
        ],
    )
    monkeypatch.setattr(
        deploy_release,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("no calibration seed is configured"),
    )

    result = deploy_release.resume_after_catalog_approval(plan, acknowledgement="solvan-demo")

    assert result["status"] == "DEPLOYED_UNVERIFIED_SCHEDULERS_PAUSED"
    assert result["phases_completed"] == list(plan.phases)
    assert result["attempts"] == 2


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
                    "buildTriggerId": "11111111-1111-1111-1111-111111111111",
                    "serviceAccount": (
                        "projects/solvan-demo/serviceAccounts/"
                        "solvan-build@solvan-demo.iam.gserviceaccount.com"
                    ),
                    "approval": {
                        "state": "APPROVED",
                        "result": {"decision": "APPROVED"},
                    },
                    "sourceProvenance": {"resolvedGitSource": {"revision": "b" * 40}},
                    "options": {"requestedVerifyOption": "VERIFIED"},
                    "substitutions": {"_RELEASE_COMMIT": "b" * 40},
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
        project_id="solvan-demo",
        build_id="build-1",
        expected_commit="b" * 40,
        expected_trigger_id="11111111-1111-1111-1111-111111111111",
        expected_service_account=(
            "projects/solvan-demo/serviceAccounts/solvan-build@solvan-demo.iam.gserviceaccount.com"
        ),
        images={"api": image},
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
            project_id="solvan-demo",
            build_id="build-1",
            expected_commit="b" * 40,
            expected_trigger_id="11111111-1111-1111-1111-111111111111",
            expected_service_account=(
                "projects/solvan-demo/serviceAccounts/"
                "solvan-build@solvan-demo.iam.gserviceaccount.com"
            ),
            images={},
        )


def test_managed_build_trigger_requires_approval_source_and_dedicated_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trigger = {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "solvan-staging-release-images",
        "serviceAccount": (
            "projects/solvan-demo/serviceAccounts/solvan-build@solvan-demo.iam.gserviceaccount.com"
        ),
        "approvalConfig": {"approvalRequired": True},
        "sourceToBuild": {
            "uri": "https://github.com/ruhu-ai/solvan.git",
            "ref": "refs/heads/main",
            "repoType": "GITHUB",
        },
        "gitFileSource": {
            "path": "cloudbuild.yaml",
            "uri": "https://github.com/ruhu-ai/solvan.git",
            "revision": "refs/heads/main",
            "repoType": "GITHUB",
        },
        "substitutions": {
            "_REGION": "europe-west1",
            "_REPOSITORY": "solvan",
            "_RELEASE_COMMIT": "UNCONFIGURED",
        },
    }
    monkeypatch.setattr(deploy_release, "_run", lambda *_args, **_kwargs: json.dumps(trigger))

    result = deploy_release.describe_managed_build_trigger(
        project_id="solvan-demo",
        region="europe-west1",
        expected_repository_uri="https://github.com/ruhu-ai/solvan.git",
    )

    assert result["trigger_id"] == trigger["id"]
    trigger["approvalConfig"] = {"approvalRequired": False}
    with pytest.raises(CommandFailure, match="trigger does not match"):
        deploy_release.describe_managed_build_trigger(
            project_id="solvan-demo",
            region="europe-west1",
            expected_repository_uri="https://github.com/ruhu-ai/solvan.git",
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
        commit="b" * 40,
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
