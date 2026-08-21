from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from solvan.platform.antigravity_preflight import (
    SDK_DISTRIBUTION_HASH,
    AntigravityPreflightTopology,
)
from tools.antigravity_platform_probes import QUALIFICATION_PROOFS
from tools.qualify_antigravity import QualificationPlan, build_plan, qualify


def _optional() -> AntigravityPreflightTopology:
    return AntigravityPreflightTopology(
        provider_service_name="solvan-antigravity",
        provider_uri="https://solvan-antigravity-123456789012.europe-west1.run.app",
        provider_service_account="antigravity@solvan-demo.iam.gserviceaccount.com",
        coordinator_service_account="coordinator@solvan-demo.iam.gserviceaccount.com",
        provider_revision="antigravity-workspace-20260808-01",
        implementation_sdk="google-antigravity",
        implementation_sdk_version="0.1.13",
        implementation_distribution_hash=SDK_DISTRIBUTION_HASH,
        provider_artifact_digest=f"sha256:{'8' * 64}",
        effective_tool_set_hash=f"sha256:{'1' * 64}",
        effective_network_policy_hash=f"sha256:{'2' * 64}",
        fixture_attester_uri=("https://solvan-fixture-attester-123456789012.europe-west1.run.app"),
        fixture_attester_service_account="attester@solvan-demo.iam.gserviceaccount.com",
        fixture_attester_kms_key_version=(
            "projects/solvan-demo/locations/europe-west1/keyRings/solvan/"
            "cryptoKeys/fixture/cryptoKeyVersions/1"
        ),
        fixture_prefix="gs://runtime/org/project/environment/fixtures/payments-leak-v1/",
        registry_resource="projects/solvan-demo/locations/europe-west1/services/antigravity",
        lifecycle="EXPERIMENT_ONLY",
    )


def test_qualification_is_plan_only_until_apply(monkeypatch, tmp_path: Path) -> None:
    terraform_output = tmp_path / "terraform.json"
    terraform_output.write_text(json.dumps({"placeholder": True}), encoding="utf-8")
    monkeypatch.setattr(
        "tools.qualify_antigravity.topology_from_terraform_output",
        lambda _raw: SimpleNamespace(
            antigravity=_optional(),
            cloud_sql_connection_name="solvan-demo:europe-west1:control",
            service_uris=(("coordinator", "https://coordinator.example.run.app"),),
            evidence_bucket="solvan-demo-evidence",
        ),
    )
    plan = build_plan(
        terraform_output=terraform_output,
        project_id="solvan-demo",
        release_commit="a" * 40,
        deployment_id="deploy-20260808",
        apply=False,
    )
    assert plan.mutation_mode == "PLAN_ONLY"
    assert plan.provider_service_name == "solvan-antigravity"


def test_retry_reconciles_evidence_without_replacing_provider_again(
    monkeypatch, tmp_path: Path
) -> None:
    terraform_output = tmp_path / "terraform.json"
    terraform_output.write_text("{}", encoding="utf-8")
    topology = SimpleNamespace(antigravity=_optional())
    monkeypatch.setattr(
        "tools.qualify_antigravity.topology_from_terraform_output", lambda _raw: topology
    )
    monkeypatch.setattr("tools.qualify_antigravity._identity_token", lambda **_kwargs: "token")
    calls = iter(
        (
            {
                "workspace_id": "wsp_11111111111111111111111111",
                "checkpoint_id": "wck_22222222222222222222222222",
                "provider_service_revision": "revision-before",
                "reconciliation_pending": True,
            },
            {
                "schema_version": 1,
                "request_id": "req_33333333333333333333333333",
                "request_hash": f"sha256:{'1' * 64}",
                "workspace_id": "wsp_11111111111111111111111111",
                "workspace_generation": 1,
                "checkpoint_id": "wck_22222222222222222222222222",
                "provider_revision": _optional().provider_revision,
                "provider_service_revision": "revision-after",
                "provider_boot_hash": f"sha256:{'2' * 64}",
                "implementation_sdk": "google-antigravity",
                "implementation_sdk_version": "0.1.13",
                "implementation_sdk_distribution_hash": SDK_DISTRIBUTION_HASH,
                "provider_artifact_digest": _optional().provider_artifact_digest,
                "input_manifest_ref": "gs://runtime/input.json",
                "input_manifest_hash": f"sha256:{'3' * 64}",
                "artifact_manifest_ref": "gs://runtime/checkpoint.json",
                "artifact_manifest_hash": f"sha256:{'4' * 64}",
                "effective_tool_set_hash": _optional().effective_tool_set_hash,
                "effective_network_policy_hash": _optional().effective_network_policy_hash,
                "trace_id": "5" * 32,
                "span_id": "6" * 16,
            },
        )
    )
    monkeypatch.setattr("tools.qualify_antigravity._post", lambda *_args, **_kwargs: next(calls))
    shell_calls: list[list[str]] = []
    monkeypatch.setattr(
        "tools.qualify_antigravity.subprocess_run",
        lambda arguments: shell_calls.append(arguments) or "",
    )
    monkeypatch.setattr(
        "tools.qualify_antigravity.qualification_preflight",
        lambda *_args, **_kwargs: {name: (True, "reconciled") for name in QUALIFICATION_PROOFS},
    )
    plan = QualificationPlan(
        schema_version=1,
        mutation_mode="APPLY_PROVIDER_REPLACEMENT",
        project_id="solvan-demo",
        release_commit="a" * 40,
        deployment_id="deploy-20260808",
        provider_service_name="solvan-antigravity",
        provider_uri=_optional().provider_uri,
        coordinator_uri="https://coordinator.example.run.app",
        evidence_bucket="evidence",
    )
    result = qualify(
        plan,
        terraform_output=terraform_output,
        acknowledgement=plan.deployment_id,
        output=tmp_path / "qualification.json",
    )
    assert shell_calls == []
    assert all(result["proofs"].values())
