from __future__ import annotations

import json
from pathlib import Path

import httpx

from solvan.platform.antigravity_preflight import (
    SDK_DISTRIBUTION_HASH,
    AntigravityPreflightTopology,
)
from tools.antigravity_platform_probes import (
    QUALIFICATION_PROOFS,
    provider_preflight,
    qualification_preflight,
)


def _topology() -> AntigravityPreflightTopology:
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


def test_provider_preflight_derives_security_proofs_from_live_receipt(monkeypatch) -> None:
    topology = _topology()

    def post(url: str, **kwargs) -> httpx.Response:
        nonce = kwargs["json"]["nonce"]
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "schema_version": 1,
                "nonce": nonce,
                "provider_revision": topology.provider_revision,
                "provider_service_revision": "service-revision-2",
                "provider_boot_hash": f"sha256:{'3' * 64}",
                "sdk_version": "0.1.13",
                "sdk_distribution_hash": SDK_DISTRIBUTION_HASH,
                "enabled_builtin_tools": ["finish"],
                "enabled_custom_tools": [
                    "read_workspace_artifact",
                    "write_candidate_artifact",
                ],
                "observations": {
                    "sdk_version_matches": True,
                    "sdk_distribution_matches": True,
                    "network_policy_matches": True,
                    "custom_tool_set_exact": True,
                    "gcs_authority_denied": True,
                    "cloud_sql_authority_denied": True,
                    "secret_authority_denied": True,
                    "external_egress_denied": True,
                    "undeclared_builtin_tools_denied": True,
                    "model_armor_injection_denied": True,
                    "hosting_region_europe_west1": True,
                    "model_location_global": True,
                    "deep_workspace_model_exact": True,
                },
            },
        )

    monkeypatch.setattr(httpx, "post", post)
    results = provider_preflight(topology, run=lambda _arguments: "identity-token\n")
    assert len(results) == 6
    assert all(passed for passed, _detail in results.values())


def test_qualification_recomputes_revision_and_hash_continuity(tmp_path: Path) -> None:
    topology = _topology()
    source = tmp_path / "source.json"
    manifest_hash = f"sha256:{'4' * 64}"
    artifact_hash = f"sha256:{'5' * 64}"
    value = {
        "schema_version": 1,
        "kind": "ANTIGRAVITY_QUALIFICATION",
        "project_id": "solvan-demo",
        "release_commit": "a" * 40,
        "deployment_id": "deploy-20260808",
        "provider_revision": topology.provider_revision,
        "provider_service_revision_before": "revision-1",
        "provider_service_revision_after": "revision-2",
        "provider_boot_hash_before": f"sha256:{'6' * 64}",
        "provider_boot_hash_after": f"sha256:{'7' * 64}",
        "input_manifest_hash_before": manifest_hash,
        "input_manifest_hash_after": manifest_hash,
        "artifact_manifest_hash_before": artifact_hash,
        "artifact_manifest_hash_after": artifact_hash,
        "effective_tool_set_hash_before": topology.effective_tool_set_hash,
        "effective_tool_set_hash_after": topology.effective_tool_set_hash,
        "effective_network_policy_hash_before": topology.effective_network_policy_hash,
        "effective_network_policy_hash_after": topology.effective_network_policy_hash,
        "implementation_sdk_distribution_hash_before": SDK_DISTRIBUTION_HASH,
        "implementation_sdk_distribution_hash_after": SDK_DISTRIBUTION_HASH,
        "provider_artifact_digest_before": topology.provider_artifact_digest,
        "provider_artifact_digest_after": topology.provider_artifact_digest,
        "proofs": {name: True for name in QUALIFICATION_PROOFS},
        "evidence_refs": ["gs://evidence/qualification/source.json"],
    }
    source.write_text(json.dumps(value), encoding="utf-8")

    def copy(arguments: list[str]) -> str:
        Path(arguments[-2]).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        return ""

    results = qualification_preflight(
        topology,
        bucket="evidence",
        project_id="solvan-demo",
        release_commit="a" * 40,
        deployment_id="deploy-20260808",
        work_dir=tmp_path,
        run=copy,
    )
    assert set(results) == QUALIFICATION_PROOFS
    assert all(passed for passed, _detail in results.values())


def test_qualification_rejects_hash_continuity_overclaim(tmp_path: Path) -> None:
    topology = _topology()
    source = tmp_path / "source.json"
    base = {
        "schema_version": 1,
        "kind": "ANTIGRAVITY_QUALIFICATION",
        "project_id": "solvan-demo",
        "release_commit": "a" * 40,
        "deployment_id": "deploy-20260808",
        "provider_revision": topology.provider_revision,
        "provider_service_revision_before": "revision-1",
        "provider_service_revision_after": "revision-2",
        "provider_boot_hash_before": f"sha256:{'3' * 64}",
        "provider_boot_hash_after": f"sha256:{'4' * 64}",
        "input_manifest_hash_before": f"sha256:{'5' * 64}",
        "input_manifest_hash_after": f"sha256:{'6' * 64}",
        "artifact_manifest_hash_before": f"sha256:{'7' * 64}",
        "artifact_manifest_hash_after": f"sha256:{'7' * 64}",
        "effective_tool_set_hash_before": topology.effective_tool_set_hash,
        "effective_tool_set_hash_after": topology.effective_tool_set_hash,
        "effective_network_policy_hash_before": topology.effective_network_policy_hash,
        "effective_network_policy_hash_after": topology.effective_network_policy_hash,
        "implementation_sdk_distribution_hash_before": SDK_DISTRIBUTION_HASH,
        "implementation_sdk_distribution_hash_after": SDK_DISTRIBUTION_HASH,
        "provider_artifact_digest_before": topology.provider_artifact_digest,
        "provider_artifact_digest_after": topology.provider_artifact_digest,
        "proofs": {name: True for name in QUALIFICATION_PROOFS},
        "evidence_refs": ["gs://evidence/source.json"],
    }
    source.write_text(json.dumps(base), encoding="utf-8")

    def copy(arguments: list[str]) -> str:
        Path(arguments[-2]).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        return ""

    results = qualification_preflight(
        topology,
        bucket="evidence",
        project_id="solvan-demo",
        release_commit="a" * 40,
        deployment_id="deploy-20260808",
        work_dir=tmp_path,
        run=copy,
    )
    assert results["antigravity_checkpoint_rehydrated_new_boot"][0] is False
    assert results["antigravity_revision_continuity_preserved"][0] is False
