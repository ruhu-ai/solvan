from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from solvan.platform import (
    evaluate_platform_preflight,
    parse_platform_preflight_receipt,
    topology_from_terraform_output,
)
from solvan.platform.antigravity_preflight import ANTIGRAVITY_PROOFS
from solvan.platform.preflight import _REQUIRED_APIS, _REQUIRED_PROOFS
from tools.run_platform_preflight import load_proofs

COMMIT = "a" * 40
PROJECT = "solvan-demo"
PROJECT_NUMBER = "123456789012"
REGION = "europe-west1"


def terraform_output() -> dict[str, object]:
    agents = {
        name: f"projects/{PROJECT}/locations/{REGION}/reasoningEngines/{name}-1"
        for name in (
            "workspace_agent",
            "evidence_agent",
            "execution_agent",
            "incident_supervisor",
            "infrastructure_agent",
            "verification_agent",
        )
    }
    principals = {
        name: (
            "principal://agents.global.project-123456789012.system.id.goog/"
            f"resources/aiplatform/projects/{PROJECT_NUMBER}/locations/{REGION}/"
            f"reasoningEngines/{name}-1"
        )
        for name in agents
    }
    services = {
        name: f"https://solvan-{name.replace('_', '-')}-123456789012.{REGION}.run.app"
        for name in (
            "actuator",
            "api",
            "console",
            "coordinator",
            "detector",
            "evidence",
            "memory",
            "payments",
            "publisher",
            "verifier",
            "workspace_sandbox",
        )
    }
    registered = {
        name: f"projects/{PROJECT}/locations/{REGION}/services/{name}"
        for name in (
            "actuator",
            "aiplatform",
            "aiplatform_mtls",
            "aiplatform_rep",
            "aiplatform_eu_rep",
            "evidence",
            "logging",
            "monitoring",
            "payments",
            "resource_manager",
            "resource_manager_mtls",
            "telemetry",
            "telemetry_mtls",
            "verifier",
        )
    }
    return {
        "region": {"value": REGION},
        "required_services": {"value": sorted(_REQUIRED_APIS)},
        "cloud_sql_connection_name": {"value": f"{PROJECT}:{REGION}:control"},
        "service_uris": {"sensitive": True, "value": services},
        "evidence_bucket": {"value": "solvan-demo-evidence"},
        "runtime_bucket": {"value": "solvan-demo-runtime"},
        "agent_gateway_resources": {
            "value": {
                "egress": f"projects/{PROJECT}/locations/{REGION}/gateways/egress",
                "ingress": f"projects/{PROJECT}/locations/{REGION}/gateways/ingress",
            }
        },
        "gateway_policy_resources": {
            "value": {
                "iap_extension": f"projects/{PROJECT}/locations/{REGION}/extensions/iap",
                "iap_egress_policy": (f"projects/{PROJECT}/locations/{REGION}/policies/iap-egress"),
                "iap_ingress_policy": (
                    f"projects/{PROJECT}/locations/{REGION}/policies/iap-ingress"
                ),
                "model_armor_extension": (
                    f"projects/{PROJECT}/locations/{REGION}/extensions/model-armor"
                ),
                "model_armor_policy": (
                    f"projects/{PROJECT}/locations/{REGION}/policies/model-armor"
                ),
            }
        },
        "gateway_policy_status": {
            "value": {
                "iap": "ENFORCED",
                "inline_model_armor": "ENFORCED",
                "in_process_model_armor": "ENFORCED_FAIL_CLOSED",
            }
        },
        "model_armor_template": {
            "value": f"projects/{PROJECT}/locations/{REGION}/templates/agent-boundary"
        },
        "fast_fleet_inference": {
            "value": {
                "model_resource": "gemini-3.6-flash",
                "location": "eu",
                "endpoint": "https://aiplatform.eu.rep.googleapis.com",
            }
        },
        "registered_endpoints": {"value": registered},
        "agent_runtime_resources": {"value": agents},
        "agent_runtime_revisions": {"value": {name: f"release-{COMMIT[:12]}" for name in agents}},
        "agent_runtime_principals": {"value": principals},
        "scenario_identities": {
            "value": {
                "injector": f"solvan-injector@{PROJECT}.iam.gserviceaccount.com",
                "oracle": f"solvan-oracle@{PROJECT}.iam.gserviceaccount.com",
            }
        },
        "antigravity_workspace_provider": {
            "value": {
                "enabled": False,
                "service_name": None,
                "uri": None,
                "service_account": (f"solvan-antigravity@{PROJECT}.iam.gserviceaccount.com"),
                "coordinator_service_account": (
                    f"solvan-coordinator@{PROJECT}.iam.gserviceaccount.com"
                ),
                "provider_revision": "antigravity-workspace-20260808-01",
                "implementation_sdk": "google-antigravity",
                "implementation_sdk_version": "0.1.13",
                "implementation_distribution_hash": (
                    "sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992"
                ),
                "provider_artifact_digest": f"sha256:{'8' * 64}",
                "effective_tool_set_hash": f"sha256:{'1' * 64}",
                "effective_network_policy_hash": f"sha256:{'2' * 64}",
            }
        },
        "synthetic_fixture_attester": {"value": None},
        "antigravity_workspace_registry_binding": {"value": None},
    }


def test_preflight_pass_requires_exact_live_topology_and_all_proofs() -> None:
    topology = topology_from_terraform_output(terraform_output())
    receipt = evaluate_platform_preflight(
        topology=topology,
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        deployment_id="deploy-20260808",
        observed_at=datetime(2026, 8, 8, tzinfo=UTC),
        billing_enabled=True,
        enabled_apis=_REQUIRED_APIS,
        proof_results={proof: True for proof in _REQUIRED_PROOFS},
        evidence_refs=("gs://solvan-demo-evidence/preflight/receipt.json",),
    )
    assert receipt.status == "PASS"
    assert receipt.reason_codes == ()
    assert receipt.content_hash.startswith("sha256:")

    parsed = parse_platform_preflight_receipt(receipt.canonical_dict())
    assert parsed == receipt


def test_preflight_records_scoped_inline_model_armor_degradation_with_iap_enforced() -> None:
    output = terraform_output()
    output["gateway_policy_resources"]["value"]["model_armor_policy"] = None
    output["gateway_policy_status"]["value"]["inline_model_armor"] = (
        "DEGRADED_GOOGLE_AUTHZ_POLICY_CODE_13"
    )
    topology = topology_from_terraform_output(output)
    receipt = evaluate_platform_preflight(
        topology=topology,
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        deployment_id="deploy-20260821",
        observed_at=datetime(2026, 8, 21, tzinfo=UTC),
        billing_enabled=True,
        enabled_apis=_REQUIRED_APIS,
        proof_results={proof: True for proof in _REQUIRED_PROOFS},
        evidence_refs=("gs://solvan-demo-evidence/preflight/degraded.json",),
    )
    assert receipt.status == "DEGRADED"
    assert receipt.reason_codes == ("DEGRADED:INLINE_MODEL_ARMOR_GOOGLE_AUTHZ_POLICY_CODE_13",)
    assert dict(receipt.topology.gateway_policy_status)["iap"] == "ENFORCED"
    assert parse_platform_preflight_receipt(receipt.canonical_dict()) == receipt


@pytest.mark.parametrize("missing_policy", ["iap_egress_policy", "iap_ingress_policy"])
def test_preflight_refuses_iap_status_without_both_gateway_policies(
    missing_policy: str,
) -> None:
    output = terraform_output()
    output["gateway_policy_resources"]["value"][missing_policy] = None

    with pytest.raises(ValueError, match="IAP policies on both gateways"):
        topology_from_terraform_output(output)


def test_enabled_antigravity_topology_requires_its_exact_proof_set() -> None:
    output = terraform_output()
    provider_uri = f"https://solvan-antigravity-{PROJECT_NUMBER}.{REGION}.run.app"
    attester_uri = f"https://solvan-fixture-attester-{PROJECT_NUMBER}.{REGION}.run.app"
    output["service_uris"]["value"]["antigravity_workspace"] = provider_uri
    output["antigravity_workspace_provider"] = {
        "value": {
            "enabled": True,
            "service_name": "solvan-antigravity",
            "uri": provider_uri,
            "service_account": (f"solvan-antigravity@{PROJECT}.iam.gserviceaccount.com"),
            "coordinator_service_account": (
                f"solvan-coordinator@{PROJECT}.iam.gserviceaccount.com"
            ),
            "provider_revision": "antigravity-workspace-20260808-01",
            "implementation_sdk": "google-antigravity",
            "implementation_sdk_version": "0.1.13",
            "implementation_distribution_hash": (
                "sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992"
            ),
            "provider_artifact_digest": f"sha256:{'8' * 64}",
            "effective_tool_set_hash": f"sha256:{'1' * 64}",
            "effective_network_policy_hash": f"sha256:{'2' * 64}",
        }
    }
    output["synthetic_fixture_attester"] = {
        "value": {
            "uri": attester_uri,
            "service_account": (f"solvan-fixture-attester@{PROJECT}.iam.gserviceaccount.com"),
            "kms_key_version": (
                f"projects/{PROJECT}/locations/{REGION}/keyRings/solvan/"
                "cryptoKeys/synthetic/cryptoKeyVersions/2"
            ),
            "fixture_prefix": ("gs://solvan-demo-runtime/org/prj/env/fixtures/payments-leak-v1/"),
        }
    }
    output["antigravity_workspace_registry_binding"] = {
        "value": {
            "registry_resource": (f"projects/{PROJECT}/locations/{REGION}/services/antigravity"),
            "service_uri": provider_uri,
            "lifecycle": "EXPERIMENT_ONLY",
        }
    }
    topology = topology_from_terraform_output(output)
    assert topology.antigravity is not None
    with pytest.raises(ValueError, match="proof set"):
        evaluate_platform_preflight(
            topology=topology,
            release_commit=COMMIT,
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            deployment_id="deploy-20260808",
            observed_at=datetime(2026, 8, 8, tzinfo=UTC),
            billing_enabled=True,
            enabled_apis=_REQUIRED_APIS,
            proof_results={proof: True for proof in _REQUIRED_PROOFS},
            evidence_refs=("gs://solvan-demo-evidence/preflight/receipt.json",),
        )
    proofs = {proof: True for proof in _REQUIRED_PROOFS | ANTIGRAVITY_PROOFS}
    receipt = evaluate_platform_preflight(
        topology=topology,
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        deployment_id="deploy-20260808",
        observed_at=datetime(2026, 8, 8, tzinfo=UTC),
        billing_enabled=True,
        enabled_apis=_REQUIRED_APIS,
        proof_results=proofs,
        evidence_refs=("gs://solvan-demo-evidence/preflight/receipt.json",),
    )
    assert parse_platform_preflight_receipt(receipt.canonical_dict()) == receipt


def test_preflight_parser_rejects_tampered_hash_and_rehashed_invalid_topology() -> None:
    receipt = evaluate_platform_preflight(
        topology=topology_from_terraform_output(terraform_output()),
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        deployment_id="deploy-20260808",
        observed_at=datetime(2026, 8, 8, tzinfo=UTC),
        billing_enabled=True,
        enabled_apis=_REQUIRED_APIS,
        proof_results={proof: True for proof in _REQUIRED_PROOFS},
        evidence_refs=("gs://solvan-demo-evidence/preflight/receipt.json",),
    )
    tampered = receipt.canonical_dict()
    tampered["billing_enabled"] = False
    with pytest.raises(ValueError, match="canonical value or content hash"):
        parse_platform_preflight_receipt(tampered)

    invalid_topology = receipt.canonical_dict()
    invalid_topology["topology"]["service_uris"]["api"] = "https://example.invalid"
    with pytest.raises(ValueError, match="values are invalid"):
        parse_platform_preflight_receipt(invalid_topology)


def test_preflight_revalidates_every_security_relevant_topology_boundary() -> None:
    topology = topology_from_terraform_output(terraform_output())
    invalid = (
        replace(topology, region="us-east4"),
        replace(topology, required_services=()),
        replace(topology, service_uris=(("api", "https://example.invalid"),)),
        replace(
            topology,
            # Out of region, which is what this case tests. The region must be
            # one the pin does not approve; naming the approved region here
            # asserts nothing, which is how this case briefly stopped testing
            # anything when the pin moved to europe-west1.
            gateway_resources=(
                ("egress", "projects/other/locations/us-east4/gateways/egress"),
                ("ingress", "projects/other/locations/us-east4/gateways/ingress"),
            ),
        ),
        replace(
            topology,
            agent_resources=tuple(
                (name, "UNCONFIGURED") for name, _resource in topology.agent_resources
            ),
        ),
        replace(
            topology,
            agent_revisions=tuple(
                (name, "UNCONFIGURED") for name, _revision in topology.agent_revisions
            ),
        ),
        replace(
            topology,
            agent_principals=tuple(
                (name, "serviceAccount:agent@example.invalid")
                for name, _principal in topology.agent_principals
            ),
        ),
        replace(
            topology,
            scenario_identities=(("injector", "same"), ("oracle", "same")),
        ),
        replace(topology, cloud_sql_connection_name=""),
        replace(topology, runtime_bucket=topology.evidence_bucket),
        replace(topology, model_armor_template="projects/other/locations/global/templates/x"),
        replace(topology, fast_fleet_model_location="atlantis"),
        replace(topology, fast_fleet_model_endpoint="https://aiplatform.googleapis.com"),
    )
    for candidate in invalid:
        with pytest.raises(ValueError, match="release topology|Cloud Run services"):
            evaluate_platform_preflight(
                topology=candidate,
                release_commit=COMMIT,
                project_id=PROJECT,
                project_number=PROJECT_NUMBER,
                deployment_id="deploy-20260808",
                observed_at=datetime(2026, 8, 8, tzinfo=UTC),
                billing_enabled=True,
                enabled_apis=_REQUIRED_APIS,
                proof_results={proof: True for proof in _REQUIRED_PROOFS},
                evidence_refs=("gs://solvan-demo-evidence/preflight/receipt.json",),
            )


def test_preflight_reports_disabled_api_and_failed_proof() -> None:
    topology = topology_from_terraform_output(terraform_output())
    proofs = {proof: True for proof in _REQUIRED_PROOFS}
    proofs["gateway_bypass_denied"] = False
    enabled = _REQUIRED_APIS - {"modelarmor.googleapis.com"}
    receipt = evaluate_platform_preflight(
        topology=topology,
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        deployment_id="deploy-20260808",
        observed_at=datetime(2026, 8, 8, tzinfo=UTC),
        billing_enabled=True,
        enabled_apis=enabled,
        proof_results=proofs,
        evidence_refs=("gs://solvan-demo-evidence/preflight/receipt.json",),
    )
    assert receipt.status == "FAIL"
    assert "API_NOT_ENABLED:modelarmor.googleapis.com" in receipt.reason_codes
    assert "PROOF_FAILED:gateway_bypass_denied" in receipt.reason_codes


@pytest.mark.parametrize(
    ("output_name", "replacement", "message"),
    [
        ("required_services", ["aiplatform.googleapis.com"], "service set has drifted"),
        ("agent_runtime_resources", {}, "Runtime agents output keys"),
        ("agent_runtime_principals", {}, "Runtime principals output keys"),
        ("scenario_identities", {}, "scenario identities output keys"),
        ("fast_fleet_inference", {}, "fast-fleet inference output is malformed"),
    ],
)
def test_topology_rejects_unconfigured_or_drifted_release_output(
    output_name: str,
    replacement: object,
    message: str,
) -> None:
    output = terraform_output()
    output[output_name] = {"value": replacement}
    with pytest.raises(ValueError, match=message):
        topology_from_terraform_output(output)


def test_preflight_rejects_local_or_ambiguous_evidence_material() -> None:
    topology = topology_from_terraform_output(terraform_output())
    with pytest.raises(ValueError, match="durable GCS evidence"):
        evaluate_platform_preflight(
            topology=topology,
            release_commit=COMMIT,
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            deployment_id="deploy-20260808",
            observed_at=datetime(2026, 8, 8, tzinfo=UTC),
            billing_enabled=True,
            enabled_apis=_REQUIRED_APIS,
            proof_results={proof: True for proof in _REQUIRED_PROOFS},
            evidence_refs=("file:///tmp/preflight.json",),
        )


def test_proof_manifest_loader_requires_exact_release_binding(tmp_path) -> None:
    path = tmp_path / "proofs.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": PROJECT,
                "release_commit": COMMIT,
                "deployment_id": "deploy-20260808",
                "proofs": {
                    name: {
                        "passed": True,
                        "evidence_ref": f"gs://solvan-demo-evidence/proofs/{name}.json",
                    }
                    for name in _REQUIRED_PROOFS
                },
            }
        ),
        encoding="utf-8",
    )
    results, refs = load_proofs(
        path,
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
    )
    assert set(results) == _REQUIRED_PROOFS
    assert len(refs) == len(_REQUIRED_PROOFS)
    with pytest.raises(ValueError, match="not bound"):
        load_proofs(
            path,
            project_id=PROJECT,
            release_commit="b" * 40,
            deployment_id="deploy-20260808",
        )
