"""Live proof collectors for the optional self-hosted Antigravity provider."""

from __future__ import annotations

import json
import secrets
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from apps.antigravity_workspace.preflight import ProviderPreflightReceipt
from solvan.platform.antigravity_preflight import AntigravityPreflightTopology
from solvan.platform.google_rest import authorized_session

QUALIFICATION_PROOFS = frozenset(
    {
        "antigravity_fixture_attestation_verified",
        "antigravity_public_synthetic_allowed",
        "antigravity_nonpublic_denied",
        "antigravity_checkpoint_rehydrated_new_boot",
        "antigravity_revision_continuity_preserved",
    }
)


def provider_preflight(
    topology: AntigravityPreflightTopology,
    *,
    run: Callable[[list[str]], str],
) -> dict[str, tuple[bool, dict[str, Any]]]:
    """Call the private provider as the exact coordinator service account."""

    token = run(
        [
            "gcloud",
            "auth",
            "print-identity-token",
            f"--impersonate-service-account={topology.coordinator_service_account}",
            f"--audiences={topology.provider_uri}",
            "--include-email",
            "--quiet",
        ]
    ).strip()
    if not token:
        raise RuntimeError("gcloud returned an empty provider identity token")
    nonce = secrets.token_urlsafe(24)
    response = httpx.post(
        f"{topology.provider_uri}/internal/v1/preflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "schema_version": 1,
            "nonce": nonce,
            "expected_sdk_version": topology.implementation_sdk_version,
            "expected_sdk_distribution_hash": topology.implementation_distribution_hash,
            "expected_network_policy_hash": topology.effective_network_policy_hash,
        },
        timeout=90,
    )
    response.raise_for_status()
    receipt = ProviderPreflightReceipt.model_validate(response.json())
    if receipt.nonce != nonce:
        raise RuntimeError("provider preflight nonce does not match")
    observations = receipt.observations
    provenance_matches = (
        receipt.provider_revision == topology.provider_revision
        and receipt.sdk_version == topology.implementation_sdk_version
        and receipt.sdk_distribution_hash == topology.implementation_distribution_hash
        and observations.get("sdk_version_matches") is True
        and observations.get("sdk_distribution_matches") is True
        and observations.get("network_policy_matches") is True
        and observations.get("hosting_region_europe_west1") is True
        and observations.get("model_location_global") is True
        and observations.get("deep_workspace_model_exact") is True
    )
    tools_exact = (
        receipt.enabled_builtin_tools == ("finish",)
        and receipt.enabled_custom_tools == ("read_workspace_artifact", "write_candidate_artifact")
        and observations.get("custom_tool_set_exact") is True
    )
    detail = {
        "provider_revision": receipt.provider_revision,
        "provider_service_revision": receipt.provider_service_revision,
        "provider_boot_hash": receipt.provider_boot_hash,
        "sdk_version": receipt.sdk_version,
        "sdk_distribution_hash": receipt.sdk_distribution_hash,
        "enabled_builtin_tools": list(receipt.enabled_builtin_tools),
        "enabled_custom_tools": list(receipt.enabled_custom_tools),
        "observations": observations,
    }
    return {
        "antigravity_health": (provenance_matches and tools_exact, detail),
        "antigravity_sdk_import_pinned": (provenance_matches, detail),
        "antigravity_iam_excess_authority_denied": (
            all(
                observations.get(name) is True
                for name in (
                    "gcs_authority_denied",
                    "cloud_sql_authority_denied",
                    "secret_authority_denied",
                )
            ),
            detail,
        ),
        "antigravity_egress_denied": (
            observations.get("external_egress_denied") is True,
            detail,
        ),
        "antigravity_builtin_tool_denied": (
            tools_exact and observations.get("undeclared_builtin_tools_denied") is True,
            detail,
        ),
        "antigravity_model_armor_injection_denied": (
            observations.get("model_armor_injection_denied") is True,
            detail,
        ),
    }


def registry_preflight(
    topology: AntigravityPreflightTopology,
) -> tuple[bool, dict[str, Any]]:
    """Read the exact conditional Registry resource and interface binding."""

    resource = topology.registry_resource.removeprefix("//agentregistry.googleapis.com/")
    response = authorized_session().get(
        f"https://agentregistry.googleapis.com/v1/{resource}", timeout=30
    )
    response.raise_for_status()
    value = response.json()
    serialized = json.dumps(value, sort_keys=True)
    return topology.provider_uri in serialized, {
        "registry_resource": topology.registry_resource,
        "provider_uri_discovered": topology.provider_uri in serialized,
        "lifecycle": topology.lifecycle,
    }


def qualification_preflight(
    topology: AntigravityPreflightTopology,
    *,
    bucket: str,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    work_dir: Path,
    run: Callable[[list[str]], str],
) -> dict[str, tuple[bool, dict[str, Any]]]:
    """Load the product-produced qualification receipt; never infer its claims."""

    local = work_dir / "antigravity-qualification-source.json"
    uri = f"gs://{bucket}/preflight/{deployment_id}/antigravity-qualification.json"
    run(["gcloud", "storage", "cp", uri, str(local), "--quiet"])
    value = json.loads(local.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "kind",
        "project_id",
        "release_commit",
        "deployment_id",
        "provider_revision",
        "provider_service_revision_before",
        "provider_service_revision_after",
        "provider_boot_hash_before",
        "provider_boot_hash_after",
        "input_manifest_hash_before",
        "input_manifest_hash_after",
        "artifact_manifest_hash_before",
        "artifact_manifest_hash_after",
        "effective_tool_set_hash_before",
        "effective_tool_set_hash_after",
        "effective_network_policy_hash_before",
        "effective_network_policy_hash_after",
        "implementation_sdk_distribution_hash_before",
        "implementation_sdk_distribution_hash_after",
        "provider_artifact_digest_before",
        "provider_artifact_digest_after",
        "proofs",
        "evidence_refs",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Antigravity qualification receipt schema is invalid")
    if value["schema_version"] != 1 or value["kind"] != "ANTIGRAVITY_QUALIFICATION":
        raise ValueError("Antigravity qualification receipt kind is invalid")
    if (value["project_id"], value["release_commit"], value["deployment_id"]) != (
        project_id,
        release_commit,
        deployment_id,
    ):
        raise ValueError("Antigravity qualification receipt belongs to another release")
    if value["provider_revision"] != topology.provider_revision:
        raise ValueError("Antigravity qualification provider revision has drifted")
    proofs = value["proofs"]
    if not isinstance(proofs, dict) or set(proofs) != QUALIFICATION_PROOFS:
        raise ValueError("Antigravity qualification proof set is incomplete")
    if not all(isinstance(item, bool) for item in proofs.values()):
        raise ValueError("Antigravity qualification proofs are not Boolean")
    refs = value["evidence_refs"]
    if (
        not isinstance(refs, list)
        or not refs
        or not all(isinstance(item, str) and item.startswith("gs://") for item in refs)
    ):
        raise ValueError("Antigravity qualification evidence is not durable")
    continuity = (
        value["provider_service_revision_before"] != value["provider_service_revision_after"]
        and value["provider_boot_hash_before"] != value["provider_boot_hash_after"]
        and value["input_manifest_hash_before"] == value["input_manifest_hash_after"]
        and value["artifact_manifest_hash_before"] == value["artifact_manifest_hash_after"]
        and value["implementation_sdk_distribution_hash_before"]
        == value["implementation_sdk_distribution_hash_after"]
        == topology.implementation_distribution_hash
        and value["provider_artifact_digest_before"]
        == value["provider_artifact_digest_after"]
        == topology.provider_artifact_digest
        and value["effective_tool_set_hash_before"]
        == value["effective_tool_set_hash_after"]
        == topology.effective_tool_set_hash
        and value["effective_network_policy_hash_before"]
        == value["effective_network_policy_hash_after"]
        == topology.effective_network_policy_hash
    )
    detail = {**value, "source_uri": uri, "continuity_recomputed": continuity}
    results: dict[str, tuple[bool, dict[str, Any]]] = {}
    for name in QUALIFICATION_PROOFS:
        passed = proofs[name]
        if name in {
            "antigravity_checkpoint_rehydrated_new_boot",
            "antigravity_revision_continuity_preserved",
        }:
            passed = passed and continuity
        results[name] = (passed, detail)
    return results


def subprocess_run(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no output").strip()
        raise RuntimeError(f"{arguments[0]} failed: {detail[-1000:]}")
    return completed.stdout
