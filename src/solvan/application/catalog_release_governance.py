"""Deterministic subject and policy checks for governed catalog releases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apps.coordinator.contracts import GovernedAgentBinding
from solvan.application.default_tool_catalog import (
    AGENT_PROFILE_KEYS,
    TOOL_SEEDS,
    alert_triage_profile,
    catalog_profile,
    catalog_tools,
)
from solvan.application.tool_catalog import PermissionClass
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import Scope

PENDING_GOVERNANCE_REF = "clouddeploy://pending-evaluation-and-approval"


def _model_json(value: Any) -> dict[str, Any]:
    document = value.model_dump(mode="json")
    if not isinstance(document, dict):
        raise RuntimeError("catalog model did not produce a JSON object")
    return document


def evaluate_network_policy(*, raw_policy: bytes, expected_hash: str) -> dict[str, Any]:
    """Return the exact fail-closed network-policy evaluation document."""

    actual_hash = sha256_bytes(raw_policy)
    if actual_hash != expected_hash:
        raise RuntimeError("catalog network policy hash does not match the release binding")
    try:
        policy = json.loads(raw_policy)
    except json.JSONDecodeError as error:
        raise RuntimeError("catalog network policy is not valid JSON") from error
    if not isinstance(policy, dict):
        raise RuntimeError("catalog network policy must be a JSON object")
    fixed = {
        "schema_version": 1,
        "policy_id": "solvan-governed-tool-catalog-network-v1",
        "default_action": "DENY",
        "destination_selection": "CATALOG_REVISION_ONLY",
        "direct_model_egress": False,
    }
    for name, expected in fixed.items():
        if policy.get(name) != expected:
            raise RuntimeError(f"catalog network policy {name} is not fail-closed")
    expected_rules = [
        {
            "tool_revision": f"{seed.key}@1",
            "gateway_destination": seed.destination,
            "runtime_regions": ["europe-west1"],
        }
        for seed in sorted(TOOL_SEEDS, key=lambda item: item.key)
    ]
    if policy.get("rules") != expected_rules:
        raise RuntimeError("catalog network policy does not exactly cover the checked-in catalog")
    return {
        "schema_version": 1,
        "kind": "SOLVAN_CATALOG_NETWORK_POLICY_EVALUATION",
        "result": "PASSED",
        "network_policy_hash": actual_hash,
        "tool_revision_count": len(expected_rules),
        "runtime_region": "europe-west1",
    }


def catalog_release_subject(
    *,
    scope: Scope,
    release_commit: str,
    deployment_id: str,
    manifest_hash: str,
    network_policy_hash: str,
    bindings: dict[str, GovernedAgentBinding],
) -> dict[str, Any]:
    """Build the exact catalog subject evaluated before a human can approve it."""

    if set(bindings) != set(AGENT_PROFILE_KEYS):
        raise RuntimeError("catalog release subject requires all canonical Agent bindings")
    tools = catalog_tools(
        network_policy_hash=network_policy_hash,
        approval_ref=PENDING_GOVERNANCE_REF,
        evaluation_ref=PENDING_GOVERNANCE_REF,
    )
    tools_by_ref = {f"{tool.tool_key}@{tool.version}": tool for tool in tools}
    binding_documents: dict[str, Any] = {}
    for agent_key, profile_key in sorted(AGENT_PROFILE_KEYS.items()):
        binding = bindings[agent_key]
        if (binding.profile_key, binding.profile_version) != (profile_key, "1"):
            raise RuntimeError(f"{agent_key} is not bound to {profile_key}@1")
        profile = catalog_profile(
            agent_key=agent_key,
            approval_ref=PENDING_GOVERNANCE_REF,
            evaluation_ref=PENDING_GOVERNANCE_REF,
            classification_ceiling=binding.data_classification,
        )
        for tool_ref in profile.tool_revisions:
            tool = tools_by_ref.get(tool_ref)
            if tool is None:
                raise RuntimeError(f"catalog profile references missing Tool {tool_ref}")
            if tool.permission_class is PermissionClass.MUTATE:
                raise RuntimeError("model-facing catalog profile contains a mutation Tool")
        binding_documents[agent_key] = {
            "profile_ref": f"{binding.profile_key}@{binding.profile_version}",
            "identity_ref": binding.identity_ref,
            "accepted_tool_ordinals": list(binding.accepted_tool_ordinals),
            "connection_epochs": dict(sorted(binding.connection_epochs.items())),
            "gateway_destinations": sorted(binding.gateway_destinations),
            "data_classification": binding.data_classification,
        }
    alert_triage_profile(
        approval_ref=PENDING_GOVERNANCE_REF,
        evaluation_ref=PENDING_GOVERNANCE_REF,
    )
    return {
        "schema_version": 1,
        "kind": "SOLVAN_GOVERNED_CATALOG_RELEASE_SUBJECT",
        "scope": scope.canonical_dict(),
        "release_commit": release_commit,
        "deployment_id": deployment_id,
        "agent_manifest_hash": manifest_hash,
        "network_policy_hash": network_policy_hash,
        "bindings": binding_documents,
    }


def evaluate_catalog_release(
    *,
    policy_path: Path,
    expected_network_policy_hash: str,
    scope: Scope,
    release_commit: str,
    deployment_id: str,
    manifest_hash: str,
    bindings: dict[str, GovernedAgentBinding],
) -> dict[str, Any]:
    policy_result = evaluate_network_policy(
        raw_policy=policy_path.read_bytes(), expected_hash=expected_network_policy_hash
    )
    subject = catalog_release_subject(
        scope=scope,
        release_commit=release_commit,
        deployment_id=deployment_id,
        manifest_hash=manifest_hash,
        network_policy_hash=expected_network_policy_hash,
        bindings=bindings,
    )
    return {
        "schema_version": 1,
        "kind": "SOLVAN_GOVERNED_CATALOG_EVALUATION",
        "result": "PASSED",
        "subject_hash": canonical_sha256(subject),
        "subject": subject,
        "checks": {
            "network_policy": policy_result,
            "canonical_agent_bindings": True,
            "profile_tool_references": True,
            "model_facing_mutation_tools_absent": True,
        },
    }
