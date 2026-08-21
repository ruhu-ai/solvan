"""Strict optional Antigravity topology and proof contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SDK_DISTRIBUTION_HASH = "sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992"
ANTIGRAVITY_PROOFS = frozenset(
    {
        "antigravity_health",
        "antigravity_sdk_import_pinned",
        "antigravity_registry_discovered",
        "antigravity_fixture_attestation_verified",
        "antigravity_public_synthetic_allowed",
        "antigravity_nonpublic_denied",
        "antigravity_iam_excess_authority_denied",
        "antigravity_egress_denied",
        "antigravity_builtin_tool_denied",
        "antigravity_model_armor_injection_denied",
        "antigravity_checkpoint_rehydrated_new_boot",
        "antigravity_revision_continuity_preserved",
    }
)


@dataclass(frozen=True, slots=True)
class AntigravityPreflightTopology:
    provider_service_name: str
    provider_uri: str
    provider_service_account: str
    coordinator_service_account: str
    provider_revision: str
    implementation_sdk: str
    implementation_sdk_version: str
    implementation_distribution_hash: str
    provider_artifact_digest: str
    effective_tool_set_hash: str
    effective_network_policy_hash: str
    fixture_attester_uri: str
    fixture_attester_service_account: str
    fixture_attester_kms_key_version: str
    fixture_prefix: str
    registry_resource: str
    lifecycle: str

    def canonical_dict(self) -> dict[str, str]:
        return {
            "provider_service_name": self.provider_service_name,
            "provider_uri": self.provider_uri,
            "provider_service_account": self.provider_service_account,
            "coordinator_service_account": self.coordinator_service_account,
            "provider_revision": self.provider_revision,
            "implementation_sdk": self.implementation_sdk,
            "implementation_sdk_version": self.implementation_sdk_version,
            "implementation_distribution_hash": self.implementation_distribution_hash,
            "provider_artifact_digest": self.provider_artifact_digest,
            "effective_tool_set_hash": self.effective_tool_set_hash,
            "effective_network_policy_hash": self.effective_network_policy_hash,
            "fixture_attester_uri": self.fixture_attester_uri,
            "fixture_attester_service_account": self.fixture_attester_service_account,
            "fixture_attester_kms_key_version": self.fixture_attester_kms_key_version,
            "fixture_prefix": self.fixture_prefix,
            "registry_resource": self.registry_resource,
            "lifecycle": self.lifecycle,
        }


def parse_antigravity_terraform_outputs(
    outputs: dict[str, Any],
) -> AntigravityPreflightTopology | None:
    provider = _output(outputs, "antigravity_workspace_provider")
    attester = _output(outputs, "synthetic_fixture_attester")
    registry = _output(outputs, "antigravity_workspace_registry_binding")
    if not isinstance(provider, dict) or set(provider) != {
        "enabled",
        "service_name",
        "uri",
        "service_account",
        "coordinator_service_account",
        "provider_revision",
        "implementation_sdk",
        "implementation_sdk_version",
        "implementation_distribution_hash",
        "provider_artifact_digest",
        "effective_tool_set_hash",
        "effective_network_policy_hash",
    }:
        raise ValueError("Antigravity provider Terraform output is malformed")
    if provider["enabled"] is False:
        if (
            provider["uri"] is not None
            or provider["service_name"] is not None
            or attester is not None
            or registry is not None
        ):
            raise ValueError("disabled Antigravity topology contains active resources")
        return None
    if provider["enabled"] is not True:
        raise ValueError("Antigravity enabled flag is not Boolean")
    if not isinstance(attester, dict) or set(attester) != {
        "uri",
        "service_account",
        "kms_key_version",
        "fixture_prefix",
    }:
        raise ValueError("Antigravity fixture attester Terraform output is malformed")
    if not isinstance(registry, dict) or set(registry) != {
        "registry_resource",
        "service_uri",
        "lifecycle",
    }:
        raise ValueError("Antigravity Registry Terraform output is malformed")
    topology = AntigravityPreflightTopology(
        provider_service_name=_string(provider, "service_name"),
        provider_uri=_string(provider, "uri"),
        provider_service_account=_string(provider, "service_account"),
        coordinator_service_account=_string(provider, "coordinator_service_account"),
        provider_revision=_string(provider, "provider_revision"),
        implementation_sdk=_string(provider, "implementation_sdk"),
        implementation_sdk_version=_string(provider, "implementation_sdk_version"),
        implementation_distribution_hash=_string(provider, "implementation_distribution_hash"),
        provider_artifact_digest=_string(provider, "provider_artifact_digest"),
        effective_tool_set_hash=_string(provider, "effective_tool_set_hash"),
        effective_network_policy_hash=_string(provider, "effective_network_policy_hash"),
        fixture_attester_uri=_string(attester, "uri"),
        fixture_attester_service_account=_string(attester, "service_account"),
        fixture_attester_kms_key_version=_string(attester, "kms_key_version"),
        fixture_prefix=_string(attester, "fixture_prefix"),
        registry_resource=_string(registry, "registry_resource"),
        lifecycle=_string(registry, "lifecycle"),
    )
    if _string(registry, "service_uri") != topology.provider_uri:
        raise ValueError("Antigravity Registry and provider URI bindings differ")
    validate_antigravity_topology(topology)
    return topology


def parse_antigravity_canonical(value: object) -> AntigravityPreflightTopology | None:
    if value is None:
        return None
    fields = set(AntigravityPreflightTopology.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("preflight Antigravity topology schema is invalid")
    if any(not isinstance(value[field], str) or not value[field] for field in fields):
        raise ValueError("preflight Antigravity topology contains an empty value")
    topology = AntigravityPreflightTopology(**{field: value[field] for field in fields})
    validate_antigravity_topology(topology)
    return topology


def validate_antigravity_topology(topology: AntigravityPreflightTopology) -> None:
    uri = re.compile(r"^https://[a-z0-9-]+-[0-9]+\.europe-west1\.run\.app$")
    service_account = re.compile(r"^[a-z0-9-]+@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com$")
    sha256 = re.compile(r"^sha256:[0-9a-f]{64}$")
    if (
        uri.fullmatch(topology.provider_uri) is None
        or uri.fullmatch(topology.fixture_attester_uri) is None
    ):
        raise ValueError("Antigravity Cloud Run URI is noncanonical or cross-region")
    if re.fullmatch(r"^[a-z][a-z0-9-]{2,62}$", topology.provider_service_name) is None:
        raise ValueError("Antigravity Cloud Run service name is noncanonical")
    if any(
        service_account.fullmatch(value) is None
        for value in (
            topology.provider_service_account,
            topology.coordinator_service_account,
            topology.fixture_attester_service_account,
        )
    ):
        raise ValueError("Antigravity service account binding is malformed")
    if (
        len(
            {
                topology.provider_service_account,
                topology.coordinator_service_account,
                topology.fixture_attester_service_account,
            }
        )
        != 3
    ):
        raise ValueError("provider, coordinator, and attester identities must be independent")
    if (
        topology.implementation_sdk != "google-antigravity"
        or topology.implementation_sdk_version != "0.1.13"
        or topology.implementation_distribution_hash != SDK_DISTRIBUTION_HASH
        or sha256.fullmatch(topology.provider_artifact_digest) is None
    ):
        raise ValueError("Antigravity SDK provenance has drifted")
    if any(
        sha256.fullmatch(value) is None
        for value in (
            topology.effective_tool_set_hash,
            topology.effective_network_policy_hash,
        )
    ):
        raise ValueError("Antigravity policy hash is malformed")
    if (
        re.fullmatch(
            r"projects/[^/]+/locations/europe-west1/keyRings/[^/]+/cryptoKeys/[^/]+/"
            r"cryptoKeyVersions/[0-9]+",
            topology.fixture_attester_kms_key_version,
        )
        is None
    ):
        raise ValueError("fixture attester KMS key is malformed or cross-region")
    if (
        re.fullmatch(
            r"gs://[a-z0-9][a-z0-9._-]+/.+/fixtures/payments-leak-v1/", topology.fixture_prefix
        )
        is None
    ):
        raise ValueError("public synthetic fixture prefix is malformed")
    if "/locations/europe-west1/" not in topology.registry_resource:
        raise ValueError("Antigravity Registry resource is cross-region")
    if topology.lifecycle != "EXPERIMENT_ONLY":
        raise ValueError("Antigravity Registry lifecycle is not experiment-only")


def _output(outputs: dict[str, Any], name: str) -> Any:
    item = outputs.get(name)
    if not isinstance(item, dict) or "value" not in item:
        raise ValueError(f"Terraform output {name} is missing")
    return item["value"]


def _string(value: dict[str, Any], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item:
        raise ValueError(f"Antigravity output {name} is empty")
    return item
