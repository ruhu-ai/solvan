"""Parsing and revalidation for untrusted platform-preflight receipts."""

from __future__ import annotations

from datetime import datetime

from solvan.platform.antigravity_preflight import parse_antigravity_canonical
from solvan.platform.preflight import (
    PlatformPreflightReceipt,
    ReleaseTopology,
    evaluate_platform_preflight,
)


def parse_platform_preflight_receipt(value: object) -> PlatformPreflightReceipt:
    """Re-evaluate an untrusted canonical preflight document and its hash."""

    expected = {
        "schema_version",
        "status",
        "release_commit",
        "project_id",
        "project_number",
        "region",
        "deployment_id",
        "observed_at",
        "topology",
        "billing_enabled",
        "enabled_apis",
        "proof_results",
        "evidence_refs",
        "reason_codes",
        "content_hash",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise ValueError("preflight receipt schema is invalid")
    topology_value = value["topology"]
    topology_keys = {
        "region",
        "required_services",
        "cloud_sql_connection_name",
        "service_uris",
        "evidence_bucket",
        "runtime_bucket",
        "gateway_resources",
        "gateway_policy_resources",
        "model_armor_template",
        "fast_fleet_model_resource",
        "fast_fleet_model_location",
        "fast_fleet_model_endpoint",
        "registered_endpoints",
        "agent_resources",
        "agent_revisions",
        "agent_principals",
        "scenario_identities",
        "antigravity",
    }
    if not isinstance(topology_value, dict) or set(topology_value) != topology_keys:
        raise ValueError("preflight topology schema is invalid")

    def string_map(name: str) -> tuple[tuple[str, str], ...]:
        raw = topology_value[name]
        if not isinstance(raw, dict) or any(
            not isinstance(key, str) or not isinstance(item, str) for key, item in raw.items()
        ):
            raise ValueError(f"preflight topology {name} is invalid")
        return tuple(sorted((str(key), str(item)) for key, item in raw.items()))

    required_services = topology_value["required_services"]
    enabled_apis = value["enabled_apis"]
    proof_results = value["proof_results"]
    evidence_refs = value["evidence_refs"]
    if not isinstance(required_services, list) or not all(
        isinstance(item, str) for item in required_services
    ):
        raise ValueError("preflight required services are invalid")
    if not isinstance(enabled_apis, list) or not all(
        isinstance(item, str) for item in enabled_apis
    ):
        raise ValueError("preflight enabled APIs are invalid")
    if not isinstance(proof_results, dict) or not all(
        isinstance(name, str) and isinstance(passed, bool) for name, passed in proof_results.items()
    ):
        raise ValueError("preflight proof results are invalid")
    if not isinstance(evidence_refs, list) or not all(
        isinstance(item, str) for item in evidence_refs
    ):
        raise ValueError("preflight evidence references are invalid")
    try:
        topology = ReleaseTopology(
            region=str(topology_value["region"]),
            required_services=tuple(str(item) for item in required_services),
            cloud_sql_connection_name=str(topology_value["cloud_sql_connection_name"]),
            service_uris=string_map("service_uris"),
            evidence_bucket=str(topology_value["evidence_bucket"]),
            runtime_bucket=str(topology_value["runtime_bucket"]),
            gateway_resources=string_map("gateway_resources"),
            gateway_policy_resources=string_map("gateway_policy_resources"),
            model_armor_template=str(topology_value["model_armor_template"]),
            fast_fleet_model_resource=str(topology_value["fast_fleet_model_resource"]),
            fast_fleet_model_location=str(topology_value["fast_fleet_model_location"]),
            fast_fleet_model_endpoint=str(topology_value["fast_fleet_model_endpoint"]),
            registered_endpoints=string_map("registered_endpoints"),
            agent_resources=string_map("agent_resources"),
            agent_revisions=string_map("agent_revisions"),
            agent_principals=string_map("agent_principals"),
            scenario_identities=string_map("scenario_identities"),
            antigravity=parse_antigravity_canonical(topology_value["antigravity"]),
        )
        receipt = evaluate_platform_preflight(
            topology=topology,
            release_commit=str(value["release_commit"]),
            project_id=str(value["project_id"]),
            project_number=str(value["project_number"]),
            deployment_id=str(value["deployment_id"]),
            observed_at=datetime.fromisoformat(str(value["observed_at"])),
            billing_enabled=value["billing_enabled"] is True,
            enabled_apis=frozenset(str(item) for item in enabled_apis),
            proof_results={str(name): passed for name, passed in proof_results.items()},
            evidence_refs=tuple(str(item) for item in evidence_refs),
        )
    except (TypeError, ValueError) as error:
        raise ValueError("preflight receipt values are invalid") from error
    if receipt.canonical_dict() != value:
        raise ValueError("preflight receipt canonical value or content hash is invalid")
    return receipt
