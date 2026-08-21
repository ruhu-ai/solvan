"""Exact Terraform topology and live platform-preflight evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from solvan.platform.antigravity_preflight import (
    ANTIGRAVITY_PROOFS,
    AntigravityPreflightTopology,
    parse_antigravity_terraform_outputs,
    validate_antigravity_topology,
)
from solvan.platform.model_routes import (
    validate_fast_fleet_route,
)

_SERVICES = frozenset(
    {
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
    }
)
_AGENTS = frozenset(
    {
        "workspace_agent",
        "evidence_agent",
        "execution_agent",
        "incident_supervisor",
        "infrastructure_agent",
        "verification_agent",
    }
)
_REGISTERED = frozenset(
    {
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
    }
)
_GATEWAY_POLICIES = frozenset(
    {"iap_extension", "iap_policy", "model_armor_extension", "model_armor_policy"}
)
_RUNTIME_PRINCIPALS = _AGENTS
_SCENARIO_IDENTITIES = frozenset({"injector", "oracle"})
_REQUIRED_APIS = frozenset(
    {
        "aiplatform.googleapis.com",
        "agentregistry.googleapis.com",
        "apphub.googleapis.com",
        "apptopology.googleapis.com",
        "artifactregistry.googleapis.com",
        "billingbudgets.googleapis.com",
        "cloudapiregistry.googleapis.com",
        "cloudbuild.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "cloudscheduler.googleapis.com",
        "cloudtrace.googleapis.com",
        "compute.googleapis.com",
        "discoveryengine.googleapis.com",
        "dns.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "iap.googleapis.com",
        "logging.googleapis.com",
        "modelarmor.googleapis.com",
        "monitoring.googleapis.com",
        "networksecurity.googleapis.com",
        "networkservices.googleapis.com",
        "observability.googleapis.com",
        "pubsub.googleapis.com",
        "run.googleapis.com",
        "secretmanager.googleapis.com",
        "serviceextensions.googleapis.com",
        "servicenetworking.googleapis.com",
        "serviceusage.googleapis.com",
        "sqladmin.googleapis.com",
        "storage.googleapis.com",
        "telemetry.googleapis.com",
        "vpcaccess.googleapis.com",
    }
)
_REQUIRED_PROOFS = frozenset(
    {
        "cloud_run_health",
        "workspace_sandbox_launcher_enabled",
        "cloud_sql_61_tables",
        "registry_six_agents_discovered",
        "runtime_query_job_completed",
        "memory_exact_scope_recall",
        "memory_cross_scope_denied",
        "identity_matrix_denied_excess_authority",
        "gateway_registered_route_allowed",
        "gateway_bypass_denied",
        "model_armor_benign_allowed",
        "model_armor_injection_denied",
        "model_armor_pii_denied",
        "otel_trace_correlated",
        "cross_scope_database_read_denied",
    }
)


@dataclass(frozen=True, slots=True)
class ReleaseTopology:
    region: str
    required_services: tuple[str, ...]
    cloud_sql_connection_name: str
    service_uris: tuple[tuple[str, str], ...]
    evidence_bucket: str
    runtime_bucket: str
    gateway_resources: tuple[tuple[str, str], ...]
    gateway_policy_resources: tuple[tuple[str, str], ...]
    model_armor_template: str
    fast_fleet_model_resource: str
    fast_fleet_model_location: str
    fast_fleet_model_endpoint: str
    registered_endpoints: tuple[tuple[str, str], ...]
    agent_resources: tuple[tuple[str, str], ...]
    agent_revisions: tuple[tuple[str, str], ...]
    agent_principals: tuple[tuple[str, str], ...]
    scenario_identities: tuple[tuple[str, str], ...]
    antigravity: AntigravityPreflightTopology | None = None

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "required_services": list(self.required_services),
            "cloud_sql_connection_name": self.cloud_sql_connection_name,
            "service_uris": dict(self.service_uris),
            "evidence_bucket": self.evidence_bucket,
            "runtime_bucket": self.runtime_bucket,
            "gateway_resources": dict(self.gateway_resources),
            "gateway_policy_resources": dict(self.gateway_policy_resources),
            "model_armor_template": self.model_armor_template,
            "fast_fleet_model_resource": self.fast_fleet_model_resource,
            "fast_fleet_model_location": self.fast_fleet_model_location,
            "fast_fleet_model_endpoint": self.fast_fleet_model_endpoint,
            "registered_endpoints": dict(self.registered_endpoints),
            "agent_resources": dict(self.agent_resources),
            "agent_revisions": dict(self.agent_revisions),
            "agent_principals": dict(self.agent_principals),
            "scenario_identities": dict(self.scenario_identities),
            "antigravity": (
                None if self.antigravity is None else self.antigravity.canonical_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class PlatformPreflightReceipt:
    status: str
    release_commit: str
    project_id: str
    project_number: str
    region: str
    deployment_id: str
    observed_at: datetime
    topology: ReleaseTopology
    billing_enabled: bool
    enabled_apis: tuple[str, ...]
    proof_results: tuple[tuple[str, bool], ...]
    evidence_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    content_hash: str

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "release_commit": self.release_commit,
            "project_id": self.project_id,
            "project_number": self.project_number,
            "region": self.region,
            "deployment_id": self.deployment_id,
            "observed_at": self.observed_at.isoformat(),
            "topology": self.topology.canonical_dict(),
            "billing_enabled": self.billing_enabled,
            "enabled_apis": list(self.enabled_apis),
            "proof_results": dict(self.proof_results),
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": list(self.reason_codes),
            "content_hash": self.content_hash,
        }


def _validate_release_topology(topology: ReleaseTopology) -> None:
    if topology.region != "europe-west1":
        raise ValueError("release topology must remain in europe-west1")
    if set(topology.required_services) != _REQUIRED_APIS or len(topology.required_services) != len(
        _REQUIRED_APIS
    ):
        raise ValueError("release topology required service set has drifted")

    expected_services = set(_SERVICES)
    if topology.antigravity is not None:
        expected_services.add("antigravity_workspace")
        validate_antigravity_topology(topology.antigravity)
    service_uris = _exact_string_map(
        dict(topology.service_uris), expected_services, "Cloud Run services"
    )
    cloud_run_uri = re.compile(r"^https://[a-z0-9-]+-[0-9]+\.europe-west1\.run\.app$")
    if any(cloud_run_uri.fullmatch(uri) is None for uri in service_uris.values()):
        raise ValueError("release topology contains a noncanonical Cloud Run URI")
    location_bound_maps = (
        (_exact_string_map(dict(topology.gateway_resources), {"egress", "ingress"}, "gateways")),
        (
            _exact_string_map(
                dict(topology.gateway_policy_resources), _GATEWAY_POLICIES, "gateway policies"
            )
        ),
        (_exact_string_map(dict(topology.registered_endpoints), _REGISTERED, "Registry endpoints")),
    )
    if any(
        "/locations/europe-west1/" not in resource
        for resources in location_bound_maps
        for resource in resources.values()
    ):
        raise ValueError("release topology contains a cross-region platform resource")

    agents = _exact_string_map(dict(topology.agent_resources), _AGENTS, "Runtime agents")
    revisions = _exact_string_map(dict(topology.agent_revisions), _AGENTS, "Runtime revisions")
    principals = _exact_string_map(
        dict(topology.agent_principals), _RUNTIME_PRINCIPALS, "Runtime principals"
    )
    scenario_identities = _exact_string_map(
        dict(topology.scenario_identities), _SCENARIO_IDENTITIES, "scenario identities"
    )
    runtime_resource = re.compile(
        r"^projects/(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+)/locations/"
        r"europe-west1/reasoningEngines/[A-Za-z0-9_-]+$"
    )
    if any(runtime_resource.fullmatch(item) is None for item in agents.values()):
        raise ValueError("release topology contains a malformed Runtime agent")
    if any(item == "UNCONFIGURED" for item in revisions.values()):
        raise ValueError("release topology contains an unconfigured Runtime revision")
    runtime_principal = re.compile(
        r"^principal://agents\.global\.(?:org|project)-[0-9]+\.system\.id\.goog/"
        r"resources/aiplatform/projects/[0-9]+/locations/europe-west1/"
        r"reasoningEngines/[A-Za-z0-9_-]+$"
    )
    if any(runtime_principal.fullmatch(item) is None for item in principals.values()):
        raise ValueError("release topology contains a malformed Runtime principal")
    scenario_identity = re.compile(
        r"^solvan-(?:injector|oracle)@[a-z][a-z0-9-]{4,28}[a-z0-9]"
        r"\.iam\.gserviceaccount\.com$"
    )
    if any(scenario_identity.fullmatch(item) is None for item in scenario_identities.values()) or (
        len(set(scenario_identities.values())) != 2
    ):
        raise ValueError("release topology contains malformed or conflated scenario identities")
    if not topology.cloud_sql_connection_name:
        raise ValueError("release topology Cloud SQL binding is empty")
    if (
        not topology.evidence_bucket
        or not topology.runtime_bucket
        or topology.evidence_bucket == topology.runtime_bucket
    ):
        raise ValueError("release topology bucket bindings are invalid")
    if "/locations/europe-west1/" not in topology.model_armor_template:
        raise ValueError("release topology Model Armor template is outside europe-west1")
    validate_fast_fleet_route(
        model=topology.fast_fleet_model_resource,
        location=topology.fast_fleet_model_location,
        endpoint=topology.fast_fleet_model_endpoint,
    )
    if topology.antigravity is not None and (
        service_uris["antigravity_workspace"] != topology.antigravity.provider_uri
    ):
        raise ValueError("release topology Antigravity service URI binding differs")


def topology_from_terraform_output(value: dict[str, Any]) -> ReleaseTopology:
    def output(name: str) -> Any:
        item = value.get(name)
        if not isinstance(item, dict) or "value" not in item:
            raise ValueError(f"Terraform output {name} is missing")
        return item["value"]

    region = output("region")
    if region != "europe-west1":
        raise ValueError("Terraform release region must be europe-west1")
    required_services = output("required_services")
    if not isinstance(required_services, list) or set(required_services) != _REQUIRED_APIS:
        raise ValueError("Terraform required service set has drifted")
    if len(required_services) != len(_REQUIRED_APIS) or any(
        not isinstance(item, str) for item in required_services
    ):
        raise ValueError("Terraform required service output is malformed")
    antigravity = parse_antigravity_terraform_outputs(value)
    expected_services = set(_SERVICES)
    if antigravity is not None:
        expected_services.add("antigravity_workspace")
    service_uris = _exact_string_map(
        output("service_uris"), expected_services, "Cloud Run services"
    )
    cloud_run_uri = re.compile(r"^https://[a-z0-9-]+-[0-9]+\.europe-west1\.run\.app$")
    if any(cloud_run_uri.fullmatch(uri) is None for uri in service_uris.values()):
        raise ValueError("Cloud Run service URI is not a canonical europe-west1 URI")
    gateways = _exact_string_map(
        output("agent_gateway_resources"), {"egress", "ingress"}, "gateways"
    )
    if any("/locations/europe-west1/" not in resource for resource in gateways.values()):
        raise ValueError("Agent Gateway is outside europe-west1")
    policies = _exact_string_map(
        output("gateway_policy_resources"), _GATEWAY_POLICIES, "gateway policies"
    )
    if any("/locations/europe-west1/" not in resource for resource in policies.values()):
        raise ValueError("Agent Gateway policy is outside europe-west1")
    registered = _exact_string_map(
        output("registered_endpoints"), _REGISTERED, "Registry endpoints"
    )
    if any("/locations/europe-west1/" not in resource for resource in registered.values()):
        raise ValueError("Agent Registry endpoint is outside europe-west1")
    agents = _exact_string_map(output("agent_runtime_resources"), _AGENTS, "Runtime agents")
    revisions = _exact_string_map(output("agent_runtime_revisions"), _AGENTS, "Runtime revisions")
    principals = _exact_string_map(
        output("agent_runtime_principals"), _RUNTIME_PRINCIPALS, "Runtime principals"
    )
    scenario_identities = _exact_string_map(
        output("scenario_identities"), _SCENARIO_IDENTITIES, "scenario identities"
    )
    resource_pattern = re.compile(
        r"^projects/(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+)/locations/europe-west1/reasoningEngines/[A-Za-z0-9_-]+$"
    )
    if any(resource_pattern.fullmatch(item) is None for item in agents.values()):
        raise ValueError("Runtime agent output is unconfigured or not exact europe-west1")
    if any(item == "UNCONFIGURED" or not item for item in revisions.values()):
        raise ValueError("Runtime revision output is unconfigured")
    principal_pattern = re.compile(
        r"^principal://agents\.global\.(?:org|project)-[0-9]+\.system\.id\.goog/"
        r"resources/aiplatform/projects/[0-9]+/locations/europe-west1/"
        r"reasoningEngines/[A-Za-z0-9_-]+$"
    )
    if any(principal_pattern.fullmatch(item) is None for item in principals.values()):
        raise ValueError("Runtime principal output is unconfigured or malformed")
    harness_identity_pattern = re.compile(
        r"^solvan-(?:injector|oracle)@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
    )
    if (
        any(
            harness_identity_pattern.fullmatch(item) is None
            for item in scenario_identities.values()
        )
        or len(set(scenario_identities.values())) != 2
    ):
        raise ValueError("scenario identities are unconfigured, conflated, or malformed")
    sql_connection = output("cloud_sql_connection_name")
    evidence_bucket = output("evidence_bucket")
    runtime_bucket = output("runtime_bucket")
    armor = output("model_armor_template")
    inference = output("fast_fleet_inference")
    core_resources = (sql_connection, evidence_bucket, runtime_bucket, armor)
    if not all(isinstance(item, str) and item for item in core_resources):
        raise ValueError("Terraform core resource output is malformed")
    if evidence_bucket == runtime_bucket:
        raise ValueError("evidence and Runtime buckets must be distinct")
    if "/locations/europe-west1/" not in armor:
        raise ValueError("Model Armor template is outside europe-west1")
    if not isinstance(inference, dict) or set(inference) != {
        "model_resource",
        "location",
        "endpoint",
    }:
        raise ValueError("fast-fleet inference output is malformed")
    model_resource = inference["model_resource"]
    model_location = inference["location"]
    model_endpoint = inference["endpoint"]
    if not all(isinstance(item, str) for item in inference.values()):
        raise ValueError("fast-fleet inference output is malformed")
    validate_fast_fleet_route(
        model=model_resource,
        location=model_location,
        endpoint=model_endpoint,
    )
    topology = ReleaseTopology(
        region=region,
        required_services=tuple(sorted(required_services)),
        cloud_sql_connection_name=sql_connection,
        service_uris=tuple(sorted(service_uris.items())),
        evidence_bucket=evidence_bucket,
        runtime_bucket=runtime_bucket,
        gateway_resources=tuple(sorted(gateways.items())),
        gateway_policy_resources=tuple(sorted(policies.items())),
        model_armor_template=armor,
        fast_fleet_model_resource=model_resource,
        fast_fleet_model_location=model_location,
        fast_fleet_model_endpoint=model_endpoint,
        registered_endpoints=tuple(sorted(registered.items())),
        agent_resources=tuple(sorted(agents.items())),
        agent_revisions=tuple(sorted(revisions.items())),
        agent_principals=tuple(sorted(principals.items())),
        scenario_identities=tuple(sorted(scenario_identities.items())),
        antigravity=antigravity,
    )
    _validate_release_topology(topology)
    return topology


def evaluate_platform_preflight(
    *,
    topology: ReleaseTopology,
    release_commit: str,
    project_id: str,
    project_number: str,
    deployment_id: str,
    observed_at: datetime,
    billing_enabled: bool,
    enabled_apis: frozenset[str],
    proof_results: dict[str, bool],
    evidence_refs: tuple[str, ...],
) -> PlatformPreflightReceipt:
    _validate_release_topology(topology)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("preflight observation time must be timezone-aware")
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id) is None:
        raise ValueError("preflight project ID is malformed")
    if re.fullmatch(r"[0-9]{6,20}", project_number) is None:
        raise ValueError("preflight project number is malformed")
    if len(release_commit) != 40 or re.fullmatch(r"[0-9a-f]{40}", release_commit) is None:
        raise ValueError("preflight requires a full lowercase git commit")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", deployment_id) is None:
        raise ValueError("preflight deployment ID is malformed")
    expected_proofs = set(_REQUIRED_PROOFS)
    if topology.antigravity is not None:
        expected_proofs.update(ANTIGRAVITY_PROOFS)
    if set(proof_results) != expected_proofs:
        raise ValueError("preflight proof set is incomplete or contains unknown proofs")
    if (
        not evidence_refs
        or len(set(evidence_refs)) != len(evidence_refs)
        or any(
            re.fullmatch(r"gs://[a-z0-9][a-z0-9._-]+/.+", item) is None for item in evidence_refs
        )
    ):
        raise ValueError("preflight requires durable GCS evidence references")
    reasons: list[str] = []
    if not billing_enabled:
        reasons.append("BILLING_DISABLED")
    for api in sorted(set(topology.required_services) - enabled_apis):
        reasons.append(f"API_NOT_ENABLED:{api}")
    for proof, passed in sorted(proof_results.items()):
        if not passed:
            reasons.append(f"PROOF_FAILED:{proof}")
    canonical = {
        "schema_version": 1,
        "release_commit": release_commit,
        "project_id": project_id,
        "project_number": project_number,
        "region": topology.region,
        "deployment_id": deployment_id,
        "observed_at": observed_at.isoformat(),
        "topology": topology.canonical_dict(),
        "billing_enabled": billing_enabled,
        "enabled_apis": sorted(enabled_apis),
        "proof_results": dict(sorted(proof_results.items())),
        "evidence_refs": list(evidence_refs),
        "reason_codes": reasons,
    }
    content_hash = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    return PlatformPreflightReceipt(
        status="PASS" if not reasons else "FAIL",
        release_commit=release_commit,
        project_id=project_id,
        project_number=project_number,
        region=topology.region,
        deployment_id=deployment_id,
        observed_at=observed_at,
        topology=topology,
        billing_enabled=billing_enabled,
        enabled_apis=tuple(sorted(enabled_apis)),
        proof_results=tuple(sorted(proof_results.items())),
        evidence_refs=evidence_refs,
        reason_codes=tuple(reasons),
        content_hash=content_hash,
    )


def _exact_string_map(
    value: Any,
    expected: set[str] | frozenset[str],
    label: str,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"{label} output keys are incomplete")
    if any(not isinstance(item, str) or not item for item in value.values()):
        raise ValueError(f"{label} output contains an empty value")
    return value
