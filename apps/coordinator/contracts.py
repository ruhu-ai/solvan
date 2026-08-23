"""Coordinator request contracts, settings, Runtime, and policy composition."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from apps.evidence_broker.contracts import (
    KubernetesMetadataArgs,
    LoggingArgs,
    ManagedPrometheusArgs,
    MonitoringArgs,
    TraceArgs,
)
from solvan.domain import (
    AgentLimit,
    PlanValidationPolicy,
    Scope,
    StepBudget,
)
from solvan.observability import record_control_refusal
from solvan.platform.agent_runtime import (
    AgentRuntimeConfiguration,
    GeminiAgentRuntime,
    VertexAgentPlatformClient,
)
from solvan.platform.deployment_controller import DeploymentControllerConfiguration
from solvan.platform.github_release import GitHubReleaseProviderConfiguration
from solvan.platform.release_verifier import ReleaseVerifierConfiguration


class TickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int


class TickResponse(BaseModel):
    claimed: int
    completed: int


class WorkspaceRehydrationCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    workspace_id: str
    expected_checkpoint_id: str


class WorkspaceRehydrationCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int


class RelayObservabilityJobCommand(BaseModel):
    """Broker-to-coordinator request for one already-reserved Relay Tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    agent_run_id: str
    tool_call_id: str
    arguments: (
        MonitoringArgs | ManagedPrometheusArgs | LoggingArgs | TraceArgs | KubernetesMetadataArgs
    )


class WorkspaceRehydrationCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_id: str
    checkpoint_id: str
    provider_service_revision: str
    reconciliation_pending: bool


class PubSubMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: str
    messageId: str


class PubSubPush(BaseModel):
    model_config = ConfigDict(extra="ignore")

    message: PubSubMessage
    subscription: str


@dataclass(frozen=True, slots=True)
class AntigravityCoordinatorSettings:
    base_url: str
    audience: str
    provider_revision: str
    provider_service_identity: str
    provider_artifact_digest: str
    effective_tool_set_hash: str
    effective_network_policy_hash: str
    fixture_attester_url: str
    fixture_attester_audience: str
    fixture_attester_principal: str
    fixture_attester_kms_key_version: str
    fixture_id: str
    terms_revision: str
    release_commit: str
    deployment_id: str


@dataclass(frozen=True, slots=True)
class WorkspaceSandboxCoordinatorSettings:
    base_url: str
    audience: str
    service_revision: str
    image_hash: str


@dataclass(frozen=True, slots=True)
class WorkspaceAdapterCoordinatorSettings:
    base_url: str
    audience: str


@dataclass(frozen=True, slots=True)
class GovernedAgentBinding:
    profile_key: str
    profile_version: str
    identity_ref: str
    accepted_tool_ordinals: tuple[int, ...]
    connection_epochs: dict[str, int]
    gateway_destinations: frozenset[str]
    data_classification: str

    @classmethod
    def from_json(
        cls,
        agent_key: str,
        value: Any,
        *,
        expected_agent_resource: str | None = None,
    ) -> GovernedAgentBinding:
        if not isinstance(value, dict):
            raise ValueError(f"governed Tool binding for {agent_key} must be an object")
        profile_ref = value.get("profile_ref")
        identity_ref = value.get("identity_ref")
        accepted_ordinals = value.get("accepted_tool_ordinals")
        connections = value.get("connection_epochs")
        destinations = value.get("gateway_destinations")
        classification = value.get("data_classification")
        if not isinstance(profile_ref, str) or profile_ref.count("@") != 1:
            raise ValueError(f"governed Tool binding for {agent_key} lacks an exact profile")
        profile_key, profile_version = profile_ref.split("@", 1)
        if not isinstance(identity_ref, str) or not re.fullmatch(
            r"principal://agents\.global\.(?:org|project)-[0-9]+\.system\.id\.goog/"
            r"resources/aiplatform/projects/[0-9]+/locations/europe-west1/"
            r"reasoningEngines/[A-Za-z0-9_-]+",
            identity_ref,
        ):
            raise ValueError(
                f"governed Tool binding for {agent_key} lacks an attested Agent Identity"
            )
        if expected_agent_resource is not None and not identity_ref.endswith(
            f"/resources/aiplatform/{expected_agent_resource}"
        ):
            raise ValueError(
                f"governed Tool binding for {agent_key} does not match its Runtime resource"
            )
        if (
            not isinstance(accepted_ordinals, list)
            or any(
                not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1
                for ordinal in accepted_ordinals
            )
            or tuple(sorted(set(accepted_ordinals))) != tuple(accepted_ordinals)
        ):
            raise ValueError(
                f"governed Tool binding for {agent_key} has invalid accepted Tool ordinals"
            )
        if not isinstance(connections, dict) or any(
            not isinstance(key, str)
            or not key
            or not isinstance(epoch, int)
            or isinstance(epoch, bool)
            or epoch < 1
            for key, epoch in connections.items()
        ):
            raise ValueError(f"governed Tool binding for {agent_key} has invalid connections")
        if not isinstance(destinations, list) or any(
            not isinstance(item, str) or not item for item in destinations
        ):
            raise ValueError(f"governed Tool binding for {agent_key} has invalid Gateway routes")
        if classification not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
            raise ValueError(f"governed Tool binding for {agent_key} has invalid classification")
        return cls(
            profile_key,
            profile_version,
            identity_ref,
            tuple(accepted_ordinals),
            dict(connections),
            frozenset(destinations),
            str(classification),
        )


@dataclass(frozen=True, slots=True)
class CoordinatorSettings:
    environment: str
    coordinator_service_revision: str
    scope: Scope
    evidence_bucket: str
    runtime_bucket: str
    guidance_bucket: str
    memory_bank_resource: str
    gcp_project_id: str
    gcp_project_number: str
    gcp_region: str
    coordinator_service_account: str
    supervisor_resource: str
    supervisor_revision: str
    evidence_agent_resource: str
    evidence_agent_revision: str
    infrastructure_agent_resource: str
    infrastructure_agent_revision: str
    execution_agent_resource: str
    execution_agent_revision: str
    verification_agent_resource: str
    verification_agent_revision: str
    workspace_agent_resource: str
    workspace_agent_revision: str
    workspace_agent_principal: str
    workspace_sandbox: WorkspaceSandboxCoordinatorSettings
    workspace_adapter: WorkspaceAdapterCoordinatorSettings
    governed_agent_bindings: dict[str, GovernedAgentBinding]
    relay_job_signing_key_id: str | None = None
    relay_job_signing_key_version: str | None = None
    antigravity: AntigravityCoordinatorSettings | None = None
    github_release: GitHubReleaseProviderConfiguration | None = None
    deployment_controller: DeploymentControllerConfiguration | None = None
    release_verifier: ReleaseVerifierConfiguration | None = None

    def __post_init__(self) -> None:
        expected_suffix = f"@{self.gcp_project_id}.iam.gserviceaccount.com"
        if re.fullmatch(
            r"[a-z][a-z0-9-]{2,29}@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com",
            self.coordinator_service_account,
        ) is None or not self.coordinator_service_account.endswith(expected_suffix):
            raise ValueError("coordinator service account is not bound to the GCP project")

    @property
    def coordinator_principal(self) -> str:
        return f"serviceAccount:{self.coordinator_service_account}"

    def binding_for(self, agent_key: str) -> GovernedAgentBinding:
        try:
            return self.governed_agent_bindings[agent_key]
        except KeyError as error:
            raise RuntimeError(f"governed Tool binding for {agent_key} is missing") from error


_ENTRY_TRANSITIONS = {
    "IncidentDetected": ("DETECTED", "TRIAGING", "TRIAGE_STARTED"),
    "TRIAGE_STARTED": ("TRIAGING", "INVESTIGATING", "INVESTIGATION_STARTED"),
}


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required coordinator setting {name} is missing")
    return value


def governed_agent_bindings_from_environment(
    *, agent_resources: dict[str, str]
) -> dict[str, GovernedAgentBinding]:
    """Load only the exact catalog bindings required by dispatch-capable jobs."""

    try:
        binding_value = json.loads(_required("SOLVAN_AGENT_TOOL_BINDINGS_JSON"))
    except json.JSONDecodeError as error:
        raise RuntimeError("SOLVAN_AGENT_TOOL_BINDINGS_JSON is invalid") from error
    required_agents = {
        "incident-supervisor",
        "evidence-agent",
        "infrastructure-agent",
        "execution-agent",
        "verification-agent",
        "workspace-agent",
    }
    if not isinstance(binding_value, dict) or set(binding_value) != required_agents:
        raise RuntimeError("governed Agent Tool bindings must name the exact Agent fleet")
    if set(agent_resources) != required_agents or any(
        not resource or resource == "UNCONFIGURED" for resource in agent_resources.values()
    ):
        raise RuntimeError("exact deployed Agent Runtime resources are required for Tool binding")
    return {
        key: GovernedAgentBinding.from_json(
            key,
            value,
            expected_agent_resource=agent_resources[key],
        )
        for key, value in binding_value.items()
    }


def governed_agent_resources_from_environment() -> dict[str, str]:
    """Load the exact deployed Runtime resources for all dispatchable Agents."""

    return {
        "incident-supervisor": _required("SOLVAN_INCIDENT_SUPERVISOR_RESOURCE"),
        "evidence-agent": _required("SOLVAN_EVIDENCE_AGENT_RESOURCE"),
        "infrastructure-agent": _required("SOLVAN_INFRASTRUCTURE_AGENT_RESOURCE"),
        "execution-agent": _required("SOLVAN_EXECUTION_AGENT_RESOURCE"),
        "verification-agent": _required("SOLVAN_VERIFICATION_AGENT_RESOURCE"),
        "workspace-agent": _required("SOLVAN_WORKSPACE_AGENT_RESOURCE"),
    }


def _settings() -> CoordinatorSettings:
    antigravity_enabled = _required("SOLVAN_ANTIGRAVITY_ENABLED").lower() == "true"
    antigravity = (
        AntigravityCoordinatorSettings(
            base_url=_required("SOLVAN_ANTIGRAVITY_URL"),
            audience=_required("SOLVAN_ANTIGRAVITY_AUDIENCE"),
            provider_revision=_required("SOLVAN_ANTIGRAVITY_PROVIDER_REVISION"),
            provider_service_identity=_required("SOLVAN_ANTIGRAVITY_SERVICE_IDENTITY"),
            provider_artifact_digest=_required("SOLVAN_ANTIGRAVITY_ARTIFACT_DIGEST"),
            effective_tool_set_hash=_required("SOLVAN_ANTIGRAVITY_TOOL_SET_HASH"),
            effective_network_policy_hash=_required("SOLVAN_ANTIGRAVITY_NETWORK_POLICY_HASH"),
            fixture_attester_url=_required("SOLVAN_FIXTURE_ATTESTER_URL"),
            fixture_attester_audience=_required("SOLVAN_FIXTURE_ATTESTER_AUDIENCE"),
            fixture_attester_principal=_required("SOLVAN_FIXTURE_ATTESTER_PRINCIPAL"),
            fixture_attester_kms_key_version=_required("SOLVAN_FIXTURE_ATTESTER_KMS_KEY_VERSION"),
            fixture_id=_required("SOLVAN_SYNTHETIC_FIXTURE_ID"),
            terms_revision=_required("SOLVAN_ANTIGRAVITY_TERMS_REVISION"),
            release_commit=_required("SOLVAN_RELEASE_COMMIT"),
            deployment_id=_required("SOLVAN_DEPLOYMENT_ID"),
        )
        if antigravity_enabled
        else None
    )
    github_release_enabled = (
        os.environ.get("SOLVAN_GITHUB_RELEASE_ENABLED", "false").lower() == "true"
    )
    github_repository_id = os.environ.get("SOLVAN_GITHUB_REPOSITORY_ID", "UNCONFIGURED")
    if github_release_enabled and not github_repository_id.startswith("ghr_"):
        # Enabled without a real binding is a contradiction, and it used to be
        # a control-plane outage: the placeholder refused inside the dataclass,
        # settings construction raised, and every coordinator route 500ed --
        # including workspace rehydration, which has nothing to do with GitHub
        # (staging-20260823-05). One feature's misconfiguration must fail that
        # feature closed, loudly, and nothing else. Terraform now also refuses
        # this pairing at plan time; this is the runtime half.
        record_control_refusal(
            service_name="coordinator",
            reason_code="GITHUB_RELEASE_BINDING_INVALID",
        )
        github_release_enabled = False
    github_release = (
        GitHubReleaseProviderConfiguration(
            base_url=_required("SOLVAN_GITHUB_PROVIDER_URL"),
            audience=_required("SOLVAN_GITHUB_PROVIDER_AUDIENCE"),
            repository_id=github_repository_id,
        )
        if github_release_enabled
        else None
    )
    deployment_controller_enabled = (
        os.environ.get("SOLVAN_DEPLOYMENT_CONTROLLER_ENABLED", "false").lower() == "true"
    )
    deployment_controller = (
        DeploymentControllerConfiguration(
            base_url=_required("SOLVAN_DEPLOYMENT_CONTROLLER_URL"),
            audience=_required("SOLVAN_DEPLOYMENT_CONTROLLER_AUDIENCE"),
            service_principal=(
                "serviceAccount:" + _required("SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT")
            ),
        )
        if deployment_controller_enabled
        else None
    )
    release_verifier_enabled = (
        os.environ.get("SOLVAN_RELEASE_VERIFIER_ENABLED", "false").lower() == "true"
    )
    release_verifier = (
        ReleaseVerifierConfiguration(
            base_url=_required("SOLVAN_RELEASE_VERIFIER_URL"),
            audience=_required("SOLVAN_RELEASE_VERIFIER_AUDIENCE"),
            service_principal=(
                "serviceAccount:" + _required("SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT")
            ),
        )
        if release_verifier_enabled
        else None
    )
    agent_resources = governed_agent_resources_from_environment()
    return CoordinatorSettings(
        environment=_required("SOLVAN_ENVIRONMENT"),
        coordinator_service_revision=os.environ.get("K_REVISION", "LOCAL_UNQUALIFIED"),
        scope=Scope(
            _required("SOLVAN_ORGANIZATION_ID"),
            _required("SOLVAN_SCOPE_PROJECT_ID"),
            _required("SOLVAN_ENVIRONMENT_ID"),
        ),
        evidence_bucket=_required("SOLVAN_EVIDENCE_BUCKET"),
        runtime_bucket=_required("SOLVAN_RUNTIME_BUCKET"),
        guidance_bucket=_required("SOLVAN_GUIDANCE_BUCKET"),
        memory_bank_resource=_required("SOLVAN_MEMORY_BANK_RESOURCE"),
        gcp_project_id=_required("SOLVAN_GCP_PROJECT"),
        gcp_project_number=_required("SOLVAN_GCP_PROJECT_NUMBER"),
        gcp_region=_required("SOLVAN_GCP_REGION"),
        coordinator_service_account=_required("SOLVAN_COORDINATOR_SERVICE_ACCOUNT"),
        supervisor_resource=agent_resources["incident-supervisor"],
        supervisor_revision=_required("SOLVAN_INCIDENT_SUPERVISOR_REVISION"),
        evidence_agent_resource=agent_resources["evidence-agent"],
        evidence_agent_revision=_required("SOLVAN_EVIDENCE_AGENT_REVISION"),
        infrastructure_agent_resource=agent_resources["infrastructure-agent"],
        infrastructure_agent_revision=_required("SOLVAN_INFRASTRUCTURE_AGENT_REVISION"),
        execution_agent_resource=agent_resources["execution-agent"],
        execution_agent_revision=_required("SOLVAN_EXECUTION_AGENT_REVISION"),
        verification_agent_resource=agent_resources["verification-agent"],
        verification_agent_revision=_required("SOLVAN_VERIFICATION_AGENT_REVISION"),
        workspace_agent_resource=agent_resources["workspace-agent"],
        workspace_agent_revision=_required("SOLVAN_WORKSPACE_AGENT_REVISION"),
        workspace_agent_principal=_required("SOLVAN_WORKSPACE_AGENT_PRINCIPAL"),
        workspace_sandbox=WorkspaceSandboxCoordinatorSettings(
            base_url=_required("SOLVAN_WORKSPACE_SANDBOX_URL"),
            audience=_required("SOLVAN_WORKSPACE_SANDBOX_AUDIENCE"),
            service_revision=_required("SOLVAN_WORKSPACE_SANDBOX_REVISION"),
            image_hash=_required("SOLVAN_WORKSPACE_SANDBOX_IMAGE_HASH"),
        ),
        workspace_adapter=WorkspaceAdapterCoordinatorSettings(
            base_url=_required("SOLVAN_WORKSPACE_ADAPTER_URL"),
            audience=_required("SOLVAN_WORKSPACE_ADAPTER_AUDIENCE"),
        ),
        governed_agent_bindings=governed_agent_bindings_from_environment(
            agent_resources=agent_resources
        ),
        relay_job_signing_key_id=os.environ.get("SOLVAN_RELAY_JOB_SIGNING_KEY_ID"),
        relay_job_signing_key_version=os.environ.get("SOLVAN_RELAY_JOB_SIGNING_KEY_VERSION"),
        antigravity=antigravity,
        github_release=github_release,
        deployment_controller=deployment_controller,
        release_verifier=release_verifier,
    )


def _runtime(settings: CoordinatorSettings) -> GeminiAgentRuntime:
    return GeminiAgentRuntime(
        config=AgentRuntimeConfiguration(
            gcp_project_id=settings.gcp_project_id,
            gcp_project_number=settings.gcp_project_number,
            location=settings.gcp_region,
            output_gcs_prefix=f"gs://{settings.runtime_bucket}/query-jobs",
        ),
        client=VertexAgentPlatformClient(
            project=settings.gcp_project_id, location=settings.gcp_region
        ),
    )


def _investigation_policy(settings: CoordinatorSettings) -> PlanValidationPolicy:
    scope_refs = frozenset({"scope:primary-service"})
    return PlanValidationPolicy(
        agent_limits={
            "evidence-agent": AgentLimit(
                agent_resource=settings.evidence_agent_resource,
                agent_revision=settings.evidence_agent_revision,
                maximum=StepBudget(300_000, 10, 128_000, 4, 1),
                allowed_scope_refs=scope_refs,
                allowed_tool_names=(
                    "cloud_logging_query",
                    "cloud_monitoring_query",
                    "cloud_trace_read",
                    "cloud_audit_log_query",
                    "error_reporting_query",
                    "managed_prometheus_query",
                    "metric_baseline_compare",
                    "metric_change_point_detect",
                    "metric_correlate",
                    "log_pattern_summary",
                    "log_sample_bounded",
                ),
            ),
            "infrastructure-agent": AgentLimit(
                agent_resource=settings.infrastructure_agent_resource,
                agent_revision=settings.infrastructure_agent_revision,
                maximum=StepBudget(300_000, 8, 128_000, 4, 1),
                allowed_scope_refs=scope_refs,
                allowed_tool_names=(
                    "cloud_run_read",
                    "cloud_sql_metadata_read",
                    "production_graph_read",
                    "cloud_asset_inventory_search",
                    "cloud_run_revision_compare",
                    "github_commit_range_read",
                    "github_pr_diff_read",
                    "github_workflow_run_read",
                    "cloud_build_history_read",
                ),
            ),
        },
        allowed_scope_refs=scope_refs,
        maximum_steps=6,
        required_agent_keys=frozenset({"evidence-agent", "infrastructure-agent"}),
    )
