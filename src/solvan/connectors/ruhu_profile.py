"""Strict, observe-only loader for the Ruhu-on-GCP adoption profile."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator


class RuhuProfileError(ValueError):
    """The Ruhu profile would widen the declared adoption boundary."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Owners(StrictModel):
    workload: str
    reliability_control_plane: str
    security: str


class Source(StrictModel):
    repository: str
    commit: str
    deployed_artifact_digest: str
    require_clean_source: bool


class SyntheticScope(StrictModel):
    organization_id: str
    agent_id: str
    contains_real_customer_data: bool


class Environment(StrictModel):
    name: str
    workload_project: str
    control_project: str
    region: str
    require_separate_projects_in_production: bool
    require_same_approved_residency: bool
    synthetic_scope: SyntheticScope


class AdoptionPhase(StrictModel):
    status: Literal["target", "implemented", "verified"]
    mutations_allowed: bool | None = None
    approval_required: bool | None = None
    available: bool | None = None
    blocked_by: str | None = None


class Adoption(StrictModel):
    enabled_phase: Literal[
        "observe_only", "approval_bound_rollback", "bounded_autonomous_pool_recycle"
    ]
    phases: dict[str, AdoptionPhase]


class DataBoundary(StrictModel):
    allowed: list[str]
    denied: list[str]
    memory_promotion_default: Literal["denied"]


class IdentityBoundary(StrictModel):
    allowed: list[str]
    denied: list[str]


class Identities(StrictModel):
    evidence: IdentityBoundary
    infrastructure: IdentityBoundary
    actuator: IdentityBoundary
    verifier: IdentityBoundary


class ProductionGraph(StrictModel):
    require_declared_discovered_reconciliation: bool
    required_nodes: list[str]


class Signals(StrictModel):
    approved_metric_names: list[str]
    availability_preflight: Literal["required"]


class IncidentClass(StrictModel):
    phase: Literal["observe_only", "approval_bound_rollback", "bounded_autonomous_pool_recycle"]
    candidate_action: str
    verification_profile: str
    action_risk: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    approval_required: bool | None = None
    action_available: bool | None = None


class MutationOperation(StrictModel):
    status: Literal["target", "implemented", "verified"]
    approval_required: bool | None = None
    preferred_route: str | None = None
    available: bool | None = None
    required_route: str | None = None


class Tools(StrictModel):
    read: list[str]
    mutation: dict[str, MutationOperation]
    prohibited: list[str]


class Verification(StrictModel):
    independent_identity: bool
    connector_success_is_recovery: bool
    thresholds_require_deployed_calibration: bool
    injector_and_oracle_hidden_from_agents: bool


class RuhuIntegrationProfile(StrictModel):
    schema_version: Literal[1]
    profile_key: Literal["ruhu-gcp-v1"]
    status: Literal["target", "implemented", "verified"]
    competition_release: Literal["excluded"]
    owners: Owners
    source: Source
    environment: Environment
    adoption: Adoption
    data_boundary: DataBoundary
    identities: Identities
    production_graph: ProductionGraph
    signals: Signals
    incident_classes: dict[str, IncidentClass]
    tools: Tools
    verification: Verification
    gates: dict[str, list[str]]

    @model_validator(mode="after")
    def enforce_observe_only_boundary(self) -> RuhuIntegrationProfile:
        required_phases = {
            "observe_only",
            "approval_bound_rollback",
            "bounded_autonomous_pool_recycle",
        }
        if set(self.adoption.phases) != required_phases:
            raise ValueError("Ruhu adoption profile must define all three named phases")
        if self.adoption.enabled_phase != "observe_only":
            raise ValueError("current Solvan build permits only observe-only Ruhu adoption")
        selected = self.adoption.phases["observe_only"]
        if selected.mutations_allowed is not False:
            raise ValueError("observe-only Ruhu adoption must explicitly deny mutations")
        if self.environment.synthetic_scope.contains_real_customer_data:
            raise ValueError("Ruhu synthetic scope cannot contain real customer data")
        if not self.environment.require_same_approved_residency:
            raise ValueError("Ruhu integration must fail closed across residencies")
        if not self.source.require_clean_source:
            raise ValueError("Ruhu integration requires a clean immutable source commit")
        if self.data_boundary.memory_promotion_default != "denied":  # pragma: no cover
            raise ValueError("Ruhu memory promotion must default to denied")
        if any(item.phase != "observe_only" for item in self.incident_classes.values()):
            raise ValueError("current Ruhu incident classes must remain observe-only")
        if any(operation.status != "target" for operation in self.tools.mutation.values()):
            raise ValueError("Ruhu mutation operations are not implemented in this build")
        if any(operation.available is True for operation in self.tools.mutation.values()):
            raise ValueError("Ruhu mutation operation cannot be marked available")
        required_prohibitions = {
            "generic_http",
            "generic_shell",
            "raw_sql",
            "cloud_run_instance_restart",
        }
        if not required_prohibitions.issubset(self.tools.prohibited):
            raise ValueError("Ruhu profile is missing a required prohibited operation")
        required_data_denials = {
            "customer_prompt_or_response",
            "conversation_or_call_transcript",
            "cloud_sql_data_plane",
            "secret_manager_payload",
        }
        if not required_data_denials.issubset(self.data_boundary.denied):
            raise ValueError("Ruhu profile is missing a required sensitive-data denial")
        if "mutation" not in self.identities.evidence.denied:
            raise ValueError("Ruhu evidence identity must have no mutation authority")
        if "mutation" not in self.identities.verifier.denied:
            raise ValueError("Ruhu verifier identity must have no mutation authority")
        if set(self.tools.read) & set(self.tools.prohibited):
            raise ValueError("a Ruhu tool cannot be both allowed and prohibited")
        if set(self.gates) != {"phase_a", "phase_b", "phase_c"}:
            raise ValueError("Ruhu adoption profile must define all phase gates")
        return self

    def deployment_blockers(self) -> tuple[str, ...]:
        """Return evidence placeholders that prevent a deployed Phase A claim."""

        values = {
            "source.repository": self.source.repository,
            "source.commit": self.source.commit,
            "source.deployed_artifact_digest": self.source.deployed_artifact_digest,
            "environment.name": self.environment.name,
            "environment.workload_project": self.environment.workload_project,
            "environment.control_project": self.environment.control_project,
            "environment.region": self.environment.region,
            "environment.synthetic_scope.organization_id": (
                self.environment.synthetic_scope.organization_id
            ),
            "environment.synthetic_scope.agent_id": self.environment.synthetic_scope.agent_id,
        }
        return tuple(key for key, value in values.items() if value.startswith("REPLACE_WITH_"))


def load_ruhu_profile(path: str | Path) -> RuhuIntegrationProfile:
    """Load YAML through a closed schema and semantic least-authority checks."""

    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return RuhuIntegrationProfile.model_validate(raw)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise RuhuProfileError(f"invalid Ruhu integration profile: {exc}") from exc
