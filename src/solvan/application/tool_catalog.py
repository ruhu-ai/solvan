"""Fail-closed governed Tool Catalog and immutable capability profiles.

The catalog is application policy, not model context.  It resolves an exact
ordered set of approved revisions before dispatch and rejects discovery-only,
wildcard, stale, implicit-connection, and mutation-bearing profiles.
Specification 16 is the governing contract.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.capability_resolution import CapabilityLayer
from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolConnectionBindingKind,
    ToolRevisionRefV1,
)
from solvan.application.workspace_hashing import canonical_sha256


class ToolCatalogError(RuntimeError):
    """Catalog material is absent, ambiguous, stale, or unauthorized.

    Every refusal `resolve` raises names the authority that refused, drawn from
    the same enumeration the operator console renders. That is what keeps one
    rule: the console derived its own weaker predicate list and the two drifted
    into disagreeing about fourteen of twenty-three capabilities, so a predicate
    added here without a layer is now a visible omission rather than a silent
    divergence. `run_scoped` marks the refusals that belong to one run rather
    than to standing capability — a verified identity, a known run
    classification, a frozen target project — which the matrix cannot and must
    not claim to answer.

    `str(error)` is unchanged; the message stays the sole positional argument.
    """

    def __init__(
        self,
        message: str,
        *,
        layer: CapabilityLayer | None = None,
        run_scoped: bool = False,
    ) -> None:
        super().__init__(message)
        self.layer = layer
        self.run_scoped = run_scoped


_DATA_CLASSIFICATIONS = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"})
#: The one ordering of data sensitivity. It was declared here and again as a
#: literal inside the run binder, so a fourth reader had no single place to
#: take it from — the shape of divergence this whole change exists to close.
DATA_CLASSIFICATION_RANKS = {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
}


class RegistryKind(StrEnum):
    AGENT = "AGENT"
    DETERMINISTIC_SERVICE = "DETERMINISTIC_SERVICE"


class ExecutionRole(StrEnum):
    SUPERVISOR = "SUPERVISOR"
    SPECIALIST = "SPECIALIST"
    WORKSPACE = "WORKSPACE"
    WORKSPACE_PROVIDER = "WORKSPACE_PROVIDER"
    SERVICE = "SERVICE"


class PermissionClass(StrEnum):
    READ = "READ"
    COMPUTE = "COMPUTE"
    PROPOSE = "PROPOSE"
    MUTATE = "MUTATE"


class ImplementationKind(StrEnum):
    APPLICATION_SERVICE = "APPLICATION_SERVICE"
    CONNECTOR = "CONNECTOR"
    DETERMINISTIC_SERVICE = "DETERMINISTIC_SERVICE"
    MCP = "MCP"


class CatalogLifecycle(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"


class EvidenceKind(StrEnum):
    LOGS = "LOGS"
    METRICS = "METRICS"
    TRACES = "TRACES"
    EVENTS = "EVENTS"
    TOPOLOGY = "TOPOLOGY"
    DEPLOYMENT_METADATA = "DEPLOYMENT_METADATA"
    QUERY_STATS = "QUERY_STATS"
    ARTIFACT = "ARTIFACT"
    NONE = "NONE"


class NoDataSemantics(StrEnum):
    HEALTHY = "HEALTHY"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ModelArmorCoverage(StrEnum):
    SUPPORTED_OPERATION = "SUPPORTED_OPERATION"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class IdempotencyKind(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NATIVE = "NATIVE"
    SOLVAN_RECONCILED = "SOLVAN_RECONCILED"


class CatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CatalogPrincipal(CatalogModel):
    principal_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    display_name: str = Field(min_length=1, max_length=120)
    registry_kind: RegistryKind
    execution_role: ExecutionRole
    model_backed: bool
    manifest_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if self.model_backed != (self.registry_kind is RegistryKind.AGENT):
            raise ValueError("only AGENT catalog principals are model-backed")
        if self.model_backed and self.execution_role is ExecutionRole.SERVICE:
            raise ValueError("a model-backed Agent cannot have the deterministic service role")
        if not self.model_backed and self.execution_role is not ExecutionRole.SERVICE:
            raise ValueError("a deterministic service must use the SERVICE execution role")
        return self


class ToolRevision(CatalogModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    tool_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    display_name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=1000)
    use_cases: tuple[str, ...]
    anti_use_cases: tuple[str, ...]
    owner_department: str = Field(min_length=1, max_length=160)
    permission_class: PermissionClass
    implementation_kind: ImplementationKind
    allowed_requester_keys: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    required_connection_providers: tuple[str, ...]
    input_schema_ref: str = Field(min_length=1)
    input_schema_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    output_schema_ref: str = Field(min_length=1)
    output_schema_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evidence_kind: EvidenceKind
    output_semantics: tuple[str, ...]
    supported_retrieval_controls: tuple[str, ...]
    no_data_semantics: NoDataSemantics
    failure_taxonomy: tuple[str, ...]
    supported_data_classes: tuple[str, ...]
    runtime_regions: tuple[str, ...]
    gateway_destination: str = Field(min_length=1)
    registry_resource: str = Field(min_length=1)
    model_armor_coverage: ModelArmorCoverage
    network_policy_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    timeout_ms: int = Field(ge=1, le=300_000)
    max_input_bytes: int = Field(ge=1, le=10_000_000)
    max_output_bytes: int = Field(ge=1, le=10_000_000)
    default_call_budget: int = Field(ge=1, le=100)
    idempotency: IdempotencyKind
    lifecycle: CatalogLifecycle
    approval_ref: str | None = None
    evaluation_ref: str | None = None
    supersedes: str | None = None

    @property
    def revision_ref(self) -> str:
        return f"{self.tool_key}@{self.version}"

    @property
    def content_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        required_sets = {
            "use cases": self.use_cases,
            "anti-use cases": self.anti_use_cases,
            "allowed requester keys": self.allowed_requester_keys,
            "required capabilities": self.required_capabilities,
            "required connection providers": self.required_connection_providers,
            "output semantics": self.output_semantics,
            "supported retrieval controls": self.supported_retrieval_controls,
            "supported data classes": self.supported_data_classes,
            "runtime regions": self.runtime_regions,
            "failure taxonomy": self.failure_taxonomy,
        }
        for label, values in required_sets.items():
            if not values:
                raise ValueError(f"{label} must not be empty")
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must contain unique values")
            if any(not value.strip() for value in values):
                raise ValueError(f"{label} contains an empty value")
        if self.permission_class is PermissionClass.MUTATE and (
            self.implementation_kind is not ImplementationKind.DETERMINISTIC_SERVICE
        ):
            raise ValueError("MUTATE is restricted to deterministic services")
        if self.lifecycle is CatalogLifecycle.APPROVED and (
            not self.approval_ref or not self.evaluation_ref
        ):
            raise ValueError("an approved Tool revision requires approval and evaluation")
        if self.supersedes == self.revision_ref:
            raise ValueError("a Tool revision cannot supersede itself")
        if not set(self.supported_data_classes).issubset(_DATA_CLASSIFICATIONS):
            raise ValueError("supported data classes must use the closed classification set")
        return self


#: Specification 16: provider and capability form a closed pair, not two freely
#: combinable enums. The same pairs are enumerated by the CHECK constraint on
#: `solvan_operability.tool_profile_connection_requirements`, and
#: `test_source_connection_pairs_match_the_authoritative_ddl` fails if the two
#: ever diverge — they did, in opposite directions, and a profile this layer
#: accepted was one the schema refused to store. Adding a pair requires its
#: Tool revision, capability probe/coverage semantics, threat model, target
#: DDL, and negative fixtures in the same change.
SOURCE_CONNECTION_PAIRS: dict[str, str] = {
    "CLOUD_MONITORING": "METRIC_READ",
    "CLOUD_LOGGING": "LOG_SEARCH",
    "CLOUD_AUDIT": "AUDIT_LOG_READ",
    "CLOUD_TRACE": "TRACE_READ",
    "MANAGED_PROMETHEUS": "PROMQL_READ",
    "KUBERNETES": "KUBERNETES_METADATA_READ",
    "ERROR_REPORTING": "ERROR_GROUP_READ",
    "CLOUD_RUN": "RESOURCE_METADATA_READ",
    "CLOUD_SQL": "RESOURCE_METADATA_READ",
}


class ToolConnectionRequirement(CatalogModel):
    """Closed symbolic requirement resolved to an instance at run binding."""

    ordinal: int = Field(ge=1)
    tool_revision: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*@[^@]+$")
    binding_kind: ToolConnectionBindingKind
    provider: str | None = None
    capability_key: str | None = None
    external_project_selector: str | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.binding_kind is ToolConnectionBindingKind.COMPUTE_ONLY:
            if any(
                value is not None
                for value in (
                    self.provider,
                    self.capability_key,
                    self.external_project_selector,
                )
            ):
                raise ValueError("compute-only requirements cannot name a connection")
        elif (
            SOURCE_CONNECTION_PAIRS.get(self.provider or "") != self.capability_key
            or self.external_project_selector != "TARGET_RESOURCE_PROJECT"
        ):
            raise ValueError("policy-source requirements must use a closed read-provider shape")
        return self


class ToolProfileRevision(CatalogModel):
    schema_version: int = Field(default=2, ge=2, le=2)
    canonicalization_version: int = Field(default=1, ge=1, le=1)
    profile_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    purpose: str = Field(min_length=1, max_length=500)
    allowed_agent_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    tool_revisions: tuple[str, ...]
    maximum_total_calls: int = Field(ge=0, le=1000)
    maximum_parallel_calls: int = Field(ge=0, le=100)
    # Zero explicitly denies time-windowed source retrieval for profiles that
    # operate only on Coordinator-materialized artifacts or local compute.
    maximum_read_window_ms: int = Field(default=3_600_000, ge=0)
    maximum_aggregate_evidence_bytes: int = Field(default=1_048_576, gt=0)
    tool_connection_requirements: tuple[ToolConnectionRequirement, ...]
    data_classification_ceiling: str
    runtime_region: str = Field(min_length=1)
    lifecycle: CatalogLifecycle
    approval_ref: str | None = None
    evaluation_ref: str | None = None

    @property
    def profile_ref(self) -> str:
        return f"{self.profile_key}@{self.version}"

    @property
    def profile_material_hash(self) -> str:
        # Approval/evaluation references and resolved connection instances are
        # deliberately outside the immutable profile material.  Instances are
        # selected only after the coordinator evaluates this symbolic contract.
        material = {
            "schema_version": self.schema_version,
            "canonicalization_version": self.canonicalization_version,
            "profile_key": self.profile_key,
            "version": self.version,
            "purpose": self.purpose,
            "allowed_agent_key": self.allowed_agent_key,
            "tool_revisions": list(self.tool_revisions),
            "tool_connection_requirements": [
                requirement.model_dump(mode="json")
                for requirement in self.tool_connection_requirements
            ],
            "maximum_total_calls": self.maximum_total_calls,
            "maximum_parallel_calls": self.maximum_parallel_calls,
            "maximum_read_window_ms": self.maximum_read_window_ms,
            "maximum_aggregate_evidence_bytes": self.maximum_aggregate_evidence_bytes,
            "data_classification_ceiling": self.data_classification_ceiling,
            "runtime_region": self.runtime_region,
        }
        return canonical_sha256(material)

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        for revision in self.tool_revisions:
            if "*" in revision or revision.count("@") != 1:
                raise ValueError("profile members must be exact Tool revision references")
        if len(self.tool_revisions) != len(self.tool_connection_requirements):
            raise ValueError("every Tool revision requires exactly one connection requirement")
        if any(
            requirement.ordinal != ordinal or requirement.tool_revision != revision
            for ordinal, (revision, requirement) in enumerate(
                zip(self.tool_revisions, self.tool_connection_requirements, strict=True), start=1
            )
        ):
            raise ValueError("Tool connection requirements must match ordered Tool revisions")
        if len(self.tool_revisions) != len(set(self.tool_revisions)):
            raise ValueError("a profile cannot repeat a Tool revision")
        if self.maximum_parallel_calls > self.maximum_total_calls:
            raise ValueError("parallel calls cannot exceed the total call budget")
        if not self.tool_revisions and (
            self.maximum_total_calls != 0 or self.maximum_parallel_calls != 0
        ):
            raise ValueError("a tool-less profile must have a zero call budget")
        if self.tool_revisions and (
            self.maximum_total_calls == 0 or self.maximum_parallel_calls == 0
        ):
            raise ValueError("a Tool profile requires a positive call budget")
        if self.lifecycle is CatalogLifecycle.APPROVED and (
            not self.approval_ref or not self.evaluation_ref
        ):
            raise ValueError("an approved profile requires approval and evaluation")
        if self.data_classification_ceiling not in _DATA_CLASSIFICATIONS:
            raise ValueError("Tool profile classification ceiling is unknown")
        return self


class CapabilityProbe(CatalogModel):
    connection_id: str = Field(min_length=1)
    tool_revision: str = Field(pattern=r"^[^*@]+@[^*@]+$")
    agent_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    connection_provider: str = Field(min_length=1)
    capabilities: frozenset[str]
    connection_epoch: int = Field(ge=1)
    identity_ref: str = Field(min_length=1)
    registry_resource: str = Field(min_length=1)
    gateway_policy_ref: str = Field(min_length=1)
    network_policy_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    region: str = Field(min_length=1)
    classification_ceiling: str = Field(min_length=1)
    outcome: str = Field(pattern=r"^(PASSED|FAILED)$")
    reason_code: str | None = None
    missing_grant: str | None = None
    observed_at: datetime
    expires_at: datetime
    receipt_ref: str = Field(min_length=1)
    receipt_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_probe(self) -> Self:
        if self.observed_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("probe timestamps require timezones")
        if self.expires_at <= self.observed_at:
            raise ValueError("a probe must expire after observation")
        if self.outcome == "PASSED" and (self.reason_code or self.missing_grant):
            raise ValueError("a successful probe cannot report a missing grant")
        if self.outcome == "FAILED" and (not self.reason_code or not self.missing_grant):
            raise ValueError("a failed probe requires reason and actionable missing grant")
        return self


class ProfileResolutionContext(CatalogModel):
    agent_key: str
    agent_revision: str
    scope: dict[str, str]
    identity_ref: str
    identity_verified: bool
    runtime_region: str
    data_classification: str
    connection_epochs: dict[str, int]
    registered_gateway_destinations: frozenset[str]
    target_external_project_id: str | None = None
    policy_head_activation_id: str | None = None
    policy_head_epoch: int = Field(default=0, ge=0)
    placement_epoch: int = Field(ge=1)
    accepted_step_budget_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    now: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ResolvedToolSet(CatalogModel):
    profile_key: str
    profile_version: str
    profile_material_hash: str
    ordered_tool_revisions: tuple[str, ...]
    effective_tool_set_hash: str
    connection_epochs: dict[str, int]


class ToolCatalog:
    """In-memory policy engine over repository-loaded immutable revisions."""

    def __init__(
        self,
        *,
        principals: tuple[CatalogPrincipal, ...],
        tools: tuple[ToolRevision, ...],
        probes: tuple[CapabilityProbe, ...],
    ) -> None:
        self._principals = {item.principal_key: item for item in principals}
        self._tools = {item.revision_ref: item for item in tools}
        self._probes = {
            (item.connection_id, item.tool_revision, item.agent_key): item for item in probes
        }
        if len(self._principals) != len(principals) or len(self._tools) != len(tools):
            raise ToolCatalogError("catalog principal and Tool revision keys must be unique")

    def resolve(
        self, *, profile: ToolProfileRevision, context: ProfileResolutionContext
    ) -> ResolvedToolSet:
        if profile.lifecycle is not CatalogLifecycle.APPROVED:
            raise ToolCatalogError(
                "only an approved profile may enter a new run",
                layer=CapabilityLayer.PROFILE_MEMBERSHIP,
            )
        principal = self._principals.get(context.agent_key)
        if principal is None or not principal.model_backed:
            raise ToolCatalogError(
                "the requested Agent is not an approved model-backed principal",
                layer=CapabilityLayer.REQUESTER_DECLARATION,
            )
        if context.agent_key != profile.allowed_agent_key:
            raise ToolCatalogError(
                "the profile is bound to a different Agent",
                layer=CapabilityLayer.PROFILE_MEMBERSHIP,
            )
        if not context.identity_verified or not context.identity_ref:
            raise ToolCatalogError("verified Agent Identity is required", run_scoped=True)
        # A POLICY_BOUND profile matches any run region: its region comes from
        # the bound connection's policy, not the run's placement. This mirrors
        # the production SQL binder exactly.
        if profile.runtime_region not in {context.runtime_region, "POLICY_BOUND"}:
            raise ToolCatalogError(
                "the profile runtime region does not match the run",
                layer=CapabilityLayer.CLASSIFICATION_AND_REGION,
            )
        if context.data_classification not in DATA_CLASSIFICATION_RANKS:
            raise ToolCatalogError("the run data classification is unknown", run_scoped=True)
        if (
            DATA_CLASSIFICATION_RANKS[context.data_classification]
            > DATA_CLASSIFICATION_RANKS[profile.data_classification_ceiling]
        ):
            raise ToolCatalogError(
                "run classification exceeds the Tool profile ceiling",
                layer=CapabilityLayer.CLASSIFICATION_AND_REGION,
            )
        ordered: list[str] = []
        accepted_tools: list[ToolRevisionRefV1] = []
        effective_bindings: list[EffectiveToolBindingV1] = []
        proven_connections: set[str] = set()
        for revision_ref, requirement in zip(
            profile.tool_revisions, profile.tool_connection_requirements, strict=True
        ):
            revision = self._tools.get(revision_ref)
            if revision is None or revision.lifecycle is not CatalogLifecycle.APPROVED:
                raise ToolCatalogError(
                    f"Tool revision {revision_ref} is unavailable for new work",
                    layer=CapabilityLayer.REVISION_LIFECYCLE,
                )
            if context.agent_key not in revision.allowed_requester_keys:
                raise ToolCatalogError(
                    f"Tool revision {revision_ref} does not allow this Agent",
                    layer=CapabilityLayer.REQUESTER_DECLARATION,
                )
            if revision.permission_class is PermissionClass.MUTATE:
                raise ToolCatalogError(
                    "a model-backed Agent profile cannot contain MUTATE",
                    layer=CapabilityLayer.REVISION_LIFECYCLE,
                )
            if context.data_classification not in revision.supported_data_classes:
                raise ToolCatalogError(
                    f"Tool revision {revision_ref} does not support the run classification",
                    layer=CapabilityLayer.CLASSIFICATION_AND_REGION,
                )
            if context.runtime_region not in revision.runtime_regions:
                raise ToolCatalogError(
                    f"Tool revision {revision_ref} is unavailable in this region",
                    layer=CapabilityLayer.CLASSIFICATION_AND_REGION,
                )
            if revision.gateway_destination not in context.registered_gateway_destinations:
                raise ToolCatalogError(
                    f"Tool revision {revision_ref} has no registered Gateway route",
                    layer=CapabilityLayer.GATEWAY_ROUTE,
                )
            if requirement.binding_kind is ToolConnectionBindingKind.COMPUTE_ONLY:
                # A compute-only Tool binds no connection itself; connections
                # in the context belong to the profile's source-bound Tools.
                # Refusing them here rejected every mixed profile the catalog
                # ships, while the production binder simply accepts.
                ordered.append(revision_ref)
                accepted_tools.append(
                    ToolRevisionRefV1(tool_key=revision.tool_key, version=revision.version)
                )
                effective_bindings.append(
                    EffectiveToolBindingV1(
                        binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
                        tool=accepted_tools[-1],
                    )
                )
                continue
            if not context.connection_epochs:
                raise ToolCatalogError(
                    "a policy-source Tool requires an exact connection",
                    layer=CapabilityLayer.CONNECTION_BINDING,
                )
            eligible_probe: CapabilityProbe | None = None
            observed_probe = False
            stale_probe = False
            wrong_epoch = False
            wrong_identity = False
            incompatible_provider = False
            missing_capability = False
            for connection_id, epoch in context.connection_epochs.items():
                probe = self._probes.get((connection_id, revision_ref, context.agent_key))
                if probe is None:
                    continue
                observed_probe = True
                if probe.outcome != "PASSED" or context.now >= probe.expires_at:
                    stale_probe = True
                    continue
                if probe.connection_epoch != epoch:
                    wrong_epoch = True
                    continue
                if probe.identity_ref != context.identity_ref:
                    wrong_identity = True
                    continue
                if probe.connection_provider not in revision.required_connection_providers:
                    incompatible_provider = True
                    continue
                if requirement.provider != probe.connection_provider:
                    incompatible_provider = True
                    continue
                if requirement.capability_key not in probe.capabilities:
                    missing_capability = True
                    continue
                if not set(revision.required_capabilities).issubset(probe.capabilities):
                    missing_capability = True
                    continue
                eligible_probe = probe
                proven_connections.add(connection_id)
            if eligible_probe is None:
                if wrong_identity:
                    raise ToolCatalogError(
                        f"Tool revision {revision_ref} was probed under another identity",
                        layer=CapabilityLayer.CAPABILITY_PROBE,
                    )
                if wrong_epoch:
                    raise ToolCatalogError(
                        f"Tool revision {revision_ref} has a stale connection epoch",
                        layer=CapabilityLayer.CAPABILITY_PROBE,
                    )
                if stale_probe:
                    raise ToolCatalogError(
                        f"Tool revision {revision_ref} capability proof is stale or failed",
                        layer=CapabilityLayer.CAPABILITY_PROBE,
                    )
                if incompatible_provider:
                    raise ToolCatalogError(
                        f"Tool revision {revision_ref} has an incompatible connection provider",
                        layer=CapabilityLayer.CAPABILITY_PROBE,
                    )
                if missing_capability:
                    raise ToolCatalogError(
                        f"Tool revision {revision_ref} is missing a required capability",
                        layer=CapabilityLayer.CAPABILITY_PROBE,
                    )
                if observed_probe:
                    raise ToolCatalogError(
                        f"Tool revision {revision_ref} has no eligible exact capability proof",
                        layer=CapabilityLayer.CAPABILITY_PROBE,
                    )
                raise ToolCatalogError(
                    f"Tool revision {revision_ref} has no current exact capability proof",
                    layer=CapabilityLayer.CAPABILITY_PROBE,
                )
            ordered.append(revision_ref)
            if context.target_external_project_id is None:
                raise ToolCatalogError(
                    "a policy-source Tool requires an exact target project", run_scoped=True
                )
            accepted_tools.append(
                ToolRevisionRefV1(tool_key=revision.tool_key, version=revision.version)
            )
            effective_bindings.append(
                EffectiveToolBindingV1(
                    binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                    tool=accepted_tools[-1],
                    provider=requirement.provider,
                    capability_key=requirement.capability_key,
                    external_project_selector=requirement.external_project_selector,
                    connection_id=eligible_probe.connection_id,
                    connection_epoch=eligible_probe.connection_epoch,
                    capability_receipt_id=eligible_probe.receipt_ref,
                    capability_receipt_hash=eligible_probe.receipt_hash,
                    external_project_id=context.target_external_project_id,
                )
            )

        if not profile.tool_connection_requirements and context.connection_epochs:
            raise ToolCatalogError(
                "a tool-less profile cannot bind external connections",
                layer=CapabilityLayer.CONNECTION_BINDING,
            )
        if profile.tool_connection_requirements and (
            not any(
                requirement.binding_kind is ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION
                for requirement in profile.tool_connection_requirements
            )
            and context.connection_epochs
        ):
            raise ToolCatalogError(
                "a compute-only profile cannot bind external connections",
                layer=CapabilityLayer.CONNECTION_BINDING,
            )

        if proven_connections != set(context.connection_epochs):
            raise ToolCatalogError(
                "one or more profile connections prove no frozen Tool",
                layer=CapabilityLayer.CONNECTION_BINDING,
            )

        effective = EffectiveToolSetV1(
            profile_material_hash=profile.profile_material_hash,
            accepted_tools=tuple(accepted_tools),
            agent_key=context.agent_key,
            agent_revision=context.agent_revision,
            scope=context.scope,
            connection_bindings=tuple(effective_bindings),
            runtime_region=context.runtime_region,
            accepted_data_classification=context.data_classification,
            classification_ceiling=profile.data_classification_ceiling,
            policy_head_activation_id=context.policy_head_activation_id,
            policy_head_epoch=context.policy_head_epoch,
            placement_epoch=context.placement_epoch,
            accepted_step_budget_hash=context.accepted_step_budget_hash,
        )
        return ResolvedToolSet(
            profile_key=profile.profile_key,
            profile_version=profile.version,
            profile_material_hash=profile.profile_material_hash,
            ordered_tool_revisions=tuple(ordered),
            effective_tool_set_hash=effective.effective_tool_set_hash,
            connection_epochs=context.connection_epochs,
        )
