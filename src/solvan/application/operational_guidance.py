"""Immutable Operational Guidance and trigger-policy application contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.tool_catalog import (
    CatalogLifecycle,
    PermissionClass,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.application.workspace_hashing import canonical_sha256


class GuidanceError(RuntimeError):
    """Guidance material is ineligible, ambiguous, or unsafe."""


class GuidanceLifecycle(StrEnum):
    DRAFT = "DRAFT"
    IN_REVIEW = "IN_REVIEW"
    APPROVED = "APPROVED"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"


class GuidanceKind(StrEnum):
    RUNBOOK = "RUNBOOK"
    SKILL = "SKILL"
    CHECKLIST = "CHECKLIST"
    DIAGNOSTIC_PROCEDURE = "DIAGNOSTIC_PROCEDURE"


class GuidanceStepKind(StrEnum):
    OBSERVE = "OBSERVE"
    COMPUTE = "COMPUTE"
    PROPOSE = "PROPOSE"
    CHECKPOINT = "CHECKPOINT"


class BlockedBehavior(StrEnum):
    CONTINUE = "CONTINUE"
    STOP_INCONCLUSIVE = "STOP_INCONCLUSIVE"
    ESCALATE = "ESCALATE"


class GuidanceSourceKind(StrEnum):
    SOLVAN_AUTHORED = "SOLVAN_AUTHORED"
    CUSTOMER_AUTHORED = "CUSTOMER_AUTHORED"
    IMPORTED = "IMPORTED"


KNOWN_GUIDANCE_EVIDENCE_KINDS = frozenset(
    {
        "LOGS",
        "METRICS",
        "TRACES",
        "EVENTS",
        "TOPOLOGY",
        "DEPLOYMENT_METADATA",
        "QUERY_STATS",
        "ARTIFACT",
        "NONE",
        "GUIDANCE_FETCH_RECEIPT",
    }
)


class GuidanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class GuidanceStepRevision(GuidanceModel):
    step_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    ordinal: int = Field(ge=1, le=100)
    title: str = Field(min_length=1, max_length=160)
    objective: str = Field(min_length=1, max_length=1_000)
    step_kind: GuidanceStepKind
    allowed_tool_revisions: tuple[str, ...]
    prerequisite_step_keys: tuple[str, ...]
    completion_predicate_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    completion_predicate_version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    required_evidence_kinds: tuple[str, ...]
    maximum_tool_requests: int = Field(ge=0, le=100)
    on_blocked: BlockedBehavior

    @model_validator(mode="after")
    def validate_step(self) -> Self:
        for ref in self.allowed_tool_revisions:
            if "*" in ref or ref.count("@") != 1:
                raise ValueError("guidance Tools must be exact revision references")
        if len(self.allowed_tool_revisions) != len(set(self.allowed_tool_revisions)):
            raise ValueError("a guidance step cannot repeat a Tool revision")
        if len(self.prerequisite_step_keys) != len(set(self.prerequisite_step_keys)):
            raise ValueError("a guidance step cannot repeat a prerequisite")
        if self.step_key in self.prerequisite_step_keys:
            raise ValueError("a guidance step cannot depend on itself")
        if not self.required_evidence_kinds:
            raise ValueError("a guidance step requires explicit evidence kinds")
        normalized = self.objective.casefold()
        forbidden = (
            "ignore previous",
            "system prompt",
            "password",
            "api key",
            "access token",
            "approve this",
            "approval granted",
            "root cause is",
            "verification passed",
            "service recovered",
        )
        if any(phrase in normalized for phrase in forbidden):
            raise ValueError("guidance objective contains prohibited authority or secret language")
        return self


class GuidanceIncompatibilityDeclaration(GuidanceModel):
    guidance_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,79}$")


class GuidanceRevision(GuidanceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    guidance_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    display_name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=1_000)
    owner_department: str = Field(min_length=1, max_length=160)
    discoverable_departments: tuple[str, ...]
    guidance_kind: GuidanceKind
    applicable_service_kinds: tuple[str, ...]
    applicable_incident_classes: tuple[str, ...]
    symptom_tags: tuple[str, ...]
    purpose: str = Field(min_length=1, max_length=160)
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    eligible_regions: tuple[str, ...]
    allowed_agent_keys: tuple[str, ...]
    required_profile_revisions: tuple[str, ...]
    steps: tuple[GuidanceStepRevision, ...]
    content_ref: str = Field(min_length=1, max_length=2_000)
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_kind: GuidanceSourceKind
    source_ref: str = Field(min_length=1, max_length=2_000)
    source_license: str | None = Field(default=None, max_length=160)
    incompatibilities: tuple[GuidanceIncompatibilityDeclaration, ...] = ()
    evaluation_ref: str | None = None
    approval_ref: str | None = None
    author_principal: str = Field(min_length=3, max_length=255)
    approved_by_principal: str | None = Field(default=None, min_length=3, max_length=255)
    approved_at: datetime | None = None
    supersedes: str | None = None
    lifecycle: GuidanceLifecycle

    @property
    def revision_ref(self) -> str:
        return f"{self.guidance_key}@{self.version}"

    @property
    def revision_digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    @property
    def approval_digest(self) -> str:
        """Digest the exact reviewable material, excluding approval state itself."""

        return canonical_sha256(
            self.model_dump(
                mode="json",
                exclude={
                    "evaluation_ref",
                    "approval_ref",
                    "approved_by_principal",
                    "approved_at",
                    "lifecycle",
                },
            )
        )

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        required_sets = {
            "discoverable departments": self.discoverable_departments,
            "service kinds": self.applicable_service_kinds,
            "incident classes": self.applicable_incident_classes,
            "symptom tags": self.symptom_tags,
            "eligible regions": self.eligible_regions,
            "allowed Agents": self.allowed_agent_keys,
            "required profiles": self.required_profile_revisions,
            "steps": self.steps,
        }
        for label, values in required_sets.items():
            if not values:
                raise ValueError(f"{label} must not be empty")
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must contain unique values")
        for profile in self.required_profile_revisions:
            if "*" in profile or profile.count("@") != 1:
                raise ValueError("guidance profiles must be exact revision references")
        if self.source_kind is GuidanceSourceKind.IMPORTED and not self.source_license:
            raise ValueError("imported guidance requires a source license")
        incompatible_keys = tuple(item.guidance_key for item in self.incompatibilities)
        if len(incompatible_keys) != len(set(incompatible_keys)):
            raise ValueError("guidance incompatibilities must be unique")
        if self.guidance_key in incompatible_keys:
            raise ValueError("guidance cannot be incompatible with itself")
        if self.lifecycle is GuidanceLifecycle.APPROVED:
            if not self.evaluation_ref or not self.approval_ref:
                raise ValueError("approved guidance requires evaluation and approval")
            if not self.approved_by_principal or self.approved_at is None:
                raise ValueError("approved guidance requires independent approval material")
            if self.approved_by_principal == self.author_principal:
                raise ValueError("a guidance author cannot approve their own revision")
        elif (
            self.approval_ref is not None
            or self.evaluation_ref is not None
            or self.approved_by_principal is not None
            or self.approved_at is not None
        ):
            raise ValueError("unapproved guidance cannot carry approval material")
        ordinals = [step.ordinal for step in self.steps]
        keys = {step.step_key for step in self.steps}
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("guidance step ordinals must be unique")
        for step in self.steps:
            if not set(step.prerequisite_step_keys).issubset(keys):
                raise ValueError("guidance prerequisite names an unknown step")
        _require_acyclic(self.steps)
        if self.supersedes == self.revision_ref:
            raise ValueError("guidance cannot supersede itself")
        return self


def _require_acyclic(steps: tuple[GuidanceStepRevision, ...]) -> None:
    graph = {step.step_key: set(step.prerequisite_step_keys) for step in steps}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(key: str) -> None:
        if key in visiting:
            raise ValueError("guidance prerequisites must form an acyclic graph")
        if key in visited:
            return
        visiting.add(key)
        for prerequisite in graph[key]:
            visit(prerequisite)
        visiting.remove(key)
        visited.add(key)

    for key in graph:
        visit(key)


class PredicateRegistry(GuidanceModel):
    predicates: frozenset[str]

    def permits(self, *, key: str, version: str) -> bool:
        return f"{key}@{version}" in self.predicates


def validate_guidance_approval(
    *,
    revision: GuidanceRevision,
    profiles: tuple[ToolProfileRevision, ...],
    tools: tuple[ToolRevision, ...],
    predicates: PredicateRegistry,
) -> None:
    """Validate approval-time Tool/profile/predicate invariants."""

    if revision.lifecycle is not GuidanceLifecycle.APPROVED:
        raise GuidanceError("approval validation requires an APPROVED revision")
    profiles_by_ref = {profile.profile_ref: profile for profile in profiles}
    tools_by_ref = {tool.revision_ref: tool for tool in tools}
    required_profiles = []
    for ref in revision.required_profile_revisions:
        profile = profiles_by_ref.get(ref)
        if profile is None or profile.lifecycle is not CatalogLifecycle.APPROVED:
            raise GuidanceError(f"required Tool profile {ref} is unavailable")
        required_profiles.append(profile)
    for step in revision.steps:
        if not predicates.permits(
            key=step.completion_predicate_key, version=step.completion_predicate_version
        ):
            raise GuidanceError("guidance uses an unknown completion predicate")
        unknown_evidence = set(step.required_evidence_kinds) - KNOWN_GUIDANCE_EVIDENCE_KINDS
        if unknown_evidence:
            raise GuidanceError(
                "guidance uses unknown evidence kinds: " + ", ".join(sorted(unknown_evidence))
            )
        for tool_ref in step.allowed_tool_revisions:
            tool = tools_by_ref.get(tool_ref)
            if tool is None or tool.lifecycle is not CatalogLifecycle.APPROVED:
                raise GuidanceError(f"guidance Tool {tool_ref} is unavailable")
            if tool.permission_class is PermissionClass.MUTATE:
                raise GuidanceError("guidance cannot contain a MUTATE Tool")
            if any(tool_ref not in profile.tool_revisions for profile in required_profiles):
                raise GuidanceError("guidance Tool is outside a required frozen profile")


_CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


class GuidanceSelectionContext(GuidanceModel):
    department: str
    service_kind: str
    incident_class: str
    symptom_tags: frozenset[str]
    purpose: str
    classification_ceiling: str
    region: str
    agent_key: str
    profile_revision: str


class GuidanceCandidate(GuidanceModel):
    guidance_key: str
    version: str
    display_name: str
    description: str
    owner_department: str
    evaluation_ref: str


def eligible_guidance(
    revisions: tuple[GuidanceRevision, ...], *, context: GuidanceSelectionContext
) -> tuple[GuidanceCandidate, ...]:
    """Build the metadata-only shortlist; full content is deliberately absent."""

    if context.classification_ceiling not in _CLASSIFICATION_RANK:
        raise GuidanceError("classification ceiling is unknown")
    matches: list[GuidanceCandidate] = []
    for revision in revisions:
        if revision.lifecycle is not GuidanceLifecycle.APPROVED:
            continue
        if context.department not in revision.discoverable_departments:
            continue
        if context.service_kind not in revision.applicable_service_kinds:
            continue
        if context.incident_class not in revision.applicable_incident_classes:
            continue
        if not context.symptom_tags.intersection(revision.symptom_tags):
            continue
        if context.purpose != revision.purpose or context.region not in revision.eligible_regions:
            continue
        if context.agent_key not in revision.allowed_agent_keys:
            continue
        if context.profile_revision not in revision.required_profile_revisions:
            continue
        if (
            _CLASSIFICATION_RANK[revision.classification]
            > _CLASSIFICATION_RANK[context.classification_ceiling]
        ):
            continue
        if revision.evaluation_ref is None:
            continue
        matches.append(
            GuidanceCandidate(
                guidance_key=revision.guidance_key,
                version=revision.version,
                display_name=revision.display_name,
                description=revision.description,
                owner_department=revision.owner_department,
                evaluation_ref=revision.evaluation_ref,
            )
        )
    matches.sort(key=lambda item: (item.display_name, item.guidance_key, item.version))
    return tuple(matches[:20])


class TriggerKind(StrEnum):
    DEPLOYMENT_ROLLOUT = "DEPLOYMENT_ROLLOUT"
    ALERT_OPENED = "ALERT_OPENED"
    ERROR_SIGNATURE = "ERROR_SIGNATURE"
    SCHEDULE = "SCHEDULE"
    RECURRENCE_DUE = "RECURRENCE_DUE"
    VERIFICATION_DUE = "VERIFICATION_DUE"


class TriggerLifecycle(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    DISABLED = "DISABLED"
    RETIRED = "RETIRED"


class TriggerPolicyRevision(GuidanceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    policy_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    owner_department: str = Field(min_length=1, max_length=160)
    trigger_kind: TriggerKind
    source_connection_id: str = Field(min_length=1)
    source_connection_epoch: int = Field(ge=1)
    source_capability_tool_ref: str = Field(pattern=r"^[^*@]+@[^*@]+$")
    source_capability_agent_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    source_capability_identity_ref: str = Field(min_length=1, max_length=512)
    source_capability_class: str = Field(
        pattern=(
            r"^(LOG_SEARCH|METRIC_READ|PROMQL_READ|AUDIT_LOG_READ|TRACE_READ|"
            r"ERROR_GROUP_READ|ASSET_SEARCH|RESOURCE_ADMIN_READ|RESOURCE_METADATA_READ|"
            r"KUBERNETES_METADATA_READ)$"
        )
    )
    target_selector_ref: str = Field(pattern=r"^selector://[a-z0-9/_.-]+@[a-zA-Z0-9._-]+$")
    incident_class: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    severity: str = Field(pattern=r"^SEV[1-4]$")
    deduplication_dimension: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,79}$")
    action_budget: int = Field(ge=1, le=10)
    repeated_action_limit: int = Field(ge=1, le=3)
    guidance_revision: str | None = Field(default=None, pattern=r"^[^*@]+@[^*@]+$")
    investigation_profile_ref: str = Field(pattern=r"^[^*@]+@[^*@]+$")
    delay_ms: int = Field(ge=0, le=604_800_000)
    cooldown_ms: int = Field(ge=0, le=2_592_000_000)
    maximum_pending_per_target: int = Field(ge=1, le=100)
    supersession: str = Field(pattern=r"^(KEEP_ALL|LATEST_WAITING_PER_TARGET)$")
    region: str = Field(min_length=1)
    classification_ceiling: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    lifecycle: TriggerLifecycle
    author_principal: str = Field(min_length=3, max_length=255)
    approval_ref: str | None = None
    evaluation_ref: str | None = None
    approved_by_principal: str | None = Field(default=None, min_length=3, max_length=255)
    approved_at: datetime | None = None

    @model_validator(mode="after")
    def bounded_actions(self) -> Self:
        if self.repeated_action_limit > self.action_budget:
            raise ValueError("trigger repeated-action limit exceeds its action budget")
        return self

    @model_validator(mode="after")
    def approved_material(self) -> Self:
        governed = self.lifecycle in {
            TriggerLifecycle.APPROVED,
            TriggerLifecycle.DISABLED,
            TriggerLifecycle.RETIRED,
        }
        if governed:
            if not self.approval_ref or not self.evaluation_ref:
                raise ValueError("governed trigger policy requires approval and evaluation")
            if not self.approved_by_principal or self.approved_at is None:
                raise ValueError("governed trigger policy requires independent approval material")
            if self.approved_by_principal == self.author_principal:
                raise ValueError("a trigger policy author cannot approve their own revision")
        elif any(
            value is not None
            for value in (
                self.approval_ref,
                self.evaluation_ref,
                self.approved_by_principal,
                self.approved_at,
            )
        ):
            raise ValueError("a draft trigger policy cannot carry approval material")
        return self

    @property
    def policy_hash(self) -> str:
        """Digest exact reviewable policy material, excluding lifecycle decisions."""

        return canonical_sha256(
            self.model_dump(
                mode="json",
                exclude={
                    "lifecycle",
                    "approval_ref",
                    "evaluation_ref",
                    "approved_by_principal",
                    "approved_at",
                },
            )
        )


class VerifiedTriggerEvent(GuidanceModel):
    source_event_id: str = Field(min_length=8, max_length=255)
    source_sequence: int = Field(ge=1)
    source_event_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    connection_id: str = Field(min_length=1)
    connection_epoch: int = Field(ge=1)
    target_key: str = Field(min_length=1, max_length=512)
    target_snapshot_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    region: str = Field(min_length=1)
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    observed_at: datetime

    @model_validator(mode="after")
    def aware_time(self) -> Self:
        if self.observed_at.tzinfo is None:
            raise ValueError("trigger event time must be timezone-aware")
        return self
