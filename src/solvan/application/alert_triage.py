"""Closed Cloud Monitoring alert-ingress contracts for specification 21."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.operational_guidance import (
    TriggerKind,
    TriggerLifecycle,
    TriggerPolicyRevision,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope

MAX_PUSH_ENVELOPE_BYTES = 262_144
MAX_PROVIDER_PAYLOAD_BYTES = 196_608
# fmt: off
_ALLOWED_RESOURCE_LABELS = frozenset((
    "project_id", "service_name", "location", "revision_name", "instance_id",
    "database_id", "cluster_name", "namespace_name", "pod_name",
))
# fmt: on


class AlertIngressError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class AlertPolicyError(ValueError):
    pass


class _AlertPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class AlertSelectorField(StrEnum):
    SOURCE_RULE_ID = "SOURCE_RULE_ID"
    SOURCE_STATE = "SOURCE_STATE"
    PROVIDER_SEVERITY = "PROVIDER_SEVERITY"
    RESOURCE_KIND = "RESOURCE_KIND"
    RESOURCE_IDENTIFIER = "RESOURCE_IDENTIFIER"
    NORMALIZED_LABEL = "NORMALIZED_LABEL"


class AlertSelectorClauseV1(_AlertPolicyModel):
    field: AlertSelectorField
    key: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    values: tuple[str, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_label_key(self) -> Self:
        if (self.field is AlertSelectorField.NORMALIZED_LABEL) != (self.key is not None):
            raise ValueError("only a normalized-label selector declares a key")
        if any(not value or len(value) > 256 for value in self.values):
            raise ValueError("selector values must contain 1 to 256 characters")
        if len(set(self.values)) != len(self.values):
            raise ValueError("selector values must be unique")
        return self


class AlertSelectorV1(_AlertPolicyModel):
    schema_version: Literal[1] = 1
    combine: Literal["ALL_OF", "ANY_OF"]
    clauses: tuple[AlertSelectorClauseV1, ...] = Field(min_length=1, max_length=32)
    fingerprint_fields: tuple[str, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def unique_material(self) -> Self:
        identities = {(clause.field, clause.key) for clause in self.clauses}
        if len(identities) != len(self.clauses):
            raise ValueError("a selector field/key may appear only once")
        if len(set(self.fingerprint_fields)) != len(self.fingerprint_fields):
            raise ValueError("fingerprint fields must be unique")
        allowed = {
            "source_rule_id",
            "source_state",
            "provider_severity",
            "resource_kind",
            "resource_identifier",
        } | {f"normalized_labels.{key}" for key in _ALLOWED_RESOURCE_LABELS}
        if not set(self.fingerprint_fields).issubset(allowed):
            raise ValueError("fingerprint field is outside the canonical alert projection")
        return self


class TargetMappingV1(_AlertPolicyModel):
    schema_version: Literal[1] = 1
    kind: Literal["EXACT_NODE", "RESOURCE_IDENTITY"]
    node_key: str | None = Field(default=None, min_length=1, max_length=512)
    node_kind: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{1,63}$")
    resource_label: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")

    @model_validator(mode="after")
    def closed_mapping(self) -> Self:
        exact = self.node_key is not None and self.node_kind is None and self.resource_label is None
        derived = (
            self.node_key is None
            and self.node_kind is not None
            and self.resource_label in _ALLOWED_RESOURCE_LABELS
        )
        if (self.kind == "EXACT_NODE" and not exact) or (
            self.kind == "RESOURCE_IDENTITY" and not derived
        ):
            raise ValueError("target mapping fields do not match its declared kind")
        return self


class SeverityMappingEntryV1(_AlertPolicyModel):
    provider_value: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{1,63}$")
    solvan_severity: Literal["SEV1", "SEV2", "SEV3", "SEV4"]


class SeverityMappingV1(_AlertPolicyModel):
    schema_version: Literal[1] = 1
    entries: tuple[SeverityMappingEntryV1, ...] = Field(min_length=1, max_length=32)
    unknown_behavior: Literal["BLOCKED", "UNMATCHED"]

    @model_validator(mode="after")
    def unique_provider_values(self) -> Self:
        values = [entry.provider_value for entry in self.entries]
        if len(values) != len(set(values)):
            raise ValueError("provider severity values must be unique")
        return self


class InvestigationBudgetV1(_AlertPolicyModel):
    schema_version: Literal[1] = 1
    maximum_starts_per_hour: int = Field(ge=1, le=10_000)
    maximum_starts_per_day: int = Field(ge=1, le=100_000)
    maximum_concurrent_runs: int = Field(ge=1, le=1_000)
    maximum_model_calls: int = Field(ge=0, le=100)
    maximum_tool_calls: int = Field(ge=0, le=1_000)
    maximum_runtime_seconds: int = Field(ge=1, le=86_400)
    maximum_queue_age_ms: int = Field(ge=1_000, le=604_800_000)
    maximum_connection_requests: int = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def daily_budget_not_smaller_than_hourly(self) -> Self:
        if self.maximum_starts_per_day < self.maximum_starts_per_hour:
            raise ValueError("daily starts cannot be lower than hourly starts")
        return self


class PredicateNodeV1(_AlertPolicyModel):
    node_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    kind: Literal[
        "ALL_OF",
        "ANY_OF",
        "NOT",
        "EVIDENCE_FACT",
        "APPLICATION_FACT",
        "SOURCE_FIELD",
        "WITHIN_DURATION",
        "CONSTANT",
    ]
    children: tuple[str, ...] = Field(default=(), max_length=32)
    predicate_ref: str | None = Field(default=None, pattern=r"^[^*@]+@[^*@]+$")
    comparator: Literal["EQ", "NE", "LT", "LTE", "GT", "GTE", "IN"] | None = None
    record_kind: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{1,63}$")
    field_path: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.]{1,127}$")
    expected_value: bool | int | float | str | tuple[str, ...] | None = None
    duration_ms: int | None = Field(default=None, ge=1_000, le=604_800_000)
    constant: bool | None = None

    @model_validator(mode="after")
    def closed_node_shape(self) -> Self:
        branch_counts = {"ALL_OF": (1, 32), "ANY_OF": (1, 32), "NOT": (1, 1)}
        if self.kind in branch_counts:
            low, high = branch_counts[self.kind]
            if not low <= len(self.children) <= high:
                raise ValueError("predicate branch has an invalid child count")
            if any(
                value is not None
                for value in (
                    self.predicate_ref,
                    self.comparator,
                    self.record_kind,
                    self.field_path,
                    self.expected_value,
                    self.duration_ms,
                    self.constant,
                )
            ):
                raise ValueError("predicate branches cannot carry leaf operands")
            return self
        if self.children:
            raise ValueError("predicate leaves cannot carry child references")
        if self.kind == "CONSTANT":
            if self.constant is None or any(
                value is not None
                for value in (
                    self.predicate_ref,
                    self.comparator,
                    self.record_kind,
                    self.field_path,
                    self.expected_value,
                    self.duration_ms,
                )
            ):
                raise ValueError("constant predicate shape is invalid")
            return self
        if self.constant is not None or self.comparator is None or self.field_path is None:
            raise ValueError("predicate leaf is incomplete")
        if self.kind in {"EVIDENCE_FACT", "APPLICATION_FACT"} and (
            self.predicate_ref is None or self.record_kind is None
        ):
            raise ValueError("committed-fact predicates require registry and record bindings")
        if self.kind == "SOURCE_FIELD" and (
            self.predicate_ref is not None or self.record_kind is not None
        ):
            raise ValueError("source-field predicates cannot name an external fact validator")
        if self.kind == "WITHIN_DURATION" and self.duration_ms is None:
            raise ValueError("duration predicates require a bounded duration")
        if self.kind != "WITHIN_DURATION" and self.duration_ms is not None:
            raise ValueError("only duration predicates carry a duration")
        return self


class PredicateExpressionV1(_AlertPolicyModel):
    schema_version: Literal[1] = 1
    root_node_id: str
    nodes: tuple[PredicateNodeV1, ...] = Field(min_length=1, max_length=128)
    on_inconclusive: Literal["HOLD", "MANUAL_REVIEW", "BLOCKED"]

    @model_validator(mode="after")
    def closed_acyclic_graph(self) -> Self:
        by_id = {node.node_id: node for node in self.nodes}
        if len(by_id) != len(self.nodes) or self.root_node_id not in by_id:
            raise ValueError("predicate node IDs must be unique and include the root")
        if any(child not in by_id for node in self.nodes for child in node.children):
            raise ValueError("predicate references an unknown child")
        visited: set[str] = set()
        visiting: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError("predicate expression must be acyclic")
            if node_id in visited:
                return
            visiting.add(node_id)
            for child in by_id[node_id].children:
                visit(child)
            visiting.remove(node_id)
            visited.add(node_id)

        visit(self.root_node_id)
        if visited != set(by_id):
            raise ValueError("predicate expression cannot contain unreachable nodes")
        return self


class AlertPolicyRevisionV1(_AlertPolicyModel):
    schema_version: Literal[1] = 1
    policy_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    owner_department: str = Field(min_length=1, max_length=160)
    source_connection_id: str = Field(min_length=1)
    source_connection_epoch: int = Field(ge=1)
    source_capability_tool_ref: str = Field(pattern=r"^[^*@]+@[^*@]+$")
    source_capability_agent_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    source_capability_identity_ref: str = Field(min_length=1, max_length=512)
    selector: AlertSelectorV1
    target_mapping: TargetMappingV1
    severity_mapping: SeverityMappingV1
    incident_class: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    mode: Literal["TRIAGE", "POLICY_ESCALATED", "FULL_INCIDENT"]
    guidance_revision: str | None = Field(default=None, pattern=r"^[^*@]+@[^*@]+$")
    triage_profile_ref: Literal["alert-triage-read-compute-v1@1"]
    incident_profile_ref: str = Field(pattern=r"^[^*@]+@[^*@]+$")
    escalation_expression: PredicateExpressionV1 | None = None
    full_incident_admission_expression: PredicateExpressionV1 | None = None
    triage_budget: InvestigationBudgetV1
    incident_admission_budget: InvestigationBudgetV1
    cooldown_ms: int = Field(ge=0, le=2_592_000_000)
    maximum_pending_per_target: int = Field(ge=1, le=100)
    supersession: Literal["KEEP_ALL", "LATEST_WAITING_PER_TARGET"]
    episode_horizon_ms: int = Field(ge=1_000, le=7_776_000_000)
    region: str = Field(min_length=1, max_length=64)
    classification_ceiling: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    delivery_policy_ref: str | None = Field(default=None, min_length=1, max_length=512)
    template_ref: str | None = Field(
        default=None,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*@[a-zA-Z0-9][a-zA-Z0-9._-]*$",
    )
    calibration_receipt_refs: tuple[str, ...] = ()
    recommendation_ref: str | None = Field(
        default=None,
        pattern=r"^rec_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
    )

    @model_validator(mode="after")
    def mode_contract(self) -> Self:
        if self.template_ref is not None and not self.calibration_receipt_refs:
            raise ValueError("template-derived policies require calibration receipts")
        if len(set(self.calibration_receipt_refs)) != len(self.calibration_receipt_refs):
            raise ValueError("calibration receipt references must be unique")
        if any(not value.startswith("ref_") for value in self.calibration_receipt_refs):
            raise ValueError("calibration receipt references must be opaque refs")
        if self.mode == "TRIAGE" and (
            self.escalation_expression is not None
            or self.full_incident_admission_expression is not None
        ):
            raise ValueError("TRIAGE policies cannot carry escalation expressions")
        if self.mode == "POLICY_ESCALATED" and (
            self.escalation_expression is None
            or self.full_incident_admission_expression is not None
        ):
            raise ValueError("POLICY_ESCALATED requires only its escalation expression")
        if self.mode == "FULL_INCIDENT" and (
            self.escalation_expression is not None
            or self.full_incident_admission_expression is None
        ):
            raise ValueError("FULL_INCIDENT requires only its admission expression")
        expression = self.escalation_expression or self.full_incident_admission_expression
        if (
            self.mode == "FULL_INCIDENT"
            and expression is not None
            and expression.on_inconclusive == "HOLD"
        ):
            raise ValueError("FULL_INCIDENT cannot hold on an inconclusive predicate")
        return self

    @property
    def alert_material_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    @property
    def bound_selector_ref(self) -> str:
        return f"selector://alert-policy/{self.alert_material_hash.removeprefix('sha256:')}@1"

    def trigger_policy(self, *, principal: str) -> TriggerPolicyRevision:
        highest_severity = min(
            (entry.solvan_severity for entry in self.severity_mapping.entries),
            key=lambda value: int(value[-1]),
        )
        return TriggerPolicyRevision(
            policy_key=self.policy_key,
            version=self.version,
            owner_department=self.owner_department,
            trigger_kind=TriggerKind.ALERT_OPENED,
            source_connection_id=self.source_connection_id,
            source_connection_epoch=self.source_connection_epoch,
            source_capability_tool_ref=self.source_capability_tool_ref,
            source_capability_agent_key=self.source_capability_agent_key,
            source_capability_identity_ref=self.source_capability_identity_ref,
            source_capability_class="METRIC_READ",
            target_selector_ref=self.bound_selector_ref,
            incident_class=self.incident_class,
            severity=highest_severity,
            deduplication_dimension="alert_policy_fingerprint",
            action_budget=1,
            repeated_action_limit=1,
            guidance_revision=self.guidance_revision,
            investigation_profile_ref=self.triage_profile_ref,
            delay_ms=0,
            cooldown_ms=self.cooldown_ms,
            maximum_pending_per_target=self.maximum_pending_per_target,
            supersession=self.supersession,
            region=self.region,
            classification_ceiling=self.classification_ceiling,
            lifecycle=TriggerLifecycle.DRAFT,
            author_principal=principal,
        )


@dataclass(frozen=True, slots=True)
class CloudMonitoringSourceBinding:
    scope: Scope
    source_identity_id: str
    connection_id: str
    connection_epoch: int
    continuity_epoch: int
    cell_id: str
    placement_epoch: int
    scoping_project_id: str
    topic_name: str
    topic_binding_receipt_ref: str
    subscription_name: str
    push_principal: str
    oidc_audience: str
    payload_schema_version: Literal["1.2"]
    source_material_hash: str
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    retention_policy_revision: str
    source_binding_id: str = ""
    binding_epoch: int = 1


@dataclass(frozen=True, slots=True)
class VerifiedPushIdentity:
    issuer: str
    subject: str
    email: str
    audience: str

    @property
    def principal(self) -> str:
        return f"serviceAccount:{self.email.lower()}"


@dataclass(frozen=True, slots=True)
class PubSubEnvelopeIdentity:
    message_id: str
    subscription_name: str
    publish_time: datetime | None
    envelope_hash: str


@dataclass(frozen=True, slots=True)
class CanonicalCloudMonitoringAlert:
    envelope: PubSubEnvelopeIdentity
    provider_incident_key: str
    lifecycle_state: Literal["OPEN", "CLOSED"]
    transition_discriminator: str
    transition_sequence: int
    started_at: datetime
    ended_at: datetime | None
    observed_at: datetime
    scoping_project_id: str
    monitored_resource_project_id: str
    resource_type: str
    resource_labels: Mapping[str, str]
    normalized_labels: Mapping[str, str]
    provider_severity: str
    canonical_event_hash: str
    raw_payload_hash: str


@dataclass(frozen=True, slots=True)
class AlertIngressReceipt:
    delivery_id: str
    receive_attempt_id: str
    semantic_event_id: str | None
    provider_generation_id: str | None
    outcome: Literal["COMMITTED", "REFUSED", "QUARANTINED"]
    reason_code: str
    created: bool


@dataclass(frozen=True, slots=True)
class AlertGenerationProjectionReceipt:
    provider_generation_id: str
    outcome: Literal["MATCHED", "UNMATCHED", "POLICY_CONFLICT"]
    episode_id: str | None
    selected_policy_key: str | None
    created: bool


def inspect_pubsub_envelope(raw_body: bytes) -> tuple[PubSubEnvelopeIdentity, dict[str, Any]]:
    from solvan.application.alert_ingress_parser import inspect_pubsub_envelope as parse

    return parse(raw_body)


def canonicalize_cloud_monitoring_push(raw_body: bytes) -> CanonicalCloudMonitoringAlert:
    from solvan.application.alert_ingress_parser import (
        canonicalize_cloud_monitoring_push as parse,
    )

    return parse(raw_body)
