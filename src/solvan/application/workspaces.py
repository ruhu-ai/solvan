"""Provider-neutral logical workspace contracts and integrity helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from solvan.application.effective_tool_set import EffectiveToolSetV1
from solvan.application.workspace_cognition import WorkspaceHypothesisProposal
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import ActionType, Scope, validate_identifier

_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_GCS_PATTERN = r"^gs://"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_TRACE_PATTERN = r"^[0-9a-f]{32}$"
_SPAN_PATTERN = r"^[0-9a-f]{16}$"
_SAFE_ARTIFACT_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+$")


def workspace_artifact_handle(path: str, content_hash: str) -> str:
    """Derive an opaque stable handle without disclosing an object reference."""

    return "wah_" + hashlib.sha256(f"{path}\0{content_hash}".encode()).hexdigest()[:32]


class WorkspaceContractError(ValueError):
    """Raised when a workspace request or result violates a trust boundary."""


class WorkspaceKind(StrEnum):
    SERVICE = "SERVICE"
    INCIDENT = "INCIDENT"


class WorkspaceStatus(StrEnum):
    OPEN = "OPEN"
    HIBERNATED = "HIBERNATED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class WorkspaceTaskKind(StrEnum):
    MAINTAIN_DOSSIER = "MAINTAIN_DOSSIER"
    FORENSICS = "FORENSICS"
    SYNTHESIZE_EVIDENCE = "SYNTHESIZE_EVIDENCE"
    REPRODUCE = "REPRODUCE"
    BISECT = "BISECT"
    REPAIR = "REPAIR"
    PREVALIDATE = "PREVALIDATE"
    REHEARSE = "REHEARSE"
    LEARN = "LEARN"


class WorkspaceProviderKind(StrEnum):
    GEMINI_ADK_AGENT_ENGINE = "GEMINI_ADK_AGENT_ENGINE"
    ANTIGRAVITY_SDK_CLOUD_RUN = "ANTIGRAVITY_SDK_CLOUD_RUN"


class WorkspaceClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class WorkspaceTerminalStatus(StrEnum):
    """Every member here is a state the durable record can actually hold.

    Specification 12 §7.3 also describes a paused workspace awaiting one bounded
    question. It is deliberately absent: `agent_runs.status` has no parked state,
    so a returned pause would be persisted as a failed run and the task would die
    instead of waiting. The member returns with the durable park, not before.
    """

    SUCCEEDED = "SUCCEEDED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class RemediationStepKind(StrEnum):
    """Specification 12 §7.2: the shapes a remedy is allowed to take.

    Returning only a code patch decided in advance that every incident is
    fixable by editing this repository. Coverage is a property of how many kinds
    of answer the contract can express, not of how capable the model is.
    """

    PATCH = "PATCH"
    RUNBOOK = "RUNBOOK"
    COMMAND_PLAN = "COMMAND_PLAN"
    ENUMERATED_ACTION_REQUEST = "ENUMERATED_ACTION_REQUEST"


class WorkspaceModel(BaseModel):
    """Strict immutable base for material crossing the provider boundary."""

    # Enum and dataclass values must remain JSON-decodable at the private HTTP
    # boundary; explicit field constraints and extra=forbid provide the strict
    # shape without making valid JSON require Python object instances.
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkspaceTaskBudget(WorkspaceModel):
    max_runtime_seconds: int = Field(ge=1, le=3_600)
    max_model_calls: int = Field(ge=1, le=32)
    max_tool_calls: int = Field(ge=0, le=256)
    max_input_bytes: int = Field(ge=1, le=20_000_000)
    max_output_bytes: int = Field(ge=1, le=20_000_000)


def workspace_repair_budget(*, synthetic_provider: bool) -> WorkspaceTaskBudget:
    """Return the sole coordinator-owned budget for a repair attempt."""

    if synthetic_provider:
        return WorkspaceTaskBudget(
            max_runtime_seconds=120,
            max_model_calls=8,
            max_tool_calls=7,
            max_input_bytes=1_000_000,
            max_output_bytes=600_000,
        )
    return WorkspaceTaskBudget(
        max_runtime_seconds=600,
        max_model_calls=8,
        max_tool_calls=104,
        max_input_bytes=1_000_000,
        max_output_bytes=600_000,
    )


class WorkspaceArtifactDescriptor(WorkspaceModel):
    artifact_handle: str = Field(pattern=r"^wah_[0-9a-f]{32}$")
    path: str = Field(min_length=1, max_length=512)
    object_ref: str = Field(pattern=_GCS_PATTERN)
    content_hash: str = Field(pattern=_SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)
    provenance_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_path_and_provenance(self) -> Self:
        if _SAFE_ARTIFACT_PATH.fullmatch(self.path) is None:
            raise ValueError("artifact path must be relative and traversal-free")
        if len(set(self.provenance_refs)) != len(self.provenance_refs):
            raise ValueError("artifact provenance refs must be unique")
        return self


class WorkspaceInputMaterial(WorkspaceModel):
    """Coordinator-materialized input; the provider has no storage credentials."""

    path: str = Field(min_length=1, max_length=512)
    content: str
    content_hash: str = Field(pattern=_SHA256_PATTERN)
    media_type: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_material(self) -> Self:
        if _SAFE_ARTIFACT_PATH.fullmatch(self.path) is None:
            raise ValueError("input path must be relative and traversal-free")
        if self.content_hash != sha256_bytes(self.content.encode("utf-8")):
            raise ValueError("input content hash does not match materialized bytes")
        return self


class WorkspaceModelProposal(WorkspaceModel):
    """Only fields an untrusted workspace model is allowed to author."""

    schema_version: int = Field(default=1, ge=1, le=1)
    terminal_status: WorkspaceTerminalStatus
    summary: str = Field(min_length=1, max_length=16_000)
    mechanism: str | None = Field(default=None, max_length=32_000)
    base_commit_sha: str | None = Field(default=None, pattern=_COMMIT_PATTERN)
    unified_diff: str | None = Field(default=None, max_length=2_000_000)
    candidate_generation_id: str | None = None
    candidate_tree_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    reproduction_command: str | None = Field(default=None, max_length=4_000)
    test_command: str | None = Field(default=None, max_length=4_000)
    hypotheses: tuple[WorkspaceHypothesisProposal, ...]
    candidate_artifact_paths: tuple[str, ...] = ()
    citations: tuple[str, ...]
    residual_risks: tuple[str, ...]
    #: Specification 12 §7.2. The single-patch fields above remain for the
    #: repair whose remedy is a code change; a plan expresses the remedies that
    #: are not. A plan never carries authority, so it needs no separate gate.
    remediation_plan: RemediationPlan | None = None

    @model_validator(mode="after")
    def validate_unique_paths_and_citations(self) -> Self:
        if (self.candidate_generation_id is None) != (self.candidate_tree_hash is None):
            raise ValueError("candidate generation identity and tree hash must agree")
        if self.candidate_generation_id is not None:
            validate_identifier(self.candidate_generation_id, expected_prefix="wcg")
        if len(set(self.candidate_artifact_paths)) != len(self.candidate_artifact_paths):
            raise ValueError("candidate artifact paths must be unique")
        if any(
            _SAFE_ARTIFACT_PATH.fullmatch(path) is None for path in self.candidate_artifact_paths
        ):
            raise ValueError("candidate artifact path is unsafe")
        if len(set(self.citations)) != len(self.citations):
            raise ValueError("citations must be unique")
        successful_repair = self.terminal_status is WorkspaceTerminalStatus.SUCCEEDED and (
            self.unified_diff is not None
            or (self.candidate_generation_id is not None and self.candidate_tree_hash is not None)
        )
        if successful_repair:
            if (self.unified_diff is None) == (self.candidate_generation_id is None):
                raise ValueError("successful repair requires exactly one patch material form")
            if (
                self.mechanism is None
                or self.reproduction_command is None
                or len(self.hypotheses) < 2
            ):
                raise ValueError(
                    "successful repair requires a mechanism, reproduction, and competing hypotheses"
                )
            if sum(item.leading for item in self.hypotheses) != 1:
                raise ValueError("successful repair requires exactly one leading hypothesis")
            if not any(item.contradicting_citations for item in self.hypotheses):
                raise ValueError("successful repair requires explicit contradiction evidence")
        return self


#: The closed set an ENUMERATED_ACTION_REQUEST may name. Imported lazily from
#: the domain enum so the workspace contract and the actuator cannot drift: a
#: step proposing an action the actuator has no branch for is a proposal that
#: could never be executed.
_ENUMERATED_ACTION_TYPES: frozenset[str] = frozenset(item.value for item in ActionType)
_PROCEDURE_KINDS = frozenset({RemediationStepKind.RUNBOOK, RemediationStepKind.COMMAND_PLAN})


class RemediationStep(WorkspaceModel):
    """One proposed remedy. It carries no authority of any kind.

    A `PATCH` is not a merge, a `COMMAND_PLAN` is not an execution, and an
    `ENUMERATED_ACTION_REQUEST` is a proposal that still requires the exact
    stored action, human approval, target reservation, and actuator
    revalidation. The kind decides which fields must be present, so a step
    cannot claim to be one thing and carry the material of another.
    """

    schema_version: int = Field(default=1, ge=1, le=1)
    kind: RemediationStepKind
    ordinal: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=8_000)
    citations: tuple[str, ...]
    #: PATCH
    base_commit_sha: str | None = Field(default=None, pattern=_COMMIT_PATTERN)
    unified_diff: str | None = Field(default=None, max_length=2_000_000)
    reproduction_command: str | None = Field(default=None, max_length=4_000)
    test_command: str | None = Field(default=None, max_length=4_000)
    #: RUNBOOK and COMMAND_PLAN
    steps: tuple[str, ...] = ()
    expected_observations: tuple[str, ...] = ()
    #: ENUMERATED_ACTION_REQUEST
    action_type: str | None = Field(default=None, max_length=120)
    action_payload_json: str | None = Field(default=None, max_length=64_000)

    @model_validator(mode="after")
    def validate_kind_matches_material(self) -> Self:
        if not self.citations:
            raise ValueError("a remediation step must cite its evidence")
        if len(set(self.citations)) != len(self.citations):
            raise ValueError("citations must be unique")
        patch_fields = (self.base_commit_sha, self.unified_diff, self.test_command)
        action_fields = (self.action_type, self.action_payload_json)
        if self.kind is RemediationStepKind.PATCH:
            if any(value is None for value in patch_fields) or self.reproduction_command is None:
                raise ValueError(
                    "a patch step requires a base commit, diff, reproduction, and test command"
                )
            if any(value is not None for value in action_fields) or self.steps:
                raise ValueError("a patch step cannot carry action or procedure material")
        elif self.kind is RemediationStepKind.ENUMERATED_ACTION_REQUEST:
            if any(value is None for value in action_fields):
                raise ValueError("an action request requires an action type and payload")
            if any(value is not None for value in patch_fields) or self.steps:
                raise ValueError("an action request cannot carry patch or procedure material")
        else:
            if not self.steps:
                raise ValueError("a runbook or command plan requires ordered steps")
            if any(value is not None for value in patch_fields + action_fields):
                raise ValueError("a procedure step cannot carry patch or action material")
        if self.expected_observations and self.kind not in _PROCEDURE_KINDS:
            raise ValueError("only a runbook or command plan declares expected observations")
        return self

    @model_validator(mode="after")
    def validate_action_material_is_real(self) -> Self:
        """An action request names an action that exists, with a payload that parses.

        Accepting any string meant a step could request `NOT_AN_ACTION_TYPE`
        carrying prose, and nothing would notice until something downstream tried
        to build authorized action material from it. A proposal that cannot
        possibly become an action is a defect at the point it is written, not at
        the point it is consumed — and a reviewer should never be shown one.
        """

        if self.kind is not RemediationStepKind.ENUMERATED_ACTION_REQUEST:
            return self
        if self.action_type not in _ENUMERATED_ACTION_TYPES:
            raise ValueError("action request names no enumerated action type")
        try:
            payload = json.loads(self.action_payload_json or "")
        except json.JSONDecodeError as error:
            raise ValueError("action request payload must be JSON") from error
        if not isinstance(payload, dict):
            raise ValueError("action request payload must be a JSON object")
        return self


class RemediationPlan(WorkspaceModel):
    """Specification 12 §7.2. Widens what a workspace may say, never what it may do."""

    schema_version: int = Field(default=1, ge=1, le=1)
    steps: tuple[RemediationStep, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_ordinals(self) -> Self:
        if tuple(step.ordinal for step in self.steps) != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("remediation steps must be ordered from one without gaps")
        return self


class WorkspaceCandidateArtifact(WorkspaceModel):
    """In-memory candidate returned to the coordinator for trusted persistence."""

    path: str
    content: str
    content_hash: str = Field(pattern=_SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        encoded = self.content.encode("utf-8")
        if _SAFE_ARTIFACT_PATH.fullmatch(self.path) is None:
            raise ValueError("candidate path is unsafe")
        if len(encoded) != self.size_bytes or sha256_bytes(encoded) != self.content_hash:
            raise ValueError("candidate content does not match its descriptor")
        return self


class WorkspaceSpec(WorkspaceModel):
    scope: Scope
    workspace_id: str
    kind: WorkspaceKind
    service_id: str
    reliability_case_id: str | None = None
    provider: WorkspaceProviderKind
    implementation_sdk: str = Field(min_length=1)
    implementation_sdk_version: str = Field(min_length=1)
    provider_revision: str = Field(min_length=1)
    registry_agent_key: str = Field(min_length=1)
    provider_agent_resource: str = Field(min_length=1)
    provider_service_identity: str = Field(min_length=1)
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    effective_network_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    classification: WorkspaceClassification
    synthetic: bool
    synthetic_attestation_ref: str | None = Field(default=None, pattern=_GCS_PATTERN)
    synthetic_attestation_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    provider_eligibility_decision_id: str
    artifact_prefix: str = Field(pattern=_GCS_PATTERN)
    input_manifest_ref: str = Field(pattern=_GCS_PATTERN)
    input_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    created_by_principal: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_provider_and_owner(self) -> Self:
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        validate_identifier(self.service_id, expected_prefix="svc")
        validate_identifier(self.provider_eligibility_decision_id, expected_prefix="pol")
        if self.reliability_case_id is not None:
            validate_identifier(self.reliability_case_id, expected_prefix="rel")
        if (self.kind is WorkspaceKind.INCIDENT) != (self.reliability_case_id is not None):
            raise ValueError("only an INCIDENT workspace has a reliability case")
        if self.provider is WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN:
            if (
                self.classification is not WorkspaceClassification.PUBLIC
                or not self.synthetic
                or self.implementation_sdk != "google-antigravity"
                or self.implementation_sdk_version != "0.1.13"
                or self.synthetic_attestation_ref is None
                or self.synthetic_attestation_hash is None
            ):
                raise ValueError("Antigravity workspaces require public synthetic attested data")
        elif self.implementation_sdk != "google-adk":
            raise ValueError("the Agent Runtime provider requires google-adk")
        return self


class WorkspaceRef(WorkspaceModel):
    scope: Scope
    workspace_id: str
    generation: int = Field(ge=1)
    kind: WorkspaceKind
    provider: WorkspaceProviderKind
    implementation_sdk: str
    implementation_sdk_version: str
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    provider_revision: str
    status: WorkspaceStatus
    classification: WorkspaceClassification
    synthetic: bool
    artifact_prefix: str = Field(pattern=_GCS_PATTERN)
    input_manifest_ref: str = Field(pattern=_GCS_PATTERN)
    input_manifest_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_id(self) -> Self:
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        return self


class WorkspaceCheckpoint(WorkspaceModel):
    scope: Scope
    checkpoint_id: str
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    sequence_no: int = Field(ge=1)
    event_kind: str = Field(pattern=r"^(CHECKPOINT|REHYDRATION)$")
    parent_checkpoint_id: str | None = None
    provider: WorkspaceProviderKind
    implementation_sdk: str
    implementation_sdk_version: str
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    provider_revision: str
    provider_request_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_receipt_ref: str = Field(pattern=_GCS_PATTERN)
    provider_receipt_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_boot_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_service_revision: str = Field(min_length=1)
    input_manifest_ref: str = Field(pattern=_GCS_PATTERN)
    input_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    artifact_manifest_ref: str = Field(pattern=_GCS_PATTERN)
    artifact_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    effective_tool_set_hash: str = Field(pattern=_SHA256_PATTERN)
    effective_network_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    created_by_principal: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_lineage_shape(self) -> Self:
        validate_identifier(self.checkpoint_id, expected_prefix="wck")
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        if self.parent_checkpoint_id is not None:
            validate_identifier(self.parent_checkpoint_id, expected_prefix="wck")
        if (self.event_kind == "REHYDRATION") != (self.parent_checkpoint_id is not None):
            raise ValueError("rehydration requires exactly one parent checkpoint")
        return self


class WorkspaceTaskInvocation(WorkspaceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    request_id: str
    request_hash: str = Field(pattern=_SHA256_PATTERN)
    run_id: str
    invocation_id: str
    logical_step_key: str = Field(min_length=1, max_length=512)
    attempt: int = Field(ge=1)
    scope: Scope
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    task_kind: WorkspaceTaskKind
    provider: WorkspaceProviderKind
    provider_resource: str = Field(min_length=1, max_length=2_000)
    provider_revision: str = Field(min_length=1)
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    workflow_version: int = Field(ge=1)
    deadline: datetime
    budget: WorkspaceTaskBudget
    input_manifest_ref: str = Field(pattern=_GCS_PATTERN)
    input_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    effective_tool_set_hash: str = Field(pattern=_SHA256_PATTERN)
    effective_tool_set: EffectiveToolSetV1 | None = None
    effective_network_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    allowed_tool_names: tuple[str, ...]
    input_artifacts: tuple[WorkspaceArtifactDescriptor, ...] = Field(min_length=1)
    input_materials: tuple[WorkspaceInputMaterial, ...] = Field(min_length=1)
    objective: str = Field(min_length=1, max_length=8_000)
    task_parameters: dict[str, JsonValue]
    trace_id: str = Field(pattern=_TRACE_PATTERN)
    span_id: str = Field(pattern=_SPAN_PATTERN)

    @model_validator(mode="after")
    def validate_identity_and_request_hash(self) -> Self:
        validate_identifier(self.request_id, expected_prefix="req")
        validate_identifier(self.run_id, expected_prefix="run")
        validate_identifier(self.invocation_id, expected_prefix="inv")
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        if len(set(self.allowed_tool_names)) != len(self.allowed_tool_names):
            raise ValueError("allowed tool names must be unique")
        if self.provider is WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE:
            if self.effective_tool_set is None:
                raise ValueError("ADK workspace requests require the effective Tool-set preimage")
            if self.effective_tool_set.effective_tool_set_hash != self.effective_tool_set_hash:
                raise ValueError("workspace effective Tool-set digest does not match its preimage")
        if len({artifact.path for artifact in self.input_artifacts}) != len(self.input_artifacts):
            raise ValueError("input artifact paths must be unique")
        if len({artifact.artifact_handle for artifact in self.input_artifacts}) != len(
            self.input_artifacts
        ):
            raise ValueError("input artifact handles must be unique")
        descriptors = {artifact.path: artifact for artifact in self.input_artifacts}
        if len({material.path for material in self.input_materials}) != len(self.input_materials):
            raise ValueError("materialized input paths must be unique")
        if set(descriptors) != {material.path for material in self.input_materials}:
            raise ValueError("every input descriptor requires exactly one materialized input")
        for material in self.input_materials:
            descriptor = descriptors[material.path]
            if (
                descriptor.content_hash != material.content_hash
                or descriptor.media_type != material.media_type
                or descriptor.size_bytes != len(material.content.encode("utf-8"))
            ):
                raise ValueError("materialized input does not match its signed descriptor")
        total_bytes = sum(
            len(material.content.encode("utf-8")) for material in self.input_materials
        )
        if total_bytes > self.budget.max_input_bytes:
            raise ValueError("materialized inputs exceed the task byte budget")
        if self.task_kind is WorkspaceTaskKind.REPAIR:
            required = {
                "base_commit_sha",
                "reproduction_command",
                "test_command",
                "allowed_file_globs",
            }
            if self.provider is WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE:
                required |= {
                    "reproduction_command_id",
                    "test_command_id",
                    "command_catalog_hash",
                }
            if set(self.task_parameters) != required:
                raise ValueError("repair task parameters must contain only exact repair policy")
            base = self.task_parameters["base_commit_sha"]
            command = self.task_parameters["test_command"]
            reproduction = self.task_parameters["reproduction_command"]
            globs = self.task_parameters["allowed_file_globs"]
            command_ids = (
                self.task_parameters.get("reproduction_command_id"),
                self.task_parameters.get("test_command_id"),
            )
            command_catalog_hash = self.task_parameters.get("command_catalog_hash")
            if not isinstance(base, str) or re.fullmatch(_COMMIT_PATTERN, base) is None:
                raise ValueError("repair base commit is invalid")
            if not isinstance(command, str) or not command or len(command) > 4_000:
                raise ValueError("repair test command is invalid")
            if not isinstance(reproduction, str) or not reproduction or len(reproduction) > 4_000:
                raise ValueError("repair reproduction command is invalid")
            if (
                not isinstance(globs, list)
                or not globs
                or not all(isinstance(item, str) and item for item in globs)
            ):
                raise ValueError("repair allowed file globs are invalid")
            if self.provider is WorkspaceProviderKind.GEMINI_ADK_AGENT_ENGINE and (
                not all(isinstance(item, str) and item.startswith("rcc_") for item in command_ids)
                or command_ids[0] == command_ids[1]
                or not isinstance(command_catalog_hash, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", command_catalog_hash) is None
            ):
                raise ValueError("repair command catalog identifiers are invalid")
        if self.deadline.tzinfo is None or self.deadline.utcoffset() is None:
            raise ValueError("deadline must include a timezone")
        if self.request_hash != self.computed_request_hash():
            raise ValueError("request hash does not match the canonical invocation")
        return self

    def computed_request_hash(self) -> str:
        material = self.model_dump(mode="json", exclude={"request_hash"})
        return canonical_sha256(material)

    @classmethod
    def build(cls, **values: Any) -> Self:
        """Build an invocation with its coordinator-owned canonical request hash."""

        unhashed = cls.model_construct(request_hash=f"sha256:{'0' * 64}", **values)
        request_hash = canonical_sha256(unhashed.model_dump(mode="json", exclude={"request_hash"}))
        return cls.model_validate({**values, "request_hash": request_hash})


class WorkspaceToolReceipt(WorkspaceModel):
    tool_call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    input_hash: str = Field(pattern=_SHA256_PATTERN)
    output_hash: str = Field(pattern=_SHA256_PATTERN)
    status: str = Field(pattern=r"^(SUCCEEDED|DENIED|FAILED)$")


class WorkspaceCheckpointMaterial(WorkspaceModel):
    provider_request_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_receipt_ref: str = Field(pattern=_GCS_PATTERN)
    provider_receipt_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_boot_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_service_revision: str = Field(min_length=1)
    artifact_manifest_ref: str = Field(pattern=_GCS_PATTERN)
    artifact_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    effective_tool_set_hash: str = Field(pattern=_SHA256_PATTERN)
    effective_network_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    created_by_principal: str = Field(min_length=1)
