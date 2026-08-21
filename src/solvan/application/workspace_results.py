"""Authenticated workspace provider receipts and coordinator result fences."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Self

from pydantic import Field, model_validator

from solvan.application.workspace_cognition import WorkspaceHypothesisProposal
from solvan.application.workspace_hashing import canonical_sha256
from solvan.application.workspaces import (
    RemediationPlan,
    WorkspaceArtifactDescriptor,
    WorkspaceCandidateArtifact,
    WorkspaceContractError,
    WorkspaceModel,
    WorkspaceModelProposal,
    WorkspaceProviderKind,
    WorkspaceTaskBudget,
    WorkspaceTaskInvocation,
    WorkspaceTaskKind,
    WorkspaceTerminalStatus,
    WorkspaceToolReceipt,
)
from solvan.domain import validate_identifier

_SHA256 = r"^sha256:[0-9a-f]{64}$"
_COMMIT = r"^[0-9a-f]{40}$"
_GCS = r"^gs://"
_TRACE = r"^[0-9a-f]{32}$"
_SPAN = r"^[0-9a-f]{16}$"


class WorkspaceProviderAttemptReceipt(WorkspaceModel):
    """Authenticated provider receipt before coordinator-owned artifact persistence."""

    schema_version: int = Field(default=1, ge=1, le=1)
    request_id: str
    request_hash: str = Field(pattern=_SHA256)
    run_id: str
    invocation_id: str
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    provider_revision: str = Field(min_length=1)
    provider_service_revision: str = Field(min_length=1)
    provider_boot_hash: str = Field(pattern=_SHA256)
    implementation_sdk: str = Field(min_length=1)
    implementation_sdk_version: str = Field(min_length=1)
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256)
    provider_artifact_digest: str = Field(pattern=_SHA256)
    input_manifest_hash: str = Field(pattern=_SHA256)
    effective_tool_set_hash: str = Field(pattern=_SHA256)
    effective_network_policy_hash: str = Field(pattern=_SHA256)
    proposal: WorkspaceModelProposal
    candidate_artifacts: tuple[WorkspaceCandidateArtifact, ...]
    tool_receipts: tuple[WorkspaceToolReceipt, ...]
    completed_at: datetime
    trace_id: str = Field(pattern=_TRACE)
    span_id: str = Field(pattern=_SPAN)
    response_hash: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_hash_and_identity(self) -> Self:
        for value, prefix in (
            (self.request_id, "req"),
            (self.run_id, "run"),
            (self.invocation_id, "inv"),
            (self.workspace_id, "wsp"),
        ):
            validate_identifier(value, expected_prefix=prefix)
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("completed_at must include a timezone")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"response_hash"}))
        if self.response_hash != expected:
            raise ValueError("response hash does not match the provider receipt")
        return self

    @classmethod
    def build(cls, **values: Any) -> Self:
        unhashed = cls.model_construct(response_hash=f"sha256:{'0' * 64}", **values)
        response_hash = canonical_sha256(
            unhashed.model_dump(mode="json", exclude={"response_hash"})
        )
        return cls.model_validate({**values, "response_hash": response_hash})

    def assert_matches(self, invocation: WorkspaceTaskInvocation) -> None:
        pairs = (
            (self.request_id, invocation.request_id),
            (self.request_hash, invocation.request_hash),
            (self.run_id, invocation.run_id),
            (self.invocation_id, invocation.invocation_id),
            (self.workspace_id, invocation.workspace_id),
            (self.workspace_generation, invocation.workspace_generation),
            (self.provider_revision, invocation.provider_revision),
            (
                self.implementation_sdk_distribution_hash,
                invocation.implementation_sdk_distribution_hash,
            ),
            (self.provider_artifact_digest, invocation.provider_artifact_digest),
            (self.input_manifest_hash, invocation.input_manifest_hash),
            (self.effective_tool_set_hash, invocation.effective_tool_set_hash),
            (self.effective_network_policy_hash, invocation.effective_network_policy_hash),
            (self.trace_id, invocation.trace_id),
            (self.span_id, invocation.span_id),
        )
        if any(actual != expected for actual, expected in pairs):
            raise WorkspaceContractError("provider attempt does not match its durable request")


class WorkspaceTaskResult(WorkspaceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    request_id: str
    request_hash: str = Field(pattern=_SHA256)
    run_id: str
    invocation_id: str
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    task_kind: WorkspaceTaskKind
    provider: WorkspaceProviderKind
    provider_revision: str = Field(min_length=1)
    provider_service_revision: str = Field(min_length=1)
    provider_boot_hash: str = Field(pattern=_SHA256)
    implementation_sdk: str = Field(min_length=1)
    implementation_sdk_version: str = Field(min_length=1)
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256)
    provider_artifact_digest: str = Field(pattern=_SHA256)
    input_manifest_hash: str = Field(pattern=_SHA256)
    effective_tool_set_hash: str = Field(pattern=_SHA256)
    effective_network_policy_hash: str = Field(pattern=_SHA256)
    budget: WorkspaceTaskBudget
    terminal_status: WorkspaceTerminalStatus
    summary: str = Field(min_length=1, max_length=16_000)
    mechanism: str | None = Field(default=None, max_length=32_000)
    base_commit_sha: str | None = Field(default=None, pattern=_COMMIT)
    unified_diff: str | None = Field(default=None, max_length=2_000_000)
    reproduction_command: str | None = Field(default=None, max_length=4_000)
    test_command: str | None = Field(default=None, max_length=4_000)
    hypotheses: tuple[WorkspaceHypothesisProposal, ...]
    #: Specification 12 §7.2. Carried through from the provider proposal.
    #: Without it the durable result could express only a code patch, so a
    #: runbook, command plan, or action request was authored and then discarded
    #: in translation.
    remediation_plan: RemediationPlan | None = None
    artifacts: tuple[WorkspaceArtifactDescriptor, ...]
    tool_receipts: tuple[WorkspaceToolReceipt, ...]
    citations: tuple[str, ...]
    residual_risks: tuple[str, ...]
    output_ref: str = Field(pattern=_GCS)
    output_hash: str = Field(pattern=_SHA256)
    completed_at: datetime
    trace_id: str = Field(pattern=_TRACE)
    span_id: str = Field(pattern=_SPAN)

    @model_validator(mode="after")
    def validate_bound_result(self) -> Self:
        for value, prefix in (
            (self.request_id, "req"),
            (self.run_id, "run"),
            (self.invocation_id, "inv"),
            (self.workspace_id, "wsp"),
        ):
            validate_identifier(value, expected_prefix=prefix)
        if len(set(self.citations)) != len(self.citations):
            raise ValueError("citations must be unique")
        if len({artifact.path for artifact in self.artifacts}) != len(self.artifacts):
            raise ValueError("artifact paths must be unique")
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("completed_at must include a timezone")
        patch_fields = (
            self.base_commit_sha,
            self.unified_diff,
            self.reproduction_command,
            self.test_command,
        )
        successful_repair = (
            self.task_kind is WorkspaceTaskKind.REPAIR
            and self.terminal_status is WorkspaceTerminalStatus.SUCCEEDED
        )
        if successful_repair:
            if self.mechanism is None or any(value is None for value in patch_fields):
                raise ValueError(
                    "a successful repair result requires mechanism, base, diff, "
                    "reproduction, and test"
                )
            if len(self.hypotheses) < 2 or sum(item.leading for item in self.hypotheses) != 1:
                raise ValueError("successful repair result requires competing hypotheses")
            if not any(item.contradicting_citations for item in self.hypotheses):
                raise ValueError("successful repair result requires contradiction evidence")
        elif any(value is not None for value in patch_fields):
            raise ValueError("patch fields are permitted only on a successful repair task")
        expected_hash = canonical_sha256(self.model_dump(mode="json", exclude={"output_hash"}))
        if self.output_hash != expected_hash:
            raise ValueError("output hash does not match the canonical result")
        return self

    @classmethod
    def build(cls, **values: Any) -> Self:
        """Build a result with a canonical content hash over all trusted fields."""

        unhashed = cls.model_construct(output_hash=f"sha256:{'0' * 64}", **values)
        output_hash = canonical_sha256(unhashed.model_dump(mode="json", exclude={"output_hash"}))
        return cls.model_validate({**values, "output_hash": output_hash})

    def assert_matches(self, invocation: WorkspaceTaskInvocation) -> None:
        """Fence a provider result to the exact durable request."""

        pairs = (
            (self.request_id, invocation.request_id),
            (self.request_hash, invocation.request_hash),
            (self.run_id, invocation.run_id),
            (self.invocation_id, invocation.invocation_id),
            (self.workspace_id, invocation.workspace_id),
            (self.workspace_generation, invocation.workspace_generation),
            (self.task_kind, invocation.task_kind),
            (self.provider, invocation.provider),
            (self.provider_revision, invocation.provider_revision),
            (
                self.implementation_sdk_distribution_hash,
                invocation.implementation_sdk_distribution_hash,
            ),
            (self.provider_artifact_digest, invocation.provider_artifact_digest),
            (self.input_manifest_hash, invocation.input_manifest_hash),
            (self.effective_tool_set_hash, invocation.effective_tool_set_hash),
            (self.effective_network_policy_hash, invocation.effective_network_policy_hash),
            (self.budget, invocation.budget),
            (self.trace_id, invocation.trace_id),
            (self.span_id, invocation.span_id),
        )
        if any(actual != expected for actual, expected in pairs):
            raise WorkspaceContractError("provider result does not match its durable request")
