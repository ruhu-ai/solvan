"""Strict, content-bound workspace provider eligibility receipts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Self

from pydantic import Field, model_validator

from solvan.application.workspace_hashing import canonical_sha256
from solvan.application.workspaces import (
    WorkspaceClassification,
    WorkspaceModel,
    WorkspaceProviderKind,
    WorkspaceTaskKind,
)
from solvan.domain import validate_identifier

_SHA256 = r"^sha256:[0-9a-f]{64}$"


class ProviderEligibilityReceipt(WorkspaceModel):
    """Immutable decision persisted before a workspace provider is contacted."""

    schema_version: int = Field(default=1, ge=1, le=1)
    decision_id: str
    policy_kind: str = Field(pattern=r"^PROVIDER_ELIGIBILITY$")
    policy_version: str = Field(min_length=1)
    organization_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    task_kind: WorkspaceTaskKind
    provider: WorkspaceProviderKind
    provider_revision: str = Field(min_length=1)
    implementation_sdk: str = Field(pattern=r"^(google-adk|google-antigravity)$")
    implementation_sdk_version: str = Field(min_length=1)
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256)
    hosting_control_plane: str = Field(pattern=r"^(AGENT_RUNTIME|CLOUD_RUN)$")
    hosting_data_plane: str = Field(pattern=r"^(AGENT_RUNTIME_QUERY_API|PRIVATE_HTTPS)$")
    provider_service_identity: str = Field(min_length=1)
    provider_artifact_digest: str = Field(pattern=_SHA256)
    classification: WorkspaceClassification
    synthetic: bool
    artifact_manifest_ref: str = Field(pattern=r"^gs://")
    artifact_manifest_hash: str = Field(pattern=_SHA256)
    synthetic_attestation_ref: str | None = Field(default=None, pattern=r"^gs://")
    synthetic_attestation_hash: str | None = Field(default=None, pattern=_SHA256)
    terms_revision: str = Field(min_length=1)
    required_processing_location: str = Field(min_length=1)
    provider_location: str = Field(min_length=1)
    effective_tool_set_hash: str = Field(pattern=_SHA256)
    effective_network_policy_hash: str = Field(pattern=_SHA256)
    input_hash: str = Field(pattern=_SHA256)
    decision: str = Field(pattern=r"^(ALLOW|DENY)$")
    reason_codes: tuple[str, ...] = Field(min_length=1)
    decided_by: str = Field(min_length=1)
    decided_at: datetime

    @model_validator(mode="after")
    def validate_decision_binding(self) -> Self:
        validate_identifier(self.decision_id, expected_prefix="pol")
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        if self.decided_at.tzinfo is None or self.decided_at.utcoffset() is None:
            raise ValueError("provider eligibility decision time requires a timezone")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("provider eligibility reason codes must be unique")
        if self.provider is WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN:
            topology_exact = (
                self.implementation_sdk == "google-antigravity"
                and self.implementation_sdk_version == "0.1.10"
                and self.hosting_control_plane == "CLOUD_RUN"
                and self.hosting_data_plane == "PRIVATE_HTTPS"
                and self.required_processing_location == "europe-west1"
            )
            allowed_shape = (
                self.classification is WorkspaceClassification.PUBLIC
                and self.synthetic is True
                and self.provider_location == "europe-west1"
                and self.synthetic_attestation_ref is not None
                and self.synthetic_attestation_hash is not None
            )
            if not topology_exact or (self.decision == "ALLOW" and not allowed_shape):
                raise ValueError("Antigravity eligibility receipt has an unsafe provider shape")
        elif not (
            self.implementation_sdk == "google-adk"
            and self.hosting_control_plane == "AGENT_RUNTIME"
            and self.hosting_data_plane == "AGENT_RUNTIME_QUERY_API"
        ):
            raise ValueError("ADK eligibility receipt has an invalid provider shape")
        if self.input_hash != canonical_sha256(self.eligibility_input()):
            raise ValueError("provider eligibility input hash does not match decision material")
        return self

    def eligibility_input(self) -> dict[str, Any]:
        """Return all caller-independent material the policy adjudicates."""

        return self.model_dump(
            mode="json",
            exclude={
                "schema_version",
                "decision_id",
                "policy_kind",
                "policy_version",
                "input_hash",
                "decision",
                "reason_codes",
                "decided_by",
                "decided_at",
            },
        )

    @classmethod
    def build(cls, **values: Any) -> Self:
        draft = cls.model_construct(input_hash=f"sha256:{'0' * 64}", **values)
        input_hash = canonical_sha256(draft.eligibility_input())
        return cls.model_validate({**values, "input_hash": input_hash})
