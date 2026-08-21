"""Strict stateless provider-rehydration request and receipt contracts."""

from __future__ import annotations

from typing import Any, Self

from pydantic import Field, model_validator

from solvan.application.workspace_hashing import canonical_sha256
from solvan.application.workspace_manifests import WorkspaceArtifactManifest
from solvan.application.workspaces import WorkspaceModel
from solvan.domain import validate_identifier

_SHA256 = r"^sha256:[0-9a-f]{64}$"


class WorkspaceRehydrationRequest(WorkspaceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    request_id: str
    request_hash: str = Field(pattern=_SHA256)
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    checkpoint_id: str
    provider_revision: str = Field(min_length=1)
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256)
    provider_artifact_digest: str = Field(pattern=_SHA256)
    previous_provider_service_revision: str = Field(min_length=1)
    previous_provider_boot_hash: str = Field(pattern=_SHA256)
    input_manifest_ref: str = Field(pattern=r"^gs://")
    input_manifest_hash: str = Field(pattern=_SHA256)
    artifact_manifest_ref: str = Field(pattern=r"^gs://")
    artifact_manifest_hash: str = Field(pattern=_SHA256)
    artifact_manifest: WorkspaceArtifactManifest
    effective_tool_set_hash: str = Field(pattern=_SHA256)
    effective_network_policy_hash: str = Field(pattern=_SHA256)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$")

    @model_validator(mode="after")
    def validate_fences(self) -> Self:
        validate_identifier(self.request_id, expected_prefix="req")
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        validate_identifier(self.checkpoint_id, expected_prefix="wck")
        manifest = self.artifact_manifest
        if (
            manifest.manifest_kind != "CHECKPOINT"
            or manifest.workspace_id != self.workspace_id
            or manifest.workspace_generation != self.workspace_generation
            or canonical_sha256(manifest.model_dump(mode="json")) != self.artifact_manifest_hash
        ):
            raise ValueError("rehydration manifest does not match its durable fence")
        if self.request_hash != self.computed_request_hash():
            raise ValueError("rehydration request hash is not canonical")
        return self

    def computed_request_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude={"request_hash"}))

    @classmethod
    def build(cls, **values: Any) -> Self:
        unhashed = cls.model_construct(request_hash=f"sha256:{'0' * 64}", **values)
        request_hash = canonical_sha256(unhashed.model_dump(mode="json", exclude={"request_hash"}))
        return cls.model_validate({**values, "request_hash": request_hash})


class WorkspaceRehydrationReceipt(WorkspaceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    request_id: str
    request_hash: str = Field(pattern=_SHA256)
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    checkpoint_id: str
    provider_revision: str = Field(min_length=1)
    provider_service_revision: str = Field(min_length=1)
    provider_boot_hash: str = Field(pattern=_SHA256)
    implementation_sdk: str = Field(pattern=r"^google-antigravity$")
    implementation_sdk_version: str = Field(pattern=r"^0\.1\.13$")
    implementation_sdk_distribution_hash: str = Field(pattern=_SHA256)
    provider_artifact_digest: str = Field(pattern=_SHA256)
    input_manifest_ref: str = Field(pattern=r"^gs://")
    input_manifest_hash: str = Field(pattern=_SHA256)
    artifact_manifest_ref: str = Field(pattern=r"^gs://")
    artifact_manifest_hash: str = Field(pattern=_SHA256)
    effective_tool_set_hash: str = Field(pattern=_SHA256)
    effective_network_policy_hash: str = Field(pattern=_SHA256)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$")

    def assert_matches(self, request: WorkspaceRehydrationRequest) -> None:
        pairs = (
            (self.request_id, request.request_id),
            (self.request_hash, request.request_hash),
            (self.workspace_id, request.workspace_id),
            (self.workspace_generation, request.workspace_generation),
            (self.checkpoint_id, request.checkpoint_id),
            (self.provider_revision, request.provider_revision),
            (
                self.implementation_sdk_distribution_hash,
                request.implementation_sdk_distribution_hash,
            ),
            (self.provider_artifact_digest, request.provider_artifact_digest),
            (self.input_manifest_ref, request.input_manifest_ref),
            (self.input_manifest_hash, request.input_manifest_hash),
            (self.artifact_manifest_ref, request.artifact_manifest_ref),
            (self.artifact_manifest_hash, request.artifact_manifest_hash),
            (self.effective_tool_set_hash, request.effective_tool_set_hash),
            (self.effective_network_policy_hash, request.effective_network_policy_hash),
            (self.trace_id, request.trace_id),
            (self.span_id, request.span_id),
        )
        if any(actual != expected for actual, expected in pairs):
            raise ValueError("rehydration receipt does not match its request")
        if (
            self.provider_boot_hash == request.previous_provider_boot_hash
            or self.provider_service_revision == request.previous_provider_service_revision
        ):
            raise ValueError("rehydration did not cross a fresh provider revision and boot")
