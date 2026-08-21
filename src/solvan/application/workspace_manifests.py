"""Strict immutable logical-workspace artifact manifests."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Self

from pydantic import Field, model_validator

from solvan.application.workspaces import WorkspaceClassification, WorkspaceModel
from solvan.domain import validate_identifier

_SHA256 = r"^sha256:[0-9a-f]{64}$"
_SAFE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+$")


class WorkspaceManifestEntry(WorkspaceModel):
    path: str = Field(min_length=1, max_length=512)
    object_ref: str = Field(pattern=r"^gs://")
    content_hash: str = Field(pattern=_SHA256)
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)
    provenance_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if _SAFE_PATH.fullmatch(self.path) is None:
            raise ValueError("workspace manifest path is unsafe")
        if len(set(self.provenance_refs)) != len(self.provenance_refs):
            raise ValueError("workspace manifest provenance must be unique")
        return self


class WorkspaceArtifactManifest(WorkspaceModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    manifest_kind: str = Field(pattern=r"^(INPUT|CHECKPOINT)$")
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    checkpoint_sequence: int | None = Field(default=None, ge=1)
    parent_manifest_ref: str | None = Field(default=None, pattern=r"^gs://")
    parent_manifest_hash: str | None = Field(default=None, pattern=_SHA256)
    classification: WorkspaceClassification
    synthetic: bool
    entries: tuple[WorkspaceManifestEntry, ...] = Field(min_length=1)
    created_by: str = Field(min_length=1)
    created_at: datetime

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        validate_identifier(self.workspace_id, expected_prefix="wsp")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("workspace manifest creation time requires a timezone")
        if len({entry.path for entry in self.entries}) != len(self.entries):
            raise ValueError("workspace manifest paths must be unique")
        parents = (self.parent_manifest_ref, self.parent_manifest_hash)
        if self.manifest_kind == "INPUT":
            if self.checkpoint_sequence is not None or any(value is not None for value in parents):
                raise ValueError("input manifest cannot have checkpoint lineage")
        elif self.checkpoint_sequence is None or any(value is None for value in parents):
            raise ValueError("checkpoint manifest requires complete parent lineage")
        return self
