"""Governed, immutable policy bundle used to create Code Change Requests."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_candidate import valid_repository_selector
from solvan.application.workspace_hashing import canonical_sha256

_RESERVED = (".git/", ".github/", "infra/", "deploy/", "iam/", "policy/")


class DeliveryProfileError(ValueError):
    pass


class CodeDeliveryProfileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repository_binding_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    allowed_paths: tuple[str, ...] = Field(min_length=1, max_length=64)
    required_checks: tuple[str, ...] = Field(min_length=1, max_length=32)
    required_check_definition_paths: tuple[str, ...] = Field(min_length=1, max_length=32)
    minimum_approvals: int = Field(ge=1, le=10)
    require_code_owner_review: bool
    merge_method: str = Field(pattern=r"^(merge|squash|rebase)$")
    deployment_target_profile: str = Field(min_length=8, max_length=255)
    maximum_request_lifetime_minutes: int = Field(ge=10, le=1440)

    @model_validator(mode="after")
    def validate_closed_policy(self) -> Self:
        collections = (
            self.allowed_paths,
            self.required_checks,
            self.required_check_definition_paths,
        )
        if any(len(values) != len(set(values)) for values in collections):
            raise DeliveryProfileError("delivery profile lists must be unique")
        if not all(valid_repository_selector(value) for value in self.allowed_paths):
            raise DeliveryProfileError("allowed path selector is unsafe")
        if any(
            value == prefix.rstrip("/") or value.startswith(prefix)
            for value in self.allowed_paths
            for prefix in _RESERVED
        ):
            raise DeliveryProfileError("repair paths cannot include control-plane definitions")
        if not all(
            valid_repository_selector(value) and not any(char in value for char in "*?[]")
            for value in self.required_check_definition_paths
        ):
            raise DeliveryProfileError("required-check definition paths must be literal safe paths")
        if not all(
            value.strip() == value and 1 <= len(value) <= 128 and "\x00" not in value
            for value in self.required_checks
        ):
            raise DeliveryProfileError("required check names are malformed")
        return self

    @property
    def documents(self) -> dict[str, dict[str, object]]:
        return {
            "required-checks": {
                "schema_version": 1,
                "required_checks": sorted(self.required_checks),
                "definition_paths": sorted(self.required_check_definition_paths),
            },
            "reviewer": {
                "schema_version": 1,
                "minimum_approvals": self.minimum_approvals,
                "require_code_owner_review": self.require_code_owner_review,
            },
            "pr-creation": {"schema_version": 1, "draft_required": True},
            "merge": {"schema_version": 1, "merge_method": self.merge_method},
            "deployment": {
                "schema_version": 1,
                "target_profile": self.deployment_target_profile,
            },
        }

    @property
    def profile_hash(self) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "repository_binding_id": self.repository_binding_id,
                "allowed_paths": sorted(self.allowed_paths),
                "maximum_request_lifetime_minutes": self.maximum_request_lifetime_minutes,
                "documents": self.documents,
            }
        )
