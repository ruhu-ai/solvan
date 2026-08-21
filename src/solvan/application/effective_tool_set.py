"""Closed, shared canonical contract for one run's effective Tool set."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from solvan.application.workspace_hashing import canonical_sha256


class EffectiveToolSetError(ValueError):
    """Effective Tool-set material is incomplete or internally inconsistent."""


class EffectiveToolSetModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ToolConnectionBindingKind(StrEnum):
    COMPUTE_ONLY = "COMPUTE_ONLY"
    POLICY_SOURCE_CONNECTION = "POLICY_SOURCE_CONNECTION"


class ToolRevisionRefV1(EffectiveToolSetModel):
    tool_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


class EffectiveToolBindingV1(EffectiveToolSetModel):
    binding_kind: ToolConnectionBindingKind
    tool: ToolRevisionRefV1
    provider: str | None = None
    capability_key: str | None = None
    external_project_selector: str | None = None
    connection_id: str | None = None
    connection_epoch: int | None = Field(default=None, ge=1)
    capability_receipt_id: str | None = None
    capability_receipt_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    external_project_id: str | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        connection_values = (
            self.provider,
            self.capability_key,
            self.external_project_selector,
            self.connection_id,
            self.connection_epoch,
            self.capability_receipt_id,
            self.capability_receipt_hash,
            self.external_project_id,
        )
        if self.binding_kind is ToolConnectionBindingKind.COMPUTE_ONLY:
            if any(value is not None for value in connection_values):
                raise EffectiveToolSetError(
                    "compute-only effective bindings cannot name a connection"
                )
        elif any(value is None for value in connection_values):
            raise EffectiveToolSetError(
                "policy-source effective bindings require every exact fence"
            )
        return self


class EffectiveToolSetV1(EffectiveToolSetModel):
    """The sole canonical preimage accepted by Runtime and Gateway."""

    schema_version: int = Field(default=1, ge=1, le=1)
    profile_material_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    accepted_tools: tuple[ToolRevisionRefV1, ...]
    agent_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    agent_revision: str = Field(min_length=1)
    scope: dict[str, str]
    connection_bindings: tuple[EffectiveToolBindingV1, ...]
    runtime_region: str = Field(min_length=1)
    accepted_data_classification: str
    classification_ceiling: str
    policy_head_activation_id: str | None = None
    policy_head_epoch: int = Field(ge=0)
    placement_epoch: int = Field(ge=1)
    accepted_step_budget_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @property
    def effective_tool_set_hash(self) -> str:
        return canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_material_hash": self.profile_material_hash,
            "accepted_tools": [item.model_dump(mode="json") for item in self.accepted_tools],
            "agent_key": self.agent_key,
            "agent_revision": self.agent_revision,
            "scope": self.scope,
            "connection_bindings": [
                item.model_dump(mode="json", exclude_none=True) for item in self.connection_bindings
            ],
            "runtime_region": self.runtime_region,
            "accepted_data_classification": self.accepted_data_classification,
            "classification_ceiling": self.classification_ceiling,
            "policy_head_activation_id": self.policy_head_activation_id,
            "policy_head_epoch": self.policy_head_epoch,
            "placement_epoch": self.placement_epoch,
            "accepted_step_budget_hash": self.accepted_step_budget_hash,
        }

    @model_validator(mode="after")
    def validate_exact_order_and_fences(self) -> Self:
        classification_rank = {
            "PUBLIC": 0,
            "INTERNAL": 1,
            "CONFIDENTIAL": 2,
            "RESTRICTED": 3,
        }
        if set(self.scope) != {"organization_id", "project_id", "environment_id"}:
            raise EffectiveToolSetError("effective Tool-set scope must be the exact scope triple")
        if any(not value for value in self.scope.values()):
            raise EffectiveToolSetError("effective Tool-set scope values must not be empty")
        if len(self.accepted_tools) != len(self.connection_bindings):
            raise EffectiveToolSetError("each accepted Tool requires exactly one effective binding")
        if tuple(binding.tool for binding in self.connection_bindings) != self.accepted_tools:
            raise EffectiveToolSetError("effective Tool bindings must preserve accepted Tool order")
        if (self.policy_head_activation_id is None) != (self.policy_head_epoch == 0):
            raise EffectiveToolSetError(
                "policy-head ID and epoch must be absent or present together"
            )
        if (
            self.accepted_data_classification not in classification_rank
            or self.classification_ceiling not in classification_rank
        ):
            raise EffectiveToolSetError("effective Tool-set classification is unknown")
        if (
            classification_rank[self.accepted_data_classification]
            > classification_rank[self.classification_ceiling]
        ):
            raise EffectiveToolSetError(
                "accepted run classification exceeds the effective Tool-set ceiling"
            )
        return self


def validate_effective_tool_set_at_boundary(
    *,
    material: Mapping[str, Any],
    expected_hash: str,
    expected_agent_key: str,
    expected_tool_key: str,
) -> EffectiveToolSetV1:
    """Parse and bind the sole Tool-set preimage at Runtime/Gateway boundaries."""

    try:
        effective = EffectiveToolSetV1.model_validate(material)
    except (ValidationError, EffectiveToolSetError) as error:
        raise EffectiveToolSetError("effective Tool set has an invalid closed shape") from error
    if effective.effective_tool_set_hash != expected_hash:
        raise EffectiveToolSetError("effective Tool set does not match its frozen digest")
    if effective.agent_key != expected_agent_key:
        raise EffectiveToolSetError("effective Tool set does not match the accepted Agent")
    if expected_tool_key not in {tool.tool_key for tool in effective.accepted_tools}:
        raise EffectiveToolSetError("effective Tool set does not authorize the requested Tool")
    return effective


def accepted_step_budget_hash(budget: Any) -> str:
    """Hash one closed coordinator-owned budget without shape confusion.

    Investigation steps and durable Workspace tasks use deliberately different
    budget contracts.  The kind discriminator prevents equal-looking subsets
    from being replayed across those two execution boundaries.
    """

    if hasattr(budget, "max_runtime_seconds"):
        return canonical_sha256(
            {
                "schema_version": 1,
                "budget_kind": "WORKSPACE_TASK",
                "max_runtime_seconds": int(budget.max_runtime_seconds),
                "max_model_calls": int(budget.max_model_calls),
                "max_tool_calls": int(budget.max_tool_calls),
                "max_input_bytes": int(budget.max_input_bytes),
                "max_output_bytes": int(budget.max_output_bytes),
            }
        )

    return canonical_sha256(
        {
            "schema_version": 1,
            "budget_kind": "INVESTIGATION_STEP",
            "deadline_ms": int(budget.deadline_ms),
            "max_tool_calls": int(budget.max_tool_calls),
            "max_output_bytes": int(budget.max_output_bytes),
            "max_model_calls": int(budget.max_model_calls),
            "max_replans": int(budget.max_replans),
        }
    )
