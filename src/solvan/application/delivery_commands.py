"""Closed, durable command contracts for governed delivery services.

The command ID is the only routing input a receiver accepts from another
service.  Scope, subject, policy material, caller, audience, deadline, and the
canonical payload are all loaded from the Coordinator-created record; callers
cannot smuggle any of them through a private HTTP body.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, validate_identifier

_SHA256 = r"^sha256:[0-9a-f]{64}$"


class DeliveryCommandError(ValueError):
    """A private command is not admissible for a delivery service."""


class DeliveryCommandKind(StrEnum):
    WORKSPACE_TOOL_INVOKE = "WORKSPACE_TOOL_INVOKE"
    EXPLORATORY_SANDBOX_RUN = "EXPLORATORY_SANDBOX_RUN"
    ADJUDICATE_PATCH = "ADJUDICATE_PATCH"
    QUALIFY_CODE_CHANGE = "QUALIFY_CODE_CHANGE"
    CREATE_PR = "CREATE_PR"
    SYNC_PR = "SYNC_PR"
    MERGE_PR = "MERGE_PR"
    PUBLISH_GITHUB_CONVERSATION = "PUBLISH_GITHUB_CONVERSATION"
    START_GITHUB_LINK = "START_GITHUB_LINK"
    CONSUME_GITHUB_CALLBACK = "CONSUME_GITHUB_CALLBACK"
    REVOKE_GITHUB_LINK = "REVOKE_GITHUB_LINK"
    OBSERVE_RELEASE_TARGET = "OBSERVE_RELEASE_TARGET"
    OBSERVE_RELEASE_BASELINE = "OBSERVE_RELEASE_BASELINE"
    START_ROLLOUT = "START_ROLLOUT"
    PREPARE_CANARY = "PREPARE_CANARY"
    PROMOTE_CANARY = "PROMOTE_CANARY"
    FINALIZE_ROLLOUT = "FINALIZE_ROLLOUT"
    REGISTER_VERIFICATION_FAILURE = "REGISTER_VERIFICATION_FAILURE"
    ROLLBACK_RELEASE = "ROLLBACK_RELEASE"
    VERIFY_RELEASE_EFFECT = "VERIFY_RELEASE_EFFECT"
    VERIFY_ROLLBACK_EFFECT = "VERIFY_ROLLBACK_EFFECT"
    FINALIZE_ROLLBACK = "FINALIZE_ROLLBACK"


class DeliveryCommandStatus(StrEnum):
    PREPARED = "PREPARED"
    ISSUED = "ISSUED"
    RECONCILING = "RECONCILING"
    SUCCEEDED = "SUCCEEDED"
    REFUSED = "REFUSED"
    AMBIGUOUS = "AMBIGUOUS"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class DeliveryOutcome(StrEnum):
    ACCEPTED = "ACCEPTED"
    REFUSED = "REFUSED"
    AMBIGUOUS = "AMBIGUOUS"
    RETRYABLE = "RETRYABLE"


class DeliveryReasonCode(StrEnum):
    OPERATION_COMPLETED = "OPERATION_COMPLETED"
    AUTHENTICATION_DENIED = "AUTHENTICATION_DENIED"
    AUDIENCE_DENIED = "AUDIENCE_DENIED"
    SCOPE_DENIED = "SCOPE_DENIED"
    MATERIAL_MISMATCH = "MATERIAL_MISMATCH"
    DEADLINE_EXPIRED = "DEADLINE_EXPIRED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    POLICY_DENIED = "POLICY_DENIED"
    DECISION_STALE = "DECISION_STALE"
    RESERVATION_STALE = "RESERVATION_STALE"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    REQUIRED_CHECK_DEFINITION_TOUCHED = "REQUIRED_CHECK_DEFINITION_TOUCHED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    EXTERNAL_STATE_AMBIGUOUS = "EXTERNAL_STATE_AMBIGUOUS"
    EXTERNAL_STATE_CHANGED = "EXTERNAL_STATE_CHANGED"
    RECEIPT_INVALID = "RECEIPT_INVALID"
    INTERNAL_CONTRACT_VIOLATION = "INTERNAL_CONTRACT_VIOLATION"


# This is intentionally a closed map rather than a generic JSON convention.
# OAuth callback values are received only by the Broker's fixed callback route;
# they are not a private-command payload and therefore never become a durable
# command value or hashable record.
_PAYLOAD_KEYS: dict[DeliveryCommandKind, frozenset[str]] = {
    DeliveryCommandKind.WORKSPACE_TOOL_INVOKE: frozenset(
        {"tool_revision", "call_ordinal", "tool_input"}
    ),
    DeliveryCommandKind.EXPLORATORY_SANDBOX_RUN: frozenset(
        {"test_command_id", "candidate_tree_hash"}
    ),
    DeliveryCommandKind.ADJUDICATE_PATCH: frozenset(
        {"patch_transform_hash", "base_tree_hash", "command_definition_ids_hash"}
    ),
    DeliveryCommandKind.QUALIFY_CODE_CHANGE: frozenset(),
    DeliveryCommandKind.CREATE_PR: frozenset(),
    DeliveryCommandKind.SYNC_PR: frozenset(),
    DeliveryCommandKind.MERGE_PR: frozenset({"github_observation_hash"}),
    # The digest an operator actually decided against. It binds the rendered
    # body, the target thread, and the review event together, so a dispatch
    # cannot carry an approval that was given for different words.
    DeliveryCommandKind.PUBLISH_GITHUB_CONVERSATION: frozenset(
        {"conversation_decision_digest", "template_registry_digest"}
    ),
    DeliveryCommandKind.START_GITHUB_LINK: frozenset({"repository_binding_locator"}),
    DeliveryCommandKind.CONSUME_GITHUB_CALLBACK: frozenset(),
    DeliveryCommandKind.REVOKE_GITHUB_LINK: frozenset({"github_reviewer_binding_id"}),
    DeliveryCommandKind.OBSERVE_RELEASE_TARGET: frozenset(),
    DeliveryCommandKind.OBSERVE_RELEASE_BASELINE: frozenset(
        {"verification_profile_hash", "target_observation_hash"}
    ),
    DeliveryCommandKind.START_ROLLOUT: frozenset(),
    DeliveryCommandKind.PREPARE_CANARY: frozenset(),
    DeliveryCommandKind.PROMOTE_CANARY: frozenset({"prior_canary_receipt_hash"}),
    DeliveryCommandKind.FINALIZE_ROLLOUT: frozenset({"final_verification_receipt_hash"}),
    DeliveryCommandKind.REGISTER_VERIFICATION_FAILURE: frozenset(
        {"failed_verification_receipt_hash"}
    ),
    DeliveryCommandKind.ROLLBACK_RELEASE: frozenset(),
    DeliveryCommandKind.VERIFY_RELEASE_EFFECT: frozenset(
        {
            "verification_profile_hash",
            "predeploy_snapshot_hash",
            "intended_effect_hash",
            "observation_window_generation",
        }
    ),
    DeliveryCommandKind.VERIFY_ROLLBACK_EFFECT: frozenset(),
    DeliveryCommandKind.FINALIZE_ROLLBACK: frozenset({"rollback_verification_receipt_hash"}),
}

_WORKSPACE_TOOL_INPUT_KEYS: dict[str, frozenset[str]] = {
    "workspace.code-repair.read-artifact@1": frozenset(
        {"schema_version", "artifact_handle", "offset_bytes", "limit_bytes"}
    ),
    "workspace.code-repair.write-candidate-artifact@1": frozenset(
        {"schema_version", "operation", "relative_path", "expected_prior_hash", "content_utf8"}
    ),
    "workspace.code-repair.run-in-sandbox@1": frozenset(
        {"schema_version", "test_command_id", "candidate_tree_hash"}
    ),
}


def payload_schema_hash(command_kind: DeliveryCommandKind) -> str:
    """Return the immutable schema identity accepted for one command kind.

    This is deliberately derived from the closed field registry rather than
    supplied by a Coordinator caller.  A valid-looking digest for a different
    payload schema is not sufficient to make a private command admissible.
    """

    material: dict[str, object] = {
        "schema_version": 1,
        "command_kind": command_kind.value,
        "payload_keys": sorted(_PAYLOAD_KEYS[command_kind]),
    }
    if command_kind is DeliveryCommandKind.WORKSPACE_TOOL_INVOKE:
        material["workspace_tool_inputs"] = {
            revision: sorted(keys) for revision, keys in sorted(_WORKSPACE_TOOL_INPUT_KEYS.items())
        }
    return canonical_sha256(material)


class _DeliveryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PrivateCommandEnvelope(_DeliveryModel):
    """The only private HTTP request shape admitted by delivery services."""

    schema_version: int = Field(default=1, ge=1, le=1)
    command_id: str
    payload: dict[str, Any]

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        validate_identifier(self.command_id, expected_prefix="cmd")
        return self


class PrivateCommandRecord(_DeliveryModel):
    """Immutable Coordinator-created command material loaded by a receiver."""

    command_id: str
    scope: Scope
    command_kind: DeliveryCommandKind
    subject_id: str = Field(min_length=1, max_length=255)
    material_hash: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(min_length=8, max_length=255)
    payload_ref: str = Field(pattern=r"^gs://")
    payload: dict[str, Any]
    payload_hash: str = Field(pattern=_SHA256)
    payload_schema_hash: str = Field(pattern=_SHA256)
    admitted_caller_identity: str = Field(min_length=3, max_length=255)
    admitted_audience_hash: str = Field(pattern=_SHA256)
    deadline: datetime
    status: DeliveryCommandStatus

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        validate_identifier(self.command_id, expected_prefix="cmd")
        if self.deadline.tzinfo is None or self.deadline.utcoffset() is None:
            raise DeliveryCommandError("delivery command deadline must include a timezone")
        expected_keys = _PAYLOAD_KEYS[self.command_kind]
        if frozenset(self.payload) != expected_keys:
            raise DeliveryCommandError("delivery command payload shape does not match its kind")
        if self.command_kind is DeliveryCommandKind.WORKSPACE_TOOL_INVOKE:
            self._validate_workspace_tool_payload()
        if self.command_kind is DeliveryCommandKind.MERGE_PR and not (
            isinstance(self.payload["github_observation_hash"], str)
            and re.fullmatch(_SHA256, self.payload["github_observation_hash"])
        ):
            raise DeliveryCommandError("merge command observation binding is invalid")
        if self.command_kind is DeliveryCommandKind.PUBLISH_GITHUB_CONVERSATION and not all(
            isinstance(self.payload[key], str) and re.fullmatch(_SHA256, self.payload[key])
            for key in ("conversation_decision_digest", "template_registry_digest")
        ):
            raise DeliveryCommandError("conversation command decision binding is invalid")
        if self.payload_schema_hash != payload_schema_hash(self.command_kind):
            raise DeliveryCommandError(
                "delivery command payload schema is not the accepted version"
            )
        if canonical_sha256(self.payload) != self.payload_hash:
            raise DeliveryCommandError("delivery command payload hash does not match its body")
        return self

    def _validate_workspace_tool_payload(self) -> None:
        revision = self.payload["tool_revision"]
        ordinal = self.payload["call_ordinal"]
        tool_input = self.payload["tool_input"]
        if (
            not isinstance(revision, str)
            or revision not in _WORKSPACE_TOOL_INPUT_KEYS
            or not isinstance(ordinal, int)
            or not 1 <= ordinal <= 104
            or not isinstance(tool_input, dict)
            or frozenset(tool_input) != _WORKSPACE_TOOL_INPUT_KEYS[revision]
            or tool_input.get("schema_version") != 1
        ):
            raise DeliveryCommandError("workspace tool payload is not one closed tool invocation")
        if revision == "workspace.code-repair.read-artifact@1":
            if not (
                isinstance(tool_input["artifact_handle"], str)
                and isinstance(tool_input["offset_bytes"], int)
                and isinstance(tool_input["limit_bytes"], int)
            ):
                raise DeliveryCommandError("workspace artifact-read input is invalid")
        elif revision == "workspace.code-repair.write-candidate-artifact@1":
            if not (
                isinstance(tool_input["operation"], str)
                and tool_input["operation"] in {"CREATE", "REPLACE", "DELETE"}
                and isinstance(tool_input["relative_path"], str)
                and (
                    tool_input["expected_prior_hash"] is None
                    or isinstance(tool_input["expected_prior_hash"], str)
                )
                and (
                    tool_input["content_utf8"] is None
                    or isinstance(tool_input["content_utf8"], str)
                )
            ):
                raise DeliveryCommandError("workspace candidate-write input is invalid")
        else:
            if not (
                isinstance(tool_input["test_command_id"], str)
                and isinstance(tool_input["candidate_tree_hash"], str)
            ):
                raise DeliveryCommandError("workspace sandbox input is invalid")

    def validate_envelope(
        self,
        envelope: PrivateCommandEnvelope,
        *,
        caller_identity: str,
        audience_hash: str,
        now: datetime,
    ) -> None:
        """Fail before any provider call if transport differs from durable authority."""

        if now.tzinfo is None or now.utcoffset() is None:
            raise DeliveryCommandError("delivery command validation time must include a timezone")
        if envelope.command_id != self.command_id:
            raise DeliveryCommandError("delivery command identifier does not match durable record")
        if caller_identity != self.admitted_caller_identity:
            raise DeliveryCommandError("delivery command caller is not admitted")
        if audience_hash != self.admitted_audience_hash:
            raise DeliveryCommandError("delivery command audience is not admitted")
        if now.astimezone(UTC) >= self.deadline.astimezone(UTC):
            raise DeliveryCommandError("delivery command deadline has expired")
        if envelope.payload != self.payload:
            raise DeliveryCommandError("delivery command payload differs from durable material")


class PrivateCommandResponse(_DeliveryModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    command_id: str
    outcome: DeliveryOutcome
    reason_code: DeliveryReasonCode
    receipt_ref: str | None = Field(default=None, pattern=r"^gs://")
    receipt_hash: str | None = Field(default=None, pattern=_SHA256)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        validate_identifier(self.command_id, expected_prefix="cmd")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise DeliveryCommandError("delivery command response must include a timezone")
        if (self.receipt_ref is None) != (self.receipt_hash is None):
            raise DeliveryCommandError("delivery command receipt reference and hash must agree")
        if self.outcome is DeliveryOutcome.RETRYABLE and self.reason_code not in {
            DeliveryReasonCode.PROVIDER_UNAVAILABLE,
            DeliveryReasonCode.PROVIDER_RATE_LIMITED,
        }:
            raise DeliveryCommandError("only pre-issue provider availability can be retryable")
        if (
            self.outcome is DeliveryOutcome.ACCEPTED
            and self.reason_code is not DeliveryReasonCode.OPERATION_COMPLETED
        ):
            raise DeliveryCommandError("accepted delivery requires the completed reason code")
        return self
