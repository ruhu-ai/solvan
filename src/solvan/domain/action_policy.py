"""Deterministic action policy, anti-flapping, and approval revalidation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from solvan.domain.actions import (
    ActionType,
    AuthorizedActionMaterial,
    FrozenJson,
    RiskClass,
)


class ActionPolicyError(ValueError):
    """Raised when an action fails a deterministic authorization check."""


class BudgetDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY_BUDGET_EXHAUSTED = "DENY_BUDGET_EXHAUSTED"
    DENY_COOLDOWN = "DENY_COOLDOWN"
    DENY_CRITICAL = "DENY_CRITICAL"
    DENY_OSCILLATION = "DENY_OSCILLATION"
    DENY_REPEAT_LIMIT = "DENY_REPEAT_LIMIT"


class ApprovalDecision(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REVOKE = "REVOKE"


class PreauthorizationStatus(StrEnum):
    APPROVED = "APPROVED"
    DRAFT = "DRAFT"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass(frozen=True, slots=True)
class ActionBudgetSnapshot:
    attempt_count: int
    action_budget: int
    repeated_action_limit: int
    cooldown_until: datetime | None
    completed_signatures: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.attempt_count < 0:
            raise ActionPolicyError("attempt_count cannot be negative")
        if self.action_budget < 1 or self.repeated_action_limit < 1:
            raise ActionPolicyError("budget and repeat limit must be positive")
        if self.cooldown_until is not None and not _is_aware(self.cooldown_until):
            raise ActionPolicyError("cooldown_until must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    action_id: str
    action_digest: str
    target_key: str
    expected_target_version: str
    expected_target_epoch: int
    evidence_version: int
    policy_version: str
    approver_principal: str
    decision: ApprovalDecision
    decided_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not _is_aware(self.decided_at) or not _is_aware(self.expires_at):
            raise ActionPolicyError("approval times must be timezone-aware")
        if self.expires_at <= self.decided_at:
            raise ActionPolicyError("approval expiry must follow its decision time")


@dataclass(frozen=True, slots=True)
class StandingPreauthorization:
    preauthorization_id: str
    version: int
    status: PreauthorizationStatus
    action_type: ActionType
    service_id: str
    incident_class: str
    maximum_risk_class: RiskClass
    payload_constraints: Mapping[str, FrozenJson]
    maximum_attempts: int
    cooldown_ms: int
    valid_from: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if self.version < 1 or self.maximum_attempts != 1:
            raise ActionPolicyError("standing authority version and one-attempt limit are required")
        if self.cooldown_ms < 600_000:
            raise ActionPolicyError("standing authority cooldown must be at least ten minutes")
        if not _is_aware(self.valid_from) or not _is_aware(self.valid_until):
            raise ActionPolicyError("standing authority validity must be timezone-aware")
        if self.valid_until <= self.valid_from:
            raise ActionPolicyError("standing authority validity window is empty")


@dataclass(frozen=True, slots=True)
class PreauthorizationContext:
    service_id: str
    incident_class: str
    action_attempt_count: int
    cooldown_until: datetime | None
    now: datetime


@dataclass(frozen=True, slots=True)
class ExecutionAuthoritySnapshot:
    now: datetime
    workflow_version: int
    evidence_version: int
    target_version: str
    target_epoch: int
    reservation_expected_target_epoch: int
    reservation_epoch: int
    policy_version: str
    approver_role_active: bool
    reservation_action_id: str

    def __post_init__(self) -> None:
        if not _is_aware(self.now):
            raise ActionPolicyError("execution time must be timezone-aware")


_TARGET_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,126}$")


def canonical_target_key(*segments: str) -> str:
    """Build a stable target key without aliases, path traversal, or case folding."""

    if not segments:
        raise ActionPolicyError("target key requires at least one segment")
    normalized = tuple(segment.strip().lower() for segment in segments)
    if any(not _TARGET_SEGMENT.fullmatch(segment) for segment in normalized):
        raise ActionPolicyError("target key contains an invalid segment")
    return "/".join(normalized)


def normalized_action_signature(
    *, action_type: ActionType, target_key: str, payload: dict[str, object]
) -> str:
    """Hash canonical action intent; volatile run and approval fields are excluded."""

    canonical = json.dumps(
        {"action_type": action_type.value, "payload": payload, "target_key": target_key},
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def evaluate_action_budget(
    *,
    snapshot: ActionBudgetSnapshot,
    candidate_signature: str,
    candidate_risk: RiskClass,
    now: datetime,
) -> BudgetDecision:
    """Apply immutable risk, budget, cooldown, repeat, and A-B-A rules in order."""

    if not _is_aware(now):
        raise ActionPolicyError("evaluation time must be timezone-aware")
    if candidate_risk is RiskClass.CRITICAL:
        return BudgetDecision.DENY_CRITICAL
    if snapshot.attempt_count >= snapshot.action_budget:
        return BudgetDecision.DENY_BUDGET_EXHAUSTED
    if snapshot.cooldown_until is not None and now < snapshot.cooldown_until:
        return BudgetDecision.DENY_COOLDOWN
    if snapshot.completed_signatures.count(candidate_signature) >= snapshot.repeated_action_limit:
        return BudgetDecision.DENY_REPEAT_LIMIT
    if (
        len(snapshot.completed_signatures) >= 2
        and snapshot.completed_signatures[-2] == candidate_signature
        and snapshot.completed_signatures[-1] != candidate_signature
    ):
        return BudgetDecision.DENY_OSCILLATION
    return BudgetDecision.ALLOW


def validate_exact_approval(
    *,
    material: AuthorizedActionMaterial,
    approval: ApprovalRecord,
    execution: ExecutionAuthoritySnapshot,
) -> None:
    """Recheck exact approval and live execution authority immediately pre-mutation."""

    checks = (
        (approval.decision is ApprovalDecision.APPROVE, "approval_not_active"),
        (approval.action_id == material.action_id, "approval_action_mismatch"),
        (approval.action_digest == material.approval_digest(), "approval_digest_mismatch"),
        (approval.target_key == material.target_key, "approval_target_mismatch"),
        (
            approval.expected_target_version == material.expected_target_version,
            "approval_target_version_mismatch",
        ),
        (
            approval.expected_target_epoch == material.expected_target_epoch,
            "approval_target_epoch_mismatch",
        ),
        (approval.evidence_version == material.evidence_version, "approval_evidence_stale"),
        (approval.policy_version == material.policy_version, "approval_policy_stale"),
        (execution.now < approval.expires_at, "approval_expired"),
        (execution.approver_role_active, "approver_role_revoked"),
    )
    for valid, reason in checks:
        if not valid:
            raise ActionPolicyError(reason)
    validate_execution_authority(material=material, execution=execution)


def validate_execution_authority(
    *, material: AuthorizedActionMaterial, execution: ExecutionAuthoritySnapshot
) -> None:
    """Recheck common live authority bindings for every mutation path."""

    checks = (
        (execution.now < material.expires_at, "action_expired"),
        (execution.workflow_version == material.workflow_version, "workflow_version_stale"),
        (execution.evidence_version == material.evidence_version, "evidence_version_stale"),
        (execution.target_version == material.expected_target_version, "target_version_changed"),
        (
            execution.reservation_expected_target_epoch == material.expected_target_epoch,
            "reservation_expected_epoch_changed",
        ),
        (
            execution.reservation_epoch == material.expected_target_epoch + 1,
            "reservation_epoch_changed",
        ),
        (execution.target_epoch == execution.reservation_epoch, "target_epoch_changed"),
        (execution.policy_version == material.policy_version, "policy_version_changed"),
        (execution.reservation_action_id == material.action_id, "reservation_not_owned"),
    )
    for valid, reason in checks:
        if not valid:
            raise ActionPolicyError(reason)


def validate_standing_preauthorization(
    *,
    material: AuthorizedActionMaterial,
    authority: StandingPreauthorization,
    context: PreauthorizationContext,
) -> None:
    """Require an exact, live human-authored grant for the autonomous fixture action."""

    checks = (
        (authority.status is PreauthorizationStatus.APPROVED, "preauthorization_not_approved"),
        (
            authority.action_type is ActionType.PAYMENTS_POOL_RECYCLE
            and material.action_type is authority.action_type,
            "preauthorization_action_mismatch",
        ),
        (material.risk_class is not RiskClass.CRITICAL, "critical_action_infrastructure_denied"),
        (
            _risk_rank(material.risk_class) <= _risk_rank(authority.maximum_risk_class),
            "preauthorization_risk_exceeded",
        ),
        (context.service_id == authority.service_id, "preauthorization_service_mismatch"),
        (
            context.incident_class == authority.incident_class,
            "preauthorization_incident_class_mismatch",
        ),
        (material.payload == authority.payload_constraints, "preauthorization_payload_mismatch"),
        (
            context.action_attempt_count < authority.maximum_attempts,
            "preauthorization_attempts_exhausted",
        ),
        (
            context.cooldown_until is None or context.now >= context.cooldown_until,
            "preauthorization_cooldown_active",
        ),
        (
            authority.valid_from <= context.now < authority.valid_until,
            "preauthorization_outside_validity",
        ),
    )
    for valid, reason in checks:
        if not valid:
            raise ActionPolicyError(reason)


def _risk_rank(value: RiskClass) -> int:
    return {
        RiskClass.LOW: 0,
        RiskClass.MEDIUM: 1,
        RiskClass.HIGH: 2,
        RiskClass.CRITICAL: 3,
    }[value]


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None
