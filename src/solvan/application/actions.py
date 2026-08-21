"""Final deterministic authorization boundary before a production mutation."""

from __future__ import annotations

from dataclasses import dataclass

from solvan.domain import (
    ActionPolicyError,
    ApprovalRecord,
    AuthorizedActionMaterial,
    ExecutionAuthoritySnapshot,
    PreauthorizationContext,
    RiskClass,
    StandingPreauthorization,
    validate_exact_approval,
    validate_execution_authority,
    validate_standing_preauthorization,
)


@dataclass(frozen=True, slots=True)
class ApprovalAuthority:
    material: AuthorizedActionMaterial
    approval: ApprovalRecord
    execution: ExecutionAuthoritySnapshot
    proposer_principal: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class StandingAuthority:
    material: AuthorizedActionMaterial
    authority: StandingPreauthorization
    context: PreauthorizationContext
    execution: ExecutionAuthoritySnapshot
    idempotency_key: str


type ExecutionAuthorization = ApprovalAuthority | StandingAuthority


def authorize_approved_action(authority: ApprovalAuthority) -> None:
    """Enforce non-bypassable risk, separation, and exact approval checks."""

    if authority.material.risk_class is RiskClass.CRITICAL:
        raise ActionPolicyError("critical_action_infrastructure_denied")
    if authority.proposer_principal == authority.approval.approver_principal:
        raise ActionPolicyError("proposer_approver_separation_failed")
    validate_exact_approval(
        material=authority.material,
        approval=authority.approval,
        execution=authority.execution,
    )


def authorize_standing_action(authority: StandingAuthority) -> None:
    validate_standing_preauthorization(
        material=authority.material,
        authority=authority.authority,
        context=authority.context,
    )
    validate_execution_authority(
        material=authority.material,
        execution=authority.execution,
    )
