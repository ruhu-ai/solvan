from dataclasses import replace

import pytest

from solvan.application import ApprovalAuthority, authorize_approved_action
from solvan.domain import ActionPolicyError, RiskClass
from tests.unit.test_action_policy import approval, execution
from tests.unit.test_actions import action


def authority() -> ApprovalAuthority:
    return ApprovalAuthority(
        material=action(),
        approval=approval(),
        execution=execution(),
        proposer_principal="user:proposer@example.com",
        idempotency_key="action-idempotency-1",
    )


def test_distinct_current_approver_authorizes_exact_action() -> None:
    authorize_approved_action(authority())


def test_critical_action_is_denied_even_with_approval() -> None:
    value = authority()
    with pytest.raises(ActionPolicyError, match="critical_action"):
        authorize_approved_action(
            replace(value, material=replace(value.material, risk_class=RiskClass.CRITICAL))
        )


def test_proposer_cannot_approve_own_action() -> None:
    value = authority()
    with pytest.raises(ActionPolicyError, match="separation"):
        authorize_approved_action(
            replace(value, proposer_principal=value.approval.approver_principal)
        )
