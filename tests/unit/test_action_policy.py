from datetime import UTC, datetime, timedelta

import pytest

from solvan.domain import (
    ActionBudgetSnapshot,
    ActionPolicyError,
    ApprovalDecision,
    ApprovalRecord,
    BudgetDecision,
    ExecutionAuthoritySnapshot,
    RiskClass,
    canonical_target_key,
    evaluate_action_budget,
    normalized_action_signature,
    validate_exact_approval,
)
from tests.unit.test_actions import action

NOW = datetime(2026, 8, 9, 11, 0, tzinfo=UTC)


def budget(**overrides: object) -> ActionBudgetSnapshot:
    values: dict[str, object] = {
        "attempt_count": 0,
        "action_budget": 3,
        "repeated_action_limit": 1,
        "cooldown_until": None,
        "completed_signatures": (),
    }
    values.update(overrides)
    return ActionBudgetSnapshot(**values)  # type: ignore[arg-type]


def test_target_key_and_signature_are_canonical() -> None:
    key = canonical_target_key("Org", "Project", "payments-api", "Deployment")
    first = normalized_action_signature(
        action_type=action().action_type,
        target_key=key,
        payload={"traffic": {"v1": 1.0}, "etag": "abc"},
    )
    second = normalized_action_signature(
        action_type=action().action_type,
        target_key=key,
        payload={"etag": "abc", "traffic": {"v1": 1.0}},
    )

    assert key == "org/project/payments-api/deployment"
    assert first == second


@pytest.mark.parametrize("segments", [(), ("..",), ("contains/slash",), ("space here",)])
def test_target_key_rejects_aliases_and_unsafe_segments(segments: tuple[str, ...]) -> None:
    with pytest.raises(ActionPolicyError, match="target key"):
        canonical_target_key(*segments)


@pytest.mark.parametrize(
    ("snapshot", "risk", "expected"),
    [
        (budget(), RiskClass.CRITICAL, BudgetDecision.DENY_CRITICAL),
        (budget(attempt_count=3), RiskClass.LOW, BudgetDecision.DENY_BUDGET_EXHAUSTED),
        (
            budget(cooldown_until=NOW + timedelta(seconds=1)),
            RiskClass.LOW,
            BudgetDecision.DENY_COOLDOWN,
        ),
        (
            budget(completed_signatures=("candidate",)),
            RiskClass.LOW,
            BudgetDecision.DENY_REPEAT_LIMIT,
        ),
        (
            budget(repeated_action_limit=2, completed_signatures=("candidate", "other")),
            RiskClass.LOW,
            BudgetDecision.DENY_OSCILLATION,
        ),
        (budget(), RiskClass.MEDIUM, BudgetDecision.ALLOW),
    ],
)
def test_action_budget_enforces_every_deterministic_boundary(
    snapshot: ActionBudgetSnapshot, risk: RiskClass, expected: BudgetDecision
) -> None:
    assert (
        evaluate_action_budget(
            snapshot=snapshot,
            candidate_signature="candidate",
            candidate_risk=risk,
            now=NOW,
        )
        is expected
    )


def approval() -> ApprovalRecord:
    material = action()
    return ApprovalRecord(
        action_id=material.action_id,
        action_digest=material.approval_digest(),
        target_key=material.target_key,
        expected_target_version=material.expected_target_version,
        expected_target_epoch=material.expected_target_epoch,
        evidence_version=material.evidence_version,
        policy_version=material.policy_version,
        approver_principal="user:approver@example.com",
        decision=ApprovalDecision.APPROVE,
        decided_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )


def execution(**overrides: object) -> ExecutionAuthoritySnapshot:
    material = action()
    values: dict[str, object] = {
        "now": NOW,
        "workflow_version": material.workflow_version,
        "evidence_version": material.evidence_version,
        "target_version": material.expected_target_version,
        "target_epoch": material.expected_target_epoch + 1,
        "reservation_expected_target_epoch": material.expected_target_epoch,
        "reservation_epoch": material.expected_target_epoch + 1,
        "policy_version": material.policy_version,
        "approver_role_active": True,
        "reservation_action_id": material.action_id,
    }
    values.update(overrides)
    return ExecutionAuthoritySnapshot(**values)  # type: ignore[arg-type]


def test_exact_approval_passes_when_every_live_binding_matches() -> None:
    validate_exact_approval(material=action(), approval=approval(), execution=execution())


@pytest.mark.parametrize(
    ("field", "replacement", "reason"),
    [
        ("workflow_version", 8, "workflow_version_stale"),
        ("evidence_version", 4, "evidence_version_stale"),
        ("target_version", "revision-v3", "target_version_changed"),
        ("target_epoch", 6, "target_epoch_changed"),
        ("reservation_expected_target_epoch", 5, "reservation_expected_epoch_changed"),
        ("reservation_epoch", 6, "reservation_epoch_changed"),
        ("policy_version", "policy-v4", "policy_version_changed"),
        ("approver_role_active", False, "approver_role_revoked"),
        ("reservation_action_id", "act_00000000000000000000000001", "reservation_not_owned"),
    ],
)
def test_execution_recheck_rejects_toctou_changes(
    field: str, replacement: object, reason: str
) -> None:
    with pytest.raises(ActionPolicyError, match=reason):
        validate_exact_approval(
            material=action(), approval=approval(), execution=execution(**{field: replacement})
        )


def test_stale_material_invalidates_digest() -> None:
    with pytest.raises(ActionPolicyError, match="approval_digest_mismatch"):
        validate_exact_approval(
            material=action(evidence_version=4), approval=approval(), execution=execution()
        )
