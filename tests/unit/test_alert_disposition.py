from __future__ import annotations

from solvan.application.alert_disposition import select_alert_disposition
from solvan.application.alert_predicates import PredicateEvaluation, PredicateVerdict


def _evaluation(verdict: PredicateVerdict, on_inconclusive: str = "HOLD") -> PredicateEvaluation:
    return PredicateEvaluation(verdict, on_inconclusive, ())


def test_triage_always_holds_without_incident_authority() -> None:
    result = select_alert_disposition(mode="TRIAGE", evaluation=None)
    assert result.disposition == "TRIAGED_HOLD"
    assert result.should_open_incident is False


def test_policy_escalation_requires_true_predicate() -> None:
    passed = select_alert_disposition(
        mode="POLICY_ESCALATED", evaluation=_evaluation(PredicateVerdict.TRUE)
    )
    held = select_alert_disposition(
        mode="POLICY_ESCALATED", evaluation=_evaluation(PredicateVerdict.FALSE)
    )
    assert passed.should_open_incident is True
    assert held.disposition == "TRIAGED_HOLD"


def test_inconclusive_uses_closed_policy_outcome() -> None:
    result = select_alert_disposition(
        mode="POLICY_ESCALATED",
        evaluation=_evaluation(PredicateVerdict.INCONCLUSIVE, "MANUAL_REVIEW"),
    )
    assert result.disposition == "MANUAL_REVIEW"


def test_full_incident_false_is_blocked_not_triage_complete() -> None:
    result = select_alert_disposition(
        mode="FULL_INCIDENT", evaluation=_evaluation(PredicateVerdict.FALSE, "BLOCKED")
    )
    assert result.disposition == "BLOCKED"
    assert result.reason_code == "INCIDENT_ADMISSION_PREDICATE_FALSE"
