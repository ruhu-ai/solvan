"""Application-owned Alert disposition selection from typed predicate results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from solvan.application.alert_predicates import PredicateEvaluation, PredicateVerdict


@dataclass(frozen=True, slots=True)
class AlertDispositionDecision:
    disposition: Literal["TRIAGED_HOLD", "ESCALATED_NEW", "MANUAL_REVIEW", "BLOCKED"]
    reason_code: str
    should_open_incident: bool


def select_alert_disposition(
    *,
    mode: Literal["TRIAGE", "POLICY_ESCALATED", "FULL_INCIDENT"],
    evaluation: PredicateEvaluation | None,
) -> AlertDispositionDecision:
    """Select a closed disposition without accepting model-authored authority."""

    if mode == "TRIAGE":
        if evaluation is not None:
            raise ValueError("TRIAGE cannot carry an escalation evaluation")
        return AlertDispositionDecision("TRIAGED_HOLD", "READ_ONLY_TRIAGE_COMPLETE", False)
    if evaluation is None:
        raise ValueError(f"{mode} requires its approved predicate evaluation")
    if evaluation.verdict is PredicateVerdict.TRUE:
        return AlertDispositionDecision("ESCALATED_NEW", "POLICY_PREDICATE_TRUE", True)
    if evaluation.verdict is PredicateVerdict.FALSE:
        if mode == "FULL_INCIDENT":
            return AlertDispositionDecision("BLOCKED", "INCIDENT_ADMISSION_PREDICATE_FALSE", False)
        return AlertDispositionDecision("TRIAGED_HOLD", "ESCALATION_PREDICATE_FALSE", False)
    if evaluation.on_inconclusive == "MANUAL_REVIEW":
        return AlertDispositionDecision("MANUAL_REVIEW", "PREDICATE_INCONCLUSIVE", False)
    if evaluation.on_inconclusive == "BLOCKED":
        return AlertDispositionDecision("BLOCKED", "PREDICATE_INCONCLUSIVE", False)
    if mode == "FULL_INCIDENT":
        raise ValueError("FULL_INCIDENT cannot hold on an inconclusive predicate")
    return AlertDispositionDecision("TRIAGED_HOLD", "PREDICATE_INCONCLUSIVE_HOLD", False)
