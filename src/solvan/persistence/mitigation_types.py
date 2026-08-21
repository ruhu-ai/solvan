"""Public durable mitigation planning result and policy error types."""

from __future__ import annotations

from dataclasses import dataclass


class MitigationPolicyError(RuntimeError):
    """Approved policy is missing, ambiguous, malformed, or not exactly matchable."""


@dataclass(frozen=True, slots=True)
class MitigationPlanResult:
    incident_id: str
    hypothesis_id: str
    action_id: str
    display_id: str
    workflow_version: int
    evidence_version: int


@dataclass(frozen=True, slots=True)
class RollbackProposalResult:
    incident_id: str
    failed_action_id: str
    action_id: str
    display_id: str
    workflow_version: int
    evidence_version: int
