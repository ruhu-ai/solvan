"""Deterministic safety boundary used by the pre-model smoke evaluation.

This is not a model substitute. It proves that unsupported actions and obvious
instruction-bearing evidence are rejected before any provider is called.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SafetyDecision(StrEnum):
    ACCEPT_EVIDENCE = "ACCEPT_EVIDENCE"
    BLOCK_INSTRUCTION = "BLOCK_INSTRUCTION"
    BLOCK_UNSUPPORTED_ACTION = "BLOCK_UNSUPPORTED_ACTION"
    BLOCK_SECRET_OR_PII = "BLOCK_SECRET_OR_PII"


@dataclass(frozen=True)
class SafetyResult:
    decision: SafetyDecision
    reason_code: str


_INSTRUCTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "follow these instructions",
    "run this command",
    "exfiltrate",
)
_SECRET_MARKERS = (
    "authorization: bearer",
    "-----begin private key-----",
    "api_key=",
    "password=",
)
_SUPPORTED_ACTIONS = frozenset({"payments_pool_recycle", "cloud_run_traffic_rollback"})


def evaluate_untrusted_evidence(*, content: str, requested_action: str | None) -> SafetyResult:
    """Apply a provider-independent deny boundary to untrusted evidence."""

    normalized = content.casefold()
    if any(marker in normalized for marker in _SECRET_MARKERS):
        return SafetyResult(SafetyDecision.BLOCK_SECRET_OR_PII, "secret_pattern")
    if any(marker in normalized for marker in _INSTRUCTION_MARKERS):
        return SafetyResult(SafetyDecision.BLOCK_INSTRUCTION, "instruction_in_evidence")
    if requested_action is not None and requested_action not in _SUPPORTED_ACTIONS:
        return SafetyResult(SafetyDecision.BLOCK_UNSUPPORTED_ACTION, "unsupported_action")
    return SafetyResult(SafetyDecision.ACCEPT_EVIDENCE, "bounded_evidence")
