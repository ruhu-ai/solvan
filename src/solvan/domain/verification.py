"""Policy-owned profile resolution and deterministic recovery verdicts."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class VerificationError(ValueError):
    """Raised when a verification contract or binding is invalid."""


class Comparator(StrEnum):
    GT = "GT"
    GTE = "GTE"
    LT = "LT"
    LTE = "LTE"


class VerificationVerdict(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class VerificationBinding:
    graph_snapshot_id: str
    service_id: str
    incident_class: str
    profile_id: str
    profile_version: int
    effective_at: datetime
    superseded_at: datetime | None
    profile_approved: bool


@dataclass(frozen=True, slots=True)
class SignalRequirement:
    signal_key: str
    comparator: Comparator
    threshold: float
    sustained_samples: int

    def __post_init__(self) -> None:
        if not self.signal_key or self.sustained_samples < 1:
            raise VerificationError("signal key and sustained sample count are required")


@dataclass(frozen=True, slots=True)
class SignalSample:
    signal_key: str
    observed_at: datetime
    value: float


@dataclass(frozen=True, slots=True)
class SyntheticReceipt:
    observed_at: datetime
    succeeded: bool
    isolated_fixture: bool
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verdict: VerificationVerdict
    rationale_codes: tuple[str, ...]


def resolve_verification_binding(
    *,
    bindings: tuple[VerificationBinding, ...],
    graph_snapshot_id: str,
    service_id: str,
    incident_class: str,
    at: datetime,
    caller_profile: tuple[str, int] | None = None,
) -> VerificationBinding:
    """Resolve one live approved graph binding; callers cannot substitute a profile."""

    matches = tuple(
        binding
        for binding in bindings
        if binding.graph_snapshot_id == graph_snapshot_id
        and binding.service_id == service_id
        and binding.incident_class == incident_class
        and binding.profile_approved
        and binding.effective_at <= at
        and (binding.superseded_at is None or at < binding.superseded_at)
    )
    if len(matches) != 1:
        raise VerificationError(f"expected one approved verification binding; found {len(matches)}")
    resolved = matches[0]
    if caller_profile is not None and caller_profile != (
        resolved.profile_id,
        resolved.profile_version,
    ):
        raise VerificationError("caller profile substitution rejected")
    return resolved


def evaluate_verification(
    *,
    requirements: tuple[SignalRequirement, ...],
    samples: tuple[SignalSample, ...],
    window_start: datetime,
    window_end: datetime,
    synthetic_receipt: SyntheticReceipt | None,
) -> VerificationResult:
    """Calculate a fail-closed verdict without model or connector authority."""

    if window_end <= window_start:
        raise VerificationError("verification window must have positive duration")
    if not requirements:
        raise VerificationError("verification requires at least one signal")

    inconclusive: list[str] = []
    failures: list[str] = []
    by_key: dict[str, list[SignalSample]] = defaultdict(list)
    for sample in samples:
        by_key[sample.signal_key].append(sample)

    for requirement in requirements:
        signal_samples = sorted(by_key[requirement.signal_key], key=lambda item: item.observed_at)
        in_window = [
            sample for sample in signal_samples if window_start <= sample.observed_at <= window_end
        ]
        if not signal_samples:
            inconclusive.append(f"MISSING:{requirement.signal_key}")
            continue
        if not in_window:
            inconclusive.append(f"STALE:{requirement.signal_key}")
            continue
        values_by_time: dict[datetime, set[float]] = defaultdict(set)
        for sample in in_window:
            values_by_time[sample.observed_at].add(sample.value)
        if any(len(values) > 1 for values in values_by_time.values()):
            inconclusive.append(f"CONTRADICTORY:{requirement.signal_key}")
            continue
        if len(in_window) < requirement.sustained_samples:
            inconclusive.append(f"INSUFFICIENT:{requirement.signal_key}")
            continue
        sustained = in_window[-requirement.sustained_samples :]
        if not all(
            _compare(sample.value, requirement.comparator, requirement.threshold)
            for sample in sustained
        ):
            failures.append(f"THRESHOLD_FAILED:{requirement.signal_key}")

    if synthetic_receipt is None:
        inconclusive.append("SYNTHETIC_MISSING")
    elif not (window_start <= synthetic_receipt.observed_at <= window_end):
        inconclusive.append("SYNTHETIC_STALE")
    elif not synthetic_receipt.isolated_fixture or not synthetic_receipt.idempotency_key:
        inconclusive.append("SYNTHETIC_INVALID")
    elif not synthetic_receipt.succeeded:
        failures.append("SYNTHETIC_FAILED")

    if inconclusive:
        return VerificationResult(VerificationVerdict.INCONCLUSIVE, tuple(inconclusive + failures))
    if failures:
        return VerificationResult(VerificationVerdict.FAILED, tuple(failures))
    return VerificationResult(VerificationVerdict.VERIFIED, ("ALL_REQUIRED_SIGNALS_PASSED",))


def _compare(value: float, comparator: Comparator, threshold: float) -> bool:
    if comparator is Comparator.GT:
        return value > threshold
    if comparator is Comparator.GTE:
        return value >= threshold
    if comparator is Comparator.LT:
        return value < threshold
    return value <= threshold
