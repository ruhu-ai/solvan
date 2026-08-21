from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.detection import (
    Comparator,
    DetectionEvaluation,
    DetectionRule,
    sustained_streak,
)

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


def rule(**overrides: object) -> DetectionRule:
    values: dict[str, object] = {
        "rule_id": "payments-http-5xx",
        "version": 1,
        "service_id": "svc_00000000000000000000000000",
        "service_key": "payments-api",
        "graph_snapshot_id": "pgs_00000000000000000000000000",
        "incident_class": "connection_exhaustion",
        "signal_kind": "HTTP_5XX_RATIO",
        "query": {},
        "evaluation_interval_ms": 25_000,
        "comparator": Comparator.GT,
        "threshold": 0.05,
        "sustained_windows": 2,
        "severity": "SEV2",
        "deduplication_dimension": "http-5xx",
        "action_budget": 2,
        "repeated_action_limit": 1,
    }
    values.update(overrides)
    return DetectionRule(**values)  # type: ignore[arg-type]


def evaluation(*, seconds_ago: int, matched: bool) -> DetectionEvaluation:
    end = NOW - timedelta(seconds=seconds_ago)
    return DetectionEvaluation(end - timedelta(minutes=1), end, 0.1, matched)


def test_comparators_are_deterministic() -> None:
    assert rule(comparator=Comparator.GT).matches(0.051)
    assert not rule(comparator=Comparator.GT).matches(0.05)
    assert rule(comparator=Comparator.GTE).matches(0.05)
    assert rule(comparator=Comparator.LT).matches(0.049)
    assert rule(comparator=Comparator.LTE).matches(0.05)


def test_sustained_streak_requires_matching_consecutive_durable_windows() -> None:
    assert sustained_streak(rule(), (evaluation(seconds_ago=0, matched=True),)) is False
    assert sustained_streak(
        rule(),
        (evaluation(seconds_ago=0, matched=True), evaluation(seconds_ago=25, matched=True)),
    )
    assert not sustained_streak(
        rule(),
        (evaluation(seconds_ago=0, matched=True), evaluation(seconds_ago=25, matched=False)),
    )
    assert not sustained_streak(
        rule(),
        (evaluation(seconds_ago=0, matched=True), evaluation(seconds_ago=50, matched=True)),
    )


def test_non_finite_observation_is_rejected() -> None:
    with pytest.raises(ValueError, match="finite"):
        rule().matches(float("nan"))
