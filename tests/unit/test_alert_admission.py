from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.alert_admission import (
    AlertAdmissionInput,
    CapacityDecision,
    evaluate_alert_admission,
)

NOW = datetime(2026, 8, 13, 12, tzinfo=UTC)


def _request(**overrides: object) -> AlertAdmissionInput:
    material: dict[str, object] = {
        "source_state": "OPEN",
        "observed_at": NOW - timedelta(seconds=5),
        "evaluated_at": NOW,
        "maximum_queue_age_ms": 60_000,
        "pending_for_target": 0,
        "maximum_pending_per_target": 3,
        "capacity_decision": "RESERVED",
        "capacity_receipt_ref": "capacity://reservation/cap_42",
    }
    material.update(overrides)
    return AlertAdmissionInput.model_validate(material)


@pytest.mark.parametrize(
    ("overrides", "decision", "reason"),
    [
        ({"source_state": "CLOSED"}, "SUPPRESSED", "SOURCE_ALREADY_CLOSED"),
        ({"fence_failure_reason": "GRAPH_TARGET_STALE"}, "BLOCKED", "GRAPH_TARGET_STALE"),
        ({"observed_at": NOW + timedelta(seconds=1)}, "BLOCKED", "SOURCE_TIME_INVALID"),
        ({"observed_at": NOW - timedelta(minutes=2)}, "BLOCKED", "TRIAGE_QUEUE_EXPIRED"),
        ({"cooldown_until": NOW + timedelta(minutes=1)}, "SUPPRESSED", "COOLDOWN_ACTIVE"),
        ({"pending_for_target": 3}, "SUPPRESSED", "PENDING_LIMIT_REACHED"),
        (
            {
                "capacity_decision": "WAITING",
                "capacity_receipt_ref": None,
                "capacity_retry_at": NOW + timedelta(seconds=30),
            },
            "PENDING",
            "CENTRAL_CAPACITY_WAIT",
        ),
        (
            {"capacity_decision": "EXHAUSTED", "capacity_receipt_ref": None},
            "BLOCKED",
            "TRIAGE_CAPACITY_EXHAUSTED",
        ),
    ],
)
def test_admission_precedence_is_closed(
    overrides: dict[str, object], decision: str, reason: str
) -> None:
    result = evaluate_alert_admission(_request(**overrides))
    assert result.decision == decision
    assert result.reason_code == reason


def test_admission_preserves_exact_central_reservation() -> None:
    result = evaluate_alert_admission(_request())
    assert result.decision == "ADMITTED"
    assert result.budget_receipt_ref == "capacity://reservation/cap_42"


@pytest.mark.parametrize(
    "overrides",
    [
        {"capacity_decision": "RESERVED", "capacity_receipt_ref": None},
        {"capacity_decision": "WAITING", "capacity_receipt_ref": None},
        {
            "capacity_decision": "EXHAUSTED",
            "capacity_receipt_ref": None,
            "capacity_retry_at": NOW,
        },
        {"capacity_decision": "WAITING", "capacity_retry_at": NOW},
    ],
)
def test_capacity_shape_refuses_ambiguous_authority(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _request(**overrides)


def test_capacity_enum_is_closed() -> None:
    assert CapacityDecision.RESERVED == "RESERVED"
