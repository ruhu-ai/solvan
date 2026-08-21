from datetime import UTC, datetime

import pytest

from apps.detector.main import _validate_offsets, _validate_rule_ids, evaluation_slot


def test_evaluation_slot_is_stable_across_request_jitter() -> None:
    first = evaluation_slot(datetime(2026, 8, 8, 12, 0, 24, 999000, tzinfo=UTC), 25_000)
    second = evaluation_slot(datetime(2026, 8, 8, 12, 0, 25, 1000, tzinfo=UTC), 25_000)

    assert first != second
    assert first.microsecond == 0
    assert second.microsecond == 0


def test_detector_burst_rejects_scheduler_shape_drift() -> None:
    _validate_offsets((0, 25, 50))
    with pytest.raises(ValueError, match="exactly"):
        _validate_offsets((0, 30))


def test_detector_rule_selection_is_exact_and_canonical() -> None:
    assert _validate_rule_ids(("payments-http-5xx-v1",)) == ("payments-http-5xx-v1",)
    with pytest.raises(ValueError, match="duplicates"):
        _validate_rule_ids(("payments-http-5xx-v1", "payments-http-5xx-v1"))
    with pytest.raises(ValueError, match="canonical"):
        _validate_rule_ids(("*",))
