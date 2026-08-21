from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.incidents import CanonicalDetectionEvent, DetectionContractError


def event(**overrides: object) -> CanonicalDetectionEvent:
    start = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
    values: dict[str, object] = {
        "rule_id": "payments-http-5xx",
        "rule_version": 1,
        "service_id": "payments-api",
        "graph_snapshot_id": "pgs_00000000000000000000000000",
        "incident_class": "connection_exhaustion",
        "deduplication_dimension": "http-5xx",
        "window_start": start,
        "window_end": start + timedelta(minutes=1),
        "observed_value": 0.2,
        "severity": "SEV2",
        "action_budget": 2,
        "repeated_action_limit": 1,
    }
    values.update(overrides)
    return CanonicalDetectionEvent(**values)  # type: ignore[arg-type]


def test_detection_deduplication_key_contains_no_timestamp() -> None:
    assert event().deduplication_key == "payments-http-5xx:payments-api:http-5xx"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"rule_version": 0}, "rule version"),
        ({"window_start": datetime(2026, 8, 9, 12, 0)}, "timezone-aware"),
        (
            {
                "window_start": datetime(2026, 8, 9, 12, 2, tzinfo=UTC),
                "window_end": datetime(2026, 8, 9, 12, 1, tzinfo=UTC),
            },
            "precedes",
        ),
        ({"severity": "SEV0"}, "severity"),
        ({"action_budget": 0}, "action limits"),
        ({"observed_value": float("nan")}, "finite"),
        ({"service_id": "payments:api"}, "service"),
    ],
)
def test_invalid_detection_contract_is_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(DetectionContractError, match=message):
        event(**overrides)
