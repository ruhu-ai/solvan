from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tools.seed_demo import CalibrationReceipt


def receipt_value() -> dict[str, object]:
    hashes = [f"sha256:{character * 64}" for character in "abcd"]
    return {
        "schema_version": 1,
        "release_commit": "a" * 40,
        "project_id": "solvan-demo",
        "region": "europe-west1",
        "payments_service_name": "solvan-staging-payments",
        "known_good_revision": "solvan-staging-payments-good",
        "fault_revision": "solvan-staging-payments-bad",
        "cloud_sql_database_id": "solvan-demo:europe-west1:control",
        "evidence_ref": "gs://solvan-evidence/calibration/payments-v1.json",
        "approved_by": "user:owner@example.com",
        "approved_at": datetime(2026, 8, 8, tzinfo=UTC),
        "signals": [
            {
                "signal_kind": "HTTP_5XX_RATIO",
                "baseline_max": 0.01,
                "fault_min": 0.8,
                "detection_threshold": 0.4,
                "recovery_threshold": 0.05,
                "sustained_windows": 2,
                "sample_hashes": hashes,
            },
            {
                "signal_kind": "HTTP_P95_LATENCY",
                "baseline_max": 0.2,
                "fault_min": 2.0,
                "detection_threshold": 1.0,
                "recovery_threshold": 0.3,
                "sustained_windows": 2,
                "sample_hashes": hashes,
            },
        ],
    }


def test_calibration_requires_exact_measured_signal_set() -> None:
    receipt = CalibrationReceipt.model_validate(receipt_value())
    assert receipt.signal("HTTP_5XX_RATIO").detection_threshold == 0.4
    assert receipt.signal("HTTP_P95_LATENCY").recovery_threshold == 0.3


def test_calibration_rejects_guessed_or_nonseparating_threshold() -> None:
    value = receipt_value()
    value["signals"][0]["detection_threshold"] = 0.9  # type: ignore[index]
    with pytest.raises(ValidationError, match="strictly separate"):
        CalibrationReceipt.model_validate(value)


def test_calibration_requires_durable_evidence() -> None:
    value = receipt_value()
    value["evidence_ref"] = "file:///tmp/calibration.json"
    with pytest.raises(ValidationError, match="durable GCS"):
        CalibrationReceipt.model_validate(value)


def test_calibration_requires_two_exact_release_revisions() -> None:
    value = receipt_value()
    value["fault_revision"] = value["known_good_revision"]
    with pytest.raises(ValidationError, match="must be distinct"):
        CalibrationReceipt.model_validate(value)
