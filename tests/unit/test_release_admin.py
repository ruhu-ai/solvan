from __future__ import annotations

import hashlib
import json

import pytest

from tests.unit.test_seed_demo import receipt_value
from tools.release_admin import validate_calibration_receipt


def _raw() -> bytes:
    return json.dumps(receipt_value(), default=str, sort_keys=True).encode()


def test_release_admin_binds_seed_to_hash_and_project() -> None:
    raw = _raw()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    receipt, actual = validate_calibration_receipt(
        raw, expected_hash=digest, project_id="solvan-demo"
    )
    assert receipt.project_id == "solvan-demo"
    assert actual == digest


def test_release_admin_rejects_changed_receipt() -> None:
    with pytest.raises(RuntimeError, match="hash"):
        validate_calibration_receipt(
            _raw(), expected_hash="sha256:" + "0" * 64, project_id="solvan-demo"
        )


def test_release_admin_rejects_cross_project_receipt() -> None:
    raw = _raw()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(RuntimeError, match="another GCP project"):
        validate_calibration_receipt(raw, expected_hash=digest, project_id="other-project")
