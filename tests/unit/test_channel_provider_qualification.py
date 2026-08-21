from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from solvan.application.channel_provider_qualification import (
    parse_channel_provider_qualification,
)
from solvan.domain import Scope

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def _raw(*, status: str = "AVAILABLE", all_pass: bool = True) -> bytes:
    results = {
        "authenticated_ingress_accepted": all_pass,
        "forged_ingress_denied": True,
        "provider_identity_bound": True,
        "reader_filtered_delivery_succeeded": True,
        "duplicate_delivery_suppressed": True,
        "revocation_fenced": True,
        "pii_redaction_verified": True,
    }
    return json.dumps(
        {
            "schema_version": 1,
            "kind": "SOLVAN_CHANNEL_PROVIDER_QUALIFICATION",
            "project_id": "solvan-staging",
            "release_commit": "a" * 40,
            "deployment_id": "staging-20260815",
            "service_revision": "solvan-staging-slack-liaison-00017-xmk",
            "organization_id": SCOPE.organization_id,
            "scope_project_id": SCOPE.project_id,
            "environment_id": SCOPE.environment_id,
            "channel_kind": "SLACK",
            "status": status,
            "safe_reason_code": "DEPLOYED_PATH_PASSED",
            "next_step_code": "REQUALIFY_BEFORE_EXPIRY",
            "checked_at": NOW.isoformat(),
            "validity_seconds": 3_600,
            "results": results,
            "content_capture": "NO_PROVIDER_CONTENT_RECORDED",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _hash(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def test_available_receipt_is_exactly_bound_and_current() -> None:
    raw = _raw()
    receipt, actual_hash = parse_channel_provider_qualification(raw, expected_hash=_hash(raw))

    receipt.assert_current(
        expected_project_id="solvan-staging",
        expected_release_commit="a" * 40,
        expected_deployment_id="staging-20260815",
        expected_channel_kind="SLACK",
        expected_scope=SCOPE,
        now=NOW + timedelta(minutes=5),
    )
    assert actual_hash == _hash(raw)


def test_receipt_hash_and_scope_cannot_be_replayed() -> None:
    raw = _raw()
    with pytest.raises(ValueError, match="hash does not match"):
        parse_channel_provider_qualification(raw, expected_hash="sha256:" + "0" * 64)

    receipt, _ = parse_channel_provider_qualification(raw, expected_hash=_hash(raw))
    with pytest.raises(ValueError, match="another tenant scope"):
        receipt.assert_current(
            expected_project_id="solvan-staging",
            expected_release_commit="a" * 40,
            expected_deployment_id="staging-20260815",
            expected_channel_kind="SLACK",
            expected_scope=Scope(
                SCOPE.organization_id,
                SCOPE.project_id,
                "env_00000000000000000000000001",
            ),
            now=NOW,
        )


def test_available_receipt_refuses_a_partial_result_or_expiry() -> None:
    with pytest.raises(ValidationError, match="every deployed-path result"):
        raw = _raw(all_pass=False)
        parse_channel_provider_qualification(raw, expected_hash=_hash(raw))

    raw = _raw(status="NEEDS_ATTENTION", all_pass=False)
    receipt, _ = parse_channel_provider_qualification(raw, expected_hash=_hash(raw))
    with pytest.raises(ValueError, match="already expired"):
        receipt.assert_current(
            expected_project_id="solvan-staging",
            expected_release_commit="a" * 40,
            expected_deployment_id="staging-20260815",
            expected_channel_kind="SLACK",
            expected_scope=SCOPE,
            now=NOW + timedelta(hours=2),
        )
