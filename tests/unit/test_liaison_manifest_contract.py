from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest

from solvan.application.liaison.manifest_contract import (
    check_schema,
    validate_manifest,
    validate_manifest_freshness,
)
from tools.check_liaison_manifest_contract import baseline, baseline_expectations, manifest_hash


def _validate(value: dict[str, Any], *, expected_hash: str | None = None) -> None:
    validate_manifest(
        value,
        expected_hash=expected_hash or manifest_hash(value, 11, 13),
        policy_epoch=11,
        membership_epoch=13,
        **baseline_expectations(),
    )


def test_validation_refuses_to_supply_its_own_expectations() -> None:
    """A dispatch binding nobody passed is not a binding that was checked.

    Every expectation used to default to this fixture's own values, so a
    caller that omitted one validated a production manifest against
    `cell_eu_1`, `principal:opaque`, and a digest of sixty-four `a`s — and
    reported a pass.
    """

    value = baseline()
    with pytest.raises(TypeError):
        validate_manifest(  # type: ignore[call-arg]
            value,
            expected_hash=manifest_hash(value, 11, 13),
            policy_epoch=11,
            membership_epoch=13,
        )

    with pytest.raises(ValueError, match="compiled context bindings"):
        validate_manifest(
            value,
            expected_hash=manifest_hash(value, 11, 13),
            policy_epoch=11,
            membership_epoch=13,
            **{**baseline_expectations(), "expected_context_bindings": {}},
        )


def test_manifest_schema_and_valid_semantics() -> None:
    value = baseline()

    check_schema()
    _validate(value)


def _duplicate_source(value: dict[str, Any]) -> None:
    duplicate = copy.deepcopy(value["source_versions"][0])
    duplicate["version"] = "8"
    value["source_versions"].append(duplicate)


def _noncontiguous_sequence(value: dict[str, Any]) -> None:
    value["working_context"]["items"][1]["sequence"] = 3


def _unusable_budget(value: dict[str, Any]) -> None:
    value["working_context"]["token_budget"]["model_input_limit"] = 40


def _wrong_token_total(value: dict[str, Any]) -> None:
    value["working_context"]["token_budget"]["actual_context_tokens"] = 14


def _over_dynamic_ceiling(value: dict[str, Any]) -> None:
    value["working_context"]["token_budget"]["dynamic_context_ceiling"] = 14


def _expired(value: dict[str, Any]) -> None:
    value["working_context"]["expires_at"] = "2026-08-12T01:59:00+00:00"


def _classification_escape(value: dict[str, Any]) -> None:
    value["classification_ceiling"] = "INTERNAL"


@pytest.mark.parametrize(
    "mutation,message",
    [
        (_duplicate_source, "one record"),
        (_noncontiguous_sequence, "sequence"),
        (_unusable_budget, "usable model input"),
        (_wrong_token_total, "token count"),
        (_over_dynamic_ceiling, "dynamic context ceiling"),
        (_expired, "expiry"),
        (_classification_escape, "classification ceiling"),
    ],
)
def test_manifest_semantic_failures_are_specific(
    mutation: Callable[[dict[str, Any]], None], message: str
) -> None:
    value = baseline()
    mutation(value)

    with pytest.raises(ValueError, match=message):
        _validate(value)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("cell_id", "cell_other", "cell_id"),
        ("placement_epoch", 8, "placement_epoch"),
        ("reader_principal", "principal:other", "reader_principal"),
        ("purpose", "support-export", "purpose"),
        ("region", "us-central1", "region"),
    ],
)
def test_manifest_attempt_bindings_fail_closed(field: str, value: object, message: str) -> None:
    candidate = baseline()
    candidate[field] = value

    with pytest.raises(ValueError, match=message):
        _validate(candidate)


def test_manifest_scope_context_high_water_and_digest_are_bound() -> None:
    candidate = baseline()
    candidate["scope"]["project_id"] = "prj_other"
    with pytest.raises(ValueError, match="scope"):
        _validate(candidate)

    candidate = baseline()
    candidate["working_context"]["model_resource"] = "gemini-other"
    with pytest.raises(ValueError, match="model_resource"):
        _validate(candidate)

    candidate = baseline()
    candidate["scope_sequence_high_water"] = 1443
    with pytest.raises(ValueError, match="high-water"):
        _validate(candidate)

    candidate = baseline()
    with pytest.raises(ValueError, match="digest"):
        _validate(candidate, expected_hash="sha256:" + "0" * 64)


def test_dispatch_freshness_refuses_expired_context_and_accepts_live_context() -> None:
    from datetime import datetime

    candidate = baseline()
    validate_manifest_freshness(candidate, now=datetime.fromisoformat("2026-08-12T01:00:00+00:00"))
    with pytest.raises(ValueError, match="expired"):
        validate_manifest_freshness(
            candidate, now=datetime.fromisoformat("2026-08-12T03:00:00+00:00")
        )
    with pytest.raises(ValueError, match="timezone"):
        validate_manifest_freshness(candidate, now=datetime(2026, 8, 12, 3, 0))
