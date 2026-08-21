from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest

from solvan.application.alert_list import (
    AlertCursorCodec,
    AlertCursorPosition,
    AlertFilterError,
    AlertListFilter,
)
from solvan.domain import Scope


def test_filter_round_trips_canonical_closed_material() -> None:
    original = AlertListFilter(
        view="ALL",
        severity=("SEV1", "SEV2"),
        query="payments api",
        limit=25,
    )
    decoded = AlertListFilter.from_encoded(original.encoded())
    assert decoded == original
    assert decoded.digest.startswith("sha256:")


@pytest.mark.parametrize(
    "encoded",
    ("not-valid!", AlertListFilter().encoded() + "x"),
)
def test_filter_refuses_invalid_encoding(encoded: str) -> None:
    with pytest.raises(AlertFilterError, match="INVALID_ALERT_FILTER"):
        AlertListFilter.from_encoded(encoded)


def _encoded_json(material: str) -> str:
    return base64.urlsafe_b64encode(material.encode()).decode().rstrip("=")


def test_filter_refuses_duplicate_keys_noncanonical_json_and_unknown_provider() -> None:
    valid = AlertListFilter().canonical_dict()
    duplicate = '{"view":"ACTIVE","view":"ALL"}'
    # The values are valid, but insignificant whitespace makes these bytes
    # differ from the one accepted RFC 8785 representation.
    noncanonical = json.dumps(valid, sort_keys=True)
    unknown_provider = dict(valid)
    unknown_provider["source_provider"] = ["UNREGISTERED_PROVIDER"]

    for encoded in (
        _encoded_json(duplicate),
        _encoded_json(noncanonical),
        _encoded_json(json.dumps(unknown_provider, sort_keys=True, separators=(",", ":"))),
    ):
        with pytest.raises(AlertFilterError, match="INVALID_ALERT_FILTER"):
            AlertListFilter.from_encoded(encoded)


def test_cursor_is_bound_to_reader_filter_scope_and_epochs() -> None:
    codec = AlertCursorCodec(signing_key=b"test-alert-cursor-signing-key-0001")
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    alert_filter = AlertListFilter(view="ACTIVE")
    position = AlertCursorPosition(
        2, 0, datetime(2026, 8, 14, tzinfo=UTC), "aep_01K00000000000000000000000"
    )
    token = codec.encode(
        position=position,
        filter_digest=alert_filter.digest,
        principal="user:operator@example.com",
        scope=scope,
        placement_epoch=3,
        policy_epoch=7,
        membership_epoch=11,
    )
    assert (
        codec.decode(
            token,
            filter_digest=alert_filter.digest,
            principal="user:operator@example.com",
            scope=scope,
            placement_epoch=3,
            policy_epoch=7,
            membership_epoch=11,
        )
        == position
    )
    with pytest.raises(AlertFilterError, match="INVALID_ALERT_FILTER"):
        codec.decode(
            token,
            filter_digest=alert_filter.digest,
            principal="user:different@example.com",
            scope=scope,
            placement_epoch=3,
            policy_epoch=7,
            membership_epoch=11,
        )
