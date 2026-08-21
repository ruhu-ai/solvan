"""Strict parsing and canonical hashing of approved mitigation policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from solvan.persistence.mitigation_types import MitigationPolicyError


@dataclass(frozen=True, slots=True)
class _ObservationRequirement:
    source_kind: str
    tool_name: str
    argument_equals: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ConfirmationSpec:
    normalized_cause_key: str
    statement: str
    all_required: tuple[_ObservationRequirement, ...]


def _parse_confirmation_spec(value: object) -> _ConfirmationSpec:
    if not isinstance(value, dict) or set(value) != {
        "normalized_cause_key",
        "statement",
        "all_required",
    }:
        raise MitigationPolicyError("confirmation rule has an unsupported schema")
    cause_key = value["normalized_cause_key"]
    statement = value["statement"]
    raw_requirements = value["all_required"]
    if (
        not isinstance(cause_key, str)
        or not 1 <= len(cause_key) <= 160
        or not isinstance(statement, str)
        or not 1 <= len(statement) <= 2_000
        or not isinstance(raw_requirements, list)
        or not 1 <= len(raw_requirements) <= 8
    ):
        raise MitigationPolicyError("confirmation rule fields are invalid")
    requirements: list[_ObservationRequirement] = []
    for raw in raw_requirements:
        if not isinstance(raw, dict) or set(raw) != {
            "source_kind",
            "tool_name",
            "argument_equals",
        }:
            raise MitigationPolicyError("confirmation observation has an unsupported schema")
        source_kind = raw["source_kind"]
        tool_name = raw["tool_name"]
        argument_equals = raw["argument_equals"]
        if (
            not isinstance(source_kind, str)
            or not isinstance(tool_name, str)
            or not isinstance(argument_equals, dict)
            or not argument_equals
        ):
            raise MitigationPolicyError("confirmation observation fields are invalid")
        _canonical_json(argument_equals)
        requirements.append(_ObservationRequirement(source_kind, tool_name, argument_equals))
    return _ConfirmationSpec(cause_key, statement, tuple(requirements))


def _mapping_contains(value: object, expected: dict[str, object]) -> bool:
    if not isinstance(value, dict):
        return False
    return all(
        key in value and value[key] == expected_value for key, expected_value in expected.items()
    )


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise MitigationPolicyError("policy material is not canonical JSON") from error


def _digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value)).hexdigest()}"
