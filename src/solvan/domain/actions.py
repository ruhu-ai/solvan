"""Deterministic action authorization material and approval digests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, cast

from solvan.domain.scope import Scope


class ActionContractError(ValueError):
    """Raised when an action cannot be represented canonically."""


class ActionType(StrEnum):
    PAYMENTS_POOL_RECYCLE = "PAYMENTS_POOL_RECYCLE"
    CLOUD_RUN_TRAFFIC_ROLLBACK = "CLOUD_RUN_TRAFFIC_ROLLBACK"


class RiskClass(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


type JsonScalar = str | int | float | bool | None
type FrozenJson = JsonScalar | tuple[FrozenJson, ...] | Mapping[str, FrozenJson]


@dataclass(frozen=True, slots=True)
class ExpectedEffect:
    descriptor: Mapping[str, FrozenJson]
    content_hash: str

    def descriptor_object(self) -> dict[str, object]:
        value = _thaw_json(self.descriptor)
        if not isinstance(value, dict):  # pragma: no cover - constructor owns shape
            raise ActionContractError("expected effect must be an object")
        return value


@dataclass(frozen=True, slots=True)
class AuthorizedActionMaterial:
    action_id: str
    scope: Scope
    owner_entity_id: str
    workflow_version: int
    evidence_version: int
    action_type: ActionType
    target_key: str
    expected_target_version: str
    expected_target_epoch: int
    payload: Mapping[str, FrozenJson]
    expected_effect: Mapping[str, FrozenJson]
    expected_effect_hash: str
    risk_class: RiskClass
    reversible: bool
    rollback_plan: Mapping[str, FrozenJson]
    policy_version: str
    verification_profile_id: str
    verification_profile_version: int
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.workflow_version < 1:
            raise ActionContractError("workflow_version must be positive")
        if self.evidence_version < 0:
            raise ActionContractError("evidence_version cannot be negative")
        if self.expected_target_epoch < 0:
            raise ActionContractError("expected_target_epoch cannot be negative")
        if self.verification_profile_version < 1:
            raise ActionContractError("verification_profile_version must be positive")
        if not self.target_key or not self.expected_target_version:
            raise ActionContractError("target key and version must not be empty")
        if not self.policy_version or not self.verification_profile_id:
            raise ActionContractError("policy and verification profile must not be empty")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ActionContractError("expires_at must be timezone-aware")
        _canonical_json(_thaw_json(self.payload))
        expected = derive_expected_effect(
            action_type=self.action_type,
            target_key=self.target_key,
            expected_target_version=self.expected_target_version,
            payload=self.payload,
        )
        if _canonical_json(_thaw_json(self.expected_effect)) != _canonical_json(
            expected.descriptor_object()
        ):
            raise ActionContractError("expected effect is not application-derived")
        if self.expected_effect_hash != expected.content_hash:
            raise ActionContractError("expected effect hash does not match descriptor")
        _canonical_json(_thaw_json(self.rollback_plan))

    def approval_digest(self) -> str:
        material = {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "environment_id": self.scope.environment_id,
            "evidence_version": self.evidence_version,
            "expected_target_epoch": self.expected_target_epoch,
            "expected_target_version": self.expected_target_version,
            "expected_effect_hash": self.expected_effect_hash,
            "expires_at": self.expires_at.astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "organization_id": self.scope.organization_id,
            "owner_entity_id": self.owner_entity_id,
            "payload": _thaw_json(self.payload),
            "policy_version": self.policy_version,
            "project_id": self.scope.project_id,
            "reversible": self.reversible,
            "risk_class": self.risk_class.value,
            "rollback_plan": _thaw_json(self.rollback_plan),
            "target_key": self.target_key,
            "verification_profile_id": self.verification_profile_id,
            "verification_profile_version": self.verification_profile_version,
            "workflow_version": self.workflow_version,
        }
        return f"sha256:{hashlib.sha256(_canonical_json(material)).hexdigest()}"

    def payload_object(self) -> dict[str, object]:
        """Return a detached JSON object for a typed connector request."""

        value = _thaw_json(self.payload)
        if not isinstance(value, dict):  # pragma: no cover - field type and constructor enforce
            raise ActionContractError("action payload must be an object")
        return value


def derive_expected_effect(
    *,
    action_type: ActionType,
    target_key: str,
    expected_target_version: str,
    payload: Mapping[str, FrozenJson],
) -> ExpectedEffect:
    """Derive the sole approvable effect from typed application action material."""

    payload_value = _thaw_json(payload)
    if not isinstance(payload_value, dict):  # pragma: no cover - field type owns shape
        raise ActionContractError("action payload must be an object")
    if action_type is ActionType.PAYMENTS_POOL_RECYCLE:
        _require_keys(payload_value, {"admin_operation", "drain_timeout_ms"})
        if payload_value["admin_operation"] != "RECYCLE_DB_POOL":
            raise ActionContractError("pool recycle operation is unsupported")
        drain_timeout_ms = payload_value["drain_timeout_ms"]
        if type(drain_timeout_ms) is not int or drain_timeout_ms < 1:
            raise ActionContractError("pool recycle drain timeout is invalid")
        descriptor = {
            "action_type": action_type.value,
            "from_pool_generation": expected_target_version,
            "operation": payload_value,
            "profile": "payments-pool-recycle.v1",
            "schema_version": 1,
            "target_key": target_key,
        }
    elif action_type is ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK:
        _require_keys(payload_value, {"known_good_revision", "percent", "service_name"})
        service_name = payload_value["service_name"]
        revision = payload_value["known_good_revision"]
        percent = payload_value["percent"]
        if not isinstance(service_name, str) or not service_name:
            raise ActionContractError("Cloud Run service name is invalid")
        if not isinstance(revision, str) or not revision:
            raise ActionContractError("Cloud Run rollback revision is invalid")
        if type(percent) is not int or percent != 100:
            raise ActionContractError("Cloud Run rollback must replace 100 percent of traffic")
        descriptor = {
            "action_type": action_type.value,
            "from_revision": expected_target_version,
            "profile": "cloud-run-traffic-replacement.v1",
            "schema_version": 1,
            "service_name": service_name,
            "target_key": target_key,
            "traffic": [{"percent": percent, "revision": revision}],
        }
    else:  # pragma: no cover - closed enum currently has two members
        raise ActionContractError("action type has no expected-effect profile")
    frozen = freeze_json(descriptor)
    return ExpectedEffect(frozen, canonical_json_hash(frozen))


def canonical_json_hash(value: FrozenJson) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(_thaw_json(value))).hexdigest()}"


def freeze_json(value: dict[str, Any]) -> Mapping[str, FrozenJson]:
    """Return a detached, recursively immutable canonical JSON mapping."""

    canonical = _canonical_json(value)
    loaded = json.loads(canonical)
    if not isinstance(loaded, dict):  # defensive: input annotation is not runtime authority
        raise ActionContractError("action JSON must be an object")
    return cast(Mapping[str, FrozenJson], _freeze_json_value(loaded))


def _freeze_json_value(value: object) -> FrozenJson:
    if isinstance(value, dict):
        return MappingProxyType({str(key): _freeze_json_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json_value(item) for item in value)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise ActionContractError("action material must contain canonical JSON values")


def _require_keys(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ActionContractError("action payload does not match expected-effect profile")


def _thaw_json(value: FrozenJson) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


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
        raise ActionContractError("action material must contain canonical JSON values") from error
