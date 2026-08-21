"""Closed Alert-list filters and audience-bound pagination cursors.

The browser may present friendly controls, but the API accepts one canonical
RFC 8785 filter document.  Cursors are integrity protected and bind the exact
reader, scope, filter, and authorization/placement epochs so they cannot be
replayed after access or routing changes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

import rfc8785

from solvan.domain import Scope


class AlertFilterError(ValueError):
    """The filter or cursor is not a closed, valid Alert-list request."""


_VIEWS = frozenset({"ACTIVE", "NEEDS_REVIEW", "INVESTIGATING", "ALL"})
_STATES = frozenset(
    {
        "OPEN",
        "WAITING",
        "TRIAGING",
        "TRIAGED",
        "SUPPRESSED",
        "BLOCKED",
        "ESCALATED",
        "ATTACHED",
        "PROVIDER_REPORTED_CLEARED",
        "EXPIRED",
    }
)
_SEVERITIES = frozenset({"SEV1", "SEV2", "SEV3", "SEV4"})
_MODES = frozenset({"TRIAGE", "POLICY_ESCALATED", "FULL_INCIDENT"})
_PROVIDER_STATES = frozenset({"OPEN", "CLOSED"})
_DISPOSITIONS = frozenset(
    {
        "SUPPRESSED",
        "TRIAGED_HOLD",
        "ESCALATED_NEW",
        "ESCALATED_ATTACHED",
        "MANUAL_REVIEW",
        "BLOCKED",
    }
)
_INCIDENT_LINKS = frozenset({"ANY", "LINKED", "UNLINKED"})
_SOURCE_PROVIDERS = frozenset({"CLOUD_MONITORING"})
_SAFE_QUERY = re.compile(r"^[\w .:@/+\-]{1,128}$", re.UNICODE)
_SAFE_FILTER_VALUE = re.compile(r"^[A-Za-z0-9_.:/@+\-]{1,256}$")
_SAFE_EPISODE_ID = re.compile(r"^aep_[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    if not value or len(value) > 8192 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise AlertFilterError("INVALID_ALERT_FILTER") from error


def _closed_strings(value: Any, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    if len(value) > 100 or len(set(value)) != len(value):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    if allowed is not None and any(item not in allowed for item in value):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    if allowed is None and any(_SAFE_FILTER_VALUE.fullmatch(item) is None for item in value):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    return tuple(sorted(value))


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        result[key] = value
    return result


def _utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise AlertFilterError("INVALID_ALERT_FILTER") from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise AlertFilterError("INVALID_ALERT_FILTER")
    return parsed


@dataclass(frozen=True, slots=True)
class AlertListFilter:
    """Validated version-one list filter with deterministic serialization."""

    schema_version: int = 1
    view: str = "ACTIVE"
    episode_state: tuple[str, ...] = ()
    source_provider: tuple[str, ...] = ()
    connection_id: tuple[str, ...] = ()
    department: tuple[str, ...] = ()
    target_key: tuple[str, ...] = ()
    severity: tuple[str, ...] = ()
    policy_key: tuple[str, ...] = ()
    mode: tuple[str, ...] = ()
    provider_state: tuple[str, ...] = ()
    disposition: tuple[str, ...] = ()
    incident_link: str = "ANY"
    source_time_from: datetime | None = None
    source_time_to: datetime | None = None
    query: str | None = None
    limit: int = 50

    _KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schema_version",
            "view",
            "episode_state",
            "source_provider",
            "connection_id",
            "department",
            "target_key",
            "severity",
            "policy_key",
            "mode",
            "provider_state",
            "disposition",
            "incident_link",
            "source_time_from",
            "source_time_to",
            "query",
            "limit",
        }
    )

    @classmethod
    def from_encoded(cls, value: str | None) -> AlertListFilter:
        if value is None:
            return cls()
        decoded = _b64_decode(value)
        try:
            raw = json.loads(decoded, object_pairs_hook=_closed_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AlertFilterError("INVALID_ALERT_FILTER") from error
        if not isinstance(raw, dict) or set(raw) - cls._KEYS:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        if decoded != rfc8785.dumps(raw):
            raise AlertFilterError("INVALID_ALERT_FILTER")
        if raw.get("schema_version", 1) != 1:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        view = raw.get("view", "ACTIVE")
        incident_link = raw.get("incident_link", "ANY")
        limit = raw.get("limit", 50)
        query = raw.get("query")
        if view not in _VIEWS or incident_link not in _INCIDENT_LINKS:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        if query is not None:
            if not isinstance(query, str):
                raise AlertFilterError("INVALID_ALERT_FILTER")
            query = " ".join(query.split()).casefold()
            if not _SAFE_QUERY.fullmatch(query):
                raise AlertFilterError("INVALID_ALERT_FILTER")
        start = _utc(raw.get("source_time_from"))
        end = _utc(raw.get("source_time_to"))
        if start is not None and end is not None and start >= end:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        return cls(
            view=view,
            episode_state=_closed_strings(raw.get("episode_state"), allowed=_STATES),
            source_provider=_closed_strings(raw.get("source_provider"), allowed=_SOURCE_PROVIDERS),
            connection_id=_closed_strings(raw.get("connection_id")),
            department=_closed_strings(raw.get("department")),
            target_key=_closed_strings(raw.get("target_key")),
            severity=_closed_strings(raw.get("severity"), allowed=_SEVERITIES),
            policy_key=_closed_strings(raw.get("policy_key")),
            mode=_closed_strings(raw.get("mode"), allowed=_MODES),
            provider_state=_closed_strings(raw.get("provider_state"), allowed=_PROVIDER_STATES),
            disposition=_closed_strings(raw.get("disposition"), allowed=_DISPOSITIONS),
            incident_link=incident_link,
            source_time_from=start,
            source_time_to=end,
            query=query,
            limit=limit,
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "view": self.view,
            "episode_state": list(self.episode_state),
            "source_provider": list(self.source_provider),
            "connection_id": list(self.connection_id),
            "department": list(self.department),
            "target_key": list(self.target_key),
            "severity": list(self.severity),
            "policy_key": list(self.policy_key),
            "mode": list(self.mode),
            "provider_state": list(self.provider_state),
            "disposition": list(self.disposition),
            "incident_link": self.incident_link,
            "source_time_from": self.source_time_from.isoformat().replace("+00:00", "Z")
            if self.source_time_from
            else None,
            "source_time_to": self.source_time_to.isoformat().replace("+00:00", "Z")
            if self.source_time_to
            else None,
            "query": self.query,
            "limit": self.limit,
        }

    def encoded(self) -> str:
        return _b64_encode(rfc8785.dumps(self.canonical_dict()))

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(rfc8785.dumps(self.canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class AlertCursorPosition:
    severity_rank: int
    attention_rank: int
    last_seen_at: datetime
    alert_episode_id: str


class AlertCursorCodec:
    """HMAC cursor codec; opaque tokens contain no user-facing labels."""

    def __init__(self, *, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("Alert cursor signing key must be at least 32 bytes")
        self._key = signing_key

    def encode(
        self,
        *,
        position: AlertCursorPosition,
        filter_digest: str,
        principal: str,
        scope: Scope,
        placement_epoch: int,
        policy_epoch: int,
        membership_epoch: int,
    ) -> str:
        payload = self._payload(
            position=position,
            filter_digest=filter_digest,
            principal=principal,
            scope=scope,
            placement_epoch=placement_epoch,
            policy_epoch=policy_epoch,
            membership_epoch=membership_epoch,
        )
        body = rfc8785.dumps(payload)
        return _b64_encode(body) + "." + _b64_encode(hmac.digest(self._key, body, "sha256"))

    def decode(
        self,
        value: str | None,
        *,
        filter_digest: str,
        principal: str,
        scope: Scope,
        placement_epoch: int,
        policy_epoch: int,
        membership_epoch: int,
    ) -> AlertCursorPosition | None:
        if value is None:
            return None
        head, separator, tail = value.partition(".")
        if separator != ".":
            raise AlertFilterError("INVALID_ALERT_FILTER")
        body = _b64_decode(head)
        signature = _b64_decode(tail)
        if not hmac.compare_digest(signature, hmac.digest(self._key, body, "sha256")):
            raise AlertFilterError("INVALID_ALERT_FILTER")
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AlertFilterError("INVALID_ALERT_FILTER") from error
        expected = self._payload(
            position=None,
            filter_digest=filter_digest,
            principal=principal,
            scope=scope,
            placement_epoch=placement_epoch,
            policy_epoch=policy_epoch,
            membership_epoch=membership_epoch,
        )
        if (
            not isinstance(payload, dict)
            or set(payload) != {*expected, "position"}
            or body != rfc8785.dumps(payload)
            or any(payload.get(key) != item for key, item in expected.items())
        ):
            raise AlertFilterError("INVALID_ALERT_FILTER")
        position = payload.get("position")
        if not isinstance(position, list) or len(position) != 4:
            raise AlertFilterError("INVALID_ALERT_FILTER")
        try:
            parsed_time = _utc(position[2])
            if parsed_time is None:
                raise AlertFilterError("INVALID_ALERT_FILTER")
            severity_rank = int(position[0])
            attention_rank = int(position[1])
            alert_episode_id = str(position[3])
            if (
                isinstance(position[0], bool)
                or isinstance(position[1], bool)
                or severity_rank not in {1, 2, 3, 4}
                or attention_rank not in {0, 1}
                or _SAFE_EPISODE_ID.fullmatch(alert_episode_id) is None
            ):
                raise AlertFilterError("INVALID_ALERT_FILTER")
            return AlertCursorPosition(
                severity_rank=severity_rank,
                attention_rank=attention_rank,
                last_seen_at=parsed_time,
                alert_episode_id=alert_episode_id,
            )
        except (TypeError, ValueError) as error:
            raise AlertFilterError("INVALID_ALERT_FILTER") from error

    @staticmethod
    def _payload(
        *,
        position: AlertCursorPosition | None,
        filter_digest: str,
        principal: str,
        scope: Scope,
        placement_epoch: int,
        policy_epoch: int,
        membership_epoch: int,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": 1,
            "filter_digest": filter_digest,
            "principal_hash": "sha256:" + hashlib.sha256(principal.encode()).hexdigest(),
            "scope_hash": "sha256:"
            + hashlib.sha256(rfc8785.dumps(scope.canonical_dict())).hexdigest(),
            "placement_epoch": placement_epoch,
            "policy_epoch": policy_epoch,
            "membership_epoch": membership_epoch,
        }
        if position is not None:
            payload["position"] = [
                position.severity_rank,
                position.attention_rank,
                position.last_seen_at.isoformat().replace("+00:00", "Z"),
                position.alert_episode_id,
            ]
        return payload
