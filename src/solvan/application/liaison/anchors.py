"""Anchors: what a conversation is about, validated rather than believed.

Every thread and every question names an anchor. An anchor reference arriving
from a model, a channel, or a URL is a claim about the world, so it is checked
against the record directory before anything reads on its behalf.

The three shapes are mutually exclusive by construction here, mirroring the
exhaustive CHECK in the target DDL. Specification 14 §4 and §11.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol


class AnchorError(ValueError):
    """An anchor is malformed or does not resolve; nothing may read for it."""


class AnchorKind(StrEnum):
    RECORD = "RECORD"
    SERVICE_WINDOW = "SERVICE_WINDOW"
    SCOPE = "SCOPE"


#: Record types a conversation may anchor to. A type absent here cannot be
#: addressed at all, so a new record kind becomes conversable deliberately.
ANCHORABLE_RECORD_TYPES = frozenset(
    {
        "incident",
        "reliability_case",
        "action",
        "evidence_item",
        "verification_run",
        "patch_artifact",
        "workspace",
        "tenant_connection",
        "alert_episode",
    }
)


class RecordDirectory(Protocol):
    """Existence and shape of an addressable record, from the ledger."""

    def exists(self, record_type: str, record_id: str) -> bool: ...

    def children(self, record_type: str, record_id: str) -> tuple[tuple[str, str], ...]: ...


@dataclass(frozen=True, slots=True)
class Anchor:
    """One validated anchor. Construct through `record`, `service`, or `scope`."""

    kind: AnchorKind
    record_type: str | None = None
    record_id: str | None = None
    service_key: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None

    def __post_init__(self) -> None:
        if self.kind is AnchorKind.RECORD:
            if not self.record_type or not self.record_id:
                raise AnchorError("a record anchor needs a record type and id")
            if self.service_key or self.window_start or self.window_end:
                raise AnchorError("a record anchor carries no service or window")
            if self.record_type not in ANCHORABLE_RECORD_TYPES:
                raise AnchorError(f"record type {self.record_type} is not anchorable")
        elif self.kind is AnchorKind.SERVICE_WINDOW:
            if not self.service_key or not self.window_start or not self.window_end:
                raise AnchorError("a service anchor needs a service key and a closed window")
            if self.record_type or self.record_id:
                raise AnchorError("a service anchor carries no record reference")
            if self.window_end <= self.window_start:
                raise AnchorError("a service window must end after it starts")
        else:
            if self.record_type or self.record_id or self.service_key:
                raise AnchorError("a scope anchor carries no detail")

    @classmethod
    def record(cls, record_type: str, record_id: str) -> Anchor:
        return cls(kind=AnchorKind.RECORD, record_type=record_type, record_id=record_id)

    @classmethod
    def service(cls, service_key: str, start: datetime, end: datetime) -> Anchor:
        return cls(
            kind=AnchorKind.SERVICE_WINDOW,
            service_key=service_key,
            window_start=start,
            window_end=end,
        )

    @classmethod
    def scope(cls) -> Anchor:
        return cls(kind=AnchorKind.SCOPE)

    def label(self) -> str:
        """A short human name, used in prompts and in thread lists."""

        if self.kind is AnchorKind.RECORD:
            return f"{self.record_type}:{self.record_id}"
        if self.kind is AnchorKind.SERVICE_WINDOW:
            return f"service:{self.service_key}"
        return "scope"

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "anchor_kind": str(self.kind),
            "anchor_record_type": self.record_type,
            "anchor_record_id": self.record_id,
            "anchor_service_key": self.service_key,
            "anchor_window_start": self.window_start,
            "anchor_window_end": self.window_end,
        }


def resolve_anchor(directory: RecordDirectory, anchor: Anchor) -> Anchor:
    """Confirm a record anchor exists before it is used to read anything."""

    if anchor.kind is AnchorKind.RECORD:
        assert anchor.record_type is not None and anchor.record_id is not None
        if not directory.exists(anchor.record_type, anchor.record_id):
            raise AnchorError(
                f"{anchor.record_type} {anchor.record_id} does not exist in this scope"
            )
    return anchor


def anchor_from_mapping(value: Mapping[str, Any]) -> Anchor:
    """Build an anchor from an API payload, failing closed on nonsense."""

    raw_kind = str(value.get("anchor_kind", "")).upper()
    try:
        kind = AnchorKind(raw_kind)
    except ValueError as error:
        raise AnchorError(f"unknown anchor kind {raw_kind!r}") from error
    if kind is AnchorKind.RECORD:
        return Anchor.record(
            str(value.get("anchor_record_type", "")),
            str(value.get("anchor_record_id", "")),
        )
    if kind is AnchorKind.SERVICE_WINDOW:
        start, end = value.get("anchor_window_start"), value.get("anchor_window_end")
        if not isinstance(start, datetime) or not isinstance(end, datetime):
            raise AnchorError("a service anchor needs datetime window bounds")
        return Anchor.service(str(value.get("anchor_service_key", "")), start, end)
    return Anchor.scope()


def entity_set(directory: RecordDirectory, anchor: Anchor) -> tuple[tuple[str, str], ...]:
    """The records an anchor reaches, for reading and for catch-up.

    Context flows down the graph; authority never does — the reader filter is
    applied per record regardless of what the anchor reaches (§4).
    """

    if anchor.kind is AnchorKind.RECORD:
        assert anchor.record_type is not None and anchor.record_id is not None
        head = (anchor.record_type, anchor.record_id)
        return (head, *directory.children(*head))
    if anchor.kind is AnchorKind.SERVICE_WINDOW:
        assert anchor.service_key is not None
        return directory.children("service", anchor.service_key)
    return directory.children("scope", "*")
