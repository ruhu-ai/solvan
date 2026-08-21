"""The grant-bound projection reader and its loop guard.

Every read a turn makes goes through here, so this is where a read is
authorized against the grant, digest-bound, contained to the anchor's entity
set, watched for loops, and counted. It lives beside the turn engine rather
than inside it because the engine's subject is the shape of a turn -- budgets,
escalation, the gate -- while this is the narrower question of whether one
read is permitted at all.

Specification 14 §7 and §12.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, cast

from solvan.application.liaison.anchors import Anchor
from solvan.application.liaison.budgets import TurnUsage
from solvan.application.liaison.grants import (
    ConversationReadGrant,
    verify_read_request,
)
from solvan.application.liaison.predicates import ProjectionReader


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time comparison for grant-bound digest strings."""

    return hmac.compare_digest(left.encode(), right.encode())


def _anchor_from_label(label: str) -> Anchor | None:
    """Decode the narrow labels carried by a read grant.

    Service-window timestamps are intentionally not reconstructed from a
    label; those grants must provide an anchor-aware reader implementation.
    Record labels are sufficient for the common exact-record path.
    """

    if label == "scope":
        return Anchor.scope()
    if label.startswith("service:"):
        return None
    record_type, separator, record_id = label.partition(":")
    if not separator or not record_type or not record_id:
        return None
    try:
        return Anchor.record(record_type, record_id)
    except ValueError:
        return None


@dataclass(slots=True)
class DoomLoopGuard:
    """Identical consecutive reads become a question, not burned budget."""

    threshold: int = 3
    _last: tuple[str, str] | None = field(default=None, init=False)
    _repeats: int = field(default=0, init=False)

    def observe(self, method: str, argument: str) -> bool:
        """Return True when the caller must stop and park a question."""

        current = (method, argument)
        if current == self._last:
            self._repeats += 1
        else:
            self._last = current
            self._repeats = 1
        return self._repeats >= self.threshold


class GrantedReader:
    """Wraps a projection reader so every read is authorized and counted.

    Scope is absent from the call signature on purpose: it comes from the
    grant, so no caller — model, adapter, or route — can name another tenant.
    """

    def __init__(
        self,
        inner: ProjectionReader,
        *,
        grant: ConversationReadGrant,
        usage: TurnUsage,
        guard: DoomLoopGuard | None = None,
        verifying: bool = False,
    ) -> None:
        self._inner = inner
        self._grant = grant
        self._usage = usage
        self._guard = guard or DoomLoopGuard()
        self._verifying = verifying
        self._authorized: tuple[tuple[str, str], ...] | None = None
        self.looped = False

    def for_verification(self) -> GrantedReader:
        """The same authority, for the deterministic claim gate.

        The gate must read under the grant — a citation the grant's anchor
        never covered is not evidence this reader may be shown, whatever the
        principal could reach by another route — but it is not the drafter. So
        its reads are neither charged to the model's tool-call ceiling nor
        watched by the doom-loop guard: verifying one claim reads the same
        cited record several times by design, once to resolve the citation,
        once per record-bound slot, and once inside the predicate. That is
        verification, not a loop. The reads are counted separately instead, so
        the work stays visible rather than invisible.
        """

        return GrantedReader(
            self._inner,
            grant=self._grant,
            usage=self._usage,
            guard=self._guard,
            verifying=True,
        )

    def _authorize(self, method: str, arguments: dict[str, object]) -> None:
        """Authorize, digest-bind, loop-check, and count one exact read."""

        presented = self._grant.request_digest(method, arguments)
        verify_read_request(
            self._grant,
            method=method,
            arguments=arguments,
            presented_digest=presented,
        )
        if self._verifying:
            self._usage.verification_reads += 1
            return
        argument_key = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
        if self._guard.observe(method, argument_key):
            self.looped = True
        self._usage.tool_calls += 1

    def _authorized_records(self) -> tuple[tuple[str, str], ...]:
        if self._authorized is not None:
            return self._authorized
        records = self._resolve_authorized_records()
        if self._verifying:
            # The grant pins its anchor entity set for the whole turn, so the
            # gate's repeated containment checks resolve one immutable set once
            # instead of walking the projection for every cited record.
            self._authorized = records
        return records

    def _resolve_authorized_records(self) -> tuple[tuple[str, str], ...]:
        scoped = getattr(self._inner, "authorized_records_for_anchor", None)
        if scoped is not None:
            anchor = _anchor_from_label(self._grant.anchor_label)
            if anchor is not None:
                records = tuple(scoped(anchor))
                expected = self._grant.anchor_entity_set_digest
                if expected:
                    actual = (
                        "sha256:"
                        + hashlib.sha256(
                            json.dumps(records, separators=(",", ":"), sort_keys=True).encode()
                        ).hexdigest()
                    )
                    if not hmac_compare(expected, actual):
                        return ()
                return records
        callback = getattr(self._inner, "authorized_records", None)
        if callback is None:
            return ()
        return tuple(callback())

    def _contains(self, record_type: str, record_id: str) -> bool:
        return (record_type, record_id) in set(self._authorized_records())

    def read(self, record_type: str, record_id: str) -> Mapping[str, Any] | None:
        self._authorize(
            "read_projection",
            {"record_type": record_type, "record_id": record_id},
        )
        if not self._contains(record_type, record_id):
            return None
        return self._inner.read(record_type, record_id)

    def resolve_anchor(self, reference: str) -> Mapping[str, Any]:
        arguments: dict[str, object] = {"reference": reference}
        self._authorize("resolve_anchor", arguments)
        callback = getattr(self._inner, "resolve_reference", None)
        if callback is None:
            return {"found": False, "reason": "record_directory_unavailable"}
        resolved = callback(reference)
        if resolved is None or not self._contains(*resolved):
            return {"found": False}
        return {
            "found": True,
            "record_type": resolved[0],
            "record_id": resolved[1],
            "anchor_ref": f"{resolved[0]}:{resolved[1]}",
        }

    def read_projection(self, anchor_ref: str, projection_name: str) -> Mapping[str, Any]:
        arguments: dict[str, object] = {
            "anchor_ref": anchor_ref,
            "projection_name": projection_name,
        }
        self._authorize("read_projection", arguments)
        callback = getattr(self._inner, "resolve_reference", None)
        resolved = callback(anchor_ref) if callback is not None else None
        expected_type = {
            "case": "reliability_case",
            "verification": "verification_run",
        }.get(projection_name, projection_name)
        if resolved is None or resolved[0] != expected_type or not self._contains(*resolved):
            return {"addressable": False}
        value = self._inner.read(*resolved)
        return {"addressable": value is not None, "projection": value}

    def list_prior_incidents(
        self,
        *,
        service_key: str,
        window_start: datetime | None,
        window_end: datetime | None,
    ) -> Sequence[Mapping[str, Any]]:
        arguments: dict[str, object] = {
            "service_key": service_key,
            "window_start": window_start,
            "window_end": window_end,
        }
        self._authorize("list_prior_incidents", arguments)
        callback = getattr(self._inner, "list_prior_incidents", None)
        if callback is None:
            return ()
        return cast(
            Sequence[Mapping[str, Any]],
            callback(
                service_key=service_key,
                window_start=window_start,
                window_end=window_end,
                authorized_records=self._authorized_records(),
            ),
        )

    def search_records(
        self,
        *,
        service_key: str | None,
        state: str | None,
        window_start: datetime | None,
        window_end: datetime | None,
        record_type: str | None,
    ) -> Sequence[Mapping[str, Any]]:
        arguments: dict[str, object] = {
            "service_key": service_key,
            "state": state,
            "window_start": window_start,
            "window_end": window_end,
            "record_type": record_type,
        }
        self._authorize("search_records", arguments)
        callback = getattr(self._inner, "search_records", None)
        if callback is None:
            return ()
        return cast(
            Sequence[Mapping[str, Any]],
            callback(
                service_key=service_key,
                state=state,
                window_start=window_start,
                window_end=window_end,
                record_type=record_type,
                authorized_records=self._authorized_records(),
            ),
        )

    def catch_up(self, *, anchor_ref: str, cursor: str | None) -> Mapping[str, Any]:
        arguments: dict[str, object] = {"anchor_ref": anchor_ref, "cursor": cursor}
        self._authorize("catch_up", arguments)
        if anchor_ref != self._grant.anchor_label:
            return {"available": False, "reason": "outside_bound_anchor"}
        callback = getattr(self._inner, "catch_up", None)
        resolve = getattr(self._inner, "resolve_reference", None)
        resolved = resolve(anchor_ref) if resolve is not None else None
        if callback is None or resolved is None:
            return {"available": False, "reason": "durable_event_reader_unavailable"}
        from solvan.application.liaison.anchors import Anchor

        return cast(
            Mapping[str, Any],
            callback(
                scope=self._grant.scope,
                anchor=Anchor.record(*resolved),
                cursor=cursor,
                authorized_records=self._authorized_records(),
                policy_epoch=self._grant.policy_epoch,
            ),
        )

    def recall_memory(self, *, anchor_ref: str, purpose: str) -> Sequence[Mapping[str, Any]]:
        arguments: dict[str, object] = {"anchor_ref": anchor_ref, "purpose": purpose}
        self._authorize("recall_memory", arguments)
        if anchor_ref != self._grant.anchor_label:
            return ()
        callback = getattr(self._inner, "recall_memory", None)
        if callback is None:
            return ()
        return cast(
            Sequence[Mapping[str, Any]],
            callback(
                scope=self._grant.scope,
                authorized_records=self._authorized_records(),
                classification_ceiling=self._grant.classification_ceiling,
            ),
        )

    def recall_conversation(
        self,
        *,
        anchor_ref: str,
        purpose: str,
        limit: int = 20,
        page_token: str | None = None,
    ) -> Sequence[Mapping[str, Any]]:
        """Return reader-filtered typed references to prior conversation parts."""

        arguments: dict[str, object] = {
            "anchor_ref": anchor_ref,
            "purpose": purpose,
            "limit": limit,
            "page_token": page_token,
        }
        self._authorize("recall_conversation", arguments)
        if anchor_ref != self._grant.anchor_label:
            return ()
        callback = getattr(self._inner, "recall_conversation", None)
        resolve = getattr(self._inner, "resolve_reference", None)
        if callback is None:
            return ()
        from solvan.application.liaison.anchors import Anchor

        resolved = resolve(anchor_ref) if resolve is not None else None
        anchor = Anchor.scope() if anchor_ref == "scope" else None
        if resolved is not None:
            anchor = Anchor.record(*resolved)
        if anchor is None:
            return ()
        return cast(
            Sequence[Mapping[str, Any]],
            callback(
                scope=self._grant.scope,
                anchor=anchor,
                reader_principal=self._grant.principal,
                authorized_records=self._authorized_records(),
                limit=max(1, min(limit, 20)),
                page_token=page_token,
            ),
        )
