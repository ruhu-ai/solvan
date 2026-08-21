"""Content-free SaaS event wake-ups and fenced cursor recovery.

The deployed shared-cell implementation uses Cloud SQL for the event feed and
Pub/Sub only for wake-ups.  This module is the provider-independent seam used
by the local harness and target tests: it never stores event payloads, trusts
delivery order, or lets a stale cursor cross a placement, policy, or
membership epoch.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from solvan.application.saas_scale import ScaleRuntimeError
from solvan.application.saas_scale_runtime import SequencedEvent


class CursorRecoveryRequired(ScaleRuntimeError):
    """The caller must reacquire a verified cursor from authoritative SQL."""


class PoisonEventBlocked(ScaleRuntimeError):
    """A quarantined event prevents the scope cursor from advancing."""


@dataclass(frozen=True, slots=True)
class EventCursor:
    """A reader cursor bound to the exact cell and policy epochs."""

    cell_id: str
    placement_epoch: int
    scope_sequence: int
    policy_epoch: int
    membership_epoch: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.cell_id:
            raise ValueError("cursor cell is required")
        if self.placement_epoch < 1 or self.policy_epoch < 1 or self.membership_epoch < 1:
            raise ValueError("cursor epochs must be positive")
        if self.scope_sequence < 0 or self.schema_version != 1:
            raise ValueError("cursor sequence or schema version is invalid")


@dataclass(frozen=True, slots=True)
class ContentFreeWakeup:
    """A Pub/Sub-shaped notification that carries no transcript or payload."""

    cell_id: str
    placement_epoch: int
    scope_key_hash: str
    from_sequence: int
    to_sequence: int
    emitted_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.cell_id or not self.scope_key_hash.startswith("sha256:"):
            raise ValueError("wakeup identity must be typed")
        if len(self.scope_key_hash) != 71:
            raise ValueError("wakeup scope hash is invalid")
        if self.placement_epoch < 1 or self.from_sequence < 0:
            raise ValueError("wakeup placement or lower bound is invalid")
        if self.to_sequence < self.from_sequence or self.schema_version != 1:
            raise ValueError("wakeup sequence interval is invalid")
        if self.emitted_at.tzinfo is None or self.emitted_at.utcoffset() is None:
            raise ValueError("wakeup time must be timezone-aware")


@dataclass(frozen=True, slots=True)
class EventPage:
    """A bounded page or an explicit slow-consumer recovery decision."""

    events: tuple[SequencedEvent, ...]
    next_cursor: EventCursor
    overflow: bool = False
    recovery_reason: str | None = None

    def __post_init__(self) -> None:
        if self.overflow and (self.events or self.next_cursor.scope_sequence < 0):
            raise ValueError("an overflow page cannot advance or carry events")
        if self.overflow and not self.recovery_reason:
            raise ValueError("overflow must name a recovery reason")
        if not self.overflow and self.recovery_reason is not None:
            raise ValueError("ordinary pages cannot carry a recovery reason")


class ContentFreeEventFanout:
    """Authoritative-sequence reader with content-free wake-up fan-out.

    ``publish`` is intentionally idempotent.  A duplicate Pub/Sub wake-up
    cannot duplicate an event, and a caller must still read from this
    sequence-backed store.  A quarantined event blocks all later cursor
    advancement until the explicit supersession path has cleared it.
    """

    def __init__(
        self,
        *,
        cell_id: str,
        placement_epoch: int,
        policy_epoch: int,
        membership_epoch: int,
        buffer_ceiling: int = 100,
        now: datetime | None = None,
    ) -> None:
        if not cell_id or placement_epoch < 1 or policy_epoch < 1 or membership_epoch < 1:
            raise ValueError("fan-out binding is invalid")
        if buffer_ceiling < 1:
            raise ValueError("fan-out buffer ceiling must be positive")
        self.cell_id = cell_id
        self.placement_epoch = placement_epoch
        self.policy_epoch = policy_epoch
        self.membership_epoch = membership_epoch
        self.buffer_ceiling = buffer_ceiling
        self._now = now or datetime.now(UTC)
        self._events: dict[str, SequencedEvent] = {}
        self._wakeups: dict[tuple[int, int], ContentFreeWakeup] = {}

    @property
    def wakeups(self) -> tuple[ContentFreeWakeup, ...]:
        """Return only content-free notifications, in emission order."""

        return tuple(self._wakeups.values())

    def publish(self, events: Iterable[SequencedEvent]) -> ContentFreeWakeup | None:
        """Publish already-sequenced events and emit one idempotent wake-up."""

        batch = tuple(events)
        if not batch:
            return None
        first_scope = _scope_key_hash(batch[0])
        for event in batch:
            if event.placement_epoch != self.placement_epoch:
                raise ScaleRuntimeError("event placement epoch is stale")
            if event.state not in {"SEQUENCED", "QUARANTINED"} or event.scope_sequence is None:
                raise ScaleRuntimeError("fan-out accepts only sequenced or quarantined events")
            if _scope_key_hash(event) != first_scope:
                raise ScaleRuntimeError("fan-out batch crosses scope boundaries")
            if event.event_id in self._events:
                existing = self._events[event.event_id]
                if existing.event_hash != event.event_hash:
                    raise ScaleRuntimeError("event id was reused with a different payload")
                continue
            self._events[event.event_id] = event
        lower = min(event.scope_sequence for event in batch if event.scope_sequence is not None)
        upper = max(event.scope_sequence for event in batch if event.scope_sequence is not None)
        scope_key_hash = first_scope
        key = (lower, upper)
        existing_wakeup = self._wakeups.get(key)
        if existing_wakeup is not None:
            return existing_wakeup
        wakeup = ContentFreeWakeup(
            cell_id=self.cell_id,
            placement_epoch=self.placement_epoch,
            scope_key_hash=scope_key_hash,
            from_sequence=lower,
            to_sequence=upper,
            emitted_at=self._now,
        )
        self._wakeups[key] = wakeup
        return wakeup

    def read(
        self,
        cursor: EventCursor,
        *,
        limit: int,
        current_cell_id: str,
        current_placement_epoch: int,
        current_policy_epoch: int,
        current_membership_epoch: int,
    ) -> EventPage:
        """Read authoritative rows; Pub/Sub order is never consulted."""

        if limit < 1:
            raise ValueError("event page limit must be positive")
        self._validate_cursor(
            cursor,
            current_cell_id=current_cell_id,
            current_placement_epoch=current_placement_epoch,
            current_policy_epoch=current_policy_epoch,
            current_membership_epoch=current_membership_epoch,
        )
        poisoned = next(
            (
                event
                for event in self._events.values()
                if event.state == "QUARANTINED"
                and (event.scope_sequence is None or event.scope_sequence > cursor.scope_sequence)
            ),
            None,
        )
        if poisoned is not None:
            raise PoisonEventBlocked("quarantined event blocks cursor advancement")
        candidates = sorted(
            (
                event
                for event in self._events.values()
                if event.state == "SEQUENCED"
                and event.scope_sequence is not None
                and event.scope_sequence > cursor.scope_sequence
            ),
            key=lambda event: (event.scope_sequence or 0, event.event_id),
        )
        if len(candidates) > self.buffer_ceiling:
            return EventPage(
                events=(),
                next_cursor=cursor,
                overflow=True,
                recovery_reason="SLOW_CONSUMER_CURSOR_RECOVERY",
            )
        page = tuple(candidates[:limit])
        next_sequence = page[-1].scope_sequence if page else cursor.scope_sequence
        assert next_sequence is not None
        return EventPage(
            events=page,
            next_cursor=EventCursor(
                cell_id=cursor.cell_id,
                placement_epoch=cursor.placement_epoch,
                scope_sequence=next_sequence,
                policy_epoch=cursor.policy_epoch,
                membership_epoch=cursor.membership_epoch,
            ),
        )

    def recover_cursor(
        self,
        cursor: EventCursor,
        *,
        cell_id: str,
        placement_epoch: int,
        policy_epoch: int,
        membership_epoch: int,
        verified_high_water: int,
        receipt_hash: str,
    ) -> EventCursor:
        """Create a new cursor only from an explicit verified high-water mark."""

        if not receipt_hash.startswith("sha256:") or len(receipt_hash) != 71:
            raise ValueError("cursor recovery requires a typed receipt")
        if verified_high_water < 0:
            raise ValueError("verified high-water must be non-negative")
        if cell_id != self.cell_id or placement_epoch != self.placement_epoch:
            raise CursorRecoveryRequired("recovery target is not the current cell epoch")
        if policy_epoch != self.policy_epoch or membership_epoch != self.membership_epoch:
            raise CursorRecoveryRequired("recovery target policy or membership is stale")
        if verified_high_water > max(
            (event.scope_sequence or 0 for event in self._events.values()), default=0
        ):
            raise CursorRecoveryRequired("verified high-water exceeds authoritative feed")
        return EventCursor(
            cell_id=cell_id,
            placement_epoch=placement_epoch,
            scope_sequence=verified_high_water,
            policy_epoch=policy_epoch,
            membership_epoch=membership_epoch,
        )

    def _validate_cursor(
        self,
        cursor: EventCursor,
        *,
        current_cell_id: str,
        current_placement_epoch: int,
        current_policy_epoch: int,
        current_membership_epoch: int,
    ) -> None:
        if cursor.cell_id != current_cell_id or cursor.cell_id != self.cell_id:
            raise CursorRecoveryRequired("cursor cell is stale")
        if (
            cursor.placement_epoch != current_placement_epoch
            or cursor.placement_epoch != self.placement_epoch
        ):
            raise CursorRecoveryRequired("cursor placement epoch is stale")
        if cursor.policy_epoch != current_policy_epoch or cursor.policy_epoch != self.policy_epoch:
            raise CursorRecoveryRequired("cursor policy epoch is stale")
        if (
            cursor.membership_epoch != current_membership_epoch
            or cursor.membership_epoch != self.membership_epoch
        ):
            raise CursorRecoveryRequired("cursor membership epoch is stale")


def _scope_key_hash(event: SequencedEvent) -> str:
    canonical = "|".join((event.organization_id, event.project_id, event.environment_id))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
