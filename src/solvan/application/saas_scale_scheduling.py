"""Bounded tenant-first scheduling for the SaaS target profile."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from solvan.application.saas_scale import ScaleRuntimeError


@dataclass(slots=True)
class SchedulerItem:
    organization_id: str
    payload: Any
    cost: int = 1
    work_class: str = "INTERACTIVE_ASK"
    tenant_sequence: int = 0
    enqueued_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.organization_id:
            raise ValueError("scheduler item requires an organization")
        if self.cost <= 0:
            raise ValueError("scheduler item cost must be positive")
        if self.work_class not in {
            "CONTROL_RECONCILIATION",
            "SECURITY",
            "RECONCILIATION",
            "DELETION",
            "OPEN_SEVERE",
            "OPEN_OTHER",
            "INTERACTIVE_ASK",
            "BACKGROUND",
        }:
            raise ValueError("scheduler item names an unknown workload class")
        if self.tenant_sequence < 0:
            raise ValueError("tenant sequence cannot be negative")
        if self.enqueued_at is not None and (
            self.enqueued_at.tzinfo is None or self.enqueued_at.utcoffset() is None
        ):
            raise ValueError("scheduler enqueue time must be timezone-aware")


class DeficitRoundRobinScheduler:
    """Tenant-first bounded DRR with a structurally separate control lane."""

    _CONTROL_CLASSES: ClassVar[frozenset[str]] = frozenset(
        {"CONTROL_RECONCILIATION", "SECURITY", "RECONCILIATION", "DELETION"}
    )
    _CLASS_ORDER: ClassVar[dict[str, int]] = {
        "CONTROL_RECONCILIATION": 0,
        "SECURITY": 0,
        "RECONCILIATION": 0,
        "DELETION": 0,
        "OPEN_SEVERE": 1,
        "OPEN_OTHER": 2,
        "INTERACTIVE_ASK": 3,
        "BACKGROUND": 4,
    }

    def __init__(
        self,
        *,
        assured_share: dict[str, int],
        control_reserve: int = 1,
        base_quantum: int = 1,
        max_deficit: int = 100,
        maximum_wait_seconds: int = 0,
    ) -> None:
        if any(value <= 0 for value in assured_share.values()):
            raise ValueError("scheduler shares must be positive")
        if control_reserve < 0 or base_quantum <= 0 or max_deficit < base_quantum:
            raise ValueError("scheduler reserve and DRR bounds are invalid")
        if maximum_wait_seconds < 0:
            raise ValueError("scheduler maximum wait cannot be negative")
        self._weights = dict(assured_share)
        self._queues: dict[str, list[SchedulerItem]] = {key: [] for key in assured_share}
        # Deficit is per tenant *and per lane*. One shared counter let the two
        # lanes spend and clear each other's credit: a poll of the empty
        # control lane zeroed the deficit a tenant had accumulated waiting for
        # ordinary service, and a control item's cost came out of the same
        # purse — which is the fairness this scheduler exists to provide.
        self._deficit: defaultdict[tuple[str, bool], int] = defaultdict(int)
        self._cursor = 0
        self._control_reserve = control_reserve
        self._base_quantum = base_quantum
        self._max_deficit = max_deficit
        self._maximum_wait = maximum_wait_seconds
        self._next_sequence = 1

    def enqueue(self, item: SchedulerItem, *, now: datetime | None = None) -> None:
        if item.organization_id not in self._queues:
            raise ScaleRuntimeError("tenant is not admitted to this scheduler")
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("scheduler enqueue time must be timezone-aware")
        if item.enqueued_at is None:
            item.enqueued_at = moment
        if item.tenant_sequence == 0:
            item.tenant_sequence = self._next_sequence
            self._next_sequence += 1
        self._queues[item.organization_id].append(item)

    def _item_for_lane(
        self, queue: list[SchedulerItem], *, control: bool, now: datetime
    ) -> SchedulerItem | None:
        candidates = [
            item
            for item in queue
            if (item.work_class in self._CONTROL_CLASSES) is control
            and (not control or item.work_class in self._CONTROL_CLASSES)
        ]
        if not candidates:
            return None
        aged = [
            item
            for item in candidates
            if self._maximum_wait
            and item.enqueued_at is not None
            and (now - item.enqueued_at).total_seconds() >= self._maximum_wait
        ]
        if aged:
            return min(aged, key=lambda item: item.tenant_sequence)
        return min(
            candidates,
            key=lambda item: (self._CLASS_ORDER[item.work_class], item.tenant_sequence),
        )

    def pop(self, *, control: bool = False, now: datetime | None = None) -> SchedulerItem | None:
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("scheduler pop time must be timezone-aware")
        keys = tuple(self._queues)
        if not keys:
            return None
        for _ in range(len(keys)):
            key = keys[self._cursor % len(keys)]
            self._cursor = (self._cursor + 1) % len(keys)
            lane = (key, control)
            item = self._item_for_lane(self._queues[key], control=control, now=moment)
            if item is None:
                # An idle lane banks nothing; the tenant's other lane keeps
                # whatever it has earned.
                self._deficit[lane] = 0
                continue
            self._deficit[lane] = min(
                self._max_deficit,
                self._deficit[lane] + self._base_quantum * self._weights[key],
            )
            if item.cost > self._deficit[lane]:
                continue
            self._queues[key].remove(item)
            self._deficit[lane] -= item.cost
            return item
        return None

    @property
    def control_reserve(self) -> int:
        return self._control_reserve
