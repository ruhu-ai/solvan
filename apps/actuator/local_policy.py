"""Customer-side controls that hold when Solvan is unreachable or wrong.

The kill switch and the action budget are evaluated control-plane side too, but
a control that only exists in Solvan's database protects nobody from Solvan: a
compromised or malfunctioning control plane would simply not consult it, and a
partitioned one could not. These are therefore enforced inside the actuator
binary, before any mutation connector is constructed, from configuration the
actuator reads directly.

Both fail closed. An unparsable budget refuses rather than defaulting to
unlimited, and an unreadable kill-switch file refuses rather than assuming the
switch is open.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

#: Engaging the switch is a customer act. The file's *presence* engages it, so
#: an operator with filesystem access can stop production mutation without
#: reaching Solvan, and a deleted or unreadable path never reads as "open".
KILL_SWITCH_VARIABLE = "SOLVAN_ACTUATOR_KILL_SWITCH_FILE"
BUDGET_VARIABLE = "SOLVAN_ACTUATOR_MAX_MUTATIONS_PER_HOUR"
_WINDOW_SECONDS = 3600.0

#: The closed set of reason codes this binary can refuse with. The alert filters
#: in `infra/terraform/environments/gcp/alerting.tf` are bound to these strings,
#: so a new code that is not recorded here would refuse in silence. A test
#: reads the raise sites below and fails when the two disagree.
LOCAL_POLICY_REASON_CODES = frozenset(
    {
        "LOCAL_KILL_SWITCH_UNCONFIGURED",
        "LOCAL_KILL_SWITCH_UNREADABLE",
        "LOCAL_KILL_SWITCH_ENGAGED",
        "LOCAL_BUDGET_UNCONFIGURED",
        "LOCAL_BUDGET_INVALID",
        "LOCAL_RATE_BUDGET_EXHAUSTED",
    }
)


class LocalPolicyRefusal(Exception):
    """A local control refused this mutation."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class LocalPolicyDecision:
    reason_code: str
    detail: str


class ActionRateBudget:
    """A fixed-window-free sliding budget over recent mutations.

    In-process state is deliberate: the budget bounds what *this* actuator
    instance can do. It is a blast-radius ceiling, not a distributed quota, and
    it must keep working when the control plane cannot be consulted.
    """

    def __init__(self, limit: int, *, window_seconds: float = _WINDOW_SECONDS) -> None:
        self._limit = limit
        self._window = window_seconds
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    def claim(self, *, now: float | None = None) -> None:
        """Record one mutation, or refuse when the budget is exhausted."""

        moment = time.monotonic() if now is None else now
        with self._lock:
            while self._events and moment - self._events[0] >= self._window:
                self._events.popleft()
            if len(self._events) >= self._limit:
                raise LocalPolicyRefusal(
                    "LOCAL_RATE_BUDGET_EXHAUSTED",
                    f"local actuator budget of {self._limit} mutations per hour is exhausted",
                )
            self._events.append(moment)


def read_budget_limit(environ: dict[str, str] | None = None) -> int:
    """Parse the configured hourly ceiling, refusing anything unusable."""

    source = os.environ if environ is None else environ
    raw = source.get(BUDGET_VARIABLE)
    if raw is None or not raw.strip():
        raise LocalPolicyRefusal(
            "LOCAL_BUDGET_UNCONFIGURED",
            f"{BUDGET_VARIABLE} is not configured; the actuator refuses to mutate",
        )
    try:
        limit = int(raw.strip())
    except ValueError as error:
        raise LocalPolicyRefusal(
            "LOCAL_BUDGET_INVALID",
            f"{BUDGET_VARIABLE} is not an integer; the actuator refuses to mutate",
        ) from error
    if limit < 1:
        raise LocalPolicyRefusal(
            "LOCAL_BUDGET_INVALID",
            f"{BUDGET_VARIABLE} must be at least 1; the actuator refuses to mutate",
        )
    return limit


def check_kill_switch(environ: dict[str, str] | None = None) -> None:
    """Refuse when the local kill switch is engaged or cannot be read.

    On Cloud Run the path is a read-only GCS FUSE mount of the
    actuator-controls bucket, so engaging is one object write by a release
    approver and the actuator can never delete its own switch. Before that
    volume existed the check was real in code and unreachable in the deployed
    topology -- no way to make the file exist in a running container.
    Presence engages; a deleted or unmounted directory reads as absent or
    unreadable, and unreadable refuses.
    """

    source = os.environ if environ is None else environ
    configured = source.get(KILL_SWITCH_VARIABLE)
    if configured is None or not configured.strip():
        raise LocalPolicyRefusal(
            "LOCAL_KILL_SWITCH_UNCONFIGURED",
            f"{KILL_SWITCH_VARIABLE} is not configured; the actuator refuses to mutate",
        )
    path = Path(configured.strip())
    try:
        engaged = path.exists()
    except OSError as error:
        raise LocalPolicyRefusal(
            "LOCAL_KILL_SWITCH_UNREADABLE",
            "the local kill-switch path cannot be read; the actuator refuses to mutate",
        ) from error
    if engaged:
        raise LocalPolicyRefusal(
            "LOCAL_KILL_SWITCH_ENGAGED",
            "the local kill switch is engaged; this actuator will not mutate production",
        )
