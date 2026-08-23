"""Daily history behind the Overview's stat tiles.

A stat tile is label, value, delta and trend. The console carried only the
first two because nothing recorded what any figure had been, and a delta
computed from a window nobody observed is the invention the design system
forbids everywhere else.

Nothing new is stored to fix that. Every figure here is reconstructed from
records that were already durable: an incident's `detected_at` and its
transitions, a Reliability Case's `created_at` and its terminal reason. The
state machine's own terminal set decides what "open" means, read from
`specs/artifacts/incident-transitions.yaml` rather than restated here, so the
console cannot drift from the machine it reports on.

The reconstruction is exact rather than sampled: an incident counts at a day
boundary if it had been detected by then and its state as of then — the target
of its last transition at or before that instant — is one this tile counts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

#: Twelve points is the trend length the stat-tile contract asks for, and the
#: delta names the same period so the two describe one window.
TREND_DAYS = 12


def day_boundaries(now: datetime) -> list[datetime]:
    """The instants the trend is sampled at, oldest first, ending at `now`."""
    midnight = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    earlier = [midnight - timedelta(days=offset) for offset in range(TREND_DAYS - 1, 0, -1)]
    return [*earlier, now.astimezone(UTC)]


def state_at(
    detected_at: datetime,
    initial_state: str,
    transitions: list[tuple[datetime, str, str]],
    instant: datetime,
) -> str | None:
    """The incident's state at `instant`, or None if it did not exist yet.

    Transitions arrive oldest first. The state is the target of the last one at
    or before the instant; with none, the incident is still in the state it was
    detected in.
    """
    if detected_at > instant:
        return None
    state = initial_state
    for occurred_at, to_state, _from_state in transitions:
        if occurred_at > instant:
            break
        state = to_state
    return state


def counts_over_time(
    *,
    incidents: list[dict[str, Any]],
    transitions_by_incident: dict[str, list[tuple[datetime, str, str]]],
    cases: list[dict[str, Any]],
    active_states: tuple[str, ...],
    mitigated_states: set[str],
    now: datetime,
) -> dict[str, list[int]]:
    """One series per tile, oldest first, the last point being now."""
    boundaries = day_boundaries(now)
    series: dict[str, list[int]] = {
        "open_incidents": [],
        "reliability_cases": [],
        "awaiting_approval": [],
        "verified_mitigations": [],
    }
    for instant in boundaries:
        open_count = 0
        awaiting = 0
        mitigated = 0
        for incident in incidents:
            # The seed is the source of the first transition, which is the state
            # the incident was detected in. An incident that never moved is
            # still in its current state, so that is the seed instead. Using the
            # current state unconditionally would make every historical point
            # report today's answer.
            transitions = transitions_by_incident.get(str(incident["id"]), [])
            initial = transitions[0][2] if transitions else str(incident["state"])
            state = state_at(incident["detected_at"], initial, transitions, instant)
            if state is None:
                continue
            if state in active_states:
                open_count += 1
            if state == "AWAITING_APPROVAL":
                awaiting += 1
            if state in mitigated_states:
                mitigated += 1
        series["open_incidents"].append(open_count)
        series["awaiting_approval"].append(awaiting)
        series["verified_mitigations"].append(mitigated)
        series["reliability_cases"].append(
            sum(1 for case in cases if case["created_at"] <= instant)
        )
    return series


def tile(label: str, detail: str, points: list[int], value: int) -> dict[str, Any]:
    """A stat tile: the figure now, the change against the trend's start, the trend.

    `value` is the authoritative count taken from the records themselves, not
    the reconstruction's last point. The two should agree, and where they cannot
    — a state written without a transition, a transition recorded between the
    two reads — the authoritative count wins, so the tile can never contradict
    the list on the next screen. The trend's final point is set to it for the
    same reason.

    The delta names its period, because a signed number with no window is not a
    fact about anything. A flat trend is still reported: it says the figure did
    not move, which is different from having nothing to say.
    """
    trend = [*points[:-1], value] if points else [value]
    return {
        "label": label,
        "value": str(value),
        "detail": detail,
        "delta": value - trend[0],
        "delta_period": f"{TREND_DAYS} days",
        "trend": trend,
    }
