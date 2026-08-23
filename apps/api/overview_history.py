"""What is behind the Overview's stat tiles: history, counts, and captions.

A stat tile is label, value, delta, trend and caption. The console carried only
the first two because nothing recorded what any figure had been, and a delta
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

The caption obeys the same rule. It sits under the figure and reads as part of
it, so an operator takes it for a second measurement, and it used to be a
hand-written adjective — "durable", "exact", "stored". Each caption is now read
from the same records the figure counts, and where the records cannot support
the claim the caption says which fact is missing rather than quoting a
different clock under this one's name. `overview_tiles` is the only way to
build a tile row, so there is no parameter through which a written caption can
reach a tile.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

#: Twelve points is the trend length the stat-tile contract asks for, and the
#: delta names the same period so the two describe one window.
TREND_DAYS = 12

#: Worst first, so a severity composition reads the way the queue is sorted.
_SEVERITY_ORDER = ("SEV1", "SEV2", "SEV3", "SEV4")


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


@dataclass(frozen=True, slots=True)
class TileDetail:
    """A caption a tile is allowed to carry.

    `tile()` takes this rather than `str`, so the four `*_detail` functions
    below are the only things that can produce one and a hand-written adjective
    cannot reach a tile by accident. The wrapper is the whole point: the text
    inside it is worthless as a guarantee, and the type is the guarantee.
    """

    text: str


def elapsed(since: datetime, until: datetime) -> str:
    """A duration in the console's one duration vocabulary: s, m, h, d.

    Captions are relative rather than absolute because a wall-clock time with
    no date is ambiguous the moment the instant is more than a day away, and a
    tile row is a right-now surface with no room for a date.
    """
    seconds = max(0, int((until - since).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86_400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86_400}d"


def _severity_rank(name: str) -> int:
    return _SEVERITY_ORDER.index(name) if name in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def open_incidents_detail(incidents: Sequence[Mapping[str, Any]]) -> TileDetail:
    """The severity composition of the incidents this tile counted.

    Four open incidents is a different morning depending on whether one of them
    is a SEV1, and the severity is already on every row the count read. A
    severity outside the enumerated set is still listed, last, rather than
    dropped: a composition that does not sum to the figure above it is worse
    than an unfamiliar word.
    """
    counts = Counter(str(incident["severity"]) for incident in incidents)
    if not counts:
        return TileDetail("none open")
    ordered = sorted(counts, key=lambda name: (_severity_rank(name), name))
    return TileDetail(" · ".join(f"{counts[name]} {name}" for name in ordered))


def reliability_cases_detail(cases: Sequence[Mapping[str, Any]], now: datetime) -> TileDetail:
    """When the earliest scheduled wake-up is due, or that none is.

    A Reliability Case is a thing that sleeps, so the second useful fact about a
    pile of them is when the pile next wakes. An overdue wake-up is named as
    overdue rather than folded into the same sentence: a case that should have
    woken and did not is a different situation from one that is waiting.
    """
    if not cases:
        return TileDetail("none open")
    wakeups = [case["next_action_at"] for case in cases if case["next_action_at"] is not None]
    if not wakeups:
        return TileDetail("no wake-up scheduled")
    earliest = min(wakeups)
    if earliest <= now:
        return TileDetail(f"wake-up {elapsed(earliest, now)} overdue")
    return TileDetail(f"next wake-up in {elapsed(now, earliest)}")


def awaiting_approval_detail(
    incidents: Sequence[Mapping[str, Any]],
    transitions_by_incident: Mapping[str, Sequence[tuple[datetime, str, str]]],
    now: datetime,
) -> TileDetail:
    """How long the longest-waiting approval has been waiting.

    Read from the transition into `AWAITING_APPROVAL`, never from `detected_at`:
    an incident detected yesterday may have reached the approval gate a minute
    ago, and quoting the older clock under this caption would invent an urgency
    the records do not carry. An approval can be denied and re-requested, so the
    current wait began at the *last* entry into the gate, not the first.

    "Oldest" is a claim about every waiting incident, so it is withheld unless
    every one of them carries the transition that would prove it.
    """
    waiting = [incident for incident in incidents if str(incident["state"]) == "AWAITING_APPROVAL"]
    if not waiting:
        return TileDetail("none waiting")
    entered = [
        max(moves)
        for incident in waiting
        if (
            moves := [
                occurred_at
                for occurred_at, to_state, _from_state in transitions_by_incident.get(
                    str(incident["id"]), ()
                )
                if to_state == "AWAITING_APPROVAL"
            ]
        )
    ]
    if len(entered) != len(waiting):
        return TileDetail("wait time not recorded")
    return TileDetail(f"oldest waiting {elapsed(min(entered), now)}")


def verified_mitigations_detail(
    incidents: Sequence[Mapping[str, Any]],
    transitions_by_incident: Mapping[str, Sequence[tuple[datetime, str, str]]],
    mitigated_states: set[str],
    now: datetime,
) -> TileDetail:
    """When the most recent mitigation passed verification.

    `MITIGATED` is reachable only by `VERIFICATION_PASSED`, and `RESOLVED` only
    from `MITIGATED`, so the entry into `MITIGATED` is the instant verification
    passed — for a resolved incident too, whose later closure is a different
    event with a different time. Reading the entry into `RESOLVED` would date
    the verification to the paperwork.

    "Last" is a claim about every counted incident, so it is withheld unless
    every one of them carries that transition: the one that is missing could be
    the most recent.
    """
    counted = [incident for incident in incidents if str(incident["state"]) in mitigated_states]
    if not counted:
        return TileDetail("none verified")
    verified = [
        max(moves)
        for incident in counted
        if (
            moves := [
                occurred_at
                for occurred_at, to_state, _from_state in transitions_by_incident.get(
                    str(incident["id"]), ()
                )
                if to_state == "MITIGATED"
            ]
        )
    ]
    if len(verified) != len(counted):
        return TileDetail("verification time not recorded")
    return TileDetail(f"last verified {elapsed(max(verified), now)} ago")


def overview_tiles(
    *,
    incidents: list[dict[str, Any]],
    transitions_by_incident: dict[str, list[tuple[datetime, str, str]]],
    cases: list[dict[str, Any]],
    active_states: tuple[str, ...],
    mitigated_states: set[str],
    now: datetime,
) -> list[dict[str, Any]]:
    """The Overview's four stat tiles, every part of each read from a record.

    The counts are taken from the rows rather than from the reconstruction, and
    the captions from the same rows, so a tile's figure and its caption are two
    readings of one set of records at one instant. Callers pass records and get
    tiles; there is deliberately no seam where a label, a figure, or a caption
    can be supplied by hand.
    """
    history = counts_over_time(
        incidents=incidents,
        transitions_by_incident=transitions_by_incident,
        cases=cases,
        active_states=active_states,
        mitigated_states=mitigated_states,
        now=now,
    )
    open_incidents = [incident for incident in incidents if str(incident["state"]) in active_states]
    return [
        tile(
            "Open incidents",
            open_incidents_detail(open_incidents),
            history["open_incidents"],
            len(open_incidents),
        ),
        tile(
            "Reliability Cases",
            reliability_cases_detail(cases, now),
            history["reliability_cases"],
            len(cases),
        ),
        tile(
            "Awaiting approval",
            awaiting_approval_detail(incidents, transitions_by_incident, now),
            history["awaiting_approval"],
            sum(str(incident["state"]) == "AWAITING_APPROVAL" for incident in incidents),
        ),
        tile(
            "Verified mitigations",
            verified_mitigations_detail(incidents, transitions_by_incident, mitigated_states, now),
            history["verified_mitigations"],
            sum(str(incident["state"]) in mitigated_states for incident in incidents),
        ),
    ]


def tile(label: str, detail: TileDetail, points: list[int], value: int) -> dict[str, Any]:
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
        "detail": detail.text,
        "delta": value - trend[0],
        "delta_period": f"{TREND_DAYS} days",
        "trend": trend,
    }
