"""The Overview's stat tiles reconstruct history rather than assert it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apps.api.overview_history import (
    TREND_DAYS,
    counts_over_time,
    day_boundaries,
    state_at,
    tile,
)

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def test_the_trend_ends_at_now_and_spans_the_period_the_delta_names() -> None:
    boundaries = day_boundaries(NOW)
    assert len(boundaries) == TREND_DAYS
    assert boundaries[-1] == NOW
    assert boundaries == sorted(boundaries)
    assert (NOW - boundaries[0]).days == TREND_DAYS - 1


def test_an_incident_does_not_exist_before_it_was_detected() -> None:
    """Counting it earlier would report a figure nobody could have seen."""
    assert state_at(NOW, "DETECTED", [], NOW - timedelta(days=1)) is None
    assert state_at(NOW - timedelta(days=1), "DETECTED", [], NOW) == "DETECTED"


def test_the_state_is_the_last_transition_at_or_before_the_instant() -> None:
    transitions = [
        (NOW - timedelta(days=5), "INVESTIGATING", "DETECTED"),
        (NOW - timedelta(days=2), "RESOLVED", "VERIFYING_MITIGATION"),
    ]
    detected = NOW - timedelta(days=6)
    assert state_at(detected, "DETECTED", transitions, NOW - timedelta(days=6)) == "DETECTED"
    assert state_at(detected, "DETECTED", transitions, NOW - timedelta(days=3)) == "INVESTIGATING"
    assert state_at(detected, "DETECTED", transitions, NOW) == "RESOLVED"


def test_a_resolved_incident_stops_being_open_at_the_instant_it_resolved() -> None:
    """The whole point of the reconstruction.

    Seeding from the incident's current state would make every historical point
    report today's answer, and the trend would be a flat line at the present
    value — which reads as "nothing changed" rather than "we did not look".
    """
    resolved_at = NOW - timedelta(days=3)
    series = counts_over_time(
        incidents=[
            {
                "id": "inc_1",
                "state": "RESOLVED",
                "detected_at": NOW - timedelta(days=8),
            }
        ],
        transitions_by_incident={"inc_1": [(resolved_at, "RESOLVED", "MITIGATED")]},
        cases=[],
        active_states=("DETECTED", "INVESTIGATING", "MITIGATED"),
        mitigated_states={"RESOLVED"},
        now=NOW,
    )
    # Open for the days it was open, and not before it existed or after it closed.
    assert series["open_incidents"][0] == 0
    assert series["open_incidents"][5] == 1
    assert series["open_incidents"][-1] == 0
    assert series["verified_mitigations"][-1] == 1


def test_a_case_counts_from_the_day_it_was_created() -> None:
    series = counts_over_time(
        incidents=[],
        transitions_by_incident={},
        cases=[{"created_at": NOW - timedelta(days=4)}],
        active_states=(),
        mitigated_states=set(),
        now=NOW,
    )
    assert series["reliability_cases"][0] == 0
    assert series["reliability_cases"][-1] == 1


def test_a_tile_states_the_period_its_delta_is_measured_over() -> None:
    """A signed number with no window is not a fact about anything."""
    built = tile("Open incidents", "durable", [2, 3, 3, 4], 5)
    assert built["value"] == "5"
    assert built["delta"] == 3
    assert built["delta_period"] == f"{TREND_DAYS} days"
    assert built["trend"] == [2, 3, 3, 5]


def test_a_flat_trend_reports_zero_rather_than_nothing() -> None:
    """Not moving is a finding; having nothing to say is a different one."""
    built = tile("Awaiting approval", "exact", [1, 1, 1], 1)
    assert built["delta"] == 0
    assert built["trend"] == [1, 1, 1]


def test_the_authoritative_count_wins_over_the_reconstruction() -> None:
    """The tile must never contradict the list on the next screen.

    The reconstruction is derived from transitions; the count is read from the
    records. Where they cannot agree — a state written without a transition, a
    transition recorded between the two reads — the record decides.
    """
    built = tile("Open incidents", "durable", [1, 2, 9], value=3)
    assert built["value"] == "3"
    assert built["trend"][-1] == 3
    assert built["delta"] == 2
