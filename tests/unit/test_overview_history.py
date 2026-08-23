"""The Overview's stat tiles reconstruct history rather than assert it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apps.api.overview_history import (
    TREND_DAYS,
    TileDetail,
    awaiting_approval_detail,
    counts_over_time,
    day_boundaries,
    elapsed,
    open_incidents_detail,
    overview_tiles,
    reliability_cases_detail,
    state_at,
    tile,
    verified_mitigations_detail,
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
    built = tile("Open incidents", TileDetail("1 SEV2"), [2, 3, 3, 4], 5)
    assert built["value"] == "5"
    assert built["delta"] == 3
    assert built["delta_period"] == f"{TREND_DAYS} days"
    assert built["trend"] == [2, 3, 3, 5]


def test_a_flat_trend_reports_zero_rather_than_nothing() -> None:
    """Not moving is a finding; having nothing to say is a different one."""
    built = tile("Awaiting approval", TileDetail("oldest waiting 2h"), [1, 1, 1], 1)
    assert built["delta"] == 0
    assert built["trend"] == [1, 1, 1]


def test_the_authoritative_count_wins_over_the_reconstruction() -> None:
    """The tile must never contradict the list on the next screen.

    The reconstruction is derived from transitions; the count is read from the
    records. Where they cannot agree — a state written without a transition, a
    transition recorded between the two reads — the record decides.
    """
    built = tile("Open incidents", TileDetail("3 SEV3"), [1, 2, 9], value=3)
    assert built["value"] == "3"
    assert built["trend"][-1] == 3
    assert built["delta"] == 2


def test_a_caption_is_read_from_the_records_the_figure_counted() -> None:
    """Four open incidents is a different morning if one of them is a SEV1."""
    assert open_incidents_detail([{"severity": "SEV2"}]).text == "1 SEV2"
    composed = open_incidents_detail(
        [{"severity": "SEV3"}, {"severity": "SEV1"}, {"severity": "SEV3"}]
    )
    # Worst first, the way the queue is sorted.
    assert composed.text == "1 SEV1 · 2 SEV3"


def test_an_unenumerated_severity_is_listed_last_rather_than_dropped() -> None:
    """A composition that does not sum to the figure above it is the worse bug."""
    composed = open_incidents_detail([{"severity": "SEV1"}, {"severity": "SEV9"}])
    assert composed.text == "1 SEV1 · 1 SEV9"


def test_an_empty_tile_says_so_rather_than_carrying_a_stale_caption() -> None:
    assert open_incidents_detail([]).text == "none open"
    assert reliability_cases_detail([], NOW).text == "none open"
    assert awaiting_approval_detail([], {}, NOW).text == "none waiting"
    assert verified_mitigations_detail([], {}, {"MITIGATED"}, NOW).text == "none verified"


def test_the_case_caption_separates_a_pending_wake_up_from_an_overdue_one() -> None:
    """A case that should have woken and did not is not one that is waiting."""
    pending = reliability_cases_detail(
        [{"next_action_at": NOW + timedelta(hours=4)}, {"next_action_at": NOW + timedelta(days=2)}],
        NOW,
    )
    assert pending.text == "next wake-up in 4h"
    overdue = reliability_cases_detail([{"next_action_at": NOW - timedelta(minutes=20)}], NOW)
    assert overdue.text == "wake-up 20m overdue"
    assert reliability_cases_detail([{"next_action_at": None}], NOW).text == "no wake-up scheduled"


def test_the_wait_is_measured_from_the_approval_gate_not_from_detection() -> None:
    """An incident detected yesterday may have reached the gate a minute ago."""
    incidents = [{"id": "inc_1", "state": "AWAITING_APPROVAL"}]
    transitions = {
        "inc_1": [
            (NOW - timedelta(days=2), "INVESTIGATING", "DETECTED"),
            (NOW - timedelta(minutes=9), "AWAITING_APPROVAL", "MITIGATION_PROPOSED"),
        ]
    }
    assert awaiting_approval_detail(incidents, transitions, NOW).text == "oldest waiting 9m"


def test_a_re_requested_approval_is_timed_from_its_current_wait() -> None:
    """Denial returns the incident to the gate; the first wait already ended."""
    incidents = [{"id": "inc_1", "state": "AWAITING_APPROVAL"}]
    transitions = {
        "inc_1": [
            (NOW - timedelta(hours=6), "AWAITING_APPROVAL", "MITIGATION_PROPOSED"),
            (NOW - timedelta(hours=5), "MITIGATION_PROPOSED", "AWAITING_APPROVAL"),
            (NOW - timedelta(hours=1), "AWAITING_APPROVAL", "MITIGATION_PROPOSED"),
        ]
    }
    assert awaiting_approval_detail(incidents, transitions, NOW).text == "oldest waiting 1h"


def test_oldest_is_withheld_unless_every_waiting_incident_can_prove_its_wait() -> None:
    """The unrecorded one could be the oldest, so the claim is not made."""
    incidents = [
        {"id": "inc_1", "state": "AWAITING_APPROVAL"},
        {"id": "inc_2", "state": "AWAITING_APPROVAL"},
    ]
    transitions = {"inc_1": [(NOW - timedelta(hours=3), "AWAITING_APPROVAL", "MITIGATING")]}
    assert awaiting_approval_detail(incidents, transitions, NOW).text == "wait time not recorded"


def test_verification_is_dated_from_the_pass_not_from_the_later_closure() -> None:
    """`RESOLVED` is reached from `MITIGATED`; closure is the paperwork."""
    incidents = [{"id": "inc_1", "state": "RESOLVED"}]
    transitions = {
        "inc_1": [
            (NOW - timedelta(hours=5), "MITIGATED", "VERIFYING_MITIGATION"),
            (NOW - timedelta(minutes=2), "RESOLVED", "MITIGATED"),
        ]
    }
    caption = verified_mitigations_detail(incidents, transitions, {"MITIGATED", "RESOLVED"}, NOW)
    assert caption.text == "last verified 5h ago"


def test_last_verified_is_withheld_unless_every_counted_incident_can_prove_it() -> None:
    """The missing transition could be the most recent one."""
    incidents = [{"id": "inc_1", "state": "MITIGATED"}, {"id": "inc_2", "state": "RESOLVED"}]
    transitions = {"inc_1": [(NOW - timedelta(hours=5), "MITIGATED", "VERIFYING_MITIGATION")]}
    caption = verified_mitigations_detail(incidents, transitions, {"MITIGATED", "RESOLVED"}, NOW)
    assert caption.text == "verification time not recorded"


def test_a_duration_never_reads_as_negative() -> None:
    """A clock skew between two records must not print a caption from the future."""
    assert elapsed(NOW + timedelta(hours=3), NOW) == "0s"
    assert elapsed(NOW - timedelta(seconds=90), NOW) == "1m"
    assert elapsed(NOW - timedelta(days=3, hours=4), NOW) == "3d"


def test_the_tile_row_derives_its_figures_and_its_captions_from_one_read() -> None:
    """The whole point: no seam where a caption can be supplied by hand."""
    tiles = overview_tiles(
        incidents=[
            {
                "id": "inc_1",
                "state": "AWAITING_APPROVAL",
                "severity": "SEV1",
                "detected_at": NOW - timedelta(days=3),
            },
            {
                "id": "inc_2",
                "state": "MITIGATED",
                "severity": "SEV3",
                "detected_at": NOW - timedelta(days=5),
            },
        ],
        transitions_by_incident={
            "inc_1": [(NOW - timedelta(hours=2), "AWAITING_APPROVAL", "MITIGATION_PROPOSED")],
            "inc_2": [(NOW - timedelta(days=4), "MITIGATED", "VERIFYING_MITIGATION")],
        },
        cases=[{"created_at": NOW - timedelta(days=6), "next_action_at": NOW + timedelta(hours=9)}],
        active_states=("AWAITING_APPROVAL", "MITIGATED"),
        mitigated_states={"MITIGATED", "RESOLVED"},
        now=NOW,
    )
    assert [item["label"] for item in tiles] == [
        "Open incidents",
        "Reliability Cases",
        "Awaiting approval",
        "Verified mitigations",
    ]
    assert [item["value"] for item in tiles] == ["2", "1", "1", "1"]
    assert [item["detail"] for item in tiles] == [
        "1 SEV1 · 1 SEV3",
        "next wake-up in 9h",
        "oldest waiting 2h",
        "last verified 4d ago",
    ]
    # Every tile still carries the history and the named period beside it.
    assert all(len(item["trend"]) == TREND_DAYS for item in tiles)
    assert all(item["delta_period"] == f"{TREND_DAYS} days" for item in tiles)


def test_the_scripted_fixture_cannot_show_a_caption_the_live_path_cannot_produce() -> None:
    """The fixture holds records and derives its captions from them."""
    from apps.api.console_fixture import console_snapshot

    details = [metric["detail"] for metric in console_snapshot()["overview"]["metrics"]]
    assert details == [
        "1 SEV2",
        "next wake-up in 20h",
        "oldest waiting 13m",
        "last verified 9m ago",
    ]
