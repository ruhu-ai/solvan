"""Each verifier's refusals, stated one at a time.

A predicate that only gets exercised on its happy path is an assertion, not a
gate. These cover the branch each verifier exists for: the missing citation,
the wrong subject, the unresolvable reference, and the value nobody stored.

Specification 14 §7.
"""

from __future__ import annotations

from typing import Any

from solvan.application.liaison.predicates import (
    Citation,
    always,
    evidence_covers,
    receipt_reconciled,
    record_field_equals,
    record_text_equals,
    terminal_state,
    verification_passed,
)


class _Ledger:
    def __init__(self, records: dict[tuple[str, str], dict[str, Any]] | None = None) -> None:
        self._records = records or {}

    def read(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        return self._records.get((record_type, record_id))


EMPTY = _Ledger()


def test_verification_refuses_every_way_it_can_fail() -> None:
    assert not verification_passed(EMPTY, subject_ref="INC-1", citations=(), values={}).satisfied

    # Cited but unresolvable.
    result = verification_passed(
        EMPTY,
        subject_ref="INC-1",
        citations=(Citation("verification_run", "VER-1"),),
        values={},
    )
    assert "no verification run is cited" in result.reason

    # Resolvable, about the right incident, but not passed.
    running = _Ledger(
        {("verification_run", "VER-1"): {"id": "VER-1", "incident": "INC-1", "verdict": "RUNNING"}}
    )
    assert (
        "not PASSED"
        in verification_passed(
            running,
            subject_ref="INC-1",
            citations=(Citation("verification_run", "VER-1"),),
            values={},
        ).reason
    )

    # An absent subject can never be matched, so an empty subject is refused.
    assert not verification_passed(
        running, subject_ref="", citations=(Citation("verification_run", "VER-1"),), values={}
    ).satisfied


def test_a_receipt_must_belong_to_the_action_and_be_reconciled() -> None:
    assert (
        "no action record"
        in receipt_reconciled(EMPTY, subject_ref="ACT-1", citations=(), values={}).reason
    )

    other = _Ledger({("action", "ACT-2"): {"id": "ACT-2", "status": "VERIFIED", "receipt": "r"}})
    assert (
        "is not ACT-1"
        in receipt_reconciled(
            other, subject_ref="ACT-1", citations=(Citation("action", "ACT-2"),), values={}
        ).reason
    )

    receiptless = _Ledger({("action", "ACT-1"): {"id": "ACT-1", "status": "VERIFIED"}})
    assert (
        "no execution receipt"
        in receipt_reconciled(
            receiptless, subject_ref="ACT-1", citations=(Citation("action", "ACT-1"),), values={}
        ).reason
    )


def test_closure_requires_a_terminal_state_that_matches_what_was_said() -> None:
    assert (
        "no incident record"
        in terminal_state(EMPTY, subject_ref="INC-1", citations=(), values={}).reason
    )

    open_incident = _Ledger({("incident", "INC-1"): {"id": "INC-1", "state": "MITIGATED"}})
    assert (
        "not terminal"
        in terminal_state(
            open_incident,
            subject_ref="INC-1",
            citations=(Citation("incident", "INC-1"),),
            values={"state": "MITIGATED"},
        ).reason
    )

    closed = _Ledger({("incident", "INC-1"): {"id": "INC-1", "state": "CLOSED"}})
    assert terminal_state(
        closed,
        subject_ref="INC-1",
        citations=(Citation("incident", "INC-1"),),
        values={"state": "CLOSED"},
    ).satisfied
    # Claiming a state the record does not carry fails even when terminal.
    assert not terminal_state(
        closed,
        subject_ref="INC-1",
        citations=(Citation("incident", "INC-1"),),
        values={"state": "RESOLVED"},
    ).satisfied
    # The cited incident must be the subject.
    assert (
        "not INC-9"
        in terminal_state(
            closed, subject_ref="INC-9", citations=(Citation("incident", "INC-1"),), values={}
        ).reason
    )


def test_descriptive_values_must_exist_on_a_cited_record() -> None:
    assert (
        "cites nothing"
        in record_field_equals(EMPTY, subject_ref="INC-1", citations=(), values={"a": "b"}).reason
    )
    assert (
        "does not resolve"
        in record_field_equals(
            EMPTY, subject_ref="INC-1", citations=(Citation("incident", "INC-1"),), values={}
        ).reason
    )

    ledger = _Ledger({("incident", "INC-1"): {"id": "INC-1", "state": "MITIGATED"}})
    assert record_field_equals(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("incident", "INC-1"),),
        values={"state": "MITIGATED"},
    ).satisfied
    assert (
        "not present on the cited record"
        in record_field_equals(
            ledger,
            subject_ref="INC-1",
            citations=(Citation("incident", "INC-1"),),
            values={"state": "fully recovered"},
        ).reason
    )


def test_a_descriptive_value_may_not_be_borrowed_from_another_subject() -> None:
    """Case 54 for the ungated kinds: resolvable is not the same as relevant.

    The predicate used to pool the stored strings of *every* cited record, so
    citing this incident alongside a healthy one let the healthy one's numbers
    support a sentence about this one.
    """

    ledger = _Ledger(
        {
            ("incident", "INC-1"): {"id": "INC-1", "state": "MITIGATED"},
            ("incident", "INC-2"): {"id": "INC-2", "state": "CLOSED"},
        }
    )
    borrowed = record_field_equals(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("incident", "INC-1"), Citation("incident", "INC-2")),
        values={"state": "CLOSED"},
    )
    assert not borrowed.satisfied
    assert "not present on the cited record about INC-1" in borrowed.reason

    only_unrelated = record_field_equals(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("incident", "INC-2"),),
        values={"state": "CLOSED"},
    )
    assert not only_unrelated.satisfied
    assert "no cited record is about INC-1" in only_unrelated.reason


def test_nested_projection_values_still_count_as_stored() -> None:
    """A measured line lives inside `brief.impact_lines`, not at the top."""

    ledger = _Ledger(
        {
            ("incident", "INC-1"): {
                "id": "INC-1",
                "brief": {"impact_lines": [{"metric": "18.4% error ratio"}]},
            }
        }
    )
    assert record_field_equals(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("incident", "INC-1"),),
        values={"metric": "18.4% error ratio"},
    ).satisfied


def test_a_quotation_must_be_verbatim_and_resolvable() -> None:
    assert (
        "empty"
        in record_text_equals(
            EMPTY, subject_ref="INC-1", citations=(), values={"quoted_text": ""}
        ).reason
    )
    # An unresolvable citation is skipped, leaving nothing relevant to match.
    assert (
        "no cited record is about INC-1"
        in record_text_equals(
            EMPTY,
            subject_ref="INC-1",
            citations=(Citation("evidence_item", "evd_1"),),
            values={"quoted_text": "a fact"},
        ).reason
    )

    ledger = _Ledger(
        {("evidence_item", "evd_1"): {"incident": "INC-1", "statement": "a fact"}},
    )
    assert record_text_equals(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_1"),),
        values={"quoted_text": "a fact"},
    ).satisfied


def test_a_quotation_may_not_come_from_another_incidents_record() -> None:
    """Stored somewhere is not stored here. Bytes alone prove nothing."""

    ledger = _Ledger(
        {("evidence_item", "evd_9"): {"incident": "INC-9", "statement": "no customers affected"}}
    )
    result = record_text_equals(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_9"),),
        values={"quoted_text": "no customers affected"},
    )
    assert not result.satisfied
    assert "no cited record is about INC-1" in result.reason


def test_containment_needs_evidence_that_resolves() -> None:
    assert (
        "no evidence item"
        in evidence_covers(
            EMPTY, subject_ref="INC-1", citations=(Citation("incident", "INC-1"),), values={}
        ).reason
    )
    assert (
        "does not resolve"
        in evidence_covers(
            EMPTY, subject_ref="INC-1", citations=(Citation("evidence_item", "evd_1"),), values={}
        ).reason
    )
    ledger = _Ledger(
        {("evidence_item", "evd_1"): {"incident": "INC-1", "label": "no downstream errors"}}
    )
    assert evidence_covers(
        ledger, subject_ref="INC-1", citations=(Citation("evidence_item", "evd_1"),), values={}
    ).satisfied


def test_containment_refuses_evidence_that_resolves_but_covers_nothing_here() -> None:
    """The finding this predicate exists for: resolvable was the whole test.

    Any readable evidence item released "the fault stayed inside …", including
    one belonging to another incident — and the sentence's words were then read
    from that same unrelated record. Every cited item must be about the
    subject, not merely one of them, because the slot binding takes the first
    evidence citation that resolves.
    """

    ledger = _Ledger(
        {
            ("evidence_item", "evd_other"): {
                "incident": "INC-9",
                "label": "no error propagated past checkout",
            },
            ("evidence_item", "evd_mine"): {
                "incident": "INC-1",
                "label": "no error propagated past payments-api",
            },
        }
    )
    unrelated = evidence_covers(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_other"),),
        values={},
    )
    assert not unrelated.satisfied
    assert "evd_other is not about INC-1" in unrelated.reason

    mixed = evidence_covers(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_other"), Citation("evidence_item", "evd_mine")),
        values={},
    )
    assert not mixed.satisfied


def test_a_claim_that_names_a_window_needs_evidence_inside_it() -> None:
    """Relevance is subject *and* window; a claim without one states neither."""

    ledger = _Ledger(
        {
            ("evidence_item", "evd_late"): {
                "incident": "INC-1",
                "observed_at": "2026-08-12T14:00:00+00:00",
                "label": "clean",
            },
            ("evidence_item", "evd_inside"): {
                "incident": "INC-1",
                "observed_at": "2026-08-12T12:30:00+00:00",
                "label": "clean",
            },
            ("evidence_item", "evd_undated"): {"incident": "INC-1", "label": "clean"},
        }
    )
    window = {
        "window_start": "2026-08-12T12:00:00+00:00",
        "window_end": "2026-08-12T13:00:00+00:00",
    }
    assert evidence_covers(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_inside"),),
        values=window,
    ).satisfied
    outside = evidence_covers(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_late"),),
        values=window,
    )
    assert not outside.satisfied
    assert "outside the claimed window" in outside.reason
    # A record that cannot be placed in time is not evidence that the window
    # contained it.
    assert not evidence_covers(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_undated"),),
        values=window,
    ).satisfied
    # The same undated record is fine for a claim that names no window.
    assert evidence_covers(
        ledger,
        subject_ref="INC-1",
        citations=(Citation("evidence_item", "evd_undated"),),
        values={},
    ).satisfied


def test_holding_forms_assert_nothing_and_so_need_no_record() -> None:
    assert always(EMPTY, subject_ref="", citations=(), values={}).satisfied
