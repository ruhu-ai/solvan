"""The answerable set: what a conversation can be asked, and where.

These are the contracts the surface actually failed in production use. An
operator asked "what stage are we at?" and was told the question was outside
the incident's scope; asked "have the incident been cleared?" and was told no
answer shape existed while `STATE_REPORT` and `INCIDENT_CLOSED` sat pinned and
unreachable in the registry; and asked anything at all from the workspace Chat
and was told the anchored record could not be read.

Specification 14 §4.2 ("the offered set and the answerable set are the same
set") and §5 ("a scope anchor admits ledger and cross-record reads").
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from solvan.application.liaison import Anchor, GrantIssuer, load_registry
from solvan.application.liaison.engine import TurnState, run_turn
from solvan.application.liaison.parts import PartKind
from solvan.application.liaison.predicates import KNOWN_PREDICATES
from solvan.application.liaison.questions import (
    CHAIN_STEP_LABELS,
    SCOPE_ANSWERABLE,
    EnumeratedComposer,
    match_question,
    scope_offered_questions,
)
from solvan.domain import Scope

REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config/liaison-claim-templates.yaml"
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
WINDOW_START = datetime(2026, 8, 20, 10, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)


def _incident(identifier: str, **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": identifier,
        "state": "MITIGATED",
        "service": "payments-api",
        "next_action": "Review the exact rollback proposal.",
    }
    record.update(overrides)
    return record


class _Ledger:
    """A reader over a fixed record set, with the search the composer uses."""

    def __init__(self, records: dict[tuple[str, str], dict[str, Any]]) -> None:
        self._records = records
        self.searches: list[dict[str, Any]] = []

    def read(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        return self._records.get((record_type, record_id))

    def exists(self, record_type: str, record_id: str) -> bool:
        return (record_type, record_id) in self._records

    def children(self, record_type: str, record_id: str) -> tuple[tuple[str, str], ...]:
        return tuple(key for key in self._records if key != (record_type, record_id))

    def authorized_records(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._records)

    def authorized_records_for_anchor(self, anchor: Anchor) -> tuple[tuple[str, str], ...]:
        del anchor
        return tuple(self._records)

    def resolve_reference(self, reference: str) -> tuple[str, str] | None:
        record_type, separator, record_id = reference.partition(":")
        key = (record_type, record_id)
        return key if separator and key in self._records else None

    def search_records(self, **criteria: Any) -> tuple[dict[str, Any], ...]:
        self.searches.append(criteria)
        service_key = criteria.get("service_key")
        record_type = criteria.get("record_type")
        found = []
        for (candidate_type, record_id), record in self._records.items():
            if record_type and candidate_type != record_type:
                continue
            if service_key and record.get("service") != service_key:
                continue
            found.append(
                {
                    "record_type": candidate_type,
                    "record_id": record_id,
                    "state": record.get("state", ""),
                    "service": record.get("service", ""),
                }
            )
        return tuple(found)


@pytest.fixture(scope="module")
def registry():
    return load_registry(REGISTRY_PATH, known_predicates=KNOWN_PREDICATES)


def _grant(anchor: Anchor):
    return GrantIssuer().read_grant(
        principal="operator@example.com",
        scope=SCOPE,
        thread_id="thr_1",
        message_id="lms_1",
        attempt=1,
        anchor_label=anchor.label(),
        classification_ceiling="INTERNAL",
        policy_epoch=1,
    )


# -- matching ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("utterance", "expected"),
    [
        ("what stage are we at?", "WHERE_ARE_WE"),
        ("I mean what stage are we at in the investigation?", "WHERE_ARE_WE"),
        ("what is the status?", "WHERE_ARE_WE"),
        ("where are we?", "WHERE_ARE_WE"),
        ("any update?", "WHERE_ARE_WE"),
        ("have the incident been cleared?", "IS_IT_CLOSED"),
        ("is it over?", "IS_IT_CLOSED"),
        ("can we close this?", "IS_IT_CLOSED"),
        ("is it still open?", "IS_IT_CLOSED"),
        ("is it mitigated?", "IS_IT_FIXED"),
        ("was the change shipped?", "WAS_THE_CHANGE_APPLIED"),
        ("what happens next?", "WHAT_NEEDS_ME"),
    ],
)
def test_ordinary_phrasing_reaches_an_answer_shape(utterance: str, expected: str) -> None:
    matched = match_question(utterance)
    assert matched is not None, utterance
    assert matched.id == expected


def test_the_offered_scope_set_is_exactly_the_answerable_scope_set() -> None:
    """§4.2: a chip that cannot be answered is a chip that lies."""

    assert set(scope_offered_questions()) == set(SCOPE_ANSWERABLE)
    assert SCOPE_ANSWERABLE  # a scope conversation that offers nothing is the old defect


def test_chain_step_labels_match_the_pinned_connective(registry) -> None:
    """A label absent from the registry raises rather than rendering.

    The composer picks the label out of the projection, so the two lists must
    be the same list — this is the same drift check the tool belt carries.
    """

    assert registry.connectives["CHAIN_STEP"].allowed_leads == CHAIN_STEP_LABELS


# -- record-anchored answers ------------------------------------------------


def test_the_causal_chain_keeps_the_frame_that_carries_its_meaning() -> None:
    """Without labels, "Independent verification is pending" reads as a cause."""

    record = _incident(
        "INC-1042",
        causal_chain=[
            {"label": "Fault", "detail": "The connection exhaustion signal crossed threshold."},
            {"label": "Recovery", "detail": "No mutation has been proposed yet."},
            {"label": "Outcome", "detail": "Independent verification is pending."},
        ],
    )
    composition = EnumeratedComposer().compose(
        question="explain the incident",
        anchor=Anchor.record("incident", "INC-1042"),
        reader=_Ledger({("incident", "INC-1042"): record}),
    )
    leads = [
        draft.phrase
        for draft in composition.drafts
        if getattr(draft, "template_id", None) == "CHAIN_STEP"
    ]
    assert leads == ["Fault", "Recovery", "Outcome"]


def test_a_stage_question_answers_from_the_pinned_state_templates(registry) -> None:
    anchor = Anchor.record("incident", "INC-1042")
    reader = _Ledger({("incident", "INC-1042"): _incident("INC-1042")})
    result = run_turn(
        question="what stage are we at?",
        anchor=anchor,
        reader=reader,
        registry=registry,
        composer=EnumeratedComposer(),
        grant=_grant(anchor),
    )
    assert result.state is TurnState.COMPLETED
    sentences = " ".join(result.sentences())
    assert "MITIGATED" in sentences
    # Never a fresh telemetry read: the ledger already holds the answer.
    assert not [part for part in result.parts if part.kind is PartKind.STEER_DRAFT]


def test_a_closure_question_holds_open_rather_than_asserting_closure(registry) -> None:
    anchor = Anchor.record("incident", "INC-1042")
    reader = _Ledger({("incident", "INC-1042"): _incident("INC-1042", state="MITIGATED")})
    result = run_turn(
        question="has the incident been cleared?",
        anchor=anchor,
        reader=reader,
        registry=registry,
        composer=EnumeratedComposer(),
        grant=_grant(anchor),
    )
    sentences = " ".join(result.sentences())
    assert "still open" in sentences
    assert "is closed" not in sentences


# -- cross-record answers ---------------------------------------------------


def test_a_workspace_question_answers_over_every_visible_incident(registry) -> None:
    anchor = Anchor.scope()
    reader = _Ledger(
        {
            ("incident", "INC-1042"): _incident("INC-1042", state="MITIGATED"),
            ("incident", "INC-2001"): _incident("INC-2001", state="ESCALATED"),
        }
    )
    result = run_turn(
        question="what stage are we at?",
        anchor=anchor,
        reader=reader,
        registry=registry,
        composer=EnumeratedComposer(),
        grant=_grant(anchor),
    )
    assert result.state is TurnState.COMPLETED
    sentences = " ".join(result.sentences())
    assert "INC-1042" in sentences and "INC-2001" in sentences
    # One authorized search, not one read per record.
    assert len(reader.searches) == 1
    claims = [part for part in result.parts if part.kind is PartKind.CLAIM]
    assert {part.payload["subject_ref"] for part in claims} == {"INC-1042", "INC-2001"}


def test_a_service_window_question_narrows_to_that_service_and_window(registry) -> None:
    anchor = Anchor.service("payments-api", WINDOW_START, WINDOW_END)
    reader = _Ledger(
        {
            ("incident", "INC-1042"): _incident("INC-1042"),
            ("incident", "INC-9000"): _incident("INC-9000", service="search-api"),
        }
    )
    result = run_turn(
        question="what is the status?",
        anchor=anchor,
        reader=reader,
        registry=registry,
        composer=EnumeratedComposer(),
        grant=_grant(anchor),
    )
    assert len(reader.searches) == 1
    criteria = reader.searches[0]
    assert criteria["service_key"] == "payments-api"
    assert criteria["record_type"] == "incident"
    assert (criteria["window_start"], criteria["window_end"]) == (WINDOW_START, WINDOW_END)
    sentences = " ".join(result.sentences())
    assert "INC-1042" in sentences
    assert "INC-9000" not in sentences


def test_a_record_only_question_at_scope_is_held_not_escalated(registry) -> None:
    """§"Scope Chat is Ask-first": held with the precise missing condition.

    It must not offer a bounded telemetry read. The ledger can answer this the
    moment a record is named, so proposing a fresh metrics read names the wrong
    missing thing and spends authority to obtain it.
    """

    anchor = Anchor.scope()
    reader = _Ledger({("incident", "INC-1042"): _incident("INC-1042")})
    result = run_turn(
        question="what was the impact?",
        anchor=anchor,
        reader=reader,
        registry=registry,
        composer=EnumeratedComposer(),
        grant=_grant(anchor),
    )
    refusals = [part for part in result.parts if part.kind is PartKind.REFUSAL]
    assert [part.payload["held_reason"] for part in refusals] == ["ANCHOR_NOT_NARROWED"]
    assert not [part for part in result.parts if part.kind is PartKind.STEER_DRAFT]


def test_an_empty_visible_set_says_so_rather_than_reporting_a_read_failure() -> None:
    composition = EnumeratedComposer().compose(
        question="what stage are we at?", anchor=Anchor.scope(), reader=_Ledger({})
    )
    assert composition.drafts == ()
    assert composition.hold is not None
    assert composition.hold.held_reason == "EMPTY_AUTHORIZED_SET"


def test_an_unmatched_question_at_scope_names_the_missing_shape() -> None:
    composition = EnumeratedComposer().compose(
        question="what colour is the sky",
        anchor=Anchor.scope(),
        reader=_Ledger({("incident", "INC-1042"): _incident("INC-1042")}),
    )
    assert composition.hold is not None
    assert composition.hold.held_reason == "NO_ANSWER_SHAPE"
    assert composition.suggested == scope_offered_questions()
