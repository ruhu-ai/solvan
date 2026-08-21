"""The enumerated question set, and how free text resolves to one.

Held apart from the composer that answers them. This module is data and
matching: which questions exist, which record states admit each one, which
answer across a whole visible record set, and how an operator's words select
one. It reads nothing and drafts nothing, which is what lets the intent router
consult it without depending on the turn engine.

Specification 14 §4.2 requires suggested questions to be enumerated with
authorization predicates rather than generated, so a chip can never disclose
the existence of a record the reader cannot see. The same enumeration doubles
as the drafter's index: a question outside the set is not guessed at.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Question:
    """One askable question, with the states in which it is worth offering."""

    id: str
    prompt: str
    #: Offered only when the anchored record is in one of these states. Empty
    #: means "whenever the anchor resolves".
    offer_when_state: frozenset[str] = frozenset()
    #: Phrases that select this shape. Each is matched as a **contiguous run of
    #: whole words**, never as a substring: `"me"` must not be found inside
    #: "summarise", and `"ok"` must not be found inside "look". A phrase is
    #: therefore free to be short, but it must still be a word a person would
    #: only use when they mean this question.
    keywords: tuple[str, ...] = ()
    #: True when the shape answers across a reader's whole visible record set
    #: rather than about one record. A scope or service-window conversation may
    #: only select these; everything else is held until a record is named.
    answers_across_records: bool = False


QUESTIONS: tuple[Question, ...] = (
    Question(
        id="IS_IT_FIXED",
        prompt="Is it fixed?",
        keywords=(
            "fixed",
            "recovered",
            "recovery",
            "resolved",
            "mitigated",
            "is it safe",
            "is it ok",
            "is it okay",
            "back to normal",
            "still broken",
            "still down",
            "still failing",
            "is it working",
            "all clear",
        ),
    ),
    Question(
        id="WHAT_HAPPENED",
        prompt="What happened?",
        keywords=(
            "what happened",
            "what went wrong",
            "why",
            "cause",
            "caused",
            "causing",
            "root cause",
            "explain",
            "explanation",
            "mechanism",
            "summary",
            "summarise",
            "summarize",
            "walk me through",
            "what is going on",
            "what's going on",
        ),
    ),
    Question(
        id="WHAT_WAS_THE_IMPACT",
        prompt="What was the impact?",
        keywords=(
            "impact",
            "how bad",
            "customer",
            "customers",
            "severity",
            "how many",
            "who was affected",
        ),
    ),
    Question(
        id="WHAT_NEEDS_ME",
        prompt="What needs a person?",
        offer_when_state=frozenset({"AWAITING_APPROVAL", "MITIGATED", "ESCALATED"}),
        keywords=(
            "what needs a person",
            "needs a person",
            "needs me",
            "need from me",
            "waiting on",
            "waiting for",
            "needs approval",
            "awaiting approval",
            "who needs to",
            "blocked on",
            "blocking",
            "next step",
            "next steps",
            "what happens next",
            "anything from me",
        ),
    ),
    Question(
        id="WAS_DATA_LOST",
        prompt="Was any data lost?",
        keywords=(
            "data loss",
            "data lost",
            "lost data",
            "duplicate",
            "duplicates",
            "charged twice",
            "ledger",
        ),
    ),
    Question(
        id="IS_ANYTHING_ELSE_AFFECTED",
        prompt="Is anything else affected?",
        keywords=(
            "anything else",
            "else affected",
            "downstream",
            "blast radius",
            "spread",
            "other services",
            "contained",
        ),
    ),
    Question(
        id="WHAT_IS_THE_EVIDENCE",
        prompt="What evidence is this based on?",
        keywords=(
            "evidence",
            "proof",
            "how do you know",
            "basis",
            "citation",
            "citations",
            "sources",
        ),
    ),
    Question(
        id="WAS_THE_CHANGE_APPLIED",
        prompt="Was the change applied?",
        keywords=(
            "change applied",
            "applied",
            "deployed",
            "did it deploy",
            "rollback",
            "rolled back",
            "executed",
            "shipped",
            "went out",
            "is it live",
        ),
    ),
    # The two shapes below read the pinned STATE/CLOSURE templates. Those
    # templates and their predicates already existed; nothing selected them, so
    # "what stage are we at?" and "has the incident been cleared?" fell through
    # to the escalation valve while the answer sat in the projection.
    Question(
        id="WHERE_ARE_WE",
        prompt="What stage are we at?",
        answers_across_records=True,
        keywords=(
            "stage",
            "what stage",
            "status",
            "state",
            "progress",
            "where are we",
            "where we are",
            "how far",
            "update",
            "any update",
            "latest",
            "how is it going",
            "how are we doing",
            "current position",
        ),
    ),
    Question(
        id="IS_IT_CLOSED",
        prompt="Is it closed?",
        answers_across_records=True,
        keywords=(
            "closed",
            "close",
            "cleared",
            "clear",
            "over",
            "done",
            "finished",
            "wrapped up",
            "can we close",
            "still open",
            "is it open",
        ),
    ),
)

#: The enumerated frames a causal-chain step may carry. `_causal_chain` builds
#: exactly these five, and the CHAIN_STEP connective's `allowed_leads` pins the
#: same set; `test_liaison_questions` asserts the two agree, because a label
#: absent from the registry raises rather than rendering.
CHAIN_STEP_LABELS: tuple[str, ...] = ("Fault", "Mechanism", "Impact", "Recovery", "Outcome")

_BY_ID = {question.id: question for question in QUESTIONS}

#: Shapes a scope or service-window conversation may select. Derived from the
#: registry rather than restated, so a new cross-record shape cannot be added
#: to one list and forgotten in the other.
SCOPE_ANSWERABLE: frozenset[str] = frozenset(
    question.id for question in QUESTIONS if question.answers_across_records
)
_WORD = re.compile(r"[a-z0-9]+")


def _words(text: str) -> tuple[str, ...]:
    return tuple(_WORD.findall(text.lower()))


def _phrase_score(words: tuple[str, ...], keyword: str) -> int:
    """How many whole words of `keyword` match contiguously, or zero.

    Substring matching was the original defect: `"me"` is inside "summarise"
    and `"ok"` is inside "look", so a question about the incident's cause
    selected the answer shape for human attention. Matching whole-word runs
    also lets a longer phrase win, because specificity is the better signal —
    "waiting on" says more about intent than "impact" does.
    """

    phrase = _words(keyword)
    if not phrase or len(phrase) > len(words):
        return 0
    span = len(phrase)
    for start in range(len(words) - span + 1):
        if words[start : start + span] == phrase:
            return span
    return 0


def match_question(text: str, record: Mapping[str, Any] | None = None) -> Question | None:
    """Resolve free text to an enumerated question, or decline to guess.

    Matching is generous about phrasing and strict about outcome: an unmatched
    question produces the escalation valve, never an invented answer.

    When a record is supplied, a shape the record's state does not admit is
    passed over rather than answered. The offered-question set (§4.2) and the
    answered set must agree: a question Solvan would never *offer* for a closed
    incident must not be selectable for one either, or the surface asserts that
    a closed case is waiting on a person.
    """

    words = _words(text)
    if not words:
        return None
    state = str(record.get("state", "")).upper() if record is not None else None
    best: tuple[int, Question] | None = None
    for question in QUESTIONS:
        if (
            state is not None
            and question.offer_when_state
            and state not in question.offer_when_state
        ):
            continue
        score = max((_phrase_score(words, keyword) for keyword in question.keywords), default=0)
        if score and (best is None or score > best[0]):
            best = (score, question)
    return best[1] if best else None


def offered_questions(record: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Questions worth showing for this record's state (§4.2).

    The caller applies the reader filter before this is rendered, so a chip
    never reveals a state the reader may not see.
    """

    if record is None:
        return ()
    state = str(record.get("state", "")).upper()
    return tuple(
        question.id
        for question in QUESTIONS
        if not question.offer_when_state or state in question.offer_when_state
    )


def scope_offered_questions() -> tuple[str, ...]:
    """Questions a conversation with no single record can actually answer.

    A workspace conversation previously offered nothing, because the chip set
    was derived from an anchored record it does not have. Offering the shapes
    that *do* answer across records is what makes the surface usable before an
    incident is attached — and, per §4.2, the offered set and the answerable
    set stay the same set.
    """

    return tuple(question.id for question in QUESTIONS if question.answers_across_records)


def question_prompt(question_id: str) -> str:
    question = _BY_ID.get(question_id)
    return question.prompt if question else question_id
