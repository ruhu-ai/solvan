"""Predicate verifiers: the code that decides whether a claim may be said.

Configuration names a predicate; this module implements it. Every verifier
answers one question — does the cited record actually establish this claim? —
against the same typed projections the console renders. A citation that is
merely valid is not enough: it must be *relevant*, meaning its subject and
window match the claim's slots. Relevance is decided against the record — one
of its subject fields is the claim's `subject_ref`, and its own recorded
instant lies inside any window the claim names — never against the reference,
which the drafter chose.

Specification 14 §7. These functions are the difference between a truth gate
and a well-formatted hope.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


class ProjectionReader(Protocol):
    """Reads one authoritative record. Implemented over the projection API."""

    def read(self, record_type: str, record_id: str) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class Citation:
    """A reference a claim stands on."""

    record_type: str
    record_id: str


@dataclass(frozen=True, slots=True)
class PredicateResult:
    satisfied: bool
    #: Why it failed, in the reader's terms. Empty when satisfied.
    reason: str = ""


_TERMINAL_INCIDENT_STATES = frozenset({"RESOLVED", "CLOSED"})
_RECONCILED_ACTION_STATES = frozenset({"RECONCILED", "SUCCEEDED", "VERIFIED"})
#: States in which an incident may legitimately be blocked on a person. Used
#: only when the projection carries no explicit `waiting_on_human` flag; an
#: explicit false always wins over an inferred state.
_ATTENTION_INCIDENT_STATES = frozenset({"AWAITING_APPROVAL", "MITIGATED", "ESCALATED"})


#: How deep a projection record is walked when checking that a value is stored.
#: Projections are nested documents — an impact line lives four levels down, at
#: `incident.brief.impact_lines[].metric` — so a value can be genuinely stored
#: on a record without being one of its top-level fields. The bound is generous
#: enough for the real shape and still stops a hostile or cyclic document from
#: turning verification into an unbounded traversal.
_MAX_RECORD_DEPTH = 6


def _stored_strings(value: Any, depth: int = 0) -> set[str]:
    """Every scalar the record actually holds, to the bounded depth."""

    if depth > _MAX_RECORD_DEPTH:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, bool):
        return {str(value)}
    if isinstance(value, int | float):
        return {str(value)}
    if isinstance(value, Mapping):
        found: set[str] = set()
        for item in value.values():
            found |= _stored_strings(item, depth + 1)
        return found
    if isinstance(value, Sequence):
        found = set()
        for item in value:
            found |= _stored_strings(item, depth + 1)
        return found
    return set()


def _first(
    reader: ProjectionReader, citations: tuple[Citation, ...], record_type: str
) -> tuple[Citation, Mapping[str, Any]] | None:
    """Resolve the first citation of the required kind, or report nothing."""

    for citation in citations:
        if citation.record_type != record_type:
            continue
        record = reader.read(citation.record_type, citation.record_id)
        if record is not None:
            return citation, record
    return None


#: How a projection says which subject a subordinate record belongs to. The
#: reader stamps `incident` onto every evidence item, action, and verification
#: run it indexes, which is what makes relevance checkable in code rather than
#: inferable from prose.
_SUBJECT_FIELDS = ("id", "incident", "incident_id", "subject", "subject_ref", "action_id")

#: The slots by which a claim states the window it speaks about. They describe
#: the assertion rather than quote a stored value, so they are checked by
#: containment below and excluded from the stored-value comparison.
_WINDOW_SLOTS = frozenset({"window_start", "window_end"})

#: Where a record says when it happened. The first field present wins; a record
#: that carries none of them cannot be placed in a window at all.
_RECORD_MOMENT_FIELDS = (
    "observed_at",
    "occurred_at",
    "recorded_at",
    "committed_at",
    "window_start",
)


def matches_subject(record: Mapping[str, Any], subject_ref: str) -> bool:
    """Public form of the relevance test, for callers outside the predicates."""

    return _matches_subject(record, subject_ref)


def _matches_subject(record: Mapping[str, Any], subject_ref: str) -> bool:
    """A citation is relevant only when it is about the claim's subject.

    This is what stops a valid-but-unrelated record from carrying a claim: a
    passed verification for another incident proves nothing about this one.
    """

    if not subject_ref:
        return False
    candidates = {str(record.get(field, "")) for field in _SUBJECT_FIELDS}
    return subject_ref in {value for value in candidates if value}


def _moment(value: Any) -> datetime | None:
    """Read one timezone-aware instant, or nothing. Naive times are nothing."""

    parsed: datetime | None = None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _within_claim_window(record: Mapping[str, Any], values: Mapping[str, str]) -> bool:
    """A cited record is relevant only inside the window the claim states.

    A claim that names no window asserts nothing about time, so there is
    nothing for a record to fall outside of. A claim that *does* name one is
    fail-closed: a record whose own instant cannot be read is not evidence that
    the window contained it.
    """

    start = _moment(values.get("window_start"))
    end = _moment(values.get("window_end"))
    if start is None and end is None:
        return True
    moment: datetime | None = None
    for field in _RECORD_MOMENT_FIELDS:
        moment = _moment(record.get(field))
        if moment is not None:
            break
    if moment is None:
        return False
    if start is not None and moment < start:
        return False
    return not (end is not None and moment > end)


def _relevant(
    reader: ProjectionReader,
    citations: tuple[Citation, ...],
    *,
    subject_ref: str,
    values: Mapping[str, str],
) -> tuple[tuple[Citation, Mapping[str, Any]], ...]:
    """Resolve the citations that are actually about this claim.

    Validity and relevance are different questions. A record the reader may
    read, that resolves, and that says something true is still not permitted to
    carry a claim about another subject or another window.
    """

    found: list[tuple[Citation, Mapping[str, Any]]] = []
    for citation in citations:
        record = reader.read(citation.record_type, citation.record_id)
        if record is None:
            continue
        if _matches_subject(record, subject_ref) and _within_claim_window(record, values):
            found.append((citation, record))
    return tuple(found)


def _subject_label(subject_ref: str) -> str:
    return subject_ref or "the claim's subject"


def verification_passed(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Released only by a PASSED verification run for this subject."""

    del values
    resolved = _first(reader, citations, "verification_run")
    if resolved is None:
        return PredicateResult(False, "no verification run is cited")
    citation, record = resolved
    if not _matches_subject(record, subject_ref):
        return PredicateResult(
            False, f"verification {citation.record_id} is not about {subject_ref}"
        )
    verdict = str(record.get("verdict", "")).upper()
    if verdict != "PASSED":
        return PredicateResult(False, f"verification verdict is {verdict or 'absent'}, not PASSED")
    return PredicateResult(True)


def receipt_reconciled(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Released only by an action whose effect is reconciled."""

    del values
    resolved = _first(reader, citations, "action")
    if resolved is None:
        return PredicateResult(False, "no action record is cited")
    citation, record = resolved
    if str(record.get("id", "")) != subject_ref:
        return PredicateResult(False, f"action {citation.record_id} is not {subject_ref}")
    status = str(record.get("status", "")).upper()
    if status not in _RECONCILED_ACTION_STATES:
        return PredicateResult(False, f"action status is {status or 'absent'}, not reconciled")
    if not record.get("receipt"):
        return PredicateResult(False, "the action carries no execution receipt")
    return PredicateResult(True)


def terminal_state(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Released only by a committed terminal transition on the subject."""

    resolved = _first(reader, citations, "incident")
    if resolved is None:
        return PredicateResult(False, "no incident record is cited")
    _, record = resolved
    if str(record.get("id", "")) != subject_ref:
        return PredicateResult(False, f"the cited incident is not {subject_ref}")
    state = str(record.get("state", "")).upper()
    if state not in _TERMINAL_INCIDENT_STATES:
        return PredicateResult(
            False, f"incident state is {state or 'absent'}, which is not terminal"
        )
    if values.get("state") not in (None, state):
        return PredicateResult(False, "the stated state does not match the record")
    return PredicateResult(True)


def human_attention_pending(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Released only while the cited incident is genuinely blocked on a person.

    An attention claim asserts something about *now*, so it is verified against
    the record's present state rather than against the presence of some string
    on the record. A terminal incident is never waiting on anybody, whatever
    its `next_action` prose happens to say.
    """

    resolved = _first(reader, citations, "incident")
    if resolved is None:
        return PredicateResult(False, "no incident record is cited")
    _, record = resolved
    if str(record.get("id", "")) != subject_ref:
        return PredicateResult(False, f"the cited incident is not {subject_ref}")
    state = str(record.get("state", "")).upper()
    if state in _TERMINAL_INCIDENT_STATES:
        return PredicateResult(False, f"incident state is {state}, so nobody is blocked on it")
    waiting = record.get("waiting_on_human")
    if waiting is not None and not bool(waiting):
        return PredicateResult(False, "the incident records no pending human decision")
    if waiting is None and state not in _ATTENTION_INCIDENT_STATES:
        return PredicateResult(
            False, f"incident state is {state or 'absent'}, which does not await a person"
        )
    detail = values.get("detail", "")
    if detail and str(detail) not in _stored_strings(record):
        return PredicateResult(False, "the stated next action is not present on the incident")
    return PredicateResult(True)


def record_field_equals(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Every filled slot must equal a field on a cited record about the subject.

    Descriptive claims are ungated but never unchecked: the model may only
    restate values the ledger already holds *about this subject*. Reading the
    values out of every cited record was the hole — a resolvable record about
    another incident would lend its numbers to a sentence about this one, and
    the predicate called that support.
    """

    if not citations:
        return PredicateResult(False, "the claim cites nothing")
    for citation in citations:
        record = reader.read(citation.record_type, citation.record_id)
        if record is None:
            return PredicateResult(False, f"citation {citation.record_id} does not resolve")
    relevant = _relevant(reader, citations, subject_ref=subject_ref, values=values)
    if not relevant:
        return PredicateResult(False, f"no cited record is about {_subject_label(subject_ref)}")
    stored: set[str] = set()
    for _, record in relevant:
        stored |= _stored_strings(record)
    unsupported = [
        f"{slot}={value!r}"
        for slot, value in values.items()
        if slot not in _WINDOW_SLOTS and str(value) not in stored
    ]
    if unsupported:
        return PredicateResult(
            False,
            "values are not present on the cited record about "
            f"{_subject_label(subject_ref)}: {', '.join(sorted(unsupported))}",
        )
    return PredicateResult(True)


def record_text_equals(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """A quote must equal the stored text of a record about the claim's subject.

    Byte-equality alone proves only that somebody, somewhere, wrote those
    words. Quoting another incident's causal chain under this incident's
    subject is exactly the valid-but-irrelevant citation the gate exists to
    refuse, so the search runs over the relevant records only.
    """

    quoted = values.get("quoted_text", "")
    if not quoted:
        return PredicateResult(False, "the quotation is empty")
    relevant = _relevant(reader, citations, subject_ref=subject_ref, values=values)
    if not relevant:
        return PredicateResult(False, f"no cited record is about {_subject_label(subject_ref)}")
    for _, record in relevant:
        if quoted in _stored_strings(record):
            return PredicateResult(True)
    return PredicateResult(
        False,
        "the quotation does not match the stored text of any cited record about "
        f"{_subject_label(subject_ref)}",
    )


def evidence_covers(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Containment needs evidence that resolves *and* covers this subject.

    "Resolves" was the whole test, which made containment the weakest claim in
    the registry: any readable evidence item — one about a different incident,
    or from outside the claimed window — released "the fault stayed inside
    …", and the sentence's slots were then filled from that same unrelated
    record. Every cited item must now be about the subject, not merely one of
    them, because the slot binding takes the first evidence citation that
    resolves.
    """

    evidence = [item for item in citations if item.record_type == "evidence_item"]
    if not evidence:
        return PredicateResult(False, "no evidence item is cited")
    for citation in evidence:
        record = reader.read(citation.record_type, citation.record_id)
        if record is None:
            return PredicateResult(False, f"evidence {citation.record_id} does not resolve")
        if not _matches_subject(record, subject_ref):
            return PredicateResult(
                False,
                f"evidence {citation.record_id} is not about {_subject_label(subject_ref)}",
            )
        if not _within_claim_window(record, values):
            return PredicateResult(
                False, f"evidence {citation.record_id} falls outside the claimed window"
            )
    return PredicateResult(True)


def always(
    reader: ProjectionReader,
    *,
    subject_ref: str,
    citations: tuple[Citation, ...],
    values: Mapping[str, str],
) -> PredicateResult:
    """Holding forms carry no assertion, so they need no releasing record."""

    del reader, subject_ref, citations, values
    return PredicateResult(True)


#: The implemented predicate names. `load_registry` refuses any template that
#: references a name absent from this mapping, so configuration can never call
#: for a verifier that does not exist.
PREDICATES = {
    "VERIFICATION_PASSED": verification_passed,
    "RECEIPT_RECONCILED": receipt_reconciled,
    "TERMINAL_STATE": terminal_state,
    "HUMAN_ATTENTION_PENDING": human_attention_pending,
    "RECORD_FIELD_EQUALS": record_field_equals,
    "RECORD_TEXT_EQUALS": record_text_equals,
    "EVIDENCE_COVERS": evidence_covers,
    "ALWAYS": always,
}

KNOWN_PREDICATES = frozenset(PREDICATES)
