"""The composer that answers the enumerated question set from projections.

This composer is not a placeholder for a model — it is the deterministic path
the spec calls for, and it satisfies exactly the same gates a model's drafts
would. The enumeration itself lives in `question_registry`; what lives here is
the drafting: which pinned templates answer each shape, which records those
claims must cite, and what is said instead when the anchor cannot support the
shape at all.

Two drafting paths, chosen by what is in view rather than by anchor kind alone:
one incident, or the whole set of records this reader can see at this anchor.
The cross-record path emits one claim per record from the same pinned
templates, so a workspace answer is many gated claims and never one ungated
summary. Specification 14 §4.2, §5.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from solvan.application.liaison.anchors import Anchor, AnchorKind
from solvan.application.liaison.claims import ClaimDraft
from solvan.application.liaison.engine import (
    Composition,
    ConnectiveDraft,
    Draft,
    Escalation,
    Hold,
)
from solvan.application.liaison.predicates import Citation, ProjectionReader
from solvan.application.liaison.question_registry import (
    CHAIN_STEP_LABELS as CHAIN_STEP_LABELS,
)
from solvan.application.liaison.question_registry import (
    QUESTIONS as QUESTIONS,
)
from solvan.application.liaison.question_registry import (
    SCOPE_ANSWERABLE as SCOPE_ANSWERABLE,
)
from solvan.application.liaison.question_registry import (
    Question as Question,
)
from solvan.application.liaison.question_registry import (
    match_question as match_question,
)
from solvan.application.liaison.question_registry import (
    offered_questions as offered_questions,
)
from solvan.application.liaison.question_registry import (
    question_prompt as question_prompt,
)
from solvan.application.liaison.question_registry import (
    scope_offered_questions as scope_offered_questions,
)


def _incident_of(anchor: Anchor) -> str | None:
    if anchor.kind is AnchorKind.RECORD and anchor.record_type == "incident":
        return anchor.record_id
    return None


def _verification_citation(record: Mapping[str, Any]) -> tuple[Citation, ...]:
    verification = record.get("verification")
    if isinstance(verification, Mapping) and verification.get("id"):
        return (Citation("verification_run", str(verification["id"])),)
    return ()


class EnumeratedComposer:
    """Answers the enumerated set from durable projections, and nothing else."""

    def compose(
        self,
        *,
        question: str,
        anchor: Anchor,
        reader: ProjectionReader,
        provider_input: str | None = None,
    ) -> Composition:
        del provider_input
        incident_id = _incident_of(anchor)
        record = reader.read("incident", incident_id) if incident_id else None
        if incident_id is not None and record is None:
            # Attached to an incident this reader cannot read. Distinct from
            # having no incident in view, and the reader is owed the
            # difference: the old escalation proposed a fresh telemetry read
            # to fix what is actually a grant problem.
            return Composition(
                hold=Hold(
                    sentence="I cannot read the record this conversation is about.",
                    held_reason="ANCHOR_UNREADABLE",
                    releasing_record="a reader grant covering the anchored record",
                )
            )
        if incident_id is None:
            # No single incident is in view. That is the ordinary state of a
            # workspace or service-window conversation, and of a record anchor
            # that is not itself an incident — not a read failure, which is
            # what "the anchored record could not be read" used to tell every
            # one of them.
            return self._compose_across_records(question=question, anchor=anchor, reader=reader)
        # The record is part of the match, not just of the answer: an answer
        # shape this record's state does not admit is never selected.
        matched = match_question(question, record)
        suggested = offered_questions(record)

        if matched is None:
            return Composition(
                escalation=Escalation(
                    missing="I do not hold an answer shape for that question",
                    proposed_step="Request a bounded evidence read for this incident.",
                ),
                suggested=suggested,
            )

        handler = getattr(self, f"_answer_{matched.id.lower()}", None)
        if handler is None:  # pragma: no cover - registry and methods stay in step
            return Composition(suggested=suggested)
        drafts, escalation = handler(incident_id or "", record)
        return Composition(drafts=tuple(drafts), escalation=escalation, suggested=suggested)

    # -- answering with no single record in view ----------------------------

    def _visible_incidents(self, anchor: Anchor, reader: ProjectionReader) -> tuple[str, ...]:
        """Incident ids inside this anchor's authorized set, newest search first.

        One authorized search, not one read per record: the search is already
        bound to the grant's entity set, and the claim gate re-reads each cited
        incident under the same grant when it verifies the claim.
        """

        search = getattr(reader, "search_records", None)
        if search is None:
            return ()
        rows = search(
            service_key=anchor.service_key,
            state=None,
            record_type="incident",
            window_start=anchor.window_start,
            window_end=anchor.window_end,
        )
        return tuple(
            str(row["record_id"])
            for row in rows
            if isinstance(row, Mapping) and row.get("record_id")
        )

    def _compose_across_records(
        self, *, question: str, anchor: Anchor, reader: ProjectionReader
    ) -> Composition:
        """Answer over every incident the reader can see at this anchor (§5).

        Claims are drafted one per incident from the same pinned templates the
        record path uses, each citing its own incident. Every predicate
        therefore verifies exactly as it does for a single record: a
        cross-record answer is many gated claims, never one ungated summary.
        """

        suggested = scope_offered_questions()
        matched = match_question(question)
        if matched is None:
            return Composition(
                hold=Hold(
                    sentence="I do not hold an answer shape for that question.",
                    held_reason="NO_ANSWER_SHAPE",
                    releasing_record="an enumerated question about a visible record",
                ),
                suggested=suggested,
            )
        if not matched.answers_across_records:
            return Composition(
                hold=Hold(
                    sentence=(
                        f"\u201c{matched.prompt}\u201d is about one record, and this "
                        "conversation is not attached to one."
                    ),
                    held_reason="ANCHOR_NOT_NARROWED",
                    releasing_record="an attached incident or service window",
                ),
                suggested=suggested,
            )

        incidents = self._visible_incidents(anchor, reader)
        if not incidents:
            return Composition(
                hold=Hold(
                    sentence="No incident here is visible to you.",
                    held_reason="EMPTY_AUTHORIZED_SET",
                    releasing_record="a reader grant covering an incident",
                ),
                suggested=suggested,
            )

        frame = "The sequence:" if matched.id == "WHERE_ARE_WE" else "What remains:"
        drafts: list[Draft] = [ConnectiveDraft("LIST_FRAME", frame)]
        for incident_id in incidents:
            drafts.extend(self._cross_record_drafts(matched.id, incident_id))
        return Composition(drafts=tuple(drafts), suggested=suggested)

    def _cross_record_drafts(self, question_id: str, incident_id: str) -> tuple[Draft, ...]:
        """One incident's contribution to a cross-record answer."""

        citation = (Citation("incident", incident_id),)
        if question_id == "IS_IT_CLOSED":
            # Held kind: a non-terminal incident degrades to INCIDENT_OPEN and
            # states its committed state rather than asserting closure.
            return (
                ClaimDraft(
                    template_id="INCIDENT_CLOSED",
                    subject_ref=incident_id,
                    values={},
                    citations=citation,
                ),
            )
        return (
            ClaimDraft(
                template_id="STATE_REPORT",
                subject_ref=incident_id,
                values={},
                citations=citation,
            ),
            ClaimDraft(
                template_id="AWAITING_HUMAN",
                subject_ref=incident_id,
                values={},
                citations=citation,
            ),
        )

    # -- one method per enumerated question ---------------------------------

    def _answer_where_are_we(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        """Where this incident stands, and what it is waiting on.

        Three pinned claims rather than prose: the committed state, whether a
        person is blocking it, and whether recovery has been independently
        verified. Each degrades to its holding form on its own, so a partial
        answer stays honest instead of going silent.
        """

        citation = (Citation("incident", incident_id),)
        return (
            [
                ConnectiveDraft("LEAD_IN", "Here is the current state."),
                ClaimDraft(
                    template_id="STATE_REPORT",
                    subject_ref=incident_id,
                    values={},
                    citations=citation,
                ),
                ClaimDraft(
                    template_id="AWAITING_HUMAN",
                    subject_ref=incident_id,
                    values={},
                    citations=citation,
                ),
                ClaimDraft(
                    template_id="RECOVERY_VERIFIED",
                    subject_ref=incident_id,
                    values={},
                    citations=citation + _verification_citation(record),
                ),
            ],
            None,
        )

    def _answer_is_it_closed(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        del record
        return (
            [
                ClaimDraft(
                    template_id="INCIDENT_CLOSED",
                    subject_ref=incident_id,
                    values={},
                    citations=(Citation("incident", incident_id),),
                )
            ],
            None,
        )

    def _answer_is_it_fixed(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        verification = record.get("verification")
        detail = "the observation window and a fresh synthetic probe passed"
        if isinstance(verification, Mapping):
            detail = str(verification.get("threshold", detail))
        return (
            [
                ConnectiveDraft("LEAD_IN", "Here is what I can confirm."),
                ClaimDraft(
                    template_id="RECOVERY_VERIFIED",
                    subject_ref=incident_id,
                    values={"subject_label": incident_id, "verdict_detail": detail},
                    citations=_verification_citation(record),
                ),
            ],
            None,
        )

    def _answer_what_happened(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        drafts: list[Draft] = [ConnectiveDraft("LEAD_IN", "Here is what happened.")]
        chain = record.get("causal_chain")
        if isinstance(chain, Sequence):
            for step in chain:
                if not isinstance(step, Mapping):
                    continue
                # The chain's frame is half its meaning. Dropping it flattened
                # Fault/Mechanism/Impact/Recovery/Outcome into five unrelated
                # sentences, so "No mutation has been proposed yet" read as a
                # cause. The label rides an enumerated connective rather than
                # the claim sentence, because the claim's text must stay
                # byte-equal to what the record stores for its predicate to
                # verify it.
                label = str(step.get("label", ""))
                if label in CHAIN_STEP_LABELS:
                    drafts.append(ConnectiveDraft("CHAIN_STEP", label))
                drafts.append(
                    ClaimDraft(
                        template_id="RECORD_STATEMENT",
                        subject_ref=incident_id,
                        values={"quoted_text": str(step.get("detail", ""))},
                        citations=(Citation("incident", incident_id),),
                    )
                )
        return drafts, None

    def _answer_what_was_the_impact(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        drafts: list[Draft] = [ConnectiveDraft("LIST_FRAME", "The measured impact:")]
        brief = record.get("brief")
        lines = brief.get("impact_lines") if isinstance(brief, Mapping) else None
        if isinstance(lines, Sequence):
            for line in lines:
                if not isinstance(line, Mapping):
                    continue
                citation = line.get("citation")
                drafts.append(
                    ClaimDraft(
                        template_id="MEASURED_VALUE",
                        subject_ref=incident_id,
                        values={
                            "metric": str(line.get("metric", "")),
                            "scope_label": str(line.get("scope", "")),
                            "detail": str(line.get("detail", "")),
                        },
                        citations=(
                            (
                                Citation("incident", incident_id),
                                Citation("evidence_item", str(citation)),
                            )
                            if citation
                            else (Citation("incident", incident_id),)
                        ),
                    )
                )
        return drafts, None

    def _answer_what_needs_me(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        return (
            [
                ClaimDraft(
                    template_id="AWAITING_HUMAN",
                    subject_ref=incident_id,
                    values={
                        "subject_label": incident_id,
                        "detail": str(record.get("next_action", "")),
                    },
                    citations=(Citation("incident", incident_id),),
                ),
                ConnectiveDraft("HANDOFF", "Open the incident to act on this."),
            ],
            None,
        )

    def _answer_was_data_lost(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        brief = record.get("brief")
        detail = str(brief.get("data_loss", "")) if isinstance(brief, Mapping) else ""
        return (
            [
                ClaimDraft(
                    template_id="DATA_LOSS_ABSENT",
                    subject_ref=incident_id,
                    values={
                        "subject_label": incident_id,
                        "evidence_detail": detail or "no unreconciled effect was observed",
                    },
                    citations=_verification_citation(record),
                )
            ],
            None,
        )

    def _answer_is_anything_else_affected(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        brief = record.get("brief")
        lines = brief.get("impact_lines") if isinstance(brief, Mapping) else None
        citations: list[Citation] = []
        detail = "no error propagated beyond the affected service"
        if isinstance(lines, Sequence):
            for line in lines:
                if isinstance(line, Mapping) and "downstream" in str(line.get("metric", "")):
                    detail = str(line.get("detail", detail))
                    if line.get("citation"):
                        citations.append(Citation("evidence_item", str(line["citation"])))
        return (
            [
                ClaimDraft(
                    template_id="BLAST_RADIUS_CONTAINED",
                    subject_ref=incident_id,
                    values={
                        "subject_label": str(record.get("service", incident_id)),
                        "evidence_detail": detail,
                    },
                    citations=tuple(citations),
                )
            ],
            None,
        )

    def _answer_what_is_the_evidence(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        drafts: list[Draft] = [ConnectiveDraft("LIST_FRAME", "The evidence on file:")]
        index = record.get("evidence_index")
        if isinstance(index, Sequence):
            for item in index:
                if not isinstance(item, Mapping):
                    continue
                drafts.append(
                    ClaimDraft(
                        template_id="RECORD_STATEMENT",
                        subject_ref=incident_id,
                        values={"quoted_text": str(item.get("label", ""))},
                        citations=(Citation("evidence_item", str(item.get("ref", ""))),),
                    )
                )
        return drafts, None

    def _answer_was_the_change_applied(
        self, incident_id: str, record: Mapping[str, Any]
    ) -> tuple[Sequence[Draft], Escalation | None]:
        drafts: list[Draft] = []
        actions = record.get("actions")
        if isinstance(actions, Sequence):
            for action in actions:
                if not isinstance(action, Mapping):
                    continue
                action_id = str(action.get("id", ""))
                drafts.append(
                    ClaimDraft(
                        template_id="CHANGE_DEPLOYED",
                        subject_ref=action_id,
                        values={
                            "subject_label": str(action.get("name", action_id)),
                            "receipt_detail": str(action.get("receipt", "")),
                            "status": str(action.get("status", "")),
                        },
                        citations=(Citation("action", action_id),),
                    )
                )
        return drafts, None
