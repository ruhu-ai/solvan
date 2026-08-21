"""Turn drafted claims into deliverable ones, or refuse to deliver them.

This is the gate. A draft names a template and fills slots; this module looks
up the template (which owns kind and polarity), resolves the citations,
evaluates the predicate in code, and returns exactly one of three outcomes:

- **verified** — the predicate held; the sentence is rendered from the template;
- **held** — an affirmative claim of a held kind lacked its releasing record,
  so the holding form is delivered instead, with its releasing condition named;
- **suppressed** — the claim could not be verified at all and is not said.

There is no fourth outcome and no partial credit. A claim that cannot be
checked is not softened into hedged prose; it is withheld, and the defect is
counted. Specification 14 §7 and §12.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from solvan.application.liaison.predicates import (
    PREDICATES,
    Citation,
    ProjectionReader,
    matches_subject,
)
from solvan.application.liaison.templates import (
    ClaimTemplate,
    Polarity,
    TemplateRegistry,
    TemplateRegistryError,
)


class ClaimOutcome(StrEnum):
    VERIFIED = "VERIFIED"
    HELD = "HELD"
    SUPPRESSED = "SUPPRESSED"


@dataclass(frozen=True, slots=True)
class ClaimDraft:
    """What the model is permitted to produce: an id, a subject, and slots."""

    template_id: str
    subject_ref: str
    values: Mapping[str, str]
    citations: tuple[Citation, ...] = ()


@dataclass(frozen=True, slots=True)
class ComposedClaim:
    """What a reader may see, and why it is allowed to be seen."""

    outcome: ClaimOutcome
    template_id: str
    kind: str
    polarity: Polarity
    subject_ref: str
    #: Rendered by the template, never by the model. Empty when suppressed.
    sentence: str
    citations: tuple[Citation, ...]
    #: Present for HELD and SUPPRESSED: the failure in the reader's terms.
    reason: str = ""
    #: What would release a held claim, so the answer says when to ask again.
    releasing_record: str | None = None

    @property
    def deliverable(self) -> bool:
        return self.outcome is not ClaimOutcome.SUPPRESSED


@dataclass(slots=True)
class CompositionDefects:
    """Counted, not merely logged: a rising rate means the model is drifting."""

    suppressed: int = 0
    held: int = 0
    unresolved_citations: int = 0
    unknown_templates: int = 0
    #: One when the model planner failed and the deterministic composer stood
    #: in for it. Counted like any other defect so a rising rate is visible.
    provider_degraded: int = 0
    reasons: list[str] = field(default_factory=list)

    def record(self, outcome: ClaimOutcome, reason: str) -> None:
        if outcome is ClaimOutcome.SUPPRESSED:
            self.suppressed += 1
        elif outcome is ClaimOutcome.HELD:
            self.held += 1
        if reason:
            self.reasons.append(reason)


def _resolve_slots(
    template: ClaimTemplate,
    draft: ClaimDraft,
    reader: ProjectionReader,
    citations: tuple[Citation, ...],
    holding_reason: str = "",
) -> tuple[dict[str, str], str]:
    """Fill the sentence from the ledger, not from the model.

    A slot bound to a record is read from that record; whatever the model
    supplied for it is discarded. This is what stops a satisfied predicate from
    carrying a fabricated sentence — the predicate proves the citation, and
    these bindings prove the words.

    Returns the values and, when a required one is missing, the reason.
    """

    values: dict[str, str] = {}
    for slot in template.slots:
        source = template.slot_sources.get(slot)
        if source is None:
            return {}, f"slot {slot} has no source binding"
        if source.kind == "SUBJECT":
            values[slot] = draft.subject_ref
        elif source.kind == "HOLDING_REASON":
            values[slot] = holding_reason or "The releasing record is not present."
        elif source.kind == "MODEL_QUOTED":
            # The only slot the model fills. Its predicate must verify it
            # against stored text, so an unverified quote never renders.
            supplied = str(draft.values.get(slot, "")).strip()
            if not supplied:
                return {}, f"slot {slot} was left empty"
            values[slot] = supplied
        else:
            record = _record_of(reader, citations, source.record_type)
            if record is None:
                return {}, f"no {source.record_type} is cited for slot {slot}"
            stored = record.get(source.field or "")
            if stored in (None, ""):
                return {}, f"the cited {source.record_type} carries no {source.field}"
            values[slot] = str(stored)
    return values, ""


def _record_of(
    reader: ProjectionReader, citations: tuple[Citation, ...], record_type: str | None
) -> Mapping[str, Any] | None:
    for citation in citations:
        if citation.record_type != record_type:
            continue
        record = reader.read(citation.record_type, citation.record_id)
        if record is not None:
            return record
    return None


def _resolve_citations(
    reader: ProjectionReader, citations: tuple[Citation, ...]
) -> tuple[tuple[Citation, ...], tuple[Citation, ...]]:
    """Split citations into those that resolve and those that do not."""

    resolved: list[Citation] = []
    dangling: list[Citation] = []
    for citation in citations:
        if reader.read(citation.record_type, citation.record_id) is None:
            dangling.append(citation)
        else:
            resolved.append(citation)
    return tuple(resolved), tuple(dangling)


def _suppressed(template_id: str, subject_ref: str, reason: str) -> ComposedClaim:
    return ComposedClaim(
        outcome=ClaimOutcome.SUPPRESSED,
        template_id=template_id,
        kind="",
        polarity=Polarity.NEUTRAL,
        subject_ref=subject_ref,
        sentence="",
        citations=(),
        reason=reason,
    )


def _hold(
    registry: TemplateRegistry,
    template: ClaimTemplate,
    draft: ClaimDraft,
    citations: tuple[Citation, ...],
    reason: str,
    reader: ProjectionReader,
) -> ComposedClaim:
    """Render the holding form, which states what is true and what is pending."""

    holding = registry.claim(template.holding_template or "")
    # A holding form still makes a statement about the subject, so its words
    # come only from records that are about the subject. Resolving them from
    # whatever the affirmative draft happened to cite would let a refusal
    # describe one incident using another incident's committed state.
    relevant = tuple(
        citation
        for citation in citations
        if (record := reader.read(citation.record_type, citation.record_id)) is not None
        and matches_subject(record, draft.subject_ref)
    )
    values, missing = _resolve_slots(holding, draft, reader, relevant, holding_reason=reason)
    if missing:
        return _suppressed(template.id, draft.subject_ref, reason)
    try:
        sentence = holding.render(values)
    except TemplateRegistryError:
        # A malformed holding form must never leak the claim it was meant to hold.
        return _suppressed(template.id, draft.subject_ref, reason)
    return ComposedClaim(
        outcome=ClaimOutcome.HELD,
        template_id=holding.id,
        kind=holding.kind,
        polarity=holding.polarity,
        subject_ref=draft.subject_ref,
        sentence=sentence,
        citations=citations,
        reason=reason,
        releasing_record=template.releasing_record,
    )


def compose_claim(
    draft: ClaimDraft,
    *,
    registry: TemplateRegistry,
    reader: ProjectionReader,
    defects: CompositionDefects | None = None,
) -> ComposedClaim:
    """Verify one drafted claim against the ledger and render it, or refuse."""

    tally = defects if defects is not None else CompositionDefects()

    try:
        template = registry.claim(draft.template_id)
    except TemplateRegistryError:
        # An unknown template id is a defect, never a claim.
        tally.unknown_templates += 1
        claim = _suppressed(draft.template_id, draft.subject_ref, "unknown claim template")
        tally.record(claim.outcome, claim.reason)
        return claim

    resolved, dangling = _resolve_citations(reader, draft.citations)
    if dangling:
        tally.unresolved_citations += len(dangling)

    # An unresolvable citation fails the whole claim: a claim standing partly on
    # nothing is not a claim that may be delivered.
    if dangling:
        claim = _suppressed(
            template.id,
            draft.subject_ref,
            f"{len(dangling)} cited record(s) do not resolve",
        )
        tally.record(claim.outcome, claim.reason)
        return claim

    values, missing = _resolve_slots(template, draft, reader, resolved)
    if missing:
        # A field the affirmative form needs is often absent precisely because
        # the thing it asserts has not happened — an action with no receipt has
        # not been reconciled. So a held kind degrades to its holding form here
        # exactly as it does on a failed predicate, rather than vanishing.
        if template.held and template.holding_template:
            claim = _hold(registry, template, draft, resolved, missing, reader)
        else:
            claim = _suppressed(template.id, draft.subject_ref, missing)
        tally.record(claim.outcome, claim.reason)
        return claim

    verifier = PREDICATES[template.predicate]
    result = verifier(
        reader,
        subject_ref=draft.subject_ref,
        citations=resolved,
        values=values,
    )

    if not result.satisfied:
        # A held kind degrades to its holding form; anything else is withheld.
        if template.held and template.holding_template:
            claim = _hold(registry, template, draft, resolved, result.reason, reader)
        else:
            claim = _suppressed(template.id, draft.subject_ref, result.reason)
        tally.record(claim.outcome, claim.reason)
        return claim

    # A verified claim must still stand on something that resolves.
    if not resolved and template.predicate != "ALWAYS":
        claim = _suppressed(template.id, draft.subject_ref, "no citation resolves")
        tally.record(claim.outcome, claim.reason)
        return claim

    return ComposedClaim(
        outcome=ClaimOutcome.VERIFIED,
        template_id=template.id,
        kind=template.kind,
        polarity=template.polarity,
        subject_ref=draft.subject_ref,
        sentence=template.render(values),
        citations=resolved,
        releasing_record=template.releasing_record,
    )


def compose_all(
    drafts: Sequence[ClaimDraft],
    *,
    registry: TemplateRegistry,
    reader: ProjectionReader,
) -> tuple[tuple[ComposedClaim, ...], CompositionDefects]:
    """Compose every drafted claim, keeping only what may be delivered."""

    defects = CompositionDefects()
    composed = [
        compose_claim(draft, registry=registry, reader=reader, defects=defects) for draft in drafts
    ]
    return tuple(item for item in composed if item.deliverable), defects
