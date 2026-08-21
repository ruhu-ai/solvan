"""Typed parts and the access envelope that decides who may read each one.

A transcript is not prose with attachments; it is a list of typed parts, each
carrying its own classification and its own audience. That matters because the
leak this design must not have is the *uncited* one: a wider-authority person
quoting a restricted fact into a shared thread, or a tool row printing a record
a later reader cannot see.

So every part declares an access mode, and **an empty record set denies**.
Nothing is visible by omission. Specification 14 §5, §11, §12.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from enum import StrEnum

from solvan.application.liaison.claims import ClaimOutcome, ComposedClaim
from solvan.application.liaison.predicates import Citation


class Verb(StrEnum):
    """What a conversational input resolved to. Classification is UX; the
    gates below and in the coordinator are authorization."""

    ASK = "ASK"
    STEER = "STEER"
    ACT = "ACT"


class PartKind(StrEnum):
    TEXT = "text"
    CLAIM = "claim"
    TOOL = "tool"
    CATCHUP_DELTA = "catchup_delta"
    STEER_DRAFT = "steer_draft"
    APPROVAL_REF = "approval_ref"
    GUIDANCE_REF = "guidance_ref"
    REFUSAL = "refusal"
    BUDGET_NOTE = "budget_note"
    PARKED_REQUEST = "parked_request"
    COMPACTION = "compaction"
    CONTENT_WITHHELD = "content_withheld"
    INTERRUPTED = "interrupted"
    ERROR = "error"


class AccessMode(StrEnum):
    RECORD_SET = "RECORD_SET"
    PARTICIPANTS_AT_EPOCH = "PARTICIPANTS_AT_EPOCH"
    AUTHOR_ONLY = "AUTHOR_ONLY"
    SYSTEM_PUBLIC = "SYSTEM_PUBLIC"
    DERIVED_SOURCES = "DERIVED_SOURCES"


@dataclass(frozen=True, slots=True)
class AccessReference:
    """One record a part's visibility depends on."""

    record_type: str
    record_id: str
    relation: str  # CITES | READ | EVENT | SUBJECT | SOURCE


@dataclass(frozen=True, slots=True)
class Part:
    """One durable unit of a message. Immutable once completed."""

    kind: PartKind
    sequence: int
    payload: dict[str, object]
    classification: str
    access_mode: AccessMode
    access_set: tuple[AccessReference, ...] = ()
    author_principal: str | None = None
    membership_epoch: int | None = None
    audience_principals: frozenset[str] = frozenset()
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.access_mode is AccessMode.AUTHOR_ONLY and not self.author_principal:
            raise ValueError("an author-only part must name its author")
        if self.access_mode is AccessMode.PARTICIPANTS_AT_EPOCH and self.membership_epoch is None:
            raise ValueError("a participant-scoped part must name its membership epoch")


def _access_set_from_claim(claim: ComposedClaim) -> tuple[AccessReference, ...]:
    return tuple(
        AccessReference(citation.record_type, citation.record_id, "CITES")
        for citation in claim.citations
    )


def claim_part(claim: ComposedClaim, *, sequence: int, classification: str) -> Part:
    """Carry a composed claim, with its citations as its visibility envelope."""

    if claim.outcome is ClaimOutcome.SUPPRESSED:
        raise ValueError("a suppressed claim is never carried as a part")
    kind = PartKind.REFUSAL if claim.outcome is ClaimOutcome.HELD else PartKind.CLAIM
    payload: dict[str, object] = {
        "template_id": claim.template_id,
        "claim_kind": claim.kind,
        "polarity": str(claim.polarity),
        "subject_ref": claim.subject_ref,
        "sentence": claim.sentence,
        "citations": [
            {"record_type": item.record_type, "record_id": item.record_id}
            for item in claim.citations
        ],
    }
    if claim.outcome is ClaimOutcome.HELD:
        payload["held_reason"] = claim.reason
        payload["releasing_record"] = claim.releasing_record
    return Part(
        kind=kind,
        sequence=sequence,
        payload=payload,
        classification=classification,
        access_mode=AccessMode.RECORD_SET,
        access_set=_access_set_from_claim(claim),
    )


def connective_part(sentence: str, *, sequence: int, template_id: str) -> Part:
    """Joining text carries no assertion, so it is readable by the thread."""

    return Part(
        kind=PartKind.TEXT,
        sequence=sequence,
        payload={"template_id": template_id, "sentence": sentence},
        classification="INTERNAL",
        access_mode=AccessMode.SYSTEM_PUBLIC,
    )


def refusal_part(
    *, sequence: int, reason: str, releasing_record: str | None, classification: str = "INTERNAL"
) -> Part:
    """A first-class answer: what is true now, and what would change it."""

    return Part(
        kind=PartKind.REFUSAL,
        sequence=sequence,
        payload={"held_reason": reason, "releasing_record": releasing_record},
        classification=classification,
        access_mode=AccessMode.SYSTEM_PUBLIC,
    )


def withheld_part(*, sequence: int, verdict_ref: str, reason: str) -> Part:
    """Visible absence. A blocked or over-classified item never disappears."""

    return Part(
        kind=PartKind.CONTENT_WITHHELD,
        sequence=sequence,
        payload={"verdict_ref": verdict_ref, "reason": reason},
        classification="INTERNAL",
        access_mode=AccessMode.SYSTEM_PUBLIC,
    )


def user_part(
    text: str,
    *,
    sequence: int,
    author_principal: str,
    membership_epoch: int,
    classification: str,
    mentions: Collection[str] = (),
) -> Part:
    """User-authored content defaults to the thread's participants, redacted.

    This is the rule that closes the uncited-leak: a person quoting something
    restricted into a scope-visible thread does not thereby publish it.
    """

    return Part(
        kind=PartKind.TEXT,
        sequence=sequence,
        payload={"sentence": text, "authored": True, "mentions": sorted(set(mentions))},
        classification=classification,
        access_mode=AccessMode.PARTICIPANTS_AT_EPOCH,
        author_principal=author_principal,
        membership_epoch=membership_epoch,
    )


def reader_may_see(
    part: Part,
    *,
    reader_principal: str,
    authorized_records: Collection[tuple[str, str]],
    participants: Collection[str],
) -> bool:
    """The whole per-reader visibility decision, in one auditable function.

    An empty `RECORD_SET` envelope denies: a part that references nothing has
    no basis for being shown to anyone but its author, and defaulting such a
    part to visible is exactly how the first version of this design leaked.
    """

    if part.access_mode is AccessMode.SYSTEM_PUBLIC:
        return True
    if part.access_mode is AccessMode.AUTHOR_ONLY:
        return reader_principal == part.author_principal
    if part.access_mode is AccessMode.PARTICIPANTS_AT_EPOCH:
        return reader_principal in set(participants)
    if part.access_mode is AccessMode.DERIVED_SOURCES:
        # Persistence evaluates source-message envelopes. A detached in-memory
        # part has no source graph and therefore denies.
        return False
    if not part.access_set:
        return False
    authorized = set(authorized_records)
    return all(
        (reference.record_type, reference.record_id) in authorized for reference in part.access_set
    )


@dataclass(slots=True)
class PartBuilder:
    """Assembles an answer's parts in order, keeping sequence numbers honest."""

    parts: list[Part] = field(default_factory=list)

    def add(self, part: Part) -> Part:
        self.parts.append(part)
        return part

    def next_sequence(self) -> int:
        return len(self.parts)

    def citations(self) -> tuple[Citation, ...]:
        seen: list[Citation] = []
        for part in self.parts:
            for reference in part.access_set:
                candidate = Citation(reference.record_type, reference.record_id)
                if candidate not in seen:
                    seen.append(candidate)
        return tuple(seen)
