"""The turn engine: one question in, one gated, cited answer out.

The engine is deliberately indifferent to where drafts come from. A model in a
tool loop and the enumerated question set produce the same `ClaimDraft`s, and
both pass through the same predicate and refusal gates before anything is
rendered. That is the whole point: safety lives in the gates and the tool belt,
not in trusting a particular drafter.

Budgets, the doom-loop guard, and the escalation valve are here because they
are properties of a turn rather than of a claim. Specification 14 §12.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from solvan.application.liaison.anchors import Anchor
from solvan.application.liaison.budgets import (
    DailyBudget,
    TurnBudget,
    TurnUsage,
    default_daily_budget,
    default_turn_budget,
)
from solvan.application.liaison.claims import (
    ClaimDraft,
    CompositionDefects,
    compose_claim,
)
from solvan.application.liaison.granted_reader import DoomLoopGuard, GrantedReader
from solvan.application.liaison.grants import (
    ConversationReadGrant,
    GrantError,
)
from solvan.application.liaison.parts import (
    AccessMode,
    Part,
    PartBuilder,
    PartKind,
    claim_part,
    connective_part,
)
from solvan.application.liaison.predicates import ProjectionReader
from solvan.application.liaison.replies import MODEL_RESOLVABLE_INTENTS, reply_for
from solvan.application.liaison.templates import TemplateRegistry
from solvan.domain import new_identifier

#: Re-exported so callers keep one import site for a turn's shape and its
#: ceilings; the definitions live in `budgets` because they are configuration.
__all__ = [
    "Composer",
    "Composition",
    "ConnectiveDraft",
    "DailyBudget",
    "DoomLoopGuard",
    "Draft",
    "Escalation",
    "GrantedReader",
    "Hold",
    "PartSink",
    "TurnBudget",
    "TurnResult",
    "TurnState",
    "TurnUsage",
    "default_daily_budget",
    "default_turn_budget",
    "run_turn",
    "visible_parts",
]


class TurnState(StrEnum):
    STREAMING = "STREAMING"
    PARKED = "PARKED"
    COMPLETED = "COMPLETED"
    INTERRUPTED = "INTERRUPTED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class ConnectiveDraft:
    """Joining text, restricted to an enumerated phrase (§7)."""

    template_id: str
    phrase: str


Draft = ClaimDraft | ConnectiveDraft


@dataclass(frozen=True, slots=True)
class Escalation:
    """What the ledger cannot answer, and the Steer that would answer it.

    An Ask that ends here is not a dead end; it names the missing read and
    offers the bounded step that would obtain it (§4.1).
    """

    missing: str
    proposed_step: str
    tool_profile: tuple[str, ...] = ("metrics.read",)


@dataclass(frozen=True, slots=True)
class Hold:
    """A question the ledger could answer, but not at this anchor.

    Distinct from `Escalation` on purpose. An escalation says "no record holds
    this; here is the bounded read that would get it". A hold says "the record
    that holds this has not been named yet". Offering a telemetry read for the
    second is how a scope conversation ends up proposing a fresh metrics read
    for a question its own ledger already answers once narrowed (§"Scope Chat
    is Ask-first").
    """

    sentence: str
    held_reason: str
    releasing_record: str


@dataclass(frozen=True, slots=True)
class Composition:
    """What a drafter produced, before any gate has run."""

    drafts: tuple[Draft, ...] = ()
    escalation: Escalation | None = None
    #: A typed hold naming the missing target condition, never a Steer.
    hold: Hold | None = None
    #: Set when a bounded classifier resolved the utterance to a
    #: zero-authority intent (§3.3). The engine renders the pinned phrase; the
    #: durable intent stays what the router assigned, because the turn did
    #: spend a model call and the record must say so.
    reply_intent: str | None = None
    #: Enumerated follow-ups the reader may ask next, by question id.
    suggested: tuple[str, ...] = ()
    model_calls: int = 0
    #: Non-read tools executed by the composer. Projection reads are counted
    #: by ``GrantedReader`` at the point of authorization.
    tool_calls: int = 0
    tokens: int = 0
    screening_blocked: bool = False
    #: A typed human handoff emitted only by an enumerated park tool.
    parked_request: Mapping[str, Any] | None = None
    #: True when the model planner failed and the deterministic path answered
    #: instead. A degradation that no one can see is not a tested degradation
    #: path, so this travels to the reader rather than only to a log.
    provider_degraded: bool = False


class Composer(Protocol):
    """Produces drafts for one question. Never renders, never authorizes."""

    def compose(
        self,
        *,
        question: str,
        anchor: Anchor,
        reader: ProjectionReader,
        provider_input: str | None = None,
    ) -> Composition: ...


class PartSink(Protocol):
    """Receives typed, gated parts for private durable streaming."""

    def emit(self, part: Part) -> None: ...


@dataclass(slots=True)
class TurnResult:
    """The durable outcome of one turn."""

    state: TurnState
    parts: tuple[Part, ...]
    usage: TurnUsage
    defects: CompositionDefects
    escalation: Escalation | None = None
    suggested: tuple[str, ...] = ()
    #: The ceilings this turn actually ran under, so the surface reports the
    #: budget that applied rather than a copy of the defaults.
    budget: TurnBudget = field(default_factory=TurnBudget)

    def sentences(self) -> tuple[str, ...]:
        return tuple(
            str(part.payload.get("sentence", ""))
            for part in self.parts
            if part.kind in (PartKind.CLAIM, PartKind.TEXT, PartKind.REFUSAL)
            and part.payload.get("sentence")
        )


def run_turn(
    *,
    question: str,
    anchor: Anchor,
    reader: ProjectionReader,
    registry: TemplateRegistry,
    composer: Composer,
    grant: ConversationReadGrant,
    provider_input: str | None = None,
    budget: TurnBudget | None = None,
    classification: str = "INTERNAL",
    part_sink: PartSink | None = None,
) -> TurnResult:
    """Compose, gate, and assemble one answer.

    Every exit is durable and honest: an exhausted budget says so, a refused
    grant errors rather than degrading, and a claim that cannot be verified is
    absent rather than softened.
    """

    ceilings = budget or default_turn_budget()
    # A composer reports the work it actually performed. Deterministic local
    # composition is zero-model; an ADK query head reports one attempted model
    # call even when it degrades to the deterministic path. Starting at one
    # made local development claim provider usage that never happened.
    usage = TurnUsage()
    defects = CompositionDefects()
    builder = PartBuilder()

    def add_part(part: Part) -> None:
        """Persist only after the deterministic gates have built a typed part."""

        builder.add(part)
        if part_sink is not None:
            part_sink.emit(part)

    granted = GrantedReader(reader, grant=grant, usage=usage, guard=DoomLoopGuard())
    try:
        if provider_input is None:
            composition = composer.compose(question=question, anchor=anchor, reader=granted)
        else:
            composition = composer.compose(
                question=question,
                anchor=anchor,
                reader=granted,
                provider_input=provider_input,
            )
        usage.model_calls += composition.model_calls
        usage.tool_calls += composition.tool_calls
        usage.tokens += composition.tokens
        if composition.provider_degraded:
            defects.provider_degraded += 1
            defects.reasons.append("the model planner failed; the deterministic path answered")
    except GrantError as error:
        add_part(
            Part(
                kind=PartKind.ERROR,
                sequence=builder.next_sequence(),
                payload={"error": str(error)},
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )
        return TurnResult(TurnState.ERROR, tuple(builder.parts), usage, defects, budget=ceilings)

    if granted.looped:
        # A repeated read is a question for the operator, not more spending.
        add_part(
            Part(
                kind=PartKind.PARKED_REQUEST,
                sequence=builder.next_sequence(),
                payload={
                    "kind": "QUESTION",
                    "prompt": "I keep reading the same record without progress. "
                    "Which part of this should I look at?",
                },
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )
        return TurnResult(TurnState.PARKED, tuple(builder.parts), usage, defects, budget=ceilings)

    exceeded = ceilings.exceeded_by(usage)
    if exceeded is not None:
        add_part(
            Part(
                kind=PartKind.BUDGET_NOTE,
                sequence=builder.next_sequence(),
                payload={"ceiling": exceeded, "reached": True},
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )
        return TurnResult(
            TurnState.COMPLETED, tuple(builder.parts), usage, defects, budget=ceilings
        )

    if composition.screening_blocked:
        add_part(
            Part(
                kind=PartKind.CONTENT_WITHHELD,
                sequence=builder.next_sequence(),
                payload={"verdict": "MODEL_ARMOR_BLOCKED", "content_stored": False},
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )
        return TurnResult(
            TurnState.COMPLETED, tuple(builder.parts), usage, defects, budget=ceilings
        )

    if composition.reply_intent is not None:
        # A bounded classifier resolved this utterance to a zero-authority
        # intent (§3.3). The model chose *which* enumerated reply applies; the
        # words are still an instance of a pinned connective template, and a
        # verdict outside the model-resolvable set is a bug, not a route.
        if composition.reply_intent not in MODEL_RESOLVABLE_INTENTS:
            raise ValueError(
                f"a classifier may not resolve the intent {composition.reply_intent!r}"
            )
        resolved = reply_for(anchor, composition.reply_intent, question)
        if resolved is not None:
            template_id, phrase = resolved
            add_part(
                connective_part(
                    registry.connective(template_id).render(phrase),
                    sequence=builder.next_sequence(),
                    template_id=template_id,
                )
            )
            return TurnResult(
                TurnState.COMPLETED, tuple(builder.parts), usage, defects, budget=ceilings
            )

    if composition.parked_request is not None:
        payload = dict(composition.parked_request)
        payload.setdefault("request_id", new_identifier("prk"))
        add_part(
            Part(
                kind=PartKind.PARKED_REQUEST,
                sequence=builder.next_sequence(),
                payload=payload,
                classification=classification,
                access_mode=AccessMode.AUTHOR_ONLY,
                author_principal=grant.principal,
            )
        )
        return TurnResult(TurnState.PARKED, tuple(builder.parts), usage, defects, budget=ceilings)

    # The gate reads through the grant, not around it. Handing it the raw
    # reader verified a model-drafted citation against everything the
    # principal could reach, so a citation the turn's anchor never covered was
    # resolved, slot-filled, and rendered as a verified fact.
    gate_reader = granted.for_verification()
    try:
        for draft in composition.drafts:
            if isinstance(draft, ConnectiveDraft):
                connective = registry.connective(draft.template_id)
                add_part(
                    connective_part(
                        connective.render(draft.phrase),
                        sequence=builder.next_sequence(),
                        template_id=draft.template_id,
                    )
                )
                continue
            claim = compose_claim(draft, registry=registry, reader=gate_reader, defects=defects)
            if not claim.deliverable:
                continue
            add_part(
                claim_part(claim, sequence=builder.next_sequence(), classification=classification)
            )
    except GrantError as error:
        # A grant that lapses or never covered the projection read is a stated
        # failure. Delivering the claims already gated and then falling silent
        # would let an expired authority look like an ordinary short answer.
        add_part(
            Part(
                kind=PartKind.ERROR,
                sequence=builder.next_sequence(),
                payload={"error": str(error)},
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )
        return TurnResult(TurnState.ERROR, tuple(builder.parts), usage, defects, budget=ceilings)

    if composition.hold is not None:
        # Held, not escalated: the answer exists in the ledger and is waiting
        # on a target, so this must never render as a fresh telemetry read.
        add_part(
            Part(
                kind=PartKind.REFUSAL,
                sequence=builder.next_sequence(),
                payload={
                    "sentence": composition.hold.sentence,
                    "held_reason": composition.hold.held_reason,
                    "releasing_record": composition.hold.releasing_record,
                },
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )

    if composition.escalation is not None:
        add_part(
            Part(
                kind=PartKind.STEER_DRAFT,
                sequence=builder.next_sequence(),
                payload={
                    "missing": composition.escalation.missing,
                    "proposed_step": composition.escalation.proposed_step,
                    "tool_profile": list(composition.escalation.tool_profile),
                    "requires_confirmation": True,
                },
                classification=classification,
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
        )

    return TurnResult(
        state=TurnState.COMPLETED,
        parts=tuple(builder.parts),
        usage=usage,
        defects=defects,
        escalation=composition.escalation,
        suggested=composition.suggested,
        budget=ceilings,
    )


def visible_parts(
    result: TurnResult,
    *,
    reader_principal: str,
    authorized_records: Sequence[tuple[str, str]],
    participants: Sequence[str],
) -> tuple[Part, ...]:
    """Project one turn for one reader. Withheld parts stay, and say so."""

    from solvan.application.liaison.parts import reader_may_see, withheld_part

    projected: list[Part] = []
    for part in result.parts:
        if reader_may_see(
            part,
            reader_principal=reader_principal,
            authorized_records=authorized_records,
            participants=participants,
        ):
            projected.append(part)
        else:
            projected.append(
                withheld_part(
                    sequence=part.sequence,
                    verdict_ref="reader-authority",
                    reason="This part cites a record outside your authority.",
                )
            )
    return tuple(projected)
