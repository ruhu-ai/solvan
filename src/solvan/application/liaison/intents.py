"""Closed, deterministic conversation-intent routing.

Intent makes the surface feel conversational; it is never authority. The
application owns the closed registry and the route associated with every
intent. Specification 14 §3.3 permits the *classifier* to be model-backed for
non-trivial language while requiring that a deterministic router own the closed
registry, the `NONE` paths, tool availability, and the gates. That split is
what this module implements:

- Language this router recognizes is resolved here, for free.
- Language it does not recognize resolves to `LEDGER_QUERY` with
  `needs_classification` set. That is the read-only `ASK` route, and the model
  call it already makes returns a bounded intent verdict alongside its answer
  selection. There is no second model call and no new budget line.

The router never asks a model to *widen* a route. `STEER_DRAFT` and
`ACTION_REFERENCE` are resolved here or not at all, because a classifier that
can reach a more powerful route is a classifier that can be argued into one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from solvan.application.liaison.question_registry import match_question
from solvan.application.liaison.replies import (
    MODEL_RESOLVABLE_INTENTS,
    ZERO_AUTHORITY_INTENTS,
    record_reply,
    scope_reply,
)


class ConversationIntent(StrEnum):
    SOCIAL = "SOCIAL"
    HELP = "HELP"
    LEDGER_QUERY = "LEDGER_QUERY"
    FOLLOW_UP = "FOLLOW_UP"
    STEER_DRAFT = "STEER_DRAFT"
    ACTION_REFERENCE = "ACTION_REFERENCE"
    GUIDANCE_REFERENCE = "GUIDANCE_REFERENCE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


_ROUTES = {
    ConversationIntent.SOCIAL: "NONE",
    ConversationIntent.HELP: "NONE",
    ConversationIntent.LEDGER_QUERY: "ASK",
    ConversationIntent.FOLLOW_UP: "ASK",
    ConversationIntent.STEER_DRAFT: "STEER",
    ConversationIntent.ACTION_REFERENCE: "ACT_SURFACE_ONLY",
    ConversationIntent.GUIDANCE_REFERENCE: "ASK",
    ConversationIntent.OUT_OF_SCOPE: "NONE",
}


def _check_registry_agrees_with_replies() -> None:
    """Refuse to import if the route table and the reply module have drifted.

    Three invariants, checked where they can still be fixed rather than
    discovered in a transcript: the zero-authority set is exactly the set that
    routes to NONE (the DDL welds intent to route and route to spend), every
    model-resolvable name is a real intent, and none of them reaches a route
    above ASK. An `assert` would vanish under `-O`, which is precisely the
    build where a silent widening would matter.
    """

    free = {str(intent) for intent, route in _ROUTES.items() if route == "NONE"}
    if free != ZERO_AUTHORITY_INTENTS:
        raise RuntimeError(
            f"zero-authority intents disagree: routes say {sorted(free)}, "
            f"replies say {sorted(ZERO_AUTHORITY_INTENTS)}"
        )
    known = {str(intent) for intent in ConversationIntent}
    unknown = MODEL_RESOLVABLE_INTENTS - known
    if unknown:
        raise RuntimeError(f"model-resolvable intents are not registered: {sorted(unknown)}")
    widened = sorted(
        name
        for name in MODEL_RESOLVABLE_INTENTS
        if _ROUTES[ConversationIntent(name)] not in {"NONE", "ASK"}
    )
    if widened:
        raise RuntimeError(f"a classifier must not reach these routes: {widened}")


_check_registry_agrees_with_replies()

_SOCIAL = re.compile(
    r"^(?:hi|hello|hey|yo|good\s+(?:morning|afternoon|evening)|thanks|thank\s+you|"
    r"cheers|ta|ok|okay|got\s+it|understood|nice|great|perfect)"
    r"(?:\s+(?:there|solvan|team|all))?[!.?\s]*$",
    re.IGNORECASE,
)
_HELP = re.compile(
    r"(?:what can you do|what can you help|how can you help|help me|"
    r"show me what you can do|what can i ask|what do you know|"
    r"what are you (?:for|able to do))",
    re.IGNORECASE,
)
_ACTION = re.compile(
    r"^(?:please\s+)?(?:roll(?:\s+it)?\s+back|rollback(?:\s+it)?|deploy(?:\s+it)?|"
    r"restart(?:\s+it)?|"
    r"recycle(?:\s+it)?|approve(?:\s+it)?|execute(?:\s+it)?|apply the change|fix it)[!.?\s]*$",
    re.IGNORECASE,
)
_GUIDANCE_REFERENCE = re.compile(r"^/[a-z0-9]+(?:[-/][a-z0-9]+)*(?:\s+.*)?$", re.IGNORECASE)
_STEER = re.compile(
    r"\b(?:check|inspect|search|query|look at|pull|read)\b.*"
    r"\b(?:logs?|traces?|metrics?|telemetry)\b",
    re.IGNORECASE,
)
_FOLLOW_UP = re.compile(
    r"^(?:why|how|when|after that|what about|and then|did it|was it|that action|"
    r"the second|tell me more|i mean|sorry|no,|actually)\b",
    re.IGNORECASE,
)
#: Vocabulary that makes an utterance operational on its face. This is a fast
#: path, not a gate: text that misses it still reaches the read-only `ASK`
#: route through `needs_classification`. It was previously the *only* way to
#: avoid being declared off-topic, which is why "what stage are we at?" —
#: carrying none of these words — was answered "I can only help with this
#: incident".
_OPERATIONAL = re.compile(
    r"\b(?:incident|failure|failing|error|errors|outage|degraded|latency|impact|"
    r"customer|customers|service|revision|release|deploy|deployed|deployment|"
    r"rollback|rolled|recovery|recovered|recover|root cause|cause|evidence|"
    r"verification|verified|database|request|requests|traffic|alert|alerts|"
    r"stage|status|state|progress|update|updates|timeline|owner|owns|"
    r"next step|next steps|blocked|blocker|waiting|approval|approve|"
    r"resolved|resolve|cleared|clear|closed|close|mitigated|mitigation|"
    r"fixed|fix|broken|down|sev|severity|postmortem|remediation|"
    r"data loss|duplicate|duplicates|blast radius|downstream|runbook|"
    r"eta|how long|since when)\b",
    re.IGNORECASE,
)
#: Content-production requests that are plainly not about operational records.
#: Kept as a positive test so the obvious off-domain case stays free of a model
#: call, per §3.3's worked example. It is deliberately narrow: anything it does
#: not catch reaches the bounded classifier rather than a refusal, because
#: refusing an operational question is the costlier mistake.
_OFF_DOMAIN = re.compile(
    r"\b(?:write|compose|draft|generate|create|invent|translate|tell|sing)\b[^?]*"
    r"\b(?:poem|poems|joke|jokes|story|stories|song|songs|lyrics|essay|recipe|"
    r"marketing|advert|advertisement|blog|tweet|novel|screenplay|homework|"
    r"business plan|sales pitch)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class IntentResolution:
    intent: ConversationIntent
    authority_route: str
    #: True when the router recognized no shape and handed the utterance to
    #: the read-only route for a bounded model verdict. The durable intent is
    #: already `LEDGER_QUERY`: the turn will spend a model call whatever the
    #: verdict says, and the record must report that honestly.
    needs_classification: bool = False


def resolve_intent(text: str, *, has_prior_answer: bool) -> IntentResolution:
    """Resolve a closed intent without granting any capability.

    Action language resolves only to surfacing an existing governed action; it
    can never perform one. Unrecognized language resolves to the read-only Ask
    route rather than to a refusal, because a surface that tells an operator
    their question about the incident is off-topic is wrong far more often
    than it is right.
    """

    value = " ".join(text.strip().split())
    if not value:
        return IntentResolution(ConversationIntent.SOCIAL, _ROUTES[ConversationIntent.SOCIAL])
    if _SOCIAL.fullmatch(value):
        intent = ConversationIntent.SOCIAL
    elif _HELP.search(value):
        intent = ConversationIntent.HELP
    elif _ACTION.search(value):
        intent = ConversationIntent.ACTION_REFERENCE
    elif _GUIDANCE_REFERENCE.fullmatch(value):
        intent = ConversationIntent.GUIDANCE_REFERENCE
    elif _STEER.search(value):
        intent = ConversationIntent.STEER_DRAFT
    elif has_prior_answer and _FOLLOW_UP.search(value):
        intent = ConversationIntent.FOLLOW_UP
    elif match_question(value) is not None or _OPERATIONAL.search(value):
        intent = ConversationIntent.LEDGER_QUERY
    elif _OFF_DOMAIN.search(value):
        intent = ConversationIntent.OUT_OF_SCOPE
    else:
        # Not recognized — which is a statement about this router's vocabulary,
        # not about the operator's question. Hand it to the read-only route and
        # let the bounded classifier decide (§3.3).
        return IntentResolution(
            ConversationIntent.LEDGER_QUERY,
            _ROUTES[ConversationIntent.LEDGER_QUERY],
            needs_classification=True,
        )
    return IntentResolution(intent, _ROUTES[intent])


def deterministic_reply(intent: ConversationIntent, text: str) -> tuple[str, str] | None:
    """Return the pinned template id and phrase for a zero-authority intent."""

    return record_reply(str(intent), text)


def scope_deterministic_reply(intent: ConversationIntent, text: str) -> tuple[str, str] | None:
    """Return scope-Chat wording from the pinned template registry."""

    return scope_reply(str(intent), text)
