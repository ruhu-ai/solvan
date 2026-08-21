"""Zero-authority replies, held apart from the router that usually picks them.

These belong with the intent registry conceptually, but they cannot live there:
`intents` imports `questions`, `questions` imports `engine`, and the engine now
needs to render one of these when the *model* — rather than the deterministic
router — resolves an utterance to a zero-authority intent (§3.3). A leaf module
breaks that cycle without duplicating the phrases, which is the failure mode
that matters: two copies of a pinned sentence is one copy that can drift.

Every phrase here is an instance of an enumerated connective template. Nothing
in this module authors a factual assertion; the phrases are conversational
scaffolding whose template ids are pinned by digest in the claim registry.
"""

from __future__ import annotations

from solvan.application.liaison.anchors import Anchor, AnchorKind

#: Intents that resolve to a pinned phrase and spend nothing. Kept as strings
#: rather than importing `ConversationIntent`, which would reintroduce the
#: cycle this module exists to break; `intents` owns the enum and asserts the
#: two agree.
ZERO_AUTHORITY_INTENTS = frozenset({"SOCIAL", "HELP", "OUT_OF_SCOPE"})

#: What a model classifier may resolve an ambiguous utterance to. Every member
#: is bounded above by the `ASK` route, so a model can never talk the surface
#: into `STEER` or `ACT_SURFACE_ONLY`; those stay deterministic-only (§3.3).
MODEL_RESOLVABLE_INTENTS = frozenset({"LEDGER_QUERY", "SOCIAL", "HELP", "OUT_OF_SCOPE"})


def record_reply(intent: str, text: str) -> tuple[str, str] | None:
    """The pinned template id and phrase for a record-anchored conversation."""

    if intent == "SOCIAL":
        phrase = (
            "You're welcome."
            if "thank" in text.lower()
            else "Hello. Ask me about this incident, its impact, evidence, actions, or recovery."
        )
        return "SOCIAL_REPLY", phrase
    if intent == "HELP":
        return (
            "HELP_REPLY",
            "I can explain what happened, measured impact, evidence, governed actions, "
            "and independently verified recovery for this incident.",
        )
    if intent == "OUT_OF_SCOPE":
        return (
            "OUT_OF_SCOPE_REPLY",
            "I can only help with this incident and its governed operational records.",
        )
    return None


def scope_reply(intent: str, text: str) -> tuple[str, str] | None:
    """The pinned wording for a scope or service-window conversation.

    A scope thread is deliberately not an incident thread. Its zero-authority
    replies must say so plainly rather than implying that a vague request has
    acquired a target, a read grant, or action authority.
    """

    if intent == "SOCIAL":
        phrase = (
            "You're welcome."
            if "thank" in text.lower()
            else "Hello. Ask me about reader-visible records in the current workspace."
        )
        return "SCOPE_SOCIAL_REPLY", phrase
    if intent == "HELP":
        return (
            "SCOPE_HELP_REPLY",
            "I can summarize reader-visible incidents, evidence, governed actions, "
            "and recovery records in this workspace.",
        )
    if intent == "OUT_OF_SCOPE":
        return (
            "SCOPE_BOUNDARY_REPLY",
            "To request fresh telemetry, investigation, an approval, or an action, "
            "select a bounded incident or service window first.",
        )
    return None


def reply_for(anchor: Anchor, intent: str, text: str) -> tuple[str, str] | None:
    """Pick the wording the anchor calls for.

    A service window is not a record either: a question it cannot answer must
    not be refused in words that claim one incident is in view.
    """

    if anchor.kind is AnchorKind.RECORD:
        return record_reply(intent, text)
    return scope_reply(intent, text)
