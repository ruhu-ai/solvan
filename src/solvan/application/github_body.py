"""Compose the text Solvan publishes to GitHub, or refuse to publish any.

This is the only place a GitHub body comes into existence.  Every publication
path takes a `RenderedBody`, and only this module can build one, so there is no
route by which model prose reaches a repository.

The composition rule is the registry's rule, applied one step more strictly:
a claim that cannot be verified is dropped, a held claim degrades to its
holding form, and if nothing survives, the body is not written at all.  A
comment made of nothing but hedges is worse than silence — it occupies a thread
with the appearance of an answer.

Specification 24 §3 governs.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path

from solvan.application.github_conversation import (
    MAXIMUM_BODY_BYTES,
    GitHubConversationError,
    RenderedBody,
)
from solvan.application.liaison.claims import (
    ClaimDraft,
    ClaimOutcome,
    ComposedClaim,
    compose_all,
)
from solvan.application.liaison.predicates import KNOWN_PREDICATES, ProjectionReader
from solvan.application.liaison.templates import (
    TemplateRegistry,
    TemplateRegistryError,
    load_registry,
    pin_registry,
)

_REGISTRY_PATH = Path(__file__).resolve().parents[3] / "config/github-comment-templates.yaml"

#: The exact registry the published sentence forms were reviewed at. Changing
#: config/github-comment-templates.yaml must change this in the same commit; a
#: mismatch refuses to publish rather than uttering new sentences in public.
PINNED_REGISTRY_DIGEST = "sha256:98fe799e268afb0475dac75d7408d0c271734af0c62206fbecdcf5a437d1d2e8"

#: A body carrying more than this many claims is a report, not a comment. The
#: ceiling is a legibility control as much as a size one: a thread reply nobody
#: finishes reading is a reply that failed to communicate.
_MAXIMUM_CLAIMS = 8

_SIGNATURE_INVESTIGATION = "— Solvan (automated investigation; no changes were made)"
_SIGNATURE_APPROVED = "— Solvan (automated; every action here passed human approval)"


@lru_cache(maxsize=1)
def publication_registry() -> TemplateRegistry:
    """Load and pin the publication registry, or refuse to compose anything.

    Cached because the digest check is the expensive part and the file cannot
    change under a running process without also changing the pin, which would
    have failed here at first call.
    """

    try:
        return pin_registry(
            load_registry(_REGISTRY_PATH, known_predicates=KNOWN_PREDICATES),
            PINNED_REGISTRY_DIGEST,
        )
    except TemplateRegistryError as error:
        raise GitHubConversationError(
            f"GitHub publication template registry is unusable: {error}"
        ) from error


def compose_publication_body(
    drafts: Sequence[ClaimDraft],
    *,
    reader: ProjectionReader,
    signature: str = _SIGNATURE_INVESTIGATION,
) -> RenderedBody:
    """Render one publishable body from verified claims, or refuse.

    Returns a body only when at least one claim was verified outright.  A set
    of drafts that all degraded to holding forms produces a refusal, not a
    comment: holding language is honest inside Solvan, where the reader can see
    the pending record it names, and misleading in a public thread, where they
    cannot.
    """

    if not drafts:
        raise GitHubConversationError("a publication needs at least one claim")
    if len(drafts) > _MAXIMUM_CLAIMS:
        raise GitHubConversationError(f"a publication carries at most {_MAXIMUM_CLAIMS} claims")
    if signature not in (_SIGNATURE_INVESTIGATION, _SIGNATURE_APPROVED):
        raise GitHubConversationError("publication signature is not an enumerated form")

    registry = publication_registry()
    composed, defects = compose_all(list(drafts), registry=registry, reader=reader)
    if not composed:
        raise GitHubConversationError(
            "no drafted claim survived verification; nothing is published"
        )
    if not any(claim.outcome is ClaimOutcome.VERIFIED for claim in composed):
        raise GitHubConversationError(
            "every drafted claim degraded to a holding form; nothing is published"
        )

    text = _assemble(composed, signature=signature, held=defects.held)
    if len(text.encode("utf-8")) > MAXIMUM_BODY_BYTES:
        raise GitHubConversationError("rendered body exceeds the bounded publication size")
    return RenderedBody(
        text=text,
        template_registry_digest=registry.digest,
        template_ids=tuple(dict.fromkeys(claim.template_id for claim in composed)),
    )


def _assemble(claims: Sequence[ComposedClaim], *, signature: str, held: int) -> str:
    """Lay the verified sentences out, then say what was withheld.

    Withholding is stated rather than silently applied.  A reader who sees only
    the claims that passed has no way to tell a complete answer from a partial
    one, and the difference matters when the next step is theirs.
    """

    verified = [claim for claim in claims if claim.outcome is ClaimOutcome.VERIFIED]
    holding = [claim for claim in claims if claim.outcome is ClaimOutcome.HELD]

    lines: list[str] = []
    for claim in verified:
        lines.append(f"- {claim.sentence}")
    if holding:
        lines.append("")
        for claim in holding:
            lines.append(f"- {claim.sentence}")
    if held and not holding:
        lines.append("")
        lines.append(
            f"- {held} further statement(s) were withheld because their supporting "
            "records are not present."
        )
    lines.append("")
    lines.append(signature)
    return "\n".join(lines)


def investigation_signature() -> str:
    return _SIGNATURE_INVESTIGATION


def approved_action_signature() -> str:
    return _SIGNATURE_APPROVED
