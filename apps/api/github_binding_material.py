"""The exact thing each GitHub binding challenge authorizes.

One module for all three forms, because they exist to be compared. The console
computes the same string to request a step-up and the route recomputes it to
spend the challenge, so a drift between the two halves does not fail loudly —
it refuses every action with "the material changed", which reads like the
feature is broken rather than like the strings disagree.

Flat delimited strings rather than canonical JSON, because a browser has to
reproduce them byte for byte and a second canonical-JSON implementation would
be a silent-drift hazard for no benefit.

None of them carry the tenant scope. The challenge record is already looked up
scope-bound when it is spent, so repeating the scope here would add nothing to
check while forcing the console to know three identifiers it otherwise never
needs — which is how the two halves come to disagree.
"""

from __future__ import annotations

from solvan.application.github import GitHubOperationKind

#: Investigate-only authority, repeated here so the bulk-connect material does
#: not depend on the routes module and create an import cycle.
_INVESTIGATE_ONLY: tuple[GitHubOperationKind, ...] = ("SYNC_PULL_REQUEST",)


def binding_material(
    *,
    installation_id: int,
    owner: str,
    name: str,
    classification: str,
    allowed_operations: tuple[GitHubOperationKind, ...],
) -> str:
    """The exact binding a challenge authorizes, as both sides compute it.

    Re-authenticating to bind one repository must not return authority to bind
    another, or to bind the same one with more authority than was shown. A page
    altered while the operator was away at the step-up produces a different
    string, and the challenge refuses.
    """

    return (
        f"github-bind:v1:{installation_id}:{owner}/{name}:{classification}"
        f":{','.join(sorted(allowed_operations))}"
    )


def connect_all_material(*, installation_id: int, classification: str) -> str:
    """The exact bulk connect a challenge authorizes.

    Deliberately not a digest of the repository list. That list is read from
    GitHub after the challenge is spent, and binding the challenge to it would
    either require reading GitHub before authenticating the operator, or refuse
    the connect whenever a repository was added between the two reads. What the
    operator authorizes is "everything this installation reaches,
    investigate-only" — which is what this string says.
    """

    return (
        f"github-connect-all:v1:{installation_id}:{classification}"
        f":{','.join(sorted(_INVESTIGATE_ONLY))}"
    )


def regrant_material(
    *,
    repository_id: str,
    allowed_operations: tuple[str, ...],
    classification: str,
) -> str:
    """The exact widening a challenge authorizes.

    This one carries the authority itself, because that is precisely what the
    operator is being asked to approve. A page altered while they were away
    re-authenticating produces a different string and the challenge refuses.
    """

    return (
        f"github-regrant:v1:{repository_id}:{classification}:{','.join(sorted(allowed_operations))}"
    )
