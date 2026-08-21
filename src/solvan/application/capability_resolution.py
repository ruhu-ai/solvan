"""One rule for what an Agent may reach, and the chain that says why.

Two rules used to answer this question. `ToolCatalog.resolve` and the SQL run
binder resolve a Tool for an Agent against profile membership, the requester
declaration, revision lifecycle, classification and region, a registered Gateway
route, the connection binding kind, and — only when that kind reaches an
external system — a fresh capability probe. The operator console resolved
`lifecycle == APPROVED and a fresh probe exists`, against declared requesters
rather than profile membership, and rendered every other state as the word
`Denied`. The two disagreed on fourteen of twenty-three rows, and a matrix
consulted precisely when someone needs to know what is allowed is the worst
place for a second opinion.

This module holds the rule both consume. It takes the complete observed chain
and folds it into one verdict that names the layer which decided, so a cell can
cite `PROFILE_MEMBERSHIP` or `CAPABILITY_PROBE` rather than reprinting the
destination host beside itself.

Three properties are deliberate:

  * a layer nobody observed never folds to `ALLOWED`. Absence of evidence is
    `NOT_EVALUATED`, which is neither a grant nor a refusal;
  * an incomplete or duplicated chain refuses outright rather than resolving
    what it happens to hold. Visibility is never granted by omission, and a
    duplicated layer is the shape of the projection bug this replaces, where
    several probe receipts collapsed onto one key and the last one silently won;
  * a Tool in no approved profile is `NOT_REGISTERED`, not `DENIED`. Nothing
    refused a request; no profile ever offered the capability.

Governing records: specification 06 §Capabilities & Policy, specification 16 §5,
PR-031, PR-032, PR-033.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class CapabilityResolutionError(RuntimeError):
    """The observed chain is incomplete, duplicated, or internally impossible."""


class CapabilityLayer(StrEnum):
    """The authorities a capability passes through, coarsest first.

    The order is load-bearing twice: it is the order the provenance chain is
    rendered in, and it is the precedence that picks the winning refusal when
    more than one layer refuses. Coarsest first means the answer to "why can
    this Agent not reach this destination" is the most general true reason
    rather than the last one evaluated — a Tool in no profile is reported as
    unregistered even if its probe is also stale, because publishing the probe
    would not change the outcome.
    """

    PROFILE_MEMBERSHIP = "PROFILE_MEMBERSHIP"
    REQUESTER_DECLARATION = "REQUESTER_DECLARATION"
    REVISION_LIFECYCLE = "REVISION_LIFECYCLE"
    CLASSIFICATION_AND_REGION = "CLASSIFICATION_AND_REGION"
    GATEWAY_ROUTE = "GATEWAY_ROUTE"
    CONNECTION_BINDING = "CONNECTION_BINDING"
    CAPABILITY_PROBE = "CAPABILITY_PROBE"


CAPABILITY_LAYERS: tuple[CapabilityLayer, ...] = tuple(CapabilityLayer)

#: A capability that reaches no external system binds no connection and can hold
#: no probe receipt: `tool_probe_receipts` references `tenant_connections`, so
#: for an internal provider one cannot exist even in principle. Every other
#: layer applies to every capability, the Gateway route included — the binder
#: checks the route before it branches on binding kind, which is why a
#: compute-only Tool still cannot read `ALLOWED` until a route is registered.
OPTIONAL_LAYERS: frozenset[CapabilityLayer] = frozenset(
    {CapabilityLayer.CONNECTION_BINDING, CapabilityLayer.CAPABILITY_PROBE}
)


class LayerState(StrEnum):
    """What one authority said, including the two ways it can say nothing."""

    SATISFIED = "SATISFIED"
    REFUSED = "REFUSED"
    #: This layer cannot apply to this capability. Distinct from `SATISFIED`:
    #: nothing was checked, and nothing needed to be.
    NOT_APPLICABLE = "NOT_APPLICABLE"
    #: This layer applies and no record has observed it. Distinct from
    #: `REFUSED`: no authority has refused anything.
    NOT_EVALUATED = "NOT_EVALUATED"


class CapabilityVerdict(StrEnum):
    """What the cell says, in the vocabulary specification 06 §Capabilities defines."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    NOT_REGISTERED = "NOT_REGISTERED"
    NOT_EVALUATED = "NOT_EVALUATED"


@dataclass(frozen=True, slots=True)
class LayerOutcome:
    """One authority's observation, carrying the record that supports it."""

    layer: CapabilityLayer
    state: LayerState
    #: The record a reader can open: a profile revision, an approval reference,
    #: a probe receipt. Empty when the layer did not apply.
    reference: str = ""
    observed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    """One verdict, the layer that produced it, and the whole chain behind it."""

    verdict: CapabilityVerdict
    winning_layer: CapabilityLayer
    winning_reference: str
    layers: tuple[LayerOutcome, ...]


def resolve_capability(*, layers: Sequence[LayerOutcome]) -> CapabilityDecision:
    """Fold a complete observed chain into one verdict.

    Refusal outranks absence: a layer that refused is a record saying no, and no
    later evidence could overturn it, so the verdict stays `DENIED` even when a
    further layer is unobserved. Absence outranks satisfaction in the other
    direction — one unobserved applicable layer is enough to withhold `ALLOWED`.
    """

    observed = _indexed(layers)
    membership = observed[CapabilityLayer.PROFILE_MEMBERSHIP]
    if membership.state is LayerState.REFUSED:
        return _decide(CapabilityVerdict.NOT_REGISTERED, membership, observed)
    ordered = tuple(observed[layer] for layer in CAPABILITY_LAYERS)
    refused = next((item for item in ordered if item.state is LayerState.REFUSED), None)
    if refused is not None:
        return _decide(CapabilityVerdict.DENIED, refused, observed)
    unevaluated = next((item for item in ordered if item.state is LayerState.NOT_EVALUATED), None)
    if unevaluated is not None:
        return _decide(CapabilityVerdict.NOT_EVALUATED, unevaluated, observed)
    # Nothing refused and nothing is outstanding, so the grant that made this
    # capability reachable is what the cell cites.
    return _decide(CapabilityVerdict.ALLOWED, membership, observed)


def _indexed(layers: Sequence[LayerOutcome]) -> dict[CapabilityLayer, LayerOutcome]:
    """Accept the chain only when it is complete, unambiguous, and possible."""

    observed: dict[CapabilityLayer, LayerOutcome] = {}
    for outcome in layers:
        if outcome.layer in observed:
            raise CapabilityResolutionError(
                f"{outcome.layer} was observed more than once; a capability chain "
                "records one outcome per authority"
            )
        observed[outcome.layer] = outcome
    missing = [layer for layer in CAPABILITY_LAYERS if layer not in observed]
    if missing:
        raise CapabilityResolutionError(
            f"the capability chain omits {', '.join(missing)}; an unobserved authority "
            "is stated as NOT_EVALUATED rather than left out"
        )
    for layer, outcome in observed.items():
        if outcome.state is LayerState.NOT_APPLICABLE and layer not in OPTIONAL_LAYERS:
            raise CapabilityResolutionError(f"{layer} applies to every capability")
    return observed


def _decide(
    verdict: CapabilityVerdict,
    winner: LayerOutcome,
    observed: dict[CapabilityLayer, LayerOutcome],
) -> CapabilityDecision:
    return CapabilityDecision(
        verdict=verdict,
        winning_layer=winner.layer,
        winning_reference=winner.reference,
        layers=tuple(observed[layer] for layer in CAPABILITY_LAYERS),
    )
