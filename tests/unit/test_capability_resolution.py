"""The contract for one capability-resolution rule.

Two rules used to answer the same question. The run binder resolves a Tool for
an Agent against profile membership, the requester declaration, revision
lifecycle, classification and region, a registered Gateway route, the connection
binding kind, and — only when that kind reaches an external system — a fresh
capability probe. The operator console resolved `lifecycle == APPROVED and a
fresh probe exists`, against declared requesters rather than profile membership.
The two disagreed on fourteen of the twenty-three rows the Capabilities & Policy
table renders, and every disagreement was rendered as the word `Denied`, which
no record in the database ever said.

These tests describe the single rule both must consume: an ordered layer chain
folded into one verdict, where the winning layer is named rather than implied.

They were written before `solvan.application.capability_resolution` existed and
carried `xfail(strict=True)` until it did, so the contract was recorded
executably without turning the shared worktree's one authoritative gate red for
lanes that did not cause the defect. Strict is what ended that state: the moment
Phase 1 made them pass, the unexpected pass failed the suite and the markers
came off. The projection that renders this rule is still Phase 2 —
`tests/integration/test_console_capability_projection.py` holds that half.

Governing records: specification 06 §Capabilities & Policy (cells read `allowed`,
`denied`, or `not registered`, and selecting one opens each source layer),
specification 16 §5 (profile resolution), PR-031, PR-032, PR-033.
"""

from __future__ import annotations

import pytest

from solvan.application.capability_resolution import (
    CAPABILITY_LAYERS,
    CapabilityLayer,
    CapabilityResolutionError,
    CapabilityVerdict,
    LayerOutcome,
    LayerState,
    resolve_capability,
)
from tools.check_capability_parity import capability_parity_findings

#: The order is load-bearing twice over: it is the order `ProvenanceDiff` renders
#: the chain in, and it is the precedence that decides which refusal is the
#: winning one when several layers refuse at once. Coarsest authority first, so
#: the answer to "why can this Agent not reach this destination" is the most
#: general true reason rather than the last one evaluated. Spelled out as
#: strings so a reordering of the enum is a visible change here rather than a
#: silent one.
EXPECTED_LAYER_ORDER = (
    "PROFILE_MEMBERSHIP",
    "REQUESTER_DECLARATION",
    "REVISION_LIFECYCLE",
    "CLASSIFICATION_AND_REGION",
    "GATEWAY_ROUTE",
    "CONNECTION_BINDING",
    "CAPABILITY_PROBE",
)


def _outcome(layer: str, state: str, reference: str = "ref://test") -> LayerOutcome:
    return LayerOutcome(layer=CapabilityLayer(layer), state=LayerState(state), reference=reference)


def _all_satisfied() -> list[LayerOutcome]:
    return [_outcome(layer, "SATISFIED") for layer in EXPECTED_LAYER_ORDER]


def test_layer_order_is_the_rendered_provenance_order() -> None:
    assert tuple(layer.value for layer in CAPABILITY_LAYERS) == EXPECTED_LAYER_ORDER


def test_a_tool_in_no_profile_reads_not_registered_rather_than_denied() -> None:
    """`github_pr_diff_read` is in the catalog and in no approved profile.

    Specification 06 gives this its own cell value. Collapsing it into `denied`
    tells an operator that a policy refused a request, when the truth is that no
    profile has ever offered the capability to that Agent.
    """

    layers = _all_satisfied()
    layers[0] = _outcome("PROFILE_MEMBERSHIP", "REFUSED")
    decision = resolve_capability(layers=layers)
    assert decision.verdict is CapabilityVerdict.NOT_REGISTERED
    assert decision.winning_layer is CapabilityLayer.PROFILE_MEMBERSHIP


@pytest.mark.parametrize("unevaluated", EXPECTED_LAYER_ORDER)
def test_an_unevaluated_layer_never_folds_to_allowed(unevaluated: str) -> None:
    """Absence of evidence is never permission.

    This is the invariant the whole change exists to protect. Whatever else it
    alters, it must never turn a layer nobody has observed into an
    operator-facing claim that the capability is allowed.
    """

    layers = [
        _outcome(layer, "NOT_EVALUATED" if layer == unevaluated else "SATISFIED")
        for layer in EXPECTED_LAYER_ORDER
    ]
    decision = resolve_capability(layers=layers)
    assert decision.verdict is CapabilityVerdict.NOT_EVALUATED
    assert decision.winning_layer is CapabilityLayer(unevaluated)


def test_an_unevaluated_layer_does_not_become_a_refusal_either() -> None:
    """The inverse error, and the one shipping today.

    An unprobed Tool is rendered `Denied` in a danger tone. That reads as an
    enforcement decision protecting the operator, so it is not a safe default:
    it is a different fabricated claim, and on the actuator row it understates
    production mutation capability rather than overstating it.
    """

    layers = _all_satisfied()
    layers[-1] = _outcome("CAPABILITY_PROBE", "NOT_EVALUATED")
    assert resolve_capability(layers=layers).verdict is not CapabilityVerdict.DENIED


def test_the_first_refusing_layer_is_the_winning_provenance() -> None:
    layers = _all_satisfied()
    layers[2] = _outcome("REVISION_LIFECYCLE", "REFUSED", "revision://draft")
    layers[6] = _outcome("CAPABILITY_PROBE", "REFUSED", "receipt://expired")
    decision = resolve_capability(layers=layers)
    assert decision.verdict is CapabilityVerdict.DENIED
    assert decision.winning_layer is CapabilityLayer.REVISION_LIFECYCLE
    assert decision.winning_reference == "revision://draft"


def test_a_refusal_outranks_an_unobserved_layer() -> None:
    """A record that said no cannot be softened by evidence nobody gathered.

    The direction matters: adding evidence must never move a capability from
    `DENIED` toward `ALLOWED` by accident, so the refusal decides and the
    outstanding layer is still visible in the chain.
    """

    layers = _all_satisfied()
    layers[2] = _outcome("REVISION_LIFECYCLE", "REFUSED", "revision://retired")
    layers[4] = _outcome("GATEWAY_ROUTE", "NOT_EVALUATED", "")
    decision = resolve_capability(layers=layers)
    assert decision.verdict is CapabilityVerdict.DENIED
    assert decision.winning_layer is CapabilityLayer.REVISION_LIFECYCLE
    assert any(item.state is LayerState.NOT_EVALUATED for item in decision.layers)


def test_a_compute_only_tool_resolves_without_a_probe() -> None:
    """The defect that makes nine rows permanently and wrongly `Denied`.

    A `COMPUTE_ONLY` binding reaches no external system, so there is no
    connection to bind and no capability to probe — `tool_probe_receipts`
    references `tenant_connections`, so a receipt cannot exist for one even in
    principle. Those two layers are not applicable, and a layer that does not
    apply neither satisfies nor refuses.
    """

    layers = _all_satisfied()
    layers[5] = _outcome("CONNECTION_BINDING", "NOT_APPLICABLE")
    layers[6] = _outcome("CAPABILITY_PROBE", "NOT_APPLICABLE")
    assert resolve_capability(layers=layers).verdict is CapabilityVerdict.ALLOWED


@pytest.mark.parametrize("layer", EXPECTED_LAYER_ORDER[:5])
def test_an_always_applicable_layer_cannot_be_waived(layer: str) -> None:
    """Only the connection and its probe may be inapplicable.

    `NOT_APPLICABLE` is the one state that neither satisfies nor blocks, so it
    is the state a mistake would reach for. The Gateway route in particular
    applies to a compute-only Tool — the binder checks the route before it
    branches on binding kind — and waiving it here would let an unrouted
    capability read `ALLOWED`.
    """

    layers = _all_satisfied()
    layers[EXPECTED_LAYER_ORDER.index(layer)] = _outcome(layer, "NOT_APPLICABLE")
    with pytest.raises(CapabilityResolutionError):
        resolve_capability(layers=layers)


def test_an_omitted_layer_refuses_rather_than_defaulting_to_allowed() -> None:
    """Visibility is never granted by omission; an empty set denies.

    A caller that forgets to observe a layer must not thereby widen what the
    screen claims. The rule takes the complete chain or it takes nothing.
    """

    with pytest.raises(CapabilityResolutionError):
        resolve_capability(layers=_all_satisfied()[:-1])


def test_the_binder_and_the_chain_stay_one_enumeration() -> None:
    """The gate check, also run here so a divergence fails fast in the suite.

    `tools/check_capability_parity.py` owns the logic; this calls it rather than
    restating it, because a parity check that exists twice is the shape of the
    problem it guards against.
    """

    assert capability_parity_findings() == []


def test_a_duplicated_layer_is_refused_rather_than_last_write_wins() -> None:
    """Two observations of one layer is an ambiguity, not a precedence puzzle.

    The projection defect this guards against is real: the console keys probe
    receipts by Tool alone, so several receipts collapse onto one another and
    the last in sort order silently decides the row.
    """

    layers = [*_all_satisfied(), _outcome("CAPABILITY_PROBE", "REFUSED")]
    with pytest.raises(CapabilityResolutionError):
        resolve_capability(layers=layers)
