"""Hold the capability rule and the surfaces that report it to one enumeration.

Two rules used to answer what an Agent may reach. The coordinator resolved seven
authorities against profile membership; the console resolved `lifecycle ==
APPROVED and a fresh probe exists` against declared requesters. They disagreed
about fourteen of twenty-three capabilities, every disagreement rendered as the
word `Denied`, and nothing anywhere failed while that was true.

That is the failure this check exists to prevent recurring. It is deliberately
static: the point is to catch a predicate someone *adds*, and a runtime check
only sees the refusals a test happens to trigger.

It asserts three things:

  * every refusal `ToolCatalog.resolve` raises names the authority that refused,
    or declares itself scoped to one run rather than to standing reach;
  * those refusals cover every layer in `CAPABILITY_LAYERS`, so a layer the
    binder never enforces cannot sit on the screen as decoration;
  * the projection observes every layer, so a layer added to the enumeration
    cannot reach an operator as a silently missing link in the chain.

Known gap, tracked rather than implied: `tool_catalog_run_binding.py` resolves
the same predicates in SQL for the real dispatch path and is not yet layer-tagged,
so it is not covered here. Tagging it is the next parity target.
"""

from __future__ import annotations

import ast
from pathlib import Path

from solvan.application.capability_resolution import CAPABILITY_LAYERS

ROOT = Path(__file__).resolve().parents[1]
RESOLVER = ROOT / "src" / "solvan" / "application" / "tool_catalog.py"
PROJECTION = ROOT / "apps" / "api" / "fleet_capability_projection.py"


def _resolver_refusals(source: str) -> list[ast.Call]:
    tree = ast.parse(source)
    catalog = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "ToolCatalog"
    )
    resolve = next(
        node
        for node in catalog.body
        if isinstance(node, ast.FunctionDef) and node.name == "resolve"
    )
    return [
        node.exc
        for node in ast.walk(resolve)
        if isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "ToolCatalogError"
    ]


def _named_layer(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "layer" and isinstance(keyword.value, ast.Attribute):
            return keyword.value.attr
    return None


def _is_run_scoped(call: ast.Call) -> bool:
    return any(
        keyword.arg == "run_scoped" and isinstance(keyword.value, ast.Constant)
        for keyword in call.keywords
    )


def capability_parity_findings() -> list[str]:
    """Return one line per divergence; an empty list means the rule is single."""

    findings: list[str] = []
    refusals = _resolver_refusals(RESOLVER.read_text(encoding="utf-8"))
    if not refusals:
        return ["ToolCatalog.resolve raises no ToolCatalogError; this check is reading nothing"]
    for call in refusals:
        layer = _named_layer(call)
        if layer is None and not _is_run_scoped(call):
            findings.append(
                f"refusal names no authority: {ast.unparse(call)[:88]} — tag it with a "
                "CapabilityLayer, or run_scoped=True when it belongs to one run"
            )
        if layer is not None and _is_run_scoped(call):
            findings.append(f"refusal is both standing and run-scoped: {ast.unparse(call)[:88]}")
    expected = {layer.value for layer in CAPABILITY_LAYERS}
    enforced = {layer for layer in (_named_layer(call) for call in refusals) if layer is not None}
    for layer in sorted(expected - enforced):
        findings.append(
            f"{layer} is rendered to operators but no refusal in ToolCatalog.resolve enforces it"
        )
    for layer in sorted(enforced - expected):
        findings.append(f"{layer} is enforced but is not a layer the chain reports")
    observed = _projection_layers(PROJECTION.read_text(encoding="utf-8"))
    for layer in sorted(expected - observed):
        findings.append(
            f"{layer} is never observed by {PROJECTION.relative_to(ROOT)}; every layer "
            "reports a state, and an unobserved one is stated as NOT_EVALUATED"
        )
    for layer in sorted(observed - expected):
        findings.append(f"{PROJECTION.relative_to(ROOT)} observes {layer}, which is not a layer")
    return findings


def _projection_layers(source: str) -> set[str]:
    """Every `CapabilityLayer.X` the projection names.

    Read from the syntax tree rather than matched as text: `CapabilityLayer.
    GATEWAY_ROUTE_TYPO` contains `CapabilityLayer.GATEWAY_ROUTE` as a substring,
    so a substring check called a typo covered and reported parity that did not
    hold.
    """

    return {
        node.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "CapabilityLayer"
    }


def main() -> int:
    findings = capability_parity_findings()
    for finding in findings:
        print(f"{RESOLVER.relative_to(ROOT)}: [CAP001] {finding}")
    if findings:
        print(f"Capability parity check failed with {len(findings)} finding(s)")
        return 1
    print(f"Capability parity holds across {len(CAPABILITY_LAYERS)} authorities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
