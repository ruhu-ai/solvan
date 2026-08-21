"""Every mutating route is classified against the challenge registry.

Specification 05 §4.2 requires the operations needing a step-up to be an
enumerated registry with every route mapped to an entry or explicitly recorded
as requiring none. "Consequential" is otherwise a property a reviewer has to
notice, which is how estate connection came to accept an hour-old reusable
token while code-change decisions were bound to exact material.

A new mutating route that is neither mapped nor excused fails here, so the
classification is made deliberately rather than by omission.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from solvan.application.action_challenge import CHALLENGE_OPERATIONS

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "config" / "challenge-coverage.yaml"
ROUTE = re.compile(r'@(?:router|app)\.(post|put|patch|delete)\("([^"]+)"')


def declared_routes() -> set[str]:
    found: set[str] = set()
    for path in sorted(ROOT.glob("apps/*/*.py")):
        for match in ROUTE.finditer(path.read_text(encoding="utf-8")):
            found.add(f"{match.group(1).upper()} {match.group(2)}")
    return found


def coverage_findings() -> list[str]:
    findings: list[str] = []
    document = yaml.safe_load(COVERAGE.read_text(encoding="utf-8")) or {}
    entries = document.get("routes") or []
    classified: dict[str, dict[str, str]] = {}
    for entry in entries:
        route = str(entry.get("route", ""))
        if route in classified:
            findings.append(f"{route} is classified twice")
        classified[route] = entry
        operation = entry.get("operation")
        excuse = entry.get("none")
        if operation and excuse:
            findings.append(f"{route} both requires {operation} and excuses itself")
        if not operation and not excuse:
            findings.append(f"{route} is neither mapped to an operation nor excused")
        if operation and operation not in CHALLENGE_OPERATIONS:
            findings.append(
                f"{route} names {operation}, which is not a registered challenge operation"
            )
        if excuse and (not str(excuse).strip() or str(excuse) == "not yet classified"):
            findings.append(
                f'{route} excuses itself without a reason; "no challenge" is a claim about '
                "what the route can do and must be defensible on its face"
            )
    for route in sorted(declared_routes() - set(classified)):
        findings.append(
            f"{route} is a mutating route with no classification; map it to a challenge "
            "operation or record why it needs none"
        )
    for route in sorted(set(classified) - declared_routes()):
        findings.append(f"{route} is classified but no longer exists")
    return findings


def main() -> int:
    findings = coverage_findings()
    for finding in findings:
        print(f"{COVERAGE.relative_to(ROOT)}: [CHL001] {finding}")
    if findings:
        print(f"Challenge coverage check failed with {len(findings)} finding(s)")
        return 1
    total = len(declared_routes())
    print(f"All {total} mutating routes are classified against the challenge registry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
