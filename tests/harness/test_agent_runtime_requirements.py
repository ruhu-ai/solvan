"""The Agent Runtime requirements must cover the deployed import closure.

The deployed engines install only `apps/agents/runtime-requirements.txt` and
unpickle code that eagerly imports the whole `solvan` package. `rfc8785` was
imported by that closure and pinned nowhere — every deployed engine started
with `ModuleNotFoundError` while the local suite, which has the full locked
environment, stayed green. This walks the same closure the deploy tool ships
(`apps/agents/*/agent.py` entry points plus every `solvan`/`apps` module they
reach) and requires each external import to be provided by a pinned
distribution or by a declared transitive of one, resolved from the local
environment's own metadata.
"""

from __future__ import annotations

import ast
import re
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIREMENTS = ROOT / "apps" / "agents" / "runtime-requirements.txt"
ENTRY_POINTS = sorted((ROOT / "apps" / "agents").glob("*/agent.py"))

_STDLIB = frozenset(sys.stdlib_module_names)


def _pinned() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,-]+\])?==([A-Za-z0-9.]+)", stripped
        )
        assert match, f"unparsable requirement line: {stripped!r}"
        pins[metadata.Prepared.normalize(match.group(1))] = match.group(2)
    assert pins, "runtime-requirements.txt declares nothing; this check is stale"
    return pins


def _repo_module(module: str) -> Path | None:
    """Resolve a solvan/apps import to a repository file, or None."""

    parts = module.split(".")
    for base in (ROOT / "src", ROOT):
        candidate = base.joinpath(*parts).with_suffix(".py")
        package = base.joinpath(*parts, "__init__.py")
        if candidate.is_file():
            return candidate
        if package.is_file():
            return package
    return None


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module)
    return found


def _closure() -> set[str]:
    """Every external top-level module the deployed closure imports."""

    seen: set[Path] = set()
    external: set[str] = set()
    stack = list(ENTRY_POINTS)
    assert stack, "no deployed agent entry points found; this check is stale"
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        seen.add(path)
        for module in _imports(path):
            top = module.split(".", 1)[0]
            if top in _STDLIB:
                continue
            repo_file = _repo_module(module)
            if repo_file is not None:
                stack.append(repo_file)
            else:
                external.add(top)
    return external


def _reachable_distributions(pins: dict[str, str]) -> set[str]:
    """Pinned distributions plus everything they declare as a requirement.

    A declared requirement that is not installed locally still counts as a
    provider — the deploy install resolves it — it just cannot be expanded
    further from this environment's metadata.
    """

    reachable = set(pins)
    queue = list(pins)
    while queue:
        distribution = queue.pop()
        try:
            requirements = metadata.requires(distribution) or []
        except metadata.PackageNotFoundError:
            continue
        for requirement in requirements:
            name = re.split(r"[\s\[<>=!~;(]", requirement, maxsplit=1)[0]
            normalized = metadata.Prepared.normalize(name)
            if normalized not in reachable:
                reachable.add(normalized)
                queue.append(normalized)
    return reachable


def test_every_deployed_import_has_a_pinned_or_transitive_provider() -> None:
    providers = _reachable_distributions(_pinned())
    distributions = metadata.packages_distributions()
    uncovered: dict[str, list[str]] = {}
    for module in sorted(_closure()):
        owners = {
            metadata.Prepared.normalize(distribution)
            for distribution in distributions.get(module, [])
        }
        if not owners:
            uncovered[module] = ["not installed locally"]
        elif owners.isdisjoint(providers):
            uncovered[module] = sorted(owners)
    assert not uncovered, (
        "the deployed Agent Runtime closure imports modules with no provider in "
        f"apps/agents/runtime-requirements.txt: {uncovered}"
    )


def test_agent_runtime_serialization_dependency_is_explicitly_pinned() -> None:
    pins = _pinned()

    assert pins["cloudpickle"] == metadata.version("cloudpickle")
