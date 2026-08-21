"""Validate repository-local knowledge structure, links, status, and manifests."""

from __future__ import annotations

import csv
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", ".opensrc", ".solvan", ".venv", "node_modules", "dist"}
LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def included(path: Path) -> bool:
    return not EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts)


def markdown_files() -> list[Path]:
    return sorted(path for path in ROOT.rglob("*.md") if included(path))


def check_links() -> list[str]:
    failures: list[str] = []
    for source in markdown_files():
        for target in LINK_PATTERN.findall(source.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "mailto:", "#", "<")):
                continue
            local_target = unquote(target.split("#", 1)[0])
            if local_target and not (source.parent / local_target).resolve().exists():
                failures.append(f"{source.relative_to(ROOT)}: broken link {target}")
    return failures


def check_spec_status() -> list[str]:
    failures: list[str] = []
    for path in sorted((ROOT / "specs").glob("*.md")):
        first_lines = path.read_text(encoding="utf-8").splitlines()[:8]
        if not any(line.startswith("Status:") for line in first_lines):
            failures.append(f"{path.relative_to(ROOT)}: missing Status in first eight lines")
    return failures


def check_spec_index() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return [
        f"README.md: does not index {path.relative_to(ROOT)}"
        for path in sorted((ROOT / "specs").glob("*.md"))
        if path.name not in readme
    ]


def check_yaml() -> list[str]:
    failures: list[str] = []
    paths = sorted((ROOT / "config").glob("*.yaml")) + sorted(
        (ROOT / "specs/artifacts").glob("*.yaml")
    )
    for path in paths:
        try:
            value: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
            if value is None:
                failures.append(f"{path.relative_to(ROOT)}: YAML document is empty")
        except yaml.YAMLError as error:
            failures.append(f"{path.relative_to(ROOT)}: invalid YAML: {error}")
    return failures


def check_requirements() -> list[str]:
    path = ROOT / "specs/artifacts/requirements-tests.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    actual = {row["requirement_id"] for row in rows}
    expected = {f"PR-{number:03d}" for number in range(1, 51)}
    failures: list[str] = []
    if missing := sorted(expected - actual):
        failures.append(f"{path.relative_to(ROOT)}: missing requirements {missing}")
    if extras := sorted(actual - expected):
        failures.append(f"{path.relative_to(ROOT)}: unexpected requirements {extras}")
    named_tests = {
        test_id.strip() for row in rows for test_id in row["test_ids"].split(",") if test_id.strip()
    }
    implementation_path = ROOT / "specs/artifacts/test-implementations.yaml"
    value: Any = yaml.safe_load(implementation_path.read_text(encoding="utf-8"))
    implementations = value.get("implementations", {}) if isinstance(value, dict) else {}
    if not isinstance(implementations, dict):
        failures.append(f"{implementation_path.relative_to(ROOT)}: implementations must map")
        return failures
    implemented = set(implementations)
    if missing := sorted(named_tests - implemented):
        failures.append(
            f"{implementation_path.relative_to(ROOT)}: missing named test implementations {missing}"
        )
    if extras := sorted(implemented - named_tests):
        failures.append(
            f"{implementation_path.relative_to(ROOT)}: unknown named test implementations {extras}"
        )
    for test_id in sorted(named_tests & implemented):
        entry = implementations[test_id]
        if not isinstance(entry, dict) or set(entry) != {"runner", "node"}:
            failures.append(f"{test_id}: implementation must contain only runner and node")
            continue
        runner, node = entry["runner"], entry["node"]
        if runner not in {"pytest", "postgres", "playwright"} or not isinstance(node, str):
            failures.append(f"{test_id}: unsupported runner or node")
            continue
        parts = node.split("::", 1)
        if len(parts) != 2:
            failures.append(f"{test_id}: node must be file::test")
            continue
        source = ROOT / parts[0]
        if not source.is_file():
            failures.append(f"{test_id}: missing test file {parts[0]}")
            continue
        content = source.read_text(encoding="utf-8")
        if runner in {"pytest", "postgres"}:
            if runner == "postgres" and not parts[0].startswith("tests/integration/"):
                failures.append(f"{test_id}: postgres test must live under tests/integration")
            if re.search(rf"^def {re.escape(parts[1])}\(", content, re.MULTILINE) is None:
                failures.append(f"{test_id}: missing pytest function {parts[1]}")
        elif f'test("{parts[1]}"' not in content:
            failures.append(f"{test_id}: missing Playwright test {parts[1]}")
    return failures


def check_harness_contract() -> list[str]:
    required = [
        "AGENTS.md",
        "CLAUDE.md",
        "ARCHITECTURE.md",
        "docs/index.md",
        "docs/quality.md",
        "docs/tech-debt.md",
        "scripts/bootstrap",
        "scripts/start",
        "scripts/stop",
        "scripts/check",
        "scripts/check-browser",
    ]
    failures = [
        f"missing required harness file: {path}" for path in required if not (ROOT / path).exists()
    ]
    claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    if not claude.startswith("@AGENTS.md"):
        failures.append("CLAUDE.md must import @AGENTS.md as its first instruction")
    for name in required:
        path = ROOT / name
        if name.startswith("scripts/") and path.exists() and not path.stat().st_mode & stat.S_IXUSR:
            failures.append(f"{name}: script is not executable")
    return failures


def main() -> None:
    failures = [
        *check_links(),
        *check_spec_status(),
        *check_spec_index(),
        *check_yaml(),
        *check_requirements(),
        *check_harness_contract(),
    ]
    if failures:
        print("\n".join(f"- {failure}" for failure in failures))
        raise SystemExit(f"Documentation check failed with {len(failures)} finding(s)")
    print(f"Documentation check passed ({len(markdown_files())} Markdown files)")


if __name__ == "__main__":
    main()
