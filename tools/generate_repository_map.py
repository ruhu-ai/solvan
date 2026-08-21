"""Generate or verify a deterministic, agent-readable repository map."""

from __future__ import annotations

import argparse
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/generated/repository-map.md"
TOP_LEVEL = [
    "apps",
    "src",
    "config",
    "infra",
    "scripts",
    "tools",
    "tests",
    "evals",
    "specs",
    "docs",
]


def source_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(
        ROOT / relative
        for relative in result.stdout.split("\0")
        if relative and ROOT / relative != OUTPUT and (ROOT / relative).is_file()
    )


def render() -> str:
    files = source_files()
    suffixes = Counter(path.suffix or "[no extension]" for path in files)
    lines = [
        "# Generated repository map",
        "",
        "Status: generated; do not edit by hand",
        "Generator: `tools/generate_repository_map.py`",
        "",
        "## Top-level areas",
        "",
    ]
    for name in TOP_LEVEL:
        base = ROOT / name
        count = sum(1 for path in files if base in path.parents)
        if base.exists():
            lines.append(f"- `{name}/`: {count} tracked-source file(s)")
    lines.extend(["", "## File types", ""])
    for suffix, count in sorted(suffixes.items()):
        lines.append(f"- `{suffix}`: {count}")
    lines.extend(
        [
            "",
            "## Canonical entry points",
            "",
            "- Agent map: `AGENTS.md`",
            "- Product/specification entry: `README.md`",
            "- Runtime map: `ARCHITECTURE.md`",
            "- Bootstrap: `scripts/bootstrap`",
            "- Local runtime: `scripts/start`",
            "- Verification: `scripts/check`",
            "- Active execution plans: `docs/exec-plans/active/`",
            "- Known debt: `docs/tech-debt.md`",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"Wrote {OUTPUT.relative_to(ROOT)}")
        return
    actual = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if actual != expected:
        raise SystemExit("Generated repository map is stale; run scripts/generate")
    print("Generated repository map is current")


if __name__ == "__main__":
    main()
