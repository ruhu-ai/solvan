"""Turn a stored unified diff into a bounded structure a reviewer can read.

An exact patch review asks a human to accept a specific change. A digest proves
which change is meant; it does not let anyone judge it. This module parses the
stored diff into typed lines so the console can render the change itself, under
fixed ceilings so an oversized or hostile artifact cannot exhaust the console.

The text is never interpreted. Lines are carried verbatim and rendered as text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Ceilings. A patch larger than this is not summarized or sampled: it is
#: reported as too large to review inline, so nobody approves a diff believing
#: they saw all of it.
MAX_FILES = 20
MAX_LINES = 600
MAX_LINE_LENGTH = 500

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True, slots=True)
class DiffLine:
    kind: str  # "add" | "remove" | "context" | "meta"
    old_line: int | None
    new_line: int | None
    text: str


@dataclass(slots=True)
class DiffFile:
    path: str
    added: int = 0
    removed: int = 0
    lines: list[DiffLine] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ParsedDiff:
    files: tuple[DiffFile, ...]
    added: int
    removed: int
    truncated: bool
    note: str


def _clip(text: str) -> str:
    return text if len(text) <= MAX_LINE_LENGTH else f"{text[:MAX_LINE_LENGTH]}…"


def parse_unified_diff(diff: str) -> ParsedDiff:
    """Parse a unified diff into per-file lines with old/new numbering.

    Unparsable input yields no files and a stated reason rather than a partial
    render, because a half-shown diff is more dangerous than none.
    """

    files: list[DiffFile] = []
    current: DiffFile | None = None
    old_line = 0
    new_line = 0
    emitted = 0
    truncated = False

    for raw in diff.splitlines():
        if emitted >= MAX_LINES:
            truncated = True
            break
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            path = path[2:] if path.startswith("b/") else path
            if len(files) >= MAX_FILES:
                truncated = True
                break
            current = DiffFile(path=path or "unnamed")
            files.append(current)
            continue
        if raw.startswith(("--- ", "diff --git", "index ", "new file", "deleted file")):
            continue
        match = _HUNK.match(raw)
        if match is not None:
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            if current is not None:
                current.lines.append(DiffLine("meta", None, None, _clip(raw)))
                emitted += 1
            continue
        if current is None:
            continue
        if raw.startswith("+"):
            current.lines.append(DiffLine("add", None, new_line, _clip(raw[1:])))
            current.added += 1
            new_line += 1
        elif raw.startswith("-"):
            current.lines.append(DiffLine("remove", old_line, None, _clip(raw[1:])))
            current.removed += 1
            old_line += 1
        elif raw.startswith("\\"):
            continue
        else:
            body = raw[1:] if raw.startswith(" ") else raw
            current.lines.append(DiffLine("context", old_line, new_line, _clip(body)))
            old_line += 1
            new_line += 1
        emitted += 1

    added = sum(item.added for item in files)
    removed = sum(item.removed for item in files)
    if not files:
        note = "No reviewable change could be parsed from the artifact."
        return ParsedDiff((), 0, 0, False, note)
    note = (
        "Truncated at the review ceiling; approve only after reading the full artifact."
        if truncated
        else ""
    )
    return ParsedDiff(tuple(files), added, removed, truncated, note)


def diff_view(diff: str) -> dict[str, object]:
    """Render `parse_unified_diff` as the plain JSON the console consumes."""

    parsed = parse_unified_diff(diff)
    return {
        "added": parsed.added,
        "removed": parsed.removed,
        "truncated": parsed.truncated,
        "note": parsed.note,
        "files": [
            {
                "path": item.path,
                "added": item.added,
                "removed": item.removed,
                "lines": [
                    {
                        "kind": line.kind,
                        "old_line": line.old_line,
                        "new_line": line.new_line,
                        "text": line.text,
                    }
                    for line in item.lines
                ],
            }
            for item in parsed.files
        ],
    }
