"""Closed command-catalog and immutable candidate-tree rules for code repair."""

from __future__ import annotations

import base64
import difflib
import fnmatch
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes

_SHELLS = frozenset({"sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"})
_FORBIDDEN_PATH_PREFIXES = (".git/", ".github/", "infra/", "deploy/", "iam/", "policy/")


def valid_repository_selector(value: object) -> bool:
    """Whether one glob is a bounded repository-root selector."""

    if not isinstance(value, str) or not value or len(value) > 256:
        return False
    if value.startswith(("/", "~")) or "\\" in value or "\x00" in value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def resolve_declared_inputs(
    *, tree: CandidateTree, selectors: list[object]
) -> list[dict[str, str]]:
    """Resolve every declared selector against one frozen base tree."""

    if (
        not selectors
        or not all(valid_repository_selector(item) for item in selectors)
        or len(selectors) != len(set(selectors))
    ):
        raise ValueError("repair command input selectors are malformed")
    resolved: list[dict[str, str]] = []
    for untyped in selectors:
        selector = str(untyped)
        matches = [item for item in tree.files if fnmatch.fnmatchcase(item.path, selector)]
        if not matches:
            raise ValueError("repair command input selector does not resolve in the frozen base")
        resolved.extend({"path": item.path, "content_hash": item.content_hash} for item in matches)
    return sorted(
        {item["path"]: item for item in resolved}.values(),
        key=lambda item: item["path"],
    )


@dataclass(frozen=True, slots=True)
class CatalogCommand:
    """One frozen, no-egress literal command resolved by the Coordinator."""

    command_id: str
    argv: tuple[str, ...]
    working_directory: str
    timeout_ms: int
    cpu_millis: int
    memory_mib: int
    output_byte_limit: int
    network_mode: str

    def __post_init__(self) -> None:
        if not self.command_id.startswith("rcc_") or not self.argv:
            raise ValueError("catalog command identity and argv are required")
        if self.network_mode != "NONE" or self.argv[0] in _SHELLS:
            raise ValueError("catalog command must be a no-egress non-shell argv")
        if any(not value or len(value) > 512 for value in self.argv) or any(
            value in {"-c", "/c", "-Command"} for value in self.argv[1:]
        ):
            raise ValueError("catalog command contains an unsafe literal argument")
        _safe_relative_path(self.working_directory, allow_root=True)
        if not 1 <= self.timeout_ms <= 120_000:
            raise ValueError("catalog command timeout is outside the allowed ceiling")
        if not 1 <= self.cpu_millis <= 1_000 or not 16 <= self.memory_mib <= 1_024:
            raise ValueError("catalog command resource limits are outside the allowed ceiling")
        if not 1 <= self.output_byte_limit <= 131_072:
            raise ValueError("catalog command output limit is outside the allowed ceiling")


@dataclass(frozen=True, slots=True)
class CandidateFile:
    path: str
    content: str

    @property
    def content_hash(self) -> str:
        return sha256_bytes(self.content.encode())


@dataclass(frozen=True, slots=True)
class CandidateTree:
    """A disposable immutable regular-file tree; each write returns a successor."""

    files: tuple[CandidateFile, ...]
    allowed_file_globs: tuple[str, ...]

    def __post_init__(self) -> None:
        names = [item.path for item in self.files]
        if len(names) != len(set(names)) or len(names) > 128:
            raise ValueError("candidate tree file count is invalid")
        total = 0
        for item in self.files:
            _safe_relative_path(item.path)
            if not any(
                fnmatch.fnmatchcase(item.path, pattern) for pattern in self.allowed_file_globs
            ):
                raise ValueError("candidate path is outside its frozen allowlist")
            encoded = item.content.encode()
            if len(encoded) > 65_280:
                raise ValueError("candidate file exceeds its byte ceiling")
            total += len(encoded)
        if total > 1_048_576:
            raise ValueError("candidate tree exceeds its aggregate byte ceiling")

    @property
    def tree_hash(self) -> str:
        return canonical_sha256(
            {
                "files": [
                    {"path": item.path, "content_hash": item.content_hash} for item in self.files
                ]
            }
        )

    def write(
        self,
        *,
        operation: str,
        relative_path: str,
        expected_prior_hash: str | None,
        content_utf8: str | None,
    ) -> CandidateTree:
        """Apply one optimistic regular-file transition to a new tree."""

        _safe_relative_path(relative_path)
        if not any(
            fnmatch.fnmatchcase(relative_path, pattern) for pattern in self.allowed_file_globs
        ):
            raise ValueError("candidate path is outside its frozen allowlist")
        by_path = {item.path: item for item in self.files}
        prior = by_path.get(relative_path)
        if operation == "CREATE":
            if prior is not None or expected_prior_hash is not None or content_utf8 is None:
                raise ValueError("candidate create has an invalid precondition")
            by_path[relative_path] = CandidateFile(relative_path, content_utf8)
        elif operation == "REPLACE":
            if prior is None or prior.content_hash != expected_prior_hash or content_utf8 is None:
                raise ValueError("candidate replacement conflicts with its prior hash")
            by_path[relative_path] = CandidateFile(relative_path, content_utf8)
        elif operation == "DELETE":
            if (
                prior is None
                or prior.content_hash != expected_prior_hash
                or content_utf8 is not None
            ):
                raise ValueError("candidate deletion conflicts with its prior hash")
            del by_path[relative_path]
        else:
            raise ValueError("candidate operation is not closed")
        return CandidateTree(
            files=tuple(by_path[path] for path in sorted(by_path)),
            allowed_file_globs=self.allowed_file_globs,
        )


def derive_unified_diff(*, base: CandidateTree, candidate: CandidateTree) -> str:
    """Derive the sole patch representation from two validated regular-file trees."""

    base_files = {item.path: item.content for item in base.files}
    candidate_files = {item.path: item.content for item in candidate.files}
    paths = sorted(set(base_files) | set(candidate_files))
    chunks: list[str] = []
    for path in paths:
        before = base_files.get(path)
        after = candidate_files.get(path)
        if before == after:
            continue
        chunks.append(f"diff --git a/{path} b/{path}\n")
        chunks.extend(
            difflib.unified_diff(
                [] if before is None else before.splitlines(keepends=True),
                [] if after is None else after.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="\n",
            )
        )
    value = "".join(chunks)
    if not value:
        raise ValueError("candidate tree does not differ from its frozen base")
    return value


def candidate_tree_from_manifest(
    value: dict[str, Any], *, allowed_file_globs: tuple[str, ...]
) -> CandidateTree:
    """Parse the closed content-addressed candidate manifest shape."""

    if set(value) != {"schema_version", "files"} or value["schema_version"] != 1:
        raise ValueError("candidate manifest has an unsupported shape")
    rows = value["files"]
    if not isinstance(rows, list):
        raise ValueError("candidate manifest files are malformed")
    files: list[CandidateFile] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "content_base64",
            "content_hash",
        }:
            raise ValueError("candidate manifest entry is malformed")
        try:
            content = base64.b64decode(str(row["content_base64"]), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("candidate manifest content is invalid") from error
        file = CandidateFile(str(row["path"]), content)
        if file.content_hash != row["content_hash"]:
            raise ValueError("candidate manifest content hash differs")
        files.append(file)
    return CandidateTree(tuple(files), allowed_file_globs)


def _safe_relative_path(path: str, *, allow_root: bool = False) -> None:
    if unicodedata.normalize("NFC", path) != path:
        raise ValueError("candidate path must be NFC-normalized")
    parsed = PurePosixPath(path)
    if (
        (not allow_root and not path)
        or path.startswith("/")
        or "\\" in path
        or ".." in parsed.parts
        or (path == "." and not allow_root)
        or any(
            path == prefix.rstrip("/") or path.startswith(prefix)
            for prefix in _FORBIDDEN_PATH_PREFIXES
        )
    ):
        raise ValueError("candidate path is unsafe or reserved")
