"""Strict parser for curated, content-addressed repository snapshot bundles."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True, slots=True)
class RepositoryFile:
    path: str
    content: str
    content_hash: str
    mode: str


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    base_commit_sha: str
    files: tuple[RepositoryFile, ...]

    def prompt_payload(self) -> list[dict[str, str]]:
        return [
            {
                "path": item.path,
                "content": item.content,
                "content_hash": item.content_hash,
                "mode": item.mode,
            }
            for item in self.files
        ]


def parse_repository_snapshot(
    value: dict[str, Any],
    *,
    expected_commit_sha: str,
    allowed_file_globs: tuple[str, ...],
    max_total_content_bytes: int = 400_000,
) -> RepositorySnapshot:
    if set(value) != {"schema_version", "base_commit_sha", "files"}:
        raise ValueError("repository snapshot has an unsupported schema")
    if value["schema_version"] != 2 or value["base_commit_sha"] != expected_commit_sha:
        raise ValueError("repository snapshot commit does not match the repair plan")
    raw_files = value["files"]
    if not isinstance(raw_files, list) or not raw_files or len(raw_files) > 256:
        raise ValueError("repository snapshot must contain 1-256 files")
    if max_total_content_bytes < 1 or max_total_content_bytes > 800_000:
        raise ValueError("repository snapshot content ceiling is outside policy")
    files: list[RepositoryFile] = []
    seen: set[str] = set()
    total = 0
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"path", "content", "content_hash", "mode"}:
            raise ValueError("repository snapshot file has an unsupported schema")
        path, content, content_hash, mode = (
            raw["path"],
            raw["content"],
            raw["content_hash"],
            raw["mode"],
        )
        if not all(isinstance(item, str) for item in (path, content, content_hash, mode)):
            raise ValueError("repository snapshot file fields must be text")
        if mode not in {"100644", "100755"}:
            raise ValueError("repository snapshot file mode is unsupported")
        parsed = PurePosixPath(path)
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or ".." in parsed.parts
            or path in seen
            or not any(fnmatch.fnmatchcase(path, pattern) for pattern in allowed_file_globs)
        ):
            raise ValueError("repository snapshot path is unsafe, duplicated, or outside policy")
        encoded = content.encode("utf-8")
        total += len(encoded)
        if total > max_total_content_bytes:
            raise ValueError("repository snapshot exceeds the content byte ceiling")
        actual_hash = "sha256:" + hashlib.sha256(encoded).hexdigest()
        if content_hash != actual_hash:
            raise ValueError("repository snapshot file hash does not match its content")
        seen.add(path)
        files.append(RepositoryFile(path, content, content_hash, mode))
    return RepositorySnapshot(expected_commit_sha, tuple(files))
