from __future__ import annotations

import hashlib

import pytest

from solvan.platform import parse_repository_snapshot

COMMIT = "a" * 40


def file(path: str, content: str) -> dict[str, str]:
    return {
        "path": path,
        "content": content,
        "content_hash": "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
        "mode": "100644",
    }


def test_parses_exact_content_addressed_curated_files() -> None:
    snapshot = parse_repository_snapshot(
        {"schema_version": 2, "base_commit_sha": COMMIT, "files": [file("src/a.py", "x=1\n")]},
        expected_commit_sha=COMMIT,
        allowed_file_globs=("src/*.py",),
    )
    assert snapshot.files[0].path == "src/a.py"
    assert snapshot.prompt_payload()[0]["content"] == "x=1\n"


@pytest.mark.parametrize(
    "path",
    ["../secret", "/etc/passwd", "src\\evil.py", "tests/a.py"],
)
def test_rejects_unsafe_or_out_of_policy_paths(path: str) -> None:
    with pytest.raises(ValueError, match="path"):
        parse_repository_snapshot(
            {"schema_version": 2, "base_commit_sha": COMMIT, "files": [file(path, "x")]},
            expected_commit_sha=COMMIT,
            allowed_file_globs=("src/*.py",),
        )


def test_rejects_commit_hash_and_content_drift() -> None:
    with pytest.raises(ValueError, match="commit"):
        parse_repository_snapshot(
            {"schema_version": 2, "base_commit_sha": "b" * 40, "files": [file("a.py", "x")]},
            expected_commit_sha=COMMIT,
            allowed_file_globs=("*.py",),
        )
    bad = file("a.py", "x")
    bad["content_hash"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="hash"):
        parse_repository_snapshot(
            {"schema_version": 2, "base_commit_sha": COMMIT, "files": [bad]},
            expected_commit_sha=COMMIT,
            allowed_file_globs=("*.py",),
        )
