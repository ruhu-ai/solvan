from __future__ import annotations

import pytest

from apps.workspace_adapter.main import _declared_input_manifest
from solvan.application.workspace_candidate import valid_repository_selector
from solvan.persistence.workspace_repair_store import WorkspaceRepairConflict


def _manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "files": [
            {
                "path": "src/app.py",
                "content_base64": "eD0xCg==",
                "content_hash": "sha256:" + "1" * 64,
            },
            {
                "path": "secrets/internal.txt",
                "content_base64": "bm8=",
                "content_hash": "sha256:" + "2" * 64,
            },
            {
                "path": "tests/test_app.py",
                "content_base64": "eD0xCg==",
                "content_hash": "sha256:" + "3" * 64,
            },
        ],
    }


def test_sandbox_manifest_contains_only_base_resolved_catalog_inputs() -> None:
    selected = _declared_input_manifest(
        _manifest(), resolved_input_paths=("src/app.py", "tests/test_app.py")
    )
    assert [item["path"] for item in selected["files"]] == [
        "src/app.py",
        "tests/test_app.py",
    ]
    assert "secrets/internal.txt" not in str(selected)


def test_sandbox_manifest_refuses_a_disappeared_or_duplicate_input() -> None:
    with pytest.raises(WorkspaceRepairConflict, match="disappeared"):
        _declared_input_manifest(_manifest(), resolved_input_paths=("missing.py",))
    duplicate = _manifest()
    duplicate["files"] = [duplicate["files"][0], duplicate["files"][0]]  # type: ignore[index]
    with pytest.raises(WorkspaceRepairConflict, match="unique"):
        _declared_input_manifest(duplicate, resolved_input_paths=("src/app.py",))


@pytest.mark.parametrize(
    "selector",
    ("/etc/passwd", "../secret", "src/../secret", "src\\secret", "", "./src/*.py"),
)
def test_declared_input_selector_cannot_escape_the_snapshot(selector: str) -> None:
    assert not valid_repository_selector(selector)


def test_declared_input_selector_accepts_bounded_repository_globs() -> None:
    assert valid_repository_selector("src/**/*.py")
    assert valid_repository_selector("tests/*.py")
