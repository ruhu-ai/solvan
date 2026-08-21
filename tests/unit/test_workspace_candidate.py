from __future__ import annotations

import pytest

from solvan.application.workspace_candidate import (
    CandidateFile,
    CandidateTree,
    CatalogCommand,
    candidate_tree_from_manifest,
    derive_unified_diff,
)


def test_catalog_command_refuses_a_shell_or_network() -> None:
    with pytest.raises(ValueError, match="non-shell"):
        CatalogCommand("rcc_01", ("bash", "-c", "id"), ".", 1, 1, 16, 1, "NONE")
    with pytest.raises(ValueError, match="no-egress"):
        CatalogCommand("rcc_01", ("pytest",), ".", 1, 1, 16, 1, "EGRESS")


def test_candidate_tree_is_immutable_and_hash_fenced() -> None:
    base = CandidateTree((CandidateFile("src/app.py", "old"),), ("src/*.py",))
    changed = base.write(
        operation="REPLACE",
        relative_path="src/app.py",
        expected_prior_hash=base.files[0].content_hash,
        content_utf8="new",
    )
    assert base.files[0].content == "old"
    assert changed.files[0].content == "new"
    assert base.tree_hash != changed.tree_hash
    with pytest.raises(ValueError, match="conflicts"):
        base.write(
            operation="REPLACE",
            relative_path="src/app.py",
            expected_prior_hash="sha256:" + "0" * 64,
            content_utf8="bad",
        )


def test_candidate_tree_never_allows_governance_or_traversal_paths() -> None:
    with pytest.raises(ValueError, match="unsafe or reserved"):
        CandidateTree((CandidateFile(".github/workflows/release.yml", "x"),), ("**",))
    tree = CandidateTree((), ("**",))
    with pytest.raises(ValueError, match="unsafe or reserved"):
        tree.write(
            operation="CREATE",
            relative_path="../secret",
            expected_prior_hash=None,
            content_utf8="x",
        )


def test_candidate_manifest_and_diff_are_derived_from_validated_tree() -> None:
    base = CandidateTree((CandidateFile("src/app.py", "old\n"),), ("src/*.py",))
    changed = CandidateFile("src/app.py", "new\n")
    candidate = candidate_tree_from_manifest(
        {
            "schema_version": 1,
            "files": [
                {
                    "path": changed.path,
                    "content_base64": "bmV3Cg==",
                    "content_hash": changed.content_hash,
                }
            ],
        },
        allowed_file_globs=("src/*.py",),
    )
    diff = derive_unified_diff(base=base, candidate=candidate)
    assert diff.startswith("diff --git a/src/app.py b/src/app.py\n")
    assert "-old" in diff and "+new" in diff
