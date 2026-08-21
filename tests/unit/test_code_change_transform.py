from __future__ import annotations

import base64

import pytest

from solvan.application.code_change_transform import (
    CanonicalPatchTransform,
    RepositoryTreeEntry,
    TransformOperation,
    apply_patch_transform,
    derive_patch_transform,
    parse_patch_transform,
)
from solvan.application.workspace_candidate import CandidateFile, CandidateTree
from solvan.application.workspace_hashing import sha256_bytes


def _hash(value: str) -> str:
    return sha256_bytes(value.encode())


def _candidate(*files: tuple[str, str]) -> CandidateTree:
    return CandidateTree(
        tuple(CandidateFile(path, content) for path, content in files),
        ("src/**",),
    )


def test_transform_preserves_complete_tree_and_reproduces_exact_result() -> None:
    base = (
        RepositoryTreeEntry("README.md", "100644", _hash("docs\n")),
        RepositoryTreeEntry("src/app.py", "100755", _hash("old\n")),
    )
    transform = derive_patch_transform(
        base_commit_sha="a" * 40,
        qualified_base_tree=base,
        repair_base=_candidate(("src/app.py", "old\n")),
        candidate=_candidate(("src/app.py", "new\n"), ("src/test_app.py", "test\n")),
        base_modes={"src/app.py": "100755"},
        allowed_paths=("src/**",),
    )

    result = apply_patch_transform(base_tree=base, transform=transform)

    assert [item.path for item in result] == ["README.md", "src/app.py", "src/test_app.py"]
    assert result[1].mode == "100755"
    assert transform.operations[0].kind == "REPLACE"
    assert transform.operations[1].result_mode == "100644"


def test_transform_refuses_stale_curated_content_and_mode() -> None:
    base = (RepositoryTreeEntry("src/app.py", "100644", _hash("different\n")),)
    with pytest.raises(ValueError, match="differs"):
        derive_patch_transform(
            base_commit_sha="a" * 40,
            qualified_base_tree=base,
            repair_base=_candidate(("src/app.py", "old\n")),
            candidate=_candidate(("src/app.py", "new\n")),
            base_modes={"src/app.py": "100644"},
            allowed_paths=("src/**",),
        )


@pytest.mark.parametrize("mode", ["120000", "160000", "100664", "040000"])
def test_transform_refuses_non_regular_or_unsupported_modes(mode: str) -> None:
    with pytest.raises(ValueError, match="mode"):
        RepositoryTreeEntry("src/app.py", mode, _hash("old\n"))


def test_transform_refuses_mode_change_and_noncanonical_content() -> None:
    content = base64.b64encode(b"new\n").decode()
    with pytest.raises(ValueError, match="mode"):
        TransformOperation(
            "REPLACE",
            "src/app.py",
            _hash("old\n"),
            "100644",
            _hash("new\n"),
            "100755",
            content,
        )
    with pytest.raises(ValueError, match="hash differs"):
        TransformOperation("CREATE", "src/new.py", None, None, _hash("wrong\n"), "100644", content)


def test_transform_refuses_casefold_alias_and_reserved_paths() -> None:
    with pytest.raises(ValueError, match="collision"):
        apply_patch_transform(
            base_tree=(
                RepositoryTreeEntry("src/A.py", "100644", _hash("a")),
                RepositoryTreeEntry("src/a.py", "100644", _hash("b")),
            ),
            transform=CanonicalPatchTransform(
                "solvan-regular-tree-transform/v1",
                "a" * 40,
                "sha256:" + "0" * 64,
                "sha256:" + "1" * 64,
                (
                    TransformOperation(
                        "CREATE",
                        "src/new.py",
                        None,
                        None,
                        _hash("new"),
                        "100644",
                        base64.b64encode(b"new").decode(),
                    ),
                ),
            ),
        )
    with pytest.raises(ValueError, match="reserved"):
        TransformOperation(
            "CREATE",
            ".github/workflows/ci.yml",
            None,
            None,
            _hash("x"),
            "100644",
            base64.b64encode(b"x").decode(),
        )


def test_transform_document_round_trips_only_the_closed_shape() -> None:
    transform = derive_patch_transform(
        base_commit_sha="a" * 40,
        qualified_base_tree=(RepositoryTreeEntry("src/app.py", "100644", _hash("old\n")),),
        repair_base=_candidate(("src/app.py", "old\n")),
        candidate=_candidate(("src/app.py", "new\n")),
        base_modes={"src/app.py": "100644"},
        allowed_paths=("src/**",),
    )
    parsed = parse_patch_transform(transform.canonical_dict())
    assert parsed == transform
    poisoned = transform.canonical_dict() | {"branch": "attacker"}
    with pytest.raises(ValueError, match="shape"):
        parse_patch_transform(poisoned)
