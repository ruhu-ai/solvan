from __future__ import annotations

import base64
import hashlib
from dataclasses import replace

import pytest

from solvan.application.code_change_qualification import (
    CodeChangeQualificationInput,
    ObservedRepositoryFile,
    qualify_code_change,
)
from solvan.application.workspace_candidate import CandidateFile, CandidateTree
from solvan.application.workspace_hashing import sha256_bytes


def _file(path: str, content: str, mode: str = "100644") -> ObservedRepositoryFile:
    value = content.encode()
    blob = b"blob " + str(len(value)).encode() + b"\0" + value
    return ObservedRepositoryFile(
        path,
        mode,
        hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
        value,
        sha256_bytes(value),
    )


def _binary_file(path: str, content: bytes) -> ObservedRepositoryFile:
    blob = b"blob " + str(len(content)).encode() + b"\0" + content
    return ObservedRepositoryFile(
        path,
        "100644",
        hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
        content,
        sha256_bytes(content),
    )


def _input(*, attributes: str | None = None) -> CodeChangeQualificationInput:
    base = "print('old')\n"
    candidate = "print('new')\n"
    files = [
        _file(".github/workflows/ci.yml", "name: ci\n"),
        _file("README.md", "docs\n"),
        _file("src/app.py", base),
    ]
    if attributes is not None:
        files.insert(0, _file(".gitattributes", attributes))
    return CodeChangeQualificationInput(
        repository_binding_id="ghr_01J00000000000000000000000",
        code_delivery_profile_id="cdp_01J00000000000000000000000",
        code_delivery_profile_hash="sha256:" + "a" * 64,
        owner="acme",
        name="service",
        configured_default_branch="main",
        observed_default_branch="main",
        expected_base_commit_sha="b" * 40,
        observed_base_commit_sha="b" * 40,
        repair_allowed_paths=("src/**",),
        delivery_allowed_paths=("src/**",),
        required_check_definition_paths=(".github/workflows/ci.yml",),
        repair_base=CandidateTree(
            (CandidateFile("src/app.py", base),),
            ("src/**",),
        ),
        repair_base_modes={"src/app.py": "100644"},
        candidate_manifest={
            "schema_version": 1,
            "files": [
                {
                    "path": "src/app.py",
                    "content_base64": base64.b64encode(candidate.encode()).decode(),
                    "content_hash": sha256_bytes(candidate.encode()),
                }
            ],
        },
        observed_files=tuple(sorted(files, key=lambda item: item.path)),
    )


def test_qualification_derives_all_authority_documents_from_observation() -> None:
    result = qualify_code_change(_input(attributes="*.md linguist-documentation\n"))

    assert result.transform.operations[0].path == "src/app.py"
    assert result.base_tree["tree_hash"] == result.transform.base_tree_hash
    assert result.required_check_definitions["definitions"][0]["path"] == (
        ".github/workflows/ci.yml"
    )
    assert result.attributes_evaluation["dangerous_attributes_applied"] is False


@pytest.mark.parametrize(
    "attributes",
    ["*.py text\n", "*.py -text\n", "*.py eol=crlf\n", "*.py filter=lfs\n"],
)
def test_qualification_refuses_attributes_that_can_rewrite_bytes(attributes: str) -> None:
    with pytest.raises(ValueError, match="rewrite"):
        qualify_code_change(_input(attributes=attributes))


def test_qualification_refuses_stale_default_branch() -> None:
    value = _input()
    with pytest.raises(ValueError, match="moved"):
        qualify_code_change(replace(value, observed_base_commit_sha="c" * 40))


def test_qualification_binds_unchanged_binary_files_without_decoding_them() -> None:
    value = _input()
    files = tuple(
        sorted(
            (*value.observed_files, _binary_file("assets/logo.png", b"\x89PNG\r\n\x1a\n\x00")),
            key=lambda item: item.path,
        )
    )

    result = qualify_code_change(replace(value, observed_files=files))

    entries = result.base_tree["entries"]
    assert isinstance(entries, list)
    assert any(entry["path"] == "assets/logo.png" for entry in entries)


def test_qualification_refuses_non_utf8_attributes_even_when_binary_files_are_allowed() -> None:
    value = _input()
    files = tuple(
        sorted(
            (*value.observed_files, _binary_file(".gitattributes", b"\xff")),
            key=lambda item: item.path,
        )
    )

    with pytest.raises(ValueError, match="attributes are not canonical UTF-8"):
        qualify_code_change(replace(value, observed_files=files))
