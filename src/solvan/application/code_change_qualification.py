"""Deterministic repository qualification for a governed code change."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from solvan.application.code_change_transform import (
    CanonicalPatchTransform,
    RepositoryTreeEntry,
    derive_patch_transform,
)
from solvan.application.workspace_candidate import (
    CandidateTree,
    candidate_tree_from_manifest,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes

_DANGEROUS_ATTRIBUTES = frozenset({"text", "eol", "filter", "working-tree-encoding"})


@dataclass(frozen=True, slots=True)
class ObservedRepositoryFile:
    path: str
    mode: str
    blob_sha: str
    content: bytes
    content_hash: str


@dataclass(frozen=True, slots=True)
class CodeChangeQualificationInput:
    repository_binding_id: str
    code_delivery_profile_id: str
    code_delivery_profile_hash: str
    owner: str
    name: str
    configured_default_branch: str
    observed_default_branch: str
    expected_base_commit_sha: str
    observed_base_commit_sha: str
    repair_allowed_paths: tuple[str, ...]
    delivery_allowed_paths: tuple[str, ...]
    required_check_definition_paths: tuple[str, ...]
    repair_base: CandidateTree
    repair_base_modes: dict[str, str]
    candidate_manifest: dict[str, Any]
    observed_files: tuple[ObservedRepositoryFile, ...]


@dataclass(frozen=True, slots=True)
class CodeChangeQualificationDocuments:
    transform: CanonicalPatchTransform
    base_tree: dict[str, object]
    required_check_definitions: dict[str, object]
    attributes_evaluation: dict[str, object]
    provider_observation: dict[str, object]


def qualify_code_change(value: CodeChangeQualificationInput) -> CodeChangeQualificationDocuments:
    """Produce only deterministic documents; callers persist and sign receipts."""

    if value.observed_default_branch != value.configured_default_branch:
        raise ValueError("repository default branch differs from the active binding")
    if value.observed_base_commit_sha != value.expected_base_commit_sha:
        raise ValueError("repository default branch moved from the adjudicated base")
    candidate = candidate_tree_from_manifest(
        value.candidate_manifest, allowed_file_globs=value.repair_allowed_paths
    )
    observed = tuple(
        RepositoryTreeEntry(item.path, item.mode, item.content_hash)
        for item in value.observed_files
    )
    _assert_observed_files(value.observed_files)
    transform = derive_patch_transform(
        base_commit_sha=value.observed_base_commit_sha,
        qualified_base_tree=observed,
        repair_base=value.repair_base,
        candidate=candidate,
        base_modes=value.repair_base_modes,
        allowed_paths=value.delivery_allowed_paths,
    )
    changed_paths = tuple(item.path for item in transform.operations)
    attributes = _attributes_evaluation(value.observed_files, changed_paths=changed_paths)
    definitions = _required_check_definitions(
        value.observed_files,
        required_paths=value.required_check_definition_paths,
    )
    base_tree = {
        "schema_version": 1,
        "base_commit_sha": value.observed_base_commit_sha,
        "tree_hash": transform.base_tree_hash,
        "entries": [
            {
                "path": item.path,
                "mode": item.mode,
                "blob_sha": item.blob_sha,
                "content_hash": item.content_hash,
            }
            for item in value.observed_files
        ],
    }
    observation = {
        "schema_version": 1,
        "repository_binding_id": value.repository_binding_id,
        "code_delivery_profile_id": value.code_delivery_profile_id,
        "code_delivery_profile_hash": value.code_delivery_profile_hash,
        "owner": value.owner,
        "name": value.name,
        "default_branch": value.observed_default_branch,
        "base_commit_sha": value.observed_base_commit_sha,
        "base_tree_hash": transform.base_tree_hash,
        "proposed_tree_hash": transform.proposed_tree_hash,
        "patch_transform_hash": transform.transform_hash,
        "required_check_definitions_hash": canonical_sha256(definitions),
        "attributes_evaluation_hash": canonical_sha256(attributes),
    }
    return CodeChangeQualificationDocuments(
        transform=transform,
        base_tree=base_tree,
        required_check_definitions=definitions,
        attributes_evaluation=attributes,
        provider_observation=observation,
    )


def _assert_observed_files(files: tuple[ObservedRepositoryFile, ...]) -> None:
    paths = [item.path for item in files]
    if not files or paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("provider repository files are not a complete canonical sequence")
    for item in files:
        if item.content_hash != sha256_bytes(item.content):
            raise ValueError("repository file content does not match its observed hash")


def _attributes_evaluation(
    files: tuple[ObservedRepositoryFile, ...], *, changed_paths: tuple[str, ...]
) -> dict[str, object]:
    attribute_files = [
        item
        for item in files
        if item.path == ".gitattributes" or item.path.endswith("/.gitattributes")
    ]
    for item in attribute_files:
        try:
            attributes_text = item.content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("repository attributes are not canonical UTF-8") from error
        if attributes_text.encode("utf-8") != item.content:
            raise ValueError("repository attributes are not canonical UTF-8")
        for raw_line in attributes_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 2:
                raise ValueError("repository attributes contain an unsupported directive")
            for token in fields[1:]:
                name = token.lstrip("-!").split("=", 1)[0]
                if name in _DANGEROUS_ATTRIBUTES:
                    raise ValueError("repository attributes can rewrite changed file bytes")
    return {
        "schema_version": 1,
        "changed_paths": list(changed_paths),
        "dangerous_attributes_applied": False,
        "attribute_files": [
            {"path": item.path, "content_hash": item.content_hash} for item in attribute_files
        ],
    }


def _required_check_definitions(
    files: tuple[ObservedRepositoryFile, ...], *, required_paths: tuple[str, ...]
) -> dict[str, object]:
    by_path = {item.path: item for item in files}
    if not required_paths or len(required_paths) != len(set(required_paths)):
        raise ValueError("required-check definition path policy is malformed")
    missing = [path for path in required_paths if path not in by_path]
    if missing:
        raise ValueError("required-check definition is absent from the qualified base")
    return {
        "schema_version": 1,
        "definitions": [
            {
                "path": path,
                "mode": by_path[path].mode,
                "blob_sha": by_path[path].blob_sha,
                "content_hash": by_path[path].content_hash,
            }
            for path in sorted(required_paths)
        ],
    }
