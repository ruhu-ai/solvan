"""Canonical regular-file transform shared by adjudication and GitHub delivery."""

from __future__ import annotations

import base64
import fnmatch
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from solvan.application.workspace_candidate import CandidateTree
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes

TRANSFORM_VERSION = "solvan-regular-tree-transform/v1"
_REGULAR_MODES = frozenset({"100644", "100755"})
_FORBIDDEN_PREFIXES = (".git/", ".github/", "infra/", "deploy/", "iam/", "policy/")


@dataclass(frozen=True, slots=True)
class RepositoryTreeEntry:
    """One provider-observed regular Git tree entry."""

    path: str
    mode: str
    content_hash: str

    def __post_init__(self) -> None:
        _validate_path(self.path, enforce_repair_boundary=False)
        if self.mode not in _REGULAR_MODES:
            raise ValueError("repository tree contains a non-regular or unsupported mode")
        _validate_hash(self.content_hash)


@dataclass(frozen=True, slots=True)
class TransformOperation:
    """One path-local create, replace, or delete with exact preconditions."""

    kind: str
    path: str
    expected_base_hash: str | None
    expected_base_mode: str | None
    result_hash: str | None
    result_mode: str | None
    content_base64: str | None

    def __post_init__(self) -> None:
        _validate_path(self.path, enforce_repair_boundary=True)
        if self.kind == "CREATE":
            if self.expected_base_hash is not None or self.expected_base_mode is not None:
                raise ValueError("create transform cannot have a base precondition")
            self._validate_result(default_mode_only=True)
        elif self.kind == "REPLACE":
            self._validate_base()
            self._validate_result(default_mode_only=False)
            if self.result_mode != self.expected_base_mode:
                raise ValueError("transform cannot change a file mode")
        elif self.kind == "DELETE":
            self._validate_base()
            if any(
                value is not None
                for value in (self.result_hash, self.result_mode, self.content_base64)
            ):
                raise ValueError("delete transform cannot carry replacement content")
        else:
            raise ValueError("transform operation kind is not closed")

    def _validate_base(self) -> None:
        if self.expected_base_hash is None or self.expected_base_mode not in _REGULAR_MODES:
            raise ValueError("transform lacks an exact regular-file base precondition")
        _validate_hash(self.expected_base_hash)

    def _validate_result(self, *, default_mode_only: bool) -> None:
        if self.result_hash is None or self.result_mode not in _REGULAR_MODES:
            raise ValueError("transform lacks an exact regular-file result")
        if default_mode_only and self.result_mode != "100644":
            raise ValueError("new transform files must use the non-executable regular mode")
        _validate_hash(self.result_hash)
        if self.content_base64 is None:
            raise ValueError("transform result content is required")
        try:
            content = base64.b64decode(self.content_base64, validate=True)
            content.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("transform result must be canonical UTF-8 content") from error
        if sha256_bytes(content) != self.result_hash:
            raise ValueError("transform result hash differs from its content")

    def canonical_dict(self) -> dict[str, str | None]:
        return {
            "kind": self.kind,
            "path": self.path,
            "expected_base_hash": self.expected_base_hash,
            "expected_base_mode": self.expected_base_mode,
            "result_hash": self.result_hash,
            "result_mode": self.result_mode,
            "content_base64": self.content_base64,
        }


@dataclass(frozen=True, slots=True)
class CanonicalPatchTransform:
    version: str
    base_commit_sha: str
    base_tree_hash: str
    proposed_tree_hash: str
    operations: tuple[TransformOperation, ...]

    def __post_init__(self) -> None:
        if self.version != TRANSFORM_VERSION:
            raise ValueError("patch transform version is unsupported")
        if len(self.base_commit_sha) != 40 or any(
            value not in "0123456789abcdef" for value in self.base_commit_sha
        ):
            raise ValueError("patch transform base commit is invalid")
        _validate_hash(self.base_tree_hash)
        _validate_hash(self.proposed_tree_hash)
        if not 1 <= len(self.operations) <= 32:
            raise ValueError("patch transform operation count is outside policy")
        paths = [item.path for item in self.operations]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("patch transform operations must have unique sorted paths")

    @property
    def transform_hash(self) -> str:
        return canonical_sha256(self.canonical_dict())

    def canonical_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "transform_version": self.version,
            "base_commit_sha": self.base_commit_sha,
            "base_tree_hash": self.base_tree_hash,
            "proposed_tree_hash": self.proposed_tree_hash,
            "operations": [item.canonical_dict() for item in self.operations],
        }


def repository_tree_hash(entries: tuple[RepositoryTreeEntry, ...]) -> str:
    """Hash a complete, sorted provider-observed regular-file tree."""

    _validate_tree(entries)
    return canonical_sha256(
        {
            "entries": [
                {"path": item.path, "mode": item.mode, "content_hash": item.content_hash}
                for item in entries
            ]
        }
    )


def derive_patch_transform(
    *,
    base_commit_sha: str,
    qualified_base_tree: tuple[RepositoryTreeEntry, ...],
    repair_base: CandidateTree,
    candidate: CandidateTree,
    base_modes: dict[str, str],
    allowed_paths: tuple[str, ...],
) -> CanonicalPatchTransform:
    """Derive a transform from a candidate and apply it to the complete Git tree.

    `repair_base` and `candidate` are the bounded Workspace material. The
    provider-observed `qualified_base_tree` is complete, so unchanged files are
    included in both logical tree hashes without entering model context.
    """

    if not allowed_paths or len(allowed_paths) != len(set(allowed_paths)):
        raise ValueError("code delivery allowed paths are malformed")
    _validate_tree(qualified_base_tree)
    full = {item.path: item for item in qualified_base_tree}
    before = {item.path: item for item in repair_base.files}
    after = {item.path: item for item in candidate.files}
    if set(base_modes) != set(before):
        raise ValueError("repair base modes do not cover the exact curated base")
    operations: list[TransformOperation] = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old is not None and new is not None and old.content_hash == new.content_hash:
            continue
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in allowed_paths):
            raise ValueError("candidate change is outside the delivery profile")
        observed = full.get(path)
        if old is None:
            if observed is not None or new is None:
                raise ValueError("candidate create conflicts with the qualified repository tree")
            operation = TransformOperation(
                "CREATE",
                path,
                None,
                None,
                new.content_hash,
                "100644",
                base64.b64encode(new.content.encode()).decode("ascii"),
            )
            full[path] = RepositoryTreeEntry(path, "100644", new.content_hash)
        else:
            mode = base_modes[path]
            if (
                observed is None
                or observed.content_hash != old.content_hash
                or observed.mode != mode
            ):
                raise ValueError("curated repair base differs from the qualified repository tree")
            if new is None:
                operation = TransformOperation(
                    "DELETE", path, old.content_hash, mode, None, None, None
                )
                del full[path]
            else:
                operation = TransformOperation(
                    "REPLACE",
                    path,
                    old.content_hash,
                    mode,
                    new.content_hash,
                    mode,
                    base64.b64encode(new.content.encode()).decode("ascii"),
                )
                full[path] = RepositoryTreeEntry(path, mode, new.content_hash)
        operations.append(operation)
    if not operations:
        raise ValueError("candidate tree does not differ from its qualified base")
    result = tuple(sorted(full.values(), key=lambda item: item.path))
    return CanonicalPatchTransform(
        TRANSFORM_VERSION,
        base_commit_sha,
        repository_tree_hash(qualified_base_tree),
        repository_tree_hash(result),
        tuple(operations),
    )


def apply_patch_transform(
    *,
    base_tree: tuple[RepositoryTreeEntry, ...],
    transform: CanonicalPatchTransform,
) -> tuple[RepositoryTreeEntry, ...]:
    """Reproduce the exact logical tree, refusing a stale base precondition."""

    if repository_tree_hash(base_tree) != transform.base_tree_hash:
        raise ValueError("patch transform base tree is stale")
    current = {item.path: item for item in base_tree}
    for operation in transform.operations:
        observed = current.get(operation.path)
        if operation.kind == "CREATE":
            if observed is not None:
                raise ValueError("patch transform create path already exists")
            assert operation.result_hash is not None and operation.result_mode is not None
            current[operation.path] = RepositoryTreeEntry(
                operation.path, operation.result_mode, operation.result_hash
            )
        elif operation.kind == "DELETE":
            _assert_precondition(observed, operation)
            del current[operation.path]
        else:
            _assert_precondition(observed, operation)
            assert operation.result_hash is not None and operation.result_mode is not None
            current[operation.path] = RepositoryTreeEntry(
                operation.path, operation.result_mode, operation.result_hash
            )
    result = tuple(sorted(current.values(), key=lambda item: item.path))
    if repository_tree_hash(result) != transform.proposed_tree_hash:
        raise ValueError("patch transform result differs from its frozen proposed tree")
    return result


def parse_patch_transform(value: object) -> CanonicalPatchTransform:
    """Parse the one closed serialized transform shape with full validation."""

    if not isinstance(value, dict) or frozenset(value) != {
        "schema_version",
        "transform_version",
        "base_commit_sha",
        "base_tree_hash",
        "proposed_tree_hash",
        "operations",
    }:
        raise ValueError("patch transform document shape is invalid")
    operations = value.get("operations")
    if value.get("schema_version") != 1 or not isinstance(operations, list):
        raise ValueError("patch transform document version is invalid")
    parsed: list[TransformOperation] = []
    keys = {
        "kind",
        "path",
        "expected_base_hash",
        "expected_base_mode",
        "result_hash",
        "result_mode",
        "content_base64",
    }
    for item in operations:
        if not isinstance(item, dict) or frozenset(item) != keys:
            raise ValueError("patch transform operation shape is invalid")
        parsed.append(
            TransformOperation(
                kind=_string(item, "kind"),
                path=_string(item, "path"),
                expected_base_hash=_optional_string(item, "expected_base_hash"),
                expected_base_mode=_optional_string(item, "expected_base_mode"),
                result_hash=_optional_string(item, "result_hash"),
                result_mode=_optional_string(item, "result_mode"),
                content_base64=_optional_string(item, "content_base64"),
            )
        )
    return CanonicalPatchTransform(
        version=_string(value, "transform_version"),
        base_commit_sha=_string(value, "base_commit_sha"),
        base_tree_hash=_string(value, "base_tree_hash"),
        proposed_tree_hash=_string(value, "proposed_tree_hash"),
        operations=tuple(parsed),
    )


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"patch transform {key} is invalid")
    return item


def _optional_string(value: dict[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is not None and not isinstance(item, str):
        raise ValueError(f"patch transform {key} is invalid")
    return item


def _assert_precondition(
    observed: RepositoryTreeEntry | None, operation: TransformOperation
) -> None:
    if (
        observed is None
        or observed.content_hash != operation.expected_base_hash
        or observed.mode != operation.expected_base_mode
    ):
        raise ValueError("patch transform path precondition is stale")


def _validate_tree(entries: tuple[RepositoryTreeEntry, ...]) -> None:
    paths = [item.path for item in entries]
    if not entries or paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("repository tree entries must be non-empty, unique, and sorted")
    folded = [unicodedata.normalize("NFC", path).casefold() for path in paths]
    if len(folded) != len(set(folded)):
        raise ValueError("repository tree contains a case-folding path collision")


def _validate_path(path: str, *, enforce_repair_boundary: bool) -> None:
    parsed = PurePosixPath(path)
    if (
        not path
        or unicodedata.normalize("NFC", path) != path
        or path.startswith(("/", "~"))
        or "\\" in path
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or path == ".git"
        or (
            enforce_repair_boundary
            and (
                path == ".gitattributes"
                or path.endswith("/.gitattributes")
                or any(
                    path == prefix.rstrip("/") or path.startswith(prefix)
                    for prefix in _FORBIDDEN_PREFIXES
                )
            )
        )
    ):
        raise ValueError("repository path is unsafe or reserved")


def _validate_hash(value: str) -> None:
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(item not in "0123456789abcdef" for item in value[7:])
    ):
        raise ValueError("content hash is not canonical SHA-256")
