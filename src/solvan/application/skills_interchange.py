"""Deterministic, quarantined Agent Skills interchange primitives.

This module deliberately stops at a typed quarantine result. It never executes
package files, grants tools, or creates an approved guidance revision.
"""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import re
import tarfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

import yaml


class SkillImportError(ValueError):
    """A closed, auditable import rejection."""

    def __init__(self, code: str | tuple[str, ...], message: str | None = None) -> None:
        codes = (code,) if isinstance(code, str) else tuple(sorted(set(code)))
        if not codes:
            raise ValueError("a skill import error requires at least one closed code")
        self.codes = codes
        self.code = codes[0]
        super().__init__(message or ",".join(codes))


class SkillFileDisposition(StrEnum):
    PROMPT_ELIGIBLE = "PROMPT_ELIGIBLE"
    INERT_STORED = "INERT_STORED"
    STRIPPED = "STRIPPED"


MAX_ARCHIVE_BYTES = 1 * 1024 * 1024
MAX_EXPANDED_BYTES = 1 * 1024 * 1024
MAX_ENTRIES = 64
MAX_COMPRESSION_RATIO = 100
MAX_SKILL_BODY_BYTES = 64 * 1024
MAX_SKILL_BODY_LINES = 500
MAX_REFERENCE_BYTES = 64 * 1024
MAX_OTHER_FILE_BYTES = 256 * 1024

_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_KNOWN_FRONTMATTER_FIELDS = {
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
}
_EXTERNAL_LINK = re.compile(r"(?:https?://|file:|data:)", re.IGNORECASE)
_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".gz",
    ".bz2",
    ".xz",
)


@dataclass(frozen=True, slots=True)
class SkillFile:
    path: str
    content: bytes
    disposition: SkillFileDisposition

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class SkillImportInspection:
    source_bundle_hash: str
    normalized_package_hash: str
    guidance_content_hash: str
    files: tuple[SkillFile, ...]
    frontmatter: dict[str, Any]
    warnings: tuple[str, ...] = ()


def _canonical_path(raw: str) -> str:
    if "\x00" in raw or "\\" in raw:
        raise SkillImportError("PATH_UNSAFE")
    path = unicodedata.normalize("NFC", raw)
    if path.startswith("/") or not path or path.endswith("/"):
        raise SkillImportError("PATH_UNSAFE")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise SkillImportError("PATH_UNSAFE")
    normalized = posixpath.join(*parts)
    if normalized != path or not PurePosixPath(normalized).is_relative_to("."):
        # PurePosixPath's relative check is intentionally conservative; the
        # explicit component checks above are the authority.
        raise SkillImportError("PATH_UNSAFE")
    return normalized


def _normalize_text(path: str, content: bytes) -> bytes:
    if path.endswith((".md", ".yaml", ".yml", ".json", ".txt")):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillImportError("ENCODING_INVALID") from exc
        if text.startswith("\ufeff"):
            text = text[1:]
        return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return content


def _manifest(files: tuple[SkillFile, ...], *, include_disposition: bool) -> bytes:
    rows: list[dict[str, Any]] = []
    for item in sorted(files, key=lambda value: value.path.encode("utf-8")):
        row: dict[str, Any] = {
            "path": item.path,
            "size": len(item.content),
            "sha256": item.digest,
        }
        if include_disposition:
            row["disposition"] = item.disposition.value
        rows.append(row)
    return json.dumps(
        rows, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(prefix: str, manifest: bytes) -> str:
    payload = prefix.encode("ascii") + b"\0" + str(len(manifest)).encode("ascii") + b"\0" + manifest
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def source_bundle_hash(bundle: bytes) -> str:
    """Hash exact source bytes under the profile's source-bundle domain."""

    return _digest("solvan/skill/source-bundle/v1", bundle)


def _parse_frontmatter(content: bytes) -> dict[str, Any]:
    text = content.decode("utf-8")
    if not text.startswith("---\n"):
        raise SkillImportError("FRONTMATTER_INVALID")
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        raise SkillImportError("FRONTMATTER_INVALID")
    header = parts[0][4:]
    try:
        tokens = tuple(yaml.scan(header))
    except yaml.YAMLError as exc:
        raise SkillImportError("FRONTMATTER_INVALID") from exc
    if any(
        isinstance(token, yaml.tokens.AnchorToken | yaml.tokens.AliasToken | yaml.tokens.TagToken)
        for token in tokens
    ):
        raise SkillImportError("YAML_UNSAFE")

    class Loader(yaml.SafeLoader):
        pass

    def construct_mapping(
        loader: Loader, node: yaml.MappingNode, deep: bool = False
    ) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = str(loader.construct_object(key_node, deep=deep))  # type: ignore[no-untyped-call]
            if key in mapping:
                raise SkillImportError("YAML_UNSAFE")
            mapping[key] = loader.construct_object(value_node, deep=deep)  # type: ignore[no-untyped-call]
        return mapping

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    try:
        value = yaml.load(header, Loader=Loader)
    except SkillImportError:
        raise
    except yaml.YAMLError as exc:
        raise SkillImportError("FRONTMATTER_INVALID") from exc
    if not isinstance(value, dict):
        raise SkillImportError("FRONTMATTER_INVALID")
    return value


def _validate_frontmatter(frontmatter: dict[str, Any]) -> tuple[str, ...]:
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 64
        or _SKILL_NAME.fullmatch(name) is None
        or not isinstance(description, str)
        or not 1 <= len(description) <= 1024
        or not description.strip()
    ):
        raise SkillImportError("FRONTMATTER_INVALID")

    findings: set[str] = set()
    if len(description) > 1000:
        findings.add("DESCRIPTION_OVER_GOVERNED_LENGTH")
    if set(frontmatter).difference(_KNOWN_FRONTMATTER_FIELDS):
        findings.add("UNKNOWN_FRONTMATTER_FIELD")
    compatibility = frontmatter.get("compatibility")
    metadata = frontmatter.get("metadata")
    allowed_tools = frontmatter.get("allowed-tools")
    if compatibility is not None and (
        not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500
    ):
        findings.add("FRONTMATTER_FIELD_MALFORMED")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in metadata.items()
        )
    ):
        findings.add("FRONTMATTER_FIELD_MALFORMED")
    if allowed_tools is not None and not isinstance(allowed_tools, str):
        findings.add("FRONTMATTER_FIELD_MALFORMED")
    return tuple(sorted(findings))


def _frontmatter_body(content: bytes) -> bytes:
    """Return the prompt body; transport metadata is not guidance content."""
    text = content.decode("utf-8")
    if not text.startswith("---\n"):
        raise SkillImportError("FRONTMATTER_INVALID")
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        raise SkillImportError("FRONTMATTER_INVALID")
    return parts[1].encode("utf-8")


def _bounded_gunzip(archive: bytes) -> bytes:
    """Decompress one gzip stream under a hard cap before any tar parsing.

    The cap is the profile's expanded-package bound plus bounded tar framing
    overhead, so a high-ratio stream rejects after at most ~1.2 MiB of output
    instead of decompressing an arbitrarily large stream to enumerate headers.
    """

    cap = MAX_EXPANDED_BYTES + (MAX_ENTRIES * 4 + 8) * 512
    decompressor = zlib.decompressobj(wbits=31)
    output = bytearray()
    data = archive
    try:
        while data and not decompressor.eof:
            output.extend(decompressor.decompress(data, cap + 1 - len(output)))
            if len(output) > cap:
                raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
            data = decompressor.unconsumed_tail
    except zlib.error as exc:
        raise SkillImportError("ARCHIVE_INVALID") from exc
    return bytes(output)


def _extract_members(archive: bytes) -> tuple[tuple[str, bytes], ...]:
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
    members: list[tuple[str, bytes]] = []
    try:
        if zipfile.is_zipfile(io.BytesIO(archive)):
            with zipfile.ZipFile(io.BytesIO(archive)) as handle:
                zip_infos = handle.infolist()
                if len(zip_infos) > MAX_ENTRIES:
                    raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
                expanded = sum(info.file_size for info in zip_infos)
                compressed = max(1, sum(info.compress_size for info in zip_infos))
                if expanded > MAX_EXPANDED_BYTES or expanded / compressed > MAX_COMPRESSION_RATIO:
                    raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
                # The checks above read the central directory, which the archive
                # author controls. Enforce the real expanded size while decompressing
                # so an understated header cannot expand past the bound.
                remaining = MAX_EXPANDED_BYTES
                for zip_info in zip_infos:
                    if zip_info.is_dir():
                        continue
                    if (zip_info.external_attr >> 16) & 0o170000 in {
                        0o120000,
                        0o060000,
                    }:
                        raise SkillImportError("SPECIAL_FILE")
                    with handle.open(zip_info) as member:
                        content = member.read(remaining + 1)
                    if len(content) > remaining:
                        raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
                    remaining -= len(content)
                    members.append((zip_info.filename, content))
        else:
            tar_bytes = _bounded_gunzip(archive) if archive[:2] == b"\x1f\x8b" else archive
            if len(tar_bytes) < 262 or tar_bytes[257:262] != b"ustar":
                raise SkillImportError("ARCHIVE_TYPE_UNSUPPORTED")
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as handle:
                tar_infos = handle.getmembers()
                if len(tar_infos) > MAX_ENTRIES:
                    raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
                expanded = sum(info.size for info in tar_infos if info.isfile())
                if (
                    expanded > MAX_EXPANDED_BYTES
                    or expanded / max(1, len(archive)) > MAX_COMPRESSION_RATIO
                ):
                    raise SkillImportError("PACKAGE_BOUNDS_EXCEEDED")
                for tar_info in tar_infos:
                    if tar_info.isdir():
                        continue
                    if not tar_info.isfile():
                        raise SkillImportError("SPECIAL_FILE")
                    stream = handle.extractfile(tar_info)
                    if stream is None:
                        raise SkillImportError("PACKAGE_STRUCTURE_INVALID")
                    members.append((tar_info.name, stream.read()))
    except SkillImportError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise SkillImportError("ARCHIVE_INVALID") from exc
    if not members:
        raise SkillImportError("PACKAGE_STRUCTURE_INVALID")
    return tuple(members)


def _is_nested_archive(path: str, content: bytes) -> bool:
    lowered = path.casefold()
    if lowered.endswith(_ARCHIVE_SUFFIXES):
        return True
    if content.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b")):
        return True
    return len(content) >= 262 and content[257:262] == b"ustar"


def _disposition_for(relative: str, content: bytes) -> tuple[SkillFileDisposition, set[str]]:
    findings: set[str] = set()
    if relative == "SKILL.md":
        body = _frontmatter_body(content)
        if len(body) > MAX_SKILL_BODY_BYTES or len(body.splitlines()) > MAX_SKILL_BODY_LINES:
            raise SkillImportError("BODY_BOUNDS_EXCEEDED")
        if _EXTERNAL_LINK.search(body.decode("utf-8")):
            findings.add("EXTERNAL_LINK_PRESENT")
        return SkillFileDisposition.PROMPT_ELIGIBLE, findings
    if relative.startswith("references/"):
        if not relative.endswith(".md"):
            return SkillFileDisposition.STRIPPED, {"REFERENCE_NOT_MARKDOWN"}
        if len(content) > MAX_REFERENCE_BYTES:
            return SkillFileDisposition.STRIPPED, {"FILE_OVER_SIZE"}
        if relative.count("/") > 1:
            findings.add("REFERENCE_DEPTH_EXCEEDED")
        if _EXTERNAL_LINK.search(content.decode("utf-8")):
            findings.add("EXTERNAL_LINK_PRESENT")
        return SkillFileDisposition.PROMPT_ELIGIBLE, findings
    if len(content) > MAX_OTHER_FILE_BYTES:
        return SkillFileDisposition.STRIPPED, {"FILE_OVER_SIZE"}
    return SkillFileDisposition.INERT_STORED, findings


def inspect_skill_archive(archive: bytes) -> SkillImportInspection:
    """Validate and canonicalize one archive without persisting or executing it."""

    bundle_hash = source_bundle_hash(archive)
    raw_members = _extract_members(archive)
    normalized: dict[str, bytes] = {}
    collision_keys: set[str] = set()
    structural_errors: set[str] = set()
    for raw_path, content in raw_members:
        try:
            path = _canonical_path(raw_path)
        except SkillImportError as error:
            structural_errors.update(error.codes)
            continue
        collision_key = path.casefold()
        if collision_key in collision_keys:
            structural_errors.add("PATH_COLLISION")
            continue
        collision_keys.add(collision_key)
        if _is_nested_archive(path, content):
            structural_errors.add("PACKAGE_BOUNDS_EXCEEDED")
            continue
        try:
            normalized[path] = _normalize_text(path, content)
        except SkillImportError as error:
            structural_errors.update(error.codes)
    if structural_errors:
        raise SkillImportError(tuple(structural_errors))
    # Section 5.5 root discovery: expansion must yield exactly one skill root
    # directory containing exactly one SKILL.md.  Multiple SKILL.md candidates,
    # a candidate without a root directory, or files outside the discovered
    # root (a second candidate root) reject rather than silently retain.
    skill_paths = [path for path in normalized if path == "SKILL.md" or path.endswith("/SKILL.md")]
    if len(skill_paths) != 1 or "/" not in skill_paths[0]:
        raise SkillImportError("PACKAGE_STRUCTURE_INVALID")
    root = skill_paths[0].rsplit("/", 1)[0]
    if any(not path.startswith(root + "/") for path in normalized):
        raise SkillImportError("PACKAGE_STRUCTURE_INVALID")
    files: list[SkillFile] = []
    findings: set[str] = set()
    relative_paths: set[str] = set()
    for path, content in normalized.items():
        relative = path[len(root) + 1 :]
        if not relative or relative in relative_paths:
            raise SkillImportError("PACKAGE_STRUCTURE_INVALID")
        relative_paths.add(relative)
        disposition, file_findings = _disposition_for(relative, content)
        findings.update(file_findings)
        files.append(SkillFile(path=relative, content=content, disposition=disposition))
    result_files = tuple(sorted(files, key=lambda value: value.path.encode("utf-8")))
    skill_md = next(item for item in result_files if item.path == "SKILL.md")
    frontmatter = _parse_frontmatter(skill_md.content)
    findings.update(_validate_frontmatter(frontmatter))
    if root.rsplit("/", 1)[-1] != frontmatter["name"]:
        findings.add("NAME_DIRECTORY_MISMATCH")
    normalized_hash = _digest(
        "solvan/skill/normalized-package/v1", _manifest(result_files, include_disposition=True)
    )
    content_files = tuple(
        SkillFile(
            path=item.path,
            content=_frontmatter_body(item.content) if item.path == "SKILL.md" else item.content,
            disposition=item.disposition,
        )
        for item in result_files
        if item.disposition is SkillFileDisposition.PROMPT_ELIGIBLE
    )
    content_hash = _digest(
        "solvan/skill/guidance-content/v1", _manifest(content_files, include_disposition=False)
    )
    return SkillImportInspection(
        bundle_hash,
        normalized_hash,
        content_hash,
        result_files,
        frontmatter,
        tuple(sorted(findings)),
    )


def deterministic_export(files: tuple[SkillFile, ...]) -> bytes:
    """Create the profile's deterministic ZIP for prompt-eligible files."""

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for item in sorted(files, key=lambda value: value.path.encode("utf-8")):
            if item.disposition is not SkillFileDisposition.PROMPT_ELIGIBLE:
                continue
            info = zipfile.ZipInfo(item.path)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, item.content)
    return output.getvalue()


def export_bundle_hash(bundle: bytes) -> str:
    return _digest(
        "solvan/skill/export-bundle/v1",
        _manifest(
            (SkillFile("bundle.zip", bundle, SkillFileDisposition.INERT_STORED),),
            include_disposition=False,
        ),
    )
