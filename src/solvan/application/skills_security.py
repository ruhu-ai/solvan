"""Fail-closed security and licensing checks for Agent Skills packages.

The scanner deliberately returns structured receipts rather than a boolean so
the Cloud SQL ledger can bind every decision to the exact bytes and scanner
versions used.  No scanner result grants runtime authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import yaml

from solvan.application.skills_interchange import SkillFile, SkillFileDisposition


@dataclass(frozen=True, slots=True)
class SecurityScanReceipt:
    scanner: str
    version: str
    verdict: str
    reason_codes: tuple[str, ...]
    content_hash: str


class ModelArmorScanner(Protocol):
    @property
    def version(self) -> str: ...

    def scan(self, *, content: bytes, content_hash: str) -> SecurityScanReceipt: ...


_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[^\s]{12,}"),
)
_PII_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?\d[\d ()-]{8,}\d)\b"),
)
#: A telephone number carries at least ten digits. The pattern above also
#: matches an ISO date — `2026-08-17` is a digit, eight separator-or-digit
#: characters, and a digit — so a pack recording when it was reviewed was
#: refused as containing PII. Counting the digits separates the two without
#: loosening what the pattern looks for, and a date is the shape that actually
#: appears in first-party provenance.
_MINIMUM_TELEPHONE_DIGITS = 10
_ALLOWED_LICENSES = frozenset(
    {
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC-BY-4.0",
        "ISC",
        "MIT",
        "MPL-2.0",
    }
)


class UnavailableModelArmor:
    """Production default: unavailable Armor is a denial, never an allow."""

    version = "unavailable"

    def scan(self, *, content: bytes, content_hash: str) -> SecurityScanReceipt:
        return SecurityScanReceipt(
            "MODEL_ARMOR", "unavailable", "DENIED", ("MODEL_ARMOR_UNAVAILABLE",), content_hash
        )


class GoogleModelArmorScanner:
    """Adapter from Solvan's regional Model Armor gate to scan receipts."""

    def __init__(self, gate: object) -> None:
        self._gate = gate

    version = "google-regional-1"

    def scan(self, *, content: bytes, content_hash: str) -> SecurityScanReceipt:
        try:
            allowed = bool(self._gate.screen_user_prompt(content.decode("utf-8")))  # type: ignore[attr-defined]
        except Exception:
            return SecurityScanReceipt(
                "MODEL_ARMOR",
                "google-regional-1",
                "DENIED",
                ("MODEL_ARMOR_UNAVAILABLE",),
                content_hash,
            )
        return SecurityScanReceipt(
            "MODEL_ARMOR",
            "google-regional-1",
            "ALLOWED" if allowed else "DENIED",
            () if allowed else ("ARMOR_FINDING",),
            content_hash,
        )


class DeterministicModelArmor:
    """Small deterministic adapter used by tests and local target development."""

    version = "fixture-1"

    def scan(self, *, content: bytes, content_hash: str) -> SecurityScanReceipt:
        text = content.decode("utf-8", errors="replace").casefold()
        blocked = any(
            marker in text for marker in ("ignore previous", "system prompt", "tool poisoning")
        )
        return SecurityScanReceipt(
            "MODEL_ARMOR",
            "fixture-1",
            "DENIED" if blocked else "ALLOWED",
            ("ARMOR_FINDING",) if blocked else (),
            content_hash,
        )


def _pii_present(pattern: re.Pattern[str], text: str) -> bool:
    """Whether this pattern found personal data rather than something shaped like it.

    Only the telephone heuristic needs the distinction, and it needs it because
    refusing on a false positive is not a safe direction here: it withholds
    first-party content that contains no personal data at all.
    """

    for match in pattern.finditer(text):
        found = match.group()
        digits = sum(character.isdigit() for character in found)
        if "@" not in found and digits < _MINIMUM_TELEPHONE_DIGITS:
            continue
        return True
    return False


def _content_hash(files: tuple[SkillFile, ...]) -> str:
    import hashlib

    digest = hashlib.sha256()
    for item in files:
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.content)
    return f"sha256:{digest.hexdigest()}"


def _license_receipt(files: tuple[SkillFile, ...], content_hash: str) -> SecurityScanReceipt:
    skill = next((item for item in files if item.path == "SKILL.md"), None)
    if skill is None:
        return SecurityScanReceipt(
            "LICENSE_POLICY", "spdx-registry-1", "REVIEW", ("LICENSE_MISSING",), content_hash
        )
    try:
        prefix, _body = skill.content.decode("utf-8").split("\n---\n", 1)
        if not prefix.startswith("---\n"):
            raise ValueError
        frontmatter = yaml.safe_load(prefix[4:])
        value = frontmatter.get("license") if isinstance(frontmatter, dict) else None
    except (UnicodeDecodeError, ValueError, yaml.YAMLError):
        value = None
    if not isinstance(value, str) or not value.strip():
        return SecurityScanReceipt(
            "LICENSE_POLICY", "spdx-registry-1", "REVIEW", ("LICENSE_MISSING",), content_hash
        )
    normalized = " ".join(value.split())
    if normalized not in _ALLOWED_LICENSES:
        return SecurityScanReceipt(
            "LICENSE_POLICY",
            "spdx-registry-1",
            "DENIED",
            ("LICENSE_POLICY_DENIED",),
            content_hash,
        )
    return SecurityScanReceipt("LICENSE_POLICY", "spdx-registry-1", "ALLOWED", (), content_hash)


def license_policy_receipt(identifier: str, *, content_hash: str) -> SecurityScanReceipt:
    normalized = " ".join(identifier.split())
    return SecurityScanReceipt(
        "LICENSE_POLICY",
        "spdx-registry-1",
        "ALLOWED" if normalized in _ALLOWED_LICENSES else "DENIED",
        () if normalized in _ALLOWED_LICENSES else ("LICENSE_POLICY_DENIED",),
        content_hash,
    )


_MAX_EXPORT_SCAN_BYTES = 1_048_576


def _decoded_export_entries(content: bytes) -> str:
    """Decode every entry of the exact exported ZIP, bounded and fail closed."""
    import io
    import zipfile

    if len(content) > _MAX_EXPORT_SCAN_BYTES:
        raise ValueError("EXPORT_BUNDLE_UNREADABLE")
    texts: list[str] = []
    remaining = _MAX_EXPORT_SCAN_BYTES
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            with archive.open(info) as member:
                data = member.read(remaining + 1)
            if len(data) > remaining:
                raise ValueError("EXPORT_BUNDLE_UNREADABLE")
            remaining -= len(data)
            texts.append(data.decode("utf-8"))
    if not texts:
        raise ValueError("EXPORT_BUNDLE_UNREADABLE")
    return "\n".join(texts)


def scan_export_bytes(
    content: bytes, *, armor: ModelArmorScanner
) -> tuple[SecurityScanReceipt, ...]:
    """Scan the decoded entries of the exact serialized export bundle."""
    import hashlib

    content_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"
    try:
        text = _decoded_export_entries(content)
    except Exception:
        denial = ("EXPORT_BUNDLE_UNREADABLE",)
        return (
            SecurityScanReceipt(
                "SECRET_SCANNER", "deterministic-1", "DENIED", denial, content_hash
            ),
            SecurityScanReceipt("PII_SCANNER", "deterministic-1", "DENIED", denial, content_hash),
            SecurityScanReceipt("MODEL_ARMOR", armor.version, "DENIED", denial, content_hash),
        )
    secret_codes = tuple(
        "SECRET_OR_CREDENTIAL" for pattern in _SECRET_PATTERNS if pattern.search(text)
    )
    pii_codes = tuple("PII_DETECTED" for pattern in _PII_PATTERNS if _pii_present(pattern, text))
    return (
        SecurityScanReceipt(
            "SECRET_SCANNER",
            "deterministic-1",
            "DENIED" if secret_codes else "ALLOWED",
            tuple(sorted(set(secret_codes))),
            content_hash,
        ),
        SecurityScanReceipt(
            "PII_SCANNER",
            "deterministic-1",
            "DENIED" if pii_codes else "ALLOWED",
            tuple(sorted(set(pii_codes))),
            content_hash,
        ),
        armor.scan(content=text.encode("utf-8"), content_hash=content_hash),
    )


def scan_skill_files(
    files: tuple[SkillFile, ...], *, armor: ModelArmorScanner
) -> tuple[SecurityScanReceipt, ...]:
    """Scan every stored file for secrets and PII; Armor screens prompt bytes."""

    content_hash = _content_hash(files)
    text = "\n".join(item.content.decode("utf-8", errors="replace") for item in files)
    prompt_files = tuple(
        item for item in files if item.disposition is SkillFileDisposition.PROMPT_ELIGIBLE
    )
    prompt_hash = _content_hash(prompt_files)
    combined_prompt = b"\n".join(item.content for item in prompt_files)
    secret_codes = tuple(
        "SECRET_OR_CREDENTIAL" for pattern in _SECRET_PATTERNS if pattern.search(text)
    )
    pii_codes = tuple("PII_DETECTED" for pattern in _PII_PATTERNS if _pii_present(pattern, text))
    receipts: list[SecurityScanReceipt] = []
    receipts.append(
        SecurityScanReceipt(
            "SECRET_SCANNER",
            "deterministic-1",
            "DENIED" if secret_codes else "ALLOWED",
            tuple(sorted(set(secret_codes))),
            content_hash,
        )
    )
    receipts.append(
        SecurityScanReceipt(
            "PII_SCANNER",
            "deterministic-1",
            "DENIED" if pii_codes else "ALLOWED",
            tuple(sorted(set(pii_codes))),
            content_hash,
        )
    )
    receipts.append(_license_receipt(files, content_hash))
    receipts.append(armor.scan(content=combined_prompt, content_hash=prompt_hash))
    return tuple(receipts)


def normalize_license(frontmatter: dict[str, object]) -> tuple[str, bytes] | None:
    value = frontmatter.get("license")
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = " ".join(value.split())
    if len(normalized) > 160 or any(char in normalized for char in "\r\n"):
        return None
    return normalized, normalized.encode("utf-8")


def require_allowed(receipts: tuple[SecurityScanReceipt, ...]) -> None:
    if any(receipt.verdict != "ALLOWED" for receipt in receipts):
        raise ValueError("security scan did not produce an ALLOWED verdict")


def require_content_safe(receipts: tuple[SecurityScanReceipt, ...]) -> None:
    """Fail closed on content scanners; license eligibility is a separate SQL gate."""

    denied = tuple(
        receipt
        for receipt in receipts
        if receipt.scanner != "LICENSE_POLICY" and receipt.verdict != "ALLOWED"
    )
    if not denied:
        return
    reason_codes = sorted({reason for receipt in denied for reason in receipt.reason_codes})
    raise ValueError(reason_codes[0] if reason_codes else "SECURITY_SCANNER_NOT_ALLOWED")
