"""Application boundary for idempotent Agent Skills quarantine imports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from solvan.application.skills_interchange import (
    SkillImportError,
    SkillImportInspection,
    inspect_skill_archive,
    source_bundle_hash,
)
from solvan.application.skills_security import (
    ModelArmorScanner,
    SecurityScanReceipt,
    scan_skill_files,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope


class SkillImportCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    command_id: str = Field(min_length=3, max_length=80)
    scope: Scope
    purpose: str = Field(min_length=1, max_length=160)
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    region: str = Field(pattern=r"^[a-z0-9-]+$")
    source_kind: Literal["ARCHIVE", "REPOSITORY", "FIRST_PARTY"]
    source_ref: str = Field(min_length=1, max_length=2_000)
    upstream_ref: str | None = Field(default=None, max_length=2_000)
    upstream_subdirectory: str | None = Field(default=None, max_length=512)
    upstream_commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    upstream_subtree_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    principal: str = Field(min_length=3, max_length=255)
    authorization_ref: str = Field(min_length=1, max_length=2_000)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


@dataclass(frozen=True, slots=True)
class SkillImportAttempt:
    attempt_id: str
    import_request_hash: str
    decision: str
    reason_codes: tuple[str, ...]
    inspection: SkillImportInspection | None
    scan_receipts: tuple[SecurityScanReceipt, ...] = ()


class SkillImportRepository(Protocol):
    def find_by_request_hash(
        self, *, scope: Scope, request_hash: str
    ) -> SkillImportAttempt | None: ...

    def persist_attempt(
        self,
        *,
        scope: Scope,
        request: SkillImportCommand,
        request_hash: str,
        outcome: SkillImportAttempt,
        archive: bytes,
    ) -> SkillImportAttempt: ...


class SkillImportService:
    """Validate an archive once and persist one immutable attempt outcome."""

    def __init__(self, repository: SkillImportRepository, *, armor: ModelArmorScanner) -> None:
        self._repository = repository
        self._armor = armor

    @staticmethod
    def request_hash(
        request: SkillImportCommand,
        *,
        source_bundle_hash: str,
        scanner_versions: dict[str, str] | None = None,
    ) -> str:
        return canonical_sha256(
            {
                "scope": request.scope.canonical_dict(),
                "purpose": request.purpose,
                "classification": request.classification,
                "region": request.region,
                "source_kind": request.source_kind,
                "source_ref": request.source_ref,
                "upstream_ref": request.upstream_ref,
                "upstream_subdirectory": request.upstream_subdirectory,
                "upstream_commit_sha": request.upstream_commit_sha,
                "upstream_subtree_hash": request.upstream_subtree_hash,
                "source_bundle_hash": source_bundle_hash,
                "principal": request.principal,
                "profile_version": "agent-skills-import/1",
                "canonicalization_version": "skill-canonicalization/1",
                "scanner_policy_versions": scanner_versions
                or {
                    "LICENSE_POLICY": "spdx-registry-1",
                    "MODEL_ARMOR": "not-configured",
                    "PII_SCANNER": "deterministic-1",
                    "SECRET_SCANNER": "deterministic-1",
                },
            }
        )

    def _scanner_versions(self) -> dict[str, str]:
        return {
            "LICENSE_POLICY": "spdx-registry-1",
            "MODEL_ARMOR": self._armor.version,
            "PII_SCANNER": "deterministic-1",
            "SECRET_SCANNER": "deterministic-1",
        }

    def import_archive(self, request: SkillImportCommand, archive: bytes) -> SkillImportAttempt:
        bundle_hash = source_bundle_hash(archive)
        request_hash = self.request_hash(
            request,
            source_bundle_hash=bundle_hash,
            scanner_versions=self._scanner_versions(),
        )
        existing = self._repository.find_by_request_hash(
            scope=request.scope, request_hash=request_hash
        )
        if existing is not None:
            return existing
        try:
            inspection = inspect_skill_archive(archive)
        except SkillImportError as error:
            outcome = SkillImportAttempt(
                attempt_id="pending",
                import_request_hash=request_hash,
                decision="REJECTED",
                reason_codes=error.codes,
                inspection=None,
            )
        else:
            receipts = scan_skill_files(inspection.files, armor=self._armor)
            # A REVIEW receipt (for example missing license evidence) is
            # retained in quarantine for human reassessment; only a
            # deterministic DENIED verdict refuses the import itself.
            denied_reasons = {
                code
                for receipt in receipts
                if receipt.verdict == "DENIED"
                for code in receipt.reason_codes
            }
            blocking_denied_reasons = {
                code
                for receipt in receipts
                if receipt.verdict == "DENIED" and receipt.scanner != "LICENSE_POLICY"
                for code in receipt.reason_codes
            }
            reasons = tuple(sorted(set(inspection.warnings).union(denied_reasons)))
            outcome = SkillImportAttempt(
                attempt_id="pending",
                import_request_hash=request_hash,
                decision="REJECTED" if blocking_denied_reasons else "QUARANTINED",
                reason_codes=reasons,
                inspection=inspection if not blocking_denied_reasons else None,
                scan_receipts=receipts,
            )
        return self._repository.persist_attempt(
            scope=request.scope,
            request=request,
            request_hash=request_hash,
            outcome=outcome,
            archive=archive,
        )


class InMemorySkillImportRepository:
    """Deterministic fixture repository; production uses Cloud SQL."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str, str], SkillImportAttempt] = {}
        self._counter = 0

    def find_by_request_hash(self, *, scope: Scope, request_hash: str) -> SkillImportAttempt | None:
        key = (
            scope.environment_id,
            scope.organization_id,
            scope.project_id,
            request_hash,
        )
        return self._items.get(key)

    def persist_attempt(
        self,
        *,
        scope: Scope,
        request: SkillImportCommand,
        request_hash: str,
        outcome: SkillImportAttempt,
        archive: bytes,
    ) -> SkillImportAttempt:
        key = (
            scope.environment_id,
            scope.organization_id,
            scope.project_id,
            request_hash,
        )
        existing = self._items.get(key)
        if existing is not None:
            return existing
        self._counter += 1
        persisted = SkillImportAttempt(
            attempt_id=f"sia_fixture_{self._counter}",
            import_request_hash=outcome.import_request_hash,
            decision=outcome.decision,
            reason_codes=outcome.reason_codes,
            inspection=outcome.inspection,
            scan_receipts=outcome.scan_receipts,
        )
        self._items[key] = persisted
        return persisted
