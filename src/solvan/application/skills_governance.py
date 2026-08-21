"""Compilation, lineage, refresh, and export services for Agent Skills."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.operational_guidance import (
    BlockedBehavior,
    GuidanceIncompatibilityDeclaration,
    GuidanceKind,
    GuidanceLifecycle,
    GuidanceRevision,
    GuidanceSourceKind,
    GuidanceStepKind,
    GuidanceStepRevision,
)
from solvan.application.skills_interchange import (
    SkillFile,
    SkillFileDisposition,
    SkillImportInspection,
    deterministic_export,
    export_bundle_hash,
)
from solvan.domain import new_identifier

_SKILL_GUIDANCE_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*$")


def skill_name_from_key(guidance_key: str) -> str:
    """Return the skill-name part of a canonical `owner-slug.skill-name` key."""

    if _SKILL_GUIDANCE_KEY.fullmatch(guidance_key) is None:
        raise ValueError("GUIDANCE_KEY_INVALID")
    return guidance_key.partition(".")[2]


class SkillCompileCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    guidance_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    display_name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=1_000)
    owner_department: str = Field(min_length=1, max_length=160)
    discoverable_departments: tuple[str, ...] = Field(min_length=1)
    applicable_service_kinds: tuple[str, ...] = Field(min_length=1)
    applicable_incident_classes: tuple[str, ...] = Field(min_length=1)
    symptom_tags: tuple[str, ...] = Field(min_length=1)
    purpose: str = Field(min_length=1, max_length=160)
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    eligible_regions: tuple[str, ...] = Field(min_length=1)
    allowed_agent_keys: tuple[str, ...] = Field(min_length=1)
    required_profile_revisions: tuple[str, ...] = Field(min_length=1)
    normalized_license_identifier: str = Field(min_length=1, max_length=160)
    source_classification: GuidanceSourceKind = GuidanceSourceKind.IMPORTED
    provenance_attestation_ref: str | None = Field(
        default=None,
        pattern=r"^gs://[^#]+#generation=[0-9]+$",
        max_length=2_000,
    )
    provenance_attestation_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    contains_third_party_material: bool = False
    incompatibilities: tuple[GuidanceIncompatibilityDeclaration, ...] = ()
    author_principal: str = Field(min_length=3, max_length=255)
    supersedes: str | None = None
    steps: tuple[GuidanceStepRevision, ...] | None = None

    @model_validator(mode="after")
    def validate_provenance(self) -> Self:
        attested = self.provenance_attestation_ref is not None
        if attested != (self.provenance_attestation_hash is not None):
            raise ValueError("provenance attestation reference and hash must be paired")
        if self.source_classification is GuidanceSourceKind.SOLVAN_AUTHORED:
            if not attested or self.contains_third_party_material:
                raise ValueError(
                    "SOLVAN_AUTHORED requires a complete first-party attestation "
                    "and no third-party material"
                )
        elif attested != self.contains_third_party_material:
            raise ValueError(
                "an imported first-party pack attestation must declare third-party material"
            )
        return self


def advisory_checkpoint() -> tuple[GuidanceStepRevision, ...]:
    return (
        GuidanceStepRevision(
            step_key="fetch-content",
            ordinal=1,
            title="Fetch guidance content",
            objective=(
                "Fetch this exact revision's content into the labelled untrusted guidance "
                "envelope for this run."
            ),
            step_kind=GuidanceStepKind.CHECKPOINT,
            allowed_tool_revisions=(),
            prerequisite_step_keys=(),
            completion_predicate_key="guidance-content-fetched",
            completion_predicate_version="1",
            required_evidence_kinds=("GUIDANCE_FETCH_RECEIPT",),
            maximum_tool_requests=0,
            on_blocked=BlockedBehavior.CONTINUE,
        ),
    )


def compile_import(
    *, command: SkillCompileCommand, attempt_id: str, inspection: SkillImportInspection
) -> GuidanceRevision:
    """Compile quarantine metadata into a DRAFT, never an approved revision."""

    source_name = inspection.frontmatter.get("name")
    if not isinstance(source_name, str):
        raise ValueError("FRONTMATTER_INVALID")
    if len(command.description) > 1_000:
        raise ValueError("DESCRIPTION_OVER_GOVERNED_LENGTH")
    return GuidanceRevision(
        guidance_key=command.guidance_key,
        version=command.version,
        display_name=command.display_name,
        description=command.description,
        owner_department=command.owner_department,
        discoverable_departments=command.discoverable_departments,
        guidance_kind=GuidanceKind.SKILL,
        applicable_service_kinds=command.applicable_service_kinds,
        applicable_incident_classes=command.applicable_incident_classes,
        symptom_tags=command.symptom_tags,
        purpose=command.purpose,
        classification=command.classification,
        eligible_regions=command.eligible_regions,
        allowed_agent_keys=command.allowed_agent_keys,
        required_profile_revisions=command.required_profile_revisions,
        steps=command.steps or advisory_checkpoint(),
        content_ref=f"skill-import:{attempt_id}/manifest",
        content_hash=inspection.guidance_content_hash,
        source_kind=command.source_classification,
        incompatibilities=command.incompatibilities,
        source_ref=f"skill-import:{attempt_id}",
        source_license=" ".join(command.normalized_license_identifier.split()),
        author_principal=command.author_principal,
        supersedes=command.supersedes,
        lifecycle=GuidanceLifecycle.DRAFT,
    )


class GuidanceRevisionReader(Protocol):
    def read(self, *, guidance_key: str, version: str) -> GuidanceRevision: ...


@dataclass(frozen=True, slots=True)
class ExportReceipt:
    export_id: str
    guidance_key: str
    version: str
    bundle_hash: str
    content_hash: str
    lifecycle: str
    destination_id: str


def export_approved_revision(
    *,
    revision: GuidanceRevision,
    files: tuple[SkillFile, ...],
    destination_id: str,
    stale_acknowledged: bool = False,
    export_id: str | None = None,
) -> tuple[bytes, ExportReceipt]:
    if revision.lifecycle is GuidanceLifecycle.DEPRECATED and not stale_acknowledged:
        raise ValueError("STALE_CONTENT_ACKNOWLEDGMENT_REQUIRED")
    if revision.lifecycle is GuidanceLifecycle.APPROVED and stale_acknowledged:
        raise ValueError("STALE_CONTENT_ACKNOWLEDGMENT_NOT_APPLICABLE")
    if revision.lifecycle not in {GuidanceLifecycle.APPROVED, GuidanceLifecycle.DEPRECATED}:
        raise ValueError("LIFECYCLE_REFUSED")
    if revision.source_license is None:
        raise ValueError("LICENSE_MISSING")
    skill_name = skill_name_from_key(revision.guidance_key)
    stable_export_id = export_id or new_identifier("sea")
    prompt_files: list[SkillFile] = []
    for item in files:
        if item.disposition is not SkillFileDisposition.PROMPT_ELIGIBLE:
            continue
        content = item.content
        if item.path == "SKILL.md":
            text = content.decode("utf-8")
            parts = text.split("\n---\n", 1)
            if not text.startswith("---\n") or len(parts) != 2:
                raise ValueError("FRONTMATTER_INVALID")
            metadata = {
                "name": skill_name,
                "description": revision.description,
                "license": revision.source_license,
                "metadata": {
                    "solvan-content-digest": revision.content_hash,
                    "solvan-export-id": stable_export_id,
                },
            }
            generated = yaml.safe_dump(
                metadata, allow_unicode=True, sort_keys=True, default_flow_style=False
            )
            content = f"---\n{generated}---\n{parts[1]}".encode()
        prompt_files.append(
            SkillFile(
                path=f"{skill_name}/{item.path}",
                content=content,
                disposition=item.disposition,
            )
        )
    bundle = deterministic_export(tuple(prompt_files))
    return bundle, ExportReceipt(
        export_id=stable_export_id,
        guidance_key=revision.guidance_key,
        version=revision.version,
        bundle_hash=export_bundle_hash(bundle),
        content_hash=revision.content_hash,
        lifecycle=str(revision.lifecycle),
        destination_id=destination_id,
    )


@dataclass(frozen=True, slots=True)
class RefreshLease:
    token: str
    expires_at: datetime


class RefreshLedger:
    """Token-fenced refresh ledger fixture; production persistence mirrors it."""

    def __init__(self) -> None:
        self._leases: dict[str, RefreshLease] = {}

    def acquire(self, guidance_key: str, *, now: datetime | None = None) -> RefreshLease:
        current = now or datetime.now(UTC)
        old = self._leases.get(guidance_key)
        if old is not None and old.expires_at > current:
            raise ValueError("REFRESH_LEASE_HELD")
        lease = RefreshLease(secrets.token_hex(16), current + timedelta(minutes=5))
        self._leases[guidance_key] = lease
        return lease

    def release(self, guidance_key: str, *, token: str) -> None:
        lease = self._leases.get(guidance_key)
        if lease is None or lease.token != token:
            raise ValueError("REFRESH_LEASE_FENCE")
        self._leases.pop(guidance_key, None)

    def record(
        self,
        guidance_key: str,
        *,
        upstream_ref: str,
        observation: RepositoryObservation,
        outcome: str,
        now: datetime | None = None,
    ) -> None:
        del guidance_key, upstream_ref, observation, outcome, now

    def record_failure(self, guidance_key: str, *, now: datetime | None = None) -> None:
        del guidance_key, now


class RefreshLedgerLike(Protocol):
    def acquire(self, guidance_key: str, *, now: datetime | None = None) -> RefreshLease: ...

    def release(self, guidance_key: str, *, token: str) -> None: ...

    def record(
        self,
        guidance_key: str,
        *,
        upstream_ref: str,
        observation: RepositoryObservation,
        outcome: str,
        now: datetime | None = None,
    ) -> None: ...

    def record_failure(self, guidance_key: str, *, now: datetime | None = None) -> None: ...


class RepositoryMetadataConnector(Protocol):
    def observe_ref(
        self, *, repository_ref: str, upstream_ref: str, subdirectory: str
    ) -> RepositoryObservation: ...

    def observe_tree(
        self, *, repository_ref: str, commit_sha: str, subdirectory: str
    ) -> RepositoryObservation: ...


@dataclass(frozen=True, slots=True)
class RepositoryObservation:
    commit_sha: str
    subtree_hash: str


@dataclass(frozen=True, slots=True)
class RefreshResult:
    outcome: str
    observed: RepositoryObservation


def refresh_metadata_only(
    *,
    guidance_key: str,
    repository_ref: str,
    upstream_ref: str,
    subdirectory: str,
    recorded_subtree_hash: str,
    ledger: RefreshLedgerLike,
    connector: RepositoryMetadataConnector,
    now: datetime | None = None,
) -> RefreshResult:
    """Compare upstream metadata under a fenced lease; never fetch content."""
    lease = ledger.acquire(guidance_key, now=now)
    try:
        observation = connector.observe_ref(
            repository_ref=repository_ref,
            upstream_ref=upstream_ref,
            subdirectory=subdirectory,
        )
        outcome = "UNCHANGED" if observation.subtree_hash == recorded_subtree_hash else "CHANGED"
        ledger.record(
            guidance_key,
            upstream_ref=upstream_ref,
            observation=observation,
            outcome=outcome,
            now=now,
        )
        return RefreshResult(outcome=outcome, observed=observation)
    except Exception:
        ledger.record_failure(guidance_key, now=now)
        raise
    finally:
        ledger.release(guidance_key, token=lease.token)
