"""Deterministic gate for durable enterprise memory."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from solvan.domain.identifiers import validate_identifier
from solvan.domain.scope import Scope


class MemoryGateError(ValueError):
    """A memory candidate violates a non-negotiable domain contract."""


class MemoryCandidateType(StrEnum):
    ROOT_CAUSE = "ROOT_CAUSE"
    MITIGATION_OUTCOME = "MITIGATION_OUTCOME"
    PERMANENT_REPAIR_OUTCOME = "PERMANENT_REPAIR_OUTCOME"
    TEAM_PREFERENCE = "TEAM_PREFERENCE"
    RUNBOOK_FACT = "RUNBOOK_FACT"
    PATTERN = "PATTERN"


class MemoryConfirmation(StrEnum):
    CONFIRMED = "CONFIRMED"
    VERIFIED = "VERIFIED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    OWNER_APPROVED = "OWNER_APPROVED"
    SAMPLE_CONFIRMED = "SAMPLE_CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CONTRADICTED = "CONTRADICTED"


class MemoryReviewRequirement(StrEnum):
    AUTOMATIC = "AUTOMATIC"
    HUMAN = "HUMAN"
    PROHIBITED = "PROHIBITED"


class MemoryCandidateStatus(StrEnum):
    PENDING = "PENDING"
    QUARANTINED = "QUARANTINED"
    APPROVED = "APPROVED"
    PROMOTING = "PROMOTING"
    REJECTED = "REJECTED"
    PROMOTED = "PROMOTED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class MemoryScope:
    scope: Scope
    purpose: str
    classification: str
    region: str

    def __post_init__(self) -> None:
        purpose = self.purpose.strip()
        if not purpose or len(purpose) > 80:
            raise MemoryGateError("memory purpose must contain at most 80 characters")
        if self.classification not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
            raise MemoryGateError("memory classification is unsupported")
        region = self.region.strip()
        if not region or len(region) > 80:
            raise MemoryGateError("memory region must contain at most 80 characters")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "region", region)

    def canonical_dict(self) -> dict[str, str]:
        return {
            **self.scope.canonical_dict(),
            "purpose": self.purpose,
            "classification": self.classification,
            "region": self.region,
        }


@dataclass(frozen=True, slots=True)
class MemoryCandidateProposal:
    candidate_type: MemoryCandidateType
    exact_scope: MemoryScope
    fact_text: str
    source_refs: tuple[str, ...]
    source_hashes: tuple[str, ...]
    confirmation: MemoryConfirmation
    verification_ref: str | None
    classification: str
    residency: str
    redaction_manifest_ref: str
    armor_verdict_ref: str
    provenance: tuple[tuple[str, str], ...]
    policy_version: str
    created_by_principal: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MemoryGatePolicy:
    policy_version: str
    allowed_classifications: frozenset[str]
    allowed_residencies: frozenset[str]
    max_fact_characters: int = 2_000


@dataclass(frozen=True, slots=True)
class MemoryGateDecision:
    status: MemoryCandidateStatus
    review_requirement: MemoryReviewRequirement
    content_hash: str
    rationale_codes: tuple[str, ...]


_SOURCE_PREFIXES: dict[MemoryCandidateType, frozenset[str]] = {
    MemoryCandidateType.ROOT_CAUSE: frozenset({"hyp"}),
    MemoryCandidateType.MITIGATION_OUTCOME: frozenset({"ver"}),
    MemoryCandidateType.PERMANENT_REPAIR_OUTCOME: frozenset({"ver"}),
    MemoryCandidateType.TEAM_PREFERENCE: frozenset({"aud"}),
    MemoryCandidateType.RUNBOOK_FACT: frozenset({"aud", "pgs"}),
    MemoryCandidateType.PATTERN: frozenset({"hyp", "ver"}),
}

_ELIGIBLE_CONFIRMATION: dict[
    MemoryCandidateType, tuple[MemoryConfirmation, MemoryReviewRequirement]
] = {
    MemoryCandidateType.ROOT_CAUSE: (
        MemoryConfirmation.CONFIRMED,
        MemoryReviewRequirement.AUTOMATIC,
    ),
    MemoryCandidateType.MITIGATION_OUTCOME: (
        MemoryConfirmation.VERIFIED,
        MemoryReviewRequirement.AUTOMATIC,
    ),
    MemoryCandidateType.PERMANENT_REPAIR_OUTCOME: (
        MemoryConfirmation.VERIFIED,
        MemoryReviewRequirement.AUTOMATIC,
    ),
    MemoryCandidateType.TEAM_PREFERENCE: (
        MemoryConfirmation.HUMAN_APPROVED,
        MemoryReviewRequirement.HUMAN,
    ),
    MemoryCandidateType.RUNBOOK_FACT: (
        MemoryConfirmation.OWNER_APPROVED,
        MemoryReviewRequirement.HUMAN,
    ),
    MemoryCandidateType.PATTERN: (
        MemoryConfirmation.SAMPLE_CONFIRMED,
        MemoryReviewRequirement.AUTOMATIC,
    ),
}


def evaluate_memory_candidate(
    proposal: MemoryCandidateProposal,
    *,
    policy: MemoryGatePolicy,
    now: datetime,
) -> MemoryGateDecision:
    """Return a deterministic gate decision without calling Memory Bank."""

    _require_aware(now, "evaluation time")
    _require_aware(proposal.expires_at, "candidate expiry")
    if proposal.expires_at <= now:
        raise MemoryGateError("memory candidate must expire in the future")
    if proposal.policy_version != policy.policy_version:
        raise MemoryGateError("memory candidate policy version does not match gate policy")
    if (
        proposal.exact_scope.classification != proposal.classification
        or proposal.exact_scope.region != proposal.residency
    ):
        raise MemoryGateError("memory managed scope must bind classification and residency")

    fact = proposal.fact_text.strip()
    if not fact or len(fact) > policy.max_fact_characters:
        raise MemoryGateError("memory fact is empty or exceeds the configured limit")
    if not proposal.source_refs or len(proposal.source_refs) != len(proposal.source_hashes):
        raise MemoryGateError("memory sources and hashes must be non-empty and aligned")
    if len(set(proposal.source_refs)) != len(proposal.source_refs):
        raise MemoryGateError("memory source references must be unique")
    if len(set(proposal.source_hashes)) != len(proposal.source_hashes):
        raise MemoryGateError("memory source hashes must be unique")

    allowed_prefixes = _SOURCE_PREFIXES[proposal.candidate_type]
    for source_ref in proposal.source_refs:
        validate_identifier(source_ref)
        if source_ref.split("_", 1)[0] not in allowed_prefixes:
            raise MemoryGateError(f"{proposal.candidate_type} cannot cite source {source_ref}")
    for source_hash in proposal.source_hashes:
        if len(source_hash) != 64 or any(ch not in "0123456789abcdef" for ch in source_hash):
            raise MemoryGateError("memory source hashes must be lowercase SHA-256 values")
    if proposal.verification_ref is not None:
        validate_identifier(proposal.verification_ref, expected_prefix="ver")
        if proposal.verification_ref not in proposal.source_refs:
            raise MemoryGateError("verification reference must be one of the cited sources")

    for reference, label in (
        (proposal.redaction_manifest_ref, "redaction manifest"),
        (proposal.armor_verdict_ref, "Model Armor verdict"),
    ):
        if not reference.strip():
            raise MemoryGateError(f"{label} reference is required")
    if not proposal.residency.strip() or not proposal.created_by_principal.strip():
        raise MemoryGateError("residency and creator principal are required")
    if not proposal.provenance or any(
        not key.strip() or not value.strip() for key, value in proposal.provenance
    ):
        raise MemoryGateError("typed provenance is required")
    if len({key for key, _ in proposal.provenance}) != len(proposal.provenance):
        raise MemoryGateError("provenance keys must be unique")

    content_hash = _content_hash(proposal, fact)
    prohibited: list[str] = []
    if proposal.classification not in policy.allowed_classifications:
        prohibited.append("CLASSIFICATION_NOT_ALLOWED")
    if proposal.residency not in policy.allowed_residencies:
        prohibited.append("RESIDENCY_NOT_ALLOWED")
    if not proposal.armor_verdict_ref.startswith("armor:allow:"):
        prohibited.append("MODEL_ARMOR_NOT_ALLOWED")
    if not proposal.redaction_manifest_ref.startswith("redaction:"):
        prohibited.append("REDACTION_MANIFEST_INVALID")
    if prohibited:
        return MemoryGateDecision(
            MemoryCandidateStatus.QUARANTINED,
            MemoryReviewRequirement.PROHIBITED,
            content_hash,
            tuple(prohibited),
        )

    requires_verification = proposal.candidate_type in {
        MemoryCandidateType.MITIGATION_OUTCOME,
        MemoryCandidateType.PERMANENT_REPAIR_OUTCOME,
    }
    if requires_verification and proposal.verification_ref is None:
        raise MemoryGateError("outcome memories require an eligible verification source")

    required_confirmation, review_requirement = _ELIGIBLE_CONFIRMATION[proposal.candidate_type]
    if proposal.confirmation is required_confirmation:
        return MemoryGateDecision(
            MemoryCandidateStatus.APPROVED,
            review_requirement,
            content_hash,
            ("CONFIRMATION_ELIGIBLE",),
        )
    return MemoryGateDecision(
        MemoryCandidateStatus.QUARANTINED,
        MemoryReviewRequirement.PROHIBITED,
        content_hash,
        (f"CONFIRMATION_{proposal.confirmation}",),
    )


def _content_hash(proposal: MemoryCandidateProposal, fact: str) -> str:
    material = {
        "candidate_type": proposal.candidate_type,
        "exact_scope": proposal.exact_scope.canonical_dict(),
        "fact_text": fact,
        "source_hashes": proposal.source_hashes,
        "confirmation": proposal.confirmation,
        "verification_ref": proposal.verification_ref,
        "classification": proposal.classification,
        "residency": proposal.residency,
        "provenance": dict(proposal.provenance),
        "policy_version": proposal.policy_version,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise MemoryGateError(f"{label} must be timezone-aware")
