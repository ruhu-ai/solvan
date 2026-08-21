"""Application-derived memory candidates for conversational requests.

The conversational surface may suggest that an outcome should be remembered,
but neither the request nor model prose is a memory source.  This module turns
only an exact action and an independent verification projection into the
closed ``MemoryCandidateProposal`` shape.  It deliberately has no free-text
fact argument.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from solvan.domain import (
    MemoryCandidateProposal,
    MemoryCandidateType,
    MemoryConfirmation,
    MemoryScope,
)


class MemoryCandidateDerivationError(ValueError):
    """The authoritative source records cannot produce a memory candidate."""


def _sha256(value: object, *, label: str) -> str:
    text = str(value).strip()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise MemoryCandidateDerivationError(f"{label} must be a lowercase SHA-256 digest")
    return text


def derive_verified_outcome_proposal(
    *,
    candidate_type: MemoryCandidateType,
    action_record: Mapping[str, object],
    verification_record: Mapping[str, object],
    exact_scope: MemoryScope,
    redaction_manifest_ref: str,
    armor_verdict_ref: str,
    policy_version: str,
    created_by_principal: str,
    expires_at: datetime,
) -> MemoryCandidateProposal:
    """Derive an outcome-memory proposal from typed records only.

    ``action_record`` and ``verification_record`` are projection records, not
    model output.  Their ids, relationship, verdict, target, and profile are
    checked before the application instantiates the deterministic fact
    sentence.  The caller cannot supply replacement wording.
    """

    if candidate_type not in {
        MemoryCandidateType.MITIGATION_OUTCOME,
        MemoryCandidateType.PERMANENT_REPAIR_OUTCOME,
    }:
        raise MemoryCandidateDerivationError("only verified outcome memories are derivable here")

    action_id = str(action_record.get("id", "")).strip()
    verification_id = str(verification_record.get("id", "")).strip()
    if not action_id.startswith("act_") or not verification_id.startswith("ver_"):
        raise MemoryCandidateDerivationError(
            "outcome sources must be an action and verification record"
        )
    if str(verification_record.get("verdict", "")).upper() != "VERIFIED":
        raise MemoryCandidateDerivationError("only independently VERIFIED outcomes are eligible")
    linked_action = str(
        verification_record.get("action_id", verification_record.get("action_ref", ""))
    ).strip()
    if linked_action != action_id:
        raise MemoryCandidateDerivationError("verification does not bind the exact action")

    target = str(action_record.get("target_key", action_record.get("target", ""))).strip()
    profile = str(
        verification_record.get("profile_id", verification_record.get("profile", ""))
    ).strip()
    if not target or not profile:
        raise MemoryCandidateDerivationError("action target and verification profile are required")

    action_hash = _sha256(action_record.get("content_hash"), label="action content hash")
    verification_hash = _sha256(
        verification_record.get("content_hash"), label="verification content hash"
    )
    # The sentence is an application-owned template.  User questions,
    # planner output, and transcript text are intentionally not parameters.
    fact = (
        f"{candidate_type.value.replace('_', ' ').title()} {action_id} on {target} "
        f"passed independent verification profile {profile}."
    )
    return MemoryCandidateProposal(
        candidate_type=candidate_type,
        exact_scope=exact_scope,
        fact_text=fact,
        source_refs=(verification_id,),
        source_hashes=(verification_hash,),
        confirmation=MemoryConfirmation.VERIFIED,
        verification_ref=verification_id,
        classification=exact_scope.classification,
        residency=exact_scope.region,
        redaction_manifest_ref=redaction_manifest_ref,
        armor_verdict_ref=armor_verdict_ref,
        provenance=(
            ("action_ref", action_id),
            ("action_hash", action_hash),
            ("verification_ref", verification_id),
            ("verification_hash", verification_hash),
            ("template", "verified-outcome-v1"),
        ),
        policy_version=policy_version,
        created_by_principal=created_by_principal,
        expires_at=expires_at,
    )
