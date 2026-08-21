"""Deterministic Antigravity provider eligibility evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from solvan.application import (
    ProviderEligibilityReceipt,
    WorkspaceClassification,
    WorkspaceProviderKind,
    WorkspaceTaskKind,
)
from solvan.domain import Scope
from solvan.platform.workspace_attestation import (
    AttestationPolicy,
    AttestationVerificationError,
    SyntheticAttestationVerifier,
)


@dataclass(frozen=True, slots=True)
class AntigravityEligibilityPolicy:
    scope: Scope
    release_commit: str
    deployment_id: str
    terms_revision: str
    required_location: str
    allowed_issuer_principals: frozenset[str]
    allowed_kms_key_versions: frozenset[str]
    provider_revision: str
    provider_service_identity: str
    implementation_sdk_distribution_hash: str
    provider_artifact_digest: str
    effective_tool_set_hash: str
    effective_network_policy_hash: str
    decided_by: str
    now: datetime


@dataclass(frozen=True, slots=True)
class AntigravityEligibilityInput:
    decision_id: str
    workspace_id: str
    workspace_generation: int
    task_kind: WorkspaceTaskKind
    artifact_manifest_ref: str
    artifact_manifest_hash: str
    synthetic_attestation_ref: str | None
    synthetic_attestation_hash: str | None
    synthetic_attestation: dict[str, object] | None
    classification: WorkspaceClassification
    synthetic: bool
    provider_location: str
    terms_revision: str


class AntigravityEligibilityEvaluator:
    """Evaluate without side effects so the caller can persist ALLOW or DENY first."""

    POLICY_VERSION = "workspace-provider-eligibility-v1"

    def __init__(self, verifier: SyntheticAttestationVerifier) -> None:
        self._verifier = verifier

    def evaluate(
        self,
        material: AntigravityEligibilityInput,
        *,
        policy: AntigravityEligibilityPolicy,
        additional_denials: tuple[str, ...] = (),
    ) -> ProviderEligibilityReceipt:
        if len(set(additional_denials)) != len(additional_denials) or any(
            not reason for reason in additional_denials
        ):
            raise ValueError("additional eligibility denials must be unique reason codes")
        reasons = [*additional_denials, *self._static_denials(material, policy=policy)]
        if not reasons and material.synthetic_attestation is not None:
            try:
                self._verifier.verify(
                    material.synthetic_attestation,
                    policy=AttestationPolicy(
                        scope=policy.scope,
                        release_commit=policy.release_commit,
                        deployment_id=policy.deployment_id,
                        allowed_issuer_principals=policy.allowed_issuer_principals,
                        allowed_kms_key_versions=policy.allowed_kms_key_versions,
                        artifact_manifest_ref=material.artifact_manifest_ref,
                        artifact_manifest_hash=material.artifact_manifest_hash,
                        now=policy.now,
                    ),
                )
            except AttestationVerificationError:
                reasons.append("SYNTHETIC_ATTESTATION_INVALID")
        decision = "DENY" if reasons else "ALLOW"
        if not reasons:
            reasons.append("PUBLIC_SYNTHETIC_ATTESTED_POLICY_MATCH")
        return ProviderEligibilityReceipt.build(
            decision_id=material.decision_id,
            policy_kind="PROVIDER_ELIGIBILITY",
            policy_version=self.POLICY_VERSION,
            **policy.scope.canonical_dict(),
            workspace_id=material.workspace_id,
            workspace_generation=material.workspace_generation,
            task_kind=material.task_kind,
            provider=WorkspaceProviderKind.ANTIGRAVITY_SDK_CLOUD_RUN,
            provider_revision=policy.provider_revision,
            implementation_sdk="google-antigravity",
            implementation_sdk_version="0.1.10",
            implementation_sdk_distribution_hash=(policy.implementation_sdk_distribution_hash),
            hosting_control_plane="CLOUD_RUN",
            hosting_data_plane="PRIVATE_HTTPS",
            provider_service_identity=policy.provider_service_identity,
            provider_artifact_digest=policy.provider_artifact_digest,
            classification=material.classification,
            synthetic=material.synthetic,
            artifact_manifest_ref=material.artifact_manifest_ref,
            artifact_manifest_hash=material.artifact_manifest_hash,
            synthetic_attestation_ref=material.synthetic_attestation_ref,
            synthetic_attestation_hash=material.synthetic_attestation_hash,
            terms_revision=material.terms_revision,
            required_processing_location=policy.required_location,
            provider_location=material.provider_location,
            effective_tool_set_hash=policy.effective_tool_set_hash,
            effective_network_policy_hash=policy.effective_network_policy_hash,
            decision=decision,
            reason_codes=tuple(reasons),
            decided_by=policy.decided_by,
            decided_at=policy.now,
        )

    @staticmethod
    def _static_denials(
        material: AntigravityEligibilityInput,
        *,
        policy: AntigravityEligibilityPolicy,
    ) -> list[str]:
        reasons: list[str] = []
        checks = (
            (
                material.classification is WorkspaceClassification.PUBLIC,
                "CLASSIFICATION_NOT_PUBLIC",
            ),
            (material.synthetic is True, "SYNTHETIC_FLAG_NOT_ATTESTABLE"),
            (
                material.synthetic_attestation is not None
                and material.synthetic_attestation_ref is not None
                and material.synthetic_attestation_hash is not None,
                "SYNTHETIC_ATTESTATION_MISSING",
            ),
            (
                material.provider_location == policy.required_location == "europe-west1",
                "PROVIDER_LOCATION_MISMATCH",
            ),
            (material.terms_revision == policy.terms_revision, "TERMS_REVISION_MISMATCH"),
        )
        for allowed, reason in checks:
            if not allowed:
                reasons.append(reason)
        return reasons
