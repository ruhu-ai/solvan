from datetime import UTC, datetime

from solvan.application import WorkspaceClassification, WorkspaceTaskKind
from solvan.domain import Scope
from solvan.platform import (
    AntigravityEligibilityEvaluator,
    AntigravityEligibilityInput,
    AntigravityEligibilityPolicy,
    AttestationVerificationError,
)

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
HASH = f"sha256:{'1' * 64}"


class FakeVerifier:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.calls = 0

    def verify(self, value: dict[str, object], *, policy: object) -> object:
        del value, policy
        self.calls += 1
        if not self.valid:
            raise AttestationVerificationError("invalid")
        return object()


def _policy() -> AntigravityEligibilityPolicy:
    return AntigravityEligibilityPolicy(
        scope=SCOPE,
        release_commit="a" * 40,
        deployment_id="deploy-20260808-01",
        terms_revision="google-antigravity-alpha-terms-2026-08-08",
        required_location="europe-west1",
        allowed_issuer_principals=frozenset({"serviceAccount:attester@example.com"}),
        allowed_kms_key_versions=frozenset(
            {
                "projects/demo/locations/europe-west1/keyRings/workspace/"
                "cryptoKeys/attester/cryptoKeyVersions/1"
            }
        ),
        provider_revision="antigravity-workspace-20260808-01",
        provider_service_identity="serviceAccount:antigravity@example.com",
        implementation_sdk_distribution_hash=HASH,
        provider_artifact_digest=HASH,
        effective_tool_set_hash=HASH,
        effective_network_policy_hash=HASH,
        decided_by="serviceAccount:coordinator@example.com",
        now=NOW,
    )


def _input(**changes: object) -> AntigravityEligibilityInput:
    values: dict[str, object] = {
        "decision_id": "pol_00000000000000000000000000",
        "workspace_id": "wsp_00000000000000000000000000",
        "workspace_generation": 1,
        "task_kind": WorkspaceTaskKind.FORENSICS,
        "artifact_manifest_ref": "gs://evidence/workspace/input.json",
        "artifact_manifest_hash": HASH,
        "synthetic_attestation_ref": "gs://evidence/workspace/attestation.json",
        "synthetic_attestation_hash": HASH,
        "synthetic_attestation": {"schema_version": 1},
        "classification": WorkspaceClassification.PUBLIC,
        "synthetic": True,
        "provider_location": "europe-west1",
        "terms_revision": "google-antigravity-alpha-terms-2026-08-08",
    }
    values.update(changes)
    return AntigravityEligibilityInput(**values)  # type: ignore[arg-type]


def test_public_attested_exact_provider_material_is_allowed() -> None:
    verifier = FakeVerifier()
    receipt = AntigravityEligibilityEvaluator(verifier).evaluate(  # type: ignore[arg-type]
        _input(), policy=_policy()
    )
    assert receipt.decision == "ALLOW"
    assert receipt.reason_codes == ("PUBLIC_SYNTHETIC_ATTESTED_POLICY_MATCH",)
    assert verifier.calls == 1


def test_invalid_signature_is_denied_before_provider_use() -> None:
    verifier = FakeVerifier(valid=False)
    receipt = AntigravityEligibilityEvaluator(verifier).evaluate(  # type: ignore[arg-type]
        _input(), policy=_policy()
    )
    assert receipt.decision == "DENY"
    assert receipt.reason_codes == ("SYNTHETIC_ATTESTATION_INVALID",)


def test_nonpublic_missing_attestation_produces_a_schema_valid_deny_receipt() -> None:
    verifier = FakeVerifier()
    receipt = AntigravityEligibilityEvaluator(verifier).evaluate(  # type: ignore[arg-type]
        _input(
            classification=WorkspaceClassification.CONFIDENTIAL,
            synthetic=False,
            synthetic_attestation=None,
            synthetic_attestation_ref=None,
            synthetic_attestation_hash=None,
        ),
        policy=_policy(),
    )
    assert receipt.decision == "DENY"
    assert receipt.reason_codes == (
        "CLASSIFICATION_NOT_PUBLIC",
        "SYNTHETIC_FLAG_NOT_ATTESTABLE",
        "SYNTHETIC_ATTESTATION_MISSING",
    )
    assert verifier.calls == 0


def test_terms_or_region_mismatch_is_denied_without_signature_work() -> None:
    verifier = FakeVerifier()
    receipt = AntigravityEligibilityEvaluator(verifier).evaluate(  # type: ignore[arg-type]
        _input(provider_location="global", terms_revision="stale"), policy=_policy()
    )
    assert receipt.decision == "DENY"
    assert receipt.reason_codes == (
        "PROVIDER_LOCATION_MISMATCH",
        "TERMS_REVISION_MISMATCH",
    )
    assert verifier.calls == 0
