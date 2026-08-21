import hashlib
from datetime import UTC, datetime, timedelta

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from solvan.domain import Scope
from solvan.platform import (
    AttestationPolicy,
    AttestationVerificationError,
    SyntheticAttestationVerifier,
)

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
KEY_VERSION = (
    "projects/solvan-demo/locations/europe-west1/keyRings/workspace/"
    "cryptoKeys/synthetic-attester/cryptoKeyVersions/1"
)


class FakeEvidenceReader:
    def __init__(self, signature: bytes) -> None:
        self.signature = signature

    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int) -> bytes:
        assert uri == "gs://evidence/attestations/signature.der"
        assert expected_hash == _sha(self.signature)
        assert max_bytes == 512
        return self.signature


class FakeKmsReader:
    def __init__(self, public_key: bytes) -> None:
        self.public_key = public_key

    def public_key_pem(self, key_version: str) -> bytes:
        assert key_version == KEY_VERSION
        return self.public_key


def _sha(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _signed_attestation(
    *, issuer: str = "serviceAccount:fixture-attester@solvan-demo.iam.gserviceaccount.com"
) -> tuple[dict[str, object], ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    signed = {
        "schema_version": 1,
        "attestation_id": "att_00000000000000000000000000",
        **SCOPE.canonical_dict(),
        "release_commit": "a" * 40,
        "deployment_id": "deploy-20260808-01",
        "fixture_id": "synthetic-payments-leak-v1",
        "classification": "PUBLIC",
        "synthetic": True,
        "artifact_manifest_ref": "gs://evidence/workspaces/input-manifest.json",
        "artifact_manifest_hash": f"sha256:{'1' * 64}",
        "issuer_principal": issuer,
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "canonicalization": "RFC8785",
        "signature_algorithm": "EC_SIGN_P256_SHA256",
        "kms_key_version": KEY_VERSION,
    }
    payload = rfc8785.dumps(signed)
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return (
        {
            **signed,
            "signed_payload_hash": _sha(payload),
            "signature_ref": "gs://evidence/attestations/signature.der",
            "signature_hash": _sha(signature),
            "_signature": signature,
        },
        key,
    )


def _policy(**changes: object) -> AttestationPolicy:
    values: dict[str, object] = {
        "scope": SCOPE,
        "release_commit": "a" * 40,
        "deployment_id": "deploy-20260808-01",
        "allowed_issuer_principals": frozenset(
            {"serviceAccount:fixture-attester@solvan-demo.iam.gserviceaccount.com"}
        ),
        "allowed_kms_key_versions": frozenset({KEY_VERSION}),
        "artifact_manifest_ref": "gs://evidence/workspaces/input-manifest.json",
        "artifact_manifest_hash": f"sha256:{'1' * 64}",
        "now": NOW,
    }
    values.update(changes)
    return AttestationPolicy(**values)  # type: ignore[arg-type]


def _verifier(
    value: dict[str, object], key: ec.EllipticCurvePrivateKey
) -> SyntheticAttestationVerifier:
    signature = value.pop("_signature")
    assert isinstance(signature, bytes)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return SyntheticAttestationVerifier(
        evidence_reader=FakeEvidenceReader(signature),  # type: ignore[arg-type]
        kms_reader=FakeKmsReader(public_pem),
    )


def test_valid_attestation_is_signature_release_scope_and_manifest_bound() -> None:
    value, key = _signed_attestation()
    verifier = _verifier(value, key)
    verified = verifier.verify(value, policy=_policy())
    assert verified.fixture_id == "synthetic-payments-leak-v1"
    assert verified.synthetic is True


@pytest.mark.parametrize(
    ("policy_change", "message"),
    [
        ({"release_commit": "b" * 40}, "release or deployment"),
        ({"artifact_manifest_hash": f"sha256:{'2' * 64}"}, "manifest binding"),
        ({"allowed_issuer_principals": frozenset({"serviceAccount:other@example.com"})}, "issuer"),
        ({"now": NOW + timedelta(hours=2)}, "currently valid"),
    ],
)
def test_attestation_policy_changes_fail_closed(
    policy_change: dict[str, object], message: str
) -> None:
    value, key = _signed_attestation()
    verifier = _verifier(value, key)
    with pytest.raises(AttestationVerificationError, match=message):
        verifier.verify(value, policy=_policy(**policy_change))


def test_model_or_caller_cannot_change_signed_synthetic_material() -> None:
    value, key = _signed_attestation()
    verifier = _verifier(value, key)
    value["fixture_id"] = "model-authored-fixture"
    with pytest.raises(AttestationVerificationError, match="schema is invalid"):
        verifier.verify(value, policy=_policy())
