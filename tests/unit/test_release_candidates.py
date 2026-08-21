from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from solvan.application.release_candidates import (
    ReleaseCandidateEnvelope,
    ReleaseCandidateError,
    ReleaseCandidateExpected,
    verify_release_candidate,
)
from solvan.application.workspace_hashing import sha256_bytes


class Evidence:
    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values

    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int) -> bytes:
        value = self.values[uri]
        assert len(value) <= max_bytes
        if sha256_bytes(value) != expected_hash:
            raise ValueError("hash mismatch")
        return value


class Kms:
    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self.key = key

    def public_key_pem(self, key_version: str) -> bytes:
        assert key_version.endswith("/1")
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def _candidate(signature_hash: str) -> ReleaseCandidateEnvelope:
    return ReleaseCandidateEnvelope(
        code_change_request_id="ccr_00000000000000000000000000",
        repository_binding_id="ghr_00000000000000000000000000",
        merged_commit_sha="a" * 40,
        source_tree_hash="sha256:" + "b" * 64,
        build_definition_ref="gs://evidence/build.json",
        build_definition_hash=sha256_bytes(b"build"),
        builder_identity="serviceAccount:builder@example.iam.gserviceaccount.com",
        build_invocation_ref="gs://evidence/invocation.json",
        build_invocation_hash=sha256_bytes(b"invocation"),
        build_artifact_ref="registry.example/repo/app@sha256:" + "c" * 64,
        build_artifact_hash="sha256:" + "c" * 64,
        sbom_ref="gs://evidence/sbom.json",
        sbom_hash=sha256_bytes(b"sbom"),
        provenance_predicate_type="https://slsa.dev/provenance/v1",
        provenance_predicate_version="1",
        provenance_ref="gs://evidence/provenance.json",
        provenance_hash=sha256_bytes(b"provenance"),
        signer_identity="serviceAccount:builder@example.iam.gserviceaccount.com",
        signer_key_version="projects/example/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        deployment_manifest_ref="gs://evidence/manifest.json",
        deployment_manifest_hash=sha256_bytes(b"manifest"),
        release_policy_hash="sha256:" + "d" * 64,
        release_signature_ref="gs://evidence/signature.der",
        release_signature_hash=signature_hash,
        issued_at=datetime(2026, 8, 17, tzinfo=UTC),
    )


def test_signed_release_candidate_binds_every_delivery_input() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    unsigned = _candidate("sha256:" + "0" * 64)
    signature = key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    candidate = _candidate(sha256_bytes(signature))
    evidence = Evidence(
        {
            "gs://evidence/build.json": b"build",
            "gs://evidence/invocation.json": b"invocation",
            "gs://evidence/sbom.json": b"sbom",
            "gs://evidence/provenance.json": b"provenance",
            "gs://evidence/manifest.json": b"manifest",
            "gs://evidence/signature.der": signature,
        }
    )
    expected = ReleaseCandidateExpected(
        code_change_request_id=candidate.code_change_request_id,
        repository_binding_id=candidate.repository_binding_id,
        merged_commit_sha=candidate.merged_commit_sha,
        source_tree_hash=candidate.source_tree_hash,
        release_policy_hash=candidate.release_policy_hash,
        signer_identity=candidate.signer_identity,
        signer_key_version=candidate.signer_key_version,
        maximum_age_seconds=3600,
        now=datetime(2026, 8, 17, 0, 30, tzinfo=UTC),
    )
    verify_release_candidate(candidate, expected=expected, evidence=evidence, kms=Kms(key))
    with pytest.raises(ReleaseCandidateError, match="lineage"):
        verify_release_candidate(
            candidate,
            expected=expected.model_copy(update={"source_tree_hash": "sha256:" + "e" * 64}),
            evidence=evidence,
            kms=Kms(key),
        )
