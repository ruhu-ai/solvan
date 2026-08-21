import hashlib
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from apps.fixture_attester.main import AttesterSettings, create_app
from solvan.domain import Scope
from solvan.platform.evidence_objects import ObjectReceipt

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
WORKSPACE_ID = "wsp_00000000000000000000000000"
RUNTIME_BUCKET = "solvan-runtime"
EVIDENCE_BUCKET = "solvan-evidence"
MANIFEST_REF = (
    f"gs://{RUNTIME_BUCKET}/{SCOPE.organization_id}/{SCOPE.project_id}/"
    f"{SCOPE.environment_id}/workspaces/{WORKSPACE_ID}/input-manifest.json"
)
MANIFEST_HASH = f"sha256:{'1' * 64}"


class FixedClock:
    def now(self) -> datetime:
        return NOW


class FakeVerifier:
    def verify(self, token: str, *, audience: str) -> dict[str, str]:
        assert token == "coordinator-token"
        assert audience == "https://fixture-attester.example.run.app"
        return {"email": "coordinator@example.iam.gserviceaccount.com"}


class FakeReader:
    def __init__(self, manifest: dict[str, object]) -> None:
        self.manifest = manifest

    def get_json(self, *, uri: str, expected_hash: str, max_bytes: int) -> dict[str, object]:
        assert uri == MANIFEST_REF
        assert expected_hash == MANIFEST_HASH
        assert max_bytes == 2_000_000
        return self.manifest


class FakeSigner:
    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes:
        assert len(digest) == 32
        assert key_version.endswith("/cryptoKeyVersions/1")
        return b"strict-detached-signature"


class FakeWriter:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> ObjectReceipt:
        del content_type
        self.objects[object_name] = content
        return self._receipt(object_name, content)

    def put_json(self, *, object_name: str, value: dict[str, object]) -> ObjectReceipt:
        content = str(sorted(value.items())).encode()
        self.objects[object_name] = content
        return self._receipt(object_name, content)

    @staticmethod
    def _receipt(object_name: str, content: bytes) -> ObjectReceipt:
        return ObjectReceipt(
            uri=f"gs://{EVIDENCE_BUCKET}/{object_name}",
            content_hash=f"sha256:{hashlib.sha256(content).hexdigest()}",
            generation="1",
        )


def _settings() -> AttesterSettings:
    return AttesterSettings(
        scope=SCOPE,
        release_commit="a" * 40,
        deployment_id="deploy-20260808-01",
        coordinator_service_account="coordinator@example.iam.gserviceaccount.com",
        attester_service_account="fixture-attester@example.iam.gserviceaccount.com",
        audience="https://fixture-attester.example.run.app",
        runtime_bucket=RUNTIME_BUCKET,
        evidence_bucket=EVIDENCE_BUCKET,
        fixture_prefix=f"gs://{RUNTIME_BUCKET}/fixtures/payments-leak-v1/",
        fixture_ids=frozenset({"payments-leak-v1"}),
        kms_key_version=(
            "projects/demo/locations/europe-west1/keyRings/workspace/"
            "cryptoKeys/synthetic-attester/cryptoKeyVersions/1"
        ),
    )


def _manifest(*, entry_ref: str | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "manifest_kind": "INPUT",
        "workspace_id": WORKSPACE_ID,
        "workspace_generation": 1,
        "checkpoint_sequence": None,
        "parent_manifest_ref": None,
        "parent_manifest_hash": None,
        "classification": "PUBLIC",
        "synthetic": True,
        "entries": [
            {
                "path": "src/payments.py",
                "object_ref": entry_ref
                or f"gs://{RUNTIME_BUCKET}/fixtures/payments-leak-v1/repository.json#path=x",
                "content_hash": f"sha256:{'2' * 64}",
                "size_bytes": 12,
                "media_type": "text/plain",
                "provenance_refs": ["fixture:payments-leak-v1"],
            }
        ],
        "created_by": "serviceAccount:coordinator@example.iam.gserviceaccount.com",
        "created_at": NOW.isoformat(),
    }


def _client(manifest: dict[str, object], writer: FakeWriter | None = None) -> TestClient:
    return TestClient(
        create_app(
            settings=_settings(),
            reader=FakeReader(manifest),
            writer=writer or FakeWriter(),
            signer=FakeSigner(),
            verifier=FakeVerifier(),
            clock=FixedClock(),
        )
    )


def _request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "workspace_id": WORKSPACE_ID,
        "workspace_generation": 1,
        "fixture_id": "payments-leak-v1",
        "artifact_manifest_ref": MANIFEST_REF,
        "artifact_manifest_hash": MANIFEST_HASH,
    }


def test_attester_signs_only_exact_public_synthetic_fixture_manifest() -> None:
    writer = FakeWriter()
    response = _client(_manifest(), writer).post(
        "/internal/v1/synthetic-attestations",
        json=_request(),
        headers={"Authorization": "Bearer coordinator-token"},
    )
    assert response.status_code == 200
    value = response.json()
    assert value["attestation"]["synthetic"] is True
    assert value["attestation"]["classification"] == "PUBLIC"
    assert value["attestation"]["release_commit"] == "a" * 40
    assert value["attestation"]["signature_algorithm"] == "EC_SIGN_P256_SHA256"
    assert len(writer.objects) == 2


def test_attester_rejects_source_outside_fixture_prefix_before_signing() -> None:
    response = _client(_manifest(entry_ref="gs://private/customer/repository.json")).post(
        "/internal/v1/synthetic-attestations",
        json=_request(),
        headers={"Authorization": "Bearer coordinator-token"},
    )
    assert response.status_code == 422
    assert "outside the isolated synthetic fixture prefix" in response.json()["detail"]


def test_attester_rejects_wrong_caller() -> None:
    response = _client(_manifest()).post(
        "/internal/v1/synthetic-attestations",
        json=_request(),
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401
