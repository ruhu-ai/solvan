from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi.testclient import TestClient
from psycopg import Connection

from apps.relay_control.main import KmsSigner, RelayControlSettings, TokenVerifier, create_app
from solvan.domain import (
    RelayEnrollmentState,
    RelayIdentityBinding,
    RelayJobClaim,
    RelayReadinessChallenge,
    Scope,
)
from solvan.persistence.relay_store import IssuedReadinessChallenge


class Verifier(TokenVerifier):
    def __init__(self, claims: dict[str, object] | None = None) -> None:
        self.claims = claims or {"iss": "https://issuer.example", "sub": "relay-subject"}

    def verify(self, token: str, *, audience: str) -> dict[str, object]:
        assert token == "relay-token"
        assert audience == "https://relay-control.example"
        return self.claims


class Database(AbstractContextManager[Connection[Any]]):
    committed = False

    def __enter__(self) -> Connection[Any]:
        return cast(Connection[Any], self)

    def __exit__(self, *_args: object) -> None:
        return None

    def commit(self) -> None:
        self.committed = True


class Store:
    def __init__(self) -> None:
        self.claim_scope: Scope | None = None

    def resolve_verified_identity(
        self, *, issuer: str, subject: str, audience: str
    ) -> RelayIdentityBinding | None:
        assert (issuer, subject, audience) == (
            "https://issuer.example",
            "relay-subject",
            "https://relay-control.example",
        )
        suffix = "0" * 26
        return RelayIdentityBinding(
            "org_" + suffix,
            "prj_" + suffix,
            "env_" + suffix,
            "ren_" + suffix,
            1,
            audience,
            RelayEnrollmentState.READY,
        )

    def submit_deployment_profile(self, **kwargs: object) -> str:
        assert kwargs["principal_issuer"] == "https://issuer.example"
        assert kwargs["principal_subject"] == "relay-subject"
        assert kwargs["expected_audience"] == "https://relay-control.example"
        assert kwargs["relay_connection_id"] == "con_" + "0" * 26
        return "rdp_" + "0" * 26

    def claim_job(self, *, scope: Scope, **kwargs: object) -> RelayJobClaim:
        self.claim_scope = scope
        assert kwargs["enrollment_id"] == "ren_" + "0" * 26
        return RelayJobClaim(
            collection_job_id=cast(str, kwargs["collection_job_id"]),
            job_digest=cast(str, kwargs["job_digest"]),
            claim_token="00000000-0000-0000-0000-000000000001",
            attempt_id="rat_" + "0" * 26,
            attempt_number=1,
            lease_expires_at=datetime(2026, 8, 13, 10, 1, tzinfo=UTC),
            workflow_version=1,
        )

    def issue_readiness_challenge(
        self, *, scope: Scope, **kwargs: object
    ) -> IssuedReadinessChallenge:
        self.claim_scope = scope
        now = cast(datetime, kwargs["issued_at"])
        suffix = "0" * 26
        challenge = RelayReadinessChallenge(
            challenge_id="rch_" + suffix,
            challenge_digest="sha256:" + "2" * 64,
            nonce_hash="sha256:" + "3" * 64,
            enrollment_id="ren_" + suffix,
            enrollment_epoch=1,
            placement_epoch=1,
            cell_id="cell-europe",
            principal_claims_hash="sha256:" + "4" * 64,
            expected_audience="https://relay-control.example",
            process_boot_id=cast(str, kwargs["process_boot_id"]),
            image_digest=cast(str, kwargs["image_digest"]),
            local_policy_digest="sha256:" + "5" * 64,
            policy_key_id="policy-v1",
            connector_catalog_digest="sha256:" + "6" * 64,
            redaction_revision="relay-redaction.v1",
            runtime_proof_key_id=cast(str, kwargs["runtime_proof_key_id"]),
            runtime_proof_key_digest="sha256:" + "7" * 64,
            region="europe-west1",
            classification_ceiling="INTERNAL",
            signing_key_id="control-v1",
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
        )
        return IssuedReadinessChallenge(challenge=challenge, nonce="nonce-value")

    def record_poll_readiness(self, *, scope: Scope, **kwargs: object) -> None:
        self.claim_scope = scope
        assert kwargs["enrollment_epoch"] == 1
        assert kwargs["declared_adapter_revisions"] == ("1",)

    def poll_signed_job(self, *, scope: Scope, enrollment_id: str, now: datetime) -> None:
        assert scope == self.claim_scope
        assert enrollment_id == "ren_" + "0" * 26
        assert now.tzinfo is not None
        return None

    def record_retryable_attempt_failure(self, **kwargs: object) -> object:
        from solvan.persistence.relay_store import RelayRetryOutcome

        assert kwargs["enrollment_id"] == "ren_" + "0" * 26
        return RelayRetryOutcome(
            collection_job_id=cast(str, kwargs["collection_job_id"]),
            attempt_id=cast(str, kwargs["attempt_id"]),
            attempt_number=cast(int, kwargs["attempt_number"]),
            job_state="PENDING",
            action="POLL_FOR_RETRY",
            workflow_version=3,
        )

    def get_job_status(self, **kwargs: object) -> object:
        from solvan.persistence.relay_store import RelayJobStatus

        return RelayJobStatus(
            collection_job_id=cast(str, kwargs["collection_job_id"]),
            job_digest="sha256:" + "1" * 64,
            state="PENDING",
            action="POLL_FOR_RETRY",
            attempt_id="rat_" + "0" * 26,
            attempt_number=1,
            local_result_hash=None,
            cancel_requested=False,
        )

    def acknowledge_cancellation(self, **kwargs: object) -> object:
        assert kwargs["process_boot_id"] == "boot-1"
        return self.get_job_status(collection_job_id=kwargs["collection_job_id"])


class Signer(KmsSigner):
    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes:
        assert key_version.endswith("/1")
        assert len(digest) == 32
        return b"control-signature"


def _client(*, verifier: TokenVerifier | None = None) -> tuple[TestClient, Store, Database]:
    store = Store()
    database = Database()
    app = create_app(
        settings=RelayControlSettings(
            audience="https://relay-control.example",
            signing_key_version=(
                "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
            ),
        ),
        verifier=verifier or Verifier(),
        signer=Signer(),
        connection_factory=lambda: database,
        store_factory=lambda _connection: cast(Any, store),
    )
    return TestClient(app), store, database


def test_claim_requires_verified_identity_and_derives_scope_from_enrollment() -> None:
    client, store, database = _client()
    now = datetime(2026, 8, 13, 10, tzinfo=UTC)
    response = client.post(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26 + "/claim",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "job_digest": "sha256:" + "1" * 64,
            "claim_request_nonce": "nonce-1",
            "process_boot_id": "boot-1",
            "accepted_at": now.isoformat(),
        },
    )
    assert response.status_code == 200
    assert response.json()["workflow_version"] == 1
    assert store.claim_scope is not None
    assert store.claim_scope.organization_id == "org_" + "0" * 26
    assert database.committed


def test_customer_deployment_profile_is_oidc_bound_and_short_lived() -> None:
    client, _store, database = _client()
    response = client.post(
        "/internal/v1/relay/deployment-profiles",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "relay_connection_id": "con_" + "0" * 26,
            "host_kind": "GKE",
            "image_digest": "sha256:" + "1" * 64,
            "image_attestation_id": "ria_" + "0" * 26,
            "local_policy_digest": "sha256:" + "2" * 64,
            "policy_key_id": "policy-v1",
            "connector_catalog_digest": "sha256:" + "3" * 64,
            "redaction_revision": "relay-redaction.v1",
            "region": "europe-west1",
            "classification_ceiling": "INTERNAL",
            "relay_version": "1.0.0",
            "runtime_proof_key_id": "runtime-v1",
            "runtime_proof_public_key_ref": "gs://customer-keys/relay.pub",
            "runtime_proof_public_key_digest": "sha256:" + "4" * 64,
            "egress_manifest_digest": "sha256:" + "5" * 64,
            "local_binding_digest": "sha256:" + "6" * 64,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert response.status_code == 201
    assert response.json() == {
        "deployment_profile_id": "rdp_" + "0" * 26,
        "review_state": "PENDING_REVIEW",
    }
    assert database.committed


def test_claim_rejects_missing_or_malformed_identity() -> None:
    client, _store, _database = _client()
    response = client.post(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26 + "/claim",
        json={
            "schema_version": 1,
            "job_digest": "sha256:" + "1" * 64,
            "claim_request_nonce": "nonce-1",
            "process_boot_id": "boot-1",
            "accepted_at": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "IDENTITY_INVALID"

    invalid, _store, _database = _client(verifier=Verifier({"iss": "not-https", "sub": "x"}))
    response = invalid.post(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26 + "/claim",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "job_digest": "sha256:" + "1" * 64,
            "claim_request_nonce": "nonce-1",
            "process_boot_id": "boot-1",
            "accepted_at": (datetime.now(UTC) + timedelta(seconds=1)).isoformat(),
        },
    )
    assert response.status_code == 401


def test_claim_request_rejects_unknown_fields() -> None:
    client, _store, _database = _client()
    response = client.post(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26 + "/claim",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "job_digest": "sha256:" + "1" * 64,
            "claim_request_nonce": "nonce-1",
            "process_boot_id": "boot-1",
            "accepted_at": datetime.now(UTC).isoformat(),
            "organization_id": "attacker-selected",
        },
    )
    assert response.status_code == 422


def test_readiness_challenge_uses_verified_enrollment_not_body_scope() -> None:
    client, store, database = _client()
    response = client.post(
        "/internal/v1/relay/readiness-challenges",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "process_boot_id": "boot-1",
            "relay_version": "1.0.0",
            "image_digest": "sha256:" + "1" * 64,
            "runtime_proof_key_id": "runtime-v1",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["signing_key_id"] == "control-v1"
    assert body["challenge"]["process_boot_id"] == "boot-1"
    assert body["signature_base64"] == "Y29udHJvbC1zaWduYXR1cmU="
    assert store.claim_scope is not None
    assert store.claim_scope.organization_id == "org_" + "0" * 26
    assert database.committed


def test_poll_records_proof_backed_readiness_before_returning_no_work() -> None:
    client, store, database = _client()
    response = client.post(
        "/internal/v1/relay/poll",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "relay_version": "1.0.0",
            "process_boot_id": "boot-1",
            "image_digest": "sha256:" + "1" * 64,
            "image_attestation_digest": "sha256:" + "2" * 64,
            "local_policy_id": "rpol_" + "0" * 26,
            "local_policy_digest": "sha256:" + "3" * 64,
            "runtime_policy_proof_id": "rpf_" + "0" * 26,
            "runtime_policy_proof_digest": "sha256:" + "4" * 64,
            "connector_catalog_digest": "sha256:" + "5" * 64,
            "relay_connection_epoch": 1,
            "enrollment_epoch": 1,
            "kill_switch_engaged": False,
            "declared_adapter_revisions": ["1"],
        },
    )
    assert response.status_code == 204
    assert response.content == b""
    assert store.claim_scope is not None
    assert database.committed


def test_retryable_attempt_outcome_is_identity_bound_and_content_free() -> None:
    client, _store, database = _client()
    response = client.post(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26 + "/attempt-outcome",
        headers={"Authorization": "Bearer relay-token"},
        json={
            "schema_version": 1,
            "job_digest": "sha256:" + "1" * 64,
            "claim_token": "00000000-0000-0000-0000-000000000001",
            "attempt_id": "rat_" + "0" * 26,
            "attempt_number": 1,
            "process_boot_id": "boot-1",
            "input_hash": "sha256:" + "2" * 64,
            "attempt_outcome_hash": "sha256:" + "3" * 64,
            "error_class": "UPSTREAM_UNAVAILABLE",
            "safe_measurements": {"items": 0, "pages": 0, "bytes": 0, "calls": 1},
            "started_at": "2026-08-13T10:00:00Z",
            "completed_at": "2026-08-13T10:00:01Z",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "collection_job_id": "rcj_" + "0" * 26,
        "attempt_id": "rat_" + "0" * 26,
        "attempt_number": 1,
        "state": "PENDING",
        "action": "POLL_FOR_RETRY",
        "workflow_version": 3,
    }
    assert database.committed


def test_status_is_identity_bound_and_never_returns_evidence_content() -> None:
    client, _store, _database = _client()
    response = client.get(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26,
        headers={"Authorization": "Bearer relay-token"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "POLL_FOR_RETRY"
    assert "evidence" not in body


def test_cancellation_acknowledgement_is_identity_bound() -> None:
    client, _store, database = _client()
    response = client.post(
        "/internal/v1/relay/jobs/rcj_" + "0" * 26 + "/cancel-ack",
        headers={"Authorization": "Bearer relay-token"},
        json={"schema_version": 1, "process_boot_id": "boot-1"},
    )
    assert response.status_code == 200
    assert response.json()["collection_job_id"] == "rcj_" + "0" * 26
    assert database.committed
