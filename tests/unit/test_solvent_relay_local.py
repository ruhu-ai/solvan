from __future__ import annotations

import ast
import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from apps.solvant_relay.cloud_monitoring import CloudMonitoringRelayAdapter, _ratio
from apps.solvant_relay.control_client import RelayControlClient
from apps.solvant_relay.ledger import AttemptRecord, EncryptedAttemptLedger, RelayLedgerError
from apps.solvant_relay.main import RelayConfigurationError, _local_kill_switch_engaged
from apps.solvant_relay.policy import RelayPolicyError, verify_local_policy
from apps.solvant_relay.readiness import build_runtime_policy_proof, verify_readiness_challenge
from apps.solvant_relay.redaction import RedactionError, evidence_envelope
from apps.solvant_relay.runtime import RelayAttemptRunner, RelayRuntimeError
from apps.solvant_relay.signatures import EcdsaJobVerifier
from solvan.domain import RelayReadinessChallenge, canonical_digest

HASH = "sha256:" + "a" * 64


def _identifier(prefix: str) -> str:
    return prefix + "_" + "0" * 26


def test_customer_relay_has_no_listener_or_mutation_dependency_boundary() -> None:
    root = Path(__file__).resolve().parents[2] / "apps" / "solvant_relay"
    forbidden = {
        "fastapi",
        "uvicorn",
        "subprocess",
        "solvan.connectors.mutation",
        "solvan.application.actuator",
        "solvan.persistence.action_store",
    }
    imported: set[str] = set()
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in imported
        for prefix in forbidden
    )


def test_monitoring_ratio_is_derived_from_bounded_aligned_projections() -> None:
    records = _ratio(
        total=(
            {"timestamp": "2026-08-15T10:00:00+00:00", "value": 100.0},
            {"timestamp": "2026-08-15T10:01:00+00:00", "value": 0.0},
        ),
        failures=({"timestamp": "2026-08-15T10:00:00+00:00", "value": 5.0},),
        maximum_bytes=2_000,
    )
    assert [record["value"] for record in records] == [0.05, 0.0]
    assert {record["metric_key"] for record in records} == {"http_5xx_ratio"}


def test_customer_deployment_template_has_no_ingress_or_solvant_identity() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = (root / "infra" / "customer-relay" / "gke-cronjob.yaml").read_text(encoding="utf-8")
    cloud_run = (root / "infra" / "customer-relay" / "cloud-run-job.yaml").read_text(
        encoding="utf-8"
    )
    onprem = (root / "infra" / "customer-relay" / "onprem-compose.yaml").read_text(encoding="utf-8")
    unit = (root / "infra" / "customer-relay" / "solvant-relay.service").read_text(encoding="utf-8")
    image = (root / "Dockerfile.solvant-relay").read_text(encoding="utf-8")
    assert "kind: CronJob" in manifest
    assert "kind: Service" not in manifest
    assert "kind: Ingress" not in manifest
    assert "PORT=" not in image
    assert "uvicorn" not in image
    assert "kind: Job" in cloud_run
    assert "kind: Service" not in cloud_run
    assert "ports:" not in cloud_run
    assert "read_only: true" in onprem
    assert "cap_drop: [ALL]" in onprem
    assert "ports:" not in onprem
    assert "--read-only" in unit
    assert "--cap-drop ALL" in unit


def test_customer_local_kill_switch_is_explicit_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    switch = tmp_path / "state"
    monkeypatch.delenv("SOLVANT_RELAY_KILL_SWITCH_PATH", raising=False)
    assert _local_kill_switch_engaged() is False

    switch.write_text("ENGAGED\n", encoding="ascii")
    monkeypatch.setenv("SOLVANT_RELAY_KILL_SWITCH_PATH", str(switch))
    assert _local_kill_switch_engaged() is True

    switch.write_text("not a state", encoding="ascii")
    with pytest.raises(RelayConfigurationError, match="invalid state"):
        _local_kill_switch_engaged()


def _policy(*, key: ec.EllipticCurvePrivateKey, now: datetime) -> dict[str, object]:
    policy: dict[str, object] = {
        "schema_version": 1,
        "policy_id": _identifier("rpol"),
        "organization_binding_hash": HASH,
        "relay_connection_id": _identifier("con"),
        "relay_connection_epoch": 1,
        "relay_enrollment_id": _identifier("ren"),
        "relay_enrollment_epoch": 1,
        "relay_image_digest": HASH,
        "control_plane_audience": "https://relay-control.example",
        "region": "europe-west1",
        "classification_ceiling": "CONFIDENTIAL",
        "connector_catalog_digest": HASH,
        "redaction_revision": "relay-redaction-v1",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "maximum_concurrent_jobs": 1,
        "adapters": [
            {
                "adapter_key": "cloud-monitoring.v1",
                "adapter_revision": "1",
                "source_connection_id": _identifier("con"),
                "source_connection_epoch": 3,
                "metrics_scope_project_id": "customer-metrics-project",
                "credential_ref": "customer-secret://monitoring-reader",
                "endpoint": {"scheme": "https", "host": "monitoring.googleapis.com", "port": 443},
                "tls_policy": {
                    "minimum_version": "TLS1_2",
                    "redirects": "DENY",
                    "server_name": "monitoring.googleapis.com",
                    "ca_bundle_ref": None,
                    "client_certificate_ref": None,
                },
                "operations": ["monitoring.time-series.read.v1"],
                "maximum_response_bytes": 100000,
                "maximum_pages": 2,
                "maximum_calls_per_job": 2,
                "maximum_calls_per_minute": 10,
            }
        ],
    }
    digest = canonical_digest(policy)
    signature = key.sign(
        bytes.fromhex(digest.removeprefix("sha256:")), ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    policy["signature"] = {
        "algorithm": "ECDSA_P256_SHA256",
        "key_id": "customer-policy-key-1",
        "signed_digest": digest,
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return policy


def test_verified_policy_is_exact_and_denies_a_substituted_operation() -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policy = verify_local_policy(
        _policy(key=key, now=now),
        key_resolver=lambda key_id: pem if key_id == "customer-policy-key-1" else b"",
        now=now,
        expected_image_digest=HASH,
        expected_audience="https://relay-control.example",
    )
    assert (
        policy.adapter_for(
            adapter_key="cloud-monitoring.v1",
            source_connection_id=_identifier("con"),
            source_connection_epoch=3,
            operation="monitoring.time-series.read.v1",
        )["endpoint"]["host"]
        == "monitoring.googleapis.com"
    )
    with pytest.raises(RelayPolicyError, match="operation"):
        policy.adapter_for(
            adapter_key="cloud-monitoring.v1",
            source_connection_id=_identifier("con"),
            source_connection_epoch=3,
            operation="logging.entries.read.v1",
        )


def test_policy_refuses_a_tampered_or_expired_document() -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    tampered = _policy(key=key, now=now)
    tampered["region"] = "us-central1"
    with pytest.raises(RelayPolicyError, match="signed digest"):
        verify_local_policy(
            tampered,
            key_resolver=lambda _key_id: pem,
            now=now,
            expected_image_digest=HASH,
            expected_audience="https://relay-control.example",
        )
    expired = _policy(key=key, now=now - timedelta(minutes=2))
    with pytest.raises(RelayPolicyError, match="not currently valid"):
        verify_local_policy(
            expired,
            key_resolver=lambda _key_id: pem,
            now=now,
            expected_image_digest=HASH,
            expected_audience="https://relay-control.example",
        )


def test_readiness_challenge_requires_a_control_signature_and_exact_local_policy() -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    policy_key = ec.generate_private_key(ec.SECP256R1())
    policy_key_pem = policy_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policy = verify_local_policy(
        _policy(key=policy_key, now=now),
        key_resolver=lambda _key_id: policy_key_pem,
        now=now,
        expected_image_digest=HASH,
        expected_audience="https://relay-control.example",
    )
    nonce = "nonce-1"
    unsigned_challenge = RelayReadinessChallenge(
        challenge_id=_identifier("rch"),
        challenge_digest=HASH,
        nonce_hash="sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        enrollment_id=policy.enrollment_id,
        enrollment_epoch=policy.enrollment_epoch,
        placement_epoch=1,
        cell_id="cell-europe",
        principal_claims_hash=HASH,
        expected_audience=policy.control_plane_audience,
        process_boot_id="boot-1",
        image_digest=policy.image_digest,
        local_policy_digest=policy.digest,
        policy_key_id=policy.policy_key_id,
        connector_catalog_digest=policy.connector_catalog_digest,
        redaction_revision=policy.redaction_revision,
        runtime_proof_key_id="runtime-v1",
        runtime_proof_key_digest=HASH,
        region=policy.region,
        classification_ceiling=policy.classification_ceiling,
        signing_key_id="control-v1",
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )
    digest_fields = unsigned_challenge.unsigned_projection(nonce=nonce)
    digest_fields.pop("nonce")
    digest_fields.pop("challenge_digest")
    challenge = replace(unsigned_challenge, challenge_digest=canonical_digest(digest_fields))
    payload = challenge.unsigned_projection(nonce=nonce)
    control_key = ec.generate_private_key(ec.SECP256R1())
    signature = control_key.sign(
        bytes.fromhex(canonical_digest(payload).removeprefix("sha256:")),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    verified, returned_nonce = verify_readiness_challenge(
        {
            "challenge": payload,
            "signing_key_id": "control-v1",
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        },
        key_resolver=lambda _key_id: control_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        now=now,
    )
    runtime_key = ec.generate_private_key(ec.SECP256R1())
    proof = build_runtime_policy_proof(
        challenge=verified,
        policy=policy,
        runtime_proof_key_id="runtime-v1",
        private_key_resolver=lambda _key_id: runtime_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        now=now,
    )
    assert returned_nonce == nonce
    assert proof.local_policy_verified
    assert proof.proof_digest != HASH


def _attempt(now: datetime, *, state: str = "LOCAL_RESULT_STORED") -> AttemptRecord:
    return AttemptRecord(
        collection_job_id=_identifier("rcj"),
        attempt_id=_identifier("rat"),
        attempt_number=1,
        job_digest=HASH,
        claim_token="00000000-0000-0000-0000-000000000001",
        process_boot_id="boot-1",
        state=state,
        input_hash=HASH,
        outcome_hash=HASH,
        local_result_hash="sha256:" + hashlib.sha256(b"redacted evidence").hexdigest(),
        created_at=now,
        updated_at=now,
    )


def test_encrypted_attempt_ledger_binds_attempt_and_purges_only_after_ack(tmp_path: Path) -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    ledger = EncryptedAttemptLedger(directory=tmp_path, key=b"k" * 32, max_records=1)
    record = _attempt(now)
    ledger.upsert(record, result_bytes=b"redacted evidence")
    assert ledger.read_result(record.attempt_id) == b"redacted evidence"
    assert ledger.purge(now=now + timedelta(days=8), legal_hold=True) == 0
    assert ledger.pending_reconciliation(now=now + timedelta(days=8)) == (record,)
    acknowledged = replace(
        record,
        acknowledged_at=now + timedelta(minutes=1),
        updated_at=now + timedelta(minutes=1),
    )
    ledger.upsert(acknowledged)
    assert ledger.purge(now=now + timedelta(days=2), legal_hold=False) == 1
    assert ledger.read_result(record.attempt_id) is None


def test_terminal_status_acknowledges_local_attempt_without_replaying_a_read(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    ledger = EncryptedAttemptLedger(directory=tmp_path, key=b"k" * 32)
    record = _attempt(now)
    ledger.upsert(record, result_bytes=b"redacted evidence")

    class TerminalControl(_Control):
        def status(self, **_kwargs: object) -> dict[str, object]:
            return {
                "collection_job_id": record.collection_job_id,
                "job_digest": record.job_digest,
                "state": "ACCEPTED",
            }

    runner = RelayAttemptRunner(
        control=TerminalControl(),
        job_verifier=_JobVerifier(),
        monitoring=_Monitoring(),
        uploader=_Uploader(),
        ledger=ledger,
        process_boot_id="boot-1",
    )
    assert runner.acknowledge_terminal_outcomes(now=now + timedelta(minutes=1)) == 1
    recovered = ledger.pending_reconciliation(now=now + timedelta(minutes=2))
    assert recovered == ()


def test_ledger_refuses_a_full_disk_before_a_second_claim(tmp_path: Path) -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    ledger = EncryptedAttemptLedger(directory=tmp_path, key=b"k" * 32, max_records=1)
    ledger.upsert(_attempt(now))
    second = replace(_attempt(now), attempt_id=_identifier("rat").replace("0", "1", 1))
    with pytest.raises(RelayLedgerError, match="full"):
        ledger.upsert(second)


def test_redaction_projects_only_typed_metric_fields_and_withholds_pii() -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    envelope, content_hash, manifest_hash = evidence_envelope(
        collection_job_id=_identifier("rcj"),
        job_digest=HASH,
        adapter_key="cloud-monitoring.v1",
        adapter_revision="1",
        operation="monitoring.time-series.read.v1",
        resource_binding_id=_identifier("pgn"),
        resource_binding_hash=HASH,
        window_start=now - timedelta(minutes=1),
        window_end=now,
        classification="INTERNAL",
        residency_region="europe-west1",
        redaction_revision="relay-redaction-v1",
        observed_at=now,
        records=[
            {
                "metric_key": "request_count",
                "timestamp": now.isoformat(),
                "value": 4,
                "unit": "1",
                "attributes": {"service.name": "payments-api", "cloud.region": "europe-west1"},
            }
        ],
    )
    assert envelope["records"][0]["kind"] == "METRIC_POINT"
    assert content_hash.startswith("sha256:") and manifest_hash.startswith("sha256:")
    with pytest.raises(RedactionError, match="sensitive"):
        evidence_envelope(
            collection_job_id=_identifier("rcj"),
            job_digest=HASH,
            adapter_key="cloud-monitoring.v1",
            adapter_revision="1",
            operation="monitoring.time-series.read.v1",
            resource_binding_id=_identifier("pgn"),
            resource_binding_hash=HASH,
            window_start=now - timedelta(minutes=1),
            window_end=now,
            classification="INTERNAL",
            residency_region="europe-west1",
            redaction_revision="relay-redaction-v1",
            observed_at=now,
            records=[
                {
                    "metric_key": "request_count",
                    "timestamp": now.isoformat(),
                    "value": 4,
                    "unit": "1",
                    "attributes": {"service.name": "operator@example.com"},
                }
            ],
        )


class _JobVerifier:
    def verify(self, envelope: dict[str, object]) -> dict[str, object]:
        assert envelope["signature_base64"] == "control-signature"
        return envelope


class _Control:
    def __init__(self) -> None:
        self.receipts: list[dict[str, object]] = []
        self.retry_bodies: list[dict[str, object]] = []

    def claim(self, **_kwargs: object) -> dict[str, object]:
        return {
            "claim_token": "00000000-0000-0000-0000-000000000001",
            "attempt_id": _identifier("rat"),
            "attempt_number": 1,
        }

    def upload_grant(self, **_kwargs: object) -> dict[str, object]:
        return {
            "put_url": "https://upload.example/object",
            "required_headers": {"x-goog-hash": "sha256=example"},
            "object_ref": "gs://customer-eu/relay/evidence.json",
            "upload_grant_id": _identifier("rug"),
            "upload_grant_digest": HASH,
        }

    def receipt(self, **kwargs: object) -> dict[str, object]:
        self.receipts.append(kwargs["body"])  # type: ignore[arg-type]
        return {"status": "accepted"}

    def retryable_outcome(self, **kwargs: object) -> dict[str, object]:
        self.retry_bodies.append(kwargs["body"])  # type: ignore[arg-type]
        return {"status": "retry_wait"}

    def status(self, **_kwargs: object) -> dict[str, object]:
        return {"state": "EXECUTING"}


class _Monitoring:
    def read(self, **_kwargs: object) -> list[dict[str, object]]:
        return [
            {
                "metric_key": "request_count",
                "timestamp": datetime(2026, 8, 15, tzinfo=UTC).isoformat(),
                "value": 4,
                "unit": "1",
                "attributes": {"service.name": "payments-api"},
            }
        ]


class _Uploader:
    def upload(self, **kwargs: object) -> dict[str, str]:
        assert kwargs["url"] == "https://upload.example/object"
        return {"object_generation": "1", "object_metadata_hash": HASH}


def test_customer_relay_executes_only_a_verified_policy_and_signed_monitoring_job(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policy = verify_local_policy(
        _policy(key=key, now=now),
        key_resolver=lambda _key_id: pem,
        now=now,
        expected_image_digest=HASH,
        expected_audience="https://relay-control.example",
    )
    parameters = {"metric_key": "request_count", "alignment_seconds": 60}
    control = _Control()
    runner = RelayAttemptRunner(
        control=control,
        job_verifier=_JobVerifier(),
        monitoring=_Monitoring(),
        uploader=_Uploader(),
        ledger=EncryptedAttemptLedger(directory=tmp_path, key=b"k" * 32),
        process_boot_id="boot-1",
    )
    attempt_id = runner.execute(
        policy=policy,
        now=now,
        envelope={
            "signature_base64": "control-signature",
            "job": {
                "schema_version": 1,
                "canonicalization_version": 1,
                "scope_hash": HASH,
                "collection_job_id": _identifier("rcj"),
                "job_digest": HASH,
                "enrollment_id": _identifier("ren"),
                "enrollment_epoch": 1,
                "relay_connection_id": _identifier("con"),
                "relay_connection_epoch": 1,
                "source_binding_id": _identifier("rsb"),
                "adapter_key": "cloud-monitoring.v1",
                "adapter_revision": "1",
                "source_connection_id": _identifier("con"),
                "source_connection_epoch": 3,
                "placement_epoch": 1,
                "cell_id": "cell-europe",
                "agent_run_id": "run-1",
                "tool_call_id": "tcl-1",
                "tool_arguments_hash": HASH,
                "incident_id": "inc-1",
                "profile_key": "gcp-observe.v1",
                "profile_version": "1",
                "profile_material_hash": HASH,
                "profile_ordinal": 1,
                "tool_key": "monitoring.time-series.read.v1",
                "tool_version": "1",
                "capability_receipt_id": "cap-1",
                "capability_receipt_hash": HASH,
                "connector_catalog_key": "gcp-observe.v1",
                "connector_catalog_revision": 1,
                "connector_catalog_digest": HASH,
                "operation": "monitoring.time-series.read.v1",
                "typed_parameters": parameters,
                "parameters_hash": canonical_digest(parameters),
                "resource_binding_id": _identifier("pgn"),
                "graph_snapshot_id": _identifier("pgs"),
                "resource_binding_hash": HASH,
                "window_start": (now - timedelta(minutes=1)).isoformat(),
                "window_end": now.isoformat(),
                "maximum_pages": 2,
                "maximum_items": 100,
                "maximum_bytes": 100_000,
                "maximum_calls": 2,
                "maximum_attempts": 2,
                "redaction_revision": "relay-redaction-v1",
                "classification_ceiling": "CONFIDENTIAL",
                "residency_region": "europe-west1",
                "input_hash": HASH,
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=90)).isoformat(),
                "job_nonce": "nonce-1",
                "signing_key_id": "control-v1",
            },
        },
    )
    assert attempt_id.startswith("rat_")
    assert control.receipts[0]["result"] == "SUCCEEDED"
    assert control.receipts[0]["evidence"]["object_ref"] == "gs://customer-eu/relay/evidence.json"


def test_customer_relay_refuses_an_unsigned_or_unrecognized_operation_before_provider(
    tmp_path: Path,
) -> None:
    class RefusingVerifier:
        def verify(self, _envelope: dict[str, object]) -> dict[str, object]:
            raise RelayRuntimeError("control signature is invalid")

    runner = RelayAttemptRunner(
        control=_Control(),
        job_verifier=RefusingVerifier(),
        monitoring=_Monitoring(),
        uploader=_Uploader(),
        ledger=EncryptedAttemptLedger(directory=tmp_path, key=b"k" * 32),
        process_boot_id="boot-1",
    )
    with pytest.raises(RelayRuntimeError, match="signature"):
        runner.execute(
            policy=None,  # type: ignore[arg-type]
            now=datetime(2026, 8, 15, tzinfo=UTC),
            envelope={},
        )


def test_control_job_signature_binds_the_unsigned_job_bytes() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    unsigned = {
        "collection_job_id": _identifier("rcj"),
        "operation": "monitoring.time-series.read.v1",
    }
    digest = canonical_digest(unsigned)
    job = {**unsigned, "job_digest": digest}
    signature = key.sign(
        bytes.fromhex(digest.removeprefix("sha256:")), ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    verifier = EcdsaJobVerifier(key_resolver=lambda _key_id: public_pem)
    signed = {
        "job": job,
        "job_digest": digest,
        "signing_key_id": "relay-control-v1",
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    assert verifier.verify(signed) == {"job": job}
    job["operation"] = "http.get"
    with pytest.raises(RelayRuntimeError, match="digest"):
        verifier.verify(signed)


class _MonitoringResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


class _MonitoringSession:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.params: dict[str, object] | None = None

    def get(self, _url: str, **kwargs: object) -> _MonitoringResponse:
        self.params = kwargs["params"]  # type: ignore[assignment]
        return _MonitoringResponse(self.payload)


def test_cloud_monitoring_adapter_uses_bound_metric_scope_and_refuses_wrong_project() -> None:
    now = datetime(2026, 8, 15, tzinfo=UTC)
    session = _MonitoringSession(
        {
            "timeSeries": [
                {
                    "resource": {"labels": {"project_id": "customer-app-project"}},
                    "points": [
                        {
                            "interval": {"endTime": now.isoformat()},
                            "value": {"int64Value": "9"},
                        }
                    ],
                }
            ]
        }
    )
    adapter = CloudMonitoringRelayAdapter(session=session)  # type: ignore[arg-type]
    records = adapter.read(
        adapter={
            "metrics_scope_project_id": "customer-metrics-project",
            "endpoint": {"host": "monitoring.googleapis.com"},
        },
        parameters={
            "metric_key": "request_count",
            "resource_binding_id": _identifier("pgn"),
            "resource_project_id": "customer-app-project",
            "resource_kind": "CLOUD_RUN_SERVICE",
            "resource_name": "payments-api",
            "window_start": (now - timedelta(minutes=1)).isoformat(),
            "window_end": now.isoformat(),
            "alignment_seconds": 60,
            "maximum_points": 100,
        },
        maximum_pages=1,
        maximum_items=100,
        maximum_bytes=100_000,
        maximum_calls=1,
    )
    assert records[0]["value"] == 9.0
    assert session.params is not None
    assert "projects/customer-metrics-project" not in str(session.params)
    assert 'resource.label."project_id"="customer-app-project"' in str(session.params)
    session.payload["timeSeries"][0]["resource"]["labels"]["project_id"] = "other-project"  # type: ignore[index]
    with pytest.raises(RelayRuntimeError, match="attribution"):
        adapter.read(
            adapter={
                "metrics_scope_project_id": "customer-metrics-project",
                "endpoint": {"host": "monitoring.googleapis.com"},
            },
            parameters={
                "metric_key": "request_count",
                "resource_binding_id": _identifier("pgn"),
                "resource_project_id": "customer-app-project",
                "resource_kind": "CLOUD_RUN_SERVICE",
                "resource_name": "payments-api",
                "window_start": (now - timedelta(minutes=1)).isoformat(),
                "window_end": now.isoformat(),
                "alignment_seconds": 60,
                "maximum_points": 100,
            },
            maximum_pages=1,
            maximum_items=100,
            maximum_bytes=100_000,
            maximum_calls=1,
        )


class _Tokens:
    def token(self, *, audience: str) -> str:
        assert audience == "https://relay-control.example"
        return "customer-oidc-token"


def test_control_client_is_outbound_only_and_uses_the_exact_protocol_route() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(204, request=request)

    client = RelayControlClient(
        audience="https://relay-control.example",
        token_provider=_Tokens(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.poll(body={"schema_version": 1}) is None
    assert calls[0].url == "https://relay-control.example/internal/v1/relay/poll"
    assert calls[0].headers["authorization"] == "Bearer customer-oidc-token"
    with pytest.raises(ValueError, match="HTTPS"):
        RelayControlClient(audience="http://relay-control.example", token_provider=_Tokens())
