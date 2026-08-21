from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from solvan.application.release_authority import ReleaseHealthSignalInput
from solvan.application.release_verification import (
    HealthSignalMeasurement,
    ReleaseHealthSnapshot,
    ReleaseHealthSnapshotExpected,
    ReleaseVerificationError,
    ReleaseVerificationResult,
    evaluate_release_health,
    verify_release_health_snapshot,
)
from solvan.domain import Scope
from solvan.platform.cloud_run_health import CloudRunHealthError, CloudRunHealthReader


class Response:
    status_code = 200

    def __init__(self, body: dict[str, object], request_id: str = "request-1") -> None:
        self._body = body
        self.headers = {"x-request-id": request_id}
        self.content = b""

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._body


class Session:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> Response:
        self.requests.append((url, kwargs))
        return self.responses.pop(0)


def _series(value: float, *, project: str = "customer-production") -> dict[str, object]:
    return {
        "timeSeries": [
            {
                "resource": {"labels": {"project_id": project, "service_name": "payments-api"}},
                "points": [{"value": {"doubleValue": value}}],
            }
        ]
    }


def _snapshot(*, errors: float, latency: float, points: int = 3) -> ReleaseHealthSnapshot:
    end = datetime(2026, 8, 17, 10, 5, tzinfo=UTC)
    return ReleaseHealthSnapshot(
        scope=Scope(
            "org_00000000000000000000000001",
            "prj_00000000000000000000000001",
            "env_00000000000000000000000001",
        ),
        code_change_request_id="ccr_00000000000000000000000001",
        release_candidate_id="rlc_00000000000000000000000001",
        release_target_profile_id="rtp_00000000000000000000000001",
        target_observation_hash="sha256:" + "1" * 64,
        verification_profile_hash="sha256:" + "2" * 64,
        target_version="7",
        target_assignment_hash="sha256:" + "3" * 64,
        external_project_id="customer-production",
        cloud_run_service_name="payments-api",
        window_start=end - timedelta(minutes=5),
        window_end=end,
        measurements=(
            HealthSignalMeasurement(
                signal_kind="CLOUD_RUN_HTTP_5XX_RATIO",
                value=errors,
                point_count=points,
                request_ids=("errors",),
            ),
            HealthSignalMeasurement(
                signal_kind="CLOUD_RUN_HTTP_P95_LATENCY_MS",
                value=latency,
                point_count=points,
                request_ids=("latency",),
            ),
        ),
        observed_at=end,
    )


def _rules() -> tuple[ReleaseHealthSignalInput, ...]:
    return (
        ReleaseHealthSignalInput(
            signal_kind="CLOUD_RUN_HTTP_5XX_RATIO",
            maximum_value=0.02,
            maximum_regression=0.01,
            minimum_points=2,
        ),
        ReleaseHealthSignalInput(
            signal_kind="CLOUD_RUN_HTTP_P95_LATENCY_MS",
            maximum_value=1000,
            maximum_regression=200,
            minimum_points=2,
        ),
    )


def test_release_health_evaluation_is_application_calculated() -> None:
    assert (
        evaluate_release_health(
            rules=_rules(),
            baseline=_snapshot(errors=0.005, latency=400),
            postdeploy=_snapshot(errors=0.01, latency=550),
        ).result
        is ReleaseVerificationResult.VERIFIED
    )


def test_release_health_snapshot_requires_exact_authority_and_valid_signature() -> None:
    snapshot = _snapshot(errors=0.005, latency=400)
    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(snapshot.signed_payload(), ec.ECDSA(hashes.SHA256()))

    class Evidence:
        def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int) -> bytes:
            assert (uri, expected_hash, max_bytes) == (
                "gs://runtime/baseline.sig",
                "sha256:" + "4" * 64,
                512,
            )
            return signature

    class Kms:
        def public_key_pem(self, key_version: str) -> bytes:
            assert key_version.endswith("/cryptoKeyVersions/1")
            return key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    expected = ReleaseHealthSnapshotExpected(
        scope=snapshot.scope,
        code_change_request_id=snapshot.code_change_request_id,
        release_candidate_id=snapshot.release_candidate_id,
        release_target_profile_id=snapshot.release_target_profile_id,
        target_observation_hash=snapshot.target_observation_hash,
        verification_profile_hash=snapshot.verification_profile_hash,
        target_version=snapshot.target_version,
        target_assignment_hash=snapshot.target_assignment_hash,
        verifier_identity="serviceAccount:release-verifier@example.iam.gserviceaccount.com",
        verifier_key_version=(
            "projects/example/locations/europe-west1/keyRings/releases/cryptoKeys/"
            "verifier/cryptoKeyVersions/1"
        ),
    )
    verify_release_health_snapshot(
        snapshot,
        expected=expected,
        signature_ref="gs://runtime/baseline.sig",
        signature_hash="sha256:" + "4" * 64,
        evidence=Evidence(),
        kms=Kms(),
    )
    with pytest.raises(ReleaseVerificationError, match="authority differs"):
        verify_release_health_snapshot(
            snapshot,
            expected=expected.model_copy(update={"target_version": "8"}),
            signature_ref="gs://runtime/baseline.sig",
            signature_hash="sha256:" + "4" * 64,
            evidence=Evidence(),
            kms=Kms(),
        )
    failed = evaluate_release_health(
        rules=_rules(),
        baseline=_snapshot(errors=0.005, latency=400),
        postdeploy=_snapshot(errors=0.03, latency=650),
    )
    assert failed.result is ReleaseVerificationResult.FAILED
    assert "CLOUD_RUN_HTTP_5XX_RATIO_ABSOLUTE_LIMIT" in failed.rationale_codes
    assert (
        evaluate_release_health(
            rules=_rules(),
            baseline=_snapshot(errors=0.005, latency=400),
            postdeploy=_snapshot(errors=0.01, latency=550, points=1),
        ).result
        is ReleaseVerificationResult.INCONCLUSIVE
    )


def test_cloud_run_health_reader_constructs_only_registered_queries() -> None:
    session = Session([Response(_series(100)), Response(_series(2), "request-2")])
    reader = CloudRunHealthReader(
        session=session, project_id="customer-production", service_name="payments-api"
    )
    end = datetime(2026, 8, 17, 10, 5, tzinfo=UTC)
    result = reader.observe(
        "CLOUD_RUN_HTTP_5XX_RATIO",
        window_start=end - timedelta(minutes=5),
        window_end=end,
    )
    assert result.value == 0.02
    assert all(
        url == ("https://monitoring.googleapis.com/v3/projects/customer-production/timeSeries")
        for url, _ in session.requests
    )
    assert all(
        'service_name"="payments-api' in item[1]["params"]["filter"] for item in session.requests
    )


def test_cloud_run_health_reader_refuses_cross_project_series() -> None:
    reader = CloudRunHealthReader(
        session=Session([Response(_series(10, project="another-project"))]),
        project_id="customer-production",
        service_name="payments-api",
    )
    end = datetime(2026, 8, 17, 10, 5, tzinfo=UTC)
    try:
        reader.observe(
            "CLOUD_RUN_HTTP_P95_LATENCY_MS",
            window_start=end - timedelta(minutes=5),
            window_end=end,
        )
    except CloudRunHealthError as error:
        assert "another health target" in str(error)
    else:
        raise AssertionError("cross-project health series was accepted")
