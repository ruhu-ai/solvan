from __future__ import annotations

import pytest
from pydantic import ValidationError

from solvan.application.release_authority import (
    CloudRunReleaseTargetInput,
    ReleaseSignerKeyInput,
)


def _target(**overrides: object) -> CloudRunReleaseTargetInput:
    value: dict[str, object] = {
        "target_key": "cloud-run:production:payments-api",
        "external_project_id": "customer-production",
        "location": "europe-west2",
        "service_name": "payments-api",
        "expected_target_epoch": 1,
        "runtime_service_account": ("payments-runtime@customer-production.iam.gserviceaccount.com"),
        "allowed_container_name": "payments-api",
        "canary_percentages": [10, 50, 100],
        "observation_windows_seconds": [120, 180, 300],
        "rollout_deadline_seconds": 3600,
        "verification_profile_id": "payments-health",
        "verification_profile_version": "1",
        "verifier_identity": (
            "serviceAccount:release-verifier@customer-production.iam.gserviceaccount.com"
        ),
        "verifier_key_version": (
            "projects/customer-production/locations/europe-west2/keyRings/releases/"
            "cryptoKeys/release-verifier/cryptoKeyVersions/1"
        ),
        "health_signals": [
            {
                "signal_kind": "CLOUD_RUN_HTTP_5XX_RATIO",
                "maximum_value": 0.02,
                "maximum_regression": 0.01,
                "minimum_points": 2,
            },
            {
                "signal_kind": "CLOUD_RUN_HTTP_P95_LATENCY_MS",
                "maximum_value": 1000,
                "maximum_regression": 200,
                "minimum_points": 2,
            },
        ],
    }
    value.update(overrides)
    return CloudRunReleaseTargetInput.model_validate(value)


def test_cloud_run_target_derives_one_exact_resource_and_profile() -> None:
    target = _target()
    assert target.service_resource_name == (
        "projects/customer-production/locations/europe-west2/services/payments-api"
    )
    assert target.documents["manifest"]["mutable_fields"] == [
        "image",
        "revision_suffix",
        "traffic",
    ]
    assert target.profile_hash == _target().profile_hash


@pytest.mark.parametrize(
    "overrides",
    [
        {"canary_percentages": [10, 50]},
        {"canary_percentages": [50, 10, 100]},
        {"observation_windows_seconds": [60]},
        {
            "health_signals": [
                {
                    "signal_kind": "CLOUD_RUN_HTTP_5XX_RATIO",
                    "maximum_value": 0.02,
                    "maximum_regression": 0.01,
                    "minimum_points": 2,
                },
                {
                    "signal_kind": "CLOUD_RUN_HTTP_5XX_RATIO",
                    "maximum_value": 0.03,
                    "maximum_regression": 0.02,
                    "minimum_points": 2,
                },
            ]
        },
    ],
)
def test_cloud_run_target_refuses_ambiguous_rollout_material(
    overrides: dict[str, object],
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        _target(**overrides)


def test_release_signer_policy_binds_public_key_bytes() -> None:
    signer = ReleaseSignerKeyInput(
        signer_identity="serviceAccount:builder@customer-production.iam.gserviceaccount.com",
        key_version=(
            "projects/customer-production/locations/europe-west2/keyRings/releases/"
            "cryptoKeys/release-signing/cryptoKeyVersions/1"
        ),
    )
    assert signer.policy_hash(public_key_pem=b"public-1") != signer.policy_hash(
        public_key_pem=b"public-2"
    )
