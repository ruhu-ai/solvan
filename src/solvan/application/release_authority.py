"""Closed administrator contracts for signed releases and Cloud Run targets."""

from __future__ import annotations

from enum import StrEnum
from math import isfinite
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes

_KMS_VERSION = (
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/keyRings/"
    r"[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[1-9][0-9]*$"
)
_SERVICE_ACCOUNT = (
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,61}[a-z0-9]"
    r"[.]iam[.]gserviceaccount[.]com$"
)


class ReleaseAuthorityError(ValueError):
    pass


class ReleaseSignerKeyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signer_identity: str = Field(pattern=r"^serviceAccount:.+@.+[.]iam[.]gserviceaccount[.]com$")
    key_version: str = Field(pattern=_KMS_VERSION)

    def policy_hash(self, *, public_key_pem: bytes) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "signer_identity": self.signer_identity,
                "key_version": self.key_version,
                "public_key_hash": sha256_bytes(public_key_pem),
                "algorithm": "EC_SIGN_P256_SHA256",
            }
        )


class ReleaseVerifierKeyInput(ReleaseSignerKeyInput):
    def policy_hash(self, *, public_key_pem: bytes) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "authority_kind": "RELEASE_EFFECT_VERIFIER",
                "verifier_identity": self.signer_identity,
                "key_version": self.key_version,
                "public_key_hash": sha256_bytes(public_key_pem),
                "algorithm": "EC_SIGN_P256_SHA256",
            }
        )


class ReleaseHealthSignalKind(StrEnum):
    HTTP_5XX_RATIO = "CLOUD_RUN_HTTP_5XX_RATIO"
    HTTP_P95_LATENCY_MS = "CLOUD_RUN_HTTP_P95_LATENCY_MS"


class ReleaseHealthSignalInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_kind: ReleaseHealthSignalKind
    maximum_value: float = Field(ge=0)
    maximum_regression: float = Field(ge=0)
    minimum_points: int = Field(ge=1, le=10_000)

    @model_validator(mode="after")
    def validate_numbers(self) -> Self:
        if not isfinite(self.maximum_value) or not isfinite(self.maximum_regression):
            raise ReleaseAuthorityError("release health thresholds must be finite")
        return self


class ReleaseVerificationProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    profile_id: str = Field(min_length=3, max_length=128)
    profile_version: str = Field(min_length=1, max_length=64)
    provider_kind: str = Field(pattern=r"^GCP_CLOUD_MONITORING_V3$")
    external_project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
    cloud_run_service_name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
    verifier_identity: str = Field(pattern=r"^serviceAccount:.+@.+[.]iam[.]gserviceaccount[.]com$")
    verifier_key_version: str = Field(pattern=_KMS_VERSION)
    health_signals: tuple[ReleaseHealthSignalInput, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_signals(self) -> Self:
        if len({item.signal_kind for item in self.health_signals}) != len(self.health_signals):
            raise ReleaseAuthorityError("release health signals must be unique")
        return self


class CloudRunReleaseTargetInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_key: str = Field(min_length=8, max_length=255)
    external_project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
    location: str = Field(pattern=r"^[a-z]+-[a-z]+[0-9]$")
    service_name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
    expected_target_epoch: int = Field(gt=0)
    runtime_service_account: str = Field(pattern=_SERVICE_ACCOUNT)
    allowed_container_name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
    canary_percentages: tuple[int, ...] = Field(min_length=2, max_length=10)
    observation_windows_seconds: tuple[int, ...] = Field(min_length=2, max_length=10)
    rollout_deadline_seconds: int = Field(ge=60, le=86400)
    verification_profile_id: str = Field(min_length=3, max_length=128)
    verification_profile_version: str = Field(min_length=1, max_length=64)
    verifier_identity: str = Field(pattern=r"^serviceAccount:.+@.+[.]iam[.]gserviceaccount[.]com$")
    verifier_key_version: str = Field(pattern=_KMS_VERSION)
    health_signals: tuple[ReleaseHealthSignalInput, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_rollout(self) -> Self:
        if (
            len(self.canary_percentages) != len(self.observation_windows_seconds)
            or self.canary_percentages[0] >= 100
            or self.canary_percentages[-1] != 100
            or any(not 1 <= item <= 100 for item in self.canary_percentages)
            or tuple(sorted(set(self.canary_percentages))) != self.canary_percentages
            or any(not 60 <= item <= 86400 for item in self.observation_windows_seconds)
            or any(
                window < max(signal.minimum_points for signal in self.health_signals) * 60
                for window in self.observation_windows_seconds
            )
        ):
            raise ReleaseAuthorityError("release target rollout sequence is invalid")
        if len({item.signal_kind for item in self.health_signals}) != len(self.health_signals):
            raise ReleaseAuthorityError("release health signals must be unique")
        return self

    @property
    def service_resource_name(self) -> str:
        return (
            f"projects/{self.external_project_id}/locations/{self.location}/"
            f"services/{self.service_name}"
        )

    @property
    def documents(self) -> dict[str, dict[str, object]]:
        return {
            "manifest": {
                "schema_version": 1,
                "provider_kind": "GCP_CLOUD_RUN_V2",
                "service_resource_name": self.service_resource_name,
                "runtime_service_account": self.runtime_service_account,
                "allowed_container_name": self.allowed_container_name,
                "mutable_fields": ["image", "revision_suffix", "traffic"],
            },
            "rollout": {
                "schema_version": 1,
                "canary_percentages": list(self.canary_percentages),
                "observation_windows_seconds": list(self.observation_windows_seconds),
                "rollout_deadline_seconds": self.rollout_deadline_seconds,
                "maximum_concurrent_rollouts": 1,
            },
            "verification": {
                **ReleaseVerificationProfile(
                    profile_id=self.verification_profile_id,
                    profile_version=self.verification_profile_version,
                    provider_kind="GCP_CLOUD_MONITORING_V3",
                    external_project_id=self.external_project_id,
                    cloud_run_service_name=self.service_name,
                    verifier_identity=self.verifier_identity,
                    verifier_key_version=self.verifier_key_version,
                    health_signals=tuple(
                        sorted(self.health_signals, key=lambda value: value.signal_kind)
                    ),
                ).model_dump(mode="json")
            },
        }

    @property
    def profile_hash(self) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "target_key": self.target_key,
                "expected_target_epoch": self.expected_target_epoch,
                "documents": self.documents,
            }
        )
