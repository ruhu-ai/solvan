"""Verified immutable evaluation receipts for governed guidance approval."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.domain import Scope


class VerifiedGuidanceEvaluation(BaseModel):
    """Receipt material produced by the registered evaluation service."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    receipt_ref: str = Field(min_length=1, max_length=2_000)
    receipt_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    object_generation: str = Field(pattern=r"^[0-9]+$")
    guidance_key: str = Field(min_length=1, max_length=160)
    guidance_version: str = Field(min_length=1, max_length=120)
    revision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    suite_version: str = Field(min_length=1, max_length=120)
    corpus_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    case_set_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scorer_name: str = Field(min_length=1, max_length=120)
    scorer_version: str = Field(min_length=1, max_length=120)
    model_config_pins: dict[str, str] = Field(min_length=1)
    repetitions: int = Field(ge=1, le=100)
    pass_thresholds: dict[str, float] = Field(min_length=1)
    passed_cases: int = Field(ge=0, le=10_000)
    failed_cases: int = Field(ge=0, le=10_000)
    decision: str = Field(pattern=r"^(PASS|FAIL)$")
    reason_codes: tuple[str, ...] = Field(min_length=1, max_length=40)

    @model_validator(mode="after")
    def validate_result(self) -> VerifiedGuidanceEvaluation:
        if self.passed_cases + self.failed_cases == 0:
            raise ValueError("evaluation receipt must contain at least one case")
        if (self.decision == "PASS") != (self.failed_cases == 0):
            raise ValueError("evaluation decision disagrees with case results")
        if any(not key or not value for key, value in self.model_config_pins.items()):
            raise ValueError("model/configuration pins must be non-empty strings")
        if any(not key or value < 0 or value > 1 for key, value in self.pass_thresholds.items()):
            raise ValueError("pass thresholds must be named values between zero and one")
        return self


class GuidanceEvaluationVerifier(Protocol):
    def verify(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        expected_digest: str,
        receipt_ref: str,
    ) -> VerifiedGuidanceEvaluation: ...


class UnavailableGuidanceEvaluationVerifier:
    def verify(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        expected_digest: str,
        receipt_ref: str,
    ) -> VerifiedGuidanceEvaluation:
        del scope, guidance_key, version, expected_digest, receipt_ref
        raise RuntimeError("registered evaluation receipt verifier is unavailable")


def verify_evaluation_binding(
    value: dict[str, Any],
    *,
    receipt_ref: str,
    receipt_hash: str,
    object_generation: str,
    guidance_key: str,
    version: str,
    expected_digest: str,
) -> VerifiedGuidanceEvaluation:
    receipt = VerifiedGuidanceEvaluation.model_validate(
        {
            **value,
            "receipt_ref": receipt_ref,
            "receipt_hash": receipt_hash,
            "object_generation": object_generation,
        }
    )
    if (
        receipt.guidance_key != guidance_key
        or receipt.guidance_version != version
        or receipt.revision_digest != expected_digest
    ):
        raise ValueError("evaluation receipt binding does not match the requested revision")
    return receipt
