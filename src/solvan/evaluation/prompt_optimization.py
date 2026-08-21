"""Offline prompt-candidate preparation and hard-gate adjudication."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OptimizationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    experiment_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,127}$")
    agent_key: Literal["evidence-agent", "incident-supervisor"]
    base_instruction_revision: str
    base_instruction_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    optimizer: Literal["google.adk.optimization.simple_prompt_optimizer"]
    optimizer_model: str
    num_iterations: int = Field(ge=1, le=20)
    batch_size: int = Field(ge=1, le=20)
    trajectory_grader_revision: str
    train_case_ids: tuple[str, ...] = Field(min_length=1)
    validation_case_ids: tuple[str, ...] = Field(min_length=1)
    adversarial_holdout_case_ids: tuple[str, ...] = Field(min_length=1)
    minimum_validation_score: float = Field(ge=0, le=1)
    repeated_runs: int = Field(ge=2, le=20)
    production_credentials_allowed: Literal[False]
    automatic_promotion_allowed: Literal[False]

    @model_validator(mode="after")
    def disjoint_partitions(self) -> OptimizationConfig:
        groups = (
            set(self.train_case_ids),
            set(self.validation_case_ids),
            set(self.adversarial_holdout_case_ids),
        )
        if groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2]:
            raise ValueError("optimization dataset partitions must be disjoint")
        return self


@dataclass(frozen=True, slots=True)
class CandidateDecision:
    status: Literal["REJECTED", "HUMAN_REVIEW_REQUIRED"]
    rationale: tuple[str, ...]


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def prepare_manifest(
    *, config: OptimizationConfig, config_bytes: bytes, dataset_bytes: bytes
) -> dict[str, Any]:
    """Produce a content-free manifest; this function calls no model or provider."""

    from google.adk.optimization.simple_prompt_optimizer import (
        SimplePromptOptimizer,
        SimplePromptOptimizerConfig,
    )

    del SimplePromptOptimizer
    return {
        "schema_version": 1,
        "experiment_id": config.experiment_id,
        "agent_key": config.agent_key,
        "base_instruction_revision": config.base_instruction_revision,
        "base_instruction_hash": config.base_instruction_hash,
        "optimizer": config.optimizer,
        "optimizer_config_class": SimplePromptOptimizerConfig.__name__,
        "optimizer_model": config.optimizer_model,
        "config_hash": sha256_bytes(config_bytes),
        "dataset_hash": sha256_bytes(dataset_bytes),
        "trajectory_grader_revision": config.trajectory_grader_revision,
        "partition_hashes": {
            "train": _case_ids_hash(config.train_case_ids),
            "validation": _case_ids_hash(config.validation_case_ids),
            "adversarial_holdout": _case_ids_hash(config.adversarial_holdout_case_ids),
        },
        "gepa_dependency_ready": importlib.util.find_spec("pandas") is not None,
        "provider_model_called": False,
        "candidate_text_stored": False,
        "production_credentials_allowed": False,
        "automatic_promotion_allowed": False,
        "status": "PREPARED_NOT_EXECUTED",
    }


def adjudicate_candidate(
    *,
    config: OptimizationConfig,
    baseline: dict[str, bool],
    candidate: dict[str, bool],
) -> CandidateDecision:
    """Hard safety regressions always reject; passing still requires a human."""

    required = set(
        config.train_case_ids + config.validation_case_ids + config.adversarial_holdout_case_ids
    )
    if set(baseline) != required or set(candidate) != required:
        raise ValueError("candidate score maps must exactly cover configured partitions")
    rationale: list[str] = []
    if any(baseline[case_id] and not candidate[case_id] for case_id in required):
        rationale.append("HARD_GATE_REGRESSION")
    if any(not candidate[case_id] for case_id in config.adversarial_holdout_case_ids):
        rationale.append("ADVERSARIAL_HOLDOUT_FAILED")
    validation_score = sum(candidate[item] for item in config.validation_case_ids) / len(
        config.validation_case_ids
    )
    if validation_score < config.minimum_validation_score:
        rationale.append("VALIDATION_SCORE_BELOW_MINIMUM")
    if rationale:
        return CandidateDecision("REJECTED", tuple(rationale))
    return CandidateDecision("HUMAN_REVIEW_REQUIRED", ("NO_HARD_REGRESSION",))


def optimizer_configuration(config: OptimizationConfig) -> Any:
    """Build the pinned simple optimizer configuration for an isolated job."""

    from google.adk.optimization.simple_prompt_optimizer import (
        SimplePromptOptimizerConfig,
    )

    return SimplePromptOptimizerConfig(
        optimizer_model=config.optimizer_model,
        num_iterations=config.num_iterations,
        batch_size=config.batch_size,
    )


def _case_ids_hash(case_ids: tuple[str, ...]) -> str:
    return sha256_bytes(json.dumps(case_ids, separators=(",", ":")).encode())
