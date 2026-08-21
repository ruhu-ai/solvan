from __future__ import annotations

from pathlib import Path

import yaml

from solvan.evaluation.prompt_optimization import (
    OptimizationConfig,
    adjudicate_candidate,
    optimizer_configuration,
    prepare_manifest,
)

ROOT = Path(__file__).resolve().parents[2]


def configuration() -> tuple[OptimizationConfig, bytes, bytes]:
    config_bytes = (ROOT / "evals/optimization/evidence-agent-v1.yaml").read_bytes()
    dataset_bytes = (ROOT / "evals/cases/agent-trajectories.yaml").read_bytes()
    config = OptimizationConfig.model_validate(yaml.safe_load(config_bytes))
    return config, config_bytes, dataset_bytes


def test_optimizer_manifest_is_non_executing_and_pinned() -> None:
    config, config_bytes, dataset_bytes = configuration()
    manifest = prepare_manifest(
        config=config, config_bytes=config_bytes, dataset_bytes=dataset_bytes
    )
    assert manifest["optimizer_config_class"] == "SimplePromptOptimizerConfig"
    assert manifest["provider_model_called"] is False
    assert manifest["automatic_promotion_allowed"] is False
    assert manifest["status"] == "PREPARED_NOT_EXECUTED"
    sdk_config = optimizer_configuration(config)
    assert sdk_config.num_iterations == 5
    assert sdk_config.batch_size == 2


def test_optimizer_candidate_rejects_one_safety_regression() -> None:
    config, _, _ = configuration()
    case_ids = (
        config.train_case_ids + config.validation_case_ids + config.adversarial_holdout_case_ids
    )
    baseline = dict.fromkeys(case_ids, True)
    candidate = dict(baseline)
    candidate[config.adversarial_holdout_case_ids[0]] = False
    decision = adjudicate_candidate(config=config, baseline=baseline, candidate=candidate)
    assert decision.status == "REJECTED"
    assert "HARD_GATE_REGRESSION" in decision.rationale


def test_optimizer_candidate_can_only_advance_to_human_review() -> None:
    config, _, _ = configuration()
    case_ids = (
        config.train_case_ids + config.validation_case_ids + config.adversarial_holdout_case_ids
    )
    scores = dict.fromkeys(case_ids, True)
    decision = adjudicate_candidate(config=config, baseline=scores, candidate=scores)
    assert decision.status == "HUMAN_REVIEW_REQUIRED"
