"""Prepare a digest-addressed, non-executing ADK optimizer experiment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from solvan.evaluation.prompt_optimization import OptimizationConfig, prepare_manifest
from solvan.evaluation.trajectory import TrajectorySuite

ROOT = Path(__file__).resolve().parents[1]


def prepare(*, config_path: Path, dataset_path: Path, output_path: Path) -> None:
    config_bytes = config_path.read_bytes()
    dataset_bytes = dataset_path.read_bytes()
    config = OptimizationConfig.model_validate(yaml.safe_load(config_bytes))
    suite = TrajectorySuite.model_validate(yaml.safe_load(dataset_bytes))
    configured = set(
        config.train_case_ids + config.validation_case_ids + config.adversarial_holdout_case_ids
    )
    available = {case.id for case in suite.cases}
    if configured != available:
        raise ValueError("optimizer partitions must exactly cover the trajectory suite")
    if config.trajectory_grader_revision != suite.grader_revision:
        raise ValueError("optimizer grader revision is not pinned to the dataset")
    manifest = prepare_manifest(
        config=config,
        config_bytes=config_bytes,
        dataset_bytes=dataset_bytes,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Prepared offline optimizer manifest at {output_path}; no model was called")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "evals/optimization/evidence-agent-v1.yaml",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "evals/cases/agent-trajectories.yaml",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(config_path=args.config, dataset_path=args.dataset, output_path=args.output)


if __name__ == "__main__":
    main()
