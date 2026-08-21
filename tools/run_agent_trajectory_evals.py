"""Run the deterministic agent-trajectory structural gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import yaml

from solvan.evaluation import TrajectorySuite, grade_trajectory

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "evals/cases/agent-trajectories.yaml"


def run(*, dataset: Path, output: Path) -> bool:
    raw = dataset.read_bytes()
    suite = TrajectorySuite.model_validate(yaml.safe_load(raw))
    results = []
    matched = 0
    for case in suite.cases:
        grade = grade_trajectory(case)
        expectation_matched = grade.passed is case.expected_pass
        matched += int(expectation_matched)
        results.append(
            {
                "case_id": case.id,
                "family": case.family,
                "expected_pass": case.expected_pass,
                "actual_pass": grade.passed,
                "expectation_matched": expectation_matched,
                "violations": grade.violations,
                "tool_call_count": grade.tool_call_count,
                "committed_evidence_count": grade.committed_evidence_count,
                "input_records_hash": "sha256:"
                + hashlib.sha256(
                    json.dumps(case.input_records, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "raw_inputs_stored": False,
            }
        )
    receipt = {
        "schema_version": 1,
        "suite": suite.suite,
        "mode": "deterministic-structural-trajectory",
        "created_at_unix": time.time(),
        "dataset_hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "grader_revision": suite.grader_revision,
        "agent_revision": suite.agent_revision,
        "tool_catalog_hash": suite.tool_catalog_hash,
        "provider_model_called": False,
        "matched": matched,
        "total": len(suite.cases),
        "passed": matched == len(suite.cases),
        "results": results,
    }
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    receipt["receipt_hash"] = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Agent trajectory gate: {matched}/{len(suite.cases)} matched; receipt={output}")
    return bool(receipt["passed"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(dataset=args.dataset, output=args.output) else 1)


if __name__ == "__main__":
    main()
