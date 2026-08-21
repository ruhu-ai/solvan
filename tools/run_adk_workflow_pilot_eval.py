"""Evaluate the disabled ADK graph pilot against applicable R-06 hard gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import yaml

from solvan.agents.workflows._pilot import PilotInput, build_read_only_research_workflow
from solvan.evaluation import TrajectorySuite, grade_trajectory

ROOT = Path(__file__).resolve().parents[1]
APPLICABLE_FAMILIES = frozenset(
    {"deterministic router", "parallel fan-out and join", "no-progress bounded recursion"}
)


def run(*, dataset: Path, output: Path) -> bool:
    dataset_bytes = dataset.read_bytes()
    suite = TrajectorySuite.model_validate(yaml.safe_load(dataset_bytes))
    value = PilotInput(
        request_id="pilot-evaluation",
        generation=1,
        expected_generation=1,
        available_sources=frozenset({"telemetry", "change_history", "production_graph"}),
        evidence_refs=("ev_pilot_fixture",),
        allowed_read_tools=frozenset(
            {"cloud_logging_query", "cloud_monitoring_query", "production_graph_read"}
        ),
    )
    prior = os.environ.get("SOLVAN_ADK_WORKFLOW_PILOT_ENABLED")
    os.environ["SOLVAN_ADK_WORKFLOW_PILOT_ENABLED"] = "true"
    try:
        workflow = build_read_only_research_workflow(value)
    finally:
        if prior is None:
            os.environ.pop("SOLVAN_ADK_WORKFLOW_PILOT_ENABLED", None)
        else:
            os.environ["SOLVAN_ADK_WORKFLOW_PILOT_ENABLED"] = prior
    if workflow.graph is None:
        raise RuntimeError("ADK pilot did not compile a graph")
    cases = [case for case in suite.cases if case.family in APPLICABLE_FAMILIES]
    grades = [grade_trajectory(case) for case in cases]
    matched = sum(
        grade.passed is case.expected_pass for case, grade in zip(cases, grades, strict=True)
    )
    receipt = {
        "schema_version": 1,
        "mode": "disabled-read-only-adk-workflow-pilot-structural",
        "dataset_hash": "sha256:" + hashlib.sha256(dataset_bytes).hexdigest(),
        "grader_revision": suite.grader_revision,
        "input_hash": value.input_hash,
        "workflow_name": workflow.name,
        "node_names": [node.name for node in workflow.graph.nodes],
        "edge_count": len(workflow.graph.edges),
        "maximum_concurrency": workflow.max_concurrency,
        "provider_model_called": False,
        "production_enabled": False,
        "matched": matched,
        "total": len(cases),
        "passed": matched == len(cases),
        "case_results": [
            {
                "case_id": case.id,
                "expected_pass": case.expected_pass,
                "actual_pass": grade.passed,
                "violations": grade.violations,
            }
            for case, grade in zip(cases, grades, strict=True)
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"ADK workflow pilot structural gate: {matched}/{len(cases)} matched; {output}")
    return bool(receipt["passed"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "evals/cases/agent-trajectories.yaml",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(dataset=args.dataset, output=args.output) else 1)


if __name__ == "__main__":
    main()
