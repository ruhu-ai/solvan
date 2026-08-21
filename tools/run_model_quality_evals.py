"""Run and score the pinned statistical Gemini quality evaluation suite."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.platform.model_routes import qualified_model_endpoint

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evals/cases/model-quality.yaml"
THRESHOLDS = {
    "observation_precision": 0.90,
    "observation_recall": 0.85,
    "classification_accuracy": 0.95,
    "hypothesis_top_1": 0.80,
    "hypothesis_top_3": 0.95,
    "schema_first_pass": 0.95,
    "schema_after_repair": 1.00,
    "uncertainty_required_recall": 1.00,
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class QualityCase(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,127}$")
    evidence: dict[str, str] = Field(min_length=1)
    candidate_hypotheses: tuple[str, ...] = Field(min_length=3)
    expected_observation_keys: tuple[str, ...]
    expected_inference_keys: tuple[str, ...]
    expected_top_hypothesis: str
    expected_top_three: tuple[str, ...] = Field(min_length=3, max_length=3)
    expected_plan_valid: bool
    require_uncertainty: bool

    @model_validator(mode="after")
    def validate_case(self) -> QualityCase:
        evidence = set(self.evidence)
        labeled = set(self.expected_observation_keys) | set(self.expected_inference_keys)
        candidates = set(self.candidate_hypotheses)
        if not labeled <= evidence or set(self.expected_observation_keys) & set(
            self.expected_inference_keys
        ):
            raise ValueError("evaluation labels must be disjoint evidence keys")
        if (
            self.expected_top_hypothesis not in candidates
            or not set(self.expected_top_three) <= candidates
            or len(set(self.expected_top_three)) != 3
        ):
            raise ValueError("expected hypothesis ranking must use unique candidates")
        return self


class QualitySuite(StrictModel):
    schema_version: Literal[1]
    suite: Literal["solvan-model-quality-v1"]
    cases: tuple[QualityCase, ...] = Field(min_length=5)


class ClassifiedEvidence(StrictModel):
    evidence_key: str
    kind: Literal["OBSERVATION", "INFERENCE"]


class ModelQualityVerdict(StrictModel):
    classified_evidence: tuple[ClassifiedEvidence, ...]
    ranked_hypothesis_keys: tuple[str, ...] = Field(min_length=1)
    plan_valid: bool
    uncertainty_disclosed: bool

    @model_validator(mode="after")
    def validate_unique_keys(self) -> ModelQualityVerdict:
        keys = [item.evidence_key for item in self.classified_evidence]
        if len(keys) != len(set(keys)) or len(self.ranked_hypothesis_keys) != len(
            set(self.ranked_hypothesis_keys)
        ):
            raise ValueError("evaluation output keys and ranking must be unique")
        return self


class Attempt(StrictModel):
    case_id: str
    repetition: int = Field(ge=1)
    first_pass_schema_valid: bool
    after_repair_schema_valid: bool
    verdict: ModelQualityVerdict | None
    duration_ms: float = Field(ge=0)
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    error_type: str | None = None


def load_suite(path: Path = DATASET) -> QualitySuite:
    return QualitySuite.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def score(suite: QualitySuite, attempts: tuple[Attempt, ...]) -> dict[str, Any]:
    by_id = {case.id: case for case in suite.cases}
    expected_pairs = {(case.id, repetition) for case in suite.cases for repetition in range(1, 4)}
    actual_pairs = {(attempt.case_id, attempt.repetition) for attempt in attempts}
    if actual_pairs != expected_pairs or len(attempts) != len(expected_pairs):
        raise ValueError("quality scoring requires exactly three repetitions of every case")
    observation_true = observation_predicted = observation_correct = 0
    classification_total = classification_correct = 0
    top_one = top_three = plan_correct = uncertainty_required = uncertainty_found = 0
    first_valid = repaired_valid = 0
    for attempt in attempts:
        case = by_id[attempt.case_id]
        first_valid += int(attempt.first_pass_schema_valid)
        repaired_valid += int(attempt.after_repair_schema_valid)
        verdict = attempt.verdict
        expected_observations = set(case.expected_observation_keys)
        observation_true += len(expected_observations)
        expected_labels = {
            **{key: "OBSERVATION" for key in case.expected_observation_keys},
            **{key: "INFERENCE" for key in case.expected_inference_keys},
        }
        if verdict is None:
            classification_total += len(expected_labels)
            uncertainty_required += int(case.require_uncertainty)
            continue
        predicted_labels = {item.evidence_key: item.kind for item in verdict.classified_evidence}
        predicted_observations = {
            key for key, kind in predicted_labels.items() if kind == "OBSERVATION"
        }
        observation_predicted += len(predicted_observations)
        observation_correct += len(predicted_observations & expected_observations)
        label_keys = set(expected_labels) | set(predicted_labels)
        classification_total += len(label_keys)
        classification_correct += sum(
            expected_labels.get(key) == predicted_labels.get(key) for key in label_keys
        )
        top_one += int(verdict.ranked_hypothesis_keys[0] == case.expected_top_hypothesis)
        top_three += int(case.expected_top_hypothesis in verdict.ranked_hypothesis_keys[:3])
        plan_correct += int(verdict.plan_valid == case.expected_plan_valid)
        if case.require_uncertainty:
            uncertainty_required += 1
            uncertainty_found += int(verdict.uncertainty_disclosed)
    count = len(attempts)
    metrics = {
        "observation_precision": observation_correct / max(observation_predicted, 1),
        "observation_recall": observation_correct / observation_true,
        "classification_accuracy": classification_correct / classification_total,
        "hypothesis_top_1": top_one / count,
        "hypothesis_top_3": top_three / count,
        "typed_plan_accuracy": plan_correct / count,
        "schema_first_pass": first_valid / count,
        "schema_after_repair": repaired_valid / count,
        "uncertainty_required_recall": uncertainty_found / max(uncertainty_required, 1),
    }
    gates = {name: metrics[name] >= threshold for name, threshold in THRESHOLDS.items()}
    return {
        "metrics": metrics,
        "thresholds": THRESHOLDS,
        "gates": gates,
        "passed": all(gates.values()),
    }


def _input(case: QualityCase) -> tuple[str, str]:
    material = {
        "evidence": case.evidence,
        "candidate_hypotheses": case.candidate_hypotheses,
    }
    content = json.dumps(material, sort_keys=True, separators=(",", ":"))
    prompt = (
        "Classify every keyed evidence statement as OBSERVATION or INFERENCE. Rank only "
        "the supplied hypothesis keys. Set plan_valid false when evidence is insufficient "
        "for a bounded investigation plan and disclose uncertainty when material evidence "
        f"is missing. Return the typed response only.\n{content}"
    )
    return prompt, hashlib.sha256(content.encode()).hexdigest()


def live_attempts(suite: QualitySuite, *, repetitions: int = 3) -> tuple[Attempt, ...]:
    if repetitions != 3:
        raise ValueError("the canonical quality evaluation requires exactly three repetitions")
    genai = importlib.import_module("google.genai")
    types = importlib.import_module("google.genai.types")
    project = os.environ["SOLVAN_GEMINI_EVAL_PROJECT"]
    location = os.environ["SOLVAN_GEMINI_EVAL_LOCATION"]
    model = os.environ["SOLVAN_GEMINI_EVAL_MODEL"]
    qualified_model_endpoint(model=model, location=location)
    attempts: list[Attempt] = []
    with genai.Client(enterprise=True, project=project, location=location) as client:
        for case in suite.cases:
            prompt, input_hash = _input(case)
            for repetition in range(1, repetitions + 1):
                started = time.monotonic()
                first_valid = False
                verdict: ModelQualityVerdict | None = None
                error_type: str | None = None
                for pass_no in (1, 2):
                    try:
                        response = client.models.generate_content(
                            model=model,
                            contents=prompt
                            if pass_no == 1
                            else (
                                "Your prior response was invalid. Re-emit the exact schema.\n"
                                f"{prompt}"
                            ),
                            config=types.GenerateContentConfig(
                                # Gemini 3 thinking tokens share this budget. A 512-token
                                # ceiling truncated otherwise valid JSON before the first
                                # typed field completed, making the evaluator score the
                                # harness rather than the model. Gemini 3.6 Flash also
                                # ignores custom temperature values, so do not claim a
                                # determinism control that the selected release model does
                                # not support.
                                max_output_tokens=4_096,
                                response_mime_type="application/json",
                                response_schema=ModelQualityVerdict,
                            ),
                        )
                        verdict = ModelQualityVerdict.model_validate(response.parsed)
                        first_valid = pass_no == 1
                        error_type = None
                        break
                    except Exception as error:  # bounded provider/schema failure is scored
                        error_type = type(error).__name__
                attempts.append(
                    Attempt(
                        case_id=case.id,
                        repetition=repetition,
                        first_pass_schema_valid=first_valid,
                        after_repair_schema_valid=verdict is not None,
                        verdict=verdict,
                        duration_ms=round((time.monotonic() - started) * 1000, 3),
                        input_sha256=input_hash,
                        error_type=error_type,
                    )
                )
    return tuple(attempts)


def write_receipt(output: Path, *, suite: QualitySuite, attempts: tuple[Attempt, ...]) -> bool:
    result = score(suite, attempts)
    model = os.environ["SOLVAN_GEMINI_EVAL_MODEL"]
    location = os.environ["SOLVAN_GEMINI_EVAL_LOCATION"]
    value = {
        "schema_version": 1,
        "suite": suite.suite,
        "mode": "live-gemini-enterprise",
        "created_at_unix": time.time(),
        "project": os.environ["SOLVAN_GEMINI_EVAL_PROJECT"],
        "location": location,
        "model": model,
        "endpoint": qualified_model_endpoint(model=model, location=location),
        **result,
        "attempts": [attempt.model_dump(mode="json") for attempt in attempts],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(content)
    temporary.replace(output)
    return bool(result["passed"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    args = parser.parse_args()
    try:
        suite = load_suite(args.dataset)
        attempts = live_attempts(suite)
        passed = write_receipt(args.output, suite=suite, attempts=attempts)
        print(f"Gemini quality evaluation {'passed' if passed else 'failed'}: {args.output}")
        return 0 if passed else 1
    except (ImportError, KeyError, OSError, TypeError, ValueError) as error:
        print(f"Gemini quality evaluation error: {type(error).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
