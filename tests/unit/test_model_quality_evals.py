from __future__ import annotations

from tools.run_model_quality_evals import (
    Attempt,
    ClassifiedEvidence,
    ModelQualityVerdict,
    load_suite,
    score,
)


def _perfect_attempts() -> tuple[Attempt, ...]:
    attempts = []
    for case in load_suite().cases:
        verdict = ModelQualityVerdict(
            classified_evidence=tuple(
                ClassifiedEvidence(evidence_key=key, kind="OBSERVATION")
                for key in case.expected_observation_keys
            )
            + tuple(
                ClassifiedEvidence(evidence_key=key, kind="INFERENCE")
                for key in case.expected_inference_keys
            ),
            ranked_hypothesis_keys=case.expected_top_three,
            plan_valid=case.expected_plan_valid,
            uncertainty_disclosed=case.require_uncertainty,
        )
        attempts.extend(
            Attempt(
                case_id=case.id,
                repetition=repetition,
                first_pass_schema_valid=True,
                after_repair_schema_valid=True,
                verdict=verdict,
                duration_ms=1,
                input_sha256="0" * 64,
            )
            for repetition in range(1, 4)
        )
    return tuple(attempts)


def test_pinned_quality_dataset_meets_all_thresholds_for_exact_oracle() -> None:
    result = score(load_suite(), _perfect_attempts())
    assert result["passed"] is True
    assert all(result["gates"].values())
    assert all(value == 1 for value in result["metrics"].values())


def test_scorer_fails_closed_for_missing_schema_and_uncertainty() -> None:
    attempts = list(_perfect_attempts())
    cases = {case.id: case for case in load_suite().cases}
    target = next(
        index
        for index, attempt in enumerate(attempts)
        if cases[attempt.case_id].require_uncertainty
    )
    attempts[target] = attempts[target].model_copy(
        update={
            "first_pass_schema_valid": False,
            "after_repair_schema_valid": False,
            "verdict": None,
            "error_type": "ValidationError",
        }
    )
    result = score(load_suite(), tuple(attempts))
    assert result["passed"] is False
    assert result["gates"]["schema_after_repair"] is False
    assert result["gates"]["uncertainty_required_recall"] is False


def test_scorer_requires_exact_three_repetition_matrix() -> None:
    try:
        score(load_suite(), _perfect_attempts()[:-1])
    except ValueError as error:
        assert "three repetitions" in str(error)
    else:  # pragma: no cover
        raise AssertionError("incomplete evaluation matrix was accepted")
