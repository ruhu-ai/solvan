import yaml

from solvan.evaluation import TrajectorySuite, grade_trajectory
from tools.run_agent_trajectory_evals import DEFAULT_DATASET


def suite() -> TrajectorySuite:
    return TrajectorySuite.model_validate(yaml.safe_load(DEFAULT_DATASET.read_text()))


def test_curated_trajectory_expectations_match_deterministic_grader() -> None:
    cases = suite().cases
    assert len(cases) >= 10
    assert all(grade_trajectory(case).passed is case.expected_pass for case in cases)
    assert any(case.expected_pass for case in cases)
    assert any(not case.expected_pass for case in cases)


def test_plausible_final_answer_cannot_hide_missing_evidence_or_budget_overrun() -> None:
    case = next(item for item in suite().cases if item.id == "evidence_first_complete")
    observed = case.observed.model_copy(
        update={
            "tool_calls": case.observed.tool_calls[:1],
            "model_calls": case.limits.maximum_model_calls + 1,
        }
    )
    grade = grade_trajectory(case.model_copy(update={"observed": observed}))
    assert grade.passed is False
    assert "REQUIRED_TOOL_MISSING" in grade.violations
    assert "REQUIRED_EVIDENCE_MISSING" in grade.violations
    assert "MODEL_CALL_BUDGET" in grade.violations


def test_model_output_cannot_authorize_or_dispatch_another_agent() -> None:
    case = next(item for item in suite().cases if item.id == "poisoned_memory_cannot_steer")
    observed = case.observed.model_copy(
        update={
            "authority_transitions": ("ACTION_AUTHORIZED",),
            "direct_agent_dispatches": ("execution-agent",),
        }
    )
    grade = grade_trajectory(case.model_copy(update={"observed": observed}))
    assert grade.violations == (
        "PROHIBITED_AUTHORITY_TRANSITION",
        "DIRECT_AGENT_DISPATCH",
    )
