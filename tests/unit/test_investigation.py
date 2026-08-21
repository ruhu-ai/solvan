import pytest

from solvan.domain import (
    AgentLimit,
    InvestigationPlanError,
    InvestigationPlanProposal,
    InvestigationStepKind,
    PlanValidationPolicy,
    ProposedStep,
    StepBudget,
    validate_investigation_plan,
)

AGENT_BUDGET = StepBudget(120_000, 4, 32_000)
CHECK_BUDGET = StepBudget(30_000, 0, 4_000, max_model_calls=0)


def step(
    key: str,
    *,
    agent: str | None = "evidence-agent",
    kind: InvestigationStepKind = InvestigationStepKind.INVOKE_AGENT,
    depends_on: tuple[str, ...] = (),
    scope_ref: str = "scope:payments",
    budget: StepBudget = AGENT_BUDGET,
) -> ProposedStep:
    return ProposedStep(
        step_key=key,
        kind=kind,
        agent_key=agent,
        scope_ref=scope_ref,
        purpose=f"bounded purpose for {key}",
        required=True,
        depends_on=depends_on,
        budget=budget,
    )


def proposal(*steps: ProposedStep) -> InvestigationPlanProposal:
    return InvestigationPlanProposal(
        objective="identify the cause",
        completion_condition="required evidence available",
        uncertainties=("capacity may be a symptom",),
        steps=steps,
    )


def policy() -> PlanValidationPolicy:
    return PlanValidationPolicy(
        agent_limits={
            "evidence-agent": AgentLimit(
                agent_resource="projects/test/locations/europe-west1/reasoningEngines/evidence-v1",
                agent_revision="evidence-20260808-01",
                maximum=AGENT_BUDGET,
                allowed_scope_refs=frozenset({"scope:payments"}),
                allowed_tool_names=("cloud_monitoring_query",),
            ),
            "infrastructure-agent": AgentLimit(
                agent_resource="projects/test/locations/europe-west1/reasoningEngines/infra-v1",
                agent_revision="infra-20260808-01",
                maximum=AGENT_BUDGET,
                allowed_scope_refs=frozenset({"scope:deployment"}),
                allowed_tool_names=("cloud_run_read",),
            ),
        },
        allowed_scope_refs=frozenset({"scope:payments", "scope:deployment"}),
        maximum_steps=6,
    )


def test_plan_is_returned_in_stable_lexical_topological_order() -> None:
    accepted = validate_investigation_plan(
        proposal(
            step(
                "summarize",
                kind=InvestigationStepKind.COORDINATOR_CHECK,
                agent=None,
                budget=CHECK_BUDGET,
                depends_on=("telemetry", "runtime"),
            ),
            step("telemetry"),
            step("runtime", agent="infrastructure-agent", scope_ref="scope:deployment"),
        ),
        policy(),
    )
    assert [item.proposal.step_key for item in accepted.steps] == [
        "runtime",
        "telemetry",
        "summarize",
    ]
    assert [item.ordinal for item in accepted.steps] == [0, 1, 2]
    assert accepted.steps[0].agent_revision == "infra-20260808-01"
    assert accepted.steps[2].agent_revision is None


@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        (proposal(step("same"), step("same")), "duplicate step"),
        (proposal(step("unknown", agent="unknown-agent")), "unknown agent"),
        (proposal(step("wide", scope_ref="scope:all-production")), "scope widening"),
        (
            proposal(step("wrong-agent-scope", scope_ref="scope:deployment")),
            "agent scope widening",
        ),
        (
            proposal(step("expensive", budget=StepBudget(120_001, 4, 32_000))),
            "budget exceeds",
        ),
        (proposal(step("later", depends_on=("missing",))), "unknown dependencies"),
        (
            proposal(step("first", depends_on=("second",)), step("second", depends_on=("first",))),
            "dependency cycle",
        ),
        (
            proposal(
                step(
                    "check",
                    kind=InvestigationStepKind.COORDINATOR_CHECK,
                    agent="evidence-agent",
                    budget=CHECK_BUDGET,
                )
            ),
            "cannot invoke",
        ),
    ],
)
def test_invalid_or_authority_widening_plan_is_rejected(
    candidate: InvestigationPlanProposal, message: str
) -> None:
    with pytest.raises(InvestigationPlanError, match=message):
        validate_investigation_plan(candidate, policy())


def test_release_policy_can_require_minimum_agent_coverage() -> None:
    base = policy()
    required = PlanValidationPolicy(
        agent_limits=base.agent_limits,
        allowed_scope_refs=base.allowed_scope_refs,
        maximum_steps=base.maximum_steps,
        required_agent_keys=frozenset({"evidence-agent", "infrastructure-agent"}),
    )
    with pytest.raises(InvestigationPlanError, match="omits required agents"):
        validate_investigation_plan(proposal(step("telemetry")), required)
    accepted = validate_investigation_plan(
        proposal(
            step("telemetry"),
            step("runtime", agent="infrastructure-agent", scope_ref="scope:deployment"),
        ),
        required,
    )
    assert {item.proposal.agent_key for item in accepted.steps} == {
        "evidence-agent",
        "infrastructure-agent",
    }
