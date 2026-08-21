from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from solvan.application import (
    AcceptedPlanRecord,
    CoordinatorAuthority,
    DispatchOutcomeStatus,
    InvestigationCoordinator,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
)
from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolConnectionBindingKind,
    ToolRevisionRefV1,
    accepted_step_budget_hash,
)
from solvan.domain import (
    AgentLimit,
    InvestigationPlanProposal,
    InvestigationStepKind,
    PlanValidationPolicy,
    ProposedStep,
    Scope,
    StepBudget,
)

SCOPE = Scope(
    organization_id="org_00000000000000000000000000",
    project_id="prj_00000000000000000000000000",
    environment_id="env_00000000000000000000000000",
)
AUTHORITY = CoordinatorAuthority(
    owner="coordinator",
    lease_token=UUID("00000000-0000-0000-0000-000000000001"),
    workflow_version=4,
)
BUDGET = StepBudget(60_000, 2, 8_000)


class FakeRepository:
    def __init__(self) -> None:
        self.in_transaction = False
        self.pending_plan = False
        self.plan_durable = False
        self.pending_attempt = False
        self.attempt_durable = False
        self.dispatch_recorded = False
        self.failure_recorded = False

    @contextmanager
    def transaction(self) -> Iterator[None]:
        assert not self.in_transaction
        self.in_transaction = True
        try:
            yield
        finally:
            self.in_transaction = False
            if self.pending_plan:
                self.plan_durable = True
                self.pending_plan = False
            if self.pending_attempt:
                self.attempt_durable = True
                self.pending_attempt = False

    def persist_accepted_plan(self, **_: Any) -> AcceptedPlanRecord:
        assert self.in_transaction
        self.pending_plan = True
        return AcceptedPlanRecord("ipl_test", 1, "sha256:plan", ("ist_test",))

    def reserve_ready_dispatches(self, **_: Any) -> tuple[RuntimeDispatch, ...]:
        assert self.in_transaction
        assert self.plan_durable
        self.pending_attempt = True
        return (
            RuntimeDispatch(
                run_id="run_test",
                invocation_id="inv_test",
                scope=SCOPE,
                incident_id="inc_test",
                plan_id="ipl_test",
                plan_version=1,
                step_id="ist_test",
                step_key="collect",
                logical_step_key="incident:inc_test:investigation:1:collect",
                agent_key="evidence-agent",
                agent_resource="projects/test/locations/europe-west1/reasoningEngines/evidence-v1",
                agent_revision="evidence-1",
                scope_ref="scope:payments",
                purpose="inspect service telemetry",
                allowed_tool_names=("cloud_monitoring_query",),
                workflow_version=4,
                deadline=datetime(2026, 8, 9, tzinfo=UTC),
                budget=BUDGET,
                input_ref="db://step",
                input_hash="sha256:input",
                trace_id="0" * 32,
                span_id="0" * 16,
            ),
        )

    def record_runtime_dispatch(self, **_: Any) -> None:
        assert self.in_transaction
        self.dispatch_recorded = True

    def attach_dispatch_context(
        self, *, dispatch: RuntimeDispatch, context: dict[str, Any], **_: Any
    ) -> RuntimeDispatch:
        assert self.in_transaction
        return replace(
            dispatch,
            context={**dispatch.context, **context},
            input_hash="sha256:enriched",
        )

    def record_runtime_dispatch_failure(self, **_: Any) -> bool:
        assert self.in_transaction
        self.failure_recorded = True
        return False


class FakeBinder:
    def __init__(self, repository: FakeRepository) -> None:
        self._repository = repository

    def bind(self, dispatch: RuntimeDispatch) -> EffectiveToolSetV1:
        assert self._repository.in_transaction
        assert dispatch.run_id == "run_test"
        tool = ToolRevisionRefV1(tool_key="cloud_monitoring_query", version="1")
        return EffectiveToolSetV1(
            profile_material_hash="sha256:" + "1" * 64,
            accepted_tools=(tool,),
            agent_key=dispatch.agent_key,
            agent_revision=dispatch.agent_revision,
            scope=dispatch.scope.canonical_dict(),
            connection_bindings=(
                EffectiveToolBindingV1(
                    binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY, tool=tool
                ),
            ),
            runtime_region="europe-west1",
            accepted_data_classification="INTERNAL",
            classification_ceiling="INTERNAL",
            policy_head_epoch=0,
            placement_epoch=1,
            accepted_step_budget_hash=accepted_step_budget_hash(dispatch.budget),
        )


class FakeRuntime:
    def __init__(self, repository: FakeRepository, *, fail: bool = False) -> None:
        self.repository = repository
        self.fail = fail

    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
        assert not self.repository.in_transaction
        assert self.repository.plan_durable
        assert self.repository.attempt_durable
        if self.fail:
            raise TimeoutError("classified without persisting this message")
        return RuntimeInvocationReceipt(
            runtime_operation_name=f"operations/{dispatch.invocation_id}",
            session_id="session-1",
        )


def proposal() -> InvestigationPlanProposal:
    return InvestigationPlanProposal(
        objective="collect bounded evidence",
        completion_condition="evidence agent has completed",
        uncertainties=(),
        steps=(
            ProposedStep(
                step_key="collect",
                kind=InvestigationStepKind.INVOKE_AGENT,
                agent_key="evidence-agent",
                scope_ref="scope:payments",
                purpose="inspect service telemetry",
                required=True,
                depends_on=(),
                budget=BUDGET,
            ),
        ),
    )


def policy() -> PlanValidationPolicy:
    return PlanValidationPolicy(
        agent_limits={
            "evidence-agent": AgentLimit(
                agent_resource="projects/test/locations/europe-west1/reasoningEngines/evidence-v1",
                agent_revision="evidence-1",
                maximum=BUDGET,
                allowed_scope_refs=frozenset({"scope:payments"}),
                allowed_tool_names=("cloud_monitoring_query",),
            )
        },
        allowed_scope_refs=frozenset({"scope:payments"}),
        maximum_steps=4,
    )


def test_plan_and_attempt_commit_before_runtime_invocation() -> None:
    repository = FakeRepository()
    coordinator = InvestigationCoordinator(
        repository, FakeRuntime(repository), FakeBinder(repository)
    )
    accepted = coordinator.accept_supervisor_plan(
        scope=SCOPE,
        incident_id="inc_test",
        supervisor_run_id="run_supervisor",
        authority=AUTHORITY,
        proposal=proposal(),
        policy=policy(),
    )
    outcomes = coordinator.dispatch_ready_steps(
        scope=SCOPE,
        incident_id="inc_test",
        authority=AUTHORITY,
    )

    assert accepted.plan_version == 1
    assert outcomes[0].status is DispatchOutcomeStatus.DISPATCHED
    assert repository.dispatch_recorded


def test_runtime_failure_is_classified_and_persisted_for_retry() -> None:
    repository = FakeRepository()
    coordinator = InvestigationCoordinator(
        repository, FakeRuntime(repository, fail=True), FakeBinder(repository)
    )
    coordinator.accept_supervisor_plan(
        scope=SCOPE,
        incident_id="inc_test",
        supervisor_run_id="run_supervisor",
        authority=AUTHORITY,
        proposal=proposal(),
        policy=policy(),
    )
    outcomes = coordinator.dispatch_ready_steps(
        scope=SCOPE,
        incident_id="inc_test",
        authority=AUTHORITY,
    )

    assert outcomes[0].status is DispatchOutcomeStatus.FAILED
    assert outcomes[0].error_class == "TimeoutError"
    assert repository.failure_recorded
