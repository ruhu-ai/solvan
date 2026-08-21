"""Coordinator-owned investigation plan acceptance and Runtime dispatch."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from solvan.application.effective_tool_set import EffectiveToolSetV1
from solvan.domain import (
    AcceptedInvestigationPlan,
    InvestigationPlanProposal,
    PlanValidationPolicy,
    Scope,
    StepBudget,
    validate_investigation_plan,
)


class InvestigationConflict(RuntimeError):
    """A stale lease, workflow version, plan, or run attempted a durable write."""


@dataclass(frozen=True, slots=True)
class CoordinatorAuthority:
    owner: str
    lease_token: UUID
    workflow_version: int


@dataclass(frozen=True, slots=True)
class AcceptedPlanRecord:
    plan_id: str
    plan_version: int
    content_hash: str
    step_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuntimeDispatch:
    run_id: str
    invocation_id: str
    scope: Scope
    incident_id: str | None
    plan_id: str
    plan_version: int
    step_id: str
    step_key: str
    logical_step_key: str
    agent_key: str
    agent_resource: str
    agent_revision: str
    scope_ref: str
    purpose: str
    allowed_tool_names: tuple[str, ...]
    workflow_version: int
    deadline: datetime
    budget: StepBudget
    input_ref: str
    input_hash: str
    trace_id: str
    span_id: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeInvocationReceipt:
    runtime_operation_name: str
    session_id: str | None = None
    runtime_input_ref: str | None = None
    runtime_output_ref: str | None = None


@dataclass(frozen=True, slots=True)
class PartialRuntimeInvocationReceipt:
    runtime_operation_name: str | None = None
    runtime_input_ref: str | None = None
    runtime_output_ref: str | None = None


@dataclass(frozen=True, slots=True)
class AgentRunMaterial:
    agent_resource: str
    agent_revision: str
    invocation_id: str
    incident_id: str
    workflow_version: int
    input_hash: str
    output_ref: str
    trace_id: str


class DispatchOutcomeStatus(StrEnum):
    DISPATCHED = "DISPATCHED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class DispatchOutcome:
    run_id: str
    status: DispatchOutcomeStatus
    runtime_operation_name: str | None = None
    error_class: str | None = None


class InvestigationRepository(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def persist_accepted_plan(
        self,
        *,
        scope: Scope,
        incident_id: str,
        supervisor_run_id: str,
        authority: CoordinatorAuthority,
        plan: AcceptedInvestigationPlan,
    ) -> AcceptedPlanRecord: ...

    def reserve_ready_dispatches(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        batch_size: int,
    ) -> tuple[RuntimeDispatch, ...]: ...

    def attach_dispatch_context(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        context: dict[str, Any],
    ) -> RuntimeDispatch: ...

    def record_runtime_dispatch(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        receipt: RuntimeInvocationReceipt,
    ) -> None: ...

    def record_runtime_dispatch_failure(
        self,
        *,
        scope: Scope,
        dispatch: RuntimeDispatch,
        error_class: str,
    ) -> bool: ...


class AgentRuntimePort(Protocol):
    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt: ...


class AgentRunBinder(Protocol):
    def bind(self, dispatch: RuntimeDispatch) -> EffectiveToolSetV1: ...


class DispatchContextEnricher(Protocol):
    def enrich(self, dispatch: RuntimeDispatch) -> dict[str, Any]: ...


class InvestigationCoordinator:
    """The only application service permitted to turn plans into agent calls."""

    def __init__(
        self,
        repository: InvestigationRepository,
        runtime: AgentRuntimePort,
        binder: AgentRunBinder,
        context_enricher: DispatchContextEnricher | None = None,
    ) -> None:
        self._repository = repository
        self._runtime = runtime
        self._binder = binder
        self._context_enricher = context_enricher

    def accept_supervisor_plan(
        self,
        *,
        scope: Scope,
        incident_id: str,
        supervisor_run_id: str,
        authority: CoordinatorAuthority,
        proposal: InvestigationPlanProposal,
        policy: PlanValidationPolicy,
    ) -> AcceptedPlanRecord:
        accepted = validate_investigation_plan(proposal, policy)
        with self._repository.transaction():
            return self._repository.persist_accepted_plan(
                scope=scope,
                incident_id=incident_id,
                supervisor_run_id=supervisor_run_id,
                authority=authority,
                plan=accepted,
            )

    def dispatch_ready_steps(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        batch_size: int = 4,
    ) -> tuple[DispatchOutcome, ...]:
        if batch_size < 1:
            raise ValueError("batch size must be positive")
        # This transaction exits before the first network call. The accepted plan,
        # step projection, and CREATED agent attempt are therefore durable first.
        with self._repository.transaction():
            dispatches = self._repository.reserve_ready_dispatches(
                scope=scope,
                incident_id=incident_id,
                authority=authority,
                batch_size=batch_size,
            )
        dispatches = tuple(self._prepare_dispatch(scope, item) for item in dispatches)
        outcomes: list[DispatchOutcome] = []
        pending = list(dispatches)
        while pending:
            dispatch = pending.pop(0)
            try:
                receipt = self._runtime.invoke(dispatch)
            except Exception as error:  # external Runtime boundary; persist classification
                error_class = type(error).__name__
                with self._repository.transaction():
                    retry_ready = self._repository.record_runtime_dispatch_failure(
                        scope=scope,
                        dispatch=dispatch,
                        error_class=error_class,
                    )
                outcomes.append(
                    DispatchOutcome(
                        dispatch.run_id, DispatchOutcomeStatus.FAILED, None, error_class
                    )
                )
                if retry_ready:
                    with self._repository.transaction():
                        retries = self._repository.reserve_ready_dispatches(
                            scope=scope,
                            incident_id=incident_id,
                            authority=authority,
                            batch_size=1,
                        )
                    pending.extend(self._prepare_dispatch(scope, retry) for retry in retries)
                continue
            with self._repository.transaction():
                self._repository.record_runtime_dispatch(
                    scope=scope,
                    dispatch=dispatch,
                    receipt=receipt,
                )
            outcomes.append(
                DispatchOutcome(
                    dispatch.run_id,
                    DispatchOutcomeStatus.DISPATCHED,
                    receipt.runtime_operation_name,
                )
            )
        return tuple(outcomes)

    def _prepare_dispatch(self, scope: Scope, dispatch: RuntimeDispatch) -> RuntimeDispatch:
        additions: dict[str, Any] = {}
        if self._context_enricher is not None:
            additions = self._context_enricher.enrich(dispatch)
        with self._repository.transaction():
            prepared = self._repository.attach_dispatch_context(
                scope=scope,
                dispatch=dispatch,
                context=additions,
            )
            effective_tool_set = self._binder.bind(prepared)
        return replace(
            prepared,
            context={
                **prepared.context,
                "effective_tool_set": effective_tool_set.canonical_dict(),
                "effective_tool_set_hash": effective_tool_set.effective_tool_set_hash,
            },
        )
