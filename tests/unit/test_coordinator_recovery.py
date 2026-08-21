"""Containment and completeness rules that keep one coordinator tick alive."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from apps.coordinator import alert_triage as alert_triage_module
from apps.coordinator import main as coordinator_main
from apps.coordinator.alert_triage import poll_alert_triage_run, run_alert_triage_tick
from apps.coordinator.event_handlers import InboxLeaseContention
from solvan.application import ClaimedWakeup
from solvan.application.ports import ClaimedEvent
from solvan.domain import Scope
from solvan.persistence.case_wakeups import WAKEUP_CLAIM_ATTEMPT_BUDGET
from solvan.persistence.claim_sql import INBOX_CLAIM_ATTEMPT_BUDGET
from solvan.persistence.runtime_run_store import (
    CREATED_RECOVERY_AGENT_KEYS,
    _created_recovery_agent_keys,
)
from solvan.persistence.runtime_types import PendingRuntimeRun
from solvan.platform.agent_runtime import QueryJobCheck

SCOPE = Scope(
    organization_id="org_00000000000000000000000000",
    project_id="prj_00000000000000000000000000",
    environment_id="env_00000000000000000000000000",
)


# --- 1. the CREATED-run reaper covers every registered agent kind ------------


def test_created_run_recovery_covers_every_model_backed_investigation_agent() -> None:
    from solvan.application.default_tool_catalog import AGENT_PROFILE_KEYS

    # Infrastructure Agent runs are reserved exactly like Evidence Agent runs.
    # Omitting one kind strands its step with current_agent_run_id set forever.
    assert "infrastructure-agent" in CREATED_RECOVERY_AGENT_KEYS
    assert "evidence-agent" in CREATED_RECOVERY_AGENT_KEYS
    assert "incident-supervisor" in CREATED_RECOVERY_AGENT_KEYS
    # Only kinds with their own provider-fenced recovery may be left out, and
    # the exclusion has to be a deliberate, registered decision.
    assert set(CREATED_RECOVERY_AGENT_KEYS) == set(AGENT_PROFILE_KEYS) - {"workspace-agent"}


def test_created_run_recovery_refuses_an_exclusion_that_names_no_registered_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import solvan.persistence.runtime_run_store as store_module

    monkeypatch.setattr(
        store_module,
        "_PROVIDER_OWNED_CREATED_RECOVERY",
        frozenset({"retired-agent"}),
    )
    with pytest.raises(RuntimeError, match="unregistered agent keys"):
        _created_recovery_agent_keys()


# --- 4. one poisoned inbox claim cannot abort the remaining claims -----------


@dataclass
class _RecordedRelease:
    event_id: str
    refund_attempt: bool


class _FakeWorkflow:
    def __init__(self) -> None:
        self.released: list[_RecordedRelease] = []

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def release_inbox(
        self, *, scope: Scope, owner: str, claim: ClaimedEvent, refund_attempt: bool
    ) -> None:
        assert scope == SCOPE
        assert owner == "coordinator-1"
        self.released.append(_RecordedRelease(str(claim.event_id), refund_attempt))


class _FakeConnection:
    def __init__(self) -> None:
        self.rollbacks = 0

    def rollback(self) -> None:
        self.rollbacks += 1


def _claim(event_id: str) -> ClaimedEvent:
    return ClaimedEvent(
        event_id=event_id,
        event_type="IncidentDetected",
        claim_token=UUID(int=7),
        claim_expires_at=datetime.now(UTC) + timedelta(minutes=2),
    )


def _run_claim(
    monkeypatch: pytest.MonkeyPatch, error: Exception | None
) -> tuple[bool, _FakeWorkflow, _FakeConnection]:
    workflow = _FakeWorkflow()
    connection = _FakeConnection()

    def apply(**_: Any) -> None:
        if error is not None:
            raise error

    monkeypatch.setattr(coordinator_main, "_apply_inbox_claim", apply)
    completed = coordinator_main._process_inbox_claim(
        scope=SCOPE,
        owner="coordinator-1",
        claim=_claim("evt_00000000000000000000000001"),
        inbox=object(),  # type: ignore[arg-type]
        workflow=workflow,  # type: ignore[arg-type]
        connection=connection,  # type: ignore[arg-type]
        reader=object(),  # type: ignore[arg-type]
    )
    return completed, workflow, connection


def test_lease_contention_returns_the_inbox_claim_and_refunds_its_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(coordinator_main, "settings_scope_marker", None, raising=False)

    workflow = _FakeWorkflow()
    connection = _FakeConnection()

    def apply(**_: Any) -> None:
        raise InboxLeaseContention("incident inc_1 is currently leased")

    monkeypatch.setattr(coordinator_main, "_apply_inbox_claim", apply)
    completed = coordinator_main._process_inbox_claim(
        scope=SCOPE,
        owner="coordinator-1",
        claim=_claim("evt_00000000000000000000000001"),
        inbox=object(),  # type: ignore[arg-type]
        workflow=workflow,  # type: ignore[arg-type]
        connection=connection,  # type: ignore[arg-type]
        reader=object(),  # type: ignore[arg-type]
    )
    assert completed is False
    # The claim is handed straight back and the attempt it spent is refunded,
    # so a valid command on a busy incident can never reach quarantine.
    assert workflow.released == [
        _RecordedRelease("evt_00000000000000000000000001", True),
    ]
    assert connection.rollbacks == 1


def test_a_poisoned_claim_is_isolated_and_keeps_its_spent_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, workflow, connection = _run_claim(
        monkeypatch, ValueError("evidence object hash does not match the durable ledger")
    )
    assert completed is False
    # No refund: the event walks its bounded budget into durable quarantine.
    assert workflow.released == []
    assert connection.rollbacks == 1


def test_a_successful_claim_reports_progress_and_touches_no_recovery_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, workflow, connection = _run_claim(monkeypatch, None)
    assert completed is True
    assert workflow.released == []
    assert connection.rollbacks == 0


def test_the_inbox_budget_is_small_enough_that_refunding_contention_matters() -> None:
    # Five aborts park a valid event. That is why contention must be refunded
    # rather than counted, and why poison must still be counted.
    assert INBOX_CLAIM_ATTEMPT_BUDGET == 5


# --- 3. case wakeups carry the same bounded budget --------------------------


def test_case_wakeups_carry_a_bounded_claim_budget() -> None:
    assert WAKEUP_CLAIM_ATTEMPT_BUDGET >= 1


def test_permanent_repair_faults_are_classified_for_containment() -> None:
    from apps.coordinator.case_repair_start import PERMANENT_REPAIR_FAILURES
    from solvan.application import RepairPlanningError
    from solvan.persistence import WorkspaceConflict

    # A snapshot digest mismatch, an absent plan, and a provider refusal all
    # fail identically on every retry, so each becomes one owned BLOCKED review.
    assert issubclass(ValueError, PERMANENT_REPAIR_FAILURES)
    assert issubclass(RepairPlanningError, PERMANENT_REPAIR_FAILURES)
    assert issubclass(WorkspaceConflict, PERMANENT_REPAIR_FAILURES)


# --- 7. the repair-start lease outlives the step it protects ----------------


def test_starting_a_repair_holds_a_lease_longer_than_the_work_it_covers() -> None:
    from apps.coordinator.case_handlers import _DEFAULT_CASE_STEP_LEASE_MS
    from apps.coordinator.case_repair_start import START_REPAIR_LEASE_MS

    assert START_REPAIR_LEASE_MS > _DEFAULT_CASE_STEP_LEASE_MS
    # The comparable Antigravity adjudication path leases 360s for a 300s run.
    assert START_REPAIR_LEASE_MS >= 360_000


def _wakeup() -> ClaimedWakeup:
    return ClaimedWakeup(
        wakeup_id="wak_00000000000000000000000001",
        case_id="rcs_00000000000000000000000001",
        logical_step_key="case:rcs_1:start-repair:3",
        reason="Start the exact sandbox-bound repair attempt.",
        wake_at=datetime.now(UTC),
        claim_token=uuid4(),
        claim_expires_at=datetime.now(UTC) + timedelta(minutes=2),
    )


def test_releasing_a_lost_wakeup_claim_is_not_an_error() -> None:
    from apps.coordinator.case_handlers import _release_wakeup
    from solvan.application import ReliabilityCaseConflict

    class _Store:
        @contextmanager
        def transaction(self) -> Iterator[None]:
            yield

        def release_claimed_wakeup(self, **_: Any) -> None:
            raise ReliabilityCaseConflict("wakeup claim is expired or stale")

    class _Settings:
        scope = SCOPE

    _release_wakeup(
        store=_Store(),  # type: ignore[arg-type]
        settings=_Settings(),  # type: ignore[arg-type]
        scope_owner="coordinator-1",
        claim=_wakeup(),
        refund=True,
    )


# --- 5. an unplaced Alert scope cannot stop the rest of the tick ------------


class _AlertConnection:
    def __init__(self) -> None:
        self.transactions = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.transactions += 1
        yield


class _AlertSettings:
    scope = SCOPE


def test_a_scope_without_an_active_placement_skips_alert_leasing_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class _Repository:
        def __init__(self, _connection: Any) -> None:
            pass

        def reclaim_expired_alert_triage(self, **_: Any) -> None:
            calls.append("reclaim")

    monkeypatch.setattr(alert_triage_module, "AlertTriageRepository", _Repository)
    for name in ("_consume_operator_requests", "_admit_ready_episodes", "_retry_due_admissions"):
        monkeypatch.setattr(
            alert_triage_module, name, lambda _phase=name, **_: calls.append(_phase)
        )
    monkeypatch.setattr(
        alert_triage_module,
        "_start_next_alert_triage",
        lambda **_: calls.append("start"),
    )
    monkeypatch.setattr(alert_triage_module, "_current_cell_or_none", lambda *_: None)

    run_alert_triage_tick(
        settings=_AlertSettings(),  # type: ignore[arg-type]
        owner="coordinator-1",
        connection=_AlertConnection(),  # type: ignore[arg-type]
        runs=object(),  # type: ignore[arg-type]
    )
    # Durable admission still happens; only the placement-bound phases stop.
    assert calls == ["_consume_operator_requests", "_admit_ready_episodes", "_retry_due_admissions"]


def test_a_placed_scope_still_leases_and_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class _Repository:
        def __init__(self, _connection: Any) -> None:
            pass

        def reclaim_expired_alert_triage(self, *, cell_id: str, **_: Any) -> None:
            calls.append(f"reclaim:{cell_id}")

    monkeypatch.setattr(alert_triage_module, "AlertTriageRepository", _Repository)
    for name in ("_consume_operator_requests", "_admit_ready_episodes", "_retry_due_admissions"):
        monkeypatch.setattr(alert_triage_module, name, lambda **_: None)
    monkeypatch.setattr(
        alert_triage_module,
        "_start_next_alert_triage",
        lambda **kwargs: calls.append(f"start:{kwargs['cell_id']}"),
    )
    monkeypatch.setattr(alert_triage_module, "_current_cell_or_none", lambda *_: "cell_a")

    run_alert_triage_tick(
        settings=_AlertSettings(),  # type: ignore[arg-type]
        owner="coordinator-1",
        connection=_AlertConnection(),  # type: ignore[arg-type]
        runs=object(),  # type: ignore[arg-type]
    )
    assert calls == ["reclaim:cell_a", "start:cell_a"]


# --- 8. the durable Alert citation pair must be checkable -------------------


class _CompletionRepository:
    def __init__(self, _connection: Any) -> None:
        self.failures: list[str] = []
        self.completions: list[tuple[str, str]] = []

    def alert_completion_fence(self, **_: Any) -> tuple[str, str, int]:
        return ("atr_00000000000000000000000001", "token", 1)

    def complete_alert_triage(self, *, result_ref: str, result_hash: str, **_: Any) -> None:
        self.completions.append((result_ref, result_hash))

    def fail_alert_triage(self, *, error_class: str, **_: Any) -> None:
        self.failures.append(error_class)


class _StubRuntime:
    def __init__(self, *, output_gcs_uri: str | None, expected: str) -> None:
        self._output_gcs_uri = output_gcs_uri
        self._expected = expected

    def check(self, operation_name: str) -> QueryJobCheck:
        return QueryJobCheck(
            operation_name=operation_name,
            output_gcs_uri=self._output_gcs_uri,
            status="SUCCESS",
            result='{"schema_version": 1}',
        )

    def output_uri(self, *, scope: Scope, run_id: str) -> str:
        assert scope == SCOPE
        assert run_id.startswith("run_")
        return self._expected

    def cancel(self, **_: Any) -> None:  # pragma: no cover - not reached
        raise AssertionError("a live run must not be cancelled")


def _alert_run(output_ref: str) -> PendingRuntimeRun:
    return PendingRuntimeRun(
        run_id="run_00000000000000000000000001",
        incident_id=None,
        alert_episode_id="aep_00000000000000000000000001",
        reliability_case_id=None,
        agent_key="evidence-agent",
        agent_resource=("projects/123456789/locations/europe-west1/reasoningEngines/evidence-v1"),
        runtime_operation_name="projects/123456789/locations/europe-west1/operations/job-1",
        runtime_output_ref=output_ref,
        deadline=datetime.now(UTC) + timedelta(minutes=5),
        workflow_version=1,
        investigation_step_id=None,
        action_id=None,
        repair_plan_id=None,
    )


def _poll(
    monkeypatch: pytest.MonkeyPatch, *, stored_ref: str, provider_ref: str | None
) -> _CompletionRepository:
    expected = "gs://runtime/agent-runs/run_00000000000000000000000001.json"
    repository = _CompletionRepository(None)
    monkeypatch.setattr(
        alert_triage_module, "AlertTriageRepository", lambda _connection: repository
    )
    poll_alert_triage_run(
        settings=_AlertSettings(),  # type: ignore[arg-type]
        run=_alert_run(stored_ref),
        runtime=_StubRuntime(output_gcs_uri=provider_ref, expected=expected),  # type: ignore[arg-type]
        connection=_AlertConnection(),  # type: ignore[arg-type]
    )
    return repository


def test_a_correspondent_alert_result_pair_is_committed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "gs://runtime/agent-runs/run_00000000000000000000000001.json"
    repository = _poll(monkeypatch, stored_ref=expected, provider_ref=expected)
    assert repository.failures == []
    digest = "sha256:" + hashlib.sha256(b'{"schema_version": 1}').hexdigest()
    assert repository.completions == [(expected, digest)]


def test_a_provider_reference_that_drifts_from_the_hashed_result_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "gs://runtime/agent-runs/run_00000000000000000000000001.json"
    repository = _poll(
        monkeypatch,
        stored_ref=expected,
        provider_ref="gs://runtime/agent-runs/somebody-elses-object.json",
    )
    assert repository.completions == []
    assert repository.failures == ["RUNTIME_OUTPUT_REF_MISMATCH"]


def test_a_stored_reference_outside_this_runs_reserved_object_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "gs://runtime/agent-runs/run_00000000000000000000000001.json"
    repository = _poll(
        monkeypatch,
        stored_ref="gs://runtime/agent-runs/run_00000000000000000000000002.json",
        provider_ref=expected,
    )
    assert repository.completions == []
    assert repository.failures == ["RUNTIME_OUTPUT_REF_MISMATCH"]


# --- 3. a permanent repair-start fault blocks instead of aborting the tick ---


class _FakeCaseStore:
    def __init__(self, claims: tuple[ClaimedWakeup, ...], state: tuple[str, str]) -> None:
        self._claims = claims
        self._state = state
        self.completed: list[str] = []
        self.transitions: list[Any] = []
        self.blocked: list[dict[str, Any]] = []
        self.released: list[tuple[str, bool]] = []

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def claim_due_wakeups(self, **_: Any) -> tuple[ClaimedWakeup, ...]:
        return self._claims

    def claimed_case_state(self, **_: Any) -> tuple[str, None, str]:
        return (self._state[0], None, self._state[1])

    def complete_wakeup(self, *, claim: ClaimedWakeup, **_: Any) -> str:
        self.completed.append(claim.wakeup_id)
        return "evt_00000000000000000000000001"

    def commit_progress_transition(self, *, transition: Any, **kwargs: Any) -> tuple[int, str]:
        self.transitions.append(transition)
        self.blocked.append(kwargs)
        return (2, "wak_00000000000000000000000002")

    def release_claimed_wakeup(
        self, *, claim: ClaimedWakeup, refund_attempt: bool, **_: Any
    ) -> None:
        self.released.append((claim.wakeup_id, refund_attempt))


class _FakeCaseWorkflow:
    def __init__(self) -> None:
        self.lease_ttls: list[int] = []
        self.releases = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def acquire_lease(self, *, lease_ttl_ms: int, **_: Any) -> Any:
        self.lease_ttls.append(lease_ttl_ms)

        class _Lease:
            aggregate_type = None
            entity_id = "rel_00000000000000000000000001"
            owner = "coordinator-1"
            token = UUID(int=3)
            workflow_version = 1

        return _Lease()

    def release_lease(self, **_: Any) -> None:
        self.releases += 1


def _resume_with(
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: tuple[str, str],
    failure: Exception | None,
) -> tuple[_FakeCaseStore, _FakeCaseWorkflow]:
    from apps.coordinator import case_handlers

    store = _FakeCaseStore((_wakeup(),), state)
    workflow = _FakeCaseWorkflow()
    monkeypatch.setattr(case_handlers, "PostgresReliabilityCaseStore", lambda _c: store)

    def start(**_: Any) -> None:
        if failure is not None:
            raise failure

    monkeypatch.setattr(case_handlers, "start_planned_repair", start)

    class _Settings:
        scope = SCOPE

    case_handlers._resume_due_reliability_cases(
        settings=_Settings(),  # type: ignore[arg-type]
        owner="coordinator-1",
        workflow=workflow,  # type: ignore[arg-type]
        connection=_FakeConnection(),  # type: ignore[arg-type]
        reader=object(),  # type: ignore[arg-type]
    )
    return store, workflow


def test_a_permanent_repair_start_fault_becomes_one_owned_blocked_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, workflow = _resume_with(
        monkeypatch,
        state=("REPAIR_PLANNED", "START_REPAIR"),
        failure=ValueError("repository snapshot hash does not match the repair plan"),
    )
    # The wakeup is retired and the case reaches an owned, reviewable state, so
    # the same fault cannot re-abort the tick every two minutes forever.
    assert store.completed == ["wak_00000000000000000000000001"]
    assert [item.to_state for item in store.transitions] == ["BLOCKED"]
    assert store.transitions[0].from_state == "REPAIR_PLANNED"
    assert store.blocked[0]["blocked_owner"] == "application-engineering"
    assert store.blocked[0]["next_review_at"] is not None
    assert store.blocked[0]["recovery_plan"]
    # The recheck step is one the BLOCKED deferral loop already recognizes.
    assert store.blocked[0]["schedule"].next_action_kind == "RECHECK_REPAIR_POLICY"
    assert workflow.releases == 1


def test_starting_a_repair_takes_the_long_lease_and_a_healthy_step_blocks_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.coordinator.case_repair_start import START_REPAIR_LEASE_MS

    store, workflow = _resume_with(
        monkeypatch, state=("REPAIR_PLANNED", "START_REPAIR"), failure=None
    )
    assert workflow.lease_ttls == [START_REPAIR_LEASE_MS]
    assert store.transitions == []
    assert workflow.releases == 1


def test_an_unclassified_repair_fault_is_isolated_without_blocking_the_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, workflow = _resume_with(
        monkeypatch,
        state=("REPAIR_PLANNED", "START_REPAIR"),
        failure=OSError("the attester connection was reset"),
    )
    # Nothing durable is asserted about the case, the lease is still released,
    # and the claim lapses into its bounded budget rather than aborting the tick.
    assert store.transitions == []
    assert store.completed == []
    assert workflow.releases == 1


def test_a_step_owned_by_another_handler_is_refunded_rather_than_left_claimed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, workflow = _resume_with(
        monkeypatch, state=("REPAIR_IN_PROGRESS", "CHECK_PATCH_RESULT"), failure=None
    )
    assert store.released == [("wak_00000000000000000000000001", True)]
    assert workflow.lease_ttls == []
