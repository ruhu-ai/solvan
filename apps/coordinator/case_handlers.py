"""Multi-day Reliability Case opening, review, and wakeup progression."""

from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection

from apps.coordinator.case_repair_start import (
    PERMANENT_REPAIR_FAILURES,
    START_REPAIR_LEASE_MS,
    start_planned_repair,
)
from apps.coordinator.contracts import CoordinatorSettings
from solvan.application import (
    CaseSchedule,
    ClaimedWakeup,
    CoordinatorAuthority,
    ReliabilityCaseConflict,
    ReliabilityCaseCoordinator,
    RepairPlanningError,
)
from solvan.persistence import (
    AggregateType,
    LeaseHandle,
    PostgresPatchReviewStore,
    PostgresReliabilityCaseStore,
    PostgresRepairStore,
    PostgresWorkflowStore,
    TransitionWrite,
)
from solvan.platform.evidence_objects import GcsEvidenceReader

# Every other case step is a handful of bounded statements under its lease, so
# the default lease stays short; only the repair start needs a long one.
_DEFAULT_CASE_STEP_LEASE_MS = 60_000


def _release_wakeup(
    *,
    store: PostgresReliabilityCaseStore,
    settings: CoordinatorSettings,
    scope_owner: str,
    claim: ClaimedWakeup,
    refund: bool,
) -> None:
    """Hand a claim back now instead of waiting for its TTL to lapse.

    A claim whose token already lost the race has nothing left to return, so
    that conflict is the expected outcome rather than an error worth raising
    into the tick.
    """

    with suppress(ReliabilityCaseConflict), store.transaction():
        store.release_claimed_wakeup(
            scope=settings.scope,
            owner=scope_owner,
            claim=claim,
            refund_attempt=refund,
        )


def _block_case_step(
    *,
    store: PostgresReliabilityCaseStore,
    settings: CoordinatorSettings,
    owner: str,
    claim: ClaimedWakeup,
    lease: LeaseHandle,
    from_state: str,
    reason_code: str,
    rationale: str,
    logical_step_key: str,
    next_action_kind: str,
    review_reason: str,
    blocked_owner: str,
    recovery_plan: str,
) -> None:
    """Turn one permanent step fault into an owned, recoverable BLOCKED review."""

    review_at = datetime.now(UTC) + timedelta(hours=1)
    with store.transaction():
        store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
        store.commit_progress_transition(
            scope=settings.scope,
            lease=lease,
            transition=TransitionWrite(
                from_state=from_state,
                to_state="BLOCKED",
                transition_key=f"PROVIDER_BLOCKED:{claim.wakeup_id}",
                actor_type="COORDINATOR",
                actor_id=owner,
                reason_code=reason_code,
                rationale_summary=rationale[:500],
            ),
            schedule=CaseSchedule(
                logical_step_key=logical_step_key,
                next_action_kind=next_action_kind,
                wake_at=review_at,
                reason=review_reason,
            ),
            blocked_owner=blocked_owner,
            next_review_at=review_at,
            recovery_plan=recovery_plan,
        )


def _open_mitigated_reliability_cases(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
) -> None:
    """Give every verified mitigation a durable permanent-repair owner."""

    store = PostgresReliabilityCaseStore(connection)
    coordinator = ReliabilityCaseCoordinator(store)
    with store.transaction():
        incident_ids = store.mitigated_incidents_without_case(scope=settings.scope)
    for incident_id in incident_ids:
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=settings.scope,
                aggregate_type=AggregateType.INCIDENT,
                entity_id=incident_id,
                owner=owner,
                lease_ttl_ms=60_000,
            )
        if lease is None:
            continue
        authority = CoordinatorAuthority(owner, lease.token, lease.workflow_version)
        try:
            coordinator.open_for_mitigated_incident(
                scope=settings.scope,
                incident_id=incident_id,
                authority=authority,
                schedule=CaseSchedule(
                    logical_step_key=f"case:{incident_id}:start-rca:1",
                    next_action_kind="START_RCA",
                    wake_at=datetime.now(UTC),
                    reason=(
                        "Mitigation is independently verified; permanent repair "
                        "ownership must continue durably."
                    ),
                ),
            )
        finally:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)


def _advance_patch_reviews(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
) -> None:
    reviews = PostgresPatchReviewStore(connection)
    cases = PostgresReliabilityCaseStore(connection)
    with workflow.transaction():
        pending = reviews.pending(scope=settings.scope)
    for item in pending:
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=settings.scope,
                aggregate_type=AggregateType.RELIABILITY_CASE,
                entity_id=item.reliability_case_id,
                owner=owner,
                lease_ttl_ms=60_000,
            )
        if lease is None:
            continue
        try:
            with workflow.transaction():
                decision = reviews.decision_for_apply(
                    scope=settings.scope,
                    lease=lease,
                    review_id=item.review_id,
                )
                reviews.mark_applied(
                    scope=settings.scope,
                    lease=lease,
                    review_id=item.review_id,
                )
                cases.complete_active_wakeup_for_transition(scope=settings.scope, lease=lease)
                approved = decision.decision == "APPROVE"
                cases.commit_progress_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="AWAITING_REVIEW",
                        to_state="READY_FOR_CANARY" if approved else "REPAIR_IN_PROGRESS",
                        transition_key=(
                            f"REVIEW_APPROVED:{decision.review_id}"
                            if approved
                            else f"CHANGES_REQUESTED:{decision.review_id}"
                        ),
                        actor_type="HUMAN",
                        actor_id=decision.reviewer_principal,
                        reason_code=(
                            "AUTHENTICATED_PATCH_REVIEW_APPROVED"
                            if approved
                            else "AUTHENTICATED_CHANGES_REQUESTED"
                        ),
                        rationale_summary=(
                            "The coordinator applied an exact, digest-bound patch "
                            "review under the Reliability Case lease."
                        ),
                        evidence_refs=(
                            f"db://solvan/patch-reviews/{decision.review_id}",
                            f"db://solvan/patch-artifacts/{decision.patch_artifact_id}",
                        ),
                    ),
                    schedule=CaseSchedule(
                        logical_step_key=(
                            f"case:{item.reliability_case_id}:qualify-code-change:6"
                            if approved
                            else f"case:{item.reliability_case_id}:replan-repair:6"
                        ),
                        next_action_kind=("QUALIFY_CODE_CHANGE" if approved else "REPLAN_REPAIR"),
                        wake_at=datetime.now(UTC),
                        reason=(
                            "Qualify the reviewed patch against the current repository."
                            if approved
                            else "Define a new repair-plan version from requested changes."
                        ),
                    ),
                )
        finally:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)


def _resume_due_reliability_cases(
    *,
    settings: CoordinatorSettings,
    owner: str,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
) -> None:
    """Run one bounded case step; no process remains alive between wakeups."""

    store = PostgresReliabilityCaseStore(connection)
    with store.transaction():
        claims = store.claim_due_wakeups(
            scope=settings.scope,
            owner=owner,
            claim_ttl_ms=120_000,
        )
    for claim in claims:
        with store.transaction():
            state, _, next_action = store.claimed_case_state(
                scope=settings.scope, owner=owner, claim=claim
            )
        recognized = {
            ("OPEN", "START_RCA"),
            ("ROOT_CAUSE_ANALYSIS", "DEFINE_REPAIR"),
            ("REPAIR_PLANNED", "START_REPAIR"),
            ("REPAIR_IN_PROGRESS", "REPLAN_REPAIR"),
            ("READY_FOR_CANARY", "PREPARE_CANARY"),
        }
        blocked_rechecks = {
            "RECHECK_REPAIR_POLICY",
            "RECHECK_WORKSPACE_PROVIDER",
            "REVIEW_FAILED_PATCH",
            "RECHECK_CANARY_PROVIDER",
        }
        if state == "BLOCKED" and next_action in blocked_rechecks:
            with store.transaction():
                store.defer_claimed_wakeup(
                    scope=settings.scope,
                    owner=owner,
                    claim=claim,
                    wake_at=datetime.now(UTC) + timedelta(hours=1),
                    reason=(
                        "The owned dependency remains blocked; retain one durable "
                        "future review without a resident process."
                    ),
                )
            continue
        if (state, next_action) not in recognized:
            # Their provider-specific handlers own completion; acknowledging an
            # unknown step would destroy durable work. Hand the claim straight
            # back and refund it, because not being this handler's step is no
            # evidence at all that the step is poisoned.
            _release_wakeup(
                store=store, scope_owner=owner, settings=settings, claim=claim, refund=True
            )
            continue
        with workflow.transaction():
            lease = workflow.acquire_lease(
                scope=settings.scope,
                aggregate_type=AggregateType.RELIABILITY_CASE,
                entity_id=claim.case_id,
                owner=owner,
                lease_ttl_ms=(
                    START_REPAIR_LEASE_MS
                    if state == "REPAIR_PLANNED"
                    else _DEFAULT_CASE_STEP_LEASE_MS
                ),
            )
        if lease is None:
            _release_wakeup(
                store=store, scope_owner=owner, settings=settings, claim=claim, refund=True
            )
            continue
        try:
            if state == "REPAIR_IN_PROGRESS" and next_action == "REPLAN_REPAIR":
                try:
                    with store.transaction():
                        plan = PostgresRepairStore(connection).replan_after_requested_changes(
                            scope=settings.scope, lease=lease
                        )
                        store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
                        store.commit_progress_transition(
                            scope=settings.scope,
                            lease=lease,
                            transition=TransitionWrite(
                                from_state="REPAIR_IN_PROGRESS",
                                to_state="REPAIR_PLANNED",
                                transition_key=f"REPAIR_REPLAN_REQUIRED:{claim.wakeup_id}",
                                actor_type="COORDINATOR",
                                actor_id=owner,
                                reason_code="AUTHENTICATED_CHANGES_REQUESTED",
                                rationale_summary=(
                                    "An immutable successor plan preserves the approved "
                                    "repository boundary and the exact review provenance."
                                ),
                                evidence_refs=plan.evidence_refs,
                            ),
                            schedule=CaseSchedule(
                                logical_step_key=(
                                    f"case:{claim.case_id}:start-repair:{plan.plan_version}"
                                ),
                                next_action_kind="START_REPAIR",
                                wake_at=datetime.now(UTC),
                                reason="Start the reviewed successor repair attempt.",
                            ),
                        )
                    continue
                except RepairPlanningError as error:
                    with store.transaction():
                        store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
                        store.commit_progress_transition(
                            scope=settings.scope,
                            lease=lease,
                            transition=TransitionWrite(
                                from_state="REPAIR_IN_PROGRESS",
                                to_state="BLOCKED",
                                transition_key=f"PROVIDER_BLOCKED:{claim.wakeup_id}",
                                actor_type="COORDINATOR",
                                actor_id=owner,
                                reason_code="REPLAN_PROVENANCE_UNAVAILABLE",
                                rationale_summary=str(error)[:500],
                            ),
                            schedule=CaseSchedule(
                                logical_step_key=f"case:{claim.case_id}:replan-review",
                                next_action_kind="REVIEW_FAILED_PATCH",
                                wake_at=datetime.now(UTC) + timedelta(hours=1),
                                reason="Review the missing exact replan provenance.",
                            ),
                            blocked_owner="application-engineering",
                            next_review_at=datetime.now(UTC) + timedelta(hours=1),
                            recovery_plan=(
                                "Record one exact changes-requested patch review bound "
                                "to the active plan, then resume replanning."
                            ),
                        )
                    continue
            if state == "READY_FOR_CANARY" and next_action == "PREPARE_CANARY":
                # Live Git-provider merge/canary/rollout is explicitly P1 in the
                # product contract. Preserve the reviewed artifact and a durable,
                # owned recovery point instead of fabricating deployment proof.
                review_at = datetime.now(UTC) + timedelta(hours=1)
                with store.transaction():
                    store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
                    store.commit_progress_transition(
                        scope=settings.scope,
                        lease=lease,
                        transition=TransitionWrite(
                            from_state="READY_FOR_CANARY",
                            to_state="BLOCKED",
                            transition_key=f"PROVIDER_BLOCKED:{claim.wakeup_id}",
                            actor_type="COORDINATOR",
                            actor_id=owner,
                            reason_code="CANARY_RELEASE_PROVIDER_NOT_QUALIFIED",
                            rationale_summary=(
                                "The exact patch is reviewed, but no qualified release "
                                "provider receipt authorizes a production canary."
                            ),
                        ),
                        schedule=CaseSchedule(
                            logical_step_key=f"case:{claim.case_id}:canary-provider-review",
                            next_action_kind="RECHECK_CANARY_PROVIDER",
                            wake_at=review_at,
                            reason="Recheck the qualified release-provider integration.",
                        ),
                        blocked_owner="release-engineering",
                        next_review_at=review_at,
                        recovery_plan=(
                            "Qualify a digest-bound Git merge/build/deploy provider and "
                            "exact canary verification profile before resuming."
                        ),
                    )
                continue
            if state == "ROOT_CAUSE_ANALYSIS":
                try:
                    with store.transaction():
                        plan = PostgresRepairStore(connection).define_exact_plan(
                            scope=settings.scope, lease=lease
                        )
                        store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
                        store.commit_progress_transition(
                            scope=settings.scope,
                            lease=lease,
                            transition=TransitionWrite(
                                from_state="ROOT_CAUSE_ANALYSIS",
                                to_state="REPAIR_PLANNED",
                                transition_key=f"REPAIR_DEFINED:{claim.wakeup_id}",
                                actor_type="COORDINATOR",
                                actor_id=owner,
                                reason_code="REPAIR_DEFINED",
                                rationale_summary=(
                                    "A bounded immutable repair plan was resolved from "
                                    "the approved repository policy and confirmed cause."
                                ),
                                evidence_refs=plan.evidence_refs,
                            ),
                            schedule=CaseSchedule(
                                logical_step_key=f"case:{claim.case_id}:start-repair:3",
                                next_action_kind="START_REPAIR",
                                wake_at=datetime.now(UTC),
                                reason="Start the exact sandbox-bound repair attempt.",
                            ),
                        )
                    continue
                except RepairPlanningError as error:
                    with store.transaction():
                        store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
                        store.commit_progress_transition(
                            scope=settings.scope,
                            lease=lease,
                            transition=TransitionWrite(
                                from_state="ROOT_CAUSE_ANALYSIS",
                                to_state="BLOCKED",
                                transition_key=f"PROVIDER_BLOCKED:{claim.wakeup_id}",
                                actor_type="COORDINATOR",
                                actor_id=owner,
                                reason_code="REPAIR_POLICY_UNAVAILABLE",
                                rationale_summary=str(error)[:500],
                            ),
                            schedule=CaseSchedule(
                                logical_step_key=f"case:{claim.case_id}:repair-policy-review",
                                next_action_kind="RECHECK_REPAIR_POLICY",
                                wake_at=datetime.now(UTC) + timedelta(hours=1),
                                reason="Recheck the approved repository repair policy.",
                            ),
                            blocked_owner="application-engineering",
                            next_review_at=datetime.now(UTC) + timedelta(hours=1),
                            recovery_plan=(
                                "Approve one exact REPOSITORY Production Graph node "
                                "with a pinned snapshot, commit, globs, commands, and "
                                "regional ADK Workspace provider."
                            ),
                        )
                    continue
            if state == "REPAIR_PLANNED":
                try:
                    start_planned_repair(
                        settings=settings,
                        owner=owner,
                        connection=connection,
                        reader=reader,
                        store=store,
                        claim=claim,
                        lease=lease,
                    )
                except PERMANENT_REPAIR_FAILURES as error:
                    # Retrying this claim would fail identically forever and
                    # re-abort the tick with it. Record one owned review with
                    # the same shape the RCA and replan steps already use.
                    _block_case_step(
                        store=store,
                        settings=settings,
                        owner=owner,
                        claim=claim,
                        lease=lease,
                        from_state="REPAIR_PLANNED",
                        reason_code="REPAIR_START_MATERIAL_UNAVAILABLE",
                        rationale=str(error),
                        logical_step_key=f"case:{claim.case_id}:repair-start-review",
                        next_action_kind="RECHECK_REPAIR_POLICY",
                        review_reason="Recheck the exact repair material and workspace provider.",
                        blocked_owner="application-engineering",
                        recovery_plan=(
                            "Restore the pinned repository snapshot at its recorded "
                            "digest and an open workspace on the plan's approved "
                            "provider, then resume the repair start."
                        ),
                    )
                continue
            with store.transaction():
                store.complete_wakeup(scope=settings.scope, owner=owner, claim=claim)
                store.commit_progress_transition(
                    scope=settings.scope,
                    lease=lease,
                    transition=TransitionWrite(
                        from_state="OPEN",
                        to_state="ROOT_CAUSE_ANALYSIS",
                        transition_key=f"RCA_STARTED:{claim.wakeup_id}",
                        actor_type="COORDINATOR",
                        actor_id=owner,
                        reason_code="RCA_STARTED",
                        rationale_summary=(
                            "The due durable wakeup started the bounded permanent-"
                            "repair analysis step."
                        ),
                    ),
                    schedule=CaseSchedule(
                        logical_step_key=f"case:{claim.case_id}:define-repair:2",
                        next_action_kind="DEFINE_REPAIR",
                        wake_at=datetime.now(UTC) + timedelta(days=1),
                        reason=(
                            "Resume on the next calendar day with authoritative "
                            "incident evidence and no resident process."
                        ),
                    ),
                )
        except ReliabilityCaseConflict:
            # Another coordinator advanced this case first. Nothing durable
            # changed here, and the case is not poisoned, so refund the claim.
            _release_wakeup(
                store=store, scope_owner=owner, settings=settings, claim=claim, refund=True
            )
        except Exception:
            # An unclassified fault keeps the attempt it spent and leaves the
            # claim to lapse, so a step that keeps failing this way walks its
            # bounded budget into durable quarantine. One bad case never stops
            # the graph reconciliation and Relay maintenance behind it.
            with suppress(Exception):
                connection.rollback()
        finally:
            with workflow.transaction():
                workflow.release_lease(scope=settings.scope, lease=lease)
