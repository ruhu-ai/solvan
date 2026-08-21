from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from solvan.application.saas_scale import ScaleRuntimeError
from solvan.application.saas_scale_runtime import (
    CommittedEventSequencer,
    LifecycleController,
    LifecycleJobState,
    SequencedEvent,
    typed_event_hash,
)

NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)


def _event(event_id: str, *, created_at: datetime = NOW) -> SequencedEvent:
    payload_hash = "sha256:" + "a" * 64
    return SequencedEvent(
        organization_id="org-a",
        project_id="prj_a",
        environment_id="env_a",
        event_id=event_id,
        event_ref=f"ref_{event_id}",
        event_hash=typed_event_hash(f"ref_{event_id}", payload_hash),
        placement_epoch=7,
        created_at=created_at,
    )


def test_move_requires_verified_receipts_and_monotonic_cutover() -> None:
    job = LifecycleJobState(
        organization_id="org-a",
        job_id="job_move_1",
        job_kind="MOVE",
        expected_placement_epoch=7,
        source_cell_id="cell-a",
        state="VERIFYING",
    )
    controller = LifecycleController()
    ready = controller.prepare_move(
        job,
        destination_cell_id="cell-b",
        proposed_placement_epoch=8,
        quiesce_receipt_hash="sha256:" + "1" * 64,
        source_high_water=42,
        export_manifest_hash="sha256:" + "2" * 64,
        destination_verification_hash="sha256:" + "3" * 64,
        isolation_verification_hash="sha256:" + "4" * 64,
        cutover_decision_ref="ref_cutover_1",
    )
    committed = controller.commit_move(ready, decision_ref="ref_cutover_1")
    assert committed.state == "CUTOVER_COMMITTED"
    with pytest.raises(ScaleRuntimeError, match="stale"):
        controller.commit_move(ready, decision_ref="ref_other")


def test_delete_cannot_complete_with_hold_or_unsettled_mutation() -> None:
    controller = LifecycleController()
    held = LifecycleJobState(
        organization_id="org-a",
        job_id="job_delete_1",
        job_kind="DELETE",
        expected_placement_epoch=7,
        source_cell_id="cell-a",
        state="VERIFYING",
        legal_hold_ref="ref_hold",
    )
    with pytest.raises(ScaleRuntimeError, match="legal hold"):
        controller.transition(
            held,
            expected_from="VERIFYING",
            to_state="COMPLETED",
            completion_proof_hash="sha256:" + "a" * 64,
        )
    unsettled = LifecycleJobState(
        organization_id="org-a",
        job_id="job_delete_2",
        job_kind="DELETE",
        expected_placement_epoch=7,
        source_cell_id="cell-a",
        state="VERIFYING",
        unsettled_mutation_count=1,
    )
    with pytest.raises(ScaleRuntimeError, match="unsettled"):
        controller.transition(
            unsettled,
            expected_from="VERIFYING",
            to_state="COMPLETED",
            completion_proof_hash="sha256:" + "a" * 64,
        )


def test_move_cannot_complete_before_the_committed_cutover() -> None:
    job = LifecycleJobState(
        organization_id="org-a",
        job_id="job_move_direct",
        job_kind="MOVE",
        expected_placement_epoch=7,
        source_cell_id="cell-a",
        state="VERIFYING",
    )
    with pytest.raises(ScaleRuntimeError, match="committed cutover"):
        LifecycleController().transition(
            job,
            expected_from="VERIFYING",
            to_state="COMPLETED",
            completion_proof_hash="sha256:" + "a" * 64,
        )


def test_model_shaped_lifecycle_state_cannot_become_authoritative() -> None:
    with pytest.raises(ScaleRuntimeError, match="typed application records"):
        LifecycleController().transition(  # type: ignore[arg-type]
            {"state": "VERIFYING"},
            expected_from="VERIFYING",
            to_state="BLOCKED",
        )


def test_sequencer_fences_claims_and_assigns_monotonic_scope_positions() -> None:
    sequencer = CommittedEventSequencer(placement_epoch=7, now=NOW)
    first = sequencer.ingest(_event("evt_1"))
    second = sequencer.ingest(_event("evt_2", created_at=NOW + timedelta(seconds=1)))
    first_claim = sequencer.claim(first.event_id, now=NOW)
    with pytest.raises(ScaleRuntimeError, match="claim token"):
        sequencer.sequence(first.event_id, claim_token=uuid4(), now=NOW)
    first_done = sequencer.sequence(first.event_id, claim_token=first_claim.claim_token, now=NOW)
    assert first_done.scope_sequence == 1
    second_claim = sequencer.claim(second.event_id, now=NOW)
    second_done = sequencer.sequence(second.event_id, claim_token=second_claim.claim_token, now=NOW)
    assert second_done.scope_sequence == 2


def test_poison_event_blocks_cursor_until_explicit_supersession() -> None:
    sequencer = CommittedEventSequencer(placement_epoch=7, now=NOW)
    event = sequencer.ingest(_event("evt_poison"))
    claim = sequencer.claim(event.event_id, now=NOW)
    quarantined = sequencer.quarantine(
        event.event_id, claim_token=claim.claim_token, error_ref="ref_poison"
    )
    assert quarantined.state == "QUARANTINED"
    with pytest.raises(ScaleRuntimeError, match="blocks"):
        sequencer.sequence(event.event_id, claim_token=claim.claim_token, now=NOW)
    superseded = sequencer.supersede(event.event_id, error_ref="ref_poison")
    assert superseded.state == "SUPERSEDED"
