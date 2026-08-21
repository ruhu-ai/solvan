from __future__ import annotations

from datetime import UTC, datetime

import pytest

from solvan.application.saas_scale_events import (
    ContentFreeEventFanout,
    CursorRecoveryRequired,
    EventCursor,
    PoisonEventBlocked,
)
from solvan.application.saas_scale_runtime import SequencedEvent

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)


def _event(
    sequence: int, *, state: str = "SEQUENCED", event_id: str | None = None
) -> SequencedEvent:
    return SequencedEvent(
        organization_id="org_demo",
        project_id="prj_demo",
        environment_id="env_demo",
        event_id=event_id or f"evt_{sequence}",
        event_ref=f"ref_event_{sequence}",
        event_hash=f"sha256:{sequence:064x}",
        placement_epoch=3,
        created_at=NOW,
        state=state,
        scope_sequence=sequence,
    )


def _cursor(*, sequence: int = 0) -> EventCursor:
    return EventCursor(
        cell_id="cell_eu_1",
        placement_epoch=3,
        scope_sequence=sequence,
        policy_epoch=4,
        membership_epoch=5,
    )


def _fanout(*, ceiling: int = 100) -> ContentFreeEventFanout:
    return ContentFreeEventFanout(
        cell_id="cell_eu_1",
        placement_epoch=3,
        policy_epoch=4,
        membership_epoch=5,
        buffer_ceiling=ceiling,
        now=NOW,
    )


def test_pubsub_wakeup_is_content_free_and_duplicate_delivery_is_idempotent() -> None:
    fanout = _fanout()
    first = fanout.publish((_event(1), _event(2)))
    duplicate = fanout.publish((_event(1), _event(2)))

    assert first is not None
    assert duplicate == first
    assert first.scope_key_hash.startswith("sha256:")
    assert not hasattr(first, "event_ref")
    assert first.from_sequence == 1
    assert first.to_sequence == 2
    assert len(fanout.wakeups) == 1


def test_reader_uses_authoritative_order_and_advances_only_after_a_bounded_page() -> None:
    fanout = _fanout()
    fanout.publish((_event(2), _event(1)))

    page = fanout.read(
        _cursor(),
        limit=1,
        current_cell_id="cell_eu_1",
        current_placement_epoch=3,
        current_policy_epoch=4,
        current_membership_epoch=5,
    )

    assert [event.scope_sequence for event in page.events] == [1]
    assert page.next_cursor.scope_sequence == 1


def test_stale_epoch_policy_or_membership_cursor_requires_recovery() -> None:
    fanout = _fanout()
    fanout.publish((_event(1),))

    with pytest.raises(CursorRecoveryRequired, match="placement epoch"):
        fanout.read(
            _cursor(),
            limit=10,
            current_cell_id="cell_eu_1",
            current_placement_epoch=4,
            current_policy_epoch=4,
            current_membership_epoch=5,
        )

    with pytest.raises(CursorRecoveryRequired, match="policy epoch"):
        fanout.read(
            _cursor(),
            limit=10,
            current_cell_id="cell_eu_1",
            current_placement_epoch=3,
            current_policy_epoch=5,
            current_membership_epoch=5,
        )


def test_slow_consumer_is_disconnected_without_advancing_the_cursor() -> None:
    fanout = _fanout(ceiling=1)
    fanout.publish((_event(1), _event(2)))

    page = fanout.read(
        _cursor(),
        limit=100,
        current_cell_id="cell_eu_1",
        current_placement_epoch=3,
        current_policy_epoch=4,
        current_membership_epoch=5,
    )

    assert page.overflow is True
    assert page.events == ()
    assert page.next_cursor.scope_sequence == 0
    assert page.recovery_reason == "SLOW_CONSUMER_CURSOR_RECOVERY"


def test_poison_event_blocks_later_rows_until_explicit_recovery() -> None:
    fanout = _fanout()
    fanout.publish((_event(1, state="QUARANTINED"), _event(2)))

    with pytest.raises(PoisonEventBlocked):
        fanout.read(
            _cursor(),
            limit=10,
            current_cell_id="cell_eu_1",
            current_placement_epoch=3,
            current_policy_epoch=4,
            current_membership_epoch=5,
        )


def test_recovery_requires_bound_high_water_and_receipt() -> None:
    fanout = _fanout()
    fanout.publish((_event(1), _event(2)))

    with pytest.raises(ValueError, match="typed receipt"):
        fanout.recover_cursor(
            _cursor(),
            cell_id="cell_eu_1",
            placement_epoch=3,
            policy_epoch=4,
            membership_epoch=5,
            verified_high_water=1,
            receipt_hash="not-a-hash",
        )

    recovered = fanout.recover_cursor(
        _cursor(),
        cell_id="cell_eu_1",
        placement_epoch=3,
        policy_epoch=4,
        membership_epoch=5,
        verified_high_water=1,
        receipt_hash="sha256:" + "a" * 64,
    )
    assert recovered.scope_sequence == 1
