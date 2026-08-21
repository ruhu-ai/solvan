from __future__ import annotations

import pytest

from apps.api.liaison_http_support import _CLIENT_EVENT_BUFFER_CEILING
from apps.api.liaison_replay_routes import classify_stream_page


def test_stream_page_at_ceiling_forces_cursor_recovery_without_dropping_cursor() -> None:
    decision = classify_stream_page(
        page_size=_CLIENT_EVENT_BUFFER_CEILING,
        cursor=1442,
    )

    assert decision.overflow is True
    assert decision.last_sequence == 1442


def test_stream_page_below_ceiling_can_be_delivered() -> None:
    decision = classify_stream_page(page_size=_CLIENT_EVENT_BUFFER_CEILING - 1, cursor=7)

    assert decision.overflow is False
    assert decision.last_sequence == 7


@pytest.mark.parametrize(
    ("page_size", "cursor", "buffer_ceiling"),
    ((-1, 0, 10), (0, -1, 10), (0, 0, 0)),
)
def test_stream_page_rejects_invalid_flow_control_operands(
    page_size: int, cursor: int, buffer_ceiling: int
) -> None:
    with pytest.raises(ValueError, match="operands"):
        classify_stream_page(
            page_size=page_size,
            cursor=cursor,
            buffer_ceiling=buffer_ceiling,
        )
