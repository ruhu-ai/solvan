from __future__ import annotations

from solvan.persistence.liaison_compaction import (
    TRANSCRIPT_RETENTION_DAYS as COMPACTION_RETENTION_DAYS,
)
from solvan.persistence.liaison_store import TRANSCRIPT_RETENTION_DAYS


def test_transcript_and_compaction_defaults_match_the_governing_contract() -> None:
    """The two write paths must not silently choose different lifetimes."""

    assert TRANSCRIPT_RETENTION_DAYS == 180
    assert COMPACTION_RETENTION_DAYS == TRANSCRIPT_RETENTION_DAYS
