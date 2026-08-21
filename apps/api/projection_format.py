"""Shared formatting for read-only console projections."""

from __future__ import annotations

from datetime import UTC, datetime


def _age(value: datetime) -> str:
    """Elapsed time in the coarsest unit that is still honest."""

    seconds = max(0, int((datetime.now(UTC) - value).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86_400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86_400}d"


def _short(value: object) -> str:
    """Elide the middle of an identifier, never its ends."""

    text = str(value)
    return text if len(text) <= 22 else f"{text[:10]}…{text[-8:]}"
