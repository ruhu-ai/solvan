"""What one turn, and one day of turns, may spend.

Ceilings live here rather than in the engine because they are configuration
with one reader, and because everything downstream — the response model, the
transcript projection, the console meter — must read the same numbers. Every
place that restated them was a place they could drift.

Specification 14 §11.3 design constants.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TurnBudget:
    """Per-turn ceilings. A no-tool model loop is bounded by `model_calls`."""

    tool_calls: int = 25
    model_calls: int = 10
    tokens: int = 60_000

    def as_dict(self) -> dict[str, int]:
        """The ceilings as the API and console read them.

        One shape, one source. These numbers used to be written out again in
        the response model's default and a third time in the browser, so a
        change to the ceiling silently left two copies lying to the reader.
        """

        return {
            "tool_calls": self.tool_calls,
            "model_calls": self.model_calls,
            "tokens": self.tokens,
        }

    def exceeded_by(self, usage: TurnUsage) -> str | None:
        if usage.tool_calls > self.tool_calls:
            return f"tool-call ceiling of {self.tool_calls}"
        if usage.model_calls > self.model_calls:
            return f"model-call ceiling of {self.model_calls}"
        if usage.tokens > self.tokens:
            return f"token ceiling of {self.tokens}"
        return None


@dataclass(slots=True)
class TurnUsage:
    tool_calls: int = 0
    model_calls: int = 0
    tokens: int = 0
    #: Authorized projection reads made by the deterministic claim gate rather
    #: than by the drafter. They are counted — every read under a grant is —
    #: but deliberately not charged to `tool_calls`: the tool ceiling bounds
    #: what a model may explore, and verification is the application checking
    #: its own output. Charging it would let a wide answer exhaust the ceiling
    #: with work the reader never asked for.
    verification_reads: int = 0


@dataclass(frozen=True, slots=True)
class DailyBudget:
    """UTC-window ceilings above the per-turn ones (§11.3).

    A per-turn ceiling bounds one answer; these bound a day of them, so a
    thread cannot be walked into unbounded spend one cheap question at a time.
    """

    thread_model_calls: int = 200
    principal_model_calls: int = 500


def _positive_env(name: str, fallback: int) -> int:
    """Read one configured ceiling, refusing anything that would widen it away.

    Absent or unparsable configuration takes the specification default rather
    than becoming permissive: a ceiling that disappears when a variable is
    mistyped is not a ceiling.
    """

    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        value = int(raw)
    except ValueError:
        return fallback
    return value if value > 0 else fallback


def default_turn_budget() -> TurnBudget:
    """The configured per-turn ceilings (§11.3 design constants)."""

    return TurnBudget(
        tool_calls=_positive_env("SOLVAN_LIAISON_TURN_TOOL_CALLS", 25),
        model_calls=_positive_env("SOLVAN_LIAISON_TURN_MODEL_CALLS", 10),
        tokens=_positive_env("SOLVAN_LIAISON_TURN_TOKENS", 60_000),
    )


def default_daily_budget() -> DailyBudget:
    """The configured UTC daily ceilings (§11.3 design constants)."""

    return DailyBudget(
        thread_model_calls=_positive_env("SOLVAN_LIAISON_THREAD_DAILY_MODEL_CALLS", 200),
        principal_model_calls=_positive_env("SOLVAN_LIAISON_PRINCIPAL_DAILY_MODEL_CALLS", 500),
    )
