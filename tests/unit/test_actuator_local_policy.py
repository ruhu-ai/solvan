"""The actuator's own controls hold when Solvan is unreachable or wrong.

A kill switch that lives only in Solvan's database protects nobody from Solvan.
These cases prove the binary refuses on its own, before any mutation connector
is constructed.
"""

from __future__ import annotations

import pytest

from apps.actuator.local_policy import (
    BUDGET_VARIABLE,
    KILL_SWITCH_VARIABLE,
    ActionRateBudget,
    LocalPolicyRefusal,
    check_kill_switch,
    read_budget_limit,
)


def test_an_engaged_kill_switch_refuses(tmp_path) -> None:
    engaged = tmp_path / "stop"
    engaged.write_text("engaged")
    with pytest.raises(LocalPolicyRefusal) as refusal:
        check_kill_switch({KILL_SWITCH_VARIABLE: str(engaged)})
    assert refusal.value.reason_code == "LOCAL_KILL_SWITCH_ENGAGED"


def test_an_open_switch_permits(tmp_path) -> None:
    check_kill_switch({KILL_SWITCH_VARIABLE: str(tmp_path / "absent")})


def test_an_unconfigured_kill_switch_refuses() -> None:
    """Absent configuration is a missing control, not an open switch."""

    with pytest.raises(LocalPolicyRefusal) as refusal:
        check_kill_switch({})
    assert refusal.value.reason_code == "LOCAL_KILL_SWITCH_UNCONFIGURED"


@pytest.mark.parametrize("raw", ["", "   ", "many", "0", "-1", "1.5"])
def test_an_unusable_budget_refuses(raw: str) -> None:
    """An unparsable budget must never read as unlimited."""

    with pytest.raises(LocalPolicyRefusal):
        read_budget_limit({BUDGET_VARIABLE: raw})


def test_a_missing_budget_refuses() -> None:
    with pytest.raises(LocalPolicyRefusal) as refusal:
        read_budget_limit({})
    assert refusal.value.reason_code == "LOCAL_BUDGET_UNCONFIGURED"


def test_the_budget_bounds_mutations_in_the_window() -> None:
    budget = ActionRateBudget(2, window_seconds=100.0)
    budget.claim(now=0.0)
    budget.claim(now=1.0)
    with pytest.raises(LocalPolicyRefusal) as refusal:
        budget.claim(now=2.0)
    assert refusal.value.reason_code == "LOCAL_RATE_BUDGET_EXHAUSTED"


def test_the_budget_recovers_once_the_window_passes() -> None:
    budget = ActionRateBudget(1, window_seconds=100.0)
    budget.claim(now=0.0)
    with pytest.raises(LocalPolicyRefusal):
        budget.claim(now=50.0)
    budget.claim(now=100.0)
