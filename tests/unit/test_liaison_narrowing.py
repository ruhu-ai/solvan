"""A decision may shrink what was displayed, and may do nothing else.

The interesting attack is not adding a tool — that is obvious and refused. It
is *removing the field that stated the bound*, so the step arrives at the
coordinator with no profile, no budget, or no anchor at all. That reads as
narrower and is in fact unbounded, so it is refused here too.

Specification 14 §14.
"""

from __future__ import annotations

from solvan.persistence.liaison_parked import is_narrowing, payload_digest

DISPLAYED = {
    "purpose": "Read the payments error ratio",
    "agent": "evidence-agent",
    "tool_profile": ["metrics.read", "logs.read"],
    "budget": "1 model · 3 tools",
    "anchor_record_type": "incident",
    "anchor_record_id": "INC-1042",
    "dependencies": [],
}


def _decided(**changes: object) -> dict[str, object]:
    return {**DISPLAYED, **changes}


def test_a_smaller_tool_profile_is_a_narrowing() -> None:
    assert is_narrowing(DISPLAYED, _decided(tool_profile=["metrics.read"]))
    assert is_narrowing(DISPLAYED, dict(DISPLAYED)), "an unchanged decision is trivially narrower"


def test_an_added_tool_is_not_a_narrowing() -> None:
    assert not is_narrowing(DISPLAYED, _decided(tool_profile=["metrics.read", "config.write"]))


def test_a_changed_scalar_is_not_a_narrowing() -> None:
    assert not is_narrowing(DISPLAYED, _decided(anchor_record_id="INC-9999"))
    assert not is_narrowing(DISPLAYED, _decided(budget="20 models · 400 tools"))


def test_dropping_the_field_that_stated_the_bound_is_not_a_narrowing() -> None:
    """The review's P1: an omitted key used to pass, and an omitted tool
    profile is an unbounded step, not a smaller one."""

    for dropped in ("tool_profile", "budget", "anchor_record_id", "agent"):
        decided = {key: value for key, value in DISPLAYED.items() if key != dropped}
        assert not is_narrowing(DISPLAYED, decided), f"dropping {dropped} must not pass"
    assert not is_narrowing(DISPLAYED, {}), "an empty decision decides nothing"


def test_an_added_key_is_not_a_narrowing() -> None:
    assert not is_narrowing(DISPLAYED, _decided(escalate=True))


def test_the_digest_binds_what_was_displayed() -> None:
    assert payload_digest(DISPLAYED) == payload_digest(dict(reversed(list(DISPLAYED.items()))))
    assert payload_digest(DISPLAYED) != payload_digest(_decided(tool_profile=["metrics.read"]))
