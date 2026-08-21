from __future__ import annotations

from tools.run_release_scenarios import LOCAL_SCENARIOS


def test_local_scenario_plan_is_complete_but_explicitly_not_release_eligible() -> None:
    assert [item.scenario_id for item in LOCAL_SCENARIOS] == [
        "S1",
        "S2",
        "S3",
        "S4",
        "S5",
        "S6",
    ]
    assert LOCAL_SCENARIOS[0].commands == ()
    assert all(item.commands for item in LOCAL_SCENARIOS[1:])
    assert all(item.assertions for item in LOCAL_SCENARIOS)
