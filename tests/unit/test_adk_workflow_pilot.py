from __future__ import annotations

import pytest
from google.adk.workflow import JoinNode, Workflow

from solvan.agents.workflows._pilot import (
    PilotInput,
    build_read_only_research_workflow,
    select_research_branches,
)


def pilot_input(**changes: object) -> PilotInput:
    values: dict[str, object] = {
        "request_id": "run_00000000000000000000000000",
        "generation": 2,
        "expected_generation": 2,
        "available_sources": frozenset({"telemetry", "change_history", "production_graph"}),
        "evidence_refs": ("ev_00000000000000000000000000",),
        "allowed_read_tools": frozenset({"cloud_logging_query", "production_graph_read"}),
    }
    values.update(changes)
    return PilotInput.model_validate(values)


def test_pilot_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOLVAN_ADK_WORKFLOW_PILOT_ENABLED", raising=False)
    with pytest.raises(RuntimeError, match="disabled"):
        build_read_only_research_workflow(pilot_input())


def test_pilot_builds_deterministic_parallel_join_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_ADK_WORKFLOW_PILOT_ENABLED", "true")
    value = pilot_input()
    first = build_read_only_research_workflow(value)
    second = build_read_only_research_workflow(value)
    assert isinstance(first, Workflow)
    assert first.max_concurrency == 3
    assert first.graph is not None and second.graph is not None
    assert [node.name for node in first.graph.nodes] == [node.name for node in second.graph.nodes]
    assert any(isinstance(node, JoinNode) for node in first.graph.nodes)
    assert select_research_branches(value) == ("evidence", "changes", "hypotheses")
    assert len(first.graph.nodes) <= value.limits.maximum_total_nodes


def test_pilot_rejects_stale_generation_and_mutation_tools() -> None:
    with pytest.raises(ValueError, match="stale"):
        pilot_input(expected_generation=3)
    with pytest.raises(ValueError, match="read-only"):
        pilot_input(allowed_read_tools=frozenset({"execute_action"}))
