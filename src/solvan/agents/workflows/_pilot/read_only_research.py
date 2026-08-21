"""Bounded ADK graph pilot inside one pre-authorized read-only agent run."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from typing import Any, Literal

from google.adk.agents.context import Context
from google.adk.workflow import START, Edge, FunctionNode, JoinNode, Workflow
from pydantic import BaseModel, ConfigDict, Field, model_validator

Branch = Literal["evidence", "changes", "hypotheses"]


class PilotLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_parallelism: int = Field(default=3, ge=1, le=3)
    maximum_refinements: int = Field(default=1, ge=0, le=1)
    maximum_total_nodes: int = Field(default=8, ge=5, le=8)
    maximum_tool_calls: int = Field(default=3, ge=0, le=3)
    maximum_tokens: int = Field(default=2_048, ge=128, le=4_096)
    maximum_wall_time_ms: int = Field(default=10_000, ge=100, le=30_000)


class PilotInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=200)
    generation: int = Field(ge=1)
    expected_generation: int = Field(ge=1)
    available_sources: frozenset[Literal["telemetry", "change_history", "production_graph"]]
    evidence_refs: tuple[str, ...] = Field(max_length=20)
    allowed_read_tools: frozenset[str]
    limits: PilotLimits = PilotLimits()

    @model_validator(mode="after")
    def fenced(self) -> PilotInput:
        if self.generation != self.expected_generation:
            raise ValueError("pilot input generation is stale")
        if any(
            "mutat" in tool.lower() or "execute" in tool.lower() for tool in self.allowed_read_tools
        ):
            raise ValueError("pilot tools must be read-only")
        return self

    @property
    def input_hash(self) -> str:
        encoded = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def pilot_enabled() -> bool:
    return os.environ.get("SOLVAN_ADK_WORKFLOW_PILOT_ENABLED", "false").lower() == "true"


def select_research_branches(value: PilotInput) -> tuple[Branch, ...]:
    """Route from typed source availability without a model call."""

    selected: list[Branch] = []
    if "telemetry" in value.available_sources:
        selected.append("evidence")
    if "change_history" in value.available_sources:
        selected.append("changes")
    if "production_graph" in value.available_sources:
        selected.append("hypotheses")
    return tuple(selected)


def build_read_only_research_workflow(value: PilotInput) -> Workflow:
    """Build one exact graph; the production registry never calls this pilot."""

    if not pilot_enabled():
        raise RuntimeError("ADK workflow pilot is disabled")
    selected = select_research_branches(value)
    if not selected:
        raise ValueError("pilot has no authorized read-only source branch")
    if len(selected) > value.limits.maximum_parallelism:
        raise ValueError("pilot branch count exceeds maximum parallelism")

    def route(ctx: Context, node_input: Any) -> dict[str, Any]:
        parsed = PilotInput.model_validate(node_input)
        if parsed.input_hash != value.input_hash:
            raise ValueError("pilot input differs from the graph-bound request")
        ctx.route = list(selected)
        return {"input": parsed.model_dump(mode="json"), "selected": list(selected)}

    router = FunctionNode(func=route, name="deterministic_router", rerun_on_resume=True)
    branches: dict[Branch, FunctionNode] = {
        branch: FunctionNode(
            func=_branch_function(branch),
            name=f"read_{branch}",
            rerun_on_resume=True,
        )
        for branch in selected
    }
    join = JoinNode(name="complete_read_join", rerun_on_resume=True)
    refinement = FunctionNode(
        func=_bounded_refinement,
        name="bounded_refinement",
        rerun_on_resume=True,
    )
    synthesis = FunctionNode(func=_synthesize, name="typed_synthesis", rerun_on_resume=True)
    edges: list[Edge | tuple[Any, ...]] = [(START, router)]
    edges.extend(
        Edge(from_node=router, to_node=node, route=branch) for branch, node in branches.items()
    )
    edges.extend(Edge(from_node=node, to_node=join) for node in branches.values())
    edges.extend(
        (
            Edge(from_node=join, to_node=refinement),
            Edge(from_node=refinement, to_node=synthesis),
        )
    )
    return Workflow(
        name="solvan_read_only_research_pilot",
        description="Non-authoritative read-only fan-out/join experiment.",
        edges=edges,
        max_concurrency=value.limits.maximum_parallelism,
        input_schema=PilotInput,
        rerun_on_resume=True,
        timeout=value.limits.maximum_wall_time_ms / 1_000,
    )


def _branch_function(branch: Branch) -> Callable[[Any], dict[str, Any]]:
    def read_branch(node_input: Any) -> dict[str, Any]:
        envelope = dict(node_input)
        input_value = PilotInput.model_validate(envelope["input"])
        if branch not in envelope["selected"]:
            raise ValueError("unselected pilot branch was scheduled")
        return {
            "branch": branch,
            "input_hash": input_value.input_hash,
            "generation": input_value.generation,
            "evidence_refs": list(input_value.evidence_refs),
            "authority": "READ_ONLY_NON_AUTHORITATIVE",
        }

    return read_branch


async def _bounded_refinement(ctx: Context, node_input: Any) -> dict[str, Any]:
    joined = dict(node_input)
    missing = [name for name, output in joined.items() if not output.get("evidence_refs")]
    if not missing:
        return {"joined": joined, "refinement_count": 0, "stop_reason": "COVERAGE_COMPLETE"}

    def record_no_progress(child_input: Any) -> dict[str, Any]:
        return {
            "missing": list(child_input["missing"]),
            "authority": "READ_ONLY_NON_AUTHORITATIVE",
            "stop_reason": "NO_PROGRESS",
        }

    refined = await ctx.run_node(
        FunctionNode(func=record_no_progress, name="read_only_refinement", rerun_on_resume=True),
        {"missing": missing},
        run_id="refinement-1",
        use_sub_branch=True,
    )
    return {
        "joined": joined,
        "refinement": refined,
        "refinement_count": 1,
        "stop_reason": "NO_PROGRESS",
    }


def _synthesize(node_input: Any) -> dict[str, Any]:
    material = dict(node_input)
    joined = dict(material["joined"])
    hashes = {str(value["input_hash"]) for value in joined.values()}
    generations = {int(value["generation"]) for value in joined.values()}
    if len(hashes) != 1 or len(generations) != 1:
        raise ValueError("fan-in contains stale or mixed branch results")
    return {
        "schema_version": 1,
        "status": "INCONCLUSIVE" if material["stop_reason"] == "NO_PROGRESS" else "COMPLETE",
        "input_hash": hashes.pop(),
        "generation": generations.pop(),
        "branches": sorted(joined),
        "evidence_refs": sorted(
            {ref for value in joined.values() for ref in value["evidence_refs"]}
        ),
        "authority": "NON_AUTHORITATIVE_AGENT_RESULT",
        "stop_reason": material["stop_reason"],
    }
