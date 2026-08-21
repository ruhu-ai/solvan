"""Google ADK Workspace Agent that can only propose a bounded patch."""

from __future__ import annotations

import os

from solvan.agents import AgentBuildConfig, build_workspace_agent
from solvan.agents.workspace_tools import (
    read_workspace_artifact,
    run_in_exploratory_sandbox,
    write_candidate_artifact,
)

root_agent = build_workspace_agent(
    AgentBuildConfig(
        model_resource=os.environ.get("SOLVAN_AGENT_MODEL_RESOURCE", "gemini-3.6-flash"),
        timeout_seconds=300,
        max_output_tokens=16_384,
    ),
    tools=[
        read_workspace_artifact,
        write_candidate_artifact,
        run_in_exploratory_sandbox,
    ],
)
