"""Google ADK Execution Agent with one Agent Gateway-bound actuator tool."""

from __future__ import annotations

import os

from solvan.agents import AgentBuildConfig, build_execution_agent
from solvan.agents.execution_tools import execute_authorized_action

root_agent = build_execution_agent(
    AgentBuildConfig(
        model_resource=os.environ.get("SOLVAN_AGENT_MODEL_RESOURCE", "gemini-3.6-flash"),
        timeout_seconds=300,
        max_output_tokens=2_048,
    ),
    tools=[execute_authorized_action],
)
