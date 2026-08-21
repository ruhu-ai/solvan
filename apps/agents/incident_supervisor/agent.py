"""Google ADK entrypoint discovered by Agent Runtime deployment tooling."""

from __future__ import annotations

import os

from solvan.agents import AgentBuildConfig, build_incident_supervisor

root_agent = build_incident_supervisor(
    AgentBuildConfig(
        model_resource=os.environ.get("SOLVAN_AGENT_MODEL_RESOURCE", "gemini-3.6-flash"),
        timeout_seconds=300,
        max_output_tokens=4_096,
    )
)
