"""Google ADK Verification Agent with one policy-bound verifier tool."""

from __future__ import annotations

import os

from solvan.agents import AgentBuildConfig, build_verification_agent
from solvan.agents.verification_tools import run_bound_verification

root_agent = build_verification_agent(
    AgentBuildConfig(
        model_resource=os.environ.get("SOLVAN_AGENT_MODEL_RESOURCE", "gemini-3.6-flash"),
        timeout_seconds=300,
        max_output_tokens=2_048,
    ),
    tools=[run_bound_verification],
)
