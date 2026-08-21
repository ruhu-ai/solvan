"""Google ADK infrastructure agent with read-only governed tools."""

from __future__ import annotations

import os

from solvan.agents import AgentBuildConfig, build_infrastructure_agent
from solvan.agents.read_tools import (
    cloud_asset_inventory_search,
    cloud_build_history_read,
    cloud_run_read,
    cloud_run_revision_compare,
    cloud_sql_metadata_read,
    github_commit_history_read,
    github_commit_range_read,
    github_deployments_read,
    github_discussions_read,
    github_issue_read,
    github_merge_queue_read,
    github_pr_diff_read,
    github_repository_tree_read,
    github_search_read,
    github_workflow_run_read,
    github_workflow_runs_read,
    production_graph_read,
)

root_agent = build_infrastructure_agent(
    AgentBuildConfig(
        model_resource=os.environ.get("SOLVAN_AGENT_MODEL_RESOURCE", "gemini-3.6-flash"),
        timeout_seconds=300,
        max_output_tokens=8_192,
    ),
    tools=[
        cloud_asset_inventory_search,
        cloud_build_history_read,
        cloud_run_read,
        cloud_run_revision_compare,
        cloud_sql_metadata_read,
        github_commit_history_read,
        github_commit_range_read,
        github_deployments_read,
        github_discussions_read,
        github_issue_read,
        github_merge_queue_read,
        github_pr_diff_read,
        github_repository_tree_read,
        github_search_read,
        github_workflow_runs_read,
        github_workflow_run_read,
        production_graph_read,
    ],
)
