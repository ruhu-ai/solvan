"""Google ADK evidence agent with registered, typed, read-only tools."""

from __future__ import annotations

import os

from solvan.agents import AgentBuildConfig, build_evidence_agent
from solvan.agents.read_tools import (
    cloud_audit_log_query,
    cloud_logging_query,
    cloud_monitoring_query,
    cloud_trace_read,
    error_reporting_query,
    kubernetes_metadata_read,
    log_pattern_summary,
    log_sample_bounded,
    managed_prometheus_query,
    metric_baseline_compare,
    metric_change_point_detect,
    metric_correlate,
)

root_agent = build_evidence_agent(
    AgentBuildConfig(
        model_resource=os.environ.get("SOLVAN_AGENT_MODEL_RESOURCE", "gemini-3.6-flash"),
        timeout_seconds=300,
        max_output_tokens=8_192,
    ),
    tools=[
        cloud_monitoring_query,
        cloud_logging_query,
        cloud_trace_read,
        kubernetes_metadata_read,
        cloud_audit_log_query,
        error_reporting_query,
        managed_prometheus_query,
        metric_baseline_compare,
        metric_change_point_detect,
        metric_correlate,
        log_pattern_summary,
        log_sample_bounded,
    ],
)
