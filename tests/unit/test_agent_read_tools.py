from __future__ import annotations

from typing import Any

import pytest

from solvan.agents import read_tools


class _Response:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return {
            "evidence_ref": "evd_00000000000000000000000000",
            "content_ref": "gs://evidence/result.json",
            "content_hash": f"sha256:{'a' * 64}",
            "bounded_summary": "Bounded evidence was stored.",
            "classification": "INTERNAL",
            "armor_verdict_ref": None,
        }


def test_read_tool_wrappers_send_only_typed_bounded_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def post(url: str, **kwargs: Any) -> _Response:
        calls.append({"url": url, **kwargs})
        return _Response()

    monkeypatch.setenv("SOLVAN_EVIDENCE_BROKER_URL", "https://broker.example")
    monkeypatch.setenv("SOLVAN_AGENT_KEY", "evidence-agent")
    monkeypatch.setattr(
        read_tools,
        "private_service_headers",
        lambda *, audience_variable: {"Authorization": "Bearer runtime-token"},
    )
    monkeypatch.setattr(read_tools.httpx, "post", post)
    invocation = "inv_00000000000000000000000000"
    service = "svc_00000000000000000000000000"
    evidence = "evd_00000000000000000000000000"

    assert read_tools.metric_change_point_detect(invocation, service, evidence)[
        "evidence_ref"
    ].startswith("evd_")
    read_tools.metric_correlate(invocation, service, evidence, evidence)
    read_tools.log_pattern_summary(invocation, service, evidence)
    read_tools.log_sample_bounded(invocation, service, evidence, maximum_entries=7)
    read_tools.metric_baseline_compare(invocation, service, evidence, evidence)
    read_tools.cloud_trace_read(invocation, service, "0" * 32)
    read_tools.cloud_monitoring_query(
        invocation, service, "HTTP_5XX_RATIO", "2026-08-10T12:00:00Z", "2026-08-10T12:05:00Z"
    )
    read_tools.managed_prometheus_query(
        invocation, service, "payments.error-ratio", "2026-08-10T12:00:00Z", "2026-08-10T12:05:00Z"
    )
    read_tools.cloud_logging_query(
        invocation,
        service,
        "payments",
        "connection-exhaustion",
        "2026-08-10T12:00:00Z",
        "2026-08-10T12:05:00Z",
    )
    read_tools.cloud_audit_log_query(
        invocation, service, "2026-08-10T11:00:00Z", "2026-08-10T12:00:00Z"
    )
    read_tools.error_reporting_query(
        invocation, service, "2026-08-10T11:00:00Z", "2026-08-10T12:00:00Z"
    )
    read_tools.cloud_run_read(invocation, service)
    read_tools.cloud_run_revision_compare(invocation, service, evidence, evidence)
    read_tools.cloud_asset_inventory_search(invocation, service, "CLOUD_RUN_SERVICE")
    read_tools.cloud_build_history_read(
        invocation,
        service,
        "pgn_00000000000000000000000000",
        "2026-08-10T11:00:00Z",
        "2026-08-10T12:00:00Z",
    )
    read_tools.github_commit_range_read(
        invocation, service, "pgn_00000000000000000000000000", "a" * 40, "b" * 40
    )
    read_tools.github_pr_diff_read(invocation, service, "pgn_00000000000000000000000000", 7)
    read_tools.github_workflow_run_read(
        invocation, service, "pgn_00000000000000000000000000", 9, "b" * 40
    )
    read_tools.cloud_sql_metadata_read(invocation, service, "pgn_00000000000000000000000000")
    read_tools.production_graph_read(invocation, service, "pgs_00000000000000000000000000")

    assert [call["json"]["tool_name"] for call in calls] == [
        "metric_change_point_detect",
        "metric_correlate",
        "log_pattern_summary",
        "log_sample_bounded",
        "metric_baseline_compare",
        "cloud_trace_read",
        "cloud_monitoring_query",
        "managed_prometheus_query",
        "cloud_logging_query",
        "cloud_audit_log_query",
        "error_reporting_query",
        "cloud_run_read",
        "cloud_run_revision_compare",
        "cloud_asset_inventory_search",
        "cloud_build_history_read",
        "github_commit_range_read",
        "github_pr_diff_read",
        "github_workflow_run_read",
        "cloud_sql_metadata_read",
        "production_graph_read",
    ]
    assert calls[3]["json"]["arguments"]["maximum_entries"] == 7
    assert all(call["headers"] == {"Authorization": "Bearer runtime-token"} for call in calls)


def test_read_tool_boundary_refuses_missing_identity_transport_and_invalid_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOLVAN_EVIDENCE_BROKER_URL", raising=False)
    with pytest.raises(RuntimeError, match="URL is required"):
        read_tools.production_graph_read("invocation-123456", "svc", "snapshot")

    monkeypatch.setenv("SOLVAN_EVIDENCE_BROKER_URL", "https://broker.example")
    monkeypatch.setenv("SOLVAN_AGENT_KEY", "incident-supervisor")
    with pytest.raises(RuntimeError, match="approved read agent"):
        read_tools.cloud_run_read("invocation-123456", "svc")
    with pytest.raises(ValueError, match="between 1 and 100"):
        read_tools.log_sample_bounded("invocation-123456", "svc", "evidence", 0)
    with pytest.raises(ValueError, match="PR diff bounds"):
        read_tools.github_pr_diff_read("invocation-123456", "svc", "repo", 0)
    with pytest.raises(ValueError, match="check-run"):
        read_tools.github_workflow_run_read("invocation-123456", "svc", "repo", 0, "a" * 40)
