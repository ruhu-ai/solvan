"""Strict input contracts for the governed Evidence Broker."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

_SERVICE_ID = r"^svc_[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_NODE_ID = r"^pgn_[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_SNAPSHOT_ID = r"^pgs_[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_TRACE_ID = r"^[0-9a-f]{32}$"
_EVIDENCE_ID = r"^evd_[0-7][0-9A-HJKMNP-TV-Z]{25}$"


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    invocation_id: str = Field(min_length=16, max_length=512)
    tool_name: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]


class WindowArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_id: str = Field(pattern=_SERVICE_ID)
    window_start: datetime
    window_end: datetime

    def checked_window(self) -> tuple[datetime, datetime]:
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("evidence windows must be timezone-aware")
        if not self.window_start < self.window_end:
            raise ValueError("evidence window must have positive duration")
        if self.window_end - self.window_start > timedelta(minutes=15):
            raise ValueError("evidence window exceeds 15 minutes")
        if self.window_end > datetime.now(UTC) + timedelta(minutes=1):
            raise ValueError("evidence window ends in the future")
        return self.window_start, self.window_end


class MonitoringArgs(WindowArgs):
    signal_kind: Literal["HTTP_5XX_RATIO", "HTTP_P95_LATENCY", "SQL_CONNECTIONS"]


class ManagedPrometheusArgs(WindowArgs):
    query_template_key: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_.-]+$")


class LoggingArgs(WindowArgs):
    log_view_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    signature_key: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    maximum_entries: int = Field(ge=1, le=100)


class LongWindowArgs(BaseModel):
    """Change-history reads look further back than telemetry reads.

    Audit and grouped-error volume is orders of magnitude lower than log or
    metric volume, and 'what changed' is inherently a longer-horizon question
    than 'what is happening now'. The entry ceiling, not the window, is the
    blast-radius control here.
    """

    model_config = ConfigDict(extra="forbid")

    service_id: str = Field(pattern=_SERVICE_ID)
    window_start: datetime
    window_end: datetime

    def checked_window(self) -> tuple[datetime, datetime]:
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("evidence windows must be timezone-aware")
        if not self.window_start < self.window_end:
            raise ValueError("evidence window must have positive duration")
        if self.window_end - self.window_start > timedelta(hours=24):
            raise ValueError("change-history window exceeds 24 hours")
        if self.window_end > datetime.now(UTC) + timedelta(minutes=1):
            raise ValueError("evidence window ends in the future")
        return self.window_start, self.window_end


class AuditLogArgs(LongWindowArgs):
    maximum_entries: int = Field(ge=1, le=50)


class ErrorReportingArgs(LongWindowArgs):
    maximum_groups: int = Field(ge=1, le=20)


class TraceArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_id: str = Field(pattern=_SERVICE_ID)
    trace_id: str = Field(pattern=_TRACE_ID)


class KubernetesMetadataArgs(BaseModel):
    """A metadata-only list confined again by the customer local policy."""

    model_config = ConfigDict(extra="forbid")

    service_id: str = Field(pattern=_SERVICE_ID)
    namespace: str = Field(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$",
    )
    resource_kind: Literal["Deployment", "StatefulSet", "DaemonSet", "Pod", "Service"]


class ServiceArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_id: str = Field(pattern=_SERVICE_ID)


class SqlArgs(ServiceArgs):
    database_node_id: str = Field(pattern=_NODE_ID)


class GraphArgs(ServiceArgs):
    graph_snapshot_id: str = Field(pattern=_SNAPSHOT_ID)


class EvidenceOneArgs(ServiceArgs):
    evidence_ref: str = Field(pattern=_EVIDENCE_ID)


class BaselineArgs(ServiceArgs):
    baseline_evidence_ref: str = Field(pattern=_EVIDENCE_ID)
    incident_evidence_ref: str = Field(pattern=_EVIDENCE_ID)


class CorrelationArgs(ServiceArgs):
    left_evidence_ref: str = Field(pattern=_EVIDENCE_ID)
    right_evidence_ref: str = Field(pattern=_EVIDENCE_ID)


class LogSampleArgs(EvidenceOneArgs):
    maximum_entries: int = Field(ge=1, le=100)


class RevisionCompareArgs(ServiceArgs):
    before_evidence_ref: str = Field(pattern=_EVIDENCE_ID)
    after_evidence_ref: str = Field(pattern=_EVIDENCE_ID)


class AssetInventoryArgs(ServiceArgs):
    resource_kind: Literal["CLOUD_RUN_SERVICE", "CLOUD_SQL_INSTANCE", "GCS_BUCKET"]


class CloudBuildHistoryArgs(LongWindowArgs):
    deployment_node_id: str = Field(pattern=_NODE_ID)


class GitHubRepositoryArgs(ServiceArgs):
    repository_node_id: str = Field(pattern=_NODE_ID)


class GitHubCommitRangeArgs(GitHubRepositoryArgs):
    base_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class GitHubPullRequestDiffArgs(GitHubRepositoryArgs):
    pull_request_number: int = Field(gt=0)
    maximum_patch_bytes: int = Field(ge=1_000, le=500_000)


class GitHubWorkflowRunArgs(GitHubRepositoryArgs):
    check_run_id: int = Field(gt=0)
    expected_head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class GitHubSearchArgs(GitHubRepositoryArgs):
    query: str = Field(min_length=1, max_length=200)
    search_kind: str = Field(default="issues", pattern=r"^(issues|repositories)$")
    limit: int = Field(default=10, ge=1, le=50)


class GitHubIssueArgs(GitHubRepositoryArgs):
    number: int = Field(gt=0)
    include_comments: bool = True
    comment_limit: int = Field(default=30, ge=1, le=100)


class GitHubRepositoryTreeArgs(GitHubRepositoryArgs):
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    path_prefix: str = Field(default="", max_length=500)
    maximum_files: int = Field(default=128, ge=1, le=512)
    maximum_bytes: int = Field(default=1_000_000, ge=1_000, le=8_000_000)


class GitHubWorkflowRunsArgs(GitHubRepositoryArgs):
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    limit: int = Field(default=30, ge=1, le=100)


class GitHubDeploymentsArgs(GitHubRepositoryArgs):
    environment: str | None = Field(default=None, min_length=1, max_length=255)
    sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    limit: int = Field(default=20, ge=1, le=50)


class GitHubDiscussionsArgs(GitHubRepositoryArgs):
    limit: int = Field(default=20, ge=1, le=50)


class GitHubMergeQueueArgs(GitHubRepositoryArgs):
    branch: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$")
    limit: int = Field(default=20, ge=1, le=50)


class GitHubCommitHistoryArgs(GitHubRepositoryArgs):
    author: str | None = Field(default=None, min_length=1, max_length=100)
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=30, ge=1, le=100)


_ARGUMENT_MODELS: dict[str, type[BaseModel]] = {
    "cloud_monitoring_query": MonitoringArgs,
    "managed_prometheus_query": ManagedPrometheusArgs,
    "cloud_logging_query": LoggingArgs,
    "cloud_audit_log_query": AuditLogArgs,
    "error_reporting_query": ErrorReportingArgs,
    "cloud_trace_read": TraceArgs,
    "kubernetes_metadata_read": KubernetesMetadataArgs,
    "cloud_run_read": ServiceArgs,
    "cloud_sql_metadata_read": SqlArgs,
    "production_graph_read": GraphArgs,
    "metric_baseline_compare": BaselineArgs,
    "metric_change_point_detect": EvidenceOneArgs,
    "metric_correlate": CorrelationArgs,
    "log_pattern_summary": EvidenceOneArgs,
    "log_sample_bounded": LogSampleArgs,
    "cloud_run_revision_compare": RevisionCompareArgs,
    "cloud_asset_inventory_search": AssetInventoryArgs,
    "cloud_build_history_read": CloudBuildHistoryArgs,
    "github_commit_range_read": GitHubCommitRangeArgs,
    "github_pr_diff_read": GitHubPullRequestDiffArgs,
    "github_workflow_run_read": GitHubWorkflowRunArgs,
    "github_search_read": GitHubSearchArgs,
    "github_issue_read": GitHubIssueArgs,
    "github_commit_history_read": GitHubCommitHistoryArgs,
    "github_repository_tree_read": GitHubRepositoryTreeArgs,
    "github_workflow_runs_read": GitHubWorkflowRunsArgs,
    "github_deployments_read": GitHubDeploymentsArgs,
    "github_discussions_read": GitHubDiscussionsArgs,
    "github_merge_queue_read": GitHubMergeQueueArgs,
}
