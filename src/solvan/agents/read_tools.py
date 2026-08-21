"""Typed read-only tools whose egress is governed by Agent Gateway."""

from __future__ import annotations

import os
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from solvan.agents.private_service_auth import private_service_headers


class EvidenceToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_ref: str = Field(pattern=r"^evd_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    content_ref: str
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    bounded_summary: str = Field(min_length=1, max_length=8_000)
    classification: Literal["INTERNAL", "CONFIDENTIAL_REDACTED"]
    armor_verdict_ref: str | None = None


def cloud_monitoring_query(
    invocation_id: str,
    service_id: str,
    signal_kind: Literal["HTTP_5XX_RATIO", "HTTP_P95_LATENCY", "SQL_CONNECTIONS"],
    window_start: str,
    window_end: str,
) -> dict[str, object]:
    """Read one allowlisted metric for one service and bounded RFC3339 window."""

    return _read(
        invocation_id,
        "cloud_monitoring_query",
        {
            "service_id": service_id,
            "signal_kind": signal_kind,
            "window_start": window_start,
            "window_end": window_end,
        },
    )


def managed_prometheus_query(
    invocation_id: str,
    service_id: str,
    query_template_key: str,
    window_start: str,
    window_end: str,
) -> dict[str, object]:
    """Execute one registered PromQL template; raw PromQL is never accepted."""

    return _read(
        invocation_id,
        "managed_prometheus_query",
        {
            "service_id": service_id,
            "query_template_key": query_template_key,
            "window_start": window_start,
            "window_end": window_end,
        },
    )


def metric_baseline_compare(
    invocation_id: str,
    service_id: str,
    baseline_evidence_ref: str,
    incident_evidence_ref: str,
) -> dict[str, object]:
    return _read(
        invocation_id,
        "metric_baseline_compare",
        {
            "service_id": service_id,
            "baseline_evidence_ref": baseline_evidence_ref,
            "incident_evidence_ref": incident_evidence_ref,
        },
    )


def metric_change_point_detect(
    invocation_id: str, service_id: str, evidence_ref: str
) -> dict[str, object]:
    return _read(
        invocation_id,
        "metric_change_point_detect",
        {"service_id": service_id, "evidence_ref": evidence_ref},
    )


def metric_correlate(
    invocation_id: str, service_id: str, left_evidence_ref: str, right_evidence_ref: str
) -> dict[str, object]:
    return _read(
        invocation_id,
        "metric_correlate",
        {
            "service_id": service_id,
            "left_evidence_ref": left_evidence_ref,
            "right_evidence_ref": right_evidence_ref,
        },
    )


def log_pattern_summary(
    invocation_id: str, service_id: str, evidence_ref: str
) -> dict[str, object]:
    return _read(
        invocation_id,
        "log_pattern_summary",
        {"service_id": service_id, "evidence_ref": evidence_ref},
    )


def log_sample_bounded(
    invocation_id: str, service_id: str, evidence_ref: str, maximum_entries: int = 20
) -> dict[str, object]:
    if not 1 <= maximum_entries <= 100:
        raise ValueError("maximum_entries must be between 1 and 100")
    return _read(
        invocation_id,
        "log_sample_bounded",
        {
            "service_id": service_id,
            "evidence_ref": evidence_ref,
            "maximum_entries": maximum_entries,
        },
    )


def cloud_logging_query(
    invocation_id: str,
    service_id: str,
    log_view_id: str,
    signature_key: str,
    window_start: str,
    window_end: str,
    maximum_entries: int = 100,
) -> dict[str, object]:
    """Read one registered log signature without accepting arbitrary query syntax."""

    if not 1 <= maximum_entries <= 100:
        raise ValueError("maximum_entries must be between 1 and 100")
    return _read(
        invocation_id,
        "cloud_logging_query",
        {
            "service_id": service_id,
            "log_view_id": log_view_id,
            "signature_key": signature_key,
            "window_start": window_start,
            "window_end": window_end,
            "maximum_entries": maximum_entries,
        },
    )


def cloud_audit_log_query(
    invocation_id: str,
    service_id: str,
    window_start: str,
    window_end: str,
    maximum_entries: int = 50,
) -> dict[str, object]:
    """Read Admin Activity audit entries answering what changed, by whom, and when.

    Human principals are pseudonymized; service accounts are reported exactly.
    """

    if not 1 <= maximum_entries <= 50:
        raise ValueError("maximum_entries must be between 1 and 50")
    return _read(
        invocation_id,
        "cloud_audit_log_query",
        {
            "service_id": service_id,
            "window_start": window_start,
            "window_end": window_end,
            "maximum_entries": maximum_entries,
        },
    )


def error_reporting_query(
    invocation_id: str,
    service_id: str,
    window_start: str,
    window_end: str,
    maximum_groups: int = 20,
) -> dict[str, object]:
    """Read grouped error signatures with first-seen and last-seen observations."""

    if not 1 <= maximum_groups <= 20:
        raise ValueError("maximum_groups must be between 1 and 20")
    return _read(
        invocation_id,
        "error_reporting_query",
        {
            "service_id": service_id,
            "window_start": window_start,
            "window_end": window_end,
            "maximum_groups": maximum_groups,
        },
    )


def cloud_trace_read(
    invocation_id: str,
    service_id: str,
    trace_id: str,
) -> dict[str, object]:
    """Read one trace already bound to the incident's approved service scope."""

    return _read(
        invocation_id,
        "cloud_trace_read",
        {"service_id": service_id, "trace_id": trace_id},
    )


def kubernetes_metadata_read(
    invocation_id: str,
    service_id: str,
    namespace: str,
    resource_kind: Literal["Deployment", "StatefulSet", "DaemonSet", "Pod", "Service"],
) -> dict[str, object]:
    """List metadata only in a customer-policy-approved namespace and kind."""

    return _read(
        invocation_id,
        "kubernetes_metadata_read",
        {"service_id": service_id, "namespace": namespace, "resource_kind": resource_kind},
    )


def cloud_run_read(invocation_id: str, service_id: str) -> dict[str, object]:
    """Read the approved Cloud Run service revision and traffic projection."""

    return _read(invocation_id, "cloud_run_read", {"service_id": service_id})


def cloud_run_revision_compare(
    invocation_id: str,
    service_id: str,
    before_evidence_ref: str,
    after_evidence_ref: str,
) -> dict[str, object]:
    return _read(
        invocation_id,
        "cloud_run_revision_compare",
        {
            "service_id": service_id,
            "before_evidence_ref": before_evidence_ref,
            "after_evidence_ref": after_evidence_ref,
        },
    )


def cloud_asset_inventory_search(
    invocation_id: str,
    service_id: str,
    resource_kind: Literal["CLOUD_RUN_SERVICE", "CLOUD_SQL_INSTANCE", "GCS_BUCKET"],
) -> dict[str, object]:
    """Find bounded service-related candidates for Production Graph review."""

    return _read(
        invocation_id,
        "cloud_asset_inventory_search",
        {"service_id": service_id, "resource_kind": resource_kind},
    )


def cloud_build_history_read(
    invocation_id: str,
    service_id: str,
    deployment_node_id: str,
    window_start: str,
    window_end: str,
) -> dict[str, object]:
    """Read bounded build history for one graph-bound Cloud Build trigger."""

    return _read(
        invocation_id,
        "cloud_build_history_read",
        {
            "service_id": service_id,
            "deployment_node_id": deployment_node_id,
            "window_start": window_start,
            "window_end": window_end,
        },
    )


def github_commit_range_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    base_sha: str,
    head_sha: str,
) -> dict[str, object]:
    return _read(
        invocation_id,
        "github_commit_range_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "base_sha": base_sha,
            "head_sha": head_sha,
        },
    )


def github_pr_diff_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    pull_request_number: int,
    maximum_patch_bytes: int = 200_000,
) -> dict[str, object]:
    if pull_request_number <= 0 or not 1_000 <= maximum_patch_bytes <= 500_000:
        raise ValueError("GitHub PR diff bounds are invalid")
    return _read(
        invocation_id,
        "github_pr_diff_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "pull_request_number": pull_request_number,
            "maximum_patch_bytes": maximum_patch_bytes,
        },
    )


def github_workflow_run_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    check_run_id: int,
    expected_head_sha: str,
) -> dict[str, object]:
    if check_run_id <= 0:
        raise ValueError("GitHub check-run identifier must be positive")
    return _read(
        invocation_id,
        "github_workflow_run_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "check_run_id": check_run_id,
            "expected_head_sha": expected_head_sha,
        },
    )


def github_search_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    query: str,
    search_kind: str = "issues",
    limit: int = 10,
) -> dict[str, object]:
    """Search within the bound repository, or across visible repositories.

    The query carries no scope of its own: the provider prepends the binding's
    qualifier and refuses a query that tries to name one, so this tool cannot
    reach a repository the invocation was not bound to.
    """

    if search_kind not in {"issues", "repositories"}:
        raise ValueError("GitHub search kind is not available")
    if not query.strip() or len(query) > 200 or not 1 <= limit <= 50:
        raise ValueError("GitHub search bounds are invalid")
    return _read(
        invocation_id,
        "github_search_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "query": query,
            "search_kind": search_kind,
            "limit": limit,
        },
    )


def github_issue_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    number: int,
    include_comments: bool = True,
    comment_limit: int = 30,
) -> dict[str, object]:
    """Read one issue or pull-request thread with its comments."""

    if number <= 0 or not 1 <= comment_limit <= 100:
        raise ValueError("GitHub issue read bounds are invalid")
    return _read(
        invocation_id,
        "github_issue_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "number": number,
            "include_comments": include_comments,
            "comment_limit": comment_limit,
        },
    )


def github_commit_history_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    author: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 30,
) -> dict[str, object]:
    """List recent commits, optionally by author and window.

    Distinct from `github_commit_range_read`, which needs two exact SHAs. This
    is the read for "what changed here lately", where the caller has no SHA to
    anchor on yet.
    """

    if not 1 <= limit <= 100:
        raise ValueError("GitHub commit history bounds are invalid")
    return _read(
        invocation_id,
        "github_commit_history_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "author": author,
            "since": since,
            "until": until,
            "limit": limit,
        },
    )


def github_repository_tree_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    commit_sha: str,
    path_prefix: str = "",
    maximum_files: int = 128,
    maximum_bytes: int = 1_000_000,
) -> dict[str, object]:
    """Read the repository's files at one exact commit.

    This is the read a clone would otherwise be used for. No credential, git
    remote, or working copy reaches the caller: the provider fetches the blobs,
    verifies each one reproduces its Git object ID, and returns content only.
    """

    if len(commit_sha) != 40 or any(
        character not in "0123456789abcdef" for character in commit_sha
    ):
        raise ValueError("GitHub tree read requires an exact lowercase commit SHA")
    if not 1 <= maximum_files <= 512 or not 1_000 <= maximum_bytes <= 8_000_000:
        raise ValueError("GitHub tree read bounds are invalid")
    return _read(
        invocation_id,
        "github_repository_tree_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "commit_sha": commit_sha,
            "path_prefix": path_prefix,
            "maximum_files": maximum_files,
            "maximum_bytes": maximum_bytes,
        },
    )


def github_workflow_runs_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    head_sha: str,
    limit: int = 30,
) -> dict[str, object]:
    """List the Actions runs for one exact commit.

    Distinct from `github_workflow_run_read`, which returns one check run and
    its failure annotations. This answers which workflow ran, from which file,
    and what triggered it.
    """

    if len(head_sha) != 40 or any(character not in "0123456789abcdef" for character in head_sha):
        raise ValueError("GitHub workflow-run read requires an exact lowercase commit SHA")
    if not 1 <= limit <= 100:
        raise ValueError("GitHub workflow-run bounds are invalid")
    return _read(
        invocation_id,
        "github_workflow_runs_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "head_sha": head_sha,
            "limit": limit,
        },
    )


def github_deployments_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    environment: str | None = None,
    sha: str | None = None,
    limit: int = 20,
) -> dict[str, object]:
    """List recent deployments and the state each one last reported."""

    if not 1 <= limit <= 50:
        raise ValueError("GitHub deployment bounds are invalid")
    if sha is not None and (
        len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha)
    ):
        raise ValueError("GitHub deployment filter requires an exact lowercase commit SHA")
    return _read(
        invocation_id,
        "github_deployments_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "environment": environment,
            "sha": sha,
            "limit": limit,
        },
    )


def github_discussions_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    limit: int = 20,
) -> dict[str, object]:
    """List recent repository discussions, titles and categories only."""

    if not 1 <= limit <= 50:
        raise ValueError("GitHub discussion bounds are invalid")
    return _read(
        invocation_id,
        "github_discussions_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "limit": limit,
        },
    )


def github_merge_queue_read(
    invocation_id: str,
    service_id: str,
    repository_node_id: str,
    branch: str,
    limit: int = 20,
) -> dict[str, object]:
    """List what is waiting to merge into one branch, and why.

    A pull request that passed every check and still has not landed is usually
    queued behind something, which no check-run read explains.
    """

    if not 1 <= limit <= 50 or not 1 <= len(branch) <= 255:
        raise ValueError("GitHub merge-queue bounds are invalid")
    return _read(
        invocation_id,
        "github_merge_queue_read",
        {
            "service_id": service_id,
            "repository_node_id": repository_node_id,
            "branch": branch,
            "limit": limit,
        },
    )


def cloud_sql_metadata_read(
    invocation_id: str, service_id: str, database_node_id: str
) -> dict[str, object]:
    """Read capacity/configuration metadata without opening a database data session."""

    return _read(
        invocation_id,
        "cloud_sql_metadata_read",
        {"service_id": service_id, "database_node_id": database_node_id},
    )


def production_graph_read(
    invocation_id: str, service_id: str, graph_snapshot_id: str
) -> dict[str, object]:
    """Read neighbors from the exact immutable Production Graph snapshot."""

    return _read(
        invocation_id,
        "production_graph_read",
        {"service_id": service_id, "graph_snapshot_id": graph_snapshot_id},
    )


def _read(invocation_id: str, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
    base_url = os.environ.get("SOLVAN_EVIDENCE_BROKER_URL")
    if not base_url:
        raise RuntimeError("SOLVAN_EVIDENCE_BROKER_URL is required")
    agent_key = os.environ.get("SOLVAN_AGENT_KEY")
    if agent_key not in {"evidence-agent", "infrastructure-agent"}:
        raise RuntimeError("SOLVAN_AGENT_KEY is not an approved read agent")
    if not base_url.startswith("https://") and os.environ.get("SOLVAN_ENVIRONMENT") != "local":
        raise RuntimeError("evidence broker must use HTTPS outside the local harness")
    response = httpx.post(
        f"{base_url.rstrip('/')}/internal/v1/evidence/{agent_key}:query",
        headers=private_service_headers(audience_variable="SOLVAN_EVIDENCE_AUDIENCE"),
        json={
            "schema_version": 1,
            "invocation_id": invocation_id,
            "tool_name": tool_name,
            "arguments": arguments,
        },
        timeout=httpx.Timeout(5.0, read=30.0),
    )
    response.raise_for_status()
    return EvidenceToolResult.model_validate(response.json()).model_dump(mode="json")
