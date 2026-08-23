"""Bounded provider reader used by the governed Evidence Broker."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ValidationError

from apps.evidence_broker.contracts import (
    AssetInventoryArgs,
    AuditLogArgs,
    BaselineArgs,
    CloudBuildHistoryArgs,
    CorrelationArgs,
    ErrorReportingArgs,
    EvidenceOneArgs,
    GitHubCommitHistoryArgs,
    GitHubCommitRangeArgs,
    GitHubDeploymentsArgs,
    GitHubDiscussionsArgs,
    GitHubIssueArgs,
    GitHubMergeQueueArgs,
    GitHubPullRequestDiffArgs,
    GitHubRepositoryArgs,
    GitHubRepositoryTreeArgs,
    GitHubSearchArgs,
    GitHubWorkflowRunArgs,
    GitHubWorkflowRunsArgs,
    GraphArgs,
    LoggingArgs,
    LogSampleArgs,
    ManagedPrometheusArgs,
    MonitoringArgs,
    RevisionCompareArgs,
    ServiceArgs,
    SqlArgs,
    TraceArgs,
)
from apps.evidence_broker.helpers import (
    _approved_log_signature,
    _approved_prometheus_template,
    _managed_prometheus_projection,
    _required,
    cloud_build_trigger,
    cloud_sql_resource,
    github_repository_id,
    google_resource,
    monitoring_projection,
)
from apps.evidence_broker.projections import (
    error_reporting_period,
    object_payload,
    request_id,
    sanitize_audit_entry,
    sanitize_error_group,
    sanitize_log,
    sanitize_trace_span,
)
from solvan.application.detection import Comparator, DetectionRule
from solvan.application.operational_compute import LogEvidence, MetricSeries, RevisionProjection
from solvan.application.operational_compute import (
    cloud_run_revision_compare as compare_cloud_run_revisions,
)
from solvan.application.operational_compute import log_pattern_summary as summarize_log_patterns
from solvan.application.operational_compute import log_sample_bounded as sample_logs
from solvan.application.operational_compute import (
    metric_baseline_compare as compare_metric_baseline,
)
from solvan.application.operational_compute import (
    metric_change_point_detect as detect_metric_change_points,
)
from solvan.application.operational_compute import metric_correlate as correlate_metrics
from solvan.persistence import PostgresEvidenceToolStore, ToolAuthorizationError
from solvan.persistence.evidence_types import EvidenceToolReservation
from solvan.platform.cloud_monitoring import CloudMonitoringReader
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.github_evidence import (
    GitHubEvidenceProviderClient,
    GitHubEvidenceProviderConfiguration,
)
from solvan.platform.github_release import GoogleIdentityTokenProvider
from solvan.platform.google_rest import GoogleRestSession


class TypedEvidenceReader:
    """Provider boundary that returns only bounded, sanitized projections.

    Two sessions, because they carry different authority. `object_session` is
    the runtime identity and reaches Solvan's own evidence objects only.
    `provider_session` mints the customer reader identity recorded on the
    frozen connection revision, and is resolved at the moment a customer estate
    is actually addressed so a read that never leaves Solvan cannot be refused
    for want of a direct-GCP binding.
    """

    def __init__(
        self,
        *,
        provider_session: Callable[[], GoogleRestSession],
        object_session: GoogleRestSession,
        store: PostgresEvidenceToolStore,
        bucket: str,
    ) -> None:
        self._provider_session = provider_session
        self._object_session = object_session
        self._customer: GoogleRestSession | None = None
        self._store = store
        self._bucket = bucket

    def _customer_session(self) -> GoogleRestSession:
        if self._customer is None:
            self._customer = self._provider_session()
        return self._customer

    def read(
        self, reservation: EvidenceToolReservation, arguments: BaseModel
    ) -> tuple[dict[str, Any], tuple[str, ...], datetime, datetime, str]:
        now = datetime.now(UTC)
        if isinstance(arguments, GitHubRepositoryArgs):
            node = self._store.graph_node(
                reservation=reservation,
                node_id=arguments.repository_node_id,
                node_kind="REPOSITORY",
            )
            # The binding comes from the Production Graph node the reservation
            # already authorized, so it is the estate's own answer to "which
            # repository", not a caller's claim. Comparing it against one
            # configured repository and refusing the rest served exactly one
            # repository per deployment however many were connected.
            repository_id = github_repository_id(node.resource_ref)
            github_config = GitHubEvidenceProviderConfiguration(
                base_url=_required("SOLVAN_GITHUB_PROVIDER_URL"),
                audience=_required("SOLVAN_GITHUB_PROVIDER_AUDIENCE"),
                repository_id=repository_id,
            )
            with httpx.Client() as client:
                provider = GitHubEvidenceProviderClient(
                    config=github_config,
                    client=client,
                    token_provider=GoogleIdentityTokenProvider(),
                    repository_id=repository_id,
                )
                if isinstance(arguments, GitHubCommitRangeArgs):
                    value = provider.commit_range(
                        base_sha=arguments.base_sha, head_sha=arguments.head_sha
                    )
                elif isinstance(arguments, GitHubPullRequestDiffArgs):
                    value = provider.pull_request_diff(
                        pull_request_number=arguments.pull_request_number,
                        maximum_patch_bytes=arguments.maximum_patch_bytes,
                    )
                elif isinstance(arguments, GitHubWorkflowRunArgs):
                    value = provider.workflow_run(
                        check_run_id=arguments.check_run_id,
                        expected_head_sha=arguments.expected_head_sha,
                    )
                elif isinstance(arguments, GitHubSearchArgs):
                    value = provider.search(
                        query=arguments.query,
                        search_kind=arguments.search_kind,
                        limit=arguments.limit,
                    )
                elif isinstance(arguments, GitHubIssueArgs):
                    value = provider.issue(
                        number=arguments.number,
                        include_comments=arguments.include_comments,
                        comment_limit=arguments.comment_limit,
                    )
                elif isinstance(arguments, GitHubRepositoryTreeArgs):
                    value = provider.repository_tree(
                        commit_sha=arguments.commit_sha,
                        path_prefix=arguments.path_prefix,
                        maximum_files=arguments.maximum_files,
                        maximum_bytes=arguments.maximum_bytes,
                    )
                elif isinstance(arguments, GitHubWorkflowRunsArgs):
                    value = provider.workflow_runs(
                        head_sha=arguments.head_sha, limit=arguments.limit
                    )
                elif isinstance(arguments, GitHubDeploymentsArgs):
                    value = provider.deployments(
                        environment=arguments.environment,
                        sha=arguments.sha,
                        limit=arguments.limit,
                    )
                elif isinstance(arguments, GitHubDiscussionsArgs):
                    value = provider.discussions(limit=arguments.limit)
                elif isinstance(arguments, GitHubMergeQueueArgs):
                    value = provider.merge_queue(branch=arguments.branch, limit=arguments.limit)
                elif isinstance(arguments, GitHubCommitHistoryArgs):
                    value = provider.commit_history(
                        author=arguments.author,
                        since=None if arguments.since is None else arguments.since.isoformat(),
                        until=None if arguments.until is None else arguments.until.isoformat(),
                        limit=arguments.limit,
                    )
                else:
                    raise ToolAuthorizationError("unsupported GitHub read contract")
            return value, ("github-provider-bound-read",), now, now, "GITHUB"
        if isinstance(arguments, AssetInventoryArgs):
            asset_type = {
                "CLOUD_RUN_SERVICE": "run.googleapis.com/Service",
                "CLOUD_SQL_INSTANCE": "sqladmin.googleapis.com/Instance",
                "GCS_BUCKET": "storage.googleapis.com/Bucket",
            }[arguments.resource_kind]
            response = self._customer_session().get(
                "https://cloudasset.googleapis.com/v1/"
                f"projects/{quote(reservation.service_project_id)}:searchAllResources",
                params={
                    "assetTypes": asset_type,
                    "query": reservation.service_key,
                    "pageSize": 20,
                    "orderBy": "name",
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud Asset Inventory")
            raw_results = payload.get("results", [])
            if not isinstance(raw_results, list) or len(raw_results) > 20:
                raise ToolAuthorizationError("Asset Inventory result exceeds the bounded limit")
            assets = []
            for item in raw_results:
                if not isinstance(item, dict):
                    continue
                assets.append(
                    {
                        "name": str(item.get("name", ""))[:1_000],
                        "asset_type": str(item.get("assetType", ""))[:200],
                        "display_name": str(item.get("displayName", ""))[:256],
                        "location": str(item.get("location", ""))[:128],
                        "state": str(item.get("state", ""))[:64],
                    }
                )
            return (
                {
                    "resource_kind": arguments.resource_kind,
                    "service_key": reservation.service_key,
                    "candidates": assets,
                    "candidate_only": True,
                },
                (request_id(response),),
                now,
                now,
                "ASSET_INVENTORY",
            )
        if isinstance(arguments, CloudBuildHistoryArgs):
            start, end = arguments.checked_window()
            node = self._store.graph_node(
                reservation=reservation,
                node_id=arguments.deployment_node_id,
                node_kind="DEPLOYMENT",
            )
            # Specification 13 §4.2: the read addresses the project of the node
            # it is reading about. A deployment pipeline in a different project
            # than its service is ordinary, not exceptional.
            location, trigger_id = cloud_build_trigger(node.resource_ref, node.external_project_id)
            response = self._customer_session().get(
                "https://cloudbuild.googleapis.com/v1/"
                f"projects/{quote(node.external_project_id)}/locations/{quote(location)}/builds",
                params={
                    "filter": (
                        f'buildTriggerId="{trigger_id}" AND '
                        f'createTime>="{start.isoformat()}" AND '
                        f'createTime<="{end.isoformat()}"'
                    ),
                    "pageSize": 20,
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud Build")
            raw_builds = payload.get("builds", [])
            if not isinstance(raw_builds, list) or len(raw_builds) > 20:
                raise ToolAuthorizationError("Cloud Build result exceeds the bounded limit")
            builds = []
            for item in raw_builds:
                if not isinstance(item, dict):
                    continue
                images = item.get("images", [])
                builds.append(
                    {
                        "id": str(item.get("id", ""))[:128],
                        "status": str(item.get("status", "UNKNOWN"))[:32],
                        "create_time": item.get("createTime"),
                        "start_time": item.get("startTime"),
                        "finish_time": item.get("finishTime"),
                        "images": [str(value)[:1_000] for value in images[:20]]
                        if isinstance(images, list)
                        else [],
                        "log_url": str(item.get("logUrl", ""))[:2_000],
                    }
                )
            return (
                {"trigger_id": trigger_id, "builds": builds},
                (request_id(response),),
                start,
                end,
                "CLOUD_BUILD",
            )
        if isinstance(arguments, ManagedPrometheusArgs):
            start, end = arguments.checked_window()
            template = _approved_prometheus_template(arguments.query_template_key)
            response = self._customer_session().get(
                "https://monitoring.googleapis.com/v1/projects/"
                f"{quote(reservation.service_project_id)}/location/global/prometheus/api/v1/query_range",
                params={
                    "query": template["query"].replace("{{service_key}}", reservation.service_key),
                    "start": start.timestamp(),
                    "end": end.timestamp(),
                    "step": template["step_seconds"],
                },
                timeout=30,
            )
            response.raise_for_status()
            value = _managed_prometheus_projection(
                response.json(),
                query_template_key=arguments.query_template_key,
                no_data_semantics=template["no_data_semantics"],
            )
            return value, (request_id(response),), start, end, "MANAGED_PROMETHEUS"
        if isinstance(arguments, MonitoringArgs):
            start, end = arguments.checked_window()
            resource_name = reservation.platform_resource.rsplit("/", 1)[-1]
            read_project = reservation.service_project_id
            if arguments.signal_kind == "SQL_CONNECTIONS":
                graph = self._store.graph_slice(reservation=reservation)
                databases = [node for node in graph.nodes if node["node_kind"] == "DATABASE"]
                if len(databases) != 1 or not databases[0].get("resource_ref"):
                    raise ToolAuthorizationError("incident graph has no unique database resource")
                # Specification 13 §4.2: the resource and the project it lives
                # in come from the same node. Taking the resource from the
                # database node and the project from the service would address a
                # database in another project at the service's project, and
                # return nothing while looking like an answer.
                database = databases[0]
                read_project = str(database["external_project_id"])
                sql_resource = cloud_sql_resource(str(database["resource_ref"]), read_project)
                resource_name = f"{read_project}:{sql_resource.rsplit('/', 1)[-1]}"
            rule = DetectionRule(
                rule_id="broker-read",
                version=1,
                service_id=reservation.service_id,
                service_key=reservation.service_key,
                graph_snapshot_id=reservation.graph_snapshot_id,
                incident_class="evidence-read",
                signal_kind=arguments.signal_kind,
                query={
                    "gcp_project_id": read_project,
                    "resource_name": resource_name,
                },
                evaluation_interval_ms=25_000,
                comparator=Comparator.GT,
                threshold=0,
                sustained_windows=1,
                severity="SEV4",
                deduplication_dimension="broker-read",
                action_budget=1,
                repeated_action_limit=1,
            )
            observation = CloudMonitoringReader(self._customer_session()).observe(
                rule, window_start=start, window_end=end
            )
            # The aligned buckets ride with the reduction, in the shape the
            # Managed Prometheus path already emits and `MetricSeries`
            # already validates. Cloud Monitoring was the only metric source
            # that produced a scalar with no series behind it, which is why
            # correlation and baseline tooling could not read its evidence and
            # why nothing could draw the window it described.
            return (
                monitoring_projection(arguments.signal_kind, observation),
                observation.request_ids,
                start,
                end,
                "CLOUD_MONITORING",
            )
        if isinstance(arguments, LoggingArgs):
            start, end = arguments.checked_window()
            config = _approved_log_signature(arguments.log_view_id, arguments.signature_key)
            response = self._customer_session().post(
                "https://logging.googleapis.com/v2/entries:list",
                json={
                    "resourceNames": [f"projects/{reservation.service_project_id}"],
                    "filter": (
                        f'timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}" '
                        f"AND ({config})"
                    ),
                    "orderBy": "timestamp desc",
                    "pageSize": arguments.maximum_entries,
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud Logging")
            entries = payload.get("entries", [])
            if not isinstance(entries, list):
                raise RuntimeError("Cloud Logging entries is not a list")
            normalized_entries = []
            for entry in entries[:100]:
                normalized = sanitize_log(entry)
                normalized["signature_key"] = arguments.signature_key
                normalized_entries.append(normalized)
            log_projection = {"entries": normalized_entries}
            return log_projection, (request_id(response),), start, end, "CLOUD_LOGGING"
        if isinstance(arguments, AuditLogArgs):
            start, end = arguments.checked_window()
            resource = google_resource(
                reservation.platform_resource, reservation.service_project_id, "services"
            )
            response = self._customer_session().post(
                "https://logging.googleapis.com/v2/entries:list",
                json={
                    "resourceNames": [f"projects/{reservation.service_project_id}"],
                    "filter": (
                        f'logName="projects/{reservation.service_project_id}/logs/'
                        f'cloudaudit.googleapis.com%2Factivity" '
                        f'AND timestamp>="{start.isoformat()}" '
                        f'AND timestamp<="{end.isoformat()}" '
                        f'AND protoPayload.resourceName:"{resource.rsplit("/", 1)[-1]}"'
                    ),
                    "orderBy": "timestamp desc",
                    "pageSize": arguments.maximum_entries,
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud Audit Logs")
            entries = payload.get("entries", [])
            if not isinstance(entries, list):
                raise RuntimeError("Cloud Audit Logs entries is not a list")
            audit_projection = {
                "changes": [
                    sanitize_audit_entry(entry) for entry in entries[: arguments.maximum_entries]
                ]
            }
            return audit_projection, (request_id(response),), start, end, "CLOUD_AUDIT_LOG"
        if isinstance(arguments, ErrorReportingArgs):
            start, end = arguments.checked_window()
            resource = google_resource(
                reservation.platform_resource, reservation.service_project_id, "services"
            )
            response = self._customer_session().get(
                "https://clouderrorreporting.googleapis.com/v1beta1/"
                f"projects/{quote(reservation.service_project_id)}/groupStats",
                params={
                    "timeRange.period": error_reporting_period(end - start),
                    "serviceFilter.service": resource.rsplit("/", 1)[-1],
                    "pageSize": arguments.maximum_groups,
                    "order": "COUNT_DESC",
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Error Reporting")
            stats = payload.get("errorGroupStats", [])
            if not isinstance(stats, list):
                raise RuntimeError("Error Reporting errorGroupStats is not a list")
            error_projection = {
                "signatures": [
                    sanitize_error_group(item) for item in stats[: arguments.maximum_groups]
                ]
            }
            return error_projection, (request_id(response),), start, end, "ERROR_REPORTING"
        if isinstance(arguments, TraceArgs):
            self._store.require_discovered_trace(
                reservation=reservation, trace_id=arguments.trace_id
            )
            response = self._customer_session().get(
                f"https://cloudtrace.googleapis.com/v1/projects/"
                f"{quote(reservation.service_project_id)}/traces/{quote(arguments.trace_id)}",
                timeout=30,
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud Trace")
            spans = payload.get("spans", [])
            if not isinstance(spans, list):
                raise RuntimeError("Cloud Trace spans is not a list")
            trace_projection: dict[str, Any] = {
                "projectId": payload.get("projectId"),
                "traceId": payload.get("traceId"),
                "spans": [sanitize_trace_span(span) for span in spans[:100]],
            }
            return trace_projection, (request_id(response),), now, now, "CLOUD_TRACE"
        if isinstance(arguments, GraphArgs):
            if arguments.graph_snapshot_id != reservation.graph_snapshot_id:
                raise ToolAuthorizationError("requested graph is not the incident snapshot")
            graph = self._store.graph_slice(reservation=reservation)
            return (
                {
                    "snapshot_id": reservation.graph_snapshot_id,
                    "nodes": graph.nodes,
                    "edges": graph.edges,
                },
                ("postgres-production-graph",),
                now,
                now,
                "PRODUCTION_GRAPH",
            )
        if isinstance(arguments, SqlArgs):
            node = self._store.graph_node(
                reservation=reservation,
                node_id=arguments.database_node_id,
                node_kind="DATABASE",
            )
            # Specification 13 §4.2: the database node names the project it
            # lives in, which need not be the service's.
            resource = cloud_sql_resource(node.resource_ref, node.external_project_id)
            response = self._customer_session().get(
                f"https://sqladmin.googleapis.com/sql/v1beta4/{resource}", timeout=30
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud SQL Admin")
            raw_settings = payload.get("settings")
            settings: dict[str, Any] = raw_settings if isinstance(raw_settings, dict) else {}
            sql_projection: dict[str, Any] = {
                "name": payload.get("name"),
                "region": payload.get("region"),
                "state": payload.get("state"),
                "databaseVersion": payload.get("databaseVersion"),
                "settings": {
                    key: settings.get(key)
                    for key in ("tier", "availabilityType", "dataDiskSizeGb", "activationPolicy")
                },
            }
            return sql_projection, (request_id(response),), now, now, "CLOUD_SQL_METADATA"
        if isinstance(arguments, BaselineArgs):
            baseline = self._metric_series(reservation, arguments.baseline_evidence_ref)
            incident = self._metric_series(reservation, arguments.incident_evidence_ref)
            baseline_result = compare_metric_baseline(baseline=baseline, incident=incident)
            return baseline_result.model_dump(mode="json"), (), now, now, "DERIVED_METRIC"
        if isinstance(arguments, CorrelationArgs):
            left = self._metric_series(reservation, arguments.left_evidence_ref)
            right = self._metric_series(reservation, arguments.right_evidence_ref)
            correlation_result = correlate_metrics(left=left, right=right)
            return correlation_result.model_dump(mode="json"), (), now, now, "DERIVED_METRIC"
        if isinstance(arguments, LogSampleArgs):
            logs = self._log_evidence(reservation, arguments.evidence_ref)
            sample_result = sample_logs(evidence=logs, maximum_entries=arguments.maximum_entries)
            return sample_result.model_dump(mode="json"), (), now, now, "DERIVED_LOGS"
        if isinstance(arguments, EvidenceOneArgs):
            if reservation.tool_name == "metric_change_point_detect":
                series = self._metric_series(reservation, arguments.evidence_ref)
                change_result = detect_metric_change_points(series=series)
                return change_result.model_dump(mode="json"), (), now, now, "DERIVED_METRIC"
            if reservation.tool_name == "log_pattern_summary":
                logs = self._log_evidence(reservation, arguments.evidence_ref)
                summary_result = summarize_log_patterns(evidence=logs)
                return summary_result.model_dump(mode="json"), (), now, now, "DERIVED_LOGS"
            raise ToolAuthorizationError("evidence input is not valid for this Tool")
        if isinstance(arguments, RevisionCompareArgs):
            before = self._revision_projection(reservation, arguments.before_evidence_ref)
            after = self._revision_projection(reservation, arguments.after_evidence_ref)
            revision_result = compare_cloud_run_revisions(before=before, after=after)
            return (
                revision_result.model_dump(mode="json"),
                (),
                now,
                now,
                "DERIVED_DEPLOYMENT_METADATA",
            )
        if isinstance(arguments, ServiceArgs):
            resource = google_resource(
                reservation.platform_resource, reservation.service_project_id, "services"
            )
            response = self._customer_session().get(
                f"https://run.googleapis.com/v2/{resource}", timeout=30
            )
            response.raise_for_status()
            payload = object_payload(response.json(), "Cloud Run")
            traffic = payload.get("trafficStatuses", [])
            if not isinstance(traffic, list):
                traffic = []
            run_projection: dict[str, Any] = {
                "name": payload.get("name"),
                "uid": payload.get("uid"),
                "generation": payload.get("generation"),
                # When the observed revision arrived. Cloud Run returns it on
                # every read and it was being discarded, so nothing recorded
                # the instant a service last changed -- the one annotation an
                # incident axis most needs beside its own detection.
                "updateTime": payload.get("updateTime"),
                "createTime": payload.get("createTime"),
                "latestReadyRevision": payload.get("latestReadyRevision"),
                "trafficStatuses": [
                    {key: item.get(key) for key in ("type", "revision", "percent", "tag")}
                    for item in traffic[:20]
                    if isinstance(item, dict)
                ],
            }
            return run_projection, (request_id(response),), now, now, "CLOUD_RUN_METADATA"
        raise ToolAuthorizationError("unsupported evidence argument type")

    def _document(self, reservation: EvidenceToolReservation, evidence_ref: str) -> dict[str, Any]:
        stored = self._store.load_incident_evidence(
            reservation=reservation, evidence_id=evidence_ref
        )
        document = GcsEvidenceReader(
            allowed_buckets=frozenset({self._bucket}), session=self._object_session
        ).get_json(uri=stored.content_ref, expected_hash=stored.content_hash)
        if document.get("schema_version") != 1 or not isinstance(document.get("value"), dict):
            raise ToolAuthorizationError("input evidence has an unsupported document shape")
        return document

    def _metric_series(
        self, reservation: EvidenceToolReservation, evidence_ref: str
    ) -> MetricSeries:
        value = self._document(reservation, evidence_ref)["value"]
        if not isinstance(value, dict):
            raise ToolAuthorizationError("input evidence is not a metric series")
        try:
            return MetricSeries.model_validate(
                {
                    "evidence_ref": evidence_ref,
                    "signal_kind": value.get("signal_kind"),
                    "points": value.get("points"),
                }
            )
        except ValidationError as error:
            raise ToolAuthorizationError("input evidence is not a bounded metric series") from error

    def _log_evidence(self, reservation: EvidenceToolReservation, evidence_ref: str) -> LogEvidence:
        value = self._document(reservation, evidence_ref)["value"]
        raw_entries = value.get("entries") if isinstance(value, dict) else None
        if not isinstance(raw_entries, list):
            raise ToolAuthorizationError("input evidence is not a bounded log projection")
        entries = []
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            message = item.get("textPayload") or item.get("jsonPayload") or "[NO_MESSAGE]"
            entries.append(
                {
                    "observed_at": item.get("timestamp"),
                    "signature_key": item.get("signature_key"),
                    "normalized_message": json.dumps(message, sort_keys=True, default=str)[:1_000],
                }
            )
        try:
            return LogEvidence.model_validate({"evidence_ref": evidence_ref, "entries": entries})
        except ValidationError as error:
            raise ToolAuthorizationError(
                "input evidence contains invalid normalized logs"
            ) from error

    def _revision_projection(
        self, reservation: EvidenceToolReservation, evidence_ref: str
    ) -> RevisionProjection:
        value = self._document(reservation, evidence_ref)["value"]
        if not isinstance(value, dict) or not value.get("latestReadyRevision"):
            raise ToolAuthorizationError("input evidence is not a Cloud Run revision projection")
        fields = {
            key: value.get(key)
            for key in ("generation", "latestReadyRevision")
            if isinstance(value.get(key), str | int | float | bool) or value.get(key) is None
        }
        return RevisionProjection(
            evidence_ref=evidence_ref,
            revision_ref=str(value["latestReadyRevision"]),
            fields=fields,
        )
