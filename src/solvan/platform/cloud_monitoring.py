"""Typed Cloud Monitoring queries for detector policy records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import Any

from solvan.application.detection import DetectionRule
from solvan.platform.google_rest import GoogleRestSession


class ResourceAttributionError(RuntimeError):
    """A response did not come from the project the read addressed.

    Specification 13 §4.2. Either the filter was under-specified or the metrics
    scope widened after the rule was authored. Both are conditions an operator
    must see, so neither is absorbed into a value.
    """


@dataclass(frozen=True, slots=True)
class ObservedResource:
    """The monitored resource the provider reported, as it reported it."""

    project_id: str
    resource_type: str
    labels: tuple[tuple[str, str], ...]

    def as_provenance(self) -> dict[str, str]:
        return {
            "project_id": self.project_id,
            "resource_type": self.resource_type,
            **dict(self.labels),
        }


@dataclass(frozen=True, slots=True)
class MetricObservation:
    value: float
    request_ids: tuple[str, ...]
    resource: ObservedResource


class CloudMonitoringReader:
    def __init__(self, session: GoogleRestSession) -> None:
        self._session = session

    def observe(
        self, rule: DetectionRule, *, window_start: datetime, window_end: datetime
    ) -> MetricObservation:
        project_id = _query_string(rule, "gcp_project_id")
        resource_name = _query_string(rule, "resource_name")
        if rule.signal_kind == "HTTP_5XX_RATIO":
            total, total_request, total_resource = self._cloud_run_count(
                project_id, resource_name, window_start, window_end, response_class=None
            )
            failures, failure_request, failure_resource = self._cloud_run_count(
                project_id, resource_name, window_start, window_end, response_class="5xx"
            )
            if total_resource.project_id != failure_resource.project_id:
                raise ResourceAttributionError(
                    "the ratio's numerator and denominator came from different projects"
                )
            value = 0.0 if total <= 0 else failures / total
            return MetricObservation(value, (total_request, failure_request), total_resource)
        if rule.signal_kind == "HTTP_P95_LATENCY":
            value, request_id, resource = self._single_metric(
                project_id=project_id,
                metric_type="run.googleapis.com/request_latencies",
                resource_type="cloud_run_revision",
                resource_label="service_name",
                resource_name=resource_name,
                aligner="ALIGN_PERCENTILE_95",
                reducer="REDUCE_MAX",
                window_start=window_start,
                window_end=window_end,
            )
            return MetricObservation(value, (request_id,), resource)
        if rule.signal_kind == "SQL_CONNECTIONS":
            value, request_id, resource = self._single_metric(
                project_id=project_id,
                metric_type="cloudsql.googleapis.com/database/postgresql/num_backends",
                resource_type="cloudsql_database",
                resource_label="database_id",
                resource_name=resource_name,
                aligner="ALIGN_MAX",
                reducer="REDUCE_MAX",
                window_start=window_start,
                window_end=window_end,
            )
            return MetricObservation(value, (request_id,), resource)
        raise ValueError(f"unsupported typed detection signal {rule.signal_kind}")

    def _cloud_run_count(
        self,
        project_id: str,
        service_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        response_class: str | None,
    ) -> tuple[float, str, ObservedResource]:
        extra = (
            ""
            if response_class is None
            else f' AND metric.label."response_code_class"="{response_class}"'
        )
        return self._request(
            project_id=project_id,
            metric_filter=(
                'metric.type="run.googleapis.com/request_count" '
                'AND resource.type="cloud_run_revision" '
                f'AND resource.label."project_id"="{project_id}" '
                f'AND resource.label."service_name"="{service_name}"{extra}'
            ),
            aligner="ALIGN_DELTA",
            reducer="REDUCE_SUM",
            window_start=window_start,
            window_end=window_end,
        )

    def _single_metric(
        self,
        *,
        project_id: str,
        metric_type: str,
        resource_type: str,
        resource_label: str,
        resource_name: str,
        aligner: str,
        reducer: str,
        window_start: datetime,
        window_end: datetime,
    ) -> tuple[float, str, ObservedResource]:
        return self._request(
            project_id=project_id,
            metric_filter=(
                f'metric.type="{metric_type}" AND resource.type="{resource_type}" '
                f'AND resource.label."project_id"="{project_id}" '
                f'AND resource.label."{resource_label}"="{resource_name}"'
            ),
            aligner=aligner,
            reducer=reducer,
            window_start=window_start,
            window_end=window_end,
        )

    def _request(
        self,
        *,
        project_id: str,
        metric_filter: str,
        aligner: str,
        reducer: str,
        window_start: datetime,
        window_end: datetime,
    ) -> tuple[float, str, ObservedResource]:
        response = self._session.get(
            f"https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries",
            params={
                "filter": metric_filter,
                "interval.startTime": window_start.isoformat(),
                "interval.endTime": window_end.isoformat(),
                "aggregation.alignmentPeriod": "60s",
                "aggregation.perSeriesAligner": aligner,
                "aggregation.crossSeriesReducer": reducer,
                # Specification 13 §4.2. Without a grouping field the reducer
                # collapses every matching series into one and drops the labels
                # that say where the number came from. Grouping by project keeps
                # the attribution in the response so it can be verified rather
                # than assumed.
                "aggregation.groupByFields": [
                    "resource.label.project_id",
                    "resource.type",
                ],
                "view": "FULL",
                "pageSize": 100,
            },
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("Cloud Monitoring response is not an object")
        values, resource = _projected_series(payload, requested_project=project_id)
        value = sum(values) if reducer == "REDUCE_SUM" else max(values, default=0.0)
        if not isfinite(value):
            raise RuntimeError("Cloud Monitoring returned a non-finite value")
        request_id = response.headers.get("x-request-id", "monitoring-request-id-unavailable")
        return value, request_id, resource


def _query_string(rule: DetectionRule, key: str) -> str:
    value = rule.query.get(key)
    if not isinstance(value, str) or not value or any(character in value for character in '"\n\r'):
        raise ValueError(f"detection query requires safe string {key}")
    return value


def _projected_series(
    payload: dict[str, Any], *, requested_project: str
) -> tuple[tuple[float, ...], ObservedResource]:
    """Project points and the resource that produced them.

    Specification 13 §4.2. A series carries the monitored resource that produced
    it. Reducing across series from more than one project yields a number that
    describes no real service, so this refuses instead of summing.
    """
    result: list[float] = []
    observed: dict[str, ObservedResource] = {}
    series = payload.get("timeSeries", [])
    if not isinstance(series, list):
        raise RuntimeError("Cloud Monitoring timeSeries is not a list")
    for item in series:
        if not isinstance(item, dict):
            continue
        resource = _observed_resource(item)
        if resource is not None:
            observed[resource.project_id] = resource
        points = item.get("points", [])
        if not isinstance(points, list):
            continue
        for point in points:
            value = point.get("value", {}) if isinstance(point, dict) else {}
            if not isinstance(value, dict):
                continue
            raw = value.get("doubleValue", value.get("int64Value"))
            if raw is not None:
                result.append(float(raw))
    if len(observed) > 1:
        raise ResourceAttributionError(
            "Cloud Monitoring returned series from projects "
            f"{sorted(observed)}; the filter or the metrics scope is wider than "
            "the rule assumes"
        )
    if observed and requested_project not in observed:
        raise ResourceAttributionError(
            f"Cloud Monitoring returned project {next(iter(observed))} for a read "
            f"addressed to {requested_project}"
        )
    # An empty response is no-data, not a violation. It is attributed to the
    # project the read addressed, because that is the only project it could
    # have read.
    resource = observed.get(requested_project, ObservedResource(requested_project, "", ()))
    return tuple(result), resource


def _observed_resource(item: dict[str, Any]) -> ObservedResource | None:
    resource = item.get("resource")
    if not isinstance(resource, dict):
        return None
    labels = resource.get("labels")
    if not isinstance(labels, dict):
        return None
    project_id = labels.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        return None
    typed = {
        key: value
        for key, value in sorted(labels.items())
        if isinstance(key, str) and isinstance(value, str) and key != "project_id"
    }
    resource_type = resource.get("type")
    return ObservedResource(
        project_id,
        resource_type if isinstance(resource_type, str) else "",
        tuple(typed.items()),
    )
