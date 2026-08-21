"""The closed Cloud Monitoring adapter used by customer-resident Relay v1."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from math import isfinite
from typing import Any

from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.platform.google_rest import GoogleRestSession

_METRICS: dict[str, tuple[str, str, str]] = {
    "http_5xx_ratio": (
        "run.googleapis.com/request_count",
        "cloud_run_revision",
        "service_name",
    ),
    "request_count": ("run.googleapis.com/request_count", "cloud_run_revision", "service_name"),
    "p95_latency_ms": (
        "run.googleapis.com/request_latencies",
        "cloud_run_revision",
        "service_name",
    ),
    "db_connection_utilization": (
        "cloudsql.googleapis.com/database/postgresql/num_backends",
        "cloudsql_database",
        "database_id",
    ),
}
_NUMBER = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")


class CloudMonitoringRelayAdapter:
    """Reads only registered metric shapes and projects no raw provider fields."""

    def __init__(self, *, session: GoogleRestSession) -> None:
        self._session = session

    def read(
        self,
        *,
        adapter: Mapping[str, Any],
        parameters: Mapping[str, Any],
        maximum_pages: int,
        maximum_items: int,
        maximum_bytes: int,
        maximum_calls: int,
    ) -> tuple[Mapping[str, Any], ...]:
        del maximum_pages
        minimum_calls = 2 if parameters.get("metric_key") == "http_5xx_ratio" else 1
        if maximum_calls < minimum_calls:
            raise RelayRuntimeError("Cloud Monitoring call budget is exhausted")
        required = {
            "metric_key",
            "resource_binding_id",
            "resource_project_id",
            "resource_kind",
            "resource_name",
            "window_start",
            "window_end",
            "alignment_seconds",
            "maximum_points",
        }
        if set(parameters) != required:
            raise RelayRuntimeError("Cloud Monitoring parameters are not an exact closed shape")
        metric_key = parameters["metric_key"]
        resource_project_id = parameters["resource_project_id"]
        resource_kind = parameters["resource_kind"]
        resource_name = parameters["resource_name"]
        if not all(
            isinstance(value, str)
            for value in (metric_key, resource_project_id, resource_kind, resource_name)
        ):
            raise RelayRuntimeError(
                "Cloud Monitoring parameters contain an invalid resource selector"
            )
        if metric_key not in _METRICS:
            raise RelayRuntimeError("Cloud Monitoring metric key is not implemented by Relay v1")
        metric_type, expected_resource_type, resource_label = _METRICS[metric_key]
        expected_kind = (
            "CLOUD_SQL_INSTANCE"
            if expected_resource_type == "cloudsql_database"
            else "CLOUD_RUN_SERVICE"
        )
        if resource_kind != expected_kind:
            raise RelayRuntimeError("Cloud Monitoring resource kind does not match metric key")
        project_id = adapter.get("metrics_scope_project_id")
        endpoint = adapter.get("endpoint")
        if not isinstance(project_id, str) or not isinstance(endpoint, Mapping):
            raise RelayRuntimeError("Cloud Monitoring local adapter policy is malformed")
        if endpoint.get("host") != "monitoring.googleapis.com":
            raise RelayRuntimeError("Cloud Monitoring endpoint is not locally authorized")
        start = _timestamp(parameters["window_start"], field="window_start")
        end = _timestamp(parameters["window_end"], field="window_end")
        if end < start or (end - start).total_seconds() > 3600:
            raise RelayRuntimeError("Cloud Monitoring window is outside the closed bound")
        alignment = parameters["alignment_seconds"]
        points = parameters["maximum_points"]
        if alignment not in (30, 60, 300) or not isinstance(points, int) or not 1 <= points <= 1000:
            raise RelayRuntimeError("Cloud Monitoring aggregation bounds are invalid")

        def collect(response_code_class: str | None = None) -> tuple[Mapping[str, Any], ...]:
            clauses = [
                f'metric.type="{metric_type}"',
                f'resource.type="{expected_resource_type}"',
                f'resource.label."project_id"="{resource_project_id}"',
                f'resource.label."{resource_label}"="{resource_name}"',
            ]
            if response_code_class is not None:
                clauses.append(f'metric.label."response_code_class"="{response_code_class}"')
            response = self._session.get(
                f"https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries",
                params={
                    "filter": " AND ".join(clauses),
                    "interval.startTime": start.isoformat(),
                    "interval.endTime": end.isoformat(),
                    "aggregation.alignmentPeriod": f"{alignment}s",
                    "aggregation.perSeriesAligner": (
                        "ALIGN_DELTA"
                        if metric_key in {"request_count", "http_5xx_ratio"}
                        else "ALIGN_PERCENTILE_95"
                    ),
                    "aggregation.crossSeriesReducer": (
                        "REDUCE_SUM"
                        if metric_key in {"request_count", "http_5xx_ratio"}
                        else "REDUCE_MAX"
                    ),
                    "aggregation.groupByFields": ["resource.label.project_id", "resource.type"],
                    "view": "FULL",
                    "pageSize": min(points, 1000),
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, Mapping):
                raise RelayRuntimeError("Cloud Monitoring response is not an object")
            return _project(
                payload,
                metric_key=metric_key,
                resource_project_id=resource_project_id,
                maximum_items=maximum_items,
                maximum_bytes=maximum_bytes,
            )

        total = collect()
        if metric_key != "http_5xx_ratio":
            return total
        failures = collect("500")
        return _ratio(total=total, failures=failures, maximum_bytes=maximum_bytes)


def _timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise RelayRuntimeError(f"{field} is not an RFC-3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RelayRuntimeError(f"{field} is not an RFC-3339 timestamp") from error
    if parsed.tzinfo is None:
        raise RelayRuntimeError(f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _project(
    payload: Mapping[str, Any],
    *,
    metric_key: str,
    resource_project_id: str,
    maximum_items: int,
    maximum_bytes: int,
) -> tuple[Mapping[str, Any], ...]:
    series = payload.get("timeSeries")
    if not isinstance(series, list):
        raise RelayRuntimeError("Cloud Monitoring response timeSeries is malformed")
    records: list[Mapping[str, Any]] = []
    for item in series:
        if not isinstance(item, Mapping):
            raise RelayRuntimeError("Cloud Monitoring response contains an invalid series")
        resource = item.get("resource")
        labels = resource.get("labels") if isinstance(resource, Mapping) else None
        if not isinstance(labels, Mapping) or labels.get("project_id") != resource_project_id:
            raise RelayRuntimeError(
                "Cloud Monitoring response attribution does not match bound project"
            )
        points = item.get("points")
        if not isinstance(points, list):
            raise RelayRuntimeError("Cloud Monitoring series points are malformed")
        for point in points:
            if not isinstance(point, Mapping):
                raise RelayRuntimeError("Cloud Monitoring point is malformed")
            interval = point.get("interval")
            end_time = interval.get("endTime") if isinstance(interval, Mapping) else None
            values = point.get("value")
            raw = (
                values.get("doubleValue", values.get("int64Value"))
                if isinstance(values, Mapping)
                else None
            )
            if isinstance(raw, str) and _NUMBER.fullmatch(raw):
                raw = float(raw)
            if (
                not isinstance(raw, int | float)
                or isinstance(raw, bool)
                or not isfinite(float(raw))
            ):
                raise RelayRuntimeError("Cloud Monitoring point value is not finite")
            records.append(
                {
                    "metric_key": metric_key,
                    "timestamp": _timestamp(end_time, field="point.endTime").isoformat(),
                    "value": float(raw),
                    "unit": "1",
                    "attributes": {},
                }
            )
            if len(records) > maximum_items:
                raise RelayRuntimeError("Cloud Monitoring response exceeds item bound")
    estimated = len(str(records).encode("utf-8"))
    if estimated > maximum_bytes:
        raise RelayRuntimeError("Cloud Monitoring response exceeds byte bound")
    return tuple(records)


def _ratio(
    *,
    total: tuple[Mapping[str, Any], ...],
    failures: tuple[Mapping[str, Any], ...],
    maximum_bytes: int,
) -> tuple[Mapping[str, Any], ...]:
    """Return a bounded timestamp-aligned 5xx ratio without raw series egress."""

    failed_by_timestamp = {str(row["timestamp"]): float(row["value"]) for row in failures}
    records: list[Mapping[str, Any]] = []
    for row in total:
        timestamp = str(row["timestamp"])
        denominator = float(row["value"])
        if denominator < 0:
            raise RelayRuntimeError("Cloud Monitoring request-count delta is negative")
        numerator = failed_by_timestamp.get(timestamp, 0.0)
        if numerator < 0 or numerator > denominator:
            raise RelayRuntimeError("Cloud Monitoring 5xx attribution is invalid")
        records.append(
            {
                "metric_key": "http_5xx_ratio",
                "timestamp": timestamp,
                "value": 0.0 if denominator == 0 else numerator / denominator,
                "unit": "1",
                "attributes": {},
            }
        )
    if len(str(records).encode("utf-8")) > maximum_bytes:
        raise RelayRuntimeError("Cloud Monitoring ratio exceeds byte bound")
    return tuple(records)
