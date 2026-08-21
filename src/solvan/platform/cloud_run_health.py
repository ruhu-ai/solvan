"""Closed Cloud Monitoring reads for registered Cloud Run release health."""

from __future__ import annotations

import re
from datetime import datetime
from math import isfinite
from typing import Any

from solvan.application.release_authority import ReleaseHealthSignalKind
from solvan.application.release_verification import HealthSignalMeasurement
from solvan.platform.google_rest import GoogleRestSession

_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
_SERVICE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")


class CloudRunHealthError(ValueError):
    pass


class CloudRunHealthReader:
    def __init__(self, *, session: GoogleRestSession, project_id: str, service_name: str) -> None:
        if _PROJECT.fullmatch(project_id) is None or _SERVICE.fullmatch(service_name) is None:
            raise CloudRunHealthError("Cloud Run health target is invalid")
        self._session = session
        self._project = project_id
        self._service = service_name

    def observe(
        self,
        signal_kind: ReleaseHealthSignalKind | str,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> HealthSignalMeasurement:
        try:
            signal_kind = ReleaseHealthSignalKind(signal_kind)
        except ValueError as error:
            raise CloudRunHealthError("release health signal is unsupported") from error
        if (
            window_start.tzinfo is None
            or window_end.tzinfo is None
            or not window_start < window_end
            or (window_end - window_start).total_seconds() > 3600
        ):
            raise CloudRunHealthError("release health window is invalid")
        if signal_kind is ReleaseHealthSignalKind.HTTP_5XX_RATIO:
            total, total_points, total_request = self._query(
                metric_type="run.googleapis.com/request_count",
                aligner="ALIGN_DELTA",
                reducer="REDUCE_SUM",
                window_start=window_start,
                window_end=window_end,
                response_class=None,
            )
            failed, failed_points, failed_request = self._query(
                metric_type="run.googleapis.com/request_count",
                aligner="ALIGN_DELTA",
                reducer="REDUCE_SUM",
                window_start=window_start,
                window_end=window_end,
                response_class="5xx",
            )
            return HealthSignalMeasurement(
                signal_kind=signal_kind,
                value=0.0 if total <= 0 else failed / total,
                point_count=min(total_points, failed_points),
                request_ids=(total_request, failed_request),
            )
        if signal_kind is ReleaseHealthSignalKind.HTTP_P95_LATENCY_MS:
            value, points, request_id = self._query(
                metric_type="run.googleapis.com/request_latencies",
                aligner="ALIGN_PERCENTILE_95",
                reducer="REDUCE_MAX",
                window_start=window_start,
                window_end=window_end,
                response_class=None,
            )
            return HealthSignalMeasurement(
                signal_kind=signal_kind,
                value=value * 1000.0,
                point_count=points,
                request_ids=(request_id,),
            )
        raise CloudRunHealthError("release health signal is unsupported")

    def _query(
        self,
        *,
        metric_type: str,
        aligner: str,
        reducer: str,
        window_start: datetime,
        window_end: datetime,
        response_class: str | None,
    ) -> tuple[float, int, str]:
        response_clause = (
            ""
            if response_class is None
            else f' AND metric.label."response_code_class"="{response_class}"'
        )
        response = self._session.get(
            f"https://monitoring.googleapis.com/v3/projects/{self._project}/timeSeries",
            params={
                "filter": (
                    f'metric.type="{metric_type}" AND resource.type="cloud_run_revision" '
                    f'AND resource.label."project_id"="{self._project}" '
                    f'AND resource.label."service_name"="{self._service}"{response_clause}'
                ),
                "interval.startTime": window_start.isoformat(),
                "interval.endTime": window_end.isoformat(),
                "aggregation.alignmentPeriod": "60s",
                "aggregation.perSeriesAligner": aligner,
                "aggregation.crossSeriesReducer": reducer,
                "aggregation.groupByFields": [
                    "resource.label.project_id",
                    "resource.label.service_name",
                ],
                "view": "FULL",
                "pageSize": 100,
            },
            timeout=30,
        )
        response.raise_for_status()
        body: Any = response.json()
        if not isinstance(body, dict) or body.get("nextPageToken"):
            raise CloudRunHealthError("Cloud Monitoring health response is incomplete")
        series = body.get("timeSeries")
        if not isinstance(series, list):
            raise CloudRunHealthError("Cloud Monitoring health series are malformed")
        values: list[float] = []
        for item in series:
            if not isinstance(item, dict):
                raise CloudRunHealthError("Cloud Monitoring health series is malformed")
            resource = item.get("resource")
            labels = resource.get("labels") if isinstance(resource, dict) else None
            if not isinstance(labels, dict) or (
                labels.get("project_id") != self._project
                or labels.get("service_name") != self._service
            ):
                raise CloudRunHealthError("Cloud Monitoring returned another health target")
            points = item.get("points")
            if not isinstance(points, list):
                raise CloudRunHealthError("Cloud Monitoring health points are malformed")
            for point in points:
                value = point.get("value") if isinstance(point, dict) else None
                raw = (
                    value.get("doubleValue", value.get("int64Value"))
                    if isinstance(value, dict)
                    else None
                )
                if raw is None:
                    raise CloudRunHealthError("Cloud Monitoring health point has no scalar")
                parsed = float(raw)
                if not isfinite(parsed):
                    raise CloudRunHealthError("Cloud Monitoring health point is non-finite")
                values.append(parsed)
                if len(values) > 10_000:
                    raise CloudRunHealthError("Cloud Monitoring health response is oversized")
        aggregate = sum(values) if reducer == "REDUCE_SUM" else max(values, default=0.0)
        request_id = response.headers.get("x-request-id")
        return aggregate, len(values), request_id if request_id else "request-id-unavailable"
