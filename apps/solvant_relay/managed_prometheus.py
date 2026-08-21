"""Closed Managed Prometheus Relay adapter; raw PromQL is never accepted."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from math import isfinite
from typing import Any
from urllib.parse import quote

from apps.solvant_relay.cloud_monitoring import _timestamp
from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.platform.google_rest import GoogleRestSession

_TEMPLATES = {
    "http_requests_total": ('sum(rate(http_requests_total{service="{service}"}[5m]))', "1"),
    "http_error_ratio": (
        'sum(rate(http_requests_total{service="{service}",code=~"5.."}[5m])) / '
        'sum(rate(http_requests_total{service="{service}"}[5m]))',
        "1",
    ),
    "http_p95_latency_ms": (
        "histogram_quantile(0.95, sum(rate("
        'http_request_duration_seconds_bucket{service="{service}"}[5m])) by (le)) * 1000',
        "ms",
    ),
}
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,61}$")
_SERVICE_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class ManagedPrometheusRelayAdapter:
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
        del maximum_pages, maximum_bytes
        required = {
            "query_template_key",
            "resource_binding_id",
            "resource_project_id",
            "service_key",
            "window_start",
            "window_end",
            "step_seconds",
            "maximum_series",
            "maximum_points",
        }
        if set(parameters) != required or maximum_calls != 1:
            raise RelayRuntimeError("Managed Prometheus request is not closed")
        key, project, service = (
            parameters["query_template_key"],
            parameters["resource_project_id"],
            parameters["service_key"],
        )
        if (
            not isinstance(key, str)
            or key not in _TEMPLATES
            or not isinstance(project, str)
            or not _PROJECT_ID.fullmatch(project)
            or not isinstance(service, str)
            or not _SERVICE_KEY.fullmatch(service)
        ):
            raise RelayRuntimeError("Managed Prometheus template or binding is invalid")
        if key not in adapter.get("registered_query_keys", []):
            raise RelayRuntimeError("Managed Prometheus template is not locally authorized")
        if adapter.get("endpoint", {}).get("host") != "monitoring.googleapis.com":
            raise RelayRuntimeError("Managed Prometheus endpoint is not locally authorized")
        start, end = (
            _timestamp(parameters["window_start"], field="window_start"),
            _timestamp(parameters["window_end"], field="window_end"),
        )
        if (
            end <= start
            or (end - start).total_seconds() > 900
            or parameters["step_seconds"] not in {30, 60, 300}
        ):
            raise RelayRuntimeError("Managed Prometheus time bounds are invalid")
        series, points = parameters["maximum_series"], parameters["maximum_points"]
        if (
            not isinstance(series, int)
            or not isinstance(points, int)
            or not 1 <= series <= 100
            or not 1 <= points <= 1000
        ):
            raise RelayRuntimeError("Managed Prometheus result bounds are invalid")
        query, unit = _TEMPLATES[key]
        response = self._session.get(
            f"https://monitoring.googleapis.com/v1/projects/{quote(project)}/location/global/prometheus/api/v1/query_range",
            params={
                "query": query.replace("{service}", service),
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": parameters["step_seconds"],
            },
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise RelayRuntimeError("Managed Prometheus response is malformed")
        data = payload.get("data")
        result = data.get("result") if isinstance(data, Mapping) else None
        if not isinstance(result, list):
            raise RelayRuntimeError("Managed Prometheus response is malformed")
        records: list[Mapping[str, Any]] = []
        for item in result[:series]:
            if not isinstance(item, Mapping):
                raise RelayRuntimeError("Managed Prometheus series is malformed")
            values = item.get("values")
            if not isinstance(values, list):
                raise RelayRuntimeError("Managed Prometheus series values are malformed")
            for point in values[:points]:
                if (
                    not isinstance(point, list)
                    or len(point) != 2
                    or isinstance(point[0], bool)
                    or isinstance(point[1], bool)
                ):
                    raise RelayRuntimeError("Managed Prometheus point is malformed")
                timestamp, value = point
                try:
                    observed_at = datetime.fromtimestamp(float(timestamp), UTC)
                    observed_value = float(value)
                except (TypeError, ValueError, OverflowError) as error:
                    raise RelayRuntimeError("Managed Prometheus point is malformed") from error
                if not isfinite(observed_value):
                    raise RelayRuntimeError("Managed Prometheus point is non-finite")
                records.append(
                    {
                        "metric_key": key,
                        "timestamp": observed_at.isoformat(),
                        "value": observed_value,
                        "unit": unit,
                        "attributes": {"service.name": service},
                    }
                )
                if len(records) >= maximum_items:
                    return tuple(records)
        return tuple(records)
