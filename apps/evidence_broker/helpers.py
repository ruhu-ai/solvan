"""Deterministic registries and resource validators for Evidence Broker reads."""

from __future__ import annotations

import json
import math
import os
import re
from datetime import UTC, datetime
from typing import Any

from solvan.persistence import ToolAuthorizationError


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required evidence broker setting {name} is missing")
    return value


def _approved_log_signature(log_view_id: str, signature_key: str) -> str:
    raw = _required("SOLVAN_LOG_SIGNATURES_JSON")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("log signature registry must be an object")
    query = value.get(f"{log_view_id}:{signature_key}")
    if not isinstance(query, str) or not query or len(query) > 2_000:
        raise ToolAuthorizationError("log signature is not approved")
    return query


def _approved_prometheus_template(template_key: str) -> dict[str, Any]:
    raw = _required("SOLVAN_PROMETHEUS_TEMPLATES_JSON")
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get(template_key), dict):
        raise ToolAuthorizationError("Prometheus query template is not approved")
    template = value[template_key]
    query = template.get("query")
    step = template.get("step_seconds")
    no_data = template.get("no_data_semantics")
    if (
        not isinstance(query, str)
        or not query
        or len(query) > 2_000
        or type(step) is not int
        or not 15 <= step <= 300
        or no_data not in {"HEALTHY", "UNKNOWN", "NOT_APPLICABLE"}
    ):
        raise ToolAuthorizationError("Prometheus query template is invalid")
    if query.count("{{service_key}}") > 1:
        raise ToolAuthorizationError("Prometheus query template has invalid substitutions")
    return {"query": query, "step_seconds": step, "no_data_semantics": no_data}


def _managed_prometheus_projection(
    payload: Any, *, query_template_key: str, no_data_semantics: str
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise RuntimeError("Managed Service for Prometheus returned an unsuccessful response")
    data = payload.get("data")
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, list) or len(result) > 1:
        raise ToolAuthorizationError("registered Prometheus query must return at most one series")
    if not result:
        return {
            "signal_kind": query_template_key,
            "points": [],
            "no_data": True,
            "no_data_semantics": no_data_semantics,
        }
    series = result[0]
    values = series.get("values") if isinstance(series, dict) else None
    if not isinstance(values, list) or len(values) > 1_000:
        raise ToolAuthorizationError("Prometheus series is malformed or exceeds 1,000 points")
    points = []
    for item in values:
        if not isinstance(item, list) or len(item) != 2:
            raise ToolAuthorizationError("Prometheus point is malformed")
        try:
            observed_at = datetime.fromtimestamp(float(item[0]), tz=UTC)
            point_value = float(item[1])
        except (TypeError, ValueError, OverflowError) as error:
            raise ToolAuthorizationError("Prometheus point is invalid") from error
        if not math.isfinite(point_value):
            raise ToolAuthorizationError("Prometheus point is not finite")
        points.append({"observed_at": observed_at.isoformat(), "value": point_value})
    return {
        "signal_kind": query_template_key,
        "points": points,
        "no_data": not points,
        "no_data_semantics": no_data_semantics,
    }


def google_resource(resource: str, project_id: str, collection: str) -> str:
    pattern = (
        rf"^projects/{re.escape(project_id)}/locations/[a-z0-9-]+/"
        rf"{collection}/[a-zA-Z0-9_-]+$"
    )
    if not re.fullmatch(pattern, resource):
        raise ToolAuthorizationError("Production Graph contains an invalid Google resource")
    return resource


def cloud_sql_resource(resource: str, project_id: str) -> str:
    pattern = rf"^projects/{re.escape(project_id)}/instances/[a-zA-Z0-9_-]+$"
    if not re.fullmatch(pattern, resource):
        raise ToolAuthorizationError("Production Graph contains an invalid Cloud SQL resource")
    return resource


def cloud_build_trigger(resource: str, project_id: str) -> tuple[str, str]:
    pattern = (
        rf"^projects/{re.escape(project_id)}/locations/([a-z0-9-]+)/"
        r"triggers/([a-zA-Z0-9_-]+)$"
    )
    match = re.fullmatch(pattern, resource)
    if match is None:
        raise ToolAuthorizationError("Production Graph contains an invalid Cloud Build trigger")
    return match.group(1), match.group(2)


def github_repository_id(resource: str) -> str:
    match = re.fullmatch(r"^github://(ghr_[0-7][0-9A-HJKMNP-TV-Z]{25})$", resource)
    if match is None:
        raise ToolAuthorizationError("Production Graph contains an invalid GitHub repository")
    return match.group(1)
