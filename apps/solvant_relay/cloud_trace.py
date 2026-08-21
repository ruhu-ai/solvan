"""Closed Cloud Trace adapter for one incident-bound trace identifier."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from apps.solvant_relay.cloud_monitoring import _timestamp
from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.platform.google_rest import GoogleRestSession


class CloudTraceRelayAdapter:
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
            "trace_id",
            "resource_binding_id",
            "resource_project_id",
            "service_name",
            "maximum_spans",
        }
        if set(parameters) != required or maximum_calls < 1:
            raise RelayRuntimeError("Cloud Trace request is not closed")
        trace_id = parameters["trace_id"]
        project = parameters["resource_project_id"]
        service = parameters["service_name"]
        maximum = parameters["maximum_spans"]
        if (
            not isinstance(trace_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", trace_id) is None
            or not isinstance(project, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{4,61}", project) is None
            or not isinstance(service, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", service) is None
            or not isinstance(maximum, int)
            or not 1 <= maximum <= min(200, maximum_items)
        ):
            raise RelayRuntimeError("Cloud Trace parameters are invalid")
        if adapter.get("endpoint", {}).get("host") != "cloudtrace.googleapis.com":
            raise RelayRuntimeError("Cloud Trace endpoint is not locally authorized")
        response = self._session.get(
            f"https://cloudtrace.googleapis.com/v1/projects/{quote(project)}/traces/{quote(trace_id)}",
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        spans = (
            payload.get("spans")
            if isinstance(payload, Mapping) and payload.get("traceId") == trace_id
            else None
        )
        if not isinstance(spans, list):
            raise RelayRuntimeError("Cloud Trace response is malformed")
        records: list[Mapping[str, Any]] = []
        for span in spans[:maximum]:
            if not isinstance(span, Mapping) or not all(
                isinstance(span.get(key), str) for key in ("spanId", "startTime", "endTime")
            ):
                raise RelayRuntimeError("Cloud Trace span is malformed")
            labels = span.get("labels", {})
            if not isinstance(labels, Mapping):
                raise RelayRuntimeError("Cloud Trace span labels are malformed")
            duration = (
                _timestamp(span["endTime"], field="span end")
                - _timestamp(span["startTime"], field="span start")
            ).total_seconds() * 1000
            if duration < 0:
                raise RelayRuntimeError("Cloud Trace span duration is invalid")
            records.append(
                {
                    "kind": "TRACE_SPAN",
                    "trace_id": trace_id,
                    "span_id": span["spanId"].lower(),
                    "name_key": "incident_trace_span",
                    "start_time": span["startTime"],
                    "duration_ms": duration,
                    "status": "ERROR" if labels.get("error") in {True, "true"} else "OK",
                    "attributes": {"service.name": service},
                }
            )
        return tuple(records)
