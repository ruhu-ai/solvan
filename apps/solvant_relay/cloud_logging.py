"""Closed Cloud Logging Relay adapter; callers never supply a log filter."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from apps.solvant_relay.cloud_monitoring import _timestamp
from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.platform.google_rest import GoogleRestSession

_SIGNATURES = {
    "service_errors": 'severity>="ERROR"',
    "revision_errors": 'severity>="ERROR" AND resource.type="cloud_run_revision"',
    "database_connection_errors": 'severity>="ERROR" AND ("connection" OR "database")',
}
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,61}$")
_SERVICE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class CloudLoggingRelayAdapter:
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
            "signature_key",
            "resource_binding_id",
            "resource_project_id",
            "service_name",
            "window_start",
            "window_end",
            "maximum_entries",
        }
        if set(parameters) != required or maximum_calls < 1:
            raise RelayRuntimeError("Cloud Logging request is not closed")
        key, project, service = (
            parameters["signature_key"],
            parameters["resource_project_id"],
            parameters["service_name"],
        )
        maximum = parameters["maximum_entries"]
        if (
            not isinstance(key, str)
            or key not in _SIGNATURES
            or not isinstance(project, str)
            or not _PROJECT_ID.fullmatch(project)
            or not isinstance(service, str)
            or not _SERVICE_NAME.fullmatch(service)
            or key not in adapter.get("approved_log_signatures", [])
        ):
            raise RelayRuntimeError("Cloud Logging signature is not locally authorized")
        if (
            not isinstance(maximum, int)
            or not 1 <= maximum <= min(500, maximum_items)
            or adapter.get("endpoint", {}).get("host") != "logging.googleapis.com"
        ):
            raise RelayRuntimeError("Cloud Logging bounds or endpoint are invalid")
        start, end = (
            _timestamp(parameters["window_start"], field="window_start"),
            _timestamp(parameters["window_end"], field="window_end"),
        )
        if end <= start or (end - start).total_seconds() > 1800:
            raise RelayRuntimeError("Cloud Logging time bound is invalid")
        filter_value = (
            f'timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}" '
            f'AND resource.labels.service_name="{service}" AND ({_SIGNATURES[key]})'
        )
        response = self._session.post(
            "https://logging.googleapis.com/v2/entries:list",
            json={
                "resourceNames": [f"projects/{project}"],
                "filter": filter_value,
                "orderBy": "timestamp desc",
                "pageSize": maximum,
            },
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise RelayRuntimeError("Cloud Logging response is malformed")
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            raise RelayRuntimeError("Cloud Logging response is malformed")
        records: list[Mapping[str, Any]] = []
        for item in entries[:maximum]:
            if not isinstance(item, Mapping) or not isinstance(item.get("timestamp"), str):
                raise RelayRuntimeError("Cloud Logging entry is malformed")
            records.append(
                {
                    "kind": "LOG_EVENT",
                    "timestamp": item["timestamp"],
                    "severity": str(item.get("severity", "ERROR")),
                    "message_template_key": key,
                    "safe_parameters": {},
                    "attributes": {"service.name": service},
                }
            )
        return tuple(records)
