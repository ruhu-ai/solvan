"""Closed, local redaction for the first Solvant Relay evidence projection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]


class RedactionError(ValueError):
    """Provider data cannot be safely represented in the Relay envelope."""


_SECRET_PATTERN = re.compile(
    r"(?:api[_-]?key|authorization|bearer\s+|password|secret|token|private[_-]?key)", re.I
)
_EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_MAX_RECORDS = 1000


def _schema() -> dict[str, Any]:
    path = (
        Path(__file__).resolve().parents[2]
        / "specs"
        / "artifacts"
        / "relay-evidence-envelope.schema.json"
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):  # pragma: no cover - artifact harness owns this
        raise RuntimeError("Relay evidence-envelope schema is invalid")
    return value


def _safe_text(value: str, *, field: str) -> str:
    if len(value) > 256 or _SECRET_PATTERN.search(value) or _EMAIL_PATTERN.search(value):
        raise RedactionError(f"{field} contains unredacted sensitive content")
    return value


def _timestamp(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise RedactionError(f"{field} is not an RFC-3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RedactionError(f"{field} is not an RFC-3339 timestamp") from error
    if parsed.tzinfo is None:
        raise RedactionError(f"{field} is not timezone-aware")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def metric_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Project one Cloud Monitoring point; raw provider payloads are rejected."""

    expected = {"metric_key", "timestamp", "value", "unit", "attributes"}
    if set(raw) != expected:
        raise RedactionError("metric projection contains unapproved provider fields")
    attributes = raw["attributes"]
    if not isinstance(attributes, Mapping):
        raise RedactionError("metric attributes are not an object")
    safe_attributes: dict[str, Any] = {}
    for key, value in attributes.items():
        if key not in {
            "service.name",
            "deployment.environment",
            "cloud.region",
            "cloud.availability_zone",
            "http.route",
            "http.response.status_code",
            "db.system",
            "k8s.deployment.name",
        }:
            raise RedactionError("metric attribute key is not approved")
        if isinstance(value, str):
            safe_attributes[key] = _safe_text(value, field=f"attribute {key}")
        elif key == "http.response.status_code" and isinstance(value, int):
            safe_attributes[key] = value
        else:
            raise RedactionError("metric attribute value is not safe")
    value = raw["value"]
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise RedactionError("metric value is not numeric")
    metric_key = raw["metric_key"]
    unit = raw["unit"]
    if not isinstance(metric_key, str) or not isinstance(unit, str):
        raise RedactionError("metric key or unit is invalid")
    return {
        "kind": "METRIC_POINT",
        "metric_key": _safe_text(metric_key, field="metric key"),
        "timestamp": _timestamp(raw["timestamp"], field="metric timestamp"),
        "value": value,
        "unit": _safe_text(unit, field="metric unit"),
        "attributes": safe_attributes,
    }


def _safe_attributes(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RedactionError("record attributes are not an object")
    approved = {
        "service.name",
        "deployment.environment",
        "cloud.region",
        "cloud.availability_zone",
        "http.route",
        "http.response.status_code",
        "db.system",
        "k8s.deployment.name",
        "k8s.namespace.name",
        "k8s.resource.kind",
        "k8s.resource.name",
    }
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key not in approved:
            raise RedactionError("record attribute key is not approved")
        if isinstance(item, str):
            result[key] = _safe_text(item, field=f"attribute {key}")
        elif key == "http.response.status_code" and isinstance(item, int):
            result[key] = item
        else:
            raise RedactionError("record attribute value is not safe")
    return result


def relay_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a typed projection before it crosses the Relay boundary.

    Each adapter constructs one of these intentionally small shapes.  Raw
    provider objects cannot be smuggled through by adding an unknown key.
    """

    kind = raw.get("kind")
    # Cloud Monitoring v1 predates explicit record discriminators. Keep its
    # closed six-field projection compatible while all later adapters carry a
    # discriminator from the outset.
    if kind is None:
        return metric_record(raw)
    if kind == "METRIC_POINT":
        return metric_record({key: value for key, value in raw.items() if key != "kind"})
    if kind == "LOG_EVENT":
        expected = {
            "kind",
            "timestamp",
            "severity",
            "message_template_key",
            "safe_parameters",
            "attributes",
        }
        if set(raw) != expected or raw["severity"] not in {"WARNING", "ERROR", "CRITICAL"}:
            raise RedactionError("log projection has an invalid shape")
        parameters = raw["safe_parameters"]
        if not isinstance(parameters, Mapping) or len(parameters) > 16:
            raise RedactionError("log projection parameters are invalid")
        safe_parameters = {
            _safe_text(str(key), field="log parameter key"): _safe_text(
                value, field="log parameter"
            )
            if isinstance(value, str)
            else value
            for key, value in parameters.items()
        }
        if not all(
            isinstance(value, str | int | float | bool) or value is None
            for value in safe_parameters.values()
        ):
            raise RedactionError("log projection parameter is not scalar")
        return {
            "kind": kind,
            "timestamp": _timestamp(raw["timestamp"], field="log timestamp"),
            "severity": raw["severity"],
            "message_template_key": _safe_text(
                str(raw["message_template_key"]), field="message template key"
            ),
            "safe_parameters": safe_parameters,
            "attributes": _safe_attributes(raw["attributes"]),
        }
    if kind == "TRACE_SPAN":
        expected = {
            "kind",
            "trace_id",
            "span_id",
            "name_key",
            "start_time",
            "duration_ms",
            "status",
            "attributes",
        }
        if (
            set(raw) != expected
            or not re.fullmatch(r"[0-9a-f]{32}", str(raw["trace_id"]))
            or not re.fullmatch(r"[0-9a-f]{16}", str(raw["span_id"]))
        ):
            raise RedactionError("trace projection has an invalid identity")
        if raw["status"] not in {"UNSET", "OK", "ERROR"} or not isinstance(
            raw["duration_ms"], int | float
        ):
            raise RedactionError("trace projection has an invalid status")
        return {
            "kind": kind,
            "trace_id": raw["trace_id"],
            "span_id": raw["span_id"],
            "name_key": _safe_text(str(raw["name_key"]), field="trace name key"),
            "start_time": _timestamp(raw["start_time"], field="trace start time"),
            "duration_ms": raw["duration_ms"],
            "status": raw["status"],
            "attributes": _safe_attributes(raw["attributes"]),
        }
    if kind == "KUBERNETES_METADATA":
        expected = {
            "kind",
            "namespace",
            "resource_kind",
            "resource_name",
            "created_at",
            "labels",
            "attributes",
        }
        if set(raw) != expected or raw["resource_kind"] not in {
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "Pod",
            "Service",
        }:
            raise RedactionError("Kubernetes projection has an invalid shape")
        labels = raw["labels"]
        if not isinstance(labels, Mapping) or len(labels) > 16:
            raise RedactionError("Kubernetes projection labels are invalid")
        return {
            "kind": kind,
            "namespace": _safe_text(str(raw["namespace"]), field="namespace"),
            "resource_kind": raw["resource_kind"],
            "resource_name": _safe_text(str(raw["resource_name"]), field="resource name"),
            "created_at": _timestamp(raw["created_at"], field="resource creation time"),
            "labels": {
                _safe_text(str(key), field="label key"): _safe_text(str(value), field="label value")
                for key, value in labels.items()
            },
            "attributes": _safe_attributes(raw["attributes"]),
        }
    raise RedactionError("record kind is not an approved Relay projection")


def evidence_envelope(
    *,
    collection_job_id: str,
    job_digest: str,
    adapter_key: str,
    adapter_revision: str,
    operation: str,
    resource_binding_id: str,
    resource_binding_hash: str,
    window_start: datetime | None,
    window_end: datetime | None,
    classification: str,
    residency_region: str,
    redaction_revision: str,
    records: Sequence[Mapping[str, Any]],
    observed_at: datetime,
) -> tuple[dict[str, Any], str, str]:
    """Return validated, canonical envelope bytes plus content/manifest hashes."""

    if len(records) > _MAX_RECORDS:
        raise RedactionError("evidence exceeds the record ceiling")
    if observed_at.tzinfo is None:
        raise RedactionError("observed_at must be timezone-aware")
    envelope: dict[str, Any] = {
        "schema_version": 1,
        "collection_job_id": collection_job_id,
        "job_digest": job_digest,
        "adapter_key": adapter_key,
        "adapter_revision": adapter_revision,
        "operation": operation,
        "resource_binding_id": resource_binding_id,
        "resource_binding_hash": resource_binding_hash,
        "window_start": None
        if window_start is None
        else _timestamp(window_start.isoformat(), field="window_start"),
        "window_end": None
        if window_end is None
        else _timestamp(window_end.isoformat(), field="window_end"),
        "observed_at": _timestamp(observed_at.isoformat(), field="observed_at"),
        "classification": classification,
        "residency_region": _safe_text(residency_region, field="residency region"),
        "redaction_revision": _safe_text(redaction_revision, field="redaction revision"),
        "records": [relay_record(record) for record in records],
    }
    try:
        jsonschema.Draft202012Validator(_schema()).validate(envelope)
    except jsonschema.ValidationError as error:
        raise RedactionError("redacted evidence does not match the closed envelope") from error
    content = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not content or len(content) > 1_048_576:
        raise RedactionError("redacted evidence bytes are outside the closed bound")
    content_hash = "sha256:" + hashlib.sha256(content).hexdigest()
    manifest = {
        "schema_version": 1,
        "content_hash": content_hash,
        "record_count": len(envelope["records"]),
        "redaction_revision": redaction_revision,
        "classification": classification,
    }
    manifest_hash = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
    return envelope, content_hash, manifest_hash
