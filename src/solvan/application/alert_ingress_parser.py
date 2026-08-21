"""Strict parsing for Cloud Monitoring Pub/Sub alert deliveries."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal, cast

from solvan.application.alert_triage import (
    _ALLOWED_RESOURCE_LABELS,
    MAX_PROVIDER_PAYLOAD_BYTES,
    MAX_PUSH_ENVELOPE_BYTES,
    AlertIngressError,
    CanonicalCloudMonitoringAlert,
    PubSubEnvelopeIdentity,
)


def _object(value: object, *, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AlertIngressError(reason)
    return value


def _required_text(
    source: Mapping[str, Any], key: str, *, reason: str, max_length: int = 512
) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise AlertIngressError(reason)
    return value.strip()


def _timestamp(value: object, *, reason: str) -> datetime:
    try:
        if isinstance(value, bool):
            raise ValueError
        if isinstance(value, int | float):
            resolved = datetime.fromtimestamp(float(value), tz=UTC)
        elif isinstance(value, str):
            resolved = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise ValueError
    except (OverflowError, ValueError) as error:
        raise AlertIngressError(reason) from error
    if resolved.tzinfo is None:
        raise AlertIngressError(reason)
    return resolved.astimezone(UTC)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def inspect_pubsub_envelope(raw_body: bytes) -> tuple[PubSubEnvelopeIdentity, dict[str, Any]]:
    if not raw_body or len(raw_body) > MAX_PUSH_ENVELOPE_BYTES:
        raise AlertIngressError("PUSH_ENVELOPE_SIZE_INVALID")
    envelope_hash = f"sha256:{hashlib.sha256(raw_body).hexdigest()}"
    try:
        outer = _object(json.loads(raw_body), reason="PUSH_ENVELOPE_INVALID")
        message = _object(outer.get("message"), reason="PUSH_MESSAGE_INVALID")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise AlertIngressError("PUSH_ENVELOPE_INVALID") from error
    message_id = _required_text(message, "messageId", reason="PUBSUB_MESSAGE_ID_INVALID")
    if len(message_id) > 256:
        raise AlertIngressError("PUBSUB_MESSAGE_ID_INVALID")
    subscription = _required_text(outer, "subscription", reason="PUBSUB_SUBSCRIPTION_INVALID")
    publish_value = message.get("publishTime")
    publish_time = (
        None
        if publish_value is None
        else _timestamp(publish_value, reason="PUBSUB_PUBLISH_TIME_INVALID")
    )
    return (
        PubSubEnvelopeIdentity(message_id, subscription, publish_time, envelope_hash),
        message,
    )


def canonicalize_cloud_monitoring_push(raw_body: bytes) -> CanonicalCloudMonitoringAlert:
    envelope, message = inspect_pubsub_envelope(raw_body)
    encoded = _required_text(
        message,
        "data",
        reason="PUBSUB_DATA_INVALID",
        max_length=MAX_PROVIDER_PAYLOAD_BYTES * 2,
    )
    try:
        payload_bytes = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise AlertIngressError("PUBSUB_DATA_INVALID") from error
    if not payload_bytes or len(payload_bytes) > MAX_PROVIDER_PAYLOAD_BYTES:
        raise AlertIngressError("MONITORING_PAYLOAD_SIZE_INVALID")
    try:
        payload = _object(json.loads(payload_bytes), reason="MONITORING_PAYLOAD_INVALID")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise AlertIngressError("MONITORING_PAYLOAD_INVALID") from error
    if payload.get("version") != "1.2":
        raise AlertIngressError("MONITORING_SCHEMA_VERSION_UNSUPPORTED")
    incident = _object(payload.get("incident"), reason="MONITORING_INCIDENT_INVALID")
    incident_key = _required_text(incident, "incident_id", reason="PROVIDER_INCIDENT_KEY_INVALID")
    state_value = _required_text(incident, "state", reason="PROVIDER_STATE_INVALID").upper()
    if state_value not in {"OPEN", "CLOSED"}:
        raise AlertIngressError("PROVIDER_STATE_INVALID")
    state = cast(Literal["OPEN", "CLOSED"], state_value)
    started_at = _timestamp(incident.get("started_at"), reason="TRANSITION_KEY_INCOMPLETE")
    ended_at = None
    if state == "CLOSED":
        ended_at = _timestamp(incident.get("ended_at"), reason="TRANSITION_KEY_INCOMPLETE")
        if ended_at < started_at:
            raise AlertIngressError("TRANSITION_TIME_INVALID")
    transition_discriminator = (
        f"OPEN:{_rfc3339(started_at)}"
        if state == "OPEN"
        else f"CLOSED:{_rfc3339(started_at)}:{_rfc3339(cast(datetime, ended_at))}"
    )
    observed_at = ended_at or started_at
    scoping_project = _required_text(
        incident, "scoping_project_id", reason="SCOPING_PROJECT_INVALID"
    )
    resource = _object(incident.get("resource"), reason="MONITORED_RESOURCE_INVALID")
    resource_type = _required_text(resource, "type", reason="MONITORED_RESOURCE_INVALID")
    labels = _object(resource.get("labels"), reason="MONITORED_RESOURCE_LABELS_INVALID")
    project_id = _required_text(labels, "project_id", reason="MONITORED_PROJECT_INVALID")
    safe_labels: dict[str, str] = {}
    for key in sorted(_ALLOWED_RESOURCE_LABELS.intersection(labels)):
        value = labels[key]
        if isinstance(value, str) and 0 < len(value) <= 256:
            safe_labels[key] = value
    normalized_labels = {
        "condition_name": _required_text(
            incident, "condition_name", reason="CONDITION_NAME_INVALID"
        ),
        "policy_name": _required_text(incident, "policy_name", reason="POLICY_NAME_INVALID"),
    }
    severity = _required_text(incident, "severity", reason="PROVIDER_SEVERITY_INVALID").upper()
    canonical = {
        "ended_at": None if ended_at is None else _rfc3339(ended_at),
        "incident_id": incident_key,
        "labels": safe_labels,
        "normalized_labels": normalized_labels,
        "provider_severity": severity,
        "resource_type": resource_type,
        "scoping_project_id": scoping_project,
        "started_at": _rfc3339(started_at),
        "state": state,
        "transition_discriminator": transition_discriminator,
        "version": "cloud-monitoring/1.2",
    }
    return CanonicalCloudMonitoringAlert(
        envelope=envelope,
        provider_incident_key=incident_key,
        lifecycle_state=state,
        transition_discriminator=transition_discriminator,
        transition_sequence=1 if state == "OPEN" else 2,
        started_at=started_at,
        ended_at=ended_at,
        observed_at=observed_at,
        scoping_project_id=scoping_project,
        monitored_resource_project_id=project_id,
        resource_type=resource_type,
        resource_labels=safe_labels,
        normalized_labels=normalized_labels,
        provider_severity=severity,
        canonical_event_hash=_canonical_json_hash(canonical),
        raw_payload_hash=f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}",
    )


def parse_source_qualification_push(raw_body: bytes) -> tuple[PubSubEnvelopeIdentity, str, str]:
    """Parse the closed, non-semantic source-qualification envelope.

    Qualification is intentionally a different payload from a Monitoring
    incident. It may establish only a source binding and never reaches the
    normal semantic-event parser.
    """

    envelope, message = inspect_pubsub_envelope(raw_body)
    encoded = _required_text(
        message,
        "data",
        reason="PUBSUB_DATA_INVALID",
        max_length=MAX_PROVIDER_PAYLOAD_BYTES * 2,
    )
    try:
        payload_bytes = base64.b64decode(encoded, validate=True)
        payload = _object(json.loads(payload_bytes), reason="SOURCE_QUALIFICATION_PAYLOAD_INVALID")
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise AlertIngressError("SOURCE_QUALIFICATION_PAYLOAD_INVALID") from error
    qualification = _object(
        payload.get("solvan_source_qualification"),
        reason="SOURCE_QUALIFICATION_PAYLOAD_INVALID",
    )
    binding_id = _required_text(
        qualification, "source_binding_id", reason="SOURCE_QUALIFICATION_BINDING_INVALID"
    )
    configuration_digest = _required_text(
        qualification,
        "configuration_digest",
        reason="SOURCE_QUALIFICATION_DIGEST_INVALID",
        max_length=71,
    )
    if not binding_id.startswith("asb_") or not configuration_digest.startswith("sha256:"):
        raise AlertIngressError("SOURCE_QUALIFICATION_PAYLOAD_INVALID")
    return envelope, binding_id, configuration_digest


def _canonical_json_hash(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
