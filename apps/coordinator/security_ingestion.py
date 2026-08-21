"""Safe Cloud Audit Log projection for Gateway, IAM, and Model Armor controls."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import PubSubPush
from solvan.domain import Scope, new_identifier


@dataclass(frozen=True, slots=True)
class SecurityLogEvent:
    source_message_id: str
    event_type: str
    control: str
    severity: str
    actor_principal: str | None
    destination_ref: str | None
    safe_summary: str
    payload_hash: str
    policy_ref: str | None
    trace_id: str | None
    occurred_at: datetime


def decode_security_log(push: PubSubPush) -> SecurityLogEvent:
    try:
        raw = base64.b64decode(push.message.data, validate=True)
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("security log Pub/Sub payload is not canonical JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("security log entry must be an object")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    proto = value.get("protoPayload")
    proto = proto if isinstance(proto, dict) else {}
    service = str(proto.get("serviceName", ""))
    method = str(proto.get("methodName", ""))
    log_name = str(value.get("logName", ""))
    json_payload = value.get("jsonPayload")
    json_payload = json_payload if isinstance(json_payload, dict) else {}
    payload_type = str(json_payload.get("@type", ""))

    if service == "modelarmor.googleapis.com" or "modelarmor" in payload_type.lower():
        control = "MODEL_ARMOR"
        event_type = "MODEL_ARMOR_SANITIZE_OBSERVED"
    elif service == "iap.googleapis.com":
        control = "AGENT_GATEWAY"
        event_type = "AGENT_GATEWAY_IAP_DENIED"
    elif "policy" in log_name.lower():
        control = "IAM"
        event_type = "IAM_POLICY_DENIED"
    else:
        raise ValueError("log entry is outside the approved security controls")

    status_value = proto.get("status")
    status_value = status_value if isinstance(status_value, dict) else {}
    status_code = status_value.get("code", 0)
    denied = isinstance(status_code, int) and status_code != 0
    severity = "HIGH" if denied else "INFO"
    if denied and control == "MODEL_ARMOR":
        event_type = "MODEL_ARMOR_REQUEST_DENIED"

    auth = proto.get("authenticationInfo")
    auth = auth if isinstance(auth, dict) else {}
    actor = auth.get("principalEmail")
    actor_principal = str(actor) if isinstance(actor, str) and actor else None
    destination = proto.get("resourceName")
    destination_ref = str(destination)[:500] if isinstance(destination, str) else None
    policy_ref = _first_permission(proto.get("authorizationInfo"))
    trace_value = value.get("trace")
    trace_id = str(trace_value)[-32:] if isinstance(trace_value, str) and trace_value else None
    occurred_at = _timestamp(value.get("timestamp"))
    safe_summary = (
        f"{control} control observation; method={method[:160] or 'unknown'}; "
        f"outcome={'DENIED' if denied else 'OBSERVED'}"
    )
    return SecurityLogEvent(
        source_message_id=push.message.messageId,
        event_type=event_type,
        control=control,
        severity=severity,
        actor_principal=actor_principal,
        destination_ref=destination_ref,
        safe_summary=safe_summary,
        payload_hash=digest,
        policy_ref=policy_ref,
        trace_id=trace_id,
        occurred_at=occurred_at,
    )


def persist_security_log(
    connection: Connection[Any], *, scope: Scope, event: SecurityLogEvent
) -> bool:
    with connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO solvan.security_events
              (organization_id, project_id, environment_id, id, event_type,
               control, severity, actor_principal, destination_ref, safe_summary,
               payload_hash, policy_ref, trace_id, occurred_at)
              SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                %(event_id)s, %(event_type)s, %(control)s, %(severity)s,
                %(actor_principal)s, %(destination_ref)s, %(safe_summary)s,
                %(payload_hash)s, %(policy_ref)s, %(trace_id)s, %(occurred_at)s
              WHERE NOT EXISTS (
                SELECT 1 FROM solvan.security_events
                WHERE organization_id = %(organization_id)s
                  AND project_id = %(project_id)s
                  AND environment_id = %(environment_id)s
                  AND payload_hash = %(payload_hash)s)""",
            {
                **scope.canonical_dict(),
                "event_id": new_identifier("sec"),
                "event_type": event.event_type,
                "control": event.control,
                "severity": event.severity,
                "actor_principal": event.actor_principal,
                "destination_ref": event.destination_ref,
                "safe_summary": event.safe_summary,
                "payload_hash": event.payload_hash,
                "policy_ref": event.policy_ref,
                "trace_id": event.trace_id,
                "occurred_at": event.occurred_at,
            },
        )
        return cursor.rowcount == 1


def _first_permission(value: object) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, dict) and isinstance(item.get("permission"), str):
            return str(item["permission"])[:500]
    return None


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("security log timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("security log timestamp must be timezone-aware")
    return parsed
