"""Bounded, sanitized projections of external provider payloads.

Every provider response crosses this module before it can become evidence.
Nothing here performs I/O, authorization, or persistence: it exists so that a
raw Google API payload can never reach durable state, a model context, or the
browser without passing a redaction and bounding rule.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta
from typing import Any, cast

_TRACE_ID = r"^[0-9a-f]{32}$"


def object_payload(value: Any, provider: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{provider} response is not an object")
    return value


def request_id(response: Any) -> str:
    return str(response.headers.get("x-request-id", "provider-request-id-unavailable"))


def redact(value: Any) -> Any:
    if isinstance(value, str):
        value = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[EMAIL]", value, flags=re.I)
        value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", value)
        value = re.sub(r"(?i)bearer\s+[a-z0-9._~-]+", "Bearer [TOKEN]", value)
        return value[:4_000]
    if isinstance(value, dict):
        return {str(key)[:100]: redact(item) for key, item in list(value.items())[:100]}
    if isinstance(value, list):
        return [redact(item) for item in value[:100]]
    return value


def error_reporting_period(span: timedelta) -> str:
    """Map a bounded window onto the smallest covering Error Reporting period."""

    for threshold, period in (
        (timedelta(hours=1), "PERIOD_1_HOUR"),
        (timedelta(hours=6), "PERIOD_6_HOURS"),
    ):
        if span <= threshold:
            return period
    return "PERIOD_1_DAY"


def actor(principal: Any) -> str:
    """Report service accounts exactly; pseudonymize human principals.

    A deploy pipeline's identity is the operationally interesting actor and is
    not personal data. A human principal is PII, but correlation across entries
    still matters, so it becomes a stable per-project pseudonym rather than a
    flat redaction.
    """

    if not isinstance(principal, str) or not principal:
        return "unknown"
    if principal.endswith(".gserviceaccount.com") or principal.startswith("service-"):
        return principal[:200]
    digest = hashlib.sha256(principal.encode()).hexdigest()[:12]
    return f"principal:{digest}"


def sanitize_audit_entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed": True}
    payload = value.get("protoPayload")
    payload = payload if isinstance(payload, dict) else {}
    authentication = payload.get("authenticationInfo")
    authentication = authentication if isinstance(authentication, dict) else {}
    status_value = payload.get("status")
    status_value = status_value if isinstance(status_value, dict) else {}
    # actor already resolves to a service-account identity or a pseudonym, so it
    # is applied after redaction: the generic pass would otherwise flatten a
    # workload identity to [EMAIL] and destroy the "what changed" signal.
    projection = cast(
        dict[str, Any],
        redact(
            {
                "timestamp": value.get("timestamp"),
                "method_name": payload.get("methodName"),
                "resource_name": payload.get("resourceName"),
                "service_name": payload.get("serviceName"),
                "operation_first": (payload.get("operation") or {}).get("first")
                if isinstance(payload.get("operation"), dict)
                else None,
                "status_code": status_value.get("code"),
                "severity": value.get("severity"),
            }
        ),
    )
    projection["actor"] = actor(authentication.get("principalEmail"))
    return projection


def sanitize_error_group(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed": True}
    group = value.get("group")
    group = group if isinstance(group, dict) else {}
    representative = value.get("representative")
    representative = representative if isinstance(representative, dict) else {}
    message = representative.get("message")
    return cast(
        dict[str, Any],
        redact(
            {
                "group_id": group.get("groupId"),
                "count": value.get("count"),
                "affected_users_count": value.get("affectedUsersCount"),
                "first_seen_time": value.get("firstSeenTime"),
                "last_seen_time": value.get("lastSeenTime"),
                "representative_message": message[:1_000] if isinstance(message, str) else None,
            }
        ),
    )


def sanitize_log(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed": True}
    return cast(
        dict[str, Any],
        redact(
            {
                key: value.get(key)
                for key in (
                    "timestamp",
                    "severity",
                    "insertId",
                    "trace",
                    "textPayload",
                    "jsonPayload",
                )
            }
        ),
    )


def sanitize_trace_span(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed": True}
    return cast(
        dict[str, Any],
        redact(
            {
                key: value.get(key)
                for key in ("spanId", "name", "startTime", "endTime", "labels", "status")
            }
        ),
    )


def bounded_summary(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)[:8_000] or "{}"


def trace_ids(value: Any, project_id: str) -> tuple[str, ...]:
    expected = f"projects/{project_id}/traces/"
    found: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            trace = item.get("trace")
            if isinstance(trace, str) and trace.startswith(expected):
                candidate = trace.removeprefix(expected)
                if re.fullmatch(_TRACE_ID, candidate):
                    found.add(candidate)
            for child in item.values():
                visit(child)
        elif isinstance(item, list | tuple):
            for child in item:
                visit(child)

    visit(value)
    return tuple(sorted(found))
