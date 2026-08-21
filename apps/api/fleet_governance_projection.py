"""Row-to-projection mapping for the Fleet governance tabs.

Memory candidates, security events, audit events, and the durable agent-run
ledger. Split from ``console_projection`` by responsibility: these functions
shape rows the snapshot queries already fetched and hold the PR-044 boundary
— list projections carry metadata and citable identifiers, never raw
sensitive content.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _json_list(value: object) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []
    return []


def memory_candidate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """PR-044: metadata only — fact_text never leaves the store through a list."""

    return [
        {
            "id": str(row["id"]),
            "type": str(row["candidate_type"]),
            "scope": str(row["scope_json"]),
            "status": str(row["status"]),
            "decision": str(row["confirmation_status"]),
            "purpose": str(row["purpose"]),
            "classification": str(row["classification"]),
            "review": str(row["review_requirement"]),
            "created_at": _iso(row["created_at"]),
            "retention": row["expires_at"].date().isoformat(),
            "source_count": len(_json_list(row["source_refs"])),
        }
        for row in rows
    ]


def security_event_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """No continuation claim: the event records the denial, not what the denied
    work did next, and a constant asserted here read as a per-event fact."""

    return [
        {
            "id": str(row["id"]),
            "control": str(row["control"]),
            "severity": str(row["severity"]),
            "event": str(row["event_type"]),
            "summary": str(row["safe_summary"]),
            "actor": str(row["actor_principal"] or "unattributed"),
            "destination": str(row["destination_ref"] or "none"),
            "incident": None if row["incident_id"] is None else str(row["incident_id"]),
            "policy": None if row["policy_ref"] is None else str(row["policy_ref"]),
            "occurred_at": _iso(row["occurred_at"]),
            "trace": str(row["trace_id"] or "not sampled"),
        }
        for row in rows
    ]


def audit_event_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "sequence": int(row["sequence_id"]),
            "id": str(row["id"]),
            "time": _iso(row["occurred_at"]),
            "principal": str(row["actor_principal"]),
            "event": str(row["event_type"]),
            "stream_type": str(row["stream_type"]),
            "stream_id": str(row["stream_id"]),
            "decision": None if row["decision_ref"] is None else str(row["decision_ref"]),
            "trace": None if row["trace_id"] is None else str(row["trace_id"]),
            "hash": str(row["payload_hash"]),
        }
        for row in rows
    ]


def agent_run_rows(
    rows: list[dict[str, Any]], *, agent_names: dict[str, str]
) -> list[dict[str, Any]]:
    """The durable run ledger behind each agent card. Only the coordinator
    writes these rows, so this is workflow authority, not model output; refs
    and hashes stay server-side and the projection carries identifiers a
    reader can cite."""

    return [
        {
            "id": str(row["id"]),
            "agent_key": str(row["agent_key"]),
            "agent": agent_names.get(str(row["agent_key"]), str(row["agent_key"])),
            "revision": str(row["agent_revision"]),
            "status": str(row["status"]),
            "attempt": int(row["attempt"]),
            "incident_id": None if row["incident_id"] is None else str(row["incident_id"]),
            "case_id": (
                None if row["reliability_case_id"] is None else str(row["reliability_case_id"])
            ),
            "workspace_id": None if row["workspace_id"] is None else str(row["workspace_id"]),
            "step": str(row["logical_step_key"]),
            "error_class": None if row["error_class"] is None else str(row["error_class"]),
            "workflow_version": int(row["workflow_version"]),
            "deadline": _iso(row["deadline"]),
            "started_at": None if row["started_at"] is None else _iso(row["started_at"]),
            "completed_at": None if row["completed_at"] is None else _iso(row["completed_at"]),
            "trace": None if row["trace_id"] is None else str(row["trace_id"]),
        }
        for row in rows
    ]
