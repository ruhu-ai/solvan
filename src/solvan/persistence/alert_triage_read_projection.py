"""Pure projection helpers for the reader-safe Alert console."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from solvan.application.alert_list import AlertCursorPosition, AlertListFilter
from solvan.application.alert_policy_products import (
    committed_decision_explanation,
    operator_mode_explanation,
    operator_mode_label,
)

_ACTIVE = ("OPEN", "WAITING", "TRIAGING", "TRIAGED", "ESCALATED", "ATTACHED")


def jsonable(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [jsonable(item) for item in value]
    return value


def filter_values(alert_filter: AlertListFilter) -> dict[str, Any]:
    return {
        "severity": list(alert_filter.severity),
        "episode_state": list(alert_filter.episode_state),
        "source_provider": list(alert_filter.source_provider),
        "connection_id": list(alert_filter.connection_id),
        "department": list(alert_filter.department),
        "target_key": list(alert_filter.target_key),
        "policy_key": list(alert_filter.policy_key),
        "mode": list(alert_filter.mode),
        "provider_state": list(alert_filter.provider_state),
        "disposition": list(alert_filter.disposition),
        "incident_link": alert_filter.incident_link,
        "source_time_from": alert_filter.source_time_from,
        "source_time_to": alert_filter.source_time_to,
        "query": alert_filter.query,
    }


def cursor_position(row: dict[str, Any]) -> AlertCursorPosition:
    return AlertCursorPosition(
        severity_rank={"SEV1": 1, "SEV2": 2, "SEV3": 3, "SEV4": 4}[row["severity"]],
        attention_rank=0 if row["disposition"] in {"MANUAL_REVIEW", "BLOCKED"} else 1,
        last_seen_at=row["last_source_time"],
        alert_episode_id=str(row["id"]),
    )


def view_clause(view: str) -> str:
    if view == "ACTIVE":
        return " AND episode.state=ANY(ARRAY['" + "','".join(_ACTIVE) + "'])"
    if view == "NEEDS_REVIEW":
        return " AND disposition.disposition IN ('MANUAL_REVIEW','BLOCKED')"
    if view == "INVESTIGATING":
        return " AND episode.state IN ('WAITING','TRIAGING')"
    return ""


def list_row(row: dict[str, Any]) -> dict[str, Any]:
    attention = row["disposition"] in {"MANUAL_REVIEW", "BLOCKED"}
    return {
        "alert_episode_id": row["id"],
        "row_version": row["row_version"],
        "title": (
            f"{row['provider_incident_key']} on {row['service_name'] or row['target_node_key']}"
        ),
        "target": row["service_name"] or row["target_node_key"],
        "target_key": row["target_node_key"],
        "severity": row["severity"],
        "source_provider": row["provider_kind"],
        "provider_state": row["provider_state_projection"],
        "first_seen_at": row["first_source_time"].isoformat(),
        "last_seen_at": row["last_source_time"].isoformat(),
        "occurrence_count": row["occurrence_count"],
        "investigation_state": row["state"],
        "disposition": row["disposition"],
        "reason_code": row["reason_code"],
        "required_human_attention": attention,
        "next_action": "Review required" if attention else "Open investigation",
        "incident": (
            None
            if row["incident_id"] is None
            else {"id": row["incident_id"], "display_id": row["incident_display_id"]}
        ),
        "policy": f"{row['policy_key']}@{row['policy_version']}",
        "mode": row["mode"],
        "mode_label": operator_mode_label(row["mode"]),
        "mode_explanation": operator_mode_explanation(row["mode"]),
        "connection_id": row["connection_id"],
    }


def _holding(section_id: str, template: str) -> dict[str, Any]:
    return {
        "section_id": section_id,
        "status": "NOT_ESTABLISHED",
        "claims": [],
        "holding_template_id": template,
        "authorized_disclosure_count": 0,
    }


def _claim(section_id: str, template: str, values: dict[str, Any], ref: str) -> dict[str, Any]:
    return {
        "section_id": section_id,
        "status": "ESTABLISHED",
        "claims": [
            {
                "claim_template_id": template,
                "subject_ref": values.get("alert_episode_id"),
                "typed_values": values,
                "window": None,
                "source_status_kind": "PROVIDER_REPORTED",
                "citation_refs": [ref],
                "predicate_result_ref": None,
            }
        ],
        "holding_template_id": None,
        "authorized_disclosure_count": 1,
    }


def _evidence_section(
    *, row: dict[str, Any], event_ref: str, evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    claims = [
        {
            "claim_template_id": "ALERT_SEMANTIC_EVENT_COMMITTED@1",
            "subject_ref": row["id"],
            "typed_values": {
                "sentence": "The authenticated provider alert was normalized and committed.",
                "alert_episode_id": row["id"],
                "source": row["provider_kind"],
            },
            "window": None,
            "source_status_kind": "PROVIDER_REPORTED",
            "citation_refs": [event_ref],
            "predicate_result_ref": None,
        }
    ]
    claims.extend(
        {
            "claim_template_id": "ALERT_BOUNDED_EVIDENCE_CAPTURED@1",
            "subject_ref": row["id"],
            "typed_values": {
                "sentence": (
                    f"{item['source_kind']} evidence was captured from "
                    f"{item['source_resource']} for the bounded alert window."
                ),
                "source_kind": item["source_kind"],
                "source_resource": item["source_resource"],
                "content_hash": item["content_hash"],
            },
            "window": {
                "start": item["window_start"].isoformat(),
                "end": item["window_end"].isoformat(),
            },
            "source_status_kind": "SOLVAN_OBSERVED",
            "citation_refs": [str(item["id"])],
            "predicate_result_ref": None,
        }
        for item in evidence
    )
    return {
        "section_id": "KEY_EVIDENCE",
        "status": "ESTABLISHED",
        "claims": claims,
        "holding_template_id": None,
        "authorized_disclosure_count": len(claims),
    }


def report_projection(
    row: dict[str, Any],
    *,
    predicates: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    delivery_feedback_count: int,
) -> dict[str, Any]:
    event_ref = str(row["last_event_id"])
    linked = row["incident_id"] is not None
    sections = [
        _claim(
            "WHAT_HAPPENED",
            "ALERT_PROVIDER_STATE_OBSERVED@1",
            {
                "alert_episode_id": row["id"],
                "target": row["service_name"] or row["target_node_key"],
                "provider_state": row["provider_state_projection"],
                "occurrences": row["occurrence_count"],
            },
            event_ref,
        ),
        _holding("IMPACT", "ALERT_SECTION_NOT_ESTABLISHED"),
        _holding("LIKELY_CAUSE", "ALERT_SECTION_NOT_ESTABLISHED"),
        _evidence_section(row=row, event_ref=event_ref, evidence=evidence),
        _claim(
            "NEXT_STEP",
            "ALERT_NEXT_OWNER@1",
            {
                "alert_episode_id": row["id"],
                "owner": row["next_owner"] or "service-owner",
                "reason_code": row["reason_code"] or "TRIAGE_IN_PROGRESS",
            },
            row["disposition_id"] or event_ref,
        ),
    ]
    for ordinal, section in enumerate(sections, start=1):
        section["ordinal"] = ordinal
    return {
        "schema_version": 1,
        "alert_episode_id": row["id"],
        "row_version": row["row_version"],
        "header": list_row(row),
        "sections": sections,
        "technical_disclosures": [
            {"kind": "EVIDENCE_TRIAGE", "count": len(evidence) + len(predicates)},
            {"kind": "EVENT_HISTORY", "count": row["occurrence_count"]},
            {"kind": "POLICY_ROUTING", "count": 1},
            {"kind": "DELIVERY_FEEDBACK", "count": delivery_feedback_count},
        ],
        "incident_link": (
            None
            if not linked
            else {"id": row["incident_id"], "display_id": row["incident_display_id"]}
        ),
        "decision_explanation": committed_decision_explanation(row, predicates),
        "primary_control": (
            {"kind": "OPEN_INCIDENT", "incident_id": row["incident_id"]}
            if linked
            else {
                "kind": "CONTINUE_INVESTIGATION",
                "episode_id": row["id"],
                "expected_row_version": row["row_version"],
            }
        ),
        "secondary_controls": ["RUN_TRIAGE_AGAIN", "GIVE_FEEDBACK"],
        "projection_version": 1,
        "freshness_at": row["last_source_time"].isoformat(),
        "placement_epoch": row["placement_epoch"],
        "policy_epoch": row["head_epoch"],
        "membership_epoch": 0,
        "reader_cursor": None,
    }
