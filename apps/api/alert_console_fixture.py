"""Clearly labelled, non-authoritative Alert console development data."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from solvan.application.workspace_hashing import canonical_sha256

_EPISODE_ID = "aep_00000000000000000000000001"
_INCIDENT_ID = "inc_01J4QZK8Q4J8Q6B95KQY4M9R2S"


def alert_console_fixture() -> dict[str, Any]:
    """Return one coherent queue/report projection for local UI development."""

    row = {
        "alert_episode_id": _EPISODE_ID,
        "row_version": 4,
        "title": "Elevated payment errors on payments-api",
        "target": "payments-api",
        "target_key": "payments-api",
        "severity": "SEV2",
        "source_provider": "CLOUD_MONITORING",
        "provider_state": "OPEN",
        "first_seen_at": "2026-08-14T11:50:03+00:00",
        "last_seen_at": "2026-08-14T12:05:41+00:00",
        "occurrence_count": 3,
        "investigation_state": "ESCALATED",
        "disposition": "ESCALATED_NEW",
        "reason_code": "ESCALATION_PREDICATE_TRUE",
        "required_human_attention": False,
        "next_action": "Open linked Incident",
        "incident": {"id": _INCIDENT_ID, "display_id": "INC-1042"},
        "policy": "payments-http-errors@4",
        "mode": "POLICY_ESCALATED",
        "mode_label": "Investigate, then escalate by rule",
        "mode_explanation": (
            "Open or attach an Incident only when the named approved escalation "
            "rule evaluates true."
        ),
        "connection_id": "con_demo_monitoring",
    }
    list_projection: dict[str, Any] = {
        "schema_version": 1,
        "filter": {
            "schema_version": 1,
            "view": "ACTIVE",
            "severity": [],
            "episode_state": [],
            "limit": 50,
        },
        "counts": {"ACTIVE": 1, "NEEDS_REVIEW": 0, "INVESTIGATING": 0, "ALL": 1},
        "rows": [row],
        "next_cursor": None,
        "projection_version": 1,
        "freshness_at": datetime.now(UTC).isoformat(),
        "placement_epoch": 1,
        "policy_epoch": 3,
        "membership_epoch": 1,
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
    }
    list_projection["projection_digest"] = canonical_sha256(list_projection)

    def claim(
        section_id: str,
        template_id: str,
        sentence: str,
        citation: str,
        source_status: str = "SOLVAN_OBSERVED",
    ) -> dict[str, Any]:
        return {
            "section_id": section_id,
            "status": "ESTABLISHED",
            "claims": [
                {
                    "claim_template_id": template_id,
                    "subject_ref": _EPISODE_ID,
                    "typed_values": {"sentence": sentence},
                    "window": None,
                    "source_status_kind": source_status,
                    "citation_refs": [citation],
                    "predicate_result_ref": None,
                }
            ],
            "holding_template_id": None,
            "authorized_disclosure_count": 1,
        }

    sections = [
        claim(
            "WHAT_HAPPENED",
            "ALERT_PROVIDER_STATE_OBSERVED@1",
            "Cloud Monitoring reported sustained HTTP 5xx errors on payments-api; "
            "the source alert remains open.",
            "ale_00000000000000000000000001",
            "PROVIDER_REPORTED",
        ),
        claim(
            "IMPACT",
            "ALERT_IMPACT_MEASURED@1",
            "Synthetic payment failures peaked at 18.4% during the observed alert window.",
            "evd_00000000000000000000000001",
        ),
        claim(
            "LIKELY_CAUSE",
            "ALERT_CAUSE_HYPOTHESIS@1",
            "The strongest supported hypothesis is connection-pool exhaustion after "
            "revision v2.8.1; root cause is not yet independently confirmed.",
            "apr_00000000000000000000000001",
        ),
        claim(
            "KEY_EVIDENCE",
            "ALERT_EVIDENCE_WINDOW_OBSERVED@1",
            "The bounded pool reached four checked-out connections before later "
            "synthetic requests returned HTTP 503.",
            "evd_00000000000000000000000002",
        ),
        claim(
            "NEXT_STEP",
            "ALERT_NEXT_OWNER@1",
            "The approved escalation rule opened INC-1042; Incident investigation is active.",
            "ads_00000000000000000000000001",
        ),
    ]
    for ordinal, section in enumerate(sections, start=1):
        section["ordinal"] = ordinal
    report: dict[str, Any] = {
        "schema_version": 1,
        "alert_episode_id": _EPISODE_ID,
        "row_version": 4,
        "header": row,
        "sections": sections,
        "technical_disclosures": [
            {"kind": "EVIDENCE_TRIAGE", "count": 3},
            {"kind": "EVENT_HISTORY", "count": 3},
            {"kind": "POLICY_ROUTING", "count": 1},
            {"kind": "DELIVERY_FEEDBACK", "count": 0},
        ],
        "incident_link": {"id": _INCIDENT_ID, "display_id": "INC-1042"},
        "decision_explanation": {
            "kind": "COMMITTED_DECISION",
            "disposition_ref": "ads_00000000000000000000000001",
            "policy_key": "payments-http-errors",
            "policy_version": "4",
            "policy_digest": "sha256:" + "4" * 64,
            "operator_mode_label": "Investigate, then escalate by rule",
            "machine_mode": "POLICY_ESCALATED",
            "result": "ESCALATED",
            "status": "ESTABLISHED",
            "summary_template_id": "ALERT_DECISION_ESCALATED",
            "typed_values": {
                "mode_label": "Investigate, then escalate by rule",
                "mode_explanation": (
                    "Open or attach an Incident only when the named approved escalation "
                    "rule evaluates true."
                ),
                "reason_code": "ESCALATION_PREDICATE_TRUE",
            },
            "expression_digest": "sha256:" + "5" * 64,
            "authorized_node_result_refs": ["apr_00000000000000000000000001"],
            "authorized_input_refs": ["ref_s1_calibration"],
            "holding_template_id": None,
            "incident_link_decision_ref": "ads_00000000000000000000000001",
        },
        "primary_control": {
            "kind": "OPEN_INCIDENT",
            "incident_id": "INC-1042",
        },
        "secondary_controls": ["RUN_TRIAGE_AGAIN", "GIVE_FEEDBACK"],
        "projection_version": 1,
        "freshness_at": "2026-08-14T12:05:41+00:00",
        "placement_epoch": 1,
        "policy_epoch": 3,
        "membership_epoch": 1,
        "reader_cursor": None,
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
        "subresources": {
            "EVENTS": [
                {
                    "event_id": "ale_00000000000000000000000001",
                    "state": "OPEN",
                    "observed_at": "2026-08-14T11:50:03+00:00",
                    "source": "CLOUD_MONITORING",
                }
            ],
            "TRIAGE_RUNS": [
                {
                    "triage_run_id": "aru_00000000000000000000000001",
                    "status": "SUCCEEDED",
                    "profile_ref": "alert-triage-read-compute-v1@1",
                }
            ],
            "DISPOSITIONS": [
                {
                    "disposition_id": "ads_00000000000000000000000001",
                    "disposition": "ESCALATED_NEW",
                    "reason_code": "ESCALATION_PREDICATE_TRUE",
                }
            ],
            "INCIDENT_LINKS": [
                {
                    "incident_id": _INCIDENT_ID,
                    "disposition_id": "ads_00000000000000000000000001",
                    "link_kind": "CREATED",
                    "deduplication_decision": "CREATED",
                    "linked_at": "2026-08-14T12:05:41+00:00",
                }
            ],
            "CHANNEL_DELIVERIES": [],
        },
    }
    report["projection_digest"] = canonical_sha256(report)
    policies = {
        "schema_version": 1,
        "rows": [
            {
                "policy_key": "payments-http-errors",
                "version": "4",
                "lifecycle": "APPROVED",
                # The lifecycle head emits ELIGIBLE or RETIRED. The fixture said
                # AVAILABLE, a value no deployment can produce, so the console was
                # developed against a state it would never render.
                "availability": "ELIGIBLE",
                "mode": "POLICY_ESCALATED",
                "mode_label": "Investigate, then escalate by rule",
                "mode_explanation": (
                    "Open or attach an Incident only when the named approved escalation "
                    "rule evaluates true."
                ),
                "policy_hash": "sha256:" + "4" * 64,
                "author_principal": "user:policy-author@example.com",
                "approved_by_principal": "user:policy-approver@example.com",
                "evaluation_ref": "evaluation://alert-policy/payments-http-errors/4",
                "approval_ref": "ref_alert_policy_payments_http_errors_4",
                "approved_at": "2026-08-13T09:12:00+00:00",
                "connection_id": "con_demo_monitoring",
                "connection_epoch": 1,
                "connection_health": "READY",
                "connection_reason_code": None,
                "connection_binding_current": True,
                "last_match_at": "2026-08-14T11:50:03+00:00",
                "last_triage_at": "2026-08-14T12:05:41+00:00",
                "current_capacity": "AVAILABLE",
                "current_capacity_reason_code": None,
                "suppression_count": 0,
            }
        ],
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
    }
    capacity = {
        "schema_version": 1,
        "status": "AVAILABLE",
        "reason_code": None,
        "active_reservations": 0,
        "limit": 4,
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
    }
    related_alerts = {
        "schema_version": 1,
        "incident_id": _INCIDENT_ID,
        "incident_row_version": 12,
        "rows": [
            {
                "alert_episode_id": _EPISODE_ID,
                "safe_title": "Elevated payment errors on payments-api",
                "severity": "SEV2",
                "target_label": "payments-api",
                "provider_state": "OPEN",
                "provider_status_label": "ACTIVE_AT_SOURCE",
                "disposition": "ESCALATED_NEW",
                "disposition_label": "Escalation rule passed",
                "source_freshness_at": "2026-08-14T12:05:41+00:00",
                "relation": "CREATED",
                "link_disposition_ref": "ads_00000000000000000000000001",
                "linked_at": "2026-08-14T12:05:41+00:00",
                "deduplication_decision_ref": "CREATED",
                "recovery_status": "INDEPENDENTLY_VERIFIED",
                "verification_ref": "VER-1042",
            }
        ],
        "next_cursor": None,
        "freshness_at": datetime.now(UTC).isoformat(),
        "placement_epoch": 1,
        "membership_epoch": 1,
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
    }
    related_alerts["projection_digest"] = canonical_sha256(related_alerts)
    policy_templates = {
        "schema_version": 1,
        "rows": [
            {
                "template_key": "cloud-run-http-errors",
                "version": "1",
                "publisher_ref": "solvan:first-party",
                "calibration_slots": ["error_ratio", "window_ms", "connection_id"],
                "example_values": {"error_ratio": 0.02, "window_ms": 300000},
                "example_values_label": "EXAMPLE — NOT A DEFAULT",
                "compatibility": "cloud-monitoring/1.2",
                "content_digest": "sha256:" + "6" * 64,
                "lifecycle": "ACTIVE",
                "creates": "DRAFT_ONLY",
            }
        ],
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
    }
    recommendations = {
        "schema_version": 1,
        "label": "Machine-proposed — requires author review",
        "rows": [
            {
                "id": "rec_01K2M7Y8F90H6J1K3M5N7P9QRS",
                "policy_key": "payments-http-errors",
                "predecessor_version": "4",
                "source_incident_id": _INCIDENT_ID,
                "recommendation_digest": "sha256:" + "7" * 64,
                "rationale_template_id": "ALERT_RECOMMEND_POLICY_REVIEW",
                "rationale_values_json": {"outcome": "Repeated verified payment recovery"},
                "expires_at": "2026-08-21T12:05:41+00:00",
                "decision_epoch": 0,
            }
        ],
        "data_status": "SCRIPTED_RELEASE_FIXTURE",
        "authority": "NO_PRODUCTION_AUTHORITY",
    }
    simulation_receipt = {
        "schema_version": 1,
        "kind": "HYPOTHETICAL_NO_WORKFLOW_EFFECT",
        "simulation_id": "sim_01K2M7Y8F90H6J1K3M5N7P9QRS",
        "evaluator_key": "alert-predicate-evaluator",
        "evaluator_version": "1",
        "expression_digest": "sha256:" + "8" * 64,
        "result": "WOULD_ESCALATE",
        "summary_template_id": "ALERT_SIMULATION_WOULD_ESCALATE",
        "typed_values": {"operator_mode_label": "Investigate, then escalate by rule"},
        "authorized_node_summaries": [],
        "access_set_hash": "sha256:" + "9" * 64,
        "created_at": datetime.now(UTC).isoformat(),
        "retention_until": "2026-09-13T12:05:41+00:00",
    }
    return {
        "list": deepcopy(list_projection),
        "reports": {_EPISODE_ID: deepcopy(report)},
        "policies": policies,
        "capacity": capacity,
        "related_alerts": {
            _INCIDENT_ID: deepcopy(related_alerts),
            "INC-1042": deepcopy(related_alerts),
        },
        "policy_templates": policy_templates,
        "recommendations": recommendations,
        "simulation_receipt": simulation_receipt,
    }
