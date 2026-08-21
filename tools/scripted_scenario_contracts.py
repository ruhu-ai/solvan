"""Stable S2-S6 oracle assertion names and run identifiers."""

from __future__ import annotations

import re

SCRIPTED_ASSERTIONS: dict[str, tuple[str, ...]] = {
    "S2": (
        "duplicate_source_event_deduplicated",
        "two_incidents_share_exact_target",
        "maximum_active_target_reservations_one",
        "one_connector_mutation",
        "losing_action_invalidated",
    ),
    "S3": (
        "failed_attempt_stale_or_failed",
        "one_fallback_attempt_created",
        "preserved_evidence_reference_consumed",
        "no_incident_or_action_duplicate",
    ),
    "S4": (
        "stale_target_action_invalidated",
        "zero_connector_mutations",
        "reservation_released_without_mutation",
    ),
    "S5": (
        "instruction_control_blocked",
        "investigation_continued",
        "memory_candidate_quarantined",
        "memory_not_promoted",
    ),
    "S6": (
        "cross_scope_database_read_denied",
        "direct_gateway_bypass_denied",
        "global_region_configuration_denied",
        "security_events_persisted",
    ),
}


def validate_scenario_run_id(value: str) -> str:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{7,63}", value) is None:
        raise RuntimeError("scenario run ID is not canonical")
    return value
