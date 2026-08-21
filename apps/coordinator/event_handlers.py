"""Canonical inbox and Pub/Sub event parsing and entry transitions."""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Any

from apps.coordinator.contracts import _ENTRY_TRANSITIONS, PubSubPush
from solvan.application.incidents import CanonicalDetectionEvent
from solvan.application.ports import ClaimedEvent
from solvan.domain import (
    Scope,
)
from solvan.persistence import (
    AggregateType,
    PostgresWorkflowStore,
    TransitionWrite,
)
from solvan.persistence.inbox_store import InboxEnvelope


class InboxLeaseContention(RuntimeError):
    """Another coordinator holds the aggregate lease this claim needs.

    This says nothing about the claimed event, so the tick must return the
    claim without spending one of its bounded attempts. Treating contention as
    poison would quarantine a perfectly valid command after a few busy ticks.
    """


def canonical_detection(value: dict[str, Any]) -> CanonicalDetectionEvent:
    raw = value.get("canonical_event")
    if not isinstance(raw, dict):
        raise ValueError("detection receipt has no canonical_event object")
    expected = {
        "rule_id",
        "rule_version",
        "service_id",
        "graph_snapshot_id",
        "incident_class",
        "deduplication_dimension",
        "window_start",
        "window_end",
        "observed_value",
        "severity",
        "action_budget",
        "repeated_action_limit",
    }
    if set(raw) != expected:
        raise ValueError("canonical detection event fields do not match schema version 1")
    string_fields = (
        "rule_id",
        "service_id",
        "graph_snapshot_id",
        "incident_class",
        "deduplication_dimension",
        "window_start",
        "window_end",
        "severity",
    )
    if any(not isinstance(raw[field], str) for field in string_fields):
        raise ValueError("canonical detection string field has the wrong type")
    integer_fields = ("rule_version", "action_budget", "repeated_action_limit")
    if any(type(raw[field]) is not int for field in integer_fields):
        raise ValueError("canonical detection integer field has the wrong type")
    if isinstance(raw["observed_value"], bool) or not isinstance(
        raw["observed_value"], int | float
    ):
        raise ValueError("canonical detection observed value has the wrong type")
    try:
        return CanonicalDetectionEvent(
            rule_id=str(raw["rule_id"]),
            rule_version=int(raw["rule_version"]),
            service_id=str(raw["service_id"]),
            graph_snapshot_id=str(raw["graph_snapshot_id"]),
            incident_class=str(raw["incident_class"]),
            deduplication_dimension=str(raw["deduplication_dimension"]),
            window_start=datetime.fromisoformat(str(raw["window_start"])),
            window_end=datetime.fromisoformat(str(raw["window_end"])),
            observed_value=float(raw["observed_value"]),
            severity=str(raw["severity"]),
            action_budget=int(raw["action_budget"]),
            repeated_action_limit=int(raw["repeated_action_limit"]),
        )
    except (TypeError, ValueError) as error:
        raise ValueError("canonical detection event contains invalid typed values") from error


def decode_outbox_push(push: PubSubPush) -> dict[str, Any]:
    try:
        content = base64.b64decode(push.message.data, validate=True)
        value = json.loads(content)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Pub/Sub data is not canonical base64 JSON") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("unsupported outbox event schema")
    event_id = value.get("outbox_event_id")
    if not isinstance(event_id, str) or event_id != value.get("event_id"):
        raise ValueError("outbox event ID is missing or inconsistent")
    event_type = value.get("event_type")
    payload = value.get("payload")
    if not isinstance(event_type, str) or not isinstance(payload, dict):
        raise ValueError("outbox event type or payload is invalid")
    return value


def _incident_id(value: dict[str, Any]) -> str:
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("outbox event payload must be an object")
    incident_id = payload.get("incident_id", payload.get("entity_id"))
    if not isinstance(incident_id, str) or not incident_id.startswith("inc_"):
        raise ValueError("outbox event has no canonical incident ID")
    return incident_id


def _process_entry_transition(
    *,
    scope: Scope,
    owner: str,
    claim: ClaimedEvent,
    envelope: InboxEnvelope,
    value: dict[str, Any],
    workflow: PostgresWorkflowStore,
) -> None:
    from_state, to_state, event = _ENTRY_TRANSITIONS[envelope.event_type]
    incident_id = _incident_id(value)
    with workflow.transaction():
        lease = workflow.acquire_lease(
            scope=scope,
            aggregate_type=AggregateType.INCIDENT,
            entity_id=incident_id,
            owner=owner,
            lease_ttl_ms=60_000,
        )
    if lease is None:
        raise InboxLeaseContention(f"incident {incident_id} is currently leased")
    with workflow.transaction():
        current_state = workflow.incident_state_for_lease(scope=scope, lease=lease)
        if current_state == from_state:
            workflow.commit_transition(
                scope=scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state=from_state,
                    to_state=to_state,
                    transition_key=f"{event}:{envelope.source_event_id}",
                    actor_type="COORDINATOR",
                    actor_id=owner,
                    reason_code=event,
                    rationale_summary=f"Durable {event} state-entry command.",
                    evidence_refs=(envelope.payload_ref,),
                ),
            )
        elif current_state != to_state:
            raise ValueError(
                f"event {envelope.event_type} cannot progress incident from {current_state}"
            )
        workflow.complete_inbox(
            scope=scope,
            owner=owner,
            claim=claim,
            result_ref=f"incident:{incident_id}:{to_state}",
        )
        workflow.release_lease(scope=scope, lease=lease)
