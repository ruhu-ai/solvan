from __future__ import annotations

import base64
import hashlib
import json

import pytest

from apps.coordinator.liaison_steer import (
    accept_confirmed_liaison_steer,
    load_confirmed_liaison_steer,
)
from apps.coordinator.main import (
    PubSubMessage,
    PubSubPush,
    canonical_detection,
    decode_outbox_push,
)
from solvan.domain import Scope


def detection_value() -> dict[str, object]:
    return {
        "canonical_event": {
            "rule_id": "rule-1",
            "rule_version": 1,
            "service_id": "svc_00000000000000000000000000",
            "graph_snapshot_id": "pgs_00000000000000000000000000",
            "incident_class": "connection_exhaustion",
            "deduplication_dimension": "http-5xx",
            "window_start": "2026-08-08T12:00:00+00:00",
            "window_end": "2026-08-08T12:01:00+00:00",
            "observed_value": 0.08,
            "severity": "SEV2",
            "action_budget": 2,
            "repeated_action_limit": 1,
        }
    }


def test_canonical_detection_is_strict_and_timezone_aware() -> None:
    event = canonical_detection(detection_value())
    assert event.rule_id == "rule-1"
    assert event.window_end.utcoffset() is not None

    invalid = detection_value()
    assert isinstance(invalid["canonical_event"], dict)
    invalid["canonical_event"]["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        canonical_detection(invalid)


def test_outbox_push_requires_consistent_stable_event_id() -> None:
    value = {
        "schema_version": 1,
        "outbox_event_id": "evt_00000000000000000000000000",
        "event_id": "evt_00000000000000000000000000",
        "event_type": "IncidentDetected",
        "payload": {"incident_id": "inc_00000000000000000000000000"},
    }
    push = PubSubPush(
        message=PubSubMessage(
            data=base64.b64encode(json.dumps(value).encode()).decode(),
            messageId="message-1",
        ),
        subscription="projects/solvan-demo/subscriptions/workflow",
    )
    assert decode_outbox_push(push)["event_type"] == "IncidentDetected"

    value["event_id"] = "evt_11111111111111111111111111"
    push.message.data = base64.b64encode(json.dumps(value).encode()).decode()
    with pytest.raises(ValueError, match="inconsistent"):
        decode_outbox_push(push)


class _OneRow:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...]:
        return self._row


class _SteerConnection:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def execute(self, _statement: str, _params: dict[str, object]) -> _OneRow:
        return _OneRow(self._row)


class _ReplaySteerConnection:
    def __init__(self, envelope: dict[str, object]) -> None:
        self._envelope = envelope

    def execute(self, statement: str, _params: dict[str, object]) -> _OneRow:
        if "liaison_operation_ledger" in statement:
            return _OneRow(
                (
                    self._envelope["decided_payload_hash"],
                    json.dumps({"envelope": self._envelope}),
                    "ANSWERED",
                    self._envelope["decided_payload_hash"],
                    self._envelope["step"],
                )
            )
        if "actor_role_bindings" in statement:
            return _OneRow((True,))
        if "FROM solvan.incidents" in statement:
            return _OneRow(
                (
                    "inc_00000000000000000000000000",
                    "INVESTIGATING",
                    8,
                    None,
                )
            )
        if "FROM solvan.state_transitions" in statement:
            return _OneRow((8,))
        raise AssertionError(f"unexpected SQL: {statement}")


def test_confirmed_liaison_steer_is_loaded_only_from_its_typed_ledger_projection() -> None:
    envelope = {
        "audience": "COORDINATOR_INBOX",
        "parked_request_id": "prk_00000000000000000000000000",
        "decided_payload_hash": "sha256:" + "a" * 64,
        "scope": {
            "organization_id": "org_00000000000000000000000000",
            "project_id": "prj_00000000000000000000000000",
            "environment_id": "env_00000000000000000000000000",
        },
        "confirming_principal": "operator@example.com",
        "expected_workflow_version": 7,
        "expected_plan_version": None,
        "step": {"tool_profile": ["metrics.read"], "purpose": "bounded metric read"},
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    envelope_hash = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()
    loaded = load_confirmed_liaison_steer(
        _SteerConnection(
            (
                envelope["decided_payload_hash"],
                json.dumps({"inbox_id": "evt_00000000000000000000000000", "envelope": envelope}),
                "ANSWERED",
                envelope["decided_payload_hash"],
                envelope["step"],
            )
        ),  # type: ignore[arg-type]
        scope=Scope(
            "org_00000000000000000000000000",
            "prj_00000000000000000000000000",
            "env_00000000000000000000000000",
        ),
        parked_request_id="prk_00000000000000000000000000",
        expected_envelope_hash=envelope_hash,
    )
    assert loaded == envelope

    with pytest.raises(RuntimeError, match="envelope hash is stale"):
        load_confirmed_liaison_steer(
            _SteerConnection(
                (
                    envelope["decided_payload_hash"],
                    json.dumps({"envelope": envelope}),
                    "ANSWERED",
                    envelope["decided_payload_hash"],
                    envelope["step"],
                )
            ),  # type: ignore[arg-type]
            scope=Scope(
                "org_00000000000000000000000000",
                "prj_00000000000000000000000000",
                "env_00000000000000000000000000",
            ),
            parked_request_id="prk_00000000000000000000000000",
            expected_envelope_hash="sha256:" + "0" * 64,
        )


def test_confirmed_liaison_steer_replay_completes_after_its_workflow_transition() -> None:
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    envelope: dict[str, object] = {
        "audience": "COORDINATOR_INBOX",
        "parked_request_id": "prk_00000000000000000000000000",
        "decided_payload_hash": "sha256:" + "a" * 64,
        "scope": scope.canonical_dict(),
        "confirming_principal": "operator@example.com",
        "expected_workflow_version": 7,
        "expected_plan_version": None,
        "step": {
            "tool_profile": ["metrics.read"],
            "purpose": "bounded metric read",
            "anchor_record_type": "incident",
            "anchor_record_id": "inc_00000000000000000000000000",
        },
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    accept_confirmed_liaison_steer(
        _ReplaySteerConnection(envelope),  # type: ignore[arg-type]
        scope=scope,
        workflow=object(),  # type: ignore[arg-type]  # replay must not acquire a new lease
        owner="coordinator-1",
        parked_request_id="prk_00000000000000000000000000",
        expected_envelope_hash="sha256:" + hashlib.sha256(encoded.encode()).hexdigest(),
    )
