"""Coordinator acceptance of one confirmed, bounded Liaison Steer."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from psycopg import Connection

from solvan.domain import Scope
from solvan.persistence import AggregateType, PostgresWorkflowStore, TransitionWrite


def load_confirmed_liaison_steer(
    connection: Connection[Any],
    *,
    scope: Scope,
    parked_request_id: str,
    expected_envelope_hash: str,
) -> dict[str, object]:
    """Load and revalidate the one typed Liaison submission for an inbox event."""

    if not parked_request_id.startswith("prk_"):
        raise RuntimeError("Liaison Steer inbox event has an invalid request identifier")
    row = connection.execute(
        """SELECT ledger.request_hash,ledger.response_ref,parked.status,
                  parked.decided_payload_hash,parked.decided_payload_json
             FROM solvan_liaison.liaison_operation_ledger ledger
             JOIN solvan_liaison.liaison_parked_requests parked
               ON (parked.organization_id,parked.project_id,parked.environment_id,parked.id)=
                  (ledger.organization_id,ledger.project_id,ledger.environment_id,
                   %(parked_request_id)s)
            WHERE ledger.organization_id=%(organization_id)s AND ledger.project_id=%(project_id)s
              AND ledger.environment_id=%(environment_id)s
              AND ledger.operation='liaison.steer.submit'
              AND ledger.idempotency_key=%(parked_request_id)s
              -- ParkedRequestStore uses ANSWERED for a confirmed Steer.  The
              -- accepted decision is represented by the paired completed
              -- coordinator submission ledger entry, not by inventing a
              -- second parked-request status.
              AND ledger.status='COMPLETED' AND parked.status='ANSWERED'""",
        {**scope.canonical_dict(), "parked_request_id": parked_request_id},
    ).fetchone()
    if row is None:
        raise RuntimeError("Liaison Steer inbox event has no accepted submission")
    try:
        stored = json.loads(str(row[1]))
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Liaison Steer submission projection is malformed") from error
    envelope = stored.get("envelope") if isinstance(stored, dict) else None
    if not isinstance(envelope, dict):
        raise RuntimeError("Liaison Steer submission has no typed envelope")
    actual_hash = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
    )
    if actual_hash != expected_envelope_hash:
        raise RuntimeError("Liaison Steer inbox envelope hash is stale")
    if envelope.get("audience") != "COORDINATOR_INBOX":
        raise RuntimeError("Liaison Steer grant is not addressed to the coordinator")
    if envelope.get("parked_request_id") != parked_request_id:
        raise RuntimeError("Liaison Steer grant request binding is stale")
    if envelope.get("decided_payload_hash") != row[3] or row[0] != row[3]:
        raise RuntimeError("Liaison Steer decision hash is stale")
    step = envelope.get("step")
    if not isinstance(step, dict):
        raise RuntimeError("Liaison Steer has no typed step")
    profile = step.get("tool_profile")
    if (
        not isinstance(profile, list)
        or not profile
        or not set(map(str, profile))
        <= {"metrics.read", "logs.read", "traces.read", "config.read", "inventory.read"}
    ):
        raise RuntimeError("Liaison Steer requested an unavailable tool profile")
    if envelope.get("scope") != scope.canonical_dict():
        raise RuntimeError("Liaison Steer scope binding is stale")
    if not isinstance(envelope.get("confirming_principal"), str):
        raise RuntimeError("Liaison Steer has no confirming principal")
    if not isinstance(envelope.get("expected_workflow_version"), int):
        raise RuntimeError("Liaison Steer has no workflow-version fence")
    expected_plan_version = envelope.get("expected_plan_version")
    if expected_plan_version is not None and not isinstance(expected_plan_version, int):
        raise RuntimeError("Liaison Steer has an invalid plan-version fence")
    return envelope


def accept_confirmed_liaison_steer(
    connection: Connection[Any],
    *,
    scope: Scope,
    workflow: PostgresWorkflowStore,
    owner: str,
    parked_request_id: str,
    expected_envelope_hash: str,
) -> None:
    """Accept a Steer by appending a fenced investigation replan transition."""

    envelope = load_confirmed_liaison_steer(
        connection,
        scope=scope,
        parked_request_id=parked_request_id,
        expected_envelope_hash=expected_envelope_hash,
    )
    step = envelope["step"]
    assert isinstance(step, dict)
    principal = str(envelope["confirming_principal"])
    if not _holds_live_operator_role(connection, scope=scope, principal=principal):
        raise RuntimeError("Liaison Steer confirmer no longer holds an operator role")

    anchor_type = step.get("anchor_record_type")
    anchor_id = step.get("anchor_record_id")
    if anchor_type != "incident" or not isinstance(anchor_id, str):
        raise RuntimeError("Liaison Steer is not anchored to an incident")
    expected_workflow_version = envelope["expected_workflow_version"]
    assert isinstance(expected_workflow_version, int)
    expected_plan_version = envelope.get("expected_plan_version")
    if expected_plan_version is not None:
        assert isinstance(expected_plan_version, int)
    incident = connection.execute(
        """SELECT i.id,i.state,i.workflow_version,
                  (SELECT p.plan_version FROM solvan.investigation_plans p
                    WHERE p.organization_id=i.organization_id AND p.project_id=i.project_id
                      AND p.environment_id=i.environment_id AND p.incident_id=i.id
                      AND p.status='ACCEPTED'
                    ORDER BY p.plan_version DESC LIMIT 1) AS plan_version
             FROM solvan.incidents i
            WHERE i.organization_id=%(organization_id)s AND i.project_id=%(project_id)s
              AND i.environment_id=%(environment_id)s
              AND (i.id=%(anchor_id)s OR i.display_id=%(anchor_id)s)""",
        {**scope.canonical_dict(), "anchor_id": anchor_id},
    ).fetchone()
    if incident is None:
        raise RuntimeError("Liaison Steer incident anchor is no longer addressable")
    incident_id = str(incident[0])

    transition_key = f"LIAISON_STEER_ACCEPTED:{parked_request_id}"
    replay = connection.execute(
        """SELECT to_workflow_version FROM solvan.state_transitions
             WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
               AND environment_id=%(environment_id)s AND entity_type='INCIDENT'
               AND entity_id=%(incident_id)s AND transition_key=%(transition_key)s""",
        {**scope.canonical_dict(), "incident_id": incident_id, "transition_key": transition_key},
    ).fetchone()
    if replay is not None:
        if int(replay[0]) != expected_workflow_version + 1:
            raise RuntimeError("Liaison Steer replay has an invalid workflow transition")
        return
    if str(incident[1]) != "INVESTIGATING":
        raise RuntimeError("Liaison Steer incident no longer permits investigation")
    if int(incident[2]) != expected_workflow_version:
        raise RuntimeError("Liaison Steer workflow version is stale")
    current_plan_version = None if incident[3] is None else int(incident[3])
    if current_plan_version != expected_plan_version:
        raise RuntimeError("Liaison Steer plan version is stale")

    with workflow.transaction():
        lease = workflow.acquire_lease(
            scope=scope,
            aggregate_type=AggregateType.INCIDENT,
            entity_id=incident_id,
            owner=owner,
            lease_ttl_ms=60_000,
        )
        if lease is None or lease.workflow_version != expected_workflow_version:
            raise RuntimeError("Liaison Steer could not acquire the expected incident lease")
        try:
            workflow.commit_transition(
                scope=scope,
                lease=lease,
                transition=TransitionWrite(
                    from_state="INVESTIGATING",
                    to_state="INVESTIGATING",
                    transition_key=transition_key,
                    actor_type="COORDINATOR",
                    actor_id=owner,
                    reason_code="LIAISON_STEER_ACCEPTED",
                    rationale_summary=(
                        "A live operator confirmed one bounded, read-only Liaison Steer; "
                        "the coordinator advanced the investigation generation for replan."
                    ),
                    evidence_refs=(f"db://solvan_liaison/steer-submissions/{parked_request_id}",),
                ),
            )
        finally:
            workflow.release_lease(scope=scope, lease=lease)


def _holds_live_operator_role(connection: Connection[Any], *, scope: Scope, principal: str) -> bool:
    row = connection.execute(
        """SELECT EXISTS (
             SELECT 1 FROM solvan.actor_role_bindings
              WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                AND environment_id=%(environment_id)s AND principal=%(principal)s
                AND role='OPERATOR' AND (expires_at IS NULL OR expires_at > now()))""",
        {**scope.canonical_dict(), "principal": principal},
    ).fetchone()
    return bool(row and row[0])
