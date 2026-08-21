"""Token-fenced reservation of Incident Supervisor Runtime attempts."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict
from typing import Any

from psycopg import Connection
from psycopg.errors import UndefinedTable
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import CoordinatorAuthority, RuntimeDispatch
from solvan.domain import Scope, StepBudget, new_identifier
from solvan.persistence.runtime_dispatch_projection import supervisor_dispatch
from solvan.persistence.runtime_types import RuntimeRunBudgetExhausted, RuntimeRunConflict


class RuntimeSupervisorReservationMixin:
    _connection: Connection[Any]

    def reserve_supervisor(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        agent_resource: str,
        agent_revision: str,
    ) -> RuntimeDispatch | None:
        budget = StepBudget(
            deadline_ms=300_000,
            max_tool_calls=0,
            max_output_bytes=64_000,
            max_model_calls=6,
            max_replans=1,
        )
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT i.incident_class, i.severity, i.detected_at,
                    i.production_graph_snapshot_id, i.workflow_version,
                    i.display_id, s.id AS service_id, s.service_key, s.platform_kind,
                    s.platform_resource
                  FROM solvan.incidents i
                  JOIN solvan.services s
                    ON (s.organization_id, s.project_id, s.environment_id, s.id)
                     = (i.organization_id, i.project_id, i.environment_id,
                        i.primary_service_id)
                  WHERE i.organization_id = %(organization_id)s
                    AND i.project_id = %(project_id)s
                    AND i.environment_id = %(environment_id)s
                    AND i.id = %(incident_id)s AND i.state = 'INVESTIGATING'
                    AND i.workflow_version = %(workflow_version)s
                    AND i.lease_owner = %(lease_owner)s
                    AND i.lease_token = %(lease_token)s
                    AND i.lease_expires_at >= now() FOR UPDATE OF i""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "workflow_version": authority.workflow_version,
                    "lease_owner": authority.owner,
                    "lease_token": authority.lease_token,
                },
            )
            incident = cursor.fetchone()
            if incident is None:
                raise RuntimeRunConflict("supervisor dispatch has no current incident authority")
            logical_step_key = f"incident:{incident_id}:supervisor:{authority.workflow_version}"
            cursor.execute(
                """SELECT * FROM solvan.agent_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND logical_step_key = %(logical_step_key)s
                  ORDER BY attempt DESC LIMIT 1 FOR UPDATE""",
                {**scope.canonical_dict(), "logical_step_key": logical_step_key},
            )
            existing = cursor.fetchone()
            context = {
                "incident_class": str(incident["incident_class"]),
                "severity": str(incident["severity"]),
                "detected_at": incident["detected_at"].isoformat(),
                "service_id": str(incident["service_id"]),
                "service_key": str(incident["service_key"]),
                "platform_kind": str(incident["platform_kind"]),
                "platform_resource": str(incident["platform_resource"]),
                "graph_snapshot_id": str(incident["production_graph_snapshot_id"]),
                "available_agents": {
                    "evidence-agent": "scope:primary-service",
                    "infrastructure-agent": "scope:primary-service",
                },
            }
            # The target Liaison schema is intentionally absent from the
            # release-only profile.  When present, carry only the exact,
            # previously coordinator-fenced Steer into this new supervisor
            # generation.  It is instruction data for the governed Planner,
            # never an authority grant or a direct Relay selector.
            try:
                cursor.execute(
                    """SELECT parked.id,parked.decided_payload_hash,parked.decided_payload_json
                         FROM solvan_liaison.liaison_parked_requests parked
                         JOIN solvan_liaison.liaison_operation_ledger ledger
                           ON (ledger.organization_id,ledger.project_id,ledger.environment_id,
                               ledger.idempotency_key)=
                              (parked.organization_id,parked.project_id,parked.environment_id,
                               parked.id)
                        WHERE parked.organization_id=%(organization_id)s
                          AND parked.project_id=%(project_id)s
                          AND parked.environment_id=%(environment_id)s
                          AND parked.kind='STEER_CONFIRMATION' AND parked.status='ANSWERED'
                          AND parked.expected_workflow_version=%(prior_workflow_version)s
                          AND ledger.operation='liaison.steer.submit' AND ledger.status='COMPLETED'
                          AND (parked.decided_payload_json->>'anchor_record_type')='incident'
                          AND (parked.decided_payload_json->>'anchor_record_id') IN
                              (%(incident_id)s,%(display_id)s)
                        ORDER BY parked.answered_at DESC,parked.id DESC LIMIT 1""",
                    {
                        **scope.canonical_dict(),
                        "prior_workflow_version": authority.workflow_version - 1,
                        "incident_id": incident_id,
                        "display_id": str(incident["display_id"]),
                    },
                )
                steer = cursor.fetchone()
            except UndefinedTable:
                steer = None
            if steer is not None:
                payload = steer["decided_payload_json"]
                if not isinstance(payload, dict):
                    raise RuntimeRunConflict("accepted Liaison Steer has malformed typed payload")
                context["operator_steer"] = {
                    "parked_request_id": str(steer["id"]),
                    "decided_payload_hash": str(steer["decided_payload_hash"]),
                    "step": payload,
                    "directive": (
                        "Plan the confirmed bounded read exactly as supplied; do not widen its "
                        "tool profile, service anchor, budget, or dependencies."
                    ),
                }
            if existing is not None and existing["status"] in {
                "DISPATCHED",
                "RUNNING",
                "SUCCEEDED",
            }:
                return None
            if existing is not None:
                if existing["status"] == "CREATED":
                    return supervisor_dispatch(scope, existing, context, budget)
                maximum_attempts = 1 + budget.max_replans
                if int(existing["attempt"]) >= maximum_attempts:
                    raise RuntimeRunBudgetExhausted(
                        "incident Supervisor exhausted its durable replan budget"
                    )
                attempt = int(existing["attempt"]) + 1
            else:
                attempt = 1
            run_id = new_identifier("run")
            invocation_id = new_identifier("inv")
            trace_id = secrets.token_hex(16)
            span_id = secrets.token_hex(8)
            material = {
                "scope": scope.canonical_dict(),
                "incident_id": incident_id,
                "workflow_version": authority.workflow_version,
                "agent_resource": agent_resource,
                "agent_revision": agent_revision,
                "context": context,
                "budget": asdict(budget),
            }
            input_hash = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                  (organization_id, project_id, environment_id, id, incident_id,
                   logical_step_key, agent_key, agent_resource, agent_revision,
                   invocation_id, workflow_version, attempt, status, deadline,
                   budget_json, input_ref, input_hash, trace_id, span_id)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(run_id)s, %(incident_id)s, %(logical_step_key)s,
                    'incident-supervisor', %(agent_resource)s, %(agent_revision)s,
                    %(invocation_id)s, %(workflow_version)s, %(attempt)s, 'CREATED',
                    now() + interval '300 seconds', %(budget)s,
                    %(input_ref)s, %(input_hash)s, %(trace_id)s, %(span_id)s)
                  RETURNING *""",
                {
                    **scope.canonical_dict(),
                    "run_id": run_id,
                    "incident_id": incident_id,
                    "logical_step_key": logical_step_key,
                    "agent_resource": agent_resource,
                    "agent_revision": agent_revision,
                    "invocation_id": invocation_id,
                    "workflow_version": authority.workflow_version,
                    "attempt": attempt,
                    "budget": Jsonb(asdict(budget)),
                    "input_ref": f"db://solvan/incidents/{incident_id}",
                    "input_hash": input_hash,
                    "trace_id": trace_id,
                    "span_id": span_id,
                },
            )
            row = cursor.fetchone()
            assert row is not None
            return supervisor_dispatch(scope, row, context, budget)
