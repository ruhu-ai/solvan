"""Run-bound independent verification policy and result persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.domain import Scope, VerificationResult, new_identifier


class VerificationAuthorizationError(RuntimeError):
    """The agent invocation, action, profile, or workflow is not authorized."""


@dataclass(frozen=True, slots=True)
class VerificationTask:
    scope: Scope
    run_id: str
    invocation_id: str
    incident_id: str
    action_id: str
    service_id: str
    service_key: str
    platform_resource: str
    graph_snapshot_id: str
    incident_class: str
    service_project_id: str
    profile_id: str
    profile_version: int
    warmup_ms: int
    observation_ms: int
    required_signals: object
    guardrails: object
    resolved_binding_ref: str
    reconciled_at: datetime
    existing_verification_id: str | None = None
    existing_verdict: str | None = None


class PostgresVerificationStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def reserve(self, *, scope: Scope, invocation_id: str, action_id: str) -> VerificationTask:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.id AS run_id, r.invocation_id, r.incident_id,
                    a.id AS action_id, i.primary_service_id AS service_id,
                    s.service_key, s.platform_resource,
                    i.production_graph_snapshot_id,
                    i.incident_class, service_node.external_project_id
                      AS service_project_id, vp.id AS profile_id,
                    vp.version AS profile_version, vp.warmup_ms,
                    vp.observation_ms, vp.required_signals_json,
                    vp.guardrails_json, er.reconciled_at,
                    b.effective_at
                  FROM solvan.agent_runs r
                  JOIN solvan.actions a
                    ON (a.organization_id, a.project_id, a.environment_id, a.id)
                     = (r.organization_id, r.project_id, r.environment_id,
                        r.action_id)
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  JOIN solvan.services s
                    ON (s.organization_id, s.project_id, s.environment_id, s.id)
                     = (i.organization_id, i.project_id, i.environment_id,
                        i.primary_service_id)
                  -- Specification 13 §4.2. Verification reads the same estate
                  -- the incident's service runs in, resolved from the frozen
                  -- graph node rather than the tenancy row.
                  JOIN solvan.production_graph_nodes service_node
                    ON (service_node.organization_id, service_node.project_id,
                        service_node.environment_id, service_node.snapshot_id)
                     = (i.organization_id, i.project_id, i.environment_id,
                        i.production_graph_snapshot_id)
                   AND service_node.node_kind = 'SERVICE'
                   AND service_node.resource_ref = s.platform_resource
                  JOIN solvan.verification_profile_bindings b
                    ON b.organization_id = a.organization_id
                   AND b.project_id = a.project_id
                   AND b.environment_id = a.environment_id
                   AND b.production_graph_snapshot_id = i.production_graph_snapshot_id
                   AND b.service_id = i.primary_service_id
                   AND b.incident_class = i.incident_class
                   AND b.profile_id = a.verification_profile_id
                   AND b.profile_version = a.verification_profile_version
                   AND b.superseded_at IS NULL AND b.effective_at <= now()
                  JOIN solvan.verification_profiles vp
                    ON (vp.organization_id, vp.project_id, vp.environment_id,
                        vp.id, vp.version)
                     = (b.organization_id, b.project_id, b.environment_id,
                        b.profile_id, b.profile_version)
                  JOIN solvan.execution_receipts er
                    ON er.organization_id = a.organization_id
                   AND er.project_id = a.project_id
                   AND er.environment_id = a.environment_id
                   AND er.action_id = a.id AND er.result = 'SUCCEEDED'
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.invocation_id = %(invocation_id)s
                    AND r.agent_key = 'verification-agent'
                    AND r.action_id = %(action_id)s
                    AND r.status IN ('DISPATCHED','RUNNING') AND r.deadline > now()
                    AND a.status = 'SUCCEEDED' AND i.state = 'VERIFYING_MITIGATION'
                    AND r.workflow_version = i.workflow_version
                    AND vp.status = 'APPROVED'
                  FOR UPDATE OF r""",
                {
                    **scope.canonical_dict(),
                    "invocation_id": invocation_id,
                    "action_id": action_id,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise VerificationAuthorizationError(
                    "verification invocation is not bound to a live action"
                )
            cursor.execute(
                """SELECT id, verdict FROM solvan.verification_runs
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND action_id = %(action_id)s
                    AND purpose = 'MITIGATION_ACTION'""",
                {**scope.canonical_dict(), "action_id": action_id},
            )
            existing = cursor.fetchone()
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'RUNNING'
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s AND status IN ('DISPATCHED','RUNNING')""",
                {**scope.canonical_dict(), "run_id": row["run_id"]},
            )
        return VerificationTask(
            scope=scope,
            run_id=str(row["run_id"]),
            invocation_id=str(row["invocation_id"]),
            incident_id=str(row["incident_id"]),
            action_id=str(row["action_id"]),
            service_id=str(row["service_id"]),
            service_key=str(row["service_key"]),
            platform_resource=str(row["platform_resource"]),
            graph_snapshot_id=str(row["production_graph_snapshot_id"]),
            incident_class=str(row["incident_class"]),
            service_project_id=str(row["service_project_id"]),
            profile_id=str(row["profile_id"]),
            profile_version=int(row["profile_version"]),
            warmup_ms=int(row["warmup_ms"]),
            observation_ms=int(row["observation_ms"]),
            required_signals=row["required_signals_json"],
            guardrails=row["guardrails_json"],
            resolved_binding_ref=(
                f"{row['production_graph_snapshot_id']}:{row['service_id']}:"
                f"{row['incident_class']}:{row['profile_id']}:v{row['profile_version']}:"
                f"{row['effective_at'].isoformat()}"
            ),
            reconciled_at=row["reconciled_at"],
            existing_verification_id=(None if existing is None else str(existing["id"])),
            existing_verdict=None if existing is None else str(existing["verdict"]),
        )

    def complete(
        self,
        *,
        task: VerificationTask,
        window_start: datetime,
        window_end: datetime,
        signal_results: list[dict[str, object]],
        synthetic_receipt_ref: str,
        result: VerificationResult,
    ) -> str:
        if task.existing_verification_id is not None:
            if task.existing_verdict != result.verdict.value:
                raise VerificationAuthorizationError("stored verification verdict changed")
            return task.existing_verification_id
        verification_id = new_identifier("ver")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.verification_runs
                  (organization_id, project_id, environment_id, id, purpose,
                   incident_id, action_id, profile_id, profile_version,
                   resolved_binding_ref, window_start, window_end,
                   signal_results_json, synthetic_receipt_ref, verdict,
                   rationale_codes, agent_run_id, completed_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(verification_id)s, 'MITIGATION_ACTION', %(incident_id)s,
                    %(action_id)s, %(profile_id)s, %(profile_version)s,
                    %(binding_ref)s, %(window_start)s, %(window_end)s,
                    %(signal_results)s, %(synthetic_ref)s, %(verdict)s,
                    %(rationale)s, %(run_id)s, now())""",
                {
                    **task.scope.canonical_dict(),
                    "verification_id": verification_id,
                    "incident_id": task.incident_id,
                    "action_id": task.action_id,
                    "profile_id": task.profile_id,
                    "profile_version": task.profile_version,
                    "binding_ref": task.resolved_binding_ref,
                    "window_start": window_start,
                    "window_end": window_end,
                    "signal_results": Jsonb(signal_results),
                    "synthetic_ref": synthetic_receipt_ref,
                    "verdict": result.verdict.value,
                    "rationale": Jsonb(list(result.rationale_codes)),
                    "run_id": task.run_id,
                },
            )
            cursor.execute(
                """UPDATE solvan.incidents SET evidence_version = evidence_version + 1,
                    updated_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(incident_id)s""",
                {**task.scope.canonical_dict(), "incident_id": task.incident_id},
            )
            if cursor.rowcount != 1:
                raise VerificationAuthorizationError("verification incident is unavailable")
        return verification_id

    def result_for_run(
        self, *, scope: Scope, run_id: str, action_id: str
    ) -> tuple[str, str] | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT v.id, v.verdict FROM solvan.verification_runs v
                  JOIN solvan.agent_runs r
                    ON (r.organization_id, r.project_id, r.environment_id, r.id)
                     = (v.organization_id, v.project_id, v.environment_id,
                        v.agent_run_id)
                  WHERE v.organization_id = %(organization_id)s
                    AND v.project_id = %(project_id)s
                    AND v.environment_id = %(environment_id)s
                    AND r.id = %(run_id)s AND r.action_id = %(action_id)s""",
                {
                    **scope.canonical_dict(),
                    "run_id": run_id,
                    "action_id": action_id,
                },
            )
            row = cursor.fetchone()
        return None if row is None else (str(row[0]), str(row[1]))
