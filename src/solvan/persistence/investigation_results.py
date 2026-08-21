"""Fenced agent callback, finding, citation, and dependency persistence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import (
    AgentCompletion,
    AgentCompletionDisposition,
    AgentCompletionRecord,
    AgentResultConflict,
    AgentSemanticStatus,
    CoordinatorAuthority,
    FindingCommit,
)
from solvan.domain import Scope, new_identifier


class PostgresInvestigationResultStore:
    """Commit only exact, current Runtime outputs and queryable citations."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._connection.transaction():
            yield

    def commit_agent_completion(
        self,
        *,
        scope: Scope,
        authority: CoordinatorAuthority,
        completion: AgentCompletion,
    ) -> AgentCompletionRecord:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._lock_incident(cursor, scope, completion.incident_id, authority)
            run = self._load_run(cursor, scope, completion)
            self._validate_exact_material(run, completion)
            if run["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT"):
                if run["output_hash"] == completion.output_hash:
                    return AgentCompletionRecord(
                        str(run["run_id"]),
                        str(run["step_id"]),
                        AgentCompletionDisposition.DUPLICATE,
                    )
                raise AgentResultConflict("terminal attempt received a different output hash")
            if run["plan_status"] != "ACCEPTED" or run["current_agent_run_id"] != run["run_id"]:
                self._mark_stale(cursor, scope, run)
                return AgentCompletionRecord(
                    str(run["run_id"]),
                    str(run["step_id"]),
                    AgentCompletionDisposition.STALE,
                    reason_code="PLAN_OR_ATTEMPT_SUPERSEDED",
                )
            if completion.output_size_bytes > int(run["max_output_bytes"]):
                self._reject(cursor, scope, run, "OUTPUT_BUDGET_EXCEEDED", "FAILED")
                return AgentCompletionRecord(
                    str(run["run_id"]),
                    str(run["step_id"]),
                    AgentCompletionDisposition.REJECTED,
                    reason_code="OUTPUT_BUDGET_EXCEEDED",
                )
            if completion.completed_at > run["deadline"]:
                self._reject(cursor, scope, run, "RUNTIME_DEADLINE_EXCEEDED", "TIMED_OUT")
                return AgentCompletionRecord(
                    str(run["run_id"]),
                    str(run["step_id"]),
                    AgentCompletionDisposition.REJECTED,
                    reason_code="RUNTIME_DEADLINE_EXCEEDED",
                )
            evidence_refs = self._all_evidence_refs(completion)
            self._require_evidence(cursor, scope, completion.incident_id, evidence_refs)
            finding_ids = tuple(
                self._insert_finding(cursor, scope, run, finding) for finding in completion.findings
            )
            step_status = (
                "SUCCEEDED"
                if completion.semantic_status is AgentSemanticStatus.SUCCEEDED
                else "FAILED"
            )
            cursor.execute(
                """UPDATE solvan.agent_runs SET status = 'SUCCEEDED',
                    output_ref = %(output_ref)s, output_hash = %(output_hash)s,
                    completed_at = %(completed_at)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(run_id)s
                    AND status IN ('CREATED','DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "run_id": run["run_id"],
                    "output_ref": completion.output_ref,
                    "output_hash": completion.output_hash,
                    "completed_at": completion.completed_at,
                },
            )
            cursor.execute(
                """UPDATE solvan.investigation_steps SET status = %(step_status)s,
                    result_ref = %(output_ref)s,
                    evidence_delta_count = %(evidence_count)s,
                    completed_at = %(completed_at)s
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(step_id)s AND current_agent_run_id = %(run_id)s
                    AND status IN ('DISPATCHED','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "step_id": run["step_id"],
                    "run_id": run["run_id"],
                    "step_status": step_status,
                    "output_ref": completion.output_ref,
                    "evidence_count": len(evidence_refs),
                    "completed_at": completion.completed_at,
                },
            )
            if step_status == "SUCCEEDED":
                self._promote_dependents(cursor, scope, str(run["plan_id"]))
                self._complete_plan_if_done(cursor, scope, str(run["plan_id"]))
            self._append_outbox(cursor, scope, run, step_status, completion.output_hash)
        return AgentCompletionRecord(
            str(run["run_id"]),
            str(run["step_id"]),
            AgentCompletionDisposition.APPLIED,
            finding_ids,
        )

    @staticmethod
    def _lock_incident(
        cursor: Any,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
    ) -> None:
        cursor.execute(
            """SELECT id FROM solvan.incidents
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND id = %(incident_id)s
                AND workflow_version = %(workflow_version)s
                AND lease_owner = %(lease_owner)s
                AND lease_token = %(lease_token)s
                AND lease_expires_at >= now() FOR UPDATE""",
            {
                **scope.canonical_dict(),
                "incident_id": incident_id,
                "workflow_version": authority.workflow_version,
                "lease_owner": authority.owner,
                "lease_token": authority.lease_token,
            },
        )
        if cursor.fetchone() is None:
            raise AgentResultConflict("incident workflow version or coordinator lease is stale")

    @staticmethod
    def _load_run(cursor: Any, scope: Scope, completion: AgentCompletion) -> dict[str, Any]:
        cursor.execute(
            """SELECT r.id AS run_id, r.incident_id, r.status, r.output_hash, r.agent_resource,
                r.agent_revision, r.workflow_version, r.input_hash, r.deadline,
                r.trace_id, r.attempt,
                (r.budget_json->>'max_output_bytes')::bigint AS max_output_bytes,
                s.id AS step_id, s.plan_id, s.current_agent_run_id,
                s.fallback_ref,
                p.status AS plan_status, p.plan_version
              FROM solvan.agent_runs r
              JOIN solvan.investigation_steps s
                ON (s.organization_id, s.project_id, s.environment_id, s.id)
                 = (r.organization_id, r.project_id, r.environment_id,
                    r.investigation_step_id)
              JOIN solvan.investigation_plans p
                ON (p.organization_id, p.project_id, p.environment_id, p.id)
                 = (s.organization_id, s.project_id, s.environment_id, s.plan_id)
              WHERE r.organization_id = %(organization_id)s
                AND r.project_id = %(project_id)s
                AND r.environment_id = %(environment_id)s
                AND r.invocation_id = %(invocation_id)s
                AND r.incident_id = %(incident_id)s
              FOR UPDATE OF r, s, p""",
            {
                **scope.canonical_dict(),
                "invocation_id": completion.invocation_id,
                "incident_id": completion.incident_id,
            },
        )
        row = cursor.fetchone()
        if row is None:
            raise AgentResultConflict("agent result has no matching durable attempt")
        return cast(dict[str, Any], row)

    @staticmethod
    def _validate_exact_material(run: dict[str, Any], completion: AgentCompletion) -> None:
        expected = (
            run["agent_resource"],
            run["agent_revision"],
            int(run["workflow_version"]),
            run["input_hash"],
            run["trace_id"],
        )
        actual = (
            completion.agent_resource,
            completion.agent_revision,
            completion.workflow_version,
            completion.input_scope_hash,
            completion.trace_id,
        )
        if actual != expected:
            raise AgentResultConflict("agent result does not match frozen attempt material")
        if completion.output_size_bytes < 1:
            raise AgentResultConflict("agent result size must be positive")
        keys = [finding.finding_key for finding in completion.findings]
        if len(keys) != len(set(keys)):
            raise AgentResultConflict("agent result contains duplicate finding keys")
        for finding in completion.findings:
            if set(finding.evidence_refs) & set(finding.contradiction_refs):
                raise AgentResultConflict("one citation cannot support and contradict a finding")

    @staticmethod
    def _all_evidence_refs(completion: AgentCompletion) -> tuple[str, ...]:
        values = set(completion.evidence_refs)
        for finding in completion.findings:
            values.update(finding.evidence_refs)
            values.update(finding.contradiction_refs)
        return tuple(sorted(values))

    @staticmethod
    def _require_evidence(
        cursor: Any, scope: Scope, incident_id: str, evidence_refs: tuple[str, ...]
    ) -> None:
        if not evidence_refs:
            return
        cursor.execute(
            """SELECT id FROM solvan.evidence_items
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND incident_id = %(incident_id)s AND id = ANY(%(evidence_refs)s)""",
            {
                **scope.canonical_dict(),
                "incident_id": incident_id,
                "evidence_refs": list(evidence_refs),
            },
        )
        found = {str(row["id"]) for row in cursor.fetchall()}
        if found != set(evidence_refs):
            raise AgentResultConflict("agent result cites missing or cross-scope evidence")

    def _insert_finding(
        self,
        cursor: Any,
        scope: Scope,
        run: dict[str, Any],
        finding: FindingCommit,
    ) -> str:
        cursor.execute(
            """SELECT id, revision FROM solvan.findings
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND incident_id = %(incident_id)s AND finding_key = %(finding_key)s
              ORDER BY revision DESC LIMIT 1 FOR UPDATE""",
            {
                **scope.canonical_dict(),
                "incident_id": run["incident_id"],
                "finding_key": finding.finding_key,
            },
        )
        previous = cursor.fetchone()
        revision = 1 if previous is None else int(previous["revision"]) + 1
        supersedes_id = None if previous is None else str(previous["id"])
        finding_id = new_identifier("fnd")
        content_hash = _finding_hash(finding)
        cursor.execute(
            """INSERT INTO solvan.findings
              (organization_id, project_id, environment_id, id, incident_id,
               agent_run_id, finding_key, revision, kind, statement,
               confidence_score, content_hash, supersedes_id)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(finding_id)s, %(incident_id)s, %(run_id)s, %(finding_key)s,
                %(revision)s, %(kind)s, %(statement)s, %(confidence)s,
                %(content_hash)s, %(supersedes_id)s)""",
            {
                **scope.canonical_dict(),
                "finding_id": finding_id,
                "incident_id": run["incident_id"],
                "run_id": run["run_id"],
                "finding_key": finding.finding_key,
                "revision": revision,
                "kind": finding.kind.value,
                "statement": finding.statement,
                "confidence": finding.confidence,
                "content_hash": content_hash,
                "supersedes_id": supersedes_id,
            },
        )
        for relationship, evidence_refs in (
            ("SUPPORTS", finding.evidence_refs),
            ("CONTRADICTS", finding.contradiction_refs),
        ):
            for evidence_id in evidence_refs:
                cursor.execute(
                    """INSERT INTO solvan.finding_evidence
                      (organization_id, project_id, environment_id, finding_id,
                       evidence_id, relationship)
                      VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                        %(finding_id)s, %(evidence_id)s, %(relationship)s)""",
                    {
                        **scope.canonical_dict(),
                        "finding_id": finding_id,
                        "evidence_id": evidence_id,
                        "relationship": relationship,
                    },
                )
        return finding_id

    @staticmethod
    def _promote_dependents(cursor: Any, scope: Scope, plan_id: str) -> None:
        cursor.execute(
            """UPDATE solvan.investigation_steps s SET status = 'READY'
              WHERE s.organization_id = %(organization_id)s
                AND s.project_id = %(project_id)s
                AND s.environment_id = %(environment_id)s
                AND s.plan_id = %(plan_id)s AND s.status = 'PLANNED'
                AND NOT EXISTS (
                  SELECT 1 FROM jsonb_array_elements_text(s.depends_on_json) dep(step_key)
                  LEFT JOIN solvan.investigation_steps required_step
                    ON required_step.organization_id = s.organization_id
                   AND required_step.project_id = s.project_id
                   AND required_step.environment_id = s.environment_id
                   AND required_step.plan_id = s.plan_id
                   AND required_step.step_key = dep.step_key
                  WHERE required_step.id IS NULL
                    OR required_step.status NOT IN ('SUCCEEDED','SKIPPED'))""",
            {**scope.canonical_dict(), "plan_id": plan_id},
        )

    @staticmethod
    def _complete_plan_if_done(cursor: Any, scope: Scope, plan_id: str) -> None:
        cursor.execute(
            """UPDATE solvan.investigation_plans p SET status = 'COMPLETED'
              WHERE p.organization_id = %(organization_id)s
                AND p.project_id = %(project_id)s
                AND p.environment_id = %(environment_id)s
                AND p.id = %(plan_id)s AND p.status = 'ACCEPTED'
                AND NOT EXISTS (
                  SELECT 1 FROM solvan.investigation_steps s
                  WHERE s.organization_id = p.organization_id
                    AND s.project_id = p.project_id
                    AND s.environment_id = p.environment_id
                    AND s.plan_id = p.id AND s.status NOT IN ('SUCCEEDED','SKIPPED'))""",
            {**scope.canonical_dict(), "plan_id": plan_id},
        )

    @staticmethod
    def _mark_stale(cursor: Any, scope: Scope, run: dict[str, Any]) -> None:
        cursor.execute(
            """UPDATE solvan.agent_runs SET status = 'STALE', completed_at = now(),
                error_class = 'PLAN_OR_ATTEMPT_SUPERSEDED'
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND id = %(run_id)s
                AND status IN ('CREATED','DISPATCHED','RUNNING')""",
            {**scope.canonical_dict(), "run_id": run["run_id"]},
        )

    def _reject(
        self,
        cursor: Any,
        scope: Scope,
        run: dict[str, Any],
        reason_code: str,
        run_status: str,
    ) -> None:
        cursor.execute(
            """UPDATE solvan.agent_runs SET status = %(run_status)s,
                error_class = %(reason_code)s, completed_at = now()
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s AND id = %(run_id)s""",
            {
                **scope.canonical_dict(),
                "run_id": run["run_id"],
                "run_status": run_status,
                "reason_code": reason_code,
            },
        )
        retry_with_fallback = int(run["attempt"]) == 1 and run["fallback_ref"] is not None
        cursor.execute(
            """UPDATE solvan.investigation_steps SET
                status = %(step_status)s,
                current_agent_run_id = CASE WHEN %(retry)s THEN NULL
                  ELSE current_agent_run_id END,
                started_at = CASE WHEN %(retry)s THEN NULL ELSE started_at END,
                completed_at = CASE WHEN %(retry)s THEN NULL ELSE now() END,
                result_ref = %(result_ref)s
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s AND id = %(step_id)s
                AND current_agent_run_id = %(run_id)s""",
            {
                **scope.canonical_dict(),
                "step_id": run["step_id"],
                "run_id": run["run_id"],
                "step_status": "READY" if retry_with_fallback else "FAILED",
                "retry": retry_with_fallback,
                "result_ref": f"runtime-error:{reason_code}",
            },
        )
        self._append_outbox(cursor, scope, run, "FAILED", reason_code)

    @staticmethod
    def _append_outbox(
        cursor: Any,
        scope: Scope,
        run: dict[str, Any],
        step_status: str,
        result_key: str,
    ) -> None:
        cursor.execute(
            """INSERT INTO solvan.outbox_events
              (organization_id, project_id, environment_id, id, aggregate_type,
               aggregate_id, aggregate_version, topic, event_type, payload_json,
               idempotency_key)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                %(event_id)s, 'INCIDENT', %(incident_id)s, %(workflow_version)s,
                'agent-results', 'InvestigationStepCompleted', %(payload)s,
                %(idempotency_key)s) ON CONFLICT DO NOTHING""",
            {
                **scope.canonical_dict(),
                "event_id": new_identifier("evt"),
                "incident_id": run["incident_id"],
                "workflow_version": run["workflow_version"],
                "payload": Jsonb(
                    {
                        "incident_id": run["incident_id"],
                        "plan_id": run["plan_id"],
                        "plan_version": run["plan_version"],
                        "step_id": run["step_id"],
                        "run_id": run["run_id"],
                        "status": step_status,
                    }
                ),
                "idempotency_key": f"agent-result:{run['run_id']}:{result_key}",
            },
        )


def _finding_hash(finding: FindingCommit) -> str:
    value = json.dumps(
        {
            "finding_key": finding.finding_key,
            "kind": finding.kind.value,
            "statement": finding.statement,
            "evidence_refs": sorted(finding.evidence_refs),
            "confidence": finding.confidence,
            "contradiction_refs": sorted(finding.contradiction_refs),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
