"""Read-only incident detail projection for the operator console."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from apps.api.incident_evidence import _agent_council, _causal_chain, _evidence_index
from apps.api.projection_format import _age, _short
from solvan.domain import Scope
from solvan.persistence import PostgresApprovalStore


def _scope_parameters(scope: Scope) -> dict[str, str]:
    return {
        "organization_id": scope.organization_id,
        "project_id": scope.project_id,
        "environment_id": scope.environment_id,
    }


def _json_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def incident_projection(
    connection: Connection[Any], scope: Scope, incident: dict[str, Any]
) -> dict[str, Any]:
    parameters = {**_scope_parameters(scope), "incident_id": incident["id"]}
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT p.plan_version, p.objective, p.status AS plan_status,
                s.step_key, s.purpose, s.agent_key, s.agent_revision,
                s.status, s.depends_on_json, s.budget_json, s.evidence_delta_count,
                r.trace_id
              FROM solvan.investigation_plans p
              LEFT JOIN solvan.investigation_steps s
                ON (s.organization_id, s.project_id, s.environment_id, s.plan_id)
                 = (p.organization_id, p.project_id, p.environment_id, p.id)
              LEFT JOIN solvan.agent_runs r
                ON (r.organization_id, r.project_id, r.environment_id, r.id)
                 = (s.organization_id, s.project_id, s.environment_id,
                    s.current_agent_run_id)
              WHERE p.organization_id = %(organization_id)s
                AND p.project_id = %(project_id)s
                AND p.environment_id = %(environment_id)s
                AND p.incident_id = %(incident_id)s
                AND p.plan_version = (SELECT max(plan_version)
                  FROM solvan.investigation_plans p2
                  WHERE p2.organization_id = p.organization_id
                    AND p2.project_id = p.project_id
                    AND p2.environment_id = p.environment_id
                    AND p2.incident_id = p.incident_id)
              ORDER BY s.ordinal""",
            parameters,
        )
        plan_rows = cursor.fetchall()
        cursor.execute(
            """SELECT f.id, f.kind, f.statement, f.confidence_score,
                array_remove(array_agg(fe.evidence_id), NULL) AS evidence_ids
              FROM solvan.findings f
              LEFT JOIN solvan.finding_evidence fe
                ON (fe.organization_id, fe.project_id, fe.environment_id, fe.finding_id)
                 = (f.organization_id, f.project_id, f.environment_id, f.id)
              WHERE f.organization_id = %(organization_id)s
                AND f.project_id = %(project_id)s
                AND f.environment_id = %(environment_id)s
                AND f.incident_id = %(incident_id)s
              GROUP BY f.organization_id, f.project_id, f.environment_id, f.id,
                f.kind, f.statement, f.confidence_score, f.created_at
              ORDER BY f.created_at""",
            parameters,
        )
        findings = cursor.fetchall()
        cursor.execute(
            """SELECT * FROM solvan.hypotheses
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND incident_id = %(incident_id)s ORDER BY revision, id""",
            parameters,
        )
        hypotheses = cursor.fetchall()
        cursor.execute(
            """SELECT a.*, p.policy_version, p.decision AS policy_decision,
                e.id AS receipt_id, e.result AS receipt_result
              FROM solvan.actions a
              JOIN solvan.policy_decisions p
                ON (p.organization_id, p.project_id, p.environment_id, p.id)
                 = (a.organization_id, a.project_id, a.environment_id,
                    a.policy_decision_id)
              LEFT JOIN solvan.execution_receipts e
                ON (e.organization_id, e.project_id, e.environment_id, e.action_id)
                 = (a.organization_id, a.project_id, a.environment_id, a.id)
              WHERE a.organization_id = %(organization_id)s
                AND a.project_id = %(project_id)s
                AND a.environment_id = %(environment_id)s
                AND a.incident_id = %(incident_id)s
              ORDER BY a.created_at, e.attempt DESC""",
            parameters,
        )
        action_rows = cursor.fetchall()
        cursor.execute(
            """SELECT * FROM solvan.verification_runs
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND incident_id = %(incident_id)s
              ORDER BY completed_at DESC LIMIT 1""",
            parameters,
        )
        verification = cursor.fetchone()
        cursor.execute(
            """SELECT from_state, to_state, actor_type, actor_id, reason_code,
                rationale_summary, occurred_at, to_workflow_version
              FROM solvan.state_transitions
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND entity_type = 'INCIDENT' AND entity_id = %(incident_id)s
              ORDER BY occurred_at, to_workflow_version""",
            parameters,
        )
        transitions = cursor.fetchall()
        cursor.execute(
            """SELECT id, source_kind, source_resource, window_start, window_end,
                classification, redaction_manifest_ref, freshness_expires_at,
                content_ref
              FROM solvan.evidence_items
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND incident_id = %(incident_id)s
              ORDER BY observed_at""",
            parameters,
        )
        evidence_rows = cursor.fetchall()
        cursor.execute(
            """SELECT s.id AS selection_id,s.guidance_key,s.guidance_version,
                      s.guidance_hash,s.profile_key,s.profile_version,s.selection_role,
                      d.display_name,sr.step_key,sr.status,sr.predicate_key,
                      sr.predicate_version,sr.cited_records_json,sr.reason_code,
                      gs.title,gs.step_kind,
                      coalesce(array_agg(gstc.tool_call_id)
                        FILTER (WHERE gstc.tool_call_id IS NOT NULL),'{}') AS tool_call_ids
                 FROM solvan_operability.guidance_selections s
                 JOIN solvan.agent_runs ar ON
                   (ar.organization_id,ar.project_id,ar.environment_id,ar.id)=
                   (s.organization_id,s.project_id,s.environment_id,s.agent_run_id)
                 JOIN solvan_operability.guidance_definitions d ON
                   (d.organization_id,d.project_id,d.environment_id,d.guidance_key)=
                   (s.organization_id,s.project_id,s.environment_id,s.guidance_key)
                 LEFT JOIN solvan_operability.guidance_step_runs sr ON
                   (sr.organization_id,sr.project_id,sr.environment_id,sr.selection_id)=
                   (s.organization_id,s.project_id,s.environment_id,s.id)
                 LEFT JOIN solvan_operability.guidance_steps gs ON
                   (gs.organization_id,gs.project_id,gs.environment_id,gs.guidance_key,
                    gs.guidance_version,gs.step_key)=
                   (s.organization_id,s.project_id,s.environment_id,s.guidance_key,
                    s.guidance_version,sr.step_key)
                 LEFT JOIN solvan_operability.guidance_step_tool_calls gstc ON
                   (gstc.organization_id,gstc.project_id,gstc.environment_id,
                    gstc.step_run_id)=
                   (sr.organization_id,sr.project_id,sr.environment_id,sr.id)
                WHERE ar.organization_id=%(organization_id)s
                  AND ar.project_id=%(project_id)s
                  AND ar.environment_id=%(environment_id)s
                  AND ar.incident_id=%(incident_id)s AND s.selection_role='PRIMARY'
                GROUP BY s.id,s.guidance_key,s.guidance_version,s.guidance_hash,
                         s.profile_key,s.profile_version,s.selection_role,s.selected_at,
                         d.display_name,sr.id,sr.step_key,sr.status,sr.predicate_key,
                         sr.predicate_version,sr.cited_records_json,sr.reason_code,
                         gs.title,gs.step_kind,gs.ordinal
                ORDER BY s.selected_at DESC,gs.ordinal LIMIT 100""",
            parameters,
        )
        guidance_rows = cursor.fetchall()

    actions: list[dict[str, Any]] = []
    seen_actions: set[str] = set()
    approval_store = PostgresApprovalStore(connection)
    for row in action_rows:
        action_id = str(row["id"])
        if action_id in seen_actions:
            continue
        seen_actions.add(action_id)
        digest: str | None = None
        if row["requires_approval"] and row["status"] in {
            "AWAITING_APPROVAL",
            "AUTHORIZED",
        }:
            digest = approval_store.review(scope=scope, action_id=action_id).action_digest
        payload = row["payload_json"] if isinstance(row["payload_json"], dict) else {}
        expected_effect = (
            row["expected_effect_json"] if isinstance(row["expected_effect_json"], dict) else {}
        )
        rollback = row["rollback_plan_json"] if isinstance(row["rollback_plan_json"], dict) else {}
        known_good = payload.get("known_good_revision")
        if row["action_type"] == "PAYMENTS_POOL_RECYCLE":
            name = "Recycle payments connection pool"
            change = "Drain and recreate only the registered application DB pool."
        else:
            name = f"Rollback payments traffic to {known_good}"
            change = f"Move 100% traffic from {row['expected_target_version']} to {known_good}."
        actions.append(
            {
                "id": action_id,
                "name": name,
                "status": str(row["status"]),
                "phase": str(row["status"]).replace("_", " ").title(),
                "target": str(row["target_key"]),
                "change": change,
                "risk": f"{row['risk_class']} · "
                + ("human approval" if row["requires_approval"] else "standing authority"),
                "blast_radius": "one registered service target",
                "policy": str(row["policy_version"]),
                "receipt": None
                if row["receipt_id"] is None
                else f"{row['receipt_id']} · {row['receipt_result']}",
                "verification": (
                    f"{row['verification_profile_id']} v{row['verification_profile_version']}"
                ),
                "digest": digest,
                "expected_version": (
                    f"{row['expected_target_version']} · epoch {row['expected_target_epoch']}"
                ),
                "expected_effect": str(expected_effect),
                "expected_effect_hash": str(row["expected_effect_hash"]),
                "evidence_version": (
                    f"incident evidence {row['evidence_version']} · {row['policy_version']}"
                ),
                "expires": row["expires_at"].astimezone(UTC).isoformat(),
                "rollback_plan": str(rollback),
            }
        )

    validated = [row for row in findings if row["kind"] == "OBSERVATION"]
    inferred = [row for row in findings if row["kind"] == "INFERENCE"]

    def finding_view(row: dict[str, Any]) -> dict[str, Any]:
        citations = [str(item) for item in (row["evidence_ids"] or [])]
        return {
            "title": str(row["statement"])[:100],
            "statement": str(row["statement"]),
            "source": "Stored finding",
            "citations": citations,
        }

    confirmed = next((row for row in hypotheses if row["status"] == "CONFIRMED"), None)
    latest_verified = "No independent verification result yet."
    if verification is not None:
        latest_verified = (
            f"{verification['verdict']} at "
            f"{verification['completed_at'].astimezone(UTC).isoformat()}."
        )
    awaiting = next((row for row in actions if row["status"] == "AWAITING_APPROVAL"), None)
    owner = (
        f"Reliability Case {incident['case_display_id']}"
        if incident["case_display_id"] is not None
        else "Durable incident coordinator"
    )
    plan_version = int(plan_rows[0]["plan_version"]) if plan_rows else 0
    agent_council = _agent_council(plan_rows, actions, verification)
    causal_chain = _causal_chain(incident, confirmed, actions, verification)
    evidence_index = _evidence_index(list(evidence_rows))

    # Impact is reported per observed signal. Where nothing has been observed
    # the list is empty and the console falls back to the single summary line;
    # it never invents a measurement to fill the shape.
    impact_lines = [
        {
            "metric": item["kind"].title(),
            "scope": item["source"],
            "detail": item["window"],
            "citation": item["ref"],
        }
        for item in evidence_index
        if item["kind"] in {"metric", "log", "trace"}
    ]
    mitigated_at = next(
        (row["occurred_at"] for row in transitions if row["to_state"] == "MITIGATED"), None
    )
    customer_window = (
        f"Impact has been open for {_age(incident['detected_at'])} and is not yet closed."
        if mitigated_at is None
        else "Impact ran "
        f"{_duration((mitigated_at - incident['detected_at']).total_seconds())}, from "
        f"{incident['detected_at'].astimezone(UTC).strftime('%H:%M:%S')} to "
        f"{mitigated_at.astimezone(UTC).strftime('%H:%M:%S')} UTC."
    )
    lease = "Unleased"
    if incident["lease_owner"] is not None and incident["lease_expires_at"] is not None:
        remaining = (incident["lease_expires_at"] - datetime.now(UTC)).total_seconds()
        lease = (
            f"Expired · {incident['lease_owner']}"
            if remaining <= 0
            else f"Healthy · {_duration(remaining)} remaining"
        )
    versions = [int(row["to_workflow_version"]) for row in transitions]
    return {
        "id": str(incident["display_id"]),
        "machine_id": str(incident["id"]),
        "title": (
            f"{incident['incident_class'].replace('_', ' ').title()} on {incident['service_key']}"
        ),
        "severity": str(incident["severity"]),
        "service": str(incident["service_key"]),
        "state": str(incident["state"]),
        "owner": owner,
        "age": _age(incident["detected_at"]),
        "next_action": (
            "Review exact approval" if awaiting is not None else "Continue durable workflow"
        ),
        "impact_summary": (
            f"{incident['severity']} · {incident['incident_class'].replace('_', ' ').lower()}"
        ),
        "waiting_on_human": awaiting is not None,
        "environment": f"{incident['environment_name']} · {incident['region']}",
        "workflow_version": int(incident["workflow_version"]),
        "detected_at": incident["detected_at"].astimezone(UTC).isoformat(),
        "agent_council": agent_council,
        "causal_chain": causal_chain,
        "brief": {
            "situation": f"Incident is committed in {incident['state']} state.",
            "impact": f"{incident['severity']} {incident['incident_class'].replace('_', ' ')}.",
            "impact_lines": impact_lines,
            "customer_window": customer_window,
            # Data-loss is a claim, not a default. It is stated only when an
            # independent verification has adjudicated recovery.
            "data_loss": (
                ""
                if verification is None or str(verification["verdict"]) != "PASSED"
                else "Independent verification passed; no unreconciled effect was observed."
            ),
            "last_verified": latest_verified,
            "root_cause": (
                "Not yet confirmed."
                if confirmed is None
                else f"Confirmed: {confirmed['statement']}"
            ),
            "attention": (
                "No human approval is currently pending."
                if awaiting is None
                else f"Exact approval required for {awaiting['id']}."
            ),
            "next": owner,
            "freshness": f"Workflow version {incident['workflow_version']}",
            "citations": [
                _short(item) for row in validated for item in (row["evidence_ids"] or [])
            ][:5],
            "memories": [],
        },
        "evidence_index": evidence_index,
        "feed": {
            "sequence": f"v{min(versions)} to v{max(versions)}" if versions else "none",
            "last_event": max(versions) if versions else 0,
            "lease": lease,
        },
        "plan": {
            "version": plan_version,
            "progress": (
                "No accepted plan yet"
                if not plan_rows
                else f"{sum(row['status'] == 'SUCCEEDED' for row in plan_rows)} completed"
            ),
            "steps": [
                {
                    "marker": "✓" if row["status"] == "SUCCEEDED" else "~",
                    "name": str(row["step_key"] or "pending"),
                    "purpose": str(row["purpose"] or row["objective"]),
                    "agent": str(row["agent_key"] or "Coordinator"),
                    "status": str(row["status"] or row["plan_status"]),
                    "dependencies": ", ".join(
                        str(item) for item in _json_list(row["depends_on_json"])
                    )
                    or "none",
                    "budget": str(row["budget_json"] or {}),
                    "evidence_delta": f"+{row['evidence_delta_count'] or 0}",
                    "trace": _short(row["trace_id"] or "not started"),
                }
                for row in plan_rows
            ],
        },
        "guidance": _guidance_view(list(guidance_rows)),
        "findings": {
            "validated": [finding_view(row) for row in validated],
            "inferred": [finding_view(row) for row in inferred],
        },
        "hypotheses": [
            {
                "state": str(row["status"]),
                "label": str(row["statement"]),
                "confidence": "policy-confirmed" if row["status"] == "CONFIRMED" else "candidate",
                "score": "n/a" if row["confidence_score"] is None else str(row["confidence_score"]),
                "rule": f"{row['confirmation_rule_id']} v{row['confirmation_rule_version']}",
            }
            for row in hypotheses
        ],
        "actions": actions,
        "phase_rail": _phase_rail(
            list(transitions),
            detected_at=incident["detected_at"],
            current_state=str(incident["state"]),
        ),
        "verification": _verification_view(verification),
        "timeline": [
            {
                "time": row["occurred_at"].astimezone(UTC).strftime("%H:%M:%S"),
                "actor": f"{row['actor_type']} · {row['actor_id']}",
                "event": str(row["rationale_summary"]),
                "state": f"{row['from_state']} → {row['to_state']}",
                # The agent tone means a model was executing. The coordinator,
                # the policy engine, and a human are not models, so a
                # deterministic transition never wears it.
                "kind": "success"
                if row["to_state"] in {"MITIGATED", "RESOLVED"}
                else "warning"
                if row["to_state"] in {"ESCALATED", "AWAITING_APPROVAL"}
                else "agent"
                if row["actor_type"] == "AGENT"
                else "info",
            }
            for row in transitions
        ],
    }


def _guidance_view(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    selected = rows[0]
    selection_id = selected["selection_id"]
    exact = [row for row in rows if row["selection_id"] == selection_id]
    return {
        "selection_id": str(selection_id),
        "revision": f"{selected['guidance_key']}@{selected['guidance_version']}",
        "name": str(selected["display_name"]),
        "role": str(selected["selection_role"]),
        "revision_hash": str(selected["guidance_hash"]),
        "profile": f"{selected['profile_key']}@{selected['profile_version']}",
        "steps": [
            {
                "key": str(row["step_key"]),
                "title": str(row["title"]),
                "kind": str(row["step_kind"]),
                "status": str(row["status"]),
                "predicate": f"{row['predicate_key']}@{row['predicate_version']}",
                "reason": None if row["reason_code"] is None else str(row["reason_code"]),
                "citations": [str(item) for item in (row["cited_records_json"] or [])],
                "tool_receipts": [str(item) for item in (row["tool_call_ids"] or [])],
            }
            for row in exact
            if row["step_key"] is not None
        ],
    }


#: The product loop, in order. Approval wait is deliberately its own phase:
#: specification 08 section 11 requires it to be reported as its own duration
#: rather than folded into mitigation, so a slow human is never mistaken for a
#: slow system.
_PHASE_OF_STATE: dict[str, str] = {
    "DETECTED": "Detect",
    "TRIAGING": "Investigate",
    "INVESTIGATING": "Investigate",
    "DIAGNOSING": "Diagnose",
    "MITIGATION_PROPOSED": "Propose",
    "AWAITING_APPROVAL": "Await approval",
    "MITIGATING": "Mitigate",
    "VERIFYING_MITIGATION": "Verify",
}
_PHASE_ORDER = (
    "Detect",
    "Investigate",
    "Diagnose",
    "Propose",
    "Await approval",
    "Mitigate",
    "Verify",
)


def _duration(seconds: float) -> str:
    total = max(0, int(seconds))
    if total < 60:
        return f"{total}s"
    if total < 3600:
        return f"{total // 60}m {total % 60:02d}s"
    return f"{total // 3600}h {(total % 3600) // 60:02d}m"


def _phase_rail(
    transitions: list[dict[str, Any]], *, detected_at: datetime, current_state: str
) -> list[dict[str, str]]:
    """Sum wall-clock time spent in each product phase from committed transitions.

    Durations come only from durable `state_transitions` rows, so the rail can
    never claim a phase the incident did not actually occupy.
    """

    elapsed: dict[str, float] = {}
    previous = detected_at
    for row in transitions:
        occurred = row["occurred_at"]
        phase = _PHASE_OF_STATE.get(str(row["from_state"]))
        if phase is not None:
            elapsed[phase] = elapsed.get(phase, 0.0) + (occurred - previous).total_seconds()
        previous = occurred
    current_phase = _PHASE_OF_STATE.get(current_state)
    if current_phase is not None:
        elapsed[current_phase] = (
            elapsed.get(current_phase, 0.0) + (datetime.now(UTC) - previous).total_seconds()
        )
    rail: list[dict[str, str]] = []
    for phase in _PHASE_ORDER:
        if phase not in elapsed:
            continue
        rail.append(
            {
                "name": phase,
                "duration": _duration(elapsed[phase]),
                "state": "current" if phase == current_phase else "done",
            }
        )
    return rail


def _verification_view(row: dict[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {
            "id": "not-started",
            "verdict": "INCONCLUSIVE",
            "profile": "not resolved",
            "owner": "Verification Agent",
            "binding": "not resolved",
            "intervals": [],
            "threshold": "policy-owned",
            "synthetic": "not run",
        }
    signal_results = _json_list(row["signal_results_json"])
    return {
        "id": str(row["id"]),
        "verdict": str(row["verdict"]),
        "profile": f"{row['profile_id']} v{row['profile_version']}",
        "owner": "Independent Verification Agent",
        "binding": str(row["resolved_binding_ref"]),
        "intervals": [
            {
                "name": str(item.get("signal_key", "signal")),
                "window": f"{row['window_start']} to {row['window_end']}",
                "error_ratio": str(item.get("value", "n/a")),
                "p95": "n/a",
                "result": str(row["verdict"]),
            }
            for item in signal_results
            if isinstance(item, dict)
        ],
        "threshold": "immutable profile comparators",
        "synthetic": str(row["synthetic_receipt_ref"] or "missing"),
    }
