"""Read-only Cloud SQL projection for the operator console."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from apps.api.agent_manifest_projection import agent_manifest_facts
from apps.api.fleet_capability_projection import capability_projection
from apps.api.fleet_governance_projection import (
    agent_run_rows,
    audit_event_rows,
    memory_candidate_rows,
    security_event_rows,
)
from apps.api.guidance_projection import guidance_projection
from apps.api.incident_projection import incident_projection
from apps.api.overview_history import counts_over_time, tile
from apps.api.workspace_projection import workspace_case_projections
from solvan.application.alert_list import AlertListFilter
from solvan.application.patch_diff import diff_view
from solvan.domain import Scope
from solvan.persistence import (
    PostgresOperationalGuidanceStore,
    PostgresPatchReviewStore,
    PostgresToolCatalogStore,
)
from solvan.persistence.alert_triage import AlertTriageRepository
from solvan.persistence.connection_store import PostgresConnectionStore
from solvan.platform.evidence_objects import GcsEvidenceReader
from solvan.platform.google_rest import authorized_session
from solvan.platform.release_projection import unverified_platform_components

_ACTIVE_INCIDENT_STATES = (
    "DETECTED",
    "TRIAGING",
    "INVESTIGATING",
    "DIAGNOSING",
    "MITIGATION_PROPOSED",
    "AWAITING_APPROVAL",
    "MITIGATING",
    "VERIFYING_MITIGATION",
    "MITIGATED",
    "ESCALATED",
)
_CASE_PHASES = [
    "Root cause",
    "Repair",
    "Review",
    "Canary",
    "Rollout",
    "Observation",
    "Closed",
]
_DETERMINISTIC_SEATS = (
    (
        "Action Actuator",
        "action-actuator",
        "the only production mutation capability",
        ("PAYMENTS_POOL_RECYCLE", "CLOUD_RUN_TRAFFIC_ROLLBACK"),
    ),
)
_AGENTS = (
    ("Incident Supervisor Agent", "incident-supervisor", "investigation planning"),
    ("Evidence Agent", "evidence-agent", "metrics, logs, traces"),
    ("Infrastructure Agent", "infrastructure-agent", "resource metadata"),
    ("Execution Agent", "execution-agent", "private actuator only"),
    ("Verification Agent", "verification-agent", "independent recovery oracle"),
    ("Workspace Agent", "workspace-agent", "bounded patch proposal"),
)
_AGENT_NAMES = {key: name for name, key, _capability in _AGENTS}
_AGENT_CAPABILITIES = {key: capability for _name, key, capability in _AGENTS}
_TOOL_STATUS_DEFINITIONS = {
    "lifecycle": "Whether this immutable revision may enter new work.",
    "availability": "Whether policy and current connection evidence allow selection here.",
    "evidence": "Whether the exact capability was probed and remains fresh.",
    "deployment": "Implemented, deployed, and release-qualified are separate states.",
}


def _scope_parameters(scope: Scope) -> dict[str, str]:
    return {
        "organization_id": scope.organization_id,
        "project_id": scope.project_id,
        "environment_id": scope.environment_id,
    }


def _age(value: datetime) -> str:
    seconds = max(0, int((datetime.now(UTC) - value).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86_400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86_400}d"


def _short(value: object) -> str:
    text = str(value)
    return text if len(text) <= 22 else f"{text[:10]}…{text[-8:]}"


def _probe_reason(probe: dict[str, Any]) -> str:
    """Say why a receipt does not currently make a Tool selectable.

    A `PASSED` receipt carries no reason code and no missing grant — the schema
    CHECK forbids both — so an expired-but-passing probe rendered `str(None)`
    and put the literal word `None` on the screen where the operator's reason
    belongs. Expiry is a state with its own sentence, not a missing one.
    """

    reason = probe["reason_code"] or probe["missing_grant"]
    if reason:
        return str(reason)
    if probe["outcome"] == "PASSED":
        return (
            "The last passing capability proof has expired; proof is never inherited "
            "from an older observation."
        )
    return "The last capability probe did not pass and recorded no reason."


def _reviewable_diff(material: object) -> dict[str, Any]:
    """Read the stored patch and prove it is the one being approved.

    The bytes are accepted only when their hash matches the durable ledger, so
    the diff a reviewer reads is the diff the digest commits to. Any failure
    reports itself; it never degrades to showing an unverified change.
    """

    reference = getattr(material, "unified_diff_ref", "")
    expected = getattr(material, "unified_diff_hash", "")
    if not reference.startswith("gs://") or not expected:
        return {"files": [], "added": 0, "removed": 0, "truncated": False, "note": ""}
    bucket = os.environ.get("SOLVAN_EVIDENCE_BUCKET")
    if not bucket:
        return {
            "files": [],
            "added": 0,
            "removed": 0,
            "truncated": False,
            "note": "The evidence bucket is not configured, so the diff cannot be verified here.",
        }
    try:
        content = GcsEvidenceReader(
            allowed_buckets=frozenset({bucket}), session=authorized_session()
        ).get_bytes(uri=reference, expected_hash=expected, max_bytes=1_048_576)
        return diff_view(content.decode("utf-8", errors="replace"))
    except Exception:
        return {
            "files": [],
            "added": 0,
            "removed": 0,
            "truncated": False,
            "note": (
                "The stored patch could not be read and hash-verified; review it at the source."
            ),
        }


def live_console_snapshot(connection: Connection[Any], *, scope: Scope) -> dict[str, Any]:
    parameters = _scope_parameters(scope)
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT i.*, s.service_key, e.display_name AS environment_name,
                e.region, c.display_id AS case_display_id
              FROM solvan.incidents i
              JOIN solvan.services s
                ON (s.organization_id, s.project_id, s.environment_id, s.id)
                 = (i.organization_id, i.project_id, i.environment_id,
                    i.primary_service_id)
              JOIN solvan.environments e
                ON (e.organization_id, e.project_id, e.id)
                 = (i.organization_id, i.project_id, i.environment_id)
              LEFT JOIN solvan.reliability_cases c
                ON (c.organization_id, c.project_id, c.environment_id, c.id)
                 = (i.organization_id, i.project_id, i.environment_id,
                    i.reliability_case_id)
              WHERE i.organization_id = %(organization_id)s
                AND i.project_id = %(project_id)s
                AND i.environment_id = %(environment_id)s
              ORDER BY i.detected_at DESC LIMIT 25""",
            parameters,
        )
        incident_rows = cursor.fetchall()
        cursor.execute(
            """SELECT c.*, i.display_id AS incident_display_id, s.service_key,
                (SELECT p.id FROM solvan.repair_plans p
                  WHERE p.organization_id = c.organization_id
                    AND p.project_id = c.project_id
                    AND p.environment_id = c.environment_id
                    AND p.reliability_case_id = c.id AND p.status = 'ACTIVE'
                  ORDER BY p.plan_version DESC LIMIT 1) AS repair_plan_id,
                (SELECT p.base_commit_sha FROM solvan.repair_plans p
                  WHERE p.organization_id = c.organization_id
                    AND p.project_id = c.project_id
                    AND p.environment_id = c.environment_id
                    AND p.reliability_case_id = c.id AND p.status = 'ACTIVE'
                  ORDER BY p.plan_version DESC LIMIT 1) AS base_commit_sha,
                (SELECT p.provider FROM solvan.repair_plans p
                  WHERE p.organization_id = c.organization_id
                    AND p.project_id = c.project_id
                    AND p.environment_id = c.environment_id
                    AND p.reliability_case_id = c.id AND p.status = 'ACTIVE'
                  ORDER BY p.plan_version DESC LIMIT 1) AS repair_provider,
                (SELECT pa.status FROM solvan.patch_artifacts pa
                  WHERE pa.organization_id = c.organization_id
                    AND pa.project_id = c.project_id
                    AND pa.environment_id = c.environment_id
                    AND pa.reliability_case_id = c.id
                  ORDER BY pa.created_at DESC LIMIT 1) AS patch_status,
                (SELECT pa.id FROM solvan.patch_artifacts pa
                  WHERE pa.organization_id = c.organization_id
                    AND pa.project_id = c.project_id
                    AND pa.environment_id = c.environment_id
                    AND pa.reliability_case_id = c.id
                  ORDER BY pa.created_at DESC LIMIT 1) AS patch_artifact_id,
                array_remove(array_agg(w.wake_at ORDER BY w.wake_at), NULL) AS wakeups
              FROM solvan.reliability_cases c
              LEFT JOIN solvan.incidents i
                ON (i.organization_id, i.project_id, i.environment_id, i.id)
                 = (c.organization_id, c.project_id, c.environment_id,
                    c.originating_incident_id)
              LEFT JOIN solvan.services s
                ON (s.organization_id, s.project_id, s.environment_id, s.id)
                 = (i.organization_id, i.project_id, i.environment_id,
                    i.primary_service_id)
              LEFT JOIN solvan.scheduled_wakeups w
                ON (w.organization_id, w.project_id, w.environment_id, w.case_id)
                 = (c.organization_id, c.project_id, c.environment_id, c.id)
              WHERE c.organization_id = %(organization_id)s
                AND c.project_id = %(project_id)s
                AND c.environment_id = %(environment_id)s
              GROUP BY c.organization_id, c.project_id, c.environment_id, c.id,
                i.display_id, s.service_key ORDER BY c.created_at DESC""",
            parameters,
        )
        case_rows = cursor.fetchall()
        # The governance tabs filter client-side, so each projection is a
        # bounded recent window rather than a page-one teaser: 100 rows keeps
        # the filters meaningful without turning a list API into an export.
        cursor.execute(
            """SELECT * FROM solvan.memory_candidates
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
              ORDER BY created_at DESC LIMIT 100""",
            parameters,
        )
        memories = cursor.fetchall()
        cursor.execute(
            """SELECT * FROM solvan.security_events
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
              ORDER BY occurred_at DESC LIMIT 100""",
            parameters,
        )
        security = cursor.fetchall()
        cursor.execute(
            """SELECT * FROM solvan.audit_events
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
              ORDER BY sequence_id DESC LIMIT 100""",
            parameters,
        )
        audit = cursor.fetchall()
        # Durable run history for the Agents tab. A run in CREATED has no
        # started_at yet, so the deadline orders it until dispatch does.
        cursor.execute(
            """SELECT id, agent_key, agent_revision, status, attempt, incident_id,
                      reliability_case_id, workspace_id, logical_step_key,
                      error_class, workflow_version, deadline, started_at,
                      completed_at, trace_id
              FROM solvan.agent_runs
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
              ORDER BY COALESCE(started_at, deadline) DESC LIMIT 50""",
            parameters,
        )
        agent_runs = cursor.fetchall()
        cursor.execute(
            """SELECT
                count(*) FILTER (WHERE status IN ('READY','PLANNED')) AS ready,
                count(*) FILTER (WHERE status IN ('DISPATCHED','RUNNING')) AS running,
                count(*) FILTER (WHERE status IN ('FAILED','STALE')) AS fenced
              FROM solvan.investigation_steps
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s""",
            parameters,
        )
        queue = cursor.fetchone() or {"ready": 0, "running": 0, "fenced": 0}
        cursor.execute(
            """SELECT display_name, region, classification FROM solvan.environments
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s AND id = %(environment_id)s""",
            parameters,
        )
        environment = cursor.fetchone()
        # The fleet is who the catalog has registered AND given an approved
        # bounded capability profile. A principal without one cannot be
        # dispatched, so an optional or disabled agent is absent from this
        # screen rather than listed beside the seats that can actually run.
        # Two different numbers, and only one is the operative one. A Tool
        # revision may name an agent as an allowed requester while that Tool is
        # in no approved profile, in which case the agent cannot reach it: the
        # profile is what dispatch resolves. Infrastructure declares nine and
        # can reach four. Reporting the larger number overstates reach by more
        # than double, so both are projected and the console shows the gap.
        cursor.execute(
            """SELECT p.principal_key, p.display_name, p.execution_role, p.model_backed,
                 p.manifest_hash, p.created_at,
                 (SELECT count(*) FROM solvan_operability.tool_profile_members m
                    JOIN solvan_operability.tool_profile_revisions f
                      ON (f.profile_key, f.version) = (m.profile_key, m.profile_version)
                   WHERE f.allowed_agent_key = p.principal_key
                     AND f.lifecycle = 'APPROVED') AS profile_tool_count,
                 (SELECT count(*) FROM solvan_operability.tool_revision_requesters q
                   WHERE q.requester_key = p.principal_key) AS declared_tool_count
               FROM solvan_operability.catalog_principals p
              WHERE p.registry_kind = 'AGENT' AND p.model_backed
                AND EXISTS (SELECT 1 FROM solvan_operability.tool_profile_revisions f
                             WHERE f.allowed_agent_key = p.principal_key
                               AND f.lifecycle = 'APPROVED')
              ORDER BY p.display_name"""
        )
        registered_agents = cursor.fetchall()
        cursor.execute(
            """SELECT entity_id, occurred_at, to_state, from_state
                 FROM solvan.state_transitions
                WHERE organization_id = %(organization_id)s
                  AND project_id = %(project_id)s
                  AND environment_id = %(environment_id)s
                  AND entity_type = 'INCIDENT'
                ORDER BY entity_id, occurred_at""",
            _scope_parameters(scope),
        )
        transitions_by_incident: dict[str, list[tuple[Any, str, str]]] = {}
        for row in cursor.fetchall():
            transitions_by_incident.setdefault(str(row["entity_id"]), []).append(
                (row["occurred_at"], str(row["to_state"]), str(row["from_state"]))
            )
        history = counts_over_time(
            incidents=[dict(row) for row in incident_rows],
            transitions_by_incident=transitions_by_incident,
            cases=[dict(row) for row in case_rows],
            active_states=_ACTIVE_INCIDENT_STATES,
            mitigated_states={"MITIGATED", "RESOLVED"},
            now=datetime.now(UTC),
        )
    if environment is None:
        raise RuntimeError("configured console scope does not exist")
    manifest_facts = agent_manifest_facts(
        {str(row["principal_key"]): str(row["manifest_hash"]) for row in registered_agents}
    )

    incidents = [incident_projection(connection, scope, dict(row)) for row in incident_rows]
    active_count = sum(row["state"] in _ACTIVE_INCIDENT_STATES for row in incident_rows)
    awaiting_count = sum(row["state"] == "AWAITING_APPROVAL" for row in incident_rows)
    mitigated_count = sum(row["state"] in {"MITIGATED", "RESOLVED"} for row in incident_rows)
    workspace_by_case = workspace_case_projections(connection, scope=scope)
    cases = []
    for row in case_rows:
        patch_material = None
        if (
            row["patch_artifact_id"] is not None
            and row["patch_status"] == "TESTS_PASSED"
            and row["state"] in {"AWAITING_REVIEW", "READY_FOR_CANARY"}
        ):
            patch_material = PostgresPatchReviewStore(connection).review(
                scope=scope, patch_artifact_id=str(row["patch_artifact_id"])
            )
        cases.append(
            {
                "id": str(row["display_id"]),
                "service": str(row["service_key"] or "unknown"),
                "state": str(row["state"]),
                "incident": str(row["incident_display_id"] or "unknown"),
                "age": _age(row["created_at"]),
                "repair": str(row["next_action_kind"] or "Permanent repair ownership"),
                "repair_plan": str(row["repair_plan_id"] or "not defined"),
                "provider": str(row["repair_provider"] or "not selected"),
                "commit": str(row["base_commit_sha"] or "not pinned"),
                "patch_status": str(row["patch_status"] or "not proposed"),
                "patch_artifact": (
                    "not proposed" if patch_material is None else patch_material.patch_artifact_id
                ),
                "patch_digest": "" if patch_material is None else patch_material.patch_digest,
                "patch_ref": "" if patch_material is None else patch_material.unified_diff_ref,
                "patch_diff": (
                    {"files": [], "added": 0, "removed": 0, "truncated": False, "note": ""}
                    if patch_material is None
                    else _reviewable_diff(patch_material)
                ),
                "test_ref": "" if patch_material is None else patch_material.test_output_ref,
                "residual_risks": (
                    [] if patch_material is None else list(patch_material.residual_risks)
                ),
                "next": "not scheduled"
                if row["next_action_at"] is None
                else row["next_action_at"].astimezone(UTC).isoformat(),
                "owner": str(row["blocked_owner"] or "durable case coordinator"),
                "phases": _CASE_PHASES,
                "checkpoints": [
                    {
                        "day": wake.astimezone(UTC).date().isoformat(),
                        "events": [
                            f"Durable wake-up scheduled for {wake.astimezone(UTC).isoformat()}"
                        ],
                    }
                    for wake in (row["wakeups"] or [])
                ],
                "workspace": workspace_by_case.get(str(row["id"])),
            }
        )
    catalog = PostgresToolCatalogStore(connection).projection(scope=scope)
    operational_guidance = PostgresOperationalGuidanceStore(connection).projection(scope=scope)
    latest_probes = {
        (str(item["tool_key"]), str(item["tool_version"])): item for item in catalog["probes"]
    }
    tool_projection = []
    for item in catalog["tools"]:
        key = str(item["tool_key"])
        version = str(item["version"])
        probe = latest_probes.get((key, version))
        fresh = (
            probe is not None
            and probe["outcome"] == "PASSED"
            and probe["expires_at"] > datetime.now(UTC)
        )
        lifecycle = str(item["lifecycle"])
        available = lifecycle == "APPROVED" and fresh
        agent_keys = [str(value) for value in item["agents"]]
        tool_projection.append(
            {
                "key": key,
                "version": version,
                "name": str(item["display_name"]),
                "owner": str(item["owner_department"]),
                "agent_keys": agent_keys,
                "agents": [_AGENT_NAMES.get(value, value) for value in agent_keys],
                "permission_class": str(item["permission_class"]),
                "integration": str(item["gateway_destination"]),
                "connection": "No bound probe" if probe is None else str(probe["connection_id"]),
                "lifecycle": lifecycle.replace("_", " ").title(),
                # Never connected and observed-to-fail are different facts and
                # get different words. Collapsing both to "Unavailable" reads as
                # a fault, so a catalog nobody has connected yet renders as 23
                # broken things instead of one setup step not taken.
                "availability": (
                    "Available"
                    if available
                    else "Not configured"
                    if probe is None
                    else "Unavailable"
                ),
                "evidence": (
                    "Not probed"
                    if probe is None
                    else "Probe passed"
                    if fresh
                    else "Probe failed"
                    if probe["outcome"] == "FAILED"
                    else "Probe stale"
                ),
                "deployment": "Implemented",
                "registry": str(item["registry_resource"]),
                "identity": "Not observed" if probe is None else str(probe["agent_key"]),
                "gateway": str(item["gateway_destination"]),
                "armor": str(item["model_armor_coverage"]),
                "region": ", ".join(str(value) for value in item["runtime_regions_json"]),
                "last_probe": (
                    "Never" if probe is None else probe["observed_at"].astimezone(UTC).isoformat()
                ),
                "probe_expiry": (
                    "No fresh proof"
                    if probe is None
                    else probe["expires_at"].astimezone(UTC).isoformat()
                ),
                "call_budget": int(item["default_call_budget"]),
                "timeout_ms": int(item["timeout_ms"]),
                "max_payload_bytes": int(item["max_output_bytes"]),
                "last_call": "No reader-safe call projection yet",
                "trace": "Not sampled",
                "why": (
                    "The exact approved revision and fresh capability probe are eligible."
                    if available
                    else _probe_reason(probe)
                    if probe is not None
                    else "No fresh capability proof exists for this scope."
                ),
                "next_step": (
                    "No action required; dispatch still needs an exact profile."
                    if available
                    else str(probe["missing_grant"])
                    if probe is not None and probe["missing_grant"]
                    else "Re-run the capability probe for the bound connection."
                    if probe is not None
                    else "Bind an exact connection and run the capability probe."
                ),
            }
        )
    alert_reports: list[dict[str, Any]] = []
    installed = connection.execute("SELECT to_regclass('solvan_alerts.alert_episodes')").fetchone()
    if installed is not None and installed[0] is not None:
        alert_store = AlertTriageRepository(connection)
        alert_list = alert_store.list_alerts(scope=scope, alert_filter=AlertListFilter(view="ALL"))
        alert_reports = [
            report
            for row in alert_list["rows"]
            if (
                report := alert_store.get_alert_report(
                    scope=scope, episode_id=str(row["alert_episode_id"])
                )
            )
            is not None
        ]
    return {
        "schema_version": 1,
        # What the data is and what may be done with it are separate facts. The
        # projection is always live scoped Cloud SQL state; whether this
        # deployment carries control authority is a property of the deployment,
        # and a local development database read through production code has none.
        "data_status": "LIVE_CLOUD_SQL_PROJECTION",
        "authority": (
            "GOOGLE_CLOUD_IAM"
            if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"
            else "NO_PRODUCTION_AUTHORITY"
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "name": str(environment["display_name"]),
            "region": str(environment["region"]),
        },
        "overview": {
            "metrics": [
                tile("Open incidents", "durable", history["open_incidents"], active_count),
                tile("Reliability Cases", "durable", history["reliability_cases"], len(cases)),
                tile("Awaiting approval", "exact", history["awaiting_approval"], awaiting_count),
                tile(
                    "Verified mitigations",
                    "stored",
                    history["verified_mitigations"],
                    mitigated_count,
                ),
            ],
            "queue": {
                "ready": int(queue["ready"] or 0),
                "running": int(queue["running"] or 0),
                "sleeping": sum(row["next_action_at"] is not None for row in case_rows),
                "overdue": sum(
                    row["next_action_at"] is not None and row["next_action_at"] < datetime.now(UTC)
                    for row in case_rows
                ),
                "fenced": int(queue["fenced"] or 0),
            },
        },
        "incidents": incidents,
        "cases": cases,
        "fleet": {
            "tool_status_definitions": _TOOL_STATUS_DEFINITIONS,
            "tools": tool_projection,
            # What each Agent may actually reach, decided once by the same rule
            # the run binder applies and carrying the chain that produced it.
            # The Tools list above answers a different question — what the
            # catalog holds — and the two are no longer allowed to disagree.
            "capabilities": capability_projection(
                connection,
                scope=scope,
                environment_region=str(environment["region"]),
                environment_classification=(
                    None
                    if environment["classification"] is None
                    else str(environment["classification"])
                ),
            ),
            "tool_profiles": [
                {
                    "key": str(item["profile_key"]),
                    "version": str(item["version"]),
                    "agent_key": str(item["allowed_agent_key"]),
                    "lifecycle": str(item["lifecycle"]).replace("_", " ").title(),
                    "tool_count": 0,
                    "connection_count": 0,
                    "maximum_calls": int(item["maximum_total_calls"]),
                    "region": str(item["runtime_region"]),
                }
                for item in catalog["profiles"]
            ],
            "tool_probes": catalog["probes"],
            "guidance": [guidance_projection(item) for item in operational_guidance["guidance"]],
            "trigger_policies": operational_guidance["trigger_policies"],
            "trigger_firings": operational_guidance["trigger_firings"],
            # Registry version, owner and identity used to be the literals
            # "deployment-bound", "Solvan platform" and "Agent Identity
            # required", rendered on every card as though they were per-agent
            # facts. They are gone. What the catalog actually knows about each
            # agent — the role it may hold and how many governed Tool revisions
            # name it as a requester — differs between agents and is derived.
            "agents": [
                {
                    "name": str(row["display_name"]),
                    "key": str(row["principal_key"]),
                    "capabilities": _AGENT_CAPABILITIES.get(
                        str(row["principal_key"]), "no declared capability"
                    ),
                    "execution_role": str(row["execution_role"]).replace("_", " ").title(),
                    "model_backed": bool(row["model_backed"]),
                    "tool_count": int(row["profile_tool_count"]),
                    "declared_tool_count": int(row["declared_tool_count"]),
                    # Deployment is asserted only by a provisioned identity. No
                    # registry binding exists, so the honest state is
                    # implemented-but-not-deployed, and the console states that
                    # once for the fleet rather than six times.
                    "deployment": "NOT_DEPLOYED",
                    "region": str(environment["region"]),
                    "manifest_hash": str(row["manifest_hash"]),
                    "registered_at": row["created_at"].astimezone(UTC).isoformat(),
                    # Digest-verified manifest facts, or None when the pin no
                    # longer matches the checked-in manifest (superseded).
                    "manifest": manifest_facts.get(str(row["principal_key"])),
                }
                for row in registered_agents
            ],
            "agent_runs": agent_run_rows(
                [dict(row) for row in agent_runs], agent_names=_AGENT_NAMES
            ),
            "deterministic_services": [
                {
                    "name": name,
                    "key": key,
                    "capabilities": capability,
                    "model_backed": False,
                    "allowed_operations": list(operations),
                    "identity": "Workload Identity required",
                    "region": str(environment["region"]),
                }
                for name, key, capability, operations in _DETERMINISTIC_SEATS
            ],
            "memory": memory_candidate_rows([dict(row) for row in memories]),
            "security": security_event_rows([dict(row) for row in security]),
            "audit": audit_event_rows([dict(row) for row in audit]),
            # Cloud SQL is authoritative for workflow state and says nothing
            # about the platform: only a bound preflight receipt can. This is
            # the no-receipt block, replaced wholesale by the receipt-derived
            # one when a cloud release binding resolves.
            "platform": unverified_platform_components(
                detail="No bound platform preflight receipt is available in this scope.",
                next_step="Capture the platform preflight receipt before calling this healthy.",
            ),
        },
        "integration": PostgresConnectionStore(connection).integration_projection(scope=scope),
        "alerts": alert_reports,
        "release": {
            "scenarios": [
                {"id": f"S{index}", "name": name, "status": "NOT_RUN_ON_GCP"}
                for index, name in enumerate(
                    (
                        "Closed-loop recovery",
                        "Concurrency and deduplication",
                        "Agent recovery",
                        "Stale approval",
                        "Prompt injection and memory poisoning",
                        "Cross-scope denial",
                    ),
                    start=1,
                )
            ],
            "commit": "Read deployment receipt for immutable commit",
            "cloud": "PENDING_RECEIPTS",
            "gate": "NOT_EVALUATED",
        },
    }
