"""Deterministic completion predicates for Operational Guidance steps.

Every predicate here reads the durable record its step is named for and never
infers success from anything else; a predicate with no record to check is an
ERROR, not an assumption (specification 17 §4.2).
"""

from __future__ import annotations

from typing import Any

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope
from solvan.persistence.operational_guidance_base import OperationalGuidanceStoreBase


def evaluate_registered_predicate(
    *,
    cursor: Any,
    scope: Scope,
    predicate_ref: str,
    selection_id: str,
    agent_run_id: str,
    required_evidence_kinds: tuple[str, ...],
) -> tuple[str, tuple[str, ...], str | None]:
    cursor.execute(
        """SELECT incident_id,reliability_case_id FROM solvan.agent_runs
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
              AND id=%(agent_run_id)s""",
        {**scope.canonical_dict(), "agent_run_id": agent_run_id},
    )
    run = cursor.fetchone()
    if run is None:
        raise GuidanceError("guidance predicate run binding disappeared")
    incident_id = run["incident_id"]
    if incident_id is None and run["reliability_case_id"] is not None:
        # A workspace repair run anchors on the case; its cited evidence
        # belongs to the case's originating incident.
        cursor.execute(
            """SELECT originating_incident_id FROM solvan.reliability_cases
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(reliability_case_id)s""",
            {**scope.canonical_dict(), "reliability_case_id": run["reliability_case_id"]},
        )
        case = cursor.fetchone()
        incident_id = None if case is None else case["originating_incident_id"]
    boundary_ref = f"db://solvan/agent-runs/{agent_run_id}"
    if predicate_ref == "guidance-content-fetched@1":
        if set(required_evidence_kinds) != {"GUIDANCE_FETCH_RECEIPT"}:
            return "ERROR", (boundary_ref,), "FETCH_EVIDENCE_PROFILE_INVALID"
        cursor.execute(
            """SELECT s.agent_run_id,r.content_hash
                 FROM solvan_operability.guidance_selections s
                 JOIN solvan_operability.guidance_revisions r ON
                   (r.organization_id,r.project_id,r.environment_id,r.guidance_key,r.version)=
                   (s.organization_id,s.project_id,s.environment_id,
                    s.guidance_key,s.guidance_version)
                WHERE s.organization_id=%(organization_id)s
                  AND s.project_id=%(project_id)s AND s.environment_id=%(environment_id)s
                  AND s.id=%(selection_id)s""",
            {**scope.canonical_dict(), "selection_id": selection_id},
        )
        selection = cursor.fetchone()
        if selection is None or str(selection["agent_run_id"]) != agent_run_id:
            return "ERROR", (boundary_ref,), "FETCH_SELECTION_BINDING_INVALID"
        request_id = f"guidance-fetch:{selection_id}:ALLOWED"
        fetch = OperationalGuidanceStoreBase._audit_by_request(
            cursor=cursor, scope=scope, decision_request_id=request_id
        )
        if fetch is None:
            return (
                "NOT_SATISFIED",
                (f"db://solvan-operability/guidance-selections/{selection_id}",),
                "GUIDANCE_CONTENT_NOT_FETCHED",
            )
        try:
            OperationalGuidanceStoreBase._require_same_audit(
                existing=fetch,
                entity_ref=f"guidance-selection:{selection_id}",
                digest=str(selection["content_hash"]),
                principal="service:coordinator",
                event_type="GUIDANCE_FETCH_ALLOWED",
            )
        except GuidanceError:
            return "ERROR", (boundary_ref,), "FETCH_RECEIPT_BINDING_INVALID"
        return (
            "SATISFIED",
            (
                f"db://solvan-operability/guidance-selections/{selection_id}",
                f"db://solvan-operability/operability-audit-events/{fetch['id']}",
            ),
            None,
        )
    if predicate_ref == "evidence-kind-present@1":
        cursor.execute(
            """SELECT id,CASE
                       WHEN source_kind IN ('CLOUD_MONITORING','MANAGED_PROMETHEUS')
                         THEN 'METRICS'
                       WHEN source_kind='CLOUD_TRACE' THEN 'TRACES'
                       WHEN source_kind IN ('CLOUD_LOGGING','ERROR_REPORTING') THEN 'LOGS'
                       WHEN source_kind='CLOUD_AUDIT' THEN 'EVENTS'
                       ELSE 'ARTIFACT'
                     END AS evidence_kind
                 FROM solvan.evidence_items
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND incident_id=%(incident_id)s
                  AND freshness_expires_at > now()
                ORDER BY observed_at DESC,id LIMIT 50""",
            {
                **scope.canonical_dict(),
                "incident_id": incident_id,
            },
        )
        records = cursor.fetchall()
        observed = {str(item["evidence_kind"]) for item in records}
        citations = tuple(f"db://solvan/evidence-items/{item['id']}" for item in records)
        if set(required_evidence_kinds).issubset(observed):
            return "SATISFIED", citations or (boundary_ref,), None
        return "NOT_SATISFIED", citations or (boundary_ref,), "REQUIRED_EVIDENCE_ABSENT"
    if predicate_ref == "verification-profile-passed@1":
        cursor.execute(
            """SELECT id FROM solvan.verification_runs
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND incident_id=%(incident_id)s AND verdict='VERIFIED'
                ORDER BY completed_at DESC,id LIMIT 1""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
        verification = cursor.fetchone()
        if verification is None:
            return "NOT_SATISFIED", (boundary_ref,), "VERIFICATION_NOT_PASSED"
        return (
            "SATISFIED",
            (f"db://solvan/verification-runs/{verification['id']}",),
            None,
        )
    if predicate_ref == "production-graph-binding-resolved@1":
        cursor.execute(
            """SELECT g.id FROM solvan.incidents i
                 JOIN solvan.production_graph_snapshots g ON
                   (g.organization_id,g.project_id,g.environment_id,g.id)=
                   (i.organization_id,i.project_id,i.environment_id,
                    i.production_graph_snapshot_id)
                WHERE i.organization_id=%(organization_id)s
                  AND i.project_id=%(project_id)s
                  AND i.environment_id=%(environment_id)s
                  AND i.id=%(incident_id)s AND g.status='APPROVED'
                  AND g.superseded_at IS NULL""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
        graph = cursor.fetchone()
        if graph is None:
            return "NOT_SATISFIED", (boundary_ref,), "GRAPH_BINDING_UNRESOLVED"
        return (
            "SATISFIED",
            (f"db://solvan/production-graph-snapshots/{graph['id']}",),
            None,
        )
    if predicate_ref == "action-effect-reconciled@1":
        cursor.execute(
            """SELECT r.id FROM solvan.execution_receipts r
                 JOIN solvan.actions a ON
                   (a.organization_id,a.project_id,a.environment_id,a.id)=
                   (r.organization_id,r.project_id,r.environment_id,r.action_id)
                WHERE a.organization_id=%(organization_id)s
                  AND a.project_id=%(project_id)s
                  AND a.environment_id=%(environment_id)s
                  AND a.incident_id=%(incident_id)s
                  AND r.result='SUCCEEDED' AND r.reconciled_at IS NOT NULL
                ORDER BY r.reconciled_at DESC,r.id LIMIT 1""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
        receipt = cursor.fetchone()
        if receipt is None:
            return "NOT_SATISFIED", (boundary_ref,), "ACTION_EFFECT_NOT_RECONCILED"
        return (
            "SATISFIED",
            (f"db://solvan/execution-receipts/{receipt['id']}",),
            None,
        )
    # Code-repair workspace predicates (specification 23 §5). Each checks
    # the durable record its step is named for; none infers success.
    if predicate_ref == "repair-input-manifest-valid@1":
        cursor.execute(
            """SELECT s.id,s.repair_plan_id,s.repair_plan_version
                 FROM solvan_delivery.repair_plan_guidance_selection_sets s
                WHERE s.organization_id=%(organization_id)s
                  AND s.project_id=%(project_id)s
                  AND s.environment_id=%(environment_id)s
                  AND s.bound_agent_run_id=%(agent_run_id)s AND s.status='BOUND'""",
            {**scope.canonical_dict(), "agent_run_id": agent_run_id},
        )
        binding = cursor.fetchone()
        if binding is None:
            return "NOT_SATISFIED", (boundary_ref,), "REPAIR_INPUT_MANIFEST_NOT_BOUND"
        cursor.execute(
            """SELECT id FROM solvan_delivery.repair_plan_command_catalogs
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND repair_plan_id=%(repair_plan_id)s
                  AND repair_plan_version=%(repair_plan_version)s AND status='RESOLVED'
                ORDER BY command_ordinal LIMIT 8""",
            {
                **scope.canonical_dict(),
                "repair_plan_id": binding["repair_plan_id"],
                "repair_plan_version": binding["repair_plan_version"],
            },
        )
        commands = cursor.fetchall()
        set_ref = f"db://solvan-delivery/repair-plan-guidance-selection-sets/{binding['id']}"
        if not commands:
            return "NOT_SATISFIED", (set_ref,), "REPAIR_COMMAND_CATALOG_UNRESOLVED"
        return (
            "SATISFIED",
            (
                set_ref,
                *(
                    f"db://solvan-delivery/repair-plan-command-catalogs/{row['id']}"
                    for row in commands
                ),
            ),
            None,
        )
    if predicate_ref == "repair-evidence-cited@1":
        cursor.execute(
            """SELECT id FROM solvan.evidence_items
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND incident_id=%(incident_id)s AND freshness_expires_at > now()
                ORDER BY observed_at DESC,id LIMIT 50""",
            {**scope.canonical_dict(), "incident_id": incident_id},
        )
        records = cursor.fetchall()
        if not records:
            return "NOT_SATISFIED", (boundary_ref,), "REPAIR_EVIDENCE_NOT_CITED"
        return (
            "SATISFIED",
            tuple(f"db://solvan/evidence-items/{row['id']}" for row in records),
            None,
        )
    if predicate_ref in {
        "exploratory-baseline-recorded@1",
        "exploratory-regression-recorded@1",
    }:
        command_kind = (
            "REPRODUCTION" if predicate_ref == "exploratory-baseline-recorded@1" else "REGRESSION"
        )
        cursor.execute(
            """SELECT r.id FROM solvan_delivery.exploratory_sandbox_receipts r
                 JOIN solvan_delivery.repair_plan_command_catalogs c ON
                   (c.organization_id,c.project_id,c.environment_id,c.id)=
                   (r.organization_id,r.project_id,r.environment_id,r.command_catalog_id)
                 JOIN solvan_delivery.repair_plan_command_definitions d ON
                   (d.organization_id,d.project_id,d.environment_id,d.id)=
                   (c.organization_id,c.project_id,c.environment_id,c.command_definition_id)
                WHERE r.organization_id=%(organization_id)s
                  AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                  AND r.agent_run_id=%(agent_run_id)s
                  AND d.command_kind=%(command_kind)s AND r.trust_class='EXPERIMENTAL'
                ORDER BY r.completed_at DESC,r.id LIMIT 1""",
            {
                **scope.canonical_dict(),
                "agent_run_id": agent_run_id,
                "command_kind": command_kind,
            },
        )
        receipt = cursor.fetchone()
        missing = (
            "EXPLORATORY_BASELINE_NOT_RECORDED"
            if command_kind == "REPRODUCTION"
            else "EXPLORATORY_REGRESSION_NOT_RECORDED"
        )
        if receipt is None:
            return "NOT_SATISFIED", (boundary_ref,), missing
        return (
            "SATISFIED",
            (f"db://solvan-delivery/exploratory-sandbox-receipts/{receipt['id']}",),
            None,
        )
    if predicate_ref == "candidate-generation-recorded@1":
        cursor.execute(
            """SELECT id FROM solvan_delivery.workspace_candidate_generations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND agent_run_id=%(agent_run_id)s
                ORDER BY generation_ordinal DESC LIMIT 1""",
            {**scope.canonical_dict(), "agent_run_id": agent_run_id},
        )
        generation = cursor.fetchone()
        if generation is None:
            return "NOT_SATISFIED", (boundary_ref,), "CANDIDATE_GENERATION_NOT_RECORDED"
        return (
            "SATISFIED",
            (f"db://solvan-delivery/workspace-candidate-generations/{generation['id']}",),
            None,
        )
    if predicate_ref == "patch-proposal-complete@1":
        cursor.execute(
            """SELECT id FROM solvan.patch_artifacts
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND agent_run_id=%(agent_run_id)s""",
            {**scope.canonical_dict(), "agent_run_id": agent_run_id},
        )
        proposal = cursor.fetchone()
        if proposal is None:
            return "NOT_SATISFIED", (boundary_ref,), "PATCH_PROPOSAL_NOT_COMPLETE"
        return (
            "SATISFIED",
            (f"db://solvan/patch-artifacts/{proposal['id']}",),
            None,
        )
    return "ERROR", (boundary_ref,), "PREDICATE_IMPLEMENTATION_UNAVAILABLE"
