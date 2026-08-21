"""Read-only projection of logical workspace governance and execution lineage."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope

_DENIED_AUTHORITIES = (
    "root-cause confirmation",
    "patch approval or repository merge",
    "deployment or production mutation",
    "verification adjudication",
    "incident resolution or case closure",
    "Memory or Production Graph promotion",
)


def workspace_case_projections(
    connection: Connection[Any], *, scope: Scope
) -> dict[str, dict[str, Any]]:
    parameters = scope.canonical_dict()
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT * FROM solvan.workspaces
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND kind = 'INCIDENT'
              ORDER BY created_at DESC""",
            parameters,
        )
        workspace_rows = cursor.fetchall()
        cursor.execute(
            """SELECT r.* FROM solvan.agent_runs r
              WHERE r.organization_id = %(organization_id)s
                AND r.project_id = %(project_id)s
                AND r.environment_id = %(environment_id)s
                AND r.workspace_id IS NOT NULL
              ORDER BY r.started_at NULLS LAST, r.id""",
            parameters,
        )
        run_rows = cursor.fetchall()
        cursor.execute(
            """SELECT c.* FROM solvan.workspace_checkpoints c
              WHERE c.organization_id = %(organization_id)s
                AND c.project_id = %(project_id)s
                AND c.environment_id = %(environment_id)s
              ORDER BY c.workspace_id, c.sequence_no""",
            parameters,
        )
        checkpoint_rows = cursor.fetchall()
        cursor.execute(
            """SELECT DISTINCT ON (r.workspace_id)
                r.workspace_id, p.id, p.status, p.cognition_ref,
                p.cognition_hash, p.mechanism, p.hypotheses_json,
                p.reproduction_command, p.reproduction_exit_code,
                p.reproduction_output_ref, p.reproduction_output_hash,
                p.test_command, p.test_exit_code, p.test_output_ref,
                p.test_output_hash
              FROM solvan.patch_artifacts p
              JOIN solvan.agent_runs r
                ON (r.organization_id, r.project_id, r.environment_id, r.id)
                 = (p.organization_id, p.project_id, p.environment_id,
                    p.agent_run_id)
              WHERE p.organization_id = %(organization_id)s
                AND p.project_id = %(project_id)s
                AND p.environment_id = %(environment_id)s
              ORDER BY r.workspace_id, p.created_at DESC, p.id DESC""",
            parameters,
        )
        patch_rows = cursor.fetchall()

    runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        runs[str(row["workspace_id"])].append(
            {
                "id": str(row["id"]),
                "task": str(row["workspace_task_kind"]),
                "status": str(row["status"]),
                "attempt": int(row["attempt"]),
                "request_hash": str(row["provider_request_hash"]),
                "output_hash": (
                    "not completed" if row["output_hash"] is None else str(row["output_hash"])
                ),
                "provider_boot_hash": (
                    "not completed"
                    if row["provider_boot_hash"] is None
                    else str(row["provider_boot_hash"])
                ),
                "provider_service_revision": (
                    "not completed"
                    if row["provider_service_revision"] is None
                    else str(row["provider_service_revision"])
                ),
            }
        )
    checkpoints: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in checkpoint_rows:
        checkpoints[str(row["workspace_id"])].append(
            {
                "id": str(row["id"]),
                "event": str(row["event_kind"]),
                "sequence": int(row["sequence_no"]),
                "artifact_manifest_hash": str(row["artifact_manifest_hash"]),
                "provider_boot_hash": str(row["provider_boot_hash"]),
            }
        )
    cognition_by_workspace = {
        str(row["workspace_id"]): {
            "patch_artifact_id": str(row["id"]),
            "status": str(row["status"]),
            "trust_class": "PROPOSED",
            "mechanism": str(row["mechanism"]),
            "hypotheses": list(row["hypotheses_json"]),
            "artifact_ref": str(row["cognition_ref"]),
            "artifact_hash": str(row["cognition_hash"]),
            "reproduction": {
                "command": str(row["reproduction_command"]),
                "exit_code": int(row["reproduction_exit_code"]),
                "output_ref": str(row["reproduction_output_ref"]),
                "output_hash": str(row["reproduction_output_hash"]),
            },
            "regression": {
                "command": str(row["test_command"]),
                "exit_code": int(row["test_exit_code"]),
                "output_ref": str(row["test_output_ref"]),
                "output_hash": str(row["test_output_hash"]),
            },
        }
        for row in patch_rows
    }

    projected: dict[str, dict[str, Any]] = {}
    for row in workspace_rows:
        workspace_id = str(row["id"])
        case_id = str(row["reliability_case_id"])
        if case_id in projected:
            continue
        projected[case_id] = {
            "id": workspace_id,
            "kind": str(row["kind"]),
            "status": str(row["status"]),
            "provider": str(row["provider"]),
            "implementation_sdk": str(row["implementation_sdk"]),
            "implementation_sdk_version": str(row["implementation_sdk_version"]),
            "provider_revision": str(row["provider_revision"]),
            "registry_agent_key": str(row["registry_agent_key"]),
            "classification": str(row["classification"]),
            "synthetic": bool(row["synthetic"]),
            "eligibility_decision": str(row["provider_eligibility_decision_id"]),
            "input_manifest_hash": str(row["input_manifest_hash"]),
            "network_policy_hash": str(row["effective_network_policy_hash"]),
            "task_runs": runs[workspace_id],
            "checkpoints": checkpoints[workspace_id],
            "repair_cognition": cognition_by_workspace.get(workspace_id),
            "denied_authorities": list(_DENIED_AUTHORITIES),
        }
    return projected
