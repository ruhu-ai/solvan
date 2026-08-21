"""Atomic projection of a reconciled GitHub merge."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.code_change_merge_store import MergeProviderMaterial
from solvan.persistence.code_change_operation_store import CodeChangeOperationConflict


def record_merged(
    *,
    connection: Any,
    scope: Scope,
    material: MergeProviderMaterial,
    observation: Mapping[str, object],
    observation_ref: str,
    observation_hash: str,
    actor_identity: str,
) -> None:
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT r.state,r.sequence_no,COALESCE(max(o.sequence_no),0) AS observation_sequence
                 FROM solvan_delivery.code_change_requests r
                 LEFT JOIN solvan_delivery.code_change_github_observations o
                   ON o.organization_id=r.organization_id AND o.project_id=r.project_id
                  AND o.environment_id=r.environment_id AND o.code_change_request_id=r.id
                WHERE r.organization_id=%(organization_id)s
                  AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                  AND r.id=%(request_id)s
                GROUP BY r.state,r.sequence_no FOR UPDATE OF r""",
            {**scope.canonical_dict(), "request_id": material.request_id},
        )
        row = cursor.fetchone()
        if row is None or row["state"] != "MERGE_APPROVAL_PENDING":
            raise CodeChangeOperationConflict("merged transition is stale")
        cursor.execute(
            """INSERT INTO solvan_delivery.code_change_github_observations
                (organization_id,project_id,environment_id,id,code_change_request_id,
                 sequence_no,observation_kind,pull_request_number,pull_request_url,
                 branch_name,base_commit_sha,head_commit_sha,merge_commit_sha,
                 head_tree_hash,diff_hash,required_check_state,required_checks_ref,
                 required_checks_hash,branch_rule_ref,branch_rule_hash,review_state,
                 review_state_ref,review_state_hash,approved_account_node_ids,
                 required_check_definitions_ref,required_check_definitions_hash,
                 repository_policy_hash,provider_service_revision,
                 observation_ref,observation_hash,observed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(observation_sequence)s,'MERGED',
                 %(pull_request_number)s,%(pull_request_url)s,%(branch_name)s,
                 %(base_commit_sha)s,%(head_commit_sha)s,%(merge_commit_sha)s,
                 %(head_tree_hash)s,%(diff_hash)s,%(required_check_state)s,
                 %(required_checks_ref)s,%(required_checks_hash)s,
                 %(branch_rule_ref)s,%(branch_rule_hash)s,%(review_state)s,
                 %(review_state_ref)s,%(review_state_hash)s,%(approved_account_node_ids)s,
                 %(required_check_definitions_ref)s,%(required_check_definitions_hash)s,
                 %(repository_policy_hash)s,%(provider_service_revision)s,
                 %(observation_ref)s,%(observation_hash)s,%(observed_at)s)""",
            {
                **scope.canonical_dict(),
                **observation,
                "id": new_identifier("cgo"),
                "request_id": material.request_id,
                "observation_sequence": int(row["observation_sequence"]) + 1,
                "observation_ref": observation_ref,
                "observation_hash": observation_hash,
            },
        )
        sequence = int(row["sequence_no"])
        transition_material = {
            "schema_version": 1,
            "code_change_request_id": material.request_id,
            "from_state": "MERGE_APPROVAL_PENDING",
            "to_state": "MERGED",
            "decision_id": material.decision_id,
            "decision_digest": material.decision_digest,
            "observation_hash": observation_hash,
            "expected_sequence_no": sequence,
        }
        cursor.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                (organization_id,project_id,environment_id,id,code_change_request_id,
                 sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                 idempotency_key,actor_kind,actor_identity,receipt_ref,receipt_hash,
                 decision_id,decision_digest)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(next_sequence)s,'MERGE_APPROVAL_PENDING','MERGED',
                 %(sequence)s,%(input_hash)s,%(idempotency_key)s,'GITHUB_PROVIDER',
                 %(actor)s,%(receipt_ref)s,%(receipt_hash)s,%(decision_id)s,
                 %(decision_digest)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": material.request_id,
                "next_sequence": sequence + 1,
                "sequence": sequence,
                "input_hash": canonical_sha256(transition_material),
                "idempotency_key": f"merged:{material.request_id}:{material.decision_id}",
                "actor": actor_identity,
                "receipt_ref": observation_ref,
                "receipt_hash": observation_hash,
                "decision_id": material.decision_id,
                "decision_digest": material.decision_digest,
            },
        )
