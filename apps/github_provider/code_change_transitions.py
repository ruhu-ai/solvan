"""GitHub Provider projections for terminal CREATE_PR operation outcomes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.code_change_operation_store import (
    CodeChangeOperationConflict,
    PostgresCodeChangeOperationStore,
    PullRequestProviderMaterial,
)


def append_pr_created_transition(
    *,
    connection: Any,
    scope: Scope,
    material: PullRequestProviderMaterial,
    receipt_ref: str,
    receipt_hash: str,
    observation: Mapping[str, object],
    observation_ref: str,
    observation_hash: str,
    actor_identity: str,
) -> None:
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT state,sequence_no FROM solvan_delivery.code_change_requests
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(request_id)s FOR UPDATE""",
            {**scope.canonical_dict(), "request_id": material.request_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeOperationConflict("code-change request disappeared")
        if row["state"] == "PR_CREATED":
            return
        if row["state"] != "PR_REQUESTED":
            raise CodeChangeOperationConflict("PR-created transition is stale")
        sequence = int(row["sequence_no"])
        cursor.execute(
            """INSERT INTO solvan_delivery.code_change_github_observations
                (organization_id,project_id,environment_id,id,code_change_request_id,
                 sequence_no,observation_kind,pull_request_number,pull_request_url,
                 branch_name,base_commit_sha,head_commit_sha,head_tree_hash,diff_hash,
                 merge_commit_sha,
                 required_check_state,required_checks_ref,required_checks_hash,
                 branch_rule_ref,branch_rule_hash,review_state,review_state_ref,
                 review_state_hash,approved_account_node_ids,required_check_definitions_ref,
                 required_check_definitions_hash,repository_policy_hash,
                 provider_service_revision,observation_ref,observation_hash,observed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,1,'PR_CREATED',%(pull_request_number)s,
                 %(pull_request_url)s,%(branch_name)s,%(base_commit_sha)s,
                 %(head_commit_sha)s,%(head_tree_hash)s,%(diff_hash)s,
                 NULL,
                 %(required_check_state)s,%(required_checks_ref)s,%(required_checks_hash)s,
                 %(branch_rule_ref)s,%(branch_rule_hash)s,%(review_state)s,
                 %(review_state_ref)s,%(review_state_hash)s,
                 %(approved_account_node_ids)s,
                 %(required_check_definitions_ref)s,%(required_check_definitions_hash)s,
                 %(repository_policy_hash)s,%(provider_service_revision)s,
                 %(observation_ref)s,%(observation_hash)s,%(observed_at)s)
               ON CONFLICT DO NOTHING""",
            {
                **scope.canonical_dict(),
                **observation,
                "id": new_identifier("cgo"),
                "request_id": material.request_id,
                "observation_ref": observation_ref,
                "observation_hash": observation_hash,
            },
        )
        if cursor.rowcount != 1:
            cursor.execute(
                """SELECT observation_hash FROM solvan_delivery.code_change_github_observations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s AND sequence_no=1""",
                {**scope.canonical_dict(), "request_id": material.request_id},
            )
            existing = cursor.fetchone()
            if existing is None or existing["observation_hash"] != observation_hash:
                raise CodeChangeOperationConflict("PR observation replay differs")
        transition_material = {
            "code_change_request_id": material.request_id,
            "from_state": "PR_REQUESTED",
            "to_state": "PR_CREATED",
            "receipt_hash": receipt_hash,
            "expected_sequence_no": sequence,
        }
        cursor.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                (organization_id,project_id,environment_id,id,code_change_request_id,
                 sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                 idempotency_key,actor_kind,actor_identity,receipt_ref,receipt_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(next_sequence)s,'PR_REQUESTED','PR_CREATED',%(sequence)s,
                 %(input_hash)s,%(idempotency_key)s,'GITHUB_PROVIDER',%(actor)s,
                 %(receipt_ref)s,%(receipt_hash)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": material.request_id,
                "next_sequence": sequence + 1,
                "sequence": sequence,
                "input_hash": canonical_sha256(transition_material),
                "idempotency_key": f"pr-created:{material.request_id}:{receipt_hash}",
                "actor": actor_identity,
                "receipt_ref": receipt_ref,
                "receipt_hash": receipt_hash,
            },
        )


def close_open_operations(
    *,
    connection: Any,
    scope: Scope,
    material: PullRequestProviderMaterial,
    receipt_ref: str,
    receipt_hash: str,
    status: str,
    reason: str,
) -> None:
    store = PostgresCodeChangeOperationStore(connection)
    states = store.operation_statuses(scope=scope, request_id=material.request_id)
    for kind, current in states.items():
        if current not in {"SUCCEEDED", "REFUSED", "AMBIGUOUS"}:
            store.complete_operation(
                scope=scope,
                request_id=material.request_id,
                kind=kind,
                response_ref=receipt_ref,
                response_hash=receipt_hash,
                status=status,
                error_class=reason,
            )


def append_blocked_transition(
    *,
    connection: Any,
    scope: Scope,
    material: PullRequestProviderMaterial,
    receipt_ref: str,
    receipt_hash: str,
    reason: str,
) -> None:
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT state,sequence_no FROM solvan_delivery.code_change_requests
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(request_id)s FOR UPDATE""",
            {**scope.canonical_dict(), "request_id": material.request_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeOperationConflict("code-change request disappeared")
        if row["state"] == "BLOCKED":
            return
        if row["state"] != "PR_REQUESTED":
            raise CodeChangeOperationConflict("blocked transition is stale")
        sequence = int(row["sequence_no"])
        input_hash = canonical_sha256(
            {
                "code_change_request_id": material.request_id,
                "from_state": "PR_REQUESTED",
                "to_state": "BLOCKED",
                "reason": reason,
                "receipt_hash": receipt_hash,
                "expected_sequence_no": sequence,
            }
        )
        cursor.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                (organization_id,project_id,environment_id,id,code_change_request_id,
                 sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                 idempotency_key,actor_kind,actor_identity,receipt_ref,receipt_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(next_sequence)s,'PR_REQUESTED','BLOCKED',%(sequence)s,
                 %(input_hash)s,%(idempotency_key)s,'GITHUB_PROVIDER',%(actor)s,
                 %(receipt_ref)s,%(receipt_hash)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": material.request_id,
                "next_sequence": sequence + 1,
                "sequence": sequence,
                "input_hash": input_hash,
                "idempotency_key": f"pr-blocked:{material.request_id}:{receipt_hash}",
                "actor": "service:github-provider",
                "receipt_ref": receipt_ref,
                "receipt_hash": receipt_hash,
            },
        )
