"""Append-only GitHub observation and code-change state projection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.code_change_operation_store import CodeChangeOperationConflict


def record_sync_observation(
    *,
    connection: Any,
    scope: Scope,
    request_id: str,
    expected_previous_hash: str,
    observation: Mapping[str, object],
    observation_ref: str,
    observation_hash: str,
    actor_identity: str,
) -> None:
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT r.state,r.sequence_no,
                      o.sequence_no AS observation_sequence,o.observation_hash
                 FROM solvan_delivery.code_change_requests r
                 JOIN LATERAL (
                   SELECT sequence_no,observation_hash
                     FROM solvan_delivery.code_change_github_observations item
                    WHERE item.organization_id=r.organization_id
                      AND item.project_id=r.project_id
                      AND item.environment_id=r.environment_id
                      AND item.code_change_request_id=r.id
                    ORDER BY sequence_no DESC LIMIT 1
                 ) o ON true
                WHERE r.organization_id=%(organization_id)s
                  AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                  AND r.id=%(request_id)s FOR UPDATE OF r""",
            {**scope.canonical_dict(), "request_id": request_id},
        )
        row = cursor.fetchone()
        if row is None or row["observation_hash"] != expected_previous_hash:
            raise CodeChangeOperationConflict("PR sync observation predecessor changed")
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
                 %(request_id)s,%(observation_sequence)s,'PR_SYNC',
                 %(pull_request_number)s,%(pull_request_url)s,%(branch_name)s,
                 %(base_commit_sha)s,%(head_commit_sha)s,%(head_tree_hash)s,%(diff_hash)s,
                 NULL,
                 %(required_check_state)s,%(required_checks_ref)s,%(required_checks_hash)s,
                 %(branch_rule_ref)s,%(branch_rule_hash)s,%(review_state)s,
                 %(review_state_ref)s,%(review_state_hash)s,
                 %(approved_account_node_ids)s,
                 %(required_check_definitions_ref)s,%(required_check_definitions_hash)s,
                 %(repository_policy_hash)s,%(provider_service_revision)s,
                 %(observation_ref)s,%(observation_hash)s,%(observed_at)s)""",
            {
                **scope.canonical_dict(),
                **observation,
                "id": new_identifier("cgo"),
                "request_id": request_id,
                "observation_sequence": int(row["observation_sequence"]) + 1,
                "observation_ref": observation_ref,
                "observation_hash": observation_hash,
            },
        )
        state = str(row["state"])
        sequence = int(row["sequence_no"])
        transitions: list[tuple[str, str]] = []
        if state == "PR_CREATED":
            transitions.append(("PR_CREATED", "CI_PENDING"))
            state = "CI_PENDING"
        check_state = str(observation["required_check_state"])
        review_state = str(observation["review_state"])
        if state == "CI_PENDING" and check_state == "FAILING":
            transitions.append(("CI_PENDING", "CI_FAILED"))
            state = "CI_FAILED"
        elif state == "CI_PENDING" and check_state == "PASSING":
            transitions.append(("CI_PENDING", "CI_PASSED"))
            transitions.append(("CI_PASSED", "GITHUB_REVIEW_PENDING"))
            state = "GITHUB_REVIEW_PENDING"
        elif state == "CI_PASSED":
            transitions.append(("CI_PASSED", "GITHUB_REVIEW_PENDING"))
            state = "GITHUB_REVIEW_PENDING"
        if (
            state == "GITHUB_REVIEW_PENDING"
            and check_state == "PASSING"
            and review_state == "APPROVED"
        ):
            transitions.append(("GITHUB_REVIEW_PENDING", "MERGE_APPROVAL_PENDING"))
        for from_state, to_state in transitions:
            input_material = {
                "schema_version": 1,
                "code_change_request_id": request_id,
                "from_state": from_state,
                "to_state": to_state,
                "observation_hash": observation_hash,
                "expected_sequence_no": sequence,
            }
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_transitions
                    (organization_id,project_id,environment_id,id,code_change_request_id,
                     sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                     idempotency_key,actor_kind,actor_identity,receipt_ref,receipt_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(next_sequence)s,%(from_state)s,%(to_state)s,
                     %(sequence)s,%(input_hash)s,%(idempotency_key)s,'GITHUB_PROVIDER',
                     %(actor)s,%(receipt_ref)s,%(receipt_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("cct"),
                    "request_id": request_id,
                    "next_sequence": sequence + 1,
                    "from_state": from_state,
                    "to_state": to_state,
                    "sequence": sequence,
                    "input_hash": canonical_sha256(input_material),
                    "idempotency_key": (
                        f"github-sync:{request_id}:{to_state.lower()}:{observation_hash}"
                    ),
                    "actor": actor_identity,
                    "receipt_ref": observation_ref,
                    "receipt_hash": observation_hash,
                },
            )
            sequence += 1
