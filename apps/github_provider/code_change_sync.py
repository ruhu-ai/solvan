"""Command-only authoritative GitHub PR/check/review synchronization."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from apps.github_provider.code_change_sync_transitions import record_sync_observation
from solvan.application.code_change_github_observation import (
    required_check_projection,
    review_projection,
    validate_branch_rule,
    validate_changed_files,
)
from solvan.application.code_change_transform import (
    RepositoryTreeEntry,
    parse_patch_transform,
    repository_tree_hash,
)
from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    DeliveryOutcome,
    DeliveryReasonCode,
    PrivateCommandEnvelope,
    PrivateCommandResponse,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.persistence.code_change_operation_store import (
    CodeChangeOperationConflict,
    PostgresCodeChangeOperationStore,
)
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_code_change import GitHubCodeChangeClient
from solvan.platform.github_repository_qualification import (
    GitHubRegularFile,
    GitHubRepositoryQualificationReader,
)
from solvan.platform.google_rest import authorized_session


class SyncSettings(Protocol):
    coordinator_audience: str
    runtime_bucket: str
    service_revision: str
    service_principal: str


def execute_sync_pr(
    *,
    envelope: PrivateCommandEnvelope,
    caller: str,
    settings: SyncSettings,
    code_client_factory: Callable[[int], GitHubCodeChangeClient],
    reader_factory: Callable[[int], GitHubRepositoryQualificationReader],
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return _terminal_replay(prior=prior, reader=reader)
        if command.command_kind is not DeliveryCommandKind.SYNC_PR:
            raise DeliveryCommandError("PR sync handler accepts only SYNC_PR")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("SYNC_PR command issue fence was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("SYNC_PR command is no longer recoverable")
        operations = PostgresCodeChangeOperationStore(connection)
        terminal = operations.sync_operation_terminal_receipt(
            scope=command.scope,
            request_id=command.subject_id,
            material_hash=command.material_hash,
        )
        if terminal is not None:
            result = reader.get_json(uri=terminal[0], expected_hash=terminal[1], max_bytes=64_000)
            if not isinstance(result, dict):
                raise DeliveryCommandError("PR sync terminal observation is malformed")
            return _complete_command(
                command_id=command.command_id,
                result=result,
                writer=writer,
                now=now,
            )
        material = operations.load_sync_material(
            scope=command.scope,
            request_id=command.subject_id,
            command_material_hash=command.material_hash,
            now=now,
        )
        with connection.transaction():
            operations.claim_sync_operation(
                scope=command.scope,
                request_id=command.subject_id,
                material_hash=command.material_hash,
            )
    transform_value = reader.get_json(
        uri=material.patch_transform_ref,
        expected_hash=material.patch_transform_hash,
        max_bytes=1_200_000,
    )
    transform = parse_patch_transform(transform_value)
    required_policy = _policy(
        reader,
        uri=material.required_checks_policy_ref,
        expected_hash=material.required_checks_policy_hash,
    )
    reviewer_policy = _policy(
        reader,
        uri=material.reviewer_policy_ref,
        expected_hash=material.reviewer_policy_hash,
    )
    required_names = required_policy.get("required_checks")
    if not isinstance(required_names, list) or any(
        not isinstance(item, str) for item in required_names
    ):
        raise DeliveryCommandError("required-check policy is malformed")
    code = code_client_factory(material.installation_id)
    repository_reader = reader_factory(material.installation_id)
    observed_pr = code.pull_request(
        owner=material.owner, name=material.name, number=material.pull_request_number
    )
    base_head = code.read_branch(
        owner=material.owner, name=material.name, branch=material.default_branch
    )
    repair_head = code.read_branch(
        owner=material.owner, name=material.name, branch=material.branch_name
    )
    if (
        base_head != material.base_commit_sha
        or repair_head != material.expected_head_commit_sha
        or observed_pr.head_sha != material.expected_head_commit_sha
        or observed_pr.base_sha != material.base_commit_sha
        or observed_pr.html_url != material.pull_request_url
        or observed_pr.state != "open"
        or observed_pr.merged
        or observed_pr.draft
    ):
        raise CodeChangeOperationConflict("GitHub PR/base/head state changed")
    files = repository_reader.regular_file_tree(
        owner=material.owner, name=material.name, commit_sha=observed_pr.head_sha
    )
    tree = tuple(RepositoryTreeEntry(item.path, item.mode, item.content_hash) for item in files)
    if repository_tree_hash(tree) != material.proposed_tree_hash:
        raise CodeChangeOperationConflict("GitHub PR tree differs from frozen proposal")
    diff_hash = validate_changed_files(
        transform=transform,
        files=code.pull_request_files(
            owner=material.owner, name=material.name, number=observed_pr.number
        ),
    )
    definitions = _required_definitions(
        files, required_paths=material.required_check_definition_paths
    )
    definitions_hash = canonical_sha256(definitions)
    if definitions_hash != material.base_required_check_definitions_hash:
        raise CodeChangeOperationConflict("required-check definitions changed")
    check_state, checks = required_check_projection(
        required_names=cast("list[str]", required_names),
        # Both APIs, because a required context may be either and reading only
        # check runs left a status-reported requirement permanently unobserved.
        runs=(
            code.check_runs(owner=material.owner, name=material.name, head_sha=observed_pr.head_sha)
            + code.commit_statuses(
                owner=material.owner, name=material.name, head_sha=observed_pr.head_sha
            )
        ),
        head_sha=observed_pr.head_sha,
    )
    branch_rule = validate_branch_rule(
        observed=code.branch_protection(
            owner=material.owner, name=material.name, branch=material.default_branch
        ),
        required_checks=cast("list[str]", required_names),
        reviewer_policy=reviewer_policy,
    )
    review_state, reviews = review_projection(
        reviews=code.reviews(owner=material.owner, name=material.name, number=observed_pr.number),
        head_sha=observed_pr.head_sha,
        github_review_decision=code.pull_request_review_decision(
            pull_request_node_id=observed_pr.node_id
        ),
        reviewer_policy=reviewer_policy,
    )
    approved_account_node_ids = sorted(
        str(item["account_node_id"])
        for item in cast("list[dict[str, object]]", reviews["reviews"])
        if item["state"] == "APPROVED" and item["commit_sha"] == observed_pr.head_sha
    )
    prefix = _result_prefix(command.scope, command.command_id)
    checks_receipt = writer.put_json(object_name=f"{prefix}/checks.json", value=checks)
    branch_receipt = writer.put_json(object_name=f"{prefix}/branch-rule.json", value=branch_rule)
    review_receipt = writer.put_json(object_name=f"{prefix}/reviews.json", value=reviews)
    definition_receipt = writer.put_json(
        object_name=f"{prefix}/required-check-definitions.json", value=definitions
    )
    observation = {
        "schema_version": 1,
        "observation_kind": "PR_SYNC",
        "code_change_request_id": material.request_id,
        "pull_request_number": observed_pr.number,
        "pull_request_url": observed_pr.html_url,
        "branch_name": material.branch_name,
        "base_commit_sha": observed_pr.base_sha,
        "head_commit_sha": observed_pr.head_sha,
        "head_tree_hash": material.proposed_tree_hash,
        "diff_hash": diff_hash,
        "required_check_state": check_state,
        "required_checks_ref": checks_receipt.uri,
        "required_checks_hash": checks_receipt.content_hash,
        "branch_rule_ref": branch_receipt.uri,
        "branch_rule_hash": branch_receipt.content_hash,
        "review_state": review_state,
        "review_state_ref": review_receipt.uri,
        "review_state_hash": review_receipt.content_hash,
        "approved_account_node_ids": approved_account_node_ids,
        "required_check_definitions_ref": definition_receipt.uri,
        "required_check_definitions_hash": definition_receipt.content_hash,
        "repository_policy_hash": material.repository_policy_hash,
        "provider_service_revision": settings.service_revision,
        "observed_at": now.isoformat(),
    }
    observation_receipt = writer.put_json(
        object_name=f"{prefix}/observation.json", value=observation
    )
    with connect_database() as connection, connection.transaction():
        record_sync_observation(
            connection=connection,
            scope=command.scope,
            request_id=material.request_id,
            expected_previous_hash=material.previous_observation_hash,
            observation=observation,
            observation_ref=observation_receipt.uri,
            observation_hash=observation_receipt.content_hash,
            actor_identity=settings.service_principal,
        )
        PostgresCodeChangeOperationStore(connection).complete_sync_operation(
            scope=command.scope,
            request_id=material.request_id,
            material_hash=command.material_hash,
            response_ref=observation_receipt.uri,
            response_hash=observation_receipt.content_hash,
        )
    return _complete_command(
        command_id=command.command_id, result=observation, writer=writer, now=now
    )


def _policy(reader: GcsEvidenceReader, *, uri: str, expected_hash: str) -> Mapping[str, object]:
    value = reader.get_json(uri=uri, expected_hash=expected_hash, max_bytes=32_000)
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise DeliveryCommandError("GitHub policy document is malformed")
    return cast("Mapping[str, object]", value)


def _required_definitions(
    files: tuple[GitHubRegularFile, ...], *, required_paths: tuple[str, ...]
) -> dict[str, object]:
    by_path = {item.path: item for item in files}
    if any(path not in by_path for path in required_paths):
        raise CodeChangeOperationConflict("required-check definition is absent from PR head")
    return {
        "schema_version": 1,
        "definitions": [
            {
                "path": path,
                "mode": by_path[path].mode,
                "blob_sha": by_path[path].blob_sha,
                "content_hash": by_path[path].content_hash,
            }
            for path in sorted(required_paths)
        ],
    }


def _complete_command(
    *, command_id: str, result: dict[str, Any], writer: GcsEvidenceWriter, now: datetime
) -> dict[str, Any]:
    result_receipt = writer.put_json(
        object_name=f"private-command-results/{command_id}/sync-pr.json", value=result
    )
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=result_receipt.uri,
        receipt_hash=result_receipt.content_hash,
        observed_at=now,
    )
    response_receipt = writer.put_json(
        object_name=f"private-command-responses/{command_id}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=response_receipt.uri,
            response_hash=response_receipt.content_hash,
        )
    return response.model_dump(mode="json")


def _terminal_replay(*, prior: PrivateCommandResponse, reader: GcsEvidenceReader) -> dict[str, Any]:
    if prior.receipt_ref is None or prior.receipt_hash is None:
        raise DeliveryCommandError("terminal PR sync response omitted its receipt")
    reader.get_json(uri=prior.receipt_ref, expected_hash=prior.receipt_hash, max_bytes=64_000)
    return prior.model_dump(mode="json")


def _result_prefix(scope: Any, command_id: str) -> str:
    return (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        f"github-code-change/{command_id}"
    )
