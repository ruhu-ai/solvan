"""Command-only, immediately revalidated GitHub merge delivery."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from apps.github_provider.code_change_merge_transition import record_merged
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
from solvan.persistence.code_change_merge_store import (
    MergeProviderMaterial,
    PostgresCodeChangeMergeStore,
)
from solvan.persistence.code_change_operation_store import CodeChangeOperationConflict
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_code_change import GitHubCodeChangeClient
from solvan.platform.github_repository_qualification import (
    GitHubRegularFile,
    GitHubRepositoryQualificationReader,
)
from solvan.platform.google_rest import authorized_session


class MergeSettings(Protocol):
    coordinator_audience: str
    runtime_bucket: str
    service_revision: str
    service_principal: str


def execute_merge_pr(
    *,
    envelope: PrivateCommandEnvelope,
    caller: str,
    settings: MergeSettings,
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
        if command.command_kind is not DeliveryCommandKind.MERGE_PR:
            raise DeliveryCommandError("merge handler accepts only MERGE_PR")
        observation_hash = command.payload.get("github_observation_hash")
        if (
            set(command.payload) != {"github_observation_hash"}
            or not isinstance(observation_hash, str)
            or not observation_hash.startswith("sha256:")
            or len(observation_hash) != 71
        ):
            raise DeliveryCommandError("MERGE_PR observation binding is malformed")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("MERGE_PR command issue fence was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("MERGE_PR command is no longer recoverable")
        store = PostgresCodeChangeMergeStore(connection)
        terminal = store.terminal_receipt(
            scope=command.scope,
            request_id=command.subject_id,
            material_hash=command.material_hash,
        )
        if terminal is not None:
            result = reader.get_json(uri=terminal[0], expected_hash=terminal[1], max_bytes=64_000)
            if not isinstance(result, dict):
                raise DeliveryCommandError("merge terminal receipt is malformed")
            return _complete_command(
                command_id=command.command_id, result=result, writer=writer, now=now
            )
        material = store.load(
            scope=command.scope,
            request_id=command.subject_id,
            command_material_hash=command.material_hash,
            github_observation_hash=observation_hash,
            now=now,
        )
    code = code_client_factory(material.installation_id)
    repository_reader = reader_factory(material.installation_id)
    observed_pr = code.pull_request(
        owner=material.owner, name=material.name, number=material.pull_request_number
    )
    if material.operation_status == "PREPARED":
        observation = _revalidate(
            material=material,
            code=code,
            repository_reader=repository_reader,
            evidence_reader=reader,
            observed_pr=observed_pr,
        )
        checks = cast("dict[str, object]", observation.pop("_checks"))
        branch_rule = cast("dict[str, object]", observation.pop("_branch_rule"))
        reviews = cast("dict[str, object]", observation.pop("_reviews"))
        definitions = cast("dict[str, object]", observation.pop("_definitions"))
        prefix = _prefix(command.scope, command.command_id)
        checks_receipt = writer.put_json(object_name=f"{prefix}/checks.json", value=checks)
        branch_receipt = writer.put_json(
            object_name=f"{prefix}/branch-rule.json", value=branch_rule
        )
        review_receipt = writer.put_json(object_name=f"{prefix}/reviews.json", value=reviews)
        definitions_receipt = writer.put_json(
            object_name=f"{prefix}/required-check-definitions.json", value=definitions
        )
        observation.update(
            {
                "required_checks_ref": checks_receipt.uri,
                "required_checks_hash": checks_receipt.content_hash,
                "branch_rule_ref": branch_receipt.uri,
                "branch_rule_hash": branch_receipt.content_hash,
                "review_state_ref": review_receipt.uri,
                "review_state_hash": review_receipt.content_hash,
                "required_check_definitions_ref": definitions_receipt.uri,
                "required_check_definitions_hash": definitions_receipt.content_hash,
            }
        )
        merge_policy = _policy(
            reader, uri=material.merge_policy_ref, expected_hash=material.merge_policy_hash
        )
        merge_method = merge_policy.get("merge_method")
        if merge_method not in {"merge", "squash", "rebase"}:
            raise DeliveryCommandError("merge policy method is malformed")
        with connect_database() as connection, connection.transaction():
            if not PostgresCodeChangeMergeStore(connection).claim(
                scope=command.scope,
                request_id=material.request_id,
                material_hash=command.material_hash,
            ):
                raise CodeChangeOperationConflict("merge effect fence was already claimed")
        response = code.merge_pull_request(
            owner=material.owner,
            name=material.name,
            number=material.pull_request_number,
            expected_head_sha=material.expected_head_commit_sha,
            merge_method=str(merge_method),
        )
        if not response.merged or response.merge_commit_sha is None:
            raise CodeChangeOperationConflict("GitHub refused the exact protected merge")
        merge_commit_sha = response.merge_commit_sha
    else:
        observation = _recovery_observation(
            material=material,
            evidence_reader=reader,
        )
        if not observed_pr.merged or observed_pr.merge_commit_sha is None:
            raise CodeChangeOperationConflict("issued GitHub merge is externally ambiguous")
        merge_commit_sha = observed_pr.merge_commit_sha
    merged_files = repository_reader.regular_file_tree(
        owner=material.owner, name=material.name, commit_sha=merge_commit_sha
    )
    merged_tree = tuple(
        RepositoryTreeEntry(item.path, item.mode, item.content_hash) for item in merged_files
    )
    if repository_tree_hash(merged_tree) != material.proposed_tree_hash:
        raise CodeChangeOperationConflict("merged GitHub tree differs from approved proposal")
    observation = {
        **observation,
        "observation_kind": "MERGED",
        "merge_commit_sha": merge_commit_sha,
        "provider_service_revision": settings.service_revision,
        "observed_at": now.isoformat(),
    }
    receipt = writer.put_json(
        object_name=f"{_prefix(command.scope, command.command_id)}/merged.json",
        value=observation,
    )
    with connect_database() as connection, connection.transaction():
        record_merged(
            connection=connection,
            scope=command.scope,
            material=material,
            observation=observation,
            observation_ref=receipt.uri,
            observation_hash=receipt.content_hash,
            actor_identity=settings.service_principal,
        )
        PostgresCodeChangeMergeStore(connection).complete(
            scope=command.scope,
            request_id=material.request_id,
            material_hash=command.material_hash,
            response_ref=receipt.uri,
            response_hash=receipt.content_hash,
        )
    return _complete_command(
        command_id=command.command_id, result=observation, writer=writer, now=now
    )


def _revalidate(
    *,
    material: MergeProviderMaterial,
    code: GitHubCodeChangeClient,
    repository_reader: GitHubRepositoryQualificationReader,
    evidence_reader: GcsEvidenceReader,
    observed_pr: Any,
) -> dict[str, object]:
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
        raise CodeChangeOperationConflict("GitHub merge material changed")
    transform_value = evidence_reader.get_json(
        uri=material.patch_transform_ref,
        expected_hash=material.patch_transform_hash,
        max_bytes=1_200_000,
    )
    transform = parse_patch_transform(transform_value)
    files = repository_reader.regular_file_tree(
        owner=material.owner, name=material.name, commit_sha=observed_pr.head_sha
    )
    tree = tuple(RepositoryTreeEntry(item.path, item.mode, item.content_hash) for item in files)
    if repository_tree_hash(tree) != material.proposed_tree_hash:
        raise CodeChangeOperationConflict("GitHub merge head tree changed")
    diff_hash = validate_changed_files(
        transform=transform,
        files=code.pull_request_files(
            owner=material.owner, name=material.name, number=observed_pr.number
        ),
    )
    definitions = _required_definitions(
        files, required_paths=material.required_check_definition_paths
    )
    if canonical_sha256(definitions) != material.base_required_check_definitions_hash:
        raise CodeChangeOperationConflict("required-check definitions changed before merge")
    required_policy = _policy(
        evidence_reader,
        uri=material.required_checks_policy_ref,
        expected_hash=material.required_checks_policy_hash,
    )
    reviewer_policy = _policy(
        evidence_reader,
        uri=material.reviewer_policy_ref,
        expected_hash=material.reviewer_policy_hash,
    )
    required_names = required_policy.get("required_checks")
    if not isinstance(required_names, list) or any(
        not isinstance(item, str) for item in required_names
    ):
        raise DeliveryCommandError("required-check policy is malformed")
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
    approved = sorted(
        str(item["account_node_id"])
        for item in cast("list[dict[str, object]]", reviews["reviews"])
        if item["state"] == "APPROVED" and item["commit_sha"] == observed_pr.head_sha
    )
    if (
        check_state != "PASSING"
        or review_state != "APPROVED"
        or material.github_account_node_id not in approved
        or canonical_sha256(reviews) != material.github_review_state_hash
    ):
        raise CodeChangeOperationConflict("merge decision's GitHub review material changed")
    return {
        "schema_version": 1,
        "code_change_request_id": material.request_id,
        "pull_request_number": observed_pr.number,
        "pull_request_url": observed_pr.html_url,
        "branch_name": material.branch_name,
        "base_commit_sha": observed_pr.base_sha,
        "head_commit_sha": observed_pr.head_sha,
        "head_tree_hash": material.proposed_tree_hash,
        "diff_hash": diff_hash,
        "required_check_state": check_state,
        "required_checks_hash": canonical_sha256(checks),
        "branch_rule_hash": canonical_sha256(branch_rule),
        "review_state": review_state,
        "review_state_hash": canonical_sha256(reviews),
        "approved_account_node_ids": approved,
        "required_check_definitions_hash": canonical_sha256(definitions),
        "repository_policy_hash": material.repository_policy_hash,
        "_checks": checks,
        "_branch_rule": branch_rule,
        "_reviews": reviews,
        "_definitions": definitions,
    }


def _recovery_observation(
    *, material: MergeProviderMaterial, evidence_reader: GcsEvidenceReader
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "code_change_request_id": material.request_id,
        "pull_request_number": material.pull_request_number,
        "pull_request_url": material.pull_request_url,
        "branch_name": material.branch_name,
        "base_commit_sha": material.base_commit_sha,
        "head_commit_sha": material.expected_head_commit_sha,
        "head_tree_hash": material.proposed_tree_hash,
        "diff_hash": material.diff_hash,
        "required_check_state": "PASSING",
        "required_checks_ref": material.required_checks_ref,
        "required_checks_hash": material.required_checks_hash,
        "branch_rule_ref": material.branch_rule_ref,
        "branch_rule_hash": material.branch_rule_hash,
        "review_state": "APPROVED",
        "review_state_ref": material.review_state_ref,
        "review_state_hash": material.github_review_state_hash,
        "approved_account_node_ids": [material.github_account_node_id],
        "required_check_definitions_hash": material.base_required_check_definitions_hash,
        "required_check_definitions_ref": material.required_check_definitions_ref,
        "repository_policy_hash": material.repository_policy_hash,
    }


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
        raise CodeChangeOperationConflict("required-check definition is absent")
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
        object_name=f"private-command-results/{command_id}/merge-pr.json", value=result
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
        raise DeliveryCommandError("terminal merge response omitted its receipt")
    reader.get_json(uri=prior.receipt_ref, expected_hash=prior.receipt_hash, max_bytes=64_000)
    return prior.model_dump(mode="json")


def _prefix(scope: Any, command_id: str) -> str:
    return (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        f"github-code-change/{command_id}"
    )
