"""Command-only GitHub branch and draft pull-request delivery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from apps.github_provider.code_change_ready import (
    ensure_ready_for_review as _ensure_ready_for_review,
)
from apps.github_provider.code_change_transitions import (
    append_blocked_transition as _append_blocked_transition,
)
from apps.github_provider.code_change_transitions import (
    append_pr_created_transition as _append_pr_created_transition,
)
from apps.github_provider.code_change_transitions import (
    close_open_operations as _close_open_operations,
)
from solvan.application.code_change_transform import (
    RepositoryTreeEntry,
    apply_patch_transform,
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
from solvan.domain import Scope
from solvan.persistence.code_change_operation_store import (
    CodeChangeOperationConflict,
    PostgresCodeChangeOperationStore,
    PullRequestProviderMaterial,
)
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github import GitHubApiError, GitHubClient
from solvan.platform.github_code_change import GitHubCodeChangeClient
from solvan.platform.github_repository_qualification import (
    GitHubRepositoryQualificationReader,
)
from solvan.platform.google_rest import authorized_session


class CodeChangeSettings(Protocol):
    coordinator_audience: str
    runtime_bucket: str
    service_revision: str
    service_principal: str


def execute_create_pr(
    *,
    envelope: PrivateCommandEnvelope,
    caller: str,
    settings: CodeChangeSettings,
    client_factory: Callable[[int], GitHubClient],
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
        if command.command_kind is not DeliveryCommandKind.CREATE_PR:
            raise DeliveryCommandError("code-change handler accepts only CREATE_PR")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("CREATE_PR command issue fence was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("CREATE_PR command is no longer recoverable")
        material = PostgresCodeChangeOperationStore(connection).load_pr_material(
            scope=command.scope, request_id=command.subject_id, now=now
        )
    transform_value = reader.get_json(
        uri=material.patch_transform_ref,
        expected_hash=material.patch_transform_hash,
        max_bytes=1_200_000,
    )
    transform = parse_patch_transform(transform_value)
    if (
        transform.base_commit_sha != material.base_commit_sha
        or transform.base_tree_hash != material.base_tree_hash
        or transform.proposed_tree_hash != material.proposed_tree_hash
    ):
        raise DeliveryCommandError("CCR transform no longer matches immutable request")
    github = client_factory(material.installation_id)
    code = code_client_factory(material.installation_id)
    repository = github.repository(owner=material.owner, name=material.name)
    if repository.get("default_branch") != material.default_branch:
        return _refuse(
            command_id=command.command_id,
            scope=command.scope,
            material=material,
            writer=writer,
            reason="BASE_STALE",
            now=now,
        )
    current_commit = github.resolve_commit(
        owner=material.owner,
        name=material.name,
        ref=f"refs/heads/{material.default_branch}",
    )
    repository_reader = reader_factory(material.installation_id)
    base_tree = _logical_tree(
        repository_reader=repository_reader,
        material=material,
        commit_sha=current_commit,
    )
    if current_commit != material.base_commit_sha or repository_tree_hash(base_tree) != (
        material.base_tree_hash
    ):
        return _refuse(
            command_id=command.command_id,
            scope=command.scope,
            material=material,
            writer=writer,
            reason="BASE_STALE",
            now=now,
        )
    apply_patch_transform(base_tree=base_tree, transform=transform)
    prepared = code.prepare_commit(
        owner=material.owner,
        name=material.name,
        base_commit_sha=material.base_commit_sha,
        transform=transform,
        committed_at=material.created_at,
        message=f"Solvan governed repair {material.request_id}",
    )
    proposed_tree = _logical_tree(
        repository_reader=repository_reader,
        material=material,
        commit_sha=prepared.commit_sha,
    )
    if repository_tree_hash(proposed_tree) != material.proposed_tree_hash:
        return _ambiguous(
            command_id=command.command_id,
            scope=command.scope,
            material=material,
            writer=writer,
            reason="PROPOSED_TREE_MISMATCH",
            now=now,
        )
    branch_result = _ensure_branch(
        code=code,
        scope=command.scope,
        material=material,
        commit_sha=prepared.commit_sha,
        writer=writer,
        command_id=command.command_id,
    )
    if branch_result is not None:
        return _complete_command_result(
            command_id=command.command_id,
            outcome=branch_result[0],
            reason=branch_result[1],
            result=branch_result[2],
            writer=writer,
            now=now,
        )
    pr_result = _ensure_pull_request(
        code=code,
        scope=command.scope,
        material=material,
        head_sha=prepared.commit_sha,
        writer=writer,
        command_id=command.command_id,
    )
    if pr_result is not None:
        return _complete_command_result(
            command_id=command.command_id,
            outcome=pr_result[0],
            reason=pr_result[1],
            result=pr_result[2],
            writer=writer,
            now=now,
        )
    ready_result = _ensure_ready_for_review(
        code=code,
        scope=command.scope,
        material=material,
        head_sha=prepared.commit_sha,
        writer=writer,
        command_id=command.command_id,
    )
    if ready_result is not None:
        return _complete_command_result(
            command_id=command.command_id,
            outcome=ready_result[0],
            reason=ready_result[1],
            result=ready_result[2],
            writer=writer,
            now=now,
        )
    observed = code.find_pull_request(
        owner=material.owner,
        name=material.name,
        branch=material.branch_name,
        base=material.default_branch,
    )
    if observed is None or observed.head_sha != prepared.commit_sha or observed.draft:
        return _ambiguous(
            command_id=command.command_id,
            scope=command.scope,
            material=material,
            writer=writer,
            reason="PULL_REQUEST_NOT_RECONCILED",
            now=now,
        )
    result = {
        "schema_version": 1,
        "code_change_request_id": material.request_id,
        "repository_binding_id": material.repository_binding_id,
        "branch": material.branch_name,
        "head_commit_sha": prepared.commit_sha,
        "proposed_tree_hash": material.proposed_tree_hash,
        "pull_request_number": observed.number,
        "pull_request_url": observed.html_url,
        "base_commit_sha": observed.base_sha,
        "provider_service_revision": settings.service_revision,
    }
    result_receipt = writer.put_json(
        object_name=_result_name(command.scope, command.command_id, "create-pr.json"),
        value=result,
    )
    checks_receipt = writer.put_json(
        object_name=_result_name(command.scope, command.command_id, "initial-checks.json"),
        value={"schema_version": 1, "state": "PENDING", "check_runs": []},
    )
    branch_rule_receipt = writer.put_json(
        object_name=_result_name(command.scope, command.command_id, "initial-branch-rule.json"),
        value={"schema_version": 1, "state": "NOT_OBSERVED"},
    )
    review_receipt = writer.put_json(
        object_name=_result_name(command.scope, command.command_id, "initial-review.json"),
        value={"schema_version": 1, "state": "PENDING", "reviews": []},
    )
    observation = {
        "schema_version": 1,
        "observation_kind": "PR_CREATED",
        "code_change_request_id": material.request_id,
        "pull_request_number": observed.number,
        "pull_request_url": observed.html_url,
        "branch_name": material.branch_name,
        "base_commit_sha": observed.base_sha,
        "head_commit_sha": observed.head_sha,
        "head_tree_hash": material.proposed_tree_hash,
        "diff_hash": material.patch_transform_hash,
        "required_check_state": "PENDING",
        "required_checks_ref": checks_receipt.uri,
        "required_checks_hash": checks_receipt.content_hash,
        "branch_rule_ref": branch_rule_receipt.uri,
        "branch_rule_hash": branch_rule_receipt.content_hash,
        "review_state": "PENDING",
        "review_state_ref": review_receipt.uri,
        "review_state_hash": review_receipt.content_hash,
        "approved_account_node_ids": [],
        "required_check_definitions_ref": material.base_required_check_definitions_ref,
        "required_check_definitions_hash": material.base_required_check_definitions_hash,
        "repository_policy_hash": material.repository_policy_hash,
        "provider_service_revision": settings.service_revision,
        "observed_at": now.isoformat(),
    }
    observation_receipt = writer.put_json(
        object_name=_result_name(command.scope, command.command_id, "observation.json"),
        value=observation,
    )
    with connect_database() as connection, connection.transaction():
        _append_pr_created_transition(
            connection=connection,
            scope=command.scope,
            material=material,
            receipt_ref=result_receipt.uri,
            receipt_hash=result_receipt.content_hash,
            observation=observation,
            observation_ref=observation_receipt.uri,
            observation_hash=observation_receipt.content_hash,
            actor_identity=settings.service_principal,
        )
    return _complete_command_result(
        command_id=command.command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason=DeliveryReasonCode.OPERATION_COMPLETED,
        result=result,
        writer=writer,
        now=now,
    )


def _logical_tree(
    *,
    repository_reader: GitHubRepositoryQualificationReader,
    material: PullRequestProviderMaterial,
    commit_sha: str,
) -> tuple[RepositoryTreeEntry, ...]:
    files = repository_reader.regular_file_tree(
        owner=material.owner, name=material.name, commit_sha=commit_sha
    )
    return tuple(RepositoryTreeEntry(item.path, item.mode, item.content_hash) for item in files)


def _ensure_branch(
    *,
    code: GitHubCodeChangeClient,
    scope: Scope,
    material: PullRequestProviderMaterial,
    commit_sha: str,
    writer: GcsEvidenceWriter,
    command_id: str,
) -> tuple[DeliveryOutcome, DeliveryReasonCode, dict[str, Any]] | None:
    with connect_database() as connection:
        store = PostgresCodeChangeOperationStore(connection)
        status = store.operation_statuses(scope=scope, request_id=material.request_id).get(
            "CREATE_BRANCH"
        )
        observed = code.read_branch(
            owner=material.owner, name=material.name, branch=material.branch_name
        )
        if status == "PREPARED":
            if observed is not None:
                return _operation_failure(
                    store=store,
                    connection=connection,
                    scope=scope,
                    material=material,
                    kind="CREATE_BRANCH",
                    writer=writer,
                    command_id=command_id,
                    reason="REF_COLLISION",
                    ambiguous=False,
                )
            with connection.transaction():
                if not store.claim_operation(
                    scope=scope, request_id=material.request_id, kind="CREATE_BRANCH"
                ):
                    raise CodeChangeOperationConflict("branch issue fence was already claimed")
            try:
                code.create_branch(
                    owner=material.owner,
                    name=material.name,
                    branch=material.branch_name,
                    commit_sha=commit_sha,
                )
            except GitHubApiError:
                observed = code.read_branch(
                    owner=material.owner, name=material.name, branch=material.branch_name
                )
                if observed != commit_sha:
                    return _operation_failure(
                        store=store,
                        connection=connection,
                        scope=scope,
                        material=material,
                        kind="CREATE_BRANCH",
                        writer=writer,
                        command_id=command_id,
                        reason="EXTERNAL_STATE_AMBIGUOUS",
                        ambiguous=True,
                    )
            observed = commit_sha
        if status in {"ISSUED", "RECONCILING", "SUCCEEDED"} and observed != commit_sha:
            return _operation_failure(
                store=store,
                connection=connection,
                scope=scope,
                material=material,
                kind="CREATE_BRANCH",
                writer=writer,
                command_id=command_id,
                reason="EXTERNAL_STATE_CHANGED",
                ambiguous=True,
            )
        if status != "SUCCEEDED":
            receipt = writer.put_json(
                object_name=_result_name(scope, command_id, "branch.json"),
                value={"branch": material.branch_name, "head_commit_sha": commit_sha},
            )
            with connection.transaction():
                store.complete_operation(
                    scope=scope,
                    request_id=material.request_id,
                    kind="CREATE_BRANCH",
                    response_ref=receipt.uri,
                    response_hash=receipt.content_hash,
                    status="SUCCEEDED",
                )
    return None


def _ensure_pull_request(
    *,
    code: GitHubCodeChangeClient,
    scope: Scope,
    material: PullRequestProviderMaterial,
    head_sha: str,
    writer: GcsEvidenceWriter,
    command_id: str,
) -> tuple[DeliveryOutcome, DeliveryReasonCode, dict[str, Any]] | None:
    title = f"Solvan governed repair {material.request_id}"
    body = (
        "This draft was created by Solvan from an independently adjudicated, "
        f"provider-qualified transform.\n\nRequest: `{material.request_id}`\n"
        f"Proposed tree: `{material.proposed_tree_hash}`"
    )
    with connect_database() as connection:
        store = PostgresCodeChangeOperationStore(connection)
        status = store.operation_statuses(scope=scope, request_id=material.request_id).get(
            "CREATE_PR"
        )
        observed = code.find_pull_request(
            owner=material.owner,
            name=material.name,
            branch=material.branch_name,
            base=material.default_branch,
        )
        if status == "PREPARED":
            if observed is not None:
                return _operation_failure(
                    store=store,
                    connection=connection,
                    scope=scope,
                    material=material,
                    kind="CREATE_PR",
                    writer=writer,
                    command_id=command_id,
                    reason="PR_COLLISION",
                    ambiguous=False,
                )
            with connection.transaction():
                if not store.claim_operation(
                    scope=scope, request_id=material.request_id, kind="CREATE_PR"
                ):
                    raise CodeChangeOperationConflict("pull-request issue fence was claimed")
            try:
                observed = code.create_pull_request(
                    owner=material.owner,
                    name=material.name,
                    branch=material.branch_name,
                    base=material.default_branch,
                    title=title,
                    body=body,
                )
            except GitHubApiError:
                observed = code.find_pull_request(
                    owner=material.owner,
                    name=material.name,
                    branch=material.branch_name,
                    base=material.default_branch,
                )
        if (
            observed is None
            or observed.head_sha != head_sha
            or observed.base_sha != material.base_commit_sha
            or observed.title != title
        ):
            return _operation_failure(
                store=store,
                connection=connection,
                scope=scope,
                material=material,
                kind="CREATE_PR",
                writer=writer,
                command_id=command_id,
                reason="PULL_REQUEST_STATE_MISMATCH",
                ambiguous=status != "PREPARED",
            )
        if status != "SUCCEEDED":
            receipt = writer.put_json(
                object_name=_result_name(scope, command_id, "pull-request.json"),
                value={
                    "number": observed.number,
                    "url": observed.html_url,
                    "head_commit_sha": observed.head_sha,
                    "base_commit_sha": observed.base_sha,
                    "title": observed.title,
                },
            )
            with connection.transaction():
                store.complete_operation(
                    scope=scope,
                    request_id=material.request_id,
                    kind="CREATE_PR",
                    response_ref=receipt.uri,
                    response_hash=receipt.content_hash,
                    status="SUCCEEDED",
                )
    return None


def _operation_failure(
    *,
    store: PostgresCodeChangeOperationStore,
    connection: Any,
    scope: Scope,
    material: PullRequestProviderMaterial,
    kind: str,
    writer: GcsEvidenceWriter,
    command_id: str,
    reason: str,
    ambiguous: bool,
) -> tuple[DeliveryOutcome, DeliveryReasonCode, dict[str, Any]]:
    result = {
        "schema_version": 1,
        "outcome": "AMBIGUOUS" if ambiguous else "REFUSED",
        "reason": reason,
    }
    receipt = writer.put_json(
        object_name=_result_name(scope, command_id, f"{kind.lower()}-failure.json"),
        value=result,
    )
    with connection.transaction():
        current = store.operation_statuses(scope=scope, request_id=material.request_id).get(kind)
        if current not in {"SUCCEEDED", "REFUSED", "AMBIGUOUS"}:
            store.complete_operation(
                scope=scope,
                request_id=material.request_id,
                kind=kind,
                response_ref=receipt.uri,
                response_hash=receipt.content_hash,
                status="AMBIGUOUS" if ambiguous else "REFUSED",
                error_class=reason,
            )
        _append_blocked_transition(
            connection=connection,
            scope=scope,
            material=material,
            receipt_ref=receipt.uri,
            receipt_hash=receipt.content_hash,
            reason=reason,
        )
    return (
        DeliveryOutcome.AMBIGUOUS if ambiguous else DeliveryOutcome.REFUSED,
        DeliveryReasonCode.EXTERNAL_STATE_AMBIGUOUS
        if ambiguous
        else DeliveryReasonCode.PRECONDITION_FAILED,
        result,
    )


def _refuse(
    *,
    command_id: str,
    scope: Scope,
    material: PullRequestProviderMaterial,
    writer: GcsEvidenceWriter,
    reason: str,
    now: datetime,
) -> dict[str, Any]:
    result = {"schema_version": 1, "outcome": "REFUSED", "reason": reason}
    receipt = writer.put_json(
        object_name=_result_name(scope, command_id, "refusal.json"), value=result
    )
    with connect_database() as connection, connection.transaction():
        _close_open_operations(
            connection=connection,
            scope=scope,
            material=material,
            receipt_ref=receipt.uri,
            receipt_hash=receipt.content_hash,
            status="REFUSED",
            reason=reason,
        )
        _append_blocked_transition(
            connection=connection,
            scope=scope,
            material=material,
            receipt_ref=receipt.uri,
            receipt_hash=receipt.content_hash,
            reason=reason,
        )
    return _complete_command_result(
        command_id=command_id,
        outcome=DeliveryOutcome.REFUSED,
        reason=DeliveryReasonCode.PRECONDITION_FAILED,
        result=result,
        writer=writer,
        now=now,
    )


def _ambiguous(
    *,
    command_id: str,
    scope: Scope,
    material: PullRequestProviderMaterial,
    writer: GcsEvidenceWriter,
    reason: str,
    now: datetime,
) -> dict[str, Any]:
    result = {"schema_version": 1, "outcome": "AMBIGUOUS", "reason": reason}
    receipt = writer.put_json(
        object_name=_result_name(scope, command_id, "ambiguity.json"), value=result
    )
    with connect_database() as connection, connection.transaction():
        _close_open_operations(
            connection=connection,
            scope=scope,
            material=material,
            receipt_ref=receipt.uri,
            receipt_hash=receipt.content_hash,
            status="AMBIGUOUS",
            reason=reason,
        )
        _append_blocked_transition(
            connection=connection,
            scope=scope,
            material=material,
            receipt_ref=receipt.uri,
            receipt_hash=receipt.content_hash,
            reason=reason,
        )
    return _complete_command_result(
        command_id=command_id,
        outcome=DeliveryOutcome.AMBIGUOUS,
        reason=DeliveryReasonCode.EXTERNAL_STATE_AMBIGUOUS,
        result=result,
        writer=writer,
        now=now,
    )


def _complete_command_result(
    *,
    command_id: str,
    outcome: DeliveryOutcome,
    reason: DeliveryReasonCode,
    result: dict[str, Any],
    writer: GcsEvidenceWriter,
    now: datetime,
) -> dict[str, Any]:
    result_receipt = writer.put_json(object_name=f"commands/{command_id}/result.json", value=result)
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=outcome,
        reason_code=reason,
        receipt_ref=result_receipt.uri,
        receipt_hash=result_receipt.content_hash,
        observed_at=now,
    )
    envelope_receipt = writer.put_json(
        object_name=f"commands/{command_id}/response-envelope.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=envelope_receipt.uri,
            response_hash=canonical_sha256(response.model_dump(mode="json")),
        )
    return {"command": response.model_dump(mode="json"), "result": result}


def _terminal_replay(*, prior: PrivateCommandResponse, reader: GcsEvidenceReader) -> dict[str, Any]:
    result = reader.get_json(
        uri=prior.receipt_ref or "", expected_hash=prior.receipt_hash or "", max_bytes=64_000
    )
    return {"command": prior.model_dump(mode="json"), "result": result}


def _result_name(scope: Scope, command_id: str, leaf: str) -> str:
    return (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        f"code-change-requests/{command_id}/{leaf}"
    )
