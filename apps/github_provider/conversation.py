"""Publish one approved conversational action, or refuse to publish it.

This is the only code path by which text Solvan wrote reaches a repository.
Everything it needs comes from the durable action record, never from the
request body, so a caller holding a valid command ID cannot redirect a
publication to a different thread or swap the words that were approved.

Publication has no dry run.  A comment has no observable pre-state to compare
an effect against — it either exists afterwards or it does not.  So the control
is revalidation: immediately before the request is constructed, the target is
re-read and every fact the approval depended on is checked again.  What follows
is deliberately a wall of refusals; each one is a way an approval could have
gone stale between a human clicking approve and this request leaving the
process.

Specification 24 §5 and §6 govern.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError

from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    DeliveryOutcome,
    DeliveryReasonCode,
    PrivateCommandEnvelope,
    PrivateCommandResponse,
)
from solvan.application.github_body import PINNED_REGISTRY_DIGEST
from solvan.application.github_conversation import (
    ConversationOperation,
    GitHubConversationError,
    PublishConversationCommand,
    ReviewEvent,
    ThreadState,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.persistence.github_conversation_store import (
    ClaimedConversationAction,
    GitHubConversationStore,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_conversation import (
    GitHubConversationClient,
    GitHubRateLimited,
    PublicationReceipt,
)
from solvan.platform.google_rest import authorized_session


class ConversationSettings(Protocol):
    coordinator_audience: str
    runtime_bucket: str
    service_revision: str
    service_principal: str


def execute_publish_conversation(
    *,
    envelope: PrivateCommandEnvelope,
    caller: str,
    settings: ConversationSettings,
    client_factory: Callable[[int, str], GitHubConversationClient],
) -> dict[str, Any]:
    """Execute one approved publication under its durable command fence."""

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
        if command.command_kind is not DeliveryCommandKind.PUBLISH_GITHUB_CONVERSATION:
            raise DeliveryCommandError(
                "conversation handler accepts only PUBLISH_GITHUB_CONVERSATION"
            )
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("publication command issue fence was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("publication command is no longer recoverable")

        # The registry that rendered the body must still be the pinned one. A
        # template edit between approval and dispatch means the approver read
        # sentences this process would no longer produce.
        declared_digest = str(command.payload["template_registry_digest"])
        if declared_digest != PINNED_REGISTRY_DIGEST:
            raise DeliveryCommandError(
                "publication template registry digest is not the pinned version"
            )

        store = GitHubConversationStore(connection)
        with connection.transaction():
            action = store.claim_for_publication(
                scope=command.scope,
                action_id=command.subject_id,
                idempotency_key=command.idempotency_key,
                actor=settings.service_principal,
            )

        if action.decision_digest != str(command.payload["conversation_decision_digest"]):
            with connection.transaction():
                store.record_refusal(
                    scope=command.scope,
                    action_id=action.action_id,
                    error_class="DECISION_DIGEST_MISMATCH",
                )
            raise DeliveryCommandError(
                "publication decision digest does not match the approved action"
            )
        if action.template_registry_digest != declared_digest:
            with connection.transaction():
                store.record_refusal(
                    scope=command.scope,
                    action_id=action.action_id,
                    error_class="TEMPLATE_REGISTRY_DRIFT",
                )
            raise DeliveryCommandError("publication body was rendered by a different registry")

        # Reassembling the command from the claimed record re-runs every
        # contract the approval was recorded under — most importantly that the
        # stored body still hashes to the stored `body_hash`, which is the last
        # check in specification 24 §6 and the one that has no other home on
        # this path. It is cheap, and it fails closed on a record edited
        # underneath a granted approval.
        try:
            PublishConversationCommand(
                scope=command.scope,
                action_id=action.action_id,
                repository_id=action.repository_id,
                operation=action.operation,
                external_number=action.external_number,
                title=action.title,
                body=action.body,
                body_hash=action.body_hash,
                template_registry_digest=action.template_registry_digest,
                review_event=action.review_event,
                expected_thread_state=action.expected_thread_state,
                expected_head_commit_sha=action.expected_head_commit_sha,
                decision_digest=action.decision_digest,
                idempotency_key=command.idempotency_key,
                actor_principal=settings.service_principal,
            )
        except (GitHubConversationError, ValidationError) as error:
            with connection.transaction():
                store.record_refusal(
                    scope=command.scope,
                    action_id=action.action_id,
                    error_class="APPROVED_RECORD_INCONSISTENT",
                )
            raise DeliveryCommandError(
                "approved publication record no longer satisfies its own contract"
            ) from error

        client = client_factory(action.installation_id, action.api_base_url)
        try:
            _revalidate(client, action)
            receipt = _publish(client, action)
        except GitHubRateLimited as error:
            # Pre-issue availability, not a state conflict: the action returns
            # to APPROVED so the same approval can be dispatched again rather
            # than requiring a human to re-read and re-approve the same words.
            with connection.transaction():
                store.record_refusal(
                    scope=command.scope,
                    action_id=action.action_id,
                    error_class="PROVIDER_RATE_LIMITED",
                )
            return _refuse(
                command_id=command.command_id,
                outcome=DeliveryOutcome.RETRYABLE,
                reason=DeliveryReasonCode.PROVIDER_RATE_LIMITED,
                writer=writer,
                now=now,
                detail=str(error),
            )
        except (GitHubConversationError, RuntimeError, ValueError) as error:
            with connection.transaction():
                store.record_refusal(
                    scope=command.scope,
                    action_id=action.action_id,
                    error_class=type(error).__name__,
                )
            return _refuse(
                command_id=command.command_id,
                outcome=DeliveryOutcome.REFUSED,
                reason=DeliveryReasonCode.EXTERNAL_STATE_CHANGED,
                writer=writer,
                now=now,
                detail=str(error),
            )

        result = {
            "schema_version": 1,
            "action_id": action.action_id,
            "operation": action.operation.value,
            "external_id": receipt.external_id,
            "external_url": receipt.external_url,
            "external_number": receipt.external_number,
            "body_hash": action.body_hash,
            "template_registry_digest": action.template_registry_digest,
        }
        with connection.transaction():
            store.record_publication(
                scope=command.scope,
                action_id=action.action_id,
                external_id=receipt.external_id,
                external_url=receipt.external_url,
                response_hash=canonical_sha256(result),
            )

    return _complete_command(command_id=command.command_id, result=result, writer=writer, now=now)


def _revalidate(client: GitHubConversationClient, action: ClaimedConversationAction) -> None:
    """Re-read the target and refuse if anything the approval rested on moved."""

    if action.operation is ConversationOperation.CREATE_ISSUE:
        # A new issue has no prior thread to drift, so there is nothing to
        # revalidate beyond the body binding already checked by the caller.
        return
    if action.external_number is None:
        raise GitHubConversationError("a publication into a thread names its number")

    observed = client.issue(owner=action.owner, name=action.name, number=action.external_number)
    if observed.locked:
        raise GitHubConversationError("thread was locked after approval")
    current_state = ThreadState.CLOSED if observed.state == "CLOSED" else ThreadState.OPEN
    if action.expected_thread_state is not None and current_state != action.expected_thread_state:
        raise GitHubConversationError(
            f"thread state changed from {action.expected_thread_state.value} after approval"
        )
    if action.operation is ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW:
        if not observed.is_pull_request:
            raise GitHubConversationError("review target is not a pull request")
        if action.expected_head_commit_sha is None:
            raise GitHubConversationError("a review binds the head commit it reviewed")
        # The head is read from `GET /pulls/{n}`, because the issues endpoint
        # serves pull requests without one. GitHub would accept a review whose
        # `commit_id` is an older commit of this pull request and file it as
        # outdated — so a request for changes could land against code the
        # author has already replaced. The approval was given for one head;
        # anything else is a new decision, not this one.
        current = client.pull_request_head(
            owner=action.owner, name=action.name, number=action.external_number
        )
        if current.merged:
            raise GitHubConversationError("pull request was merged after approval")
        if current.head_sha != action.expected_head_commit_sha:
            raise GitHubConversationError("pull request head moved after approval")


def _publish(
    client: GitHubConversationClient, action: ClaimedConversationAction
) -> PublicationReceipt:
    """Construct exactly one request from the approved record."""

    if action.operation is ConversationOperation.CREATE_ISSUE:
        if action.title is None:
            raise GitHubConversationError("a new issue carries a title")
        return client.create_issue(
            owner=action.owner, name=action.name, title=action.title, body=action.body
        )
    if action.external_number is None:
        raise GitHubConversationError("a publication into a thread names its number")
    if action.operation is ConversationOperation.POST_ISSUE_COMMENT:
        return client.create_issue_comment(
            owner=action.owner,
            name=action.name,
            number=action.external_number,
            body=action.body,
        )
    if action.review_event is None or action.expected_head_commit_sha is None:
        raise GitHubConversationError("a review names its event and reviewed head commit")
    if action.review_event not in (ReviewEvent.COMMENT, ReviewEvent.REQUEST_CHANGES):
        raise GitHubConversationError("Solvan does not emit approving reviews")
    return client.submit_pull_request_review(
        owner=action.owner,
        name=action.name,
        number=action.external_number,
        event=action.review_event,
        body=action.body,
        commit_id=action.expected_head_commit_sha,
    )


def _complete_command(
    *, command_id: str, result: dict[str, Any], writer: GcsEvidenceWriter, now: datetime
) -> dict[str, Any]:
    result_receipt = writer.put_json(
        object_name=f"private-command-results/{command_id}/publish-conversation.json",
        value=result,
    )
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=result_receipt.uri,
        receipt_hash=result_receipt.content_hash,
        observed_at=now,
    )
    return _persist(response, writer=writer)


def _refuse(
    *,
    command_id: str,
    outcome: DeliveryOutcome,
    reason: DeliveryReasonCode,
    writer: GcsEvidenceWriter,
    now: datetime,
    detail: str,
) -> dict[str, Any]:
    """Close the command without publishing, recording why in the receipt.

    The detail is stored in the receipt rather than the response so a refusal
    reason never becomes an HTTP body a caller can enumerate against.
    """

    receipt = writer.put_json(
        object_name=f"private-command-results/{command_id}/publish-refusal.json",
        value={"schema_version": 1, "reason": reason.value, "detail": detail[:500]},
    )
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=outcome,
        reason_code=reason,
        receipt_ref=receipt.uri,
        receipt_hash=receipt.content_hash,
        observed_at=now,
    )
    return _persist(response, writer=writer)


def _persist(response: PrivateCommandResponse, *, writer: GcsEvidenceWriter) -> dict[str, Any]:
    response_receipt = writer.put_json(
        object_name=f"private-command-responses/{response.command_id}.json",
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
        raise DeliveryCommandError("terminal publication response omitted its receipt")
    reader.get_json(uri=prior.receipt_ref, expected_hash=prior.receipt_hash, max_bytes=64_000)
    return prior.model_dump(mode="json")
