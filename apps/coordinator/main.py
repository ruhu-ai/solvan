"""Cloud Run coordinator for token-fenced inbox and workflow progression."""

from __future__ import annotations

import hashlib
import json
import os
import socket
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Response, status
from psycopg import Connection
from psycopg.errors import UndefinedTable

from apps.coordinator.alert_triage import run_alert_triage_tick
from apps.coordinator.case_handlers import (
    _advance_patch_reviews,
    _open_mitigated_reliability_cases,
    _resume_due_reliability_cases,
)
from apps.coordinator.code_change_delivery import advance_code_change_delivery
from apps.coordinator.code_change_qualification import advance_code_change_qualifications
from apps.coordinator.contracts import (
    _ENTRY_TRANSITIONS,
    CoordinatorSettings,
    PubSubMessage,
    PubSubPush,
    RelayObservabilityJobCommand,
    TickRequest,
    TickResponse,
    WorkspaceRehydrationCandidate,
    WorkspaceRehydrationCandidateRequest,
    WorkspaceRehydrationCommand,
    _settings,
)
from apps.coordinator.event_handlers import (
    InboxLeaseContention,
    _process_entry_transition,
    canonical_detection,
    decode_outbox_push,
)
from apps.coordinator.guidance_progress import advance_guidance_steps
from apps.coordinator.liaison_steer import (
    accept_confirmed_liaison_steer as _accept_confirmed_liaison_steer,
)
from apps.coordinator.mitigation_handlers import _advance_completed_investigations
from apps.coordinator.production_graph import run_next_graph_reconciliation
from apps.coordinator.relay_job_authoring import RelayJobAuthor, RelayJobAuthoringError
from apps.coordinator.release_candidates import advance_release_candidates
from apps.coordinator.runtime_polling import (
    _dispatch_ready_investigation_steps,
    _poll_runtime_runs,
    _recover_expired_created_runs,
)
from apps.coordinator.runtime_starters import (
    _start_pending_executions,
    _start_pending_supervisors,
    _start_pending_verifications,
)
from apps.coordinator.security_ingestion import decode_security_log, persist_security_log
from apps.coordinator.trigger_handlers import canonical_trigger_firing
from apps.coordinator.workspace_rehydration import (
    rehydrate_antigravity_workspace,
    select_rehydration_candidate,
)
from apps.coordinator.workspace_tool_broker import (
    WorkspaceToolRequest,
    authenticate_workspace_agent,
    invoke_workspace_tool,
)
from solvan.application import WorkspaceRehydrationReceipt
from solvan.application.incidents import IncidentCoordinator
from solvan.application.ports import ClaimedEvent
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence import (
    PostgresRelayStore,
    PostgresRuntimeRunStore,
    PostgresWorkflowStore,
)
from solvan.persistence.inbox_store import PostgresInboxStore
from solvan.persistence.relay_store import RelayConflict
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_release import (
    GitHubReleaseProviderClient,
    GoogleIdentityTokenProvider,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.production_graph_sources import configured_graph_sources
from solvan.platform.relay_signing import GoogleKmsSigner
from solvan.platform.service_identity import ServiceIdentityError, verify_service_caller


def _require_internal_caller(
    authorization: str | None, *, service_account_variables: tuple[str, ...]
) -> None:
    """Bind one internal route to its exact configured workload identities.

    Cloud Run IAM is the network control; this is the application one. A push
    subscription, scheduler job, or sibling service that reaches this process
    presents a Google-signed token minted for the coordinator audience, and
    the verified email claim must equal one of the exact service accounts
    configured for this route's callers. Every variable being unset refuses:
    a route whose caller cannot be named admits no one.
    """

    try:
        caller = verify_service_caller(
            authorization, audience_variable="SOLVAN_COORDINATOR_AUDIENCE"
        )
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
    admitted = {
        value
        for name in service_account_variables
        if (value := os.environ.get(name, "").strip().lower())
    }
    if not admitted:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"none of {service_account_variables} is configured",
        )
    if caller.email is None or caller.email.lower() not in admitted:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "caller is not the admitted workload identity"
        )


__all__ = [
    "PubSubMessage",
    "PubSubPush",
    "canonical_detection",
    "decode_outbox_push",
]


def _apply_inbox_claim(
    *,
    scope: Scope,
    owner: str,
    claim: ClaimedEvent,
    inbox: PostgresInboxStore,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
) -> None:
    """Advance exactly one claimed inbox event under its own claim token."""

    envelope = inbox.load(scope=scope, owner=owner, claim=claim)
    connection.commit()
    value: dict[str, Any] = {}
    if envelope.event_type == "TRIGGER_FIRING_DUE":
        event = canonical_trigger_firing(
            connection, scope=scope, firing_id=envelope.source_event_id
        )
        IncidentCoordinator(workflow).process_trigger(
            scope=scope,
            claim_owner=owner,
            claim=claim,
            event=event,
        )
    elif envelope.event_type == "LIAISON_STEER_CONFIRMED":
        _accept_confirmed_liaison_steer(
            connection,
            scope=scope,
            workflow=workflow,
            owner=owner,
            parked_request_id=envelope.source_event_id,
            expected_envelope_hash=envelope.payload_hash,
        )
    else:
        value = reader.get_json(uri=envelope.payload_ref, expected_hash=envelope.payload_hash)
    if envelope.event_type == "MonitoringThresholdBreached":
        IncidentCoordinator(workflow).process_detection(
            scope=scope,
            claim_owner=owner,
            claim=claim,
            event=canonical_detection(value),
        )
    elif envelope.event_type in _ENTRY_TRANSITIONS:
        _process_entry_transition(
            scope=scope,
            owner=owner,
            claim=claim,
            envelope=envelope,
            value=value,
            workflow=workflow,
        )
    elif envelope.event_type != "TRIGGER_FIRING_DUE":
        with workflow.transaction():
            workflow.complete_inbox(
                scope=scope,
                owner=owner,
                claim=claim,
                result_ref=f"projection-ack:{envelope.event_type}",
            )


def _process_inbox_claim(
    *,
    scope: Scope,
    owner: str,
    claim: ClaimedEvent,
    inbox: PostgresInboxStore,
    workflow: PostgresWorkflowStore,
    connection: Connection[Any],
    reader: GcsEvidenceReader,
) -> bool:
    """Isolate one claim so a single bad event cannot abort the whole tick.

    Three outcomes are distinguished on purpose. Success reports progress.
    Lease contention returns the claim and refunds the attempt it spent, so a
    valid command on a busy incident is never quarantined. Anything else keeps
    the spent attempt and leaves the claim to expire, which walks a genuinely
    poisoned event through its bounded budget into durable quarantine while the
    remaining claims, recovery sweeps, and case handlers still run.
    """

    try:
        _apply_inbox_claim(
            scope=scope,
            owner=owner,
            claim=claim,
            inbox=inbox,
            workflow=workflow,
            connection=connection,
            reader=reader,
        )
    except InboxLeaseContention:
        with suppress(Exception):
            connection.rollback()
        # A refund that loses its own claim token has already been superseded
        # by another coordinator; there is nothing left to hand back.
        with suppress(Exception), workflow.transaction():
            workflow.release_inbox(
                scope=scope,
                owner=owner,
                claim=claim,
                refund_attempt=True,
            )
        return False
    except Exception:
        with suppress(Exception):
            connection.rollback()
        return False
    return True


def run_inbox_tick(settings: CoordinatorSettings, *, batch_size: int = 20) -> TickResponse:
    owner = f"{socket.gethostname()}:{uuid4()}"
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.evidence_bucket, settings.runtime_bucket}),
        session=session,
    )
    with connect_database() as connection:
        inbox = PostgresInboxStore(connection)
        workflow = PostgresWorkflowStore(connection)
        runtime_runs = PostgresRuntimeRunStore(connection)
        with connection.transaction():
            claims = inbox.claim(
                scope=settings.scope,
                owner=owner,
                claim_ttl_ms=120_000,
                batch_size=batch_size,
            )
        completed = 0
        for claim in claims:
            if _process_inbox_claim(
                scope=settings.scope,
                owner=owner,
                claim=claim,
                inbox=inbox,
                workflow=workflow,
                connection=connection,
                reader=reader,
            ):
                completed += 1
        _recover_expired_created_runs(
            settings=settings,
            owner=owner,
            workflow=workflow,
            runs=runtime_runs,
            connection=connection,
        )
        with suppress(UndefinedTable):
            run_alert_triage_tick(
                settings=settings,
                owner=owner,
                connection=connection,
                runs=runtime_runs,
                batch_size=batch_size,
            )
        _start_pending_supervisors(
            settings=settings,
            owner=owner,
            workflow=workflow,
            runs=runtime_runs,
            connection=connection,
        )
        _poll_runtime_runs(
            settings=settings,
            owner=owner,
            workflow=workflow,
            runs=runtime_runs,
            connection=connection,
            reader=reader,
        )
        _dispatch_ready_investigation_steps(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
        )
        _advance_completed_investigations(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
        )
        advance_guidance_steps(connection, scope=settings.scope)
        _start_pending_executions(
            settings=settings,
            owner=owner,
            workflow=workflow,
            runs=runtime_runs,
            connection=connection,
        )
        _start_pending_verifications(
            settings=settings,
            owner=owner,
            workflow=workflow,
            runs=runtime_runs,
            connection=connection,
        )
        _open_mitigated_reliability_cases(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
        )
        _advance_patch_reviews(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
        )
        advance_code_change_qualifications(settings=settings, connection=connection)
        advance_code_change_delivery(settings=settings, connection=connection)
        advance_release_candidates(settings=settings, connection=connection)
        _resume_due_reliability_cases(
            settings=settings,
            owner=owner,
            workflow=workflow,
            connection=connection,
            reader=reader,
        )
        graph_sources = configured_graph_sources(settings.scope)
        if graph_sources is not None:
            # Production Graph is a target feature. A release cell without its
            # target schema truthfully has no graph work to claim.
            with suppress(UndefinedTable):
                run_next_graph_reconciliation(
                    connection,
                    scope=settings.scope,
                    owner=owner,
                    transport=session,
                    config=graph_sources,
                )
        # Relay recovery is a coordinator-owned, deterministic maintenance
        # operation.  The target schema is intentionally absent in the release
        # profile, where this becomes a no-op rather than granting any agent or
        # customer Relay process workflow authority.
        with suppress(UndefinedTable):
            relay_store = PostgresRelayStore(connection)
            now = datetime.now(UTC)
            relay_store.expire_unclaimed_jobs(
                scope=settings.scope,
                now=now,
            )
            relay_store.reconcile_expired_claims(
                scope=settings.scope,
                now=now,
            )
    return TickResponse(claimed=len(claims), completed=completed)


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Durable Coordinator", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/workspace-tools/{operation}")
    def workspace_tool(
        operation: str,
        request: WorkspaceToolRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = _settings()
        try:
            authenticate_workspace_agent(authorization, settings=settings)
            with connect_database() as connection, httpx.Client() as transport:
                return invoke_workspace_tool(
                    settings=settings,
                    connection=connection,
                    request=request,
                    operation=operation,
                    transport=transport,
                )
        except (RuntimeError, ValueError, httpx.HTTPError) as error:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Workspace Tool invocation was refused",
            ) from error

    def github_client(
        settings: CoordinatorSettings, transport: httpx.Client
    ) -> GitHubReleaseProviderClient:
        if settings.github_release is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "GitHub release provider is not enabled",
            )
        return GitHubReleaseProviderClient(
            config=settings.github_release,
            client=transport,
            token_provider=GoogleIdentityTokenProvider(),
        )

    @app.post("/internal/v1/github/repositories:probe")
    def github_probe(authorization: str | None = Header(default=None)) -> dict[str, object]:
        # A coordinator-only seam: release tooling reaches it as the
        # coordinator identity, never as an arbitrary invoker.
        _require_internal_caller(
            authorization, service_account_variables=("SOLVAN_COORDINATOR_SERVICE_ACCOUNT",)
        )
        settings = _settings()
        try:
            with httpx.Client(timeout=60) as transport:
                return github_client(settings, transport).probe_repository()
        except (RuntimeError, ValueError) as error:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "GitHub repository probe rejected"
            ) from error

    @app.post("/internal/wakeups/tick", response_model=TickResponse)
    def tick(
        request: TickRequest, authorization: str | None = Header(default=None)
    ) -> TickResponse:
        _require_internal_caller(
            authorization,
            service_account_variables=(
                "SOLVAN_SCHEDULER_SERVICE_ACCOUNT",
                "SOLVAN_SCENARIO_INJECTOR_SERVICE_ACCOUNT",
            ),
        )
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        return run_inbox_tick(_settings())

    @app.post("/internal/v1/relay/observability-jobs", status_code=status.HTTP_202_ACCEPTED)
    def author_relay_observability_job(
        request: RelayObservabilityJobCommand,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        """Create a Relay job after, never before, a normal governed Tool call.

        Cloud Run IAM restricts this private route to the Evidence Broker
        identity, and the verified caller is bound to it here in process. The
        body names no scope, source, Relay, graph resource, adapter, policy,
        endpoint, credential, or signing material; all of those are re-derived
        in the coordinator transaction.
        """

        _require_internal_caller(
            authorization, service_account_variables=("SOLVAN_EVIDENCE_SERVICE_ACCOUNT",)
        )
        settings = _settings()
        if not settings.relay_job_signing_key_id or not settings.relay_job_signing_key_version:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Relay job authorship is not configured",
            )
        try:
            with connect_database() as connection:
                collection_job_id = RelayJobAuthor(
                    connection=connection,
                    signer=GoogleKmsSigner(),
                    signing_key_id=settings.relay_job_signing_key_id,
                    signing_key_version=settings.relay_job_signing_key_version,
                ).author_observability_job(
                    scope=settings.scope,
                    agent_run_id=request.agent_run_id,
                    tool_call_id=request.tool_call_id,
                    arguments=request.arguments,
                )
        except (RelayJobAuthoringError, RelayConflict, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, "Relay job was refused") from error
        return {"collection_job_id": collection_job_id}

    @app.post(
        "/internal/v1/workspaces:rehydrate",
        response_model=WorkspaceRehydrationReceipt,
    )
    def rehydrate_workspace(
        request: WorkspaceRehydrationCommand,
        authorization: str | None = Header(default=None),
    ) -> WorkspaceRehydrationReceipt:
        _require_internal_caller(
            authorization, service_account_variables=("SOLVAN_COORDINATOR_SERVICE_ACCOUNT",)
        )
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        settings = _settings()
        session = authorized_session()
        reader = GcsEvidenceReader(
            allowed_buckets=frozenset({settings.runtime_bucket}), session=session
        )
        writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
        evidence_writer = GcsEvidenceWriter(bucket=settings.evidence_bucket, session=session)
        try:
            with connect_database() as connection:
                return rehydrate_antigravity_workspace(
                    settings=settings,
                    connection=connection,
                    workspace_id=request.workspace_id,
                    expected_checkpoint_id=request.expected_checkpoint_id,
                    reader=reader,
                    writer=writer,
                    evidence_writer=evidence_writer,
                )
        except (RuntimeError, ValueError) as error:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"workspace rehydration rejected: {type(error).__name__}",
            ) from error

    @app.post(
        "/internal/v1/workspaces:rehydration-candidate",
        response_model=WorkspaceRehydrationCandidate,
    )
    def rehydration_candidate(
        request: WorkspaceRehydrationCandidateRequest,
        authorization: str | None = Header(default=None),
    ) -> WorkspaceRehydrationCandidate:
        _require_internal_caller(
            authorization, service_account_variables=("SOLVAN_COORDINATOR_SERVICE_ACCOUNT",)
        )
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        try:
            with connect_database() as connection:
                return select_rehydration_candidate(scope=_settings().scope, connection=connection)
        except RuntimeError as error:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"workspace candidate unavailable: {type(error).__name__}",
            ) from error

    @app.post("/internal/pubsub/workflow", status_code=status.HTTP_204_NO_CONTENT)
    def workflow_push(
        push: PubSubPush, authorization: str | None = Header(default=None)
    ) -> Response:
        _require_internal_caller(
            authorization, service_account_variables=("SOLVAN_PUBSUB_PUSH_SERVICE_ACCOUNT",)
        )
        try:
            value = decode_outbox_push(push)
        except ValueError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        settings = _settings()
        event_id = str(value["outbox_event_id"])
        content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(content).hexdigest()
        session = authorized_session()
        receipt = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session).put_json(
            object_name=f"outbox/{settings.scope.environment_id}/{event_id}-{digest}.json",
            value=value,
        )
        with connect_database() as connection, connection.transaction():
            PostgresWorkflowStore(connection).ingest_event(
                scope=settings.scope,
                source="outbox",
                source_event_id=event_id,
                event_type=str(value["event_type"]),
                payload_ref=receipt.uri,
                payload_hash=receipt.content_hash,
            )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/internal/pubsub/security", status_code=status.HTTP_204_NO_CONTENT)
    def security_push(
        push: PubSubPush, authorization: str | None = Header(default=None)
    ) -> Response:
        _require_internal_caller(
            authorization, service_account_variables=("SOLVAN_PUBSUB_PUSH_SERVICE_ACCOUNT",)
        )
        try:
            event = decode_security_log(push)
        except ValueError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        settings = _settings()
        with connect_database() as connection, connection.transaction():
            persist_security_log(connection, scope=settings.scope, event=event)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app


app = instrument_fastapi(create_app(), service_name="coordinator")
