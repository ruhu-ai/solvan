"""Scoped console projection and exact human-approval API."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.exception_handlers import (
    http_exception_handler as default_http_exception_handler,
)
from fastapi.exception_handlers import (
    request_validation_exception_handler as default_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError

from apps.api.agent_skills import include_agent_skills_routes
from apps.api.alert_console import alert_console_router
from apps.api.api_models import ApprovalRequest, ApprovalResponse, HarnessStatus
from apps.api.code_change_decisions import code_change_decision_router
from apps.api.code_delivery_profiles import code_delivery_profile_router
from apps.api.connections import connection_router
from apps.api.console_projection import live_console_snapshot
from apps.api.console_settings import (
    AvailableScopeProjection,
    OperatorContextProjection,
    SettingsProjectionResponse,
    console_settings_projection,
)
from apps.api.detection_connections import detection_connection_router
from apps.api.fleet_operability import fleet_operability_router
from apps.api.github_connect import include_github_routes
from apps.api.guidance_inspection import inspect_guidance_content
from apps.api.human_identity import (
    approval_principal as _approval_principal,
)
from apps.api.human_identity import (
    fresh_approval_session as _fresh_approval_session,
)
from apps.api.identity_configuration import (
    include_identity_routes,
    operator_step_up_pepper,
    operator_step_up_sender,
)
from apps.api.liaison import liaison_registry, liaison_router
from apps.api.liaison_channel_routes import channel_router
from apps.api.liaison_errors import (
    is_liaison_path,
    liaison_http_exception_handler,
    liaison_validation_exception_handler,
)
from apps.api.liaison_service import LiaisonService
from apps.api.local_cloud_development import local_cloud_development_router
from apps.api.operational_guidance_admin import operational_guidance_router
from apps.api.patch_reviews import patch_review_router
from apps.api.production_graph import production_graph_router
from apps.api.relay_admin import relay_admin_router
from apps.api.release_authority import release_authority_router
from apps.api.repair_commands import repair_command_router
from apps.api.session_authorization import require_administrator
from solvan import __version__
from solvan.application.guidance_evaluation import UnavailableGuidanceEvaluationVerifier
from solvan.domain import ActionPolicyError, Scope
from solvan.observability import instrument_fastapi
from solvan.persistence import (
    AggregateType,
    PostgresApprovalStore,
    PostgresWorkflowStore,
    WorkflowConflict,
)
from solvan.platform.database import (
    DatabasePoolConnectionFactory,
    DatabasePoolSettings,
    connect_database,
)
from solvan.platform.deployment_authority import (
    FIXTURE_READER_PRINCIPAL,
    connected_to_google_cloud,
)
from solvan.platform.email_enrollment import GoogleEmailEnrollmentSender
from solvan.platform.google_oauth import GoogleAssertionVerifier
from solvan.platform.google_rest import authorized_session
from solvan.platform.guidance_evaluation import GcsGuidanceEvaluationVerifier
from solvan.platform.release_projection import CloudReleaseBinding, GcsReleaseProjection


def _production_scope() -> Scope:
    try:
        return Scope(
            os.environ["SOLVAN_ORGANIZATION_ID"],
            os.environ["SOLVAN_SCOPE_PROJECT_ID"],
            os.environ["SOLVAN_ENVIRONMENT_ID"],
        )
    except KeyError as error:
        # A closed code, not prose. The console has to tell "nobody has told
        # this deployment which estate it serves" apart from "the service is
        # down", and it cannot switch on a sentence.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "PRODUCTION_SCOPE_NOT_CONFIGURED"
        ) from error


#: The hermetic harness has no production authority of any kind, and its
#: snapshot says so. Naming the reader explicitly is more honest than letting an
#: unauthenticated request inherit an operator's identity by omission.
_LOCAL_PRINCIPAL = FIXTURE_READER_PRINCIPAL
#: How often the local sweep looks for expired conversation leases. Well
#: under the five-minute lease so a wedged lane frees within one interval.
_LOCAL_REAP_SECONDS = 20.0
_LOCAL_SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


def _reader_principal(human_identity_token: str | None) -> str:
    """Identity for read-only conversation.

    In any connected deployment this is the same verified Google identity the
    approval path demands. This tested only the deployed authority mode while
    the approval path also honoured `SOLVAN_LOCAL_CONNECTED_GCP`, so a host
    connected to real Google Cloud authenticated its writes and answered its
    reads as the fixture.

    Only a hermetic harness — no cloud connection, a local database, seeded
    fixtures — uses the fixture reader, because there it protects nothing and
    refusing every question would buy nothing. Asking is still not approving:
    the two paths share a definition of connected, not a gate.
    """

    if connected_to_google_cloud():
        return _approval_principal(human_identity_token)
    return _LOCAL_PRINCIPAL


def _read_scope() -> Scope:
    """The scope this deployment projects from.

    The console, the conversational surface, and every read route resolve the
    same scope. A deployment's is configured; a local harness reads the
    local development scope its bootstrap seeds. Neither grants authority: the write
    paths take theirs from a verified identity, not from here.
    """

    if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM":
        return _production_scope()
    return _LOCAL_SCOPE


def _cloud_release_binding() -> CloudReleaseBinding | None:
    """The exact release this console may project cloud receipts for.

    Absent or incomplete configuration yields no binding rather than a guessed
    one, so the console reports that no cloud receipt exists instead of
    reporting against the wrong release.
    """

    if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") != "GOOGLE_CLOUD_IAM":
        return None
    try:
        return CloudReleaseBinding(
            project_id=os.environ["SOLVAN_GCP_PROJECT"],
            release_commit=os.environ["SOLVAN_RELEASE_COMMIT"],
            deployment_id=os.environ["SOLVAN_DEPLOYMENT_ID"],
            evidence_bucket=os.environ["SOLVAN_EVIDENCE_BUCKET"],
        )
    except (KeyError, ValueError):
        return None


def _alert_cursor_signing_key() -> bytes:
    """Deployment secret for opaque Alert-list cursors; local use is non-authoritative."""

    value = os.environ.get("SOLVAN_ALERT_CURSOR_SIGNING_KEY")
    if value:
        return value.encode("utf-8")
    if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM":
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Alert cursor signing key is not configured",
        )
    return b"solvan-local-development-alert-cursor-key-v1"


def _email_enrollment_sender() -> GoogleEmailEnrollmentSender:
    relay_url = os.environ.get("SOLVAN_EMAIL_RELAY_URL", "").strip()
    console_url = os.environ.get("SOLVAN_CONSOLE_BASE_URL", "").strip()
    if not relay_url or not console_url:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "email enrollment delivery is not configured",
        )
    return GoogleEmailEnrollmentSender(relay_url=relay_url, console_base_url=console_url)


def _append_json_line(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        handle.write("\n")


def _local_maintenance_lifespan(
    snapshot_provider: Callable[[], dict[str, Any]],
    *,
    connect: Callable[[], Any] = connect_database,
    close_database: Callable[[], None] | None = None,
    enabled: bool = True,
) -> Callable[[FastAPI], Any]:
    """Run the local harness's own maintenance tick, and only there.

    Specification 14 §12 gives recovery of `RUNNING` turns to a fenced reaper,
    and §12's queue promotion to whatever claims `READY` work. In the
    deployment both belong to the private, OIDC-bound maintenance service on
    its own schedule. The local harness has no scheduler at all, so an answer
    interrupted by `scripts/stop` kept its lease forever: the thread's single
    execution lane never freed, and every later question queued behind it —
    permanently, across restarts, because the conversation is durable. A
    development environment that wedges on first use is not usable.

    This grants no authority the API did not already have and re-invokes no
    model on a reaped turn: it finalizes expired leases `INTERRUPTED`, promotes
    the next queued attempt, and drains work that is already committed as
    `READY` — the same three steps as the deployed tick.
    """

    async def sweep() -> None:
        from apps.api.liaison_maintenance import reap_expired_turns
        from solvan.persistence.liaison_turn_control import promote_next_turn

        service = LiaisonService(
            connect=connect,
            snapshot_provider=snapshot_provider,
            registry_provider=liaison_registry,
        )
        while True:
            await asyncio.sleep(_LOCAL_REAP_SECONDS)
            try:
                scope = _read_scope()
                with connect() as connection:
                    with connection.transaction():
                        reap_expired_turns(connection, scope=scope)
                        # Self-heal a lane that is free while work waits behind
                        # it. `promote_next_turn` checks occupancy itself, so
                        # this cannot jump an attempt that is already running.
                        stalled = connection.execute(
                            """SELECT DISTINCT thread_id
                                 FROM solvan_liaison.liaison_turns queued
                                WHERE queued.organization_id=%(organization_id)s
                                  AND queued.project_id=%(project_id)s
                                  AND queued.environment_id=%(environment_id)s
                                  AND queued.status='QUEUED'""",
                            scope.canonical_dict(),
                        ).fetchall()
                        for (stalled_thread,) in stalled:
                            promote_next_turn(
                                connection, scope=scope, thread_id=str(stalled_thread)
                            )
                    ready = connection.execute(
                        """SELECT thread_id,message_id FROM solvan_liaison.liaison_turns
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s AND status='READY'
                            ORDER BY queued_at NULLS FIRST,queue_sequence LIMIT 25""",
                        scope.canonical_dict(),
                    ).fetchall()
                for thread_id, message_id in ready:
                    await run_in_threadpool(
                        service.run_pending,
                        scope=scope,
                        thread_id=str(thread_id),
                        target_message_id=str(message_id),
                    )
            except Exception:  # a local sweep must never take the API down
                continue

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task: asyncio.Task[None] | None = None
        if enabled and os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") != "GOOGLE_CLOUD_IAM":
            task = asyncio.create_task(sweep())
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
            if close_database is not None:
                close_database()

    return lifespan


def create_app(
    *,
    enable_local_maintenance: bool = True,
    snapshot_provider: Callable[[], dict[str, Any]] | None = None,
) -> FastAPI:
    database_factory: DatabasePoolConnectionFactory | None = None
    database_connect: Callable[[], Any] = connect_database
    if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM":
        database_factory = DatabasePoolConnectionFactory(
            pool=DatabasePoolSettings.from_environment()
        )
        database_connect = database_factory

    # The snapshot provider is defined below in this function; the lambda
    # defers the lookup to call time so the sweep reads the same projection
    # every route does.
    app = FastAPI(
        title="Solvan harness API",
        version=__version__,
        lifespan=_local_maintenance_lifespan(
            lambda: _current_snapshot(),
            connect=database_connect,
            close_database=database_factory.close if database_factory is not None else None,
            enabled=enable_local_maintenance,
        ),
    )

    evaluation_bucket = os.environ.get("SOLVAN_GUIDANCE_EVALUATION_BUCKET", "").strip()
    evaluation_verifier = (
        GcsGuidanceEvaluationVerifier(
            authorized_session=authorized_session(),
            allowed_buckets=frozenset({evaluation_bucket}),
        )
        if evaluation_bucket
        and os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"
        else UnavailableGuidanceEvaluationVerifier()
    )

    @app.exception_handler(HTTPException)
    async def closed_liaison_http_error(request: Request, error: HTTPException) -> Response:
        if is_liaison_path(request.url.path):
            return await liaison_http_exception_handler(request, error)
        return await default_http_exception_handler(request, error)

    @app.exception_handler(RequestValidationError)
    async def closed_liaison_validation_error(
        request: Request, error: RequestValidationError
    ) -> Response:
        if is_liaison_path(request.url.path):
            return await liaison_validation_exception_handler(request, error)
        return await default_validation_exception_handler(request, error)

    state_dir = Path(os.environ.get("SOLVAN_STATE_DIR", ".solvan/dev/unscoped"))
    trace_path = state_dir / "observability" / "traces.ndjson"
    log_path = state_dir / "observability" / "logs.ndjson"
    request_count = 0

    @app.middleware("http")
    async def local_observability(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        nonlocal request_count
        started = time.monotonic()
        trace_id = request.headers.get("x-trace-id", uuid.uuid4().hex)
        response = await call_next(request)
        request_count += 1
        duration_ms = round((time.monotonic() - started) * 1000, 3)
        common = {
            "timestamp": time.time(),
            "trace_id": trace_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "environment": "local",
            "content_captured": False,
        }
        _append_json_line(trace_path, {"kind": "server_span", **common})
        _append_json_line(log_path, {"level": "INFO", "event": "http_request", **common})
        response.headers["x-trace-id"] = trace_id
        return response

    @app.get("/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/ready")
    async def ready() -> dict[str, str]:
        return {"status": "ready", "scope": "harness-only"}

    @app.get("/api/harness", response_model=HarnessStatus)
    async def harness() -> HarnessStatus:
        return HarnessStatus(
            product="Solvan",
            version=__version__,
            environment="LOCAL",
            authority="NO_PRODUCTION_AUTHORITY",
            worktree_id=os.environ.get("SOLVAN_WORKTREE_ID", "unscoped"),
            phase="scaffold",
            api_status="ready",
        )

    def _current_snapshot() -> dict[str, Any]:
        """Return the one projection shared by the console and Liaison."""

        if snapshot_provider is not None:
            snapshot = snapshot_provider()
        else:
            with database_connect() as connection, connection.transaction():
                snapshot = live_console_snapshot(connection, scope=_read_scope())
            binding = _cloud_release_binding()
            if binding is not None:
                try:
                    platform, release = GcsReleaseProjection(
                        binding=binding, session=authorized_session()
                    ).load()
                    snapshot["fleet"]["platform"] = platform
                    snapshot["release"] = release
                except Exception as error:
                    snapshot["release"]["gate"] = "EVIDENCE_PROJECTION_UNAVAILABLE"
                    snapshot["release"]["projection_error_class"] = type(error).__name__
        snapshot["settings"] = console_settings_projection(snapshot, api_version=__version__)
        snapshot["integration"]["local_connected_development"] = (
            os.environ.get("SOLVAN_LOCAL_CONNECTED_GCP") == "true"
        )
        return snapshot

    @app.get("/api/console/snapshot")
    async def console(response: Response) -> dict[str, Any]:
        """Return the current console projection."""

        response.headers["Cache-Control"] = "private, no-store"
        return _current_snapshot()

    @app.get("/api/console/settings", response_model=SettingsProjectionResponse)
    async def console_settings(response: Response) -> dict[str, Any]:
        """Return effective, secret-free console settings."""

        response.headers["Cache-Control"] = "private, no-store"
        return cast("dict[str, Any]", _current_snapshot()["settings"])

    @app.get("/api/console/me", response_model=OperatorContextProjection)
    async def console_operator(response: Response) -> dict[str, Any]:
        """Return the truthful operator state for the current console."""

        response.headers["Cache-Control"] = "private, no-store"
        projection = cast("dict[str, Any]", _current_snapshot()["settings"])
        return cast("dict[str, Any]", projection["operator"])

    @app.get("/api/console/environments", response_model=list[AvailableScopeProjection])
    async def console_environments(response: Response) -> list[dict[str, Any]]:
        """Return only environment scopes visible to the current console."""

        response.headers["Cache-Control"] = "private, no-store"
        projection = cast("dict[str, Any]", _current_snapshot()["settings"])
        return cast("list[dict[str, Any]]", projection["environment"]["available_scopes"])

    @app.get("/api/v1/actions/{action_id}/approval-material")
    def approval_material(
        action_id: str,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        _approval_principal(human_identity_token)
        try:
            with database_connect() as connection, connection.transaction():
                review = PostgresApprovalStore(connection).review(
                    scope=_production_scope(), action_id=action_id
                )
        except ActionPolicyError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
        return asdict(review)

    @app.post(
        "/api/v1/actions/{action_id}:approve",
        response_model=ApprovalResponse,
    )
    def approve_action(
        action_id: str,
        request: ApprovalRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None),
    ) -> ApprovalResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Idempotency-Key must contain 8 to 128 characters",
            )
        principal = _approval_principal(human_identity_token)
        scope = _production_scope()
        owner = f"approval-api:{uuid.uuid4()}"
        try:
            with database_connect() as connection:
                store = PostgresApprovalStore(connection)
                with connection.transaction():
                    review = store.review(scope=scope, action_id=action_id)
                    lease = PostgresWorkflowStore(connection).acquire_lease(
                        scope=scope,
                        aggregate_type=AggregateType.INCIDENT,
                        entity_id=review.incident_id,
                        owner=owner,
                        lease_ttl_ms=60_000,
                    )
                if lease is None:
                    raise WorkflowConflict("incident is currently owned by another coordinator")
                with connection.transaction():
                    result = store.approve(
                        scope=scope,
                        lease=lease,
                        action_id=action_id,
                        approver_principal=principal,
                        expected_action_digest=request.action_digest,
                        decision_request_id=idempotency_key,
                        reason=request.reason,
                    )
                    PostgresWorkflowStore(connection).release_lease(scope=scope, lease=lease)
        except ActionPolicyError as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        except WorkflowConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return ApprovalResponse(**asdict(result))

    @app.get("/internal/dev/metrics", response_class=Response)
    async def metrics() -> Response:
        payload = (
            "# HELP solvan_harness_http_requests_total Local harness requests.\n"
            "# TYPE solvan_harness_http_requests_total counter\n"
            f"solvan_harness_http_requests_total {request_count}\n"
        )
        return Response(payload, media_type="text/plain; version=0.0.4")

    app.include_router(
        connection_router(
            principal_provider=_approval_principal,
            scope_provider=_read_scope,
        )
    )
    app.include_router(
        detection_connection_router(
            principal_provider=_approval_principal,
            scope_provider=_read_scope,
        )
    )
    if os.environ.get("SOLVAN_LOCAL_CONNECTED_GCP") == "true":
        app.include_router(
            local_cloud_development_router(
                scope_provider=_read_scope,
            )
        )
    include_github_routes(
        app,
        scope_provider=_production_scope,
        approval_principal=_approval_principal,
        administrator=require_administrator,
        connect=database_connect,
    )
    app.include_router(
        repair_command_router(
            principal_provider=_approval_principal,
            scope_provider=_production_scope,
        )
    )
    app.include_router(
        code_delivery_profile_router(
            principal_provider=_approval_principal,
            scope_provider=_production_scope,
        )
    )
    app.include_router(
        release_authority_router(
            principal_provider=_approval_principal,
            scope_provider=_production_scope,
            connect=database_connect,
        )
    )
    app.include_router(
        code_change_decision_router(
            session_provider=_fresh_approval_session,
            principal_provider=_approval_principal,
            scope_provider=_production_scope,
            connect=database_connect,
        )
    )
    app.include_router(
        relay_admin_router(
            principal_provider=_approval_principal,
            scope_provider=_production_scope,
        )
    )
    app.include_router(
        patch_review_router(
            principal_provider=_approval_principal,
            scope_provider=_production_scope,
        )
    )
    app.include_router(
        production_graph_router(
            principal_provider=_approval_principal,
            reader_principal_provider=_reader_principal,
            scope_provider=_production_scope,
            connect=database_connect,
        )
    )

    # A deployment carrying Google Cloud authority has already refused to reach
    # this line unconfigured, so this branch is now the harness case alone: no
    # client, no secret, nobody to sign in. What changed is what absence means
    # downstream — the console requires a session unconditionally and treats
    # these routes going missing as a broken deployment, where it used to treat
    # it as permission to render.
    # Refuses to build an unauthenticated deployment, then mounts sign-in and
    # the surface administering who may use it.
    include_identity_routes(
        app,
        connect=connect_database,
        scope_provider=_read_scope,
        verifier=GoogleAssertionVerifier(),
        step_up_sender_provider=operator_step_up_sender,
        step_up_pepper_provider=operator_step_up_pepper,
    )
    app.include_router(
        fleet_operability_router(
            snapshot_provider=_current_snapshot,
            principal_provider=_reader_principal,
            connect=database_connect,
        )
    )
    app.include_router(
        operational_guidance_router(
            principal_provider=_approval_principal,
            reader_principal_provider=_reader_principal,
            scope_provider=_production_scope,
            connect=database_connect,
            content_inspector=inspect_guidance_content,
            known_predicates=frozenset(
                {
                    "evidence-kind-present@1",
                    "verification-profile-passed@1",
                    "production-graph-binding-resolved@1",
                    "action-effect-reconciled@1",
                    "guidance-content-fetched@1",
                }
            ),
            evaluation_verifier=evaluation_verifier,
        )
    )
    include_agent_skills_routes(
        app,
        principal_provider=_approval_principal,
        reader_principal_provider=_reader_principal,
        scope_provider=_production_scope,
        connect=database_connect,
    )
    app.include_router(
        alert_console_router(
            scope_provider=_read_scope,
            principal_provider=_reader_principal,
            command_principal_provider=_approval_principal,
            connect=database_connect,
            local_mode_provider=lambda: os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE")
            != "GOOGLE_CLOUD_IAM",
            cursor_signing_key_provider=_alert_cursor_signing_key,
        )
    )
    app.include_router(
        liaison_router(
            snapshot_provider=_current_snapshot,
            principal_provider=_reader_principal,
            scope_provider=_read_scope,
            connect=database_connect,
            quarantine_dir=state_dir / "quarantine" / "liaison-attachments",
        )
    )
    app.include_router(
        channel_router(
            principal_provider=_reader_principal,
            scope_provider=_read_scope,
            connect=database_connect,
            email_sender_provider=_email_enrollment_sender,
        )
    )

    return app


app = instrument_fastapi(create_app(), service_name="api")
