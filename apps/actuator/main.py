"""Private, IAM-protected mutation service accepting stored action IDs only."""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime
from typing import cast

import google.auth
import httpx
from fastapi import FastAPI, Header, HTTPException, Response, status
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict

from apps.actuator.local_policy import (
    ActionRateBudget,
    LocalPolicyRefusal,
    check_kill_switch,
    read_budget_limit,
)
from solvan.application import ActionActuator
from solvan.application.action_gates import CompositeActionPreMutationGate
from solvan.application.actuator import (
    ExecutionResult,
    MutationCall,
    PredictedEffect,
    Reconciliation,
    ReservationConflict,
    ReservationLost,
    TargetObservation,
    UndoPlan,
)
from solvan.connectors.mutation.cloud_run import CloudRunRollbackConnector
from solvan.connectors.mutation.payments_admin import PaymentsAdminConnector
from solvan.domain import (
    ActionPolicyError,
    ActionType,
    AuthorizedActionMaterial,
)
from solvan.observability import instrument_fastapi, record_control_refusal
from solvan.persistence import PostgresActionStore
from solvan.persistence.production_graph import read_current_graph
from solvan.persistence.target_action_gates import (
    PostgresEarnedAutonomyActionGate,
    PostgresGraphActionBindingResolver,
    ProductionGraphActionGate,
)
from solvan.platform.customer_audit import CloudLoggingCustomerAuditSink
from solvan.platform.database import connect_database
from solvan.platform.service_identity import (
    ServiceIdentityError,
    require_agent_principal,
    verify_service_caller,
)


class ExecuteActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    invocation_id: str
    trace_id: str | None = None


class ExecuteActionResponse(BaseModel):
    receipt_id: str
    result: ExecutionResult
    reservation_id: str


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class GoogleIdTokenProvider:
    def token(self, *, audience: str) -> str:
        value = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
            GoogleAuthRequest(), audience
        )
        return cast(str, value)


class GoogleAccessTokenProvider:
    def token(self, *, scopes: tuple[str, ...]) -> str:
        credentials, _project = google.auth.default(scopes=list(scopes))
        credentials.refresh(GoogleAuthRequest())  # type: ignore[no-untyped-call]
        if not credentials.token:
            raise RuntimeError("Google credentials returned no access token")
        return cast(str, credentials.token)


class MutationConnectorRouter:
    def __init__(
        self,
        *,
        payments: PaymentsAdminConnector,
        cloud_run: CloudRunRollbackConnector,
    ) -> None:
        self._payments = payments
        self._cloud_run = cloud_run

    def observe(self, material: AuthorizedActionMaterial) -> TargetObservation:
        return self._connector(material).observe(material)

    def dry_run(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> PredictedEffect:
        return self._connector(material).dry_run(material, before_state=before_state)

    def mutate(self, material: AuthorizedActionMaterial, *, idempotency_key: str) -> MutationCall:
        return self._connector(material).mutate(material, idempotency_key=idempotency_key)

    def derive_undo(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> UndoPlan:
        return self._connector(material).derive_undo(material, before_state=before_state)

    def reconcile(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> Reconciliation:
        return self._connector(material).reconcile(material, idempotency_key=idempotency_key)

    def _connector(
        self, material: AuthorizedActionMaterial
    ) -> PaymentsAdminConnector | CloudRunRollbackConnector:
        if material.action_type is ActionType.PAYMENTS_POOL_RECYCLE:
            return self._payments
        if material.action_type is ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK:
            return self._cloud_run
        raise ActionPolicyError("unsupported_action_type")


#: Constructed on first mutation, not at import: an unusable budget must refuse
#: the mutation with a clear reason, while /live still answers so a misconfigured
#: deployment reads as refusing rather than as down.
_RATE_BUDGET: ActionRateBudget | None = None
_RATE_BUDGET_LOCK = threading.Lock()


def _rate_budget() -> ActionRateBudget:
    global _RATE_BUDGET
    with _RATE_BUDGET_LOCK:
        if _RATE_BUDGET is None:
            _RATE_BUDGET = ActionRateBudget(read_budget_limit())
        return _RATE_BUDGET


def _required_setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required actuator setting {name} is missing")
    return value


def _authorize_caller(authorization: str | None) -> None:
    # Cloud Run IAM authenticates at the boundary; this verifies the caller's
    # signed claims in process so network position is not the only control on
    # the one service that can mutate production.
    try:
        caller = verify_service_caller(authorization, audience_variable="SOLVAN_ACTUATOR_AUDIENCE")
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
    mode = _required_setting("SOLVAN_PLATFORM_AUTHORITY_MODE")
    if mode != "AGENT_IDENTITY_IAM_GATEWAY":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "platform authority is disabled")
    principal = _required_setting("SOLVAN_EXECUTION_PRINCIPAL")
    if not principal.startswith("principal://agents.global."):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "agent principal is invalid")
    # The verified caller must be the exact attested Execution Agent identity —
    # a valid token for this audience from any other workload is not admission.
    try:
        require_agent_principal(caller, admitted=frozenset({principal}))
    except ServiceIdentityError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Action Actuator", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post(
        "/internal/v1/actions/{action_id}:execute",
        response_model=ExecuteActionResponse,
        status_code=status.HTTP_200_OK,
    )
    def execute_action(
        action_id: str,
        request: ExecuteActionRequest,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> ExecuteActionResponse:
        _authorize_caller(authorization)
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        # Customer-side controls, evaluated in this binary before any mutation
        # connector exists. They hold when Solvan is unreachable or wrong.
        try:
            check_kill_switch()
            _rate_budget().claim()
        except LocalPolicyRefusal as refusal:
            # The refusal is the operator's signal, not just the caller's. It is
            # recorded before the response so an engaged switch, an exhausted
            # budget and an unparsable policy are alertable rather than being
            # indistinguishable 403s in an access log.
            record_control_refusal(service_name="actuator", reason_code=refusal.reason_code)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                {"reason_code": refusal.reason_code, "detail": refusal.detail},
            ) from refusal
        payments_admin_url = _required_setting("SOLVAN_PAYMENTS_ADMIN_URL")
        actor_identity = _required_setting("SOLVAN_ACTUATOR_IDENTITY")
        actuator_id = _required_setting("SOLVAN_ACTUATOR_ID")
        try:
            with (
                connect_database() as connection,
                httpx.Client(timeout=httpx.Timeout(10.0, read=35.0)) as client,
            ):
                store = PostgresActionStore(connection)
                with connection.transaction():
                    scope = store.bound_scope()
                    store.require_execution_invocation(
                        scope=scope,
                        invocation_id=request.invocation_id,
                        action_id=action_id,
                    )
                access_tokens = GoogleAccessTokenProvider()
                actuator = ActionActuator(
                    store=store,
                    connector=MutationConnectorRouter(
                        payments=PaymentsAdminConnector(
                            base_url=payments_admin_url,
                            token_provider=GoogleIdTokenProvider(),
                            client=client,
                        ),
                        cloud_run=CloudRunRollbackConnector(
                            token_provider=access_tokens,
                            client=client,
                            api_url=os.environ.get(
                                "SOLVAN_CLOUD_RUN_API_URL", "https://run.googleapis.com"
                            ),
                        ),
                    ),
                    customer_audit=CloudLoggingCustomerAuditSink(
                        token_provider=access_tokens,
                        client=client,
                        api_url=os.environ.get(
                            "SOLVAN_CUSTOMER_LOGGING_API_URL",
                            "https://logging.googleapis.com",
                        ),
                    ),
                    clock=SystemClock(),
                    actuator_id=actuator_id,
                    actor_identity=actor_identity,
                    reservation_ttl_ms=180_000,
                    pre_mutation_gate=CompositeActionPreMutationGate(
                        (
                            ProductionGraphActionGate(
                                read_current=lambda bound_scope: read_current_graph(
                                    connection, scope=bound_scope
                                ),
                                resolve_binding=PostgresGraphActionBindingResolver(connection),
                            ),
                            PostgresEarnedAutonomyActionGate(
                                connect=connect_database,
                            ),
                        )
                    ),
                )
                result = actuator.execute(
                    scope=scope,
                    action_id=action_id,
                    trace_id=request.trace_id,
                )
        except ActionPolicyError as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        except (ReservationConflict, ReservationLost) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        response.status_code = (
            status.HTTP_202_ACCEPTED
            if result.result is ExecutionResult.AMBIGUOUS
            else status.HTTP_200_OK
        )
        return ExecuteActionResponse(
            receipt_id=result.receipt_id,
            result=result.result,
            reservation_id=result.reservation_id,
        )

    return app


app = instrument_fastapi(create_app(), service_name="actuator")
