"""Authenticated target Production Graph review and promotion routes.

The graph schema is deliberately outside the competition release.  These
routes therefore expose a truthful target seam: when the target schema is not
installed they return 503, never the local incident fixture and never a
best-effort predecessor.  Promotion remains a SQL function-only operation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from psycopg.errors import IntegrityError, UndefinedTable
from pydantic import BaseModel, ConfigDict, Field

from apps.api.session_authorization import session_reader_principal
from solvan.application.production_graph_review import (
    GraphReviewMode,
    authorize_graph_review,
)
from solvan.application.saas_scale import ScaleRuntimeError
from solvan.domain import Scope
from solvan.persistence.production_graph import GraphSnapshotReview, ProductionGraphRepository
from solvan.platform.production_graph_sources import (
    GraphSourceConfigurationError,
    configured_graph_sources,
)


class GraphPromotionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    decision_id: str = Field(min_length=1, max_length=160)
    mode: Literal["HUMAN_APPROVED", "AUTO_PROMOTED"]
    expected_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason_ref: str | None = Field(default=None, pattern=r"^ref_[A-Za-z0-9._:-]+$")


class GraphPromotionResponse(BaseModel):
    snapshot_id: str
    decision_id: str
    mode: Literal["HUMAN_APPROVED", "AUTO_PROMOTED"]
    content_hash: str
    created: bool = True


class GraphReconciliationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    request_id: str = Field(min_length=8, max_length=128)


class GraphReconciliationResponse(BaseModel):
    run_id: str
    state: Literal["PENDING", "RUNNING", "COMPLETED", "DEGRADED", "FAILED", "CANCELLED"]
    source_count: int
    created: bool = True


def production_graph_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    reader_principal_provider: Callable[[str | None], str] | None = None,
    runtime_configured_provider: Callable[[], bool] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/production-graph")
    resolve_reader = reader_principal_provider or principal_provider
    runtime_configured = runtime_configured_provider or (
        lambda: configured_graph_sources(scope_provider()) is not None
    )

    def _execution_configured() -> bool:
        try:
            return runtime_configured()
        except GraphSourceConfigurationError as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph coordinator source registry is invalid for this scope",
            ) from error

    @router.get("/status")
    def graph_status(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        try:
            with connect() as connection, connection.transaction():
                # Who is reading: the §4.2 session a browser carries, else the
                # audience-bound grant a non-browser caller presents.
                if session_reader_principal(connection, request) is None:
                    resolve_reader(authorization)
                repository = ProductionGraphRepository(connection)
                placement = repository.current_placement(scope=scope_provider())
                sources = repository.current_source_plan()
                runs = repository.list_runs(scope=scope_provider())
                snapshots = repository.list_snapshots(scope=scope_provider())
        except UndefinedTable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph target schema is not installed",
            ) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "placement": asdict(placement) if placement is not None else None,
            "sources": [asdict(item) for item in sources],
            "runs": [asdict(item) for item in runs],
            "snapshots": [asdict(item) for item in snapshots],
            "execution_configured": _execution_configured(),
        }

    @router.post("/reconciliations", response_model=GraphReconciliationResponse)
    def enqueue_reconciliation(
        request: GraphReconciliationRequest,
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ) -> GraphReconciliationResponse:
        principal = principal_provider(authorization)
        if not _execution_configured():
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph coordinator source registry is not configured",
            )
        if idempotency_key != request.request_id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "request_id must equal Idempotency-Key for an exact retry identity",
            )
        scope = scope_provider()
        try:
            with connect() as connection, connection.transaction():
                repository = ProductionGraphRepository(connection)
                placement = repository.current_placement(scope=scope)
                source_plan = repository.current_source_plan()
                if placement is None:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "no current active Production Graph placement exists",
                    )
                if not source_plan:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "no current Production Graph source policies are registered",
                    )
                repository.start_run(
                    scope=scope,
                    cell_id=placement.cell_id,
                    placement_epoch=placement.placement_epoch,
                    run_id=request.request_id,
                    source_plan=source_plan,
                    requested_by=principal,
                )
        except UndefinedTable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph target schema is not installed",
            ) from error
        except IntegrityError as error:
            # A duplicate exact run is a safe retry only while it is still the
            # same principal's durable request. Reusing the key after another
            # principal or active-run conflict remains a conflict.
            try:
                with connect() as connection, connection.transaction():
                    retry_repository = ProductionGraphRepository(connection)
                    existing = retry_repository.get_run(scope=scope, run_id=request.request_id)
                    frozen_plan = retry_repository.run_source_plan(
                        scope=scope, run_id=request.request_id
                    )
            except UndefinedTable as table_error:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "Production Graph target schema is not installed",
                ) from table_error
            if (
                existing is not None
                and existing.requested_by == principal
                and frozen_plan == source_plan
            ):
                return GraphReconciliationResponse(
                    run_id=existing.run_id,
                    state=existing.state,  # type: ignore[arg-type]
                    source_count=len(frozen_plan),
                    created=False,
                )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "graph reconciliation request conflicts with current durable work",
            ) from error
        return GraphReconciliationResponse(
            run_id=request.request_id,
            state="PENDING",
            source_count=len(source_plan),
        )

    def _review(snapshot_id: str, token: str | None) -> GraphSnapshotReview:
        principal_provider(token)
        try:
            with connect() as connection, connection.transaction():
                material = ProductionGraphRepository(connection).review_material(
                    scope=scope_provider(), snapshot_id=snapshot_id
                )
        except UndefinedTable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph target schema is not installed",
            ) from error
        if material is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "graph snapshot was not found")
        return material

    def _public_material(material: Any) -> dict[str, Any]:
        payload = asdict(material)
        payload.pop("rejected_content_hashes", None)
        return payload

    @router.get("/{snapshot_id}/review-material")
    def review_material(
        snapshot_id: str,
        response: Response,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        material = _review(snapshot_id, human_identity_token)
        response.headers["Cache-Control"] = "private, no-store"
        return _public_material(material)

    @router.post(
        "/{snapshot_id}:promote",
        response_model=GraphPromotionResponse,
    )
    def promote_snapshot(
        snapshot_id: str,
        request: GraphPromotionRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None),
    ) -> GraphPromotionResponse:
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Idempotency-Key must contain 8 to 128 characters",
            )
        if request.decision_id != idempotency_key:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "decision_id must equal Idempotency-Key for an exact retry identity",
            )
        if request.mode == "AUTO_PROMOTED":
            # Automatic promotion belongs to the coordinator's workload
            # identity and has no console/user bearer-token path.  Exposing it
            # through the human review route would create a confused deputy.
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "automatic graph promotion is coordinator-only",
            )
        # AUTO_PROMOTED is still an application decision, but it must not
        # inherit a human identity or a human reason from the request.  The
        # branch is retained in the typed request contract for the internal
        # coordinator adapter, not accepted by this console route.
        principal = (
            principal_provider(human_identity_token) if request.mode == "HUMAN_APPROVED" else None
        )
        scope = scope_provider()
        material = _review(
            snapshot_id,
            human_identity_token if request.mode == "HUMAN_APPROVED" else None,
        )
        if material.content_hash != request.expected_content_hash:
            raise HTTPException(status.HTTP_409_CONFLICT, "graph content hash is stale")
        # Idempotent retries return the already committed decision only when
        # every immutable operand still names this exact candidate. A reused
        # key with another candidate is a conflict, never a second promotion.
        try:
            with connect() as connection, connection.transaction():
                existing = ProductionGraphRepository(connection).promotion_record(
                    scope=scope, decision_id=request.decision_id
                )
        except UndefinedTable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph target schema is not installed",
            ) from error
        if existing is not None:
            if (
                existing.snapshot_id != snapshot_id
                or existing.content_hash != material.content_hash
            ):
                raise HTTPException(status.HTTP_409_CONFLICT, "graph decision id was reused")
            if existing.decision != "HUMAN_APPROVED":
                raise HTTPException(status.HTTP_409_CONFLICT, "graph decision is not promotable")
            return GraphPromotionResponse(
                snapshot_id=existing.snapshot_id,
                decision_id=existing.decision_id,
                mode="HUMAN_APPROVED",
                content_hash=existing.content_hash,
                created=False,
            )
        try:
            decision = authorize_graph_review(
                candidate=material,
                previous=material.previous,
                diff=type(
                    "GraphDiffProjection",
                    (),
                    {"governed_change_count": material.governed_change_count},
                )(),
                mode=GraphReviewMode(request.mode),
                decision_id=request.decision_id,
                principal=principal,
                reason_ref=request.reason_ref,
                previously_rejected_hashes=material.rejected_content_hashes,
            )
            with connect() as connection, connection.transaction():
                ProductionGraphRepository(connection).promote(
                    scope=scope,
                    cell_id=material.cell_id,
                    placement_epoch=material.placement_epoch,
                    snapshot_id=decision.snapshot_id,
                    decision_id=request.decision_id,
                    mode=decision.mode.value,
                    principal=decision.principal,
                    reason_ref=decision.reason_ref,
                )
        except IntegrityError as error:
            # The pre-read above is advisory: two exact requests can race on
            # the target unique decision key.  The losing transaction must
            # re-read after its rollback and return the winner only when every
            # immutable operand matches; it must never retry the mutation.
            try:
                with connect() as connection, connection.transaction():
                    raced = ProductionGraphRepository(connection).promotion_record(
                        scope=scope, decision_id=request.decision_id
                    )
            except UndefinedTable as table_error:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "Production Graph target schema is not installed",
                ) from table_error
            if (
                raced is not None
                and raced.snapshot_id == snapshot_id
                and raced.content_hash == material.content_hash
                and raced.decision == "HUMAN_APPROVED"
            ):
                return GraphPromotionResponse(
                    snapshot_id=raced.snapshot_id,
                    decision_id=raced.decision_id,
                    mode="HUMAN_APPROVED",
                    content_hash=raced.content_hash,
                    created=False,
                )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "graph decision could not be committed for this candidate",
            ) from error
        except UndefinedTable as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Production Graph target schema is not installed",
            ) from error
        except ScaleRuntimeError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return GraphPromotionResponse(
            snapshot_id=decision.snapshot_id,
            decision_id=request.decision_id,
            mode=decision.mode.value,
            content_hash=material.content_hash or "",
        )

    return router
