"""Lease-fenced coordinator execution for Production Graph reconciliation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from solvan.application.production_graph_types import (
    GraphSourceAdapter,
    GraphSourcePlanEntry,
    GraphSourceResult,
)
from solvan.domain import Scope
from solvan.persistence.production_graph import (
    GraphRun,
    ProductionGraphReconciler,
    ProductionGraphRepository,
    diff_graphs,
    stable_graph_identifier,
)
from solvan.platform.production_graph_sources import (
    AssetInventoryDenied,
    AssetInventoryUnavailable,
    GraphSourceDenied,
    GraphSourceNotEntitled,
    GraphSourceRegistry,
    GraphSourceUnavailable,
    graph_source_registry_from_config,
)


@dataclass(frozen=True, slots=True)
class GraphReconciliationReceipt:
    run_id: str
    snapshot_id: str
    state: str
    completeness: str
    source_count: int


class _FrozenResultAdapter(GraphSourceAdapter):
    """Replay already-fetched typed results without a second provider call."""

    def __init__(self, results: Mapping[tuple[str, int], GraphSourceResult]) -> None:
        self._results = dict(results)

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        return self._results[(source_key, source_revision)]


class ProductionGraphWorker:
    """Run one durable graph request without holding locks across cloud I/O.

    The API only persists a frozen request. This coordinator-owned worker
    claims that request, performs each registered read once, then revalidates
    the exact lease and placement before writing the complete draft in one
    Cloud SQL transaction. A stale worker cannot publish partial observations,
    a draft, or a terminal result.
    """

    def __init__(
        self,
        *,
        registry: GraphSourceRegistry,
        owner: str,
        lease_seconds: int = 900,
    ) -> None:
        if not owner.strip() or not 1 <= lease_seconds <= 900:
            raise ValueError("graph worker requires an owner and bounded lease")
        self._registry = registry
        self._owner = owner
        self._lease_seconds = lease_seconds

    def execute(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        run_id: str,
    ) -> GraphReconciliationReceipt:
        repository = ProductionGraphRepository(connection)
        with connection.transaction():
            pending = repository.get_run_identity(scope=scope, run_id=run_id)
            if pending is None:
                raise RuntimeError("graph request is absent or belongs to an obsolete placement")
            source_plan = repository.run_source_plan(scope=scope, run_id=run_id)
            if not source_plan:
                raise RuntimeError("graph request has no frozen source-policy set")
            placement = repository.current_placement(scope=scope)
            if placement is None or (
                placement.cell_id,
                placement.placement_epoch,
            ) != (pending.cell_id, pending.placement_epoch):
                raise RuntimeError("graph request placement is no longer current")
            run = repository.claim_run(
                scope=scope,
                cell_id=pending.cell_id,
                placement_epoch=pending.placement_epoch,
                run_id=run_id,
                lease_owner=self._owner,
                lease_seconds=self._lease_seconds,
            )

        results = tuple(self._read_source(item) for item in source_plan)
        frozen = _FrozenResultAdapter(
            {(item.source_key, item.source_revision): item for item in results}
        )
        snapshot_id = stable_graph_identifier("pgs", run_id, "snapshot")
        try:
            candidate = ProductionGraphReconciler().reconcile(
                snapshot_id=snapshot_id,
                source_plan=source_plan,
                adapter=frozen,
            )
            with connection.transaction():
                repository.lock_run_lease(scope=scope, run=run)
                previous = repository.current_approved_draft(scope=scope)
                version = repository.next_snapshot_version(scope=scope, run=run)
                repository.create_draft(
                    scope=scope,
                    cell_id=run.cell_id,
                    placement_epoch=run.placement_epoch,
                    snapshot_id=snapshot_id,
                    snapshot_version=version,
                    run_id=run_id,
                    reconciled_at=datetime.now(UTC),
                )
                observation_ids = self._record_observations(
                    repository,
                    scope=scope,
                    run=run,
                    results=results,
                    region=placement.region,
                )
                repository.record_elements(
                    scope=scope,
                    cell_id=run.cell_id,
                    placement_epoch=run.placement_epoch,
                    snapshot_id=snapshot_id,
                    nodes=candidate.nodes,
                    edges=candidate.edges,
                    observation_ids=observation_ids,
                )
                self._record_tiers(
                    repository,
                    scope=scope,
                    run=run,
                    snapshot_id=snapshot_id,
                    source_plan=source_plan,
                    results=results,
                )
                repository.record_diff(
                    scope=scope,
                    cell_id=run.cell_id,
                    placement_epoch=run.placement_epoch,
                    diff_id=stable_graph_identifier("pgd", run_id, "diff"),
                    base_snapshot_id=previous.snapshot_id if previous is not None else None,
                    candidate_snapshot_id=snapshot_id,
                    diff=diff_graphs(previous, candidate),
                )
                self._record_findings(
                    repository,
                    scope=scope,
                    run=run,
                    snapshot_id=snapshot_id,
                    findings=candidate.findings,
                )
                repository.finalize(
                    scope=scope,
                    cell_id=run.cell_id,
                    placement_epoch=run.placement_epoch,
                    snapshot_id=snapshot_id,
                )
                terminal = "COMPLETED" if candidate.completeness == "COMPLETE" else "DEGRADED"
                repository.finish_run(
                    scope=scope,
                    cell_id=run.cell_id,
                    placement_epoch=run.placement_epoch,
                    run_id=run_id,
                    lease_token=_lease_token(run),
                    state=terminal,
                )
        except Exception:
            self._settle_failed(connection, repository=repository, scope=scope, run=run)
            raise
        return GraphReconciliationReceipt(
            run_id=run_id,
            snapshot_id=snapshot_id,
            state=terminal,
            completeness=candidate.completeness,
            source_count=len(results),
        )

    def _read_source(self, plan: GraphSourcePlanEntry) -> GraphSourceResult:
        try:
            return self._registry.fetch(
                source_key=plan.source_key,
                source_revision=plan.source_revision,
            )
        except GraphSourceNotEntitled:
            outcome = "NOT_ENTITLED"
        except (
            AssetInventoryDenied,
            AssetInventoryUnavailable,
            GraphSourceDenied,
            GraphSourceUnavailable,
        ):
            outcome = "UNAVAILABLE"
        return GraphSourceResult(
            source_key=plan.source_key,
            source_revision=plan.source_revision,
            tier=plan.tier,
            required_for_complete=plan.required_for_complete,
            outcome=outcome,
            pagination_complete=False,
            response_digest=_safe_failure_digest(plan, outcome),
            page_count=0,
        )

    def _record_observations(
        self,
        repository: ProductionGraphRepository,
        *,
        scope: Scope,
        run: GraphRun,
        results: Sequence[GraphSourceResult],
        region: str,
    ) -> dict[tuple[str, int], str]:
        identities: dict[tuple[str, int], str] = {}
        for result in results:
            observation_id = stable_graph_identifier(
                "pgo", run.run_id, f"{result.source_key}:{result.source_revision}"
            )
            identities[(result.source_key, result.source_revision)] = observation_id
            repository.record_observation(
                scope=scope,
                cell_id=run.cell_id,
                placement_epoch=run.placement_epoch,
                run_id=run.run_id,
                observation_id=observation_id,
                result=result,
                tool_invocation_ref=f"graph-source-receipt:{observation_id}",
                page_count=result.page_count,
                element_count=len(result.nodes) + len(result.edges),
                region=region,
            )
        return identities

    def _record_tiers(
        self,
        repository: ProductionGraphRepository,
        *,
        scope: Scope,
        run: GraphRun,
        snapshot_id: str,
        source_plan: Sequence[GraphSourcePlanEntry],
        results: Sequence[GraphSourceResult],
    ) -> None:
        for tier in range(1, 5):
            tier_plan = tuple(item for item in source_plan if item.tier == tier)
            tier_results = tuple(item for item in results if item.tier == tier)
            repository.record_tier_status(
                scope=scope,
                cell_id=run.cell_id,
                placement_epoch=run.placement_epoch,
                snapshot_id=snapshot_id,
                tier=tier,
                required_for_complete=any(item.required_for_complete for item in tier_plan),
                outcome=_tier_outcome(tier_results),
                observation_count=len(tier_results),
            )

    def _record_findings(
        self,
        repository: ProductionGraphRepository,
        *,
        scope: Scope,
        run: GraphRun,
        snapshot_id: str,
        findings: Sequence[str],
    ) -> None:
        for finding in findings:
            kind, subject = finding.split(":", 1)
            source_key: str | None = None
            source_revision: int | None = None
            node_key: str | None = None
            edge_key: str | None = None
            if kind == "SOURCE_INCOMPLETE":
                source_key, raw_revision = subject.rsplit(":", 1)
                source_revision = int(raw_revision)
            elif kind in {"UNDECLARED_DEPENDENCY", "UNOBSERVED_DECLARATION"}:
                edge_key = subject
            else:
                node_key = subject
            repository.record_finding(
                scope=scope,
                cell_id=run.cell_id,
                placement_epoch=run.placement_epoch,
                snapshot_id=snapshot_id,
                finding_id=stable_graph_identifier("pgf", run.run_id, finding),
                finding_kind=kind,
                detail_ref=f"ref_graph_finding_{hashlib.sha256(finding.encode()).hexdigest()}",
                subject_node_key=node_key,
                subject_edge_key=edge_key,
                subject_source_key=source_key,
                subject_source_revision=source_revision,
            )

    def _settle_failed(
        self,
        connection: Connection[Any],
        *,
        repository: ProductionGraphRepository,
        scope: Scope,
        run: GraphRun,
    ) -> None:
        try:
            with connection.transaction():
                repository.lock_run_lease(scope=scope, run=run)
                repository.finish_run(
                    scope=scope,
                    cell_id=run.cell_id,
                    placement_epoch=run.placement_epoch,
                    run_id=run.run_id,
                    lease_token=_lease_token(run),
                    state="FAILED",
                )
        except Exception:
            # The original error is authoritative. A stale lease or placement
            # deliberately prevents this worker from settling somebody else's run.
            pass


def run_next_graph_reconciliation(
    connection: Connection[Any],
    *,
    scope: Scope,
    owner: str,
    transport: Any,
    config: Mapping[str, Any],
) -> GraphReconciliationReceipt | None:
    """Execute the oldest current pending request, if one exists."""

    with connection.transaction():
        run_id = ProductionGraphRepository(connection).next_pending_run_id(scope=scope)
    if run_id is None:
        return None
    registry = graph_source_registry_from_config(transport, config=config)
    return ProductionGraphWorker(registry=registry, owner=owner).execute(
        connection,
        scope=scope,
        run_id=run_id,
    )


def _lease_token(run: GraphRun) -> str:
    if run.lease_token is None:
        raise RuntimeError("graph run has no lease token")
    return run.lease_token


def _tier_outcome(results: Sequence[GraphSourceResult]) -> str:
    if not results:
        return "NOT_CONFIGURED"
    outcomes = {item.outcome for item in results}
    if outcomes == {"COMPLETE"} and all(item.pagination_complete for item in results):
        return "COMPLETE"
    if "NOT_ENTITLED" in outcomes:
        return "NOT_ENTITLED"
    if outcomes & {"UNAVAILABLE", "REFUSED_REGION", "REFUSED_CLASSIFICATION"}:
        return "UNAVAILABLE"
    return "DEGRADED"


def _safe_failure_digest(plan: GraphSourcePlanEntry, outcome: str) -> str:
    body = json.dumps(
        {
            "schema_version": 1,
            "source_key": plan.source_key,
            "source_revision": plan.source_revision,
            "outcome": outcome,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()
