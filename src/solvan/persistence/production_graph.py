"""Target repository for the current governed Production Graph projection."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection

from solvan.application.production_graph_types import (
    GraphEdge,
    GraphNode,
    GraphSourceAdapter,
    GraphSourcePlanEntry,
    GraphSourceResult,
)
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier


@dataclass(frozen=True, slots=True)
class CurrentGraphProjection:
    snapshot_id: str
    snapshot_version: int
    reconciled_at: datetime
    age_seconds: int
    completeness: str
    autonomy_eligible: bool
    assisted_usable: bool
    cell_id: str
    placement_epoch: int
    graph_policy_binding_epoch: int


@dataclass(frozen=True, slots=True)
class TraceDependencyObservation:
    """Content-free dependency evidence from one bounded trace observation."""

    from_node_key: str
    to_node_key: str
    observed_at: datetime
    region: str

    def __post_init__(self) -> None:
        if not self.from_node_key.strip() or not self.to_node_key.strip():
            raise ValueError("trace observations require both endpoint keys")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("trace observation time must be timezone-aware")
        if not self.region.strip():
            raise ValueError("trace observation region is required")


class TraceDependencyAdapter:
    """Adapt bounded trace metadata into non-authoritative observed edges.

    Trace payloads and span attributes never enter the graph.  Only endpoint
    keys, region, time, count, and a digest of that normalized metadata are
    returned, and every edge is typed ``DEPENDS_ON_OBSERVED``.
    """

    def __init__(self, observations: Sequence[TraceDependencyObservation]) -> None:
        self._observations = tuple(observations)

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        if not source_key.strip() or source_revision < 1:
            raise ValueError("trace source identity is required")
        edges = tuple(
            GraphEdge(
                edge_key=f"observed:{item.from_node_key}->{item.to_node_key}",
                from_node_key=item.from_node_key,
                to_node_key=item.to_node_key,
                edge_kind="DEPENDS_ON_OBSERVED",
                source_key=source_key,
                source_revision=source_revision,
            )
            for item in sorted(
                self._observations,
                key=lambda value: (value.from_node_key, value.to_node_key, value.observed_at),
            )
        )
        material = [
            {
                "from": item.from_node_key,
                "to": item.to_node_key,
                "at": item.observed_at.isoformat(),
                "region": item.region,
            }
            for item in self._observations
        ]
        return GraphSourceResult(
            source_key=source_key,
            source_revision=source_revision,
            tier=4,
            required_for_complete=False,
            outcome="COMPLETE",
            pagination_complete=True,
            edges=tuple(dict.fromkeys(edges)),
            response_digest=_graph_hash({"observations": material}),
        )


@dataclass(frozen=True, slots=True)
class DraftGraphSnapshot:
    snapshot_id: str
    material_hash: str
    content_hash: str
    completeness: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GraphDiff:
    node_changes: int
    edge_changes: int
    owner_changes: int
    environment_changes: int
    criticality_changes: int
    classification_changes: int
    authorization_changes: int
    verification_profile_changes: int
    region_changes: int
    source_authority_changes: int
    instrumentation_changes: int
    completeness_changes: int

    @property
    def governed_change_count(self) -> int:
        return (
            sum(self.__dict__.values())
            if hasattr(self, "__dict__")
            else sum(
                getattr(self, field)
                for field in (
                    "node_changes",
                    "edge_changes",
                    "owner_changes",
                    "environment_changes",
                    "criticality_changes",
                    "classification_changes",
                    "authorization_changes",
                    "verification_profile_changes",
                    "region_changes",
                    "source_authority_changes",
                    "instrumentation_changes",
                    "completeness_changes",
                )
            )
        )


@dataclass(frozen=True, slots=True)
class GraphRun:
    run_id: str
    cell_id: str
    placement_epoch: int
    state: str
    lease_token: str | None = None
    lease_expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class GraphPlacement:
    cell_id: str
    placement_epoch: int
    region: str
    classification_ceiling: str


@dataclass(frozen=True, slots=True)
class GraphRunSummary:
    run_id: str
    state: str
    requested_by: str
    requested_at: datetime
    started_at: datetime | None
    ended_at: datetime | None
    source_policy_set_hash: str


@dataclass(frozen=True, slots=True)
class GraphSnapshotSummary:
    snapshot_id: str
    snapshot_version: int
    status: str
    completeness: str | None
    content_hash: str | None
    reconciled_at: datetime
    autonomy_eligible: bool


@dataclass(frozen=True, slots=True)
class GraphSnapshotReview:
    """The bounded, hash-bound material an operator may review.

    This is deliberately a projection rather than a graph payload.  Resource
    identifiers and topology remain in the target cell; the review surface
    gets the exact hashes, derived change counters, tier outcomes, and typed
    findings needed to make a promotion decision.
    """

    snapshot_id: str
    snapshot_version: int
    status: str
    completeness: str | None
    material_hash: str | None
    content_hash: str | None
    autonomy_eligible: bool
    reconciled_at: datetime
    cell_id: str
    placement_epoch: int
    predecessor_snapshot_id: str | None
    predecessor_material_hash: str | None
    diff_hash: str | None
    governed_change_count: int | None
    diff_counts: Mapping[str, int]
    tier_status: tuple[Mapping[str, Any], ...]
    findings: tuple[Mapping[str, Any], ...]
    rejected_content_hashes: frozenset[str] = frozenset()

    @property
    def previous(self) -> GraphSnapshotReview | None:
        """The predecessor fields are enough for policy without a second graph read."""

        if self.predecessor_snapshot_id is None:
            return None
        return GraphSnapshotReview(
            snapshot_id=self.predecessor_snapshot_id,
            snapshot_version=0,
            status="APPROVED",
            completeness="COMPLETE",
            material_hash=self.predecessor_material_hash,
            content_hash=None,
            autonomy_eligible=True,
            reconciled_at=self.reconciled_at,
            cell_id=self.cell_id,
            placement_epoch=self.placement_epoch,
            predecessor_snapshot_id=None,
            predecessor_material_hash=None,
            diff_hash=None,
            governed_change_count=None,
            diff_counts={},
            tier_status=(),
            findings=(),
            rejected_content_hashes=frozenset(),
        )


@dataclass(frozen=True, slots=True)
class GraphPromotionRecord:
    decision_id: str
    snapshot_id: str
    decision: str
    content_hash: str


class ProductionGraphRepository:
    """Typed writer for the target graph; authority remains in SQL functions."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def current_placement(self, *, scope: Scope) -> GraphPlacement | None:
        row = self._connection.execute(
            """SELECT cell_id,placement_epoch,region,classification_ceiling
                 FROM solvan_graph.graph_scope_bindings
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND is_current AND lifecycle='ACTIVE'""",
            scope.canonical_dict(),
        ).fetchone()
        if row is None:
            return None
        return GraphPlacement(str(row[0]), int(row[1]), str(row[2]), str(row[3]))

    def current_source_plan(self) -> tuple[GraphSourcePlanEntry, ...]:
        """Resolve the newest non-retired immutable revision per source key."""

        rows = self._connection.execute(
            """SELECT source_key,revision,tier,required_for_complete,policy_hash
                 FROM (
                   SELECT DISTINCT ON (source_key)
                          source_key,revision,tier,required_for_complete,policy_hash
                     FROM solvan_graph.graph_source_policies
                    WHERE retired_at IS NULL AND effective_at <= now()
                    ORDER BY source_key,revision DESC
                 ) current_source
                ORDER BY tier,source_key""",
            {},
        ).fetchall()
        return tuple(
            GraphSourcePlanEntry(
                source_key=str(row[0]),
                source_revision=int(row[1]),
                tier=int(row[2]),
                required_for_complete=bool(row[3]),
                policy_hash=str(row[4]),
            )
            for row in rows
        )

    def list_runs(self, *, scope: Scope, limit: int = 20) -> tuple[GraphRunSummary, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("graph run list limit must be between 1 and 100")
        rows = self._connection.execute(
            """SELECT run_id,state,requested_by,requested_at,started_at,ended_at,
                      source_policy_set_hash
                 FROM solvan_graph.graph_reconciliation_runs
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                ORDER BY requested_at DESC,run_id DESC LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(
            GraphRunSummary(
                run_id=str(row[0]),
                state=str(row[1]),
                requested_by=str(row[2]),
                requested_at=row[3],
                started_at=row[4],
                ended_at=row[5],
                source_policy_set_hash=str(row[6]),
            )
            for row in rows
        )

    def next_pending_run_id(self, *, scope: Scope) -> str | None:
        row = self._connection.execute(
            """SELECT run.run_id
                 FROM solvan_graph.graph_reconciliation_runs run
                 JOIN solvan_graph.graph_scope_bindings binding ON
                   (binding.organization_id,binding.project_id,binding.environment_id,
                    binding.cell_id,binding.placement_epoch)=
                   (run.organization_id,run.project_id,run.environment_id,
                    run.cell_id,run.placement_epoch)
                WHERE run.organization_id=%(organization_id)s
                  AND run.project_id=%(project_id)s
                  AND run.environment_id=%(environment_id)s
                  AND run.state='PENDING'
                  AND binding.is_current AND binding.lifecycle='ACTIVE'
                ORDER BY run.requested_at,run.run_id
                LIMIT 1""",
            scope.canonical_dict(),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def get_run(self, *, scope: Scope, run_id: str) -> GraphRunSummary | None:
        row = self._connection.execute(
            """SELECT run_id,state,requested_by,requested_at,started_at,ended_at,
                      source_policy_set_hash
                 FROM solvan_graph.graph_reconciliation_runs
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND run_id=%(run_id)s""",
            {**scope.canonical_dict(), "run_id": run_id},
        ).fetchone()
        if row is None:
            return None
        return GraphRunSummary(
            run_id=str(row[0]),
            state=str(row[1]),
            requested_by=str(row[2]),
            requested_at=row[3],
            started_at=row[4],
            ended_at=row[5],
            source_policy_set_hash=str(row[6]),
        )

    def get_run_identity(self, *, scope: Scope, run_id: str) -> GraphRun | None:
        """Resolve one request identity without accepting a stale placement."""

        row = self._connection.execute(
            """SELECT run.cell_id,run.placement_epoch,run.state,run.lease_token,
                      run.lease_expires_at
                 FROM solvan_graph.graph_reconciliation_runs run
                 JOIN solvan_graph.graph_scope_bindings binding ON
                   (binding.organization_id,binding.project_id,binding.environment_id,
                    binding.cell_id,binding.placement_epoch)=
                   (run.organization_id,run.project_id,run.environment_id,
                    run.cell_id,run.placement_epoch)
                WHERE run.organization_id=%(organization_id)s
                  AND run.project_id=%(project_id)s
                  AND run.environment_id=%(environment_id)s
                  AND run.run_id=%(run_id)s
                  AND binding.is_current AND binding.lifecycle='ACTIVE'""",
            {**scope.canonical_dict(), "run_id": run_id},
        ).fetchone()
        if row is None:
            return None
        return GraphRun(
            run_id=run_id,
            cell_id=str(row[0]),
            placement_epoch=int(row[1]),
            state=str(row[2]),
            lease_token=str(row[3]) if row[3] is not None else None,
            lease_expires_at=row[4],
        )

    def lock_run_lease(
        self,
        *,
        scope: Scope,
        run: GraphRun,
    ) -> None:
        """Lock and validate the exact current placement and live lease.

        Callers perform every draft write and terminal transition in the same
        transaction after this fence. Provider I/O must happen before entering
        that transaction so a slow cloud call cannot retain a database lock.
        """

        if run.state != "RUNNING" or run.lease_token is None:
            raise ValueError("a running graph lease is required")
        row = self._connection.execute(
            """SELECT run.run_id
                 FROM solvan_graph.graph_reconciliation_runs run
                 JOIN solvan_graph.graph_scope_bindings binding ON
                   (binding.organization_id,binding.project_id,binding.environment_id,
                    binding.cell_id,binding.placement_epoch)=
                   (run.organization_id,run.project_id,run.environment_id,
                    run.cell_id,run.placement_epoch)
                WHERE run.organization_id=%(organization_id)s
                  AND run.project_id=%(project_id)s
                  AND run.environment_id=%(environment_id)s
                  AND run.cell_id=%(cell_id)s
                  AND run.placement_epoch=%(placement_epoch)s
                  AND run.run_id=%(run_id)s
                  AND run.state='RUNNING'
                  AND run.lease_token=%(lease_token)s::uuid
                  AND run.lease_expires_at > clock_timestamp()
                  AND binding.is_current AND binding.lifecycle='ACTIVE'
                FOR UPDATE OF run,binding""",
            {
                **scope.canonical_dict(),
                "cell_id": run.cell_id,
                "placement_epoch": run.placement_epoch,
                "run_id": run.run_id,
                "lease_token": run.lease_token,
            },
        ).fetchone()
        if row is None:
            raise RuntimeError("graph run lease or placement is stale")

    def next_snapshot_version(self, *, scope: Scope, run: GraphRun) -> int:
        row = self._connection.execute(
            """SELECT coalesce(max(snapshot_version),0)+1
                 FROM solvan_graph.graph_snapshots
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND cell_id=%(cell_id)s
                  AND placement_epoch=%(placement_epoch)s""",
            {
                **scope.canonical_dict(),
                "cell_id": run.cell_id,
                "placement_epoch": run.placement_epoch,
            },
        ).fetchone()
        if row is None:
            raise RuntimeError("graph snapshot version could not be allocated")
        return int(row[0])

    def current_approved_draft(self, *, scope: Scope) -> DraftGraphSnapshot | None:
        """Rehydrate the exact approved candidate for deterministic diffing."""

        snapshot = self._connection.execute(
            """SELECT snapshot.snapshot_id,snapshot.material_hash,snapshot.content_hash,
                      snapshot.completeness,snapshot.cell_id,snapshot.placement_epoch
                 FROM solvan_graph.graph_scope_bindings binding
                 JOIN solvan_graph.graph_snapshots snapshot ON
                   (snapshot.organization_id,snapshot.project_id,snapshot.environment_id,
                    snapshot.cell_id,snapshot.placement_epoch)=
                   (binding.organization_id,binding.project_id,binding.environment_id,
                    binding.cell_id,binding.placement_epoch)
                WHERE binding.organization_id=%(organization_id)s
                  AND binding.project_id=%(project_id)s
                  AND binding.environment_id=%(environment_id)s
                  AND binding.is_current AND binding.lifecycle='ACTIVE'
                  AND snapshot.status='APPROVED'""",
            scope.canonical_dict(),
        ).fetchone()
        if snapshot is None:
            return None
        params = {
            **scope.canonical_dict(),
            "cell_id": str(snapshot[4]),
            "placement_epoch": int(snapshot[5]),
            "snapshot_id": str(snapshot[0]),
        }
        nodes = tuple(
            GraphNode(
                node_key=str(row[0]),
                node_kind=str(row[1]),
                resource_ref=str(row[2]),
                external_project_id=str(row[3]) if row[3] is not None else None,
                owner_team=str(row[4]) if row[4] is not None else None,
                declared_environment=str(row[5]) if row[5] is not None else None,
                business_criticality=str(row[6]) if row[6] is not None else None,
                data_classification=str(row[7]) if row[7] is not None else None,
                authorization_boundary=str(row[8]) if row[8] is not None else None,
                verification_profile=str(row[9]) if row[9] is not None else None,
                region=str(row[10]),
                instrumentation_state=str(row[11]),
                source_key=str(row[12]),
                source_revision=int(row[13]),
            )
            for row in self._connection.execute(
                """SELECT node_key,node_kind,resource_ref,external_project_id,
                          owner_team,declared_environment,business_criticality,
                          data_classification,authorization_boundary,verification_profile,
                          region,instrumentation_state,source_key,source_revision
                     FROM solvan_graph.graph_nodes
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND cell_id=%(cell_id)s
                      AND placement_epoch=%(placement_epoch)s
                      AND snapshot_id=%(snapshot_id)s
                    ORDER BY node_key""",
                params,
            ).fetchall()
        )
        edges = tuple(
            GraphEdge(
                edge_key=str(row[0]),
                from_node_key=str(row[1]),
                to_node_key=str(row[2]),
                edge_kind=str(row[3]),
                source_key=str(row[4]),
                source_revision=int(row[5]),
            )
            for row in self._connection.execute(
                """SELECT edge_key,from_node_key,to_node_key,edge_kind,
                          source_key,source_revision
                     FROM solvan_graph.graph_edges
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND cell_id=%(cell_id)s
                      AND placement_epoch=%(placement_epoch)s
                      AND snapshot_id=%(snapshot_id)s
                    ORDER BY edge_key""",
                params,
            ).fetchall()
        )
        return DraftGraphSnapshot(
            snapshot_id=str(snapshot[0]),
            material_hash=str(snapshot[1]),
            content_hash=str(snapshot[2]),
            completeness=str(snapshot[3]),
            nodes=nodes,
            edges=edges,
            findings=(),
        )

    def run_source_plan(self, *, scope: Scope, run_id: str) -> tuple[GraphSourcePlanEntry, ...]:
        rows = self._connection.execute(
            """SELECT source_key,source_revision,tier,required_for_complete,policy_hash
                 FROM solvan_graph.graph_reconciliation_run_sources
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND run_id=%(run_id)s
                ORDER BY ordinal""",
            {**scope.canonical_dict(), "run_id": run_id},
        ).fetchall()
        return tuple(
            GraphSourcePlanEntry(
                source_key=str(row[0]),
                source_revision=int(row[1]),
                tier=int(row[2]),
                required_for_complete=bool(row[3]),
                policy_hash=str(row[4]),
            )
            for row in rows
        )

    def list_snapshots(self, *, scope: Scope, limit: int = 20) -> tuple[GraphSnapshotSummary, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("graph snapshot list limit must be between 1 and 100")
        rows = self._connection.execute(
            """SELECT snapshot_id,snapshot_version,status,completeness,content_hash,
                      reconciled_at,autonomy_eligible
                 FROM solvan_graph.graph_snapshots
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                ORDER BY snapshot_version DESC LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(
            GraphSnapshotSummary(
                snapshot_id=str(row[0]),
                snapshot_version=int(row[1]),
                status=str(row[2]),
                completeness=str(row[3]) if row[3] is not None else None,
                content_hash=str(row[4]) if row[4] is not None else None,
                reconciled_at=row[5],
                autonomy_eligible=bool(row[6]),
            )
            for row in rows
        )

    def review_material(self, *, scope: Scope, snapshot_id: str) -> GraphSnapshotReview | None:
        """Read one exact candidate and its derived review operands.

        The query is scope-bound at every read.  It never falls back to a
        predecessor or to a different placement when the requested candidate
        is absent.  The target schema is intentionally not part of the MSR;
        callers must translate an unavailable schema into a truthful 503.
        """

        params = {**scope.canonical_dict(), "snapshot_id": snapshot_id}
        row = self._connection.execute(
            """SELECT snapshot_id,snapshot_version,status,completeness,material_hash,
                          content_hash,autonomy_eligible,reconciled_at,cell_id,
                          placement_epoch
                     FROM solvan_graph.graph_snapshots
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND snapshot_id=%(snapshot_id)s""",
            params,
        ).fetchone()
        if row is None:
            return None
        predecessor = self._connection.execute(
            """SELECT snapshot_id,material_hash
                     FROM solvan_graph.graph_snapshots
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND status='APPROVED'
                      AND snapshot_id<>%(snapshot_id)s
                    ORDER BY approved_at DESC NULLS LAST
                    LIMIT 1""",
            params,
        ).fetchone()
        diff = self._connection.execute(
            """SELECT diff_hash,governed_change_count,node_changes,edge_changes,
                          owner_changes,environment_changes,criticality_changes,
                          classification_changes,authorization_changes,
                          verification_profile_changes,region_changes,
                          source_authority_changes,instrumentation_changes,
                          completeness_changes,base_snapshot_id
                     FROM solvan_graph.graph_snapshot_diffs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND cell_id=%(cell_id)s
                      AND placement_epoch=%(placement_epoch)s
                      AND candidate_snapshot_id=%(snapshot_id)s""",
            {
                **params,
                "cell_id": str(row[8]),
                "placement_epoch": int(row[9]),
            },
        ).fetchone()
        tiers = tuple(
            {
                "tier": int(item[0]),
                "required_for_complete": bool(item[1]),
                "outcome": str(item[2]),
                "observation_count": int(item[3]),
            }
            for item in self._connection.execute(
                """SELECT tier,required_for_complete,outcome,observation_count
                         FROM solvan_graph.graph_snapshot_tier_status
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND cell_id=%(cell_id)s
                          AND placement_epoch=%(placement_epoch)s
                          AND snapshot_id=%(snapshot_id)s
                        ORDER BY tier""",
                {
                    **params,
                    "cell_id": str(row[8]),
                    "placement_epoch": int(row[9]),
                },
            ).fetchall()
        )
        findings = tuple(
            {
                "finding_id": str(item[0]),
                "finding_kind": str(item[1]),
                "subject_node_key": str(item[2]) if item[2] is not None else None,
                "subject_edge_key": str(item[3]) if item[3] is not None else None,
                "detail_ref": str(item[4]),
                "status": str(item[5]),
            }
            for item in self._connection.execute(
                """SELECT finding_id,finding_kind,subject_node_key,subject_edge_key,
                                  detail_ref,status
                             FROM solvan_graph.graph_findings
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND cell_id=%(cell_id)s
                              AND placement_epoch=%(placement_epoch)s
                              AND snapshot_id=%(snapshot_id)s
                            ORDER BY finding_id""",
                {
                    **params,
                    "cell_id": str(row[8]),
                    "placement_epoch": int(row[9]),
                },
            ).fetchall()
        )
        rejected_hashes = frozenset(
            str(item[0])
            for item in self._connection.execute(
                """SELECT content_hash
                         FROM solvan_graph.graph_promotion_decisions
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND decision='REJECTED'""",
                params,
            ).fetchall()
        )
        diff_counts: dict[str, int] = {}
        diff_hash: str | None = None
        governed_change_count: int | None = None
        predecessor_snapshot_id = str(predecessor[0]) if predecessor is not None else None
        if diff is not None:
            diff_hash = str(diff[0])
            governed_change_count = int(diff[1])
            diff_counts = {
                key: int(value)
                for key, value in zip(
                    (
                        "node_changes",
                        "edge_changes",
                        "owner_changes",
                        "environment_changes",
                        "criticality_changes",
                        "classification_changes",
                        "authorization_changes",
                        "verification_profile_changes",
                        "region_changes",
                        "source_authority_changes",
                        "instrumentation_changes",
                        "completeness_changes",
                    ),
                    diff[2:14],
                    strict=True,
                )
            }
            if diff[14] is not None:
                predecessor_snapshot_id = str(diff[14])
        return GraphSnapshotReview(
            snapshot_id=str(row[0]),
            snapshot_version=int(row[1]),
            status=str(row[2]),
            completeness=str(row[3]) if row[3] is not None else None,
            material_hash=str(row[4]) if row[4] is not None else None,
            content_hash=str(row[5]) if row[5] is not None else None,
            autonomy_eligible=bool(row[6]),
            reconciled_at=row[7],
            cell_id=str(row[8]),
            placement_epoch=int(row[9]),
            predecessor_snapshot_id=predecessor_snapshot_id,
            predecessor_material_hash=str(predecessor[1]) if predecessor is not None else None,
            diff_hash=diff_hash,
            governed_change_count=governed_change_count,
            diff_counts=diff_counts,
            tier_status=tiers,
            findings=findings,
            rejected_content_hashes=rejected_hashes,
        )

    def promotion_record(self, *, scope: Scope, decision_id: str) -> GraphPromotionRecord | None:
        row = self._connection.execute(
            """SELECT decision_id,snapshot_id,decision,content_hash
                     FROM solvan_graph.graph_promotion_decisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND decision_id=%(decision_id)s""",
            {**scope.canonical_dict(), "decision_id": decision_id},
        ).fetchone()
        if row is None:
            return None
        return GraphPromotionRecord(
            decision_id=str(row[0]),
            snapshot_id=str(row[1]),
            decision=str(row[2]),
            content_hash=str(row[3]),
        )

    def start_run(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        run_id: str,
        source_plan: Sequence[GraphSourcePlanEntry],
        requested_by: str,
    ) -> GraphRun:
        if not source_plan:
            raise ValueError("a graph run requires a non-empty source-policy set")
        source_refs = [(item.source_key, item.source_revision) for item in source_plan]
        if len(source_refs) != len(set(source_refs)):
            raise ValueError("a graph run source-policy set cannot contain duplicates")
        source_policy_set_hash = _graph_hash(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "ordinal": ordinal,
                        "source_key": item.source_key,
                        "source_revision": item.source_revision,
                        "tier": item.tier,
                        "required_for_complete": item.required_for_complete,
                        "policy_hash": item.policy_hash,
                    }
                    for ordinal, item in enumerate(source_plan, start=1)
                ],
            }
        )
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_reconciliation_runs
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  run_id,source_policy_set_hash,requested_by,state)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                       %(cell_id)s,%(placement_epoch)s,%(run_id)s,
                       %(source_policy_set_hash)s,%(requested_by)s,'PENDING')""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "run_id": run_id,
                "source_policy_set_hash": source_policy_set_hash,
                "requested_by": requested_by,
            },
        )
        for ordinal, source in enumerate(source_plan, start=1):
            self._connection.execute(
                """INSERT INTO solvan_graph.graph_reconciliation_run_sources
                     (organization_id,project_id,environment_id,cell_id,placement_epoch,
                      run_id,ordinal,source_key,source_revision,tier,
                      required_for_complete,policy_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(cell_id)s,%(placement_epoch)s,%(run_id)s,%(ordinal)s,
                           %(source_key)s,%(source_revision)s,%(tier)s,
                           %(required_for_complete)s,%(policy_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "cell_id": cell_id,
                    "placement_epoch": placement_epoch,
                    "run_id": run_id,
                    "ordinal": ordinal,
                    "source_key": source.source_key,
                    "source_revision": source.source_revision,
                    "tier": source.tier,
                    "required_for_complete": source.required_for_complete,
                    "policy_hash": source.policy_hash,
                },
            )
        return GraphRun(run_id, cell_id, placement_epoch, "PENDING")

    def claim_run(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        run_id: str,
        lease_owner: str,
        lease_seconds: int = 60,
    ) -> GraphRun:
        """Claim one pending/expired graph run with an epoch-fenced lease."""

        if not lease_owner or not 1 <= lease_seconds <= 900:
            raise ValueError("graph lease owner and bounded duration are required")
        result = self._connection.execute(
            """UPDATE solvan_graph.graph_reconciliation_runs
                  SET state='RUNNING',lease_owner=%(lease_owner)s,
                      lease_token=gen_random_uuid(),
                      lease_expires_at=now() + make_interval(secs=>%(lease_seconds)s),
                      started_at=COALESCE(started_at,now())
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND cell_id=%(cell_id)s
                  AND placement_epoch=%(placement_epoch)s AND run_id=%(run_id)s
                  AND state IN ('PENDING','RUNNING')
                  AND (state='PENDING' OR lease_expires_at < now())
                RETURNING lease_token,lease_expires_at""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "run_id": run_id,
                "lease_owner": lease_owner,
                "lease_seconds": lease_seconds,
            },
        )
        row = result.fetchone()
        if row is None:
            raise RuntimeError("graph run is already claimed or no longer current")
        return GraphRun(
            run_id,
            cell_id,
            placement_epoch,
            "RUNNING",
            str(row[0]),
            row[1],
        )

    def finish_run(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        run_id: str,
        lease_token: str,
        state: str,
    ) -> None:
        """Terminalize a run only while its exact lease still owns it."""

        if state not in {"COMPLETED", "DEGRADED", "FAILED", "CANCELLED"}:
            raise ValueError("graph run terminal state is closed")
        result = self._connection.execute(
            """UPDATE solvan_graph.graph_reconciliation_runs
                  SET state=%(state)s,ended_at=now(),lease_owner=NULL,
                      lease_token=NULL,lease_expires_at=NULL
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND cell_id=%(cell_id)s
                  AND placement_epoch=%(placement_epoch)s AND run_id=%(run_id)s
                  AND state='RUNNING' AND lease_token=%(lease_token)s::uuid
                  AND lease_expires_at > clock_timestamp()""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "run_id": run_id,
                "lease_token": lease_token,
                "state": state,
            },
        )
        if getattr(result, "rowcount", 1) == 0:
            raise RuntimeError("graph run lease is stale or expired")

    def record_observation(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        run_id: str,
        observation_id: str,
        result: GraphSourceResult,
        tool_invocation_ref: str,
        page_count: int,
        element_count: int,
        region: str,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_source_observations
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  run_id,observation_id,source_key,source_revision,tool_invocation_ref,
                  response_digest,page_count,element_count,pagination_complete,outcome,region)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(run_id)s,%(observation_id)s,%(source_key)s,
                       %(source_revision)s,%(tool_invocation_ref)s,%(response_digest)s,
                       %(page_count)s,%(element_count)s,%(pagination_complete)s,%(outcome)s,
                       %(region)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "run_id": run_id,
                "observation_id": observation_id,
                "source_key": result.source_key,
                "source_revision": result.source_revision,
                "tool_invocation_ref": tool_invocation_ref,
                "response_digest": result.response_digest,
                "page_count": page_count,
                "element_count": element_count,
                "pagination_complete": result.pagination_complete,
                "outcome": result.outcome,
                "region": region,
            },
        )

    def create_draft(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        snapshot_id: str,
        snapshot_version: int,
        run_id: str,
        reconciled_at: datetime,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_snapshots
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  snapshot_id,snapshot_version,run_id,reconciled_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(snapshot_id)s,%(snapshot_version)s,%(run_id)s,
                       %(reconciled_at)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "snapshot_id": snapshot_id,
                "snapshot_version": snapshot_version,
                "run_id": run_id,
                "reconciled_at": reconciled_at,
            },
        )

    def record_tier_status(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        snapshot_id: str,
        tier: int,
        required_for_complete: bool,
        outcome: str,
        observation_count: int,
    ) -> None:
        """Persist one source-tier outcome before the snapshot is finalized."""

        if tier not in {1, 2, 3, 4}:
            raise ValueError("graph tier is closed to 1..4")
        if outcome not in {"COMPLETE", "UNAVAILABLE", "NOT_ENTITLED", "DEGRADED", "NOT_CONFIGURED"}:
            raise ValueError("graph tier outcome is closed")
        if observation_count < 0:
            raise ValueError("observation count cannot be negative")
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_snapshot_tier_status
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  snapshot_id,tier,required_for_complete,outcome,observation_count)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(snapshot_id)s,%(tier)s,%(required)s,
                       %(outcome)s,%(observation_count)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "snapshot_id": snapshot_id,
                "tier": tier,
                "required": required_for_complete,
                "outcome": outcome,
                "observation_count": observation_count,
            },
        )

    def record_elements(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        snapshot_id: str,
        nodes: Sequence[GraphNode],
        edges: Sequence[GraphEdge],
        observation_ids: Mapping[tuple[str, int], str],
    ) -> None:
        """Write source-bound draft elements; SQL triggers re-check provenance."""

        node_keys = {node.node_key for node in nodes}
        if any(
            edge.from_node_key not in node_keys or edge.to_node_key not in node_keys
            for edge in edges
        ):
            raise ValueError("graph edges must reference nodes in the same draft")
        params = {
            **scope.canonical_dict(),
            "cell_id": cell_id,
            "placement_epoch": placement_epoch,
            "snapshot_id": snapshot_id,
        }
        for node in nodes:
            observation_id = observation_ids.get((node.source_key, node.source_revision))
            if observation_id is None:
                raise ValueError(
                    f"missing observation for node source {node.source_key}:{node.source_revision}"
                )
            self._connection.execute(
                """INSERT INTO solvan_graph.graph_nodes
                     (organization_id,project_id,environment_id,cell_id,placement_epoch,
                      snapshot_id,node_id,node_key,node_kind,resource_ref,external_project_id,
                      owner_team,
                      declared_environment,business_criticality,data_classification,
                      authorization_boundary,verification_profile,region,
                      instrumentation_state,observation_id,source_key,source_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                      %(placement_epoch)s,%(snapshot_id)s,%(node_id)s,%(node_key)s,%(node_kind)s,
                      %(resource_ref)s,%(external_project_id)s,%(owner_team)s,
                      %(declared_environment)s,
                      %(business_criticality)s,%(data_classification)s,
                      %(authorization_boundary)s,%(verification_profile)s,%(region)s,
                      %(instrumentation_state)s,%(observation_id)s,%(source_key)s,
                      %(source_revision)s)""",
                {
                    **params,
                    "node_id": _stable_graph_identifier("pgn", snapshot_id, node.node_key),
                    "node_key": node.node_key,
                    "node_kind": node.node_kind,
                    "external_project_id": node.external_project_id,
                    "resource_ref": node.resource_ref,
                    "owner_team": node.owner_team,
                    "declared_environment": node.declared_environment,
                    "business_criticality": node.business_criticality,
                    "data_classification": node.data_classification,
                    "authorization_boundary": node.authorization_boundary,
                    "verification_profile": node.verification_profile,
                    "region": node.region,
                    "instrumentation_state": node.instrumentation_state,
                    "observation_id": observation_id,
                    "source_key": node.source_key,
                    "source_revision": node.source_revision,
                },
            )
        for edge in edges:
            observation_id = observation_ids.get((edge.source_key, edge.source_revision))
            if observation_id is None:
                raise ValueError(
                    f"missing observation for edge source {edge.source_key}:{edge.source_revision}"
                )
            self._connection.execute(
                """INSERT INTO solvan_graph.graph_edges
                     (organization_id,project_id,environment_id,cell_id,placement_epoch,
                      snapshot_id,edge_id,edge_key,from_node_key,to_node_key,edge_kind,
                      observation_id,source_key,source_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                      %(placement_epoch)s,%(snapshot_id)s,%(edge_id)s,%(edge_key)s,%(from_node_key)s,
                      %(to_node_key)s,%(edge_kind)s,%(observation_id)s,%(source_key)s,
                      %(source_revision)s)""",
                {
                    **params,
                    "edge_id": _stable_graph_identifier("pge", snapshot_id, edge.edge_key),
                    "edge_key": edge.edge_key,
                    "from_node_key": edge.from_node_key,
                    "to_node_key": edge.to_node_key,
                    "edge_kind": edge.edge_kind,
                    "observation_id": observation_id,
                    "source_key": edge.source_key,
                    "source_revision": edge.source_revision,
                },
            )

    def record_diff(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        diff_id: str,
        base_snapshot_id: str | None,
        candidate_snapshot_id: str,
        diff: GraphDiff,
    ) -> None:
        """Persist a derived diff; callers cannot supply the material count."""

        values = {
            field: int(getattr(diff, field))
            for field in (
                "node_changes",
                "edge_changes",
                "owner_changes",
                "environment_changes",
                "criticality_changes",
                "classification_changes",
                "authorization_changes",
                "verification_profile_changes",
                "region_changes",
                "source_authority_changes",
                "instrumentation_changes",
                "completeness_changes",
            )
        }
        diff_hash = _graph_hash(
            {"base": base_snapshot_id, "candidate": candidate_snapshot_id, **values}
        )
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_snapshot_diffs
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  diff_id,base_snapshot_id,candidate_snapshot_id,node_changes,edge_changes,
                  owner_changes,environment_changes,criticality_changes,classification_changes,
                  authorization_changes,verification_profile_changes,region_changes,
                  source_authority_changes,instrumentation_changes,completeness_changes,diff_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                  %(placement_epoch)s,%(diff_id)s,%(base_snapshot_id)s,%(candidate_snapshot_id)s,
                  %(node_changes)s,%(edge_changes)s,%(owner_changes)s,%(environment_changes)s,
                  %(criticality_changes)s,%(classification_changes)s,%(authorization_changes)s,
                  %(verification_profile_changes)s,%(region_changes)s,%(source_authority_changes)s,
                  %(instrumentation_changes)s,%(completeness_changes)s,%(diff_hash)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "diff_id": diff_id,
                "base_snapshot_id": base_snapshot_id,
                "candidate_snapshot_id": candidate_snapshot_id,
                **values,
                "diff_hash": diff_hash,
            },
        )

    def record_finding(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        snapshot_id: str,
        finding_id: str,
        finding_kind: str,
        detail_ref: str,
        subject_node_key: str | None = None,
        subject_edge_key: str | None = None,
        subject_source_key: str | None = None,
        subject_source_revision: int | None = None,
    ) -> None:
        subjects = sum(
            value is not None for value in (subject_node_key, subject_edge_key, subject_source_key)
        )
        if subjects != 1 or (subject_source_key is None) != (subject_source_revision is None):
            raise ValueError("a graph finding must identify exactly one subject")
        if not detail_ref.startswith("ref_"):
            raise ValueError("finding detail must be a typed reference")
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_findings
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  finding_id,snapshot_id,finding_kind,subject_node_key,subject_edge_key,
                  detail_ref,subject_source_key,subject_source_revision,status)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                  %(placement_epoch)s,%(finding_id)s,%(snapshot_id)s,%(finding_kind)s,
                  %(subject_node_key)s,%(subject_edge_key)s,%(detail_ref)s,
                  %(subject_source_key)s,%(subject_source_revision)s,'OPEN')""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "finding_id": finding_id,
                "snapshot_id": snapshot_id,
                "finding_kind": finding_kind,
                "subject_node_key": subject_node_key,
                "subject_edge_key": subject_edge_key,
                "subject_source_key": subject_source_key,
                "subject_source_revision": subject_source_revision,
                "detail_ref": detail_ref,
            },
        )

    def finalize(
        self, *, scope: Scope, cell_id: str, placement_epoch: int, snapshot_id: str
    ) -> None:
        self._connection.execute(
            "SELECT solvan_graph.graph_finalize_snapshot(%(organization_id)s,%(project_id)s,"
            "%(environment_id)s,%(cell_id)s,%(placement_epoch)s,%(snapshot_id)s)",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "snapshot_id": snapshot_id,
            },
        )

    def promote(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        snapshot_id: str,
        decision_id: str,
        mode: str,
        principal: str | None = None,
        reason_ref: str | None = None,
    ) -> None:
        if mode not in {"HUMAN_APPROVED", "AUTO_PROMOTED"}:
            raise ValueError("graph promotion mode is closed")
        self._connection.execute(
            """SELECT solvan_graph.graph_promote_snapshot(
                 %(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                 %(placement_epoch)s,%(snapshot_id)s,%(decision_id)s,%(mode)s,
                 %(principal)s,%(reason_ref)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "snapshot_id": snapshot_id,
                "decision_id": decision_id,
                "mode": mode,
                "principal": principal,
                "reason_ref": reason_ref,
            },
        )

    def cite(
        self,
        *,
        scope: Scope,
        cell_id: str,
        placement_epoch: int,
        citation_id: str,
        snapshot_id: str,
        consumer_kind: str,
        consumer_ref: str,
        consumer_attempt: int,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_graph.graph_citations
                 (organization_id,project_id,environment_id,cell_id,placement_epoch,
                  citation_id,snapshot_id,consumer_kind,consumer_ref,consumer_attempt)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
                       %(placement_epoch)s,%(citation_id)s,%(snapshot_id)s,%(consumer_kind)s,
                       %(consumer_ref)s,%(consumer_attempt)s)""",
            {
                **scope.canonical_dict(),
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "citation_id": citation_id,
                "snapshot_id": snapshot_id,
                "consumer_kind": consumer_kind,
                "consumer_ref": consumer_ref,
                "consumer_attempt": consumer_attempt,
            },
        )


class ProductionGraphReconciler:
    """Read-only source reconciliation that can only produce a DRAFT."""

    def reconcile(
        self,
        *,
        snapshot_id: str,
        source_plan: Sequence[GraphSourcePlanEntry],
        adapter: GraphSourceAdapter,
    ) -> DraftGraphSnapshot:
        if not source_plan or not any(item.required_for_complete for item in source_plan):
            raise ValueError("a graph reconciliation requires at least one required source")
        source_refs = [(item.source_key, item.source_revision) for item in source_plan]
        if len(source_refs) != len(set(source_refs)):
            raise ValueError("a graph reconciliation source plan cannot contain duplicates")
        observations = tuple(
            adapter.fetch(source_key=item.source_key, source_revision=item.source_revision)
            for item in source_plan
        )
        for planned, observed in zip(source_plan, observations, strict=True):
            if (
                observed.source_key,
                observed.source_revision,
                observed.tier,
                observed.required_for_complete,
            ) != (
                planned.source_key,
                planned.source_revision,
                planned.tier,
                planned.required_for_complete,
            ):
                raise ValueError("graph source response does not match its frozen policy entry")
        nodes = _unique_nodes(item.nodes for item in observations)
        edges = _unique_edges(item.edges for item in observations)
        node_keys = {node.node_key for node in nodes}
        findings: list[str] = []
        source_incomplete = False
        for result in observations:
            if result.required_for_complete and (
                result.outcome != "COMPLETE" or not result.pagination_complete
            ):
                findings.append(f"SOURCE_INCOMPLETE:{result.source_key}:{result.source_revision}")
                source_incomplete = True
        for node in nodes:
            if node.instrumentation_state in {"UNINSTRUMENTED", "UNKNOWN"}:
                findings.append(f"UNINSTRUMENTED_COMPONENT:{node.node_key}")
            if not node.owner_team or not node.owner_team.strip():
                findings.append(f"ORPHANED_RESOURCE:{node.node_key}")
        invalid_edge = False
        for edge in edges:
            if edge.from_node_key not in node_keys or edge.to_node_key not in node_keys:
                findings.append(f"UNDECLARED_DEPENDENCY:{edge.edge_key}")
                invalid_edge = True
        declared_pairs = {
            (edge.from_node_key, edge.to_node_key)
            for edge in edges
            if edge.edge_kind == "DEPENDS_ON_DECLARED"
        }
        observed_pairs = {
            (edge.from_node_key, edge.to_node_key)
            for edge in edges
            if edge.edge_kind == "DEPENDS_ON_OBSERVED"
        }
        for edge in edges:
            if (
                edge.edge_kind == "DEPENDS_ON_DECLARED"
                and (edge.from_node_key, edge.to_node_key) not in observed_pairs
            ):
                findings.append(f"UNOBSERVED_DECLARATION:{edge.edge_key}")
            if (
                edge.edge_kind == "DEPENDS_ON_OBSERVED"
                and (edge.from_node_key, edge.to_node_key) not in declared_pairs
                and edge.from_node_key in node_keys
                and edge.to_node_key in node_keys
            ):
                findings.append(f"UNDECLARED_DEPENDENCY:{edge.edge_key}")
        material = _graph_hash(nodes, edges)
        content = _graph_hash(
            {
                "material": material,
                "findings": findings,
                "sources": [
                    {
                        "source_key": result.source_key,
                        "source_revision": result.source_revision,
                        "outcome": result.outcome,
                        "pagination_complete": result.pagination_complete,
                    }
                    for result in observations
                ],
            }
        )
        complete = (
            not source_incomplete
            and not invalid_edge
            and all(
                not result.required_for_complete
                or (result.outcome == "COMPLETE" and result.pagination_complete)
                for result in observations
            )
        )
        return DraftGraphSnapshot(
            snapshot_id=snapshot_id,
            material_hash=material,
            content_hash=content,
            completeness="COMPLETE" if complete else "INCOMPLETE",
            nodes=nodes,
            edges=edges,
            findings=tuple(sorted(set(findings))),
        )


def diff_graphs(previous: DraftGraphSnapshot | None, candidate: DraftGraphSnapshot) -> GraphDiff:
    """Compute the material diff; promotion remains a separate SQL decision."""

    if previous is None:
        return GraphDiff(
            node_changes=len(candidate.nodes),
            edge_changes=len(candidate.edges),
            owner_changes=0,
            environment_changes=0,
            criticality_changes=0,
            classification_changes=0,
            authorization_changes=0,
            verification_profile_changes=0,
            region_changes=0,
            source_authority_changes=0,
            instrumentation_changes=0,
            completeness_changes=1,
        )
    old_nodes = {node.node_key: node for node in previous.nodes}
    new_nodes = {node.node_key: node for node in candidate.nodes}
    changed = [
        key for key in set(old_nodes) | set(new_nodes) if old_nodes.get(key) != new_nodes.get(key)
    ]
    common = [key for key in changed if key in old_nodes and key in new_nodes]
    return GraphDiff(
        node_changes=len(changed),
        edge_changes=len(
            set(edge.edge_key for edge in previous.edges)
            ^ {edge.edge_key for edge in candidate.edges}
        ),
        owner_changes=sum(old_nodes[key].owner_team != new_nodes[key].owner_team for key in common),
        environment_changes=sum(
            old_nodes[key].declared_environment != new_nodes[key].declared_environment
            for key in common
        ),
        criticality_changes=sum(
            old_nodes[key].business_criticality != new_nodes[key].business_criticality
            for key in common
        ),
        classification_changes=sum(
            old_nodes[key].data_classification != new_nodes[key].data_classification
            for key in common
        ),
        authorization_changes=sum(
            old_nodes[key].authorization_boundary != new_nodes[key].authorization_boundary
            for key in common
        ),
        verification_profile_changes=sum(
            old_nodes[key].verification_profile != new_nodes[key].verification_profile
            for key in common
        ),
        region_changes=sum(old_nodes[key].region != new_nodes[key].region for key in common),
        source_authority_changes=sum(
            (old_nodes[key].source_key, old_nodes[key].source_revision)
            != (new_nodes[key].source_key, new_nodes[key].source_revision)
            for key in common
        ),
        instrumentation_changes=sum(
            old_nodes[key].instrumentation_state != new_nodes[key].instrumentation_state
            for key in common
        ),
        completeness_changes=int(previous.completeness != candidate.completeness),
    )


def _unique_nodes(groups: Iterable[Sequence[GraphNode]]) -> tuple[GraphNode, ...]:
    by_key: dict[str, GraphNode] = {}
    for group in groups:
        for node in group:
            existing = by_key.get(node.node_key)
            if existing is None or existing == node:
                by_key[node.node_key] = node
                continue
            # App Hub and Asset Inventory legitimately observe the same
            # underlying resource. They may corroborate identity, but Solvan
            # stores one source-bound assertion rather than manufacturing a
            # merged fact with no truthful provenance. Conflicting identity or
            # governed values refuse the whole draft. Otherwise the richer
            # single-source assertion wins deterministically.
            identity_fields = ("node_kind", "resource_ref", "external_project_id", "region")
            if any(getattr(existing, field) != getattr(node, field) for field in identity_fields):
                raise ValueError(f"conflicting graph node identity {node.node_key}")
            governed_fields = (
                "owner_team",
                "declared_environment",
                "business_criticality",
                "data_classification",
                "authorization_boundary",
                "verification_profile",
            )
            if any(
                getattr(existing, field) is not None
                and getattr(node, field) is not None
                and getattr(existing, field) != getattr(node, field)
                for field in governed_fields
            ):
                raise ValueError(f"conflicting governed graph node {node.node_key}")
            by_key[node.node_key] = max((existing, node), key=_node_assertion_precedence)
    return tuple(by_key[key] for key in sorted(by_key))


def _node_assertion_precedence(node: GraphNode) -> tuple[int, int, str, int]:
    governed = sum(
        getattr(node, field) is not None
        for field in (
            "owner_team",
            "declared_environment",
            "business_criticality",
            "data_classification",
            "authorization_boundary",
            "verification_profile",
        )
    )
    instrumentation = {"UNKNOWN": 0, "UNINSTRUMENTED": 1, "INSTRUMENTED": 2}.get(
        node.instrumentation_state, -1
    )
    return governed, instrumentation, node.source_key, node.source_revision


def _unique_edges(groups: Iterable[Sequence[GraphEdge]]) -> tuple[GraphEdge, ...]:
    by_key: dict[str, GraphEdge] = {}
    for group in groups:
        for edge in group:
            if edge.edge_key in by_key and by_key[edge.edge_key] != edge:
                raise ValueError(f"conflicting graph edge {edge.edge_key}")
            by_key[edge.edge_key] = edge
    return tuple(by_key[key] for key in sorted(by_key))


def _graph_hash(
    nodes: Sequence[GraphNode] | Mapping[str, Any], edges: Sequence[GraphEdge] | None = None
) -> str:
    if isinstance(nodes, Mapping):
        value: Any = nodes
    else:
        value = {
            "nodes": [
                node.__dict__
                if hasattr(node, "__dict__")
                else {field: getattr(node, field) for field in node.__dataclass_fields__}
                for node in nodes
            ],
            "edges": [
                edge.__dict__
                if hasattr(edge, "__dict__")
                else {field: getattr(edge, field) for field in edge.__dataclass_fields__}
                for edge in (edges or ())
            ],
        }
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _stable_graph_identifier(prefix: str, snapshot_id: str, logical_key: str) -> str:
    """Derive an idempotent opaque ID for one immutable snapshot element."""

    randomness = hashlib.sha256(f"{snapshot_id}:{prefix}:{logical_key}".encode()).digest()[:10]
    return new_identifier(prefix, timestamp_ms=0, randomness=randomness)


def stable_graph_identifier(prefix: str, namespace: str, logical_key: str) -> str:
    """Public deterministic identifier helper for coordinator-owned graph work."""

    return _stable_graph_identifier(prefix, namespace, logical_key)


def read_current_graph(
    connection: Connection[Any], *, scope: Scope
) -> CurrentGraphProjection | None:
    """Read the current approved graph with age derived inside Cloud SQL."""

    row = connection.execute(
        """SELECT snapshot_id,snapshot_version,reconciled_at,age_seconds,
                  completeness,autonomy_eligible,assisted_usable,cell_id,
                  placement_epoch,graph_policy_binding_epoch
             FROM solvan_graph.graph_read_current(
               %(organization_id)s,%(project_id)s,%(environment_id)s)""",
        scope.canonical_dict(),
    ).fetchone()
    if row is None:
        return None
    return CurrentGraphProjection(
        snapshot_id=str(row[0]),
        snapshot_version=int(row[1]),
        reconciled_at=row[2],
        age_seconds=int(row[3]),
        completeness=str(row[4]),
        autonomy_eligible=bool(row[5]),
        assisted_usable=bool(row[6]),
        cell_id=str(row[7]),
        placement_epoch=int(row[8]),
        graph_policy_binding_epoch=int(row[9]),
    )
