"""Target-only purge choreography for quality evidence and Production Graph data."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.domain import Scope


def purge_target_derived_context(
    connection: Connection[Any],
    *,
    scope: Scope,
    cell_id: str,
    placement_epoch: int,
    lifecycle_job_id: str,
    deletion_epoch: int,
) -> None:
    """Purge quality before graph data in the caller's lifecycle transaction.

    Both database functions independently lock and validate the same verified
    deletion job. Neither target schema is part of the competition release.
    """

    if placement_epoch < 1 or deletion_epoch < 1:
        raise ValueError("placement and deletion epochs must be positive")
    parameters = {
        **scope.canonical_dict(),
        "cell_id": cell_id,
        "placement_epoch": placement_epoch,
        "lifecycle_job_id": lifecycle_job_id,
        "deletion_epoch": deletion_epoch,
    }
    connection.execute(
        """SELECT solvan_quality.quality_purge_scope(
             %(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
             %(placement_epoch)s,%(lifecycle_job_id)s,%(deletion_epoch)s)""",
        parameters,
    )
    connection.execute(
        """SELECT solvan_graph.graph_purge_scope(
             %(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
             %(placement_epoch)s,%(lifecycle_job_id)s,%(deletion_epoch)s)""",
        parameters,
    )
