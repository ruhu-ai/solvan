"""Read-only logical-workspace checkpoint lineage projection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application import WorkspaceCheckpoint, WorkspaceRef
from solvan.persistence.workspace_projection import (
    matches_workspace_ref,
    project_workspace_checkpoint,
    select_workspace_row,
)
from solvan.persistence.workspace_provider_results import WorkspaceConflict


@dataclass(frozen=True, slots=True)
class WorkspaceManifestLineage:
    sequence_no: int
    parent_manifest_ref: str
    parent_manifest_hash: str


class WorkspaceLineageMixin:
    _connection: Connection[Any]

    def next_manifest_lineage(self, ref: WorkspaceRef) -> WorkspaceManifestLineage:
        """Return the exact immutable parent for the next checkpoint manifest."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            row = select_workspace_row(cursor, ref.scope, ref.workspace_id, for_update=False)
            if row is None or not matches_workspace_ref(row, ref):
                raise WorkspaceConflict("workspace lineage reference is stale")
            cursor.execute(
                """SELECT sequence_no, artifact_manifest_ref, artifact_manifest_hash
                  FROM solvan.workspace_checkpoints
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                  ORDER BY sequence_no DESC LIMIT 1""",
                {
                    **ref.scope.canonical_dict(),
                    "workspace_id": ref.workspace_id,
                    "workspace_generation": ref.generation,
                },
            )
            parent = cursor.fetchone()
        if parent is None:
            return WorkspaceManifestLineage(
                sequence_no=1,
                parent_manifest_ref=ref.input_manifest_ref,
                parent_manifest_hash=ref.input_manifest_hash,
            )
        return WorkspaceManifestLineage(
            sequence_no=int(parent["sequence_no"]) + 1,
            parent_manifest_ref=str(parent["artifact_manifest_ref"]),
            parent_manifest_hash=str(parent["artifact_manifest_hash"]),
        )

    def latest_checkpoint(self, ref: WorkspaceRef) -> WorkspaceCheckpoint:
        """Load the exact latest checkpoint for a current workspace reference."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            row = select_workspace_row(cursor, ref.scope, ref.workspace_id, for_update=False)
            if row is None or not matches_workspace_ref(row, ref):
                raise WorkspaceConflict("workspace checkpoint lookup reference is stale")
            cursor.execute(
                """SELECT * FROM solvan.workspace_checkpoints
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                  ORDER BY sequence_no DESC LIMIT 1""",
                {
                    **ref.scope.canonical_dict(),
                    "workspace_id": ref.workspace_id,
                    "workspace_generation": ref.generation,
                },
            )
            checkpoint = cursor.fetchone()
        if checkpoint is None:
            raise WorkspaceConflict("workspace has no checkpoint to rehydrate")
        return project_workspace_checkpoint(checkpoint, ref.scope)

    def checkpoint_by_id(self, ref: WorkspaceRef, checkpoint_id: str) -> WorkspaceCheckpoint:
        """Load one checkpoint only when it belongs to the exact current workspace."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            row = select_workspace_row(cursor, ref.scope, ref.workspace_id, for_update=False)
            if row is None or not matches_workspace_ref(row, ref):
                raise WorkspaceConflict("workspace checkpoint reference is stale")
            cursor.execute(
                """SELECT * FROM solvan.workspace_checkpoints
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND workspace_id = %(workspace_id)s
                    AND workspace_generation = %(workspace_generation)s
                    AND id = %(checkpoint_id)s""",
                {
                    **ref.scope.canonical_dict(),
                    "workspace_id": ref.workspace_id,
                    "workspace_generation": ref.generation,
                    "checkpoint_id": checkpoint_id,
                },
            )
            checkpoint = cursor.fetchone()
        if checkpoint is None:
            raise WorkspaceConflict("workspace checkpoint does not exist")
        return project_workspace_checkpoint(checkpoint, ref.scope)
