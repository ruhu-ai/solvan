"""Async facade for the synchronous PostgreSQL workspace authority."""

from __future__ import annotations

import asyncio

from solvan.application import (
    WorkspaceCheckpoint,
    WorkspaceCheckpointMaterial,
    WorkspaceRef,
    WorkspaceSpec,
)
from solvan.persistence.workspace_store import PostgresWorkspaceStore


class PostgresWorkspaceLifecycle:
    def __init__(self, store: PostgresWorkspaceStore) -> None:
        self._store = store

    async def open(self, spec: WorkspaceSpec) -> WorkspaceRef:
        return await asyncio.to_thread(self._store.open, spec)

    async def checkpoint(
        self, ref: WorkspaceRef, material: WorkspaceCheckpointMaterial
    ) -> WorkspaceCheckpoint:
        return await asyncio.to_thread(self._store.checkpoint, ref, material)

    async def hibernate(
        self, ref: WorkspaceRef, material: WorkspaceCheckpointMaterial
    ) -> WorkspaceCheckpoint:
        return await asyncio.to_thread(self._store.checkpoint, ref, material, hibernate=True)

    async def resume(
        self,
        checkpoint: WorkspaceCheckpoint,
        material: WorkspaceCheckpointMaterial,
    ) -> WorkspaceRef:
        return await asyncio.to_thread(self._store.resume, checkpoint, material)

    async def close(self, ref: WorkspaceRef) -> None:
        await asyncio.to_thread(self._store.close, ref)
