"""Provider-neutral workspace lifecycle ports and durable task orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from solvan.application.workspace_results import WorkspaceTaskResult
from solvan.application.workspaces import (
    WorkspaceCheckpoint,
    WorkspaceCheckpointMaterial,
    WorkspaceContractError,
    WorkspaceProviderKind,
    WorkspaceRef,
    WorkspaceSpec,
    WorkspaceTaskInvocation,
)


class WorkspaceLifecycle(Protocol):
    async def open(self, spec: WorkspaceSpec) -> WorkspaceRef: ...

    async def checkpoint(
        self, ref: WorkspaceRef, material: WorkspaceCheckpointMaterial
    ) -> WorkspaceCheckpoint: ...

    async def hibernate(
        self, ref: WorkspaceRef, material: WorkspaceCheckpointMaterial
    ) -> WorkspaceCheckpoint: ...

    async def resume(
        self,
        checkpoint: WorkspaceCheckpoint,
        material: WorkspaceCheckpointMaterial,
    ) -> WorkspaceRef: ...

    async def close(self, ref: WorkspaceRef) -> None: ...


class WorkspaceProvider(Protocol):
    async def execute(self, invocation: WorkspaceTaskInvocation) -> WorkspaceTaskResult: ...


class WorkspaceRunRepository(Protocol):
    def create_task(self, invocation: WorkspaceTaskInvocation) -> None: ...

    def mark_dispatched(self, invocation: WorkspaceTaskInvocation) -> None: ...

    def complete_task(
        self,
        *,
        invocation: WorkspaceTaskInvocation,
        result: WorkspaceTaskResult,
    ) -> None: ...

    def fail_task(self, invocation: WorkspaceTaskInvocation, *, error_class: str) -> None: ...


class WorkspaceTaskCoordinator:
    """Durable-before-network dispatcher with deterministic provider selection."""

    def __init__(
        self,
        *,
        repository: WorkspaceRunRepository,
        providers: Mapping[WorkspaceProviderKind, WorkspaceProvider],
    ) -> None:
        self._repository = repository
        self._providers = dict(providers)

    async def execute(self, invocation: WorkspaceTaskInvocation) -> WorkspaceTaskResult:
        self._repository.create_task(invocation)
        provider = self._providers.get(invocation.provider)
        if provider is None:
            self._repository.fail_task(invocation, error_class="WORKSPACE_PROVIDER_UNAVAILABLE")
            raise WorkspaceContractError(
                f"workspace provider {invocation.provider.value} is unavailable"
            )
        self._repository.mark_dispatched(invocation)
        try:
            result = await provider.execute(invocation)
            result.assert_matches(invocation)
        except Exception as error:
            self._repository.fail_task(
                invocation,
                error_class=f"WORKSPACE_PROVIDER_{type(error).__name__}"[:128],
            )
            raise
        self._repository.complete_task(invocation=invocation, result=result)
        return result
