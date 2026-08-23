"""Exact-scope Gemini Enterprise Agent Platform Memory Bank adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

import agentplatform  # type: ignore[import-untyped]

from solvan.application import MemoryBankReceipt, MemoryBankUnavailable, MemoryHint
from solvan.application.memory import MemorySearchCandidate, MemorySearchQuery
from solvan.domain import MemoryScope


@dataclass(frozen=True, slots=True)
class PlatformMemory:
    name: str
    fact: str
    scope: dict[str, str]
    revision: str | None
    distance: float | None = None


class MemoryAPI(Protocol):
    def retrieve(self, *, name: str, scope: dict[str, str]) -> tuple[PlatformMemory, ...]: ...

    def create(self, *, name: str, fact: str, scope: dict[str, str]) -> PlatformMemory: ...

    def search(
        self,
        *,
        name: str,
        scope: dict[str, str],
        query: str,
        top_k: int,
    ) -> tuple[PlatformMemory, ...]: ...


class VertexMemoryAPI:
    """Thin wrapper around `client.agent_engines.memories`."""

    def __init__(self, *, project: str, location: str) -> None:
        client = agentplatform.Client(project=project, location=location)
        self._memories = client.agent_engines.memories

    def retrieve(self, *, name: str, scope: dict[str, str]) -> tuple[PlatformMemory, ...]:
        # The current Agent Platform SDK returns an iterable of
        # RetrieveMemoriesResponseRetrievedMemory wrappers, not a response with
        # a ``memories`` field. Keeping that shape explicit prevents a live-only
        # failure hidden by a simplified test double.
        result = self._memories.retrieve(name=name, scope=scope)
        memories: list[PlatformMemory] = []
        for retrieved in result:
            item = getattr(retrieved, "memory", None)
            if item is None:
                raise MemoryBankUnavailable("Memory Bank retrieve returned no memory")
            memories.append(self._from_sdk(item))
        return tuple(memories)

    def create(self, *, name: str, fact: str, scope: dict[str, str]) -> PlatformMemory:
        operation = self._memories.create(
            name=name,
            fact=fact,
            scope=scope,
        )
        response = operation.response
        if response is None:
            raise MemoryBankUnavailable("Memory Bank create returned no response")
        return self._from_sdk(response)

    def search(
        self,
        *,
        name: str,
        scope: dict[str, str],
        query: str,
        top_k: int,
    ) -> tuple[PlatformMemory, ...]:
        result = self._memories.retrieve(
            name=name,
            scope=scope,
            similarity_search_params={"search_query": query, "top_k": top_k},
        )
        memories: list[PlatformMemory] = []
        try:
            for retrieved in result:
                item = getattr(retrieved, "memory", None)
                distance = getattr(retrieved, "distance", None)
                if item is None or distance is None:
                    raise MemoryBankUnavailable("Memory Bank search returned an incomplete hit")
                parsed = self._from_sdk(item)
                memories.append(
                    PlatformMemory(
                        parsed.name,
                        parsed.fact,
                        parsed.scope,
                        parsed.revision,
                        float(distance),
                    )
                )
        except MemoryBankUnavailable:
            raise
        except Exception as error:
            raise MemoryBankUnavailable("Memory Bank search iteration failed") from error
        return tuple(memories)

    @staticmethod
    def _from_sdk(value: Any) -> PlatformMemory:
        return PlatformMemory(
            name=cast(str, value.name),
            fact=cast(str, value.fact),
            scope=dict(cast(dict[str, str], value.scope)),
            revision=(str(value.update_time) if value.update_time is not None else None),
        )


@dataclass(frozen=True, slots=True)
class MemoryBankConfiguration:
    project_id: str
    location: str
    reasoning_engine_id: str

    def __post_init__(self) -> None:
        if not all(
            value.strip() for value in (self.project_id, self.location, self.reasoning_engine_id)
        ):
            raise ValueError("Memory Bank project, location, and engine are required")

    @property
    def engine_resource(self) -> str:
        return (
            f"projects/{self.project_id}/locations/{self.location}/"
            f"reasoningEngines/{self.reasoning_engine_id}"
        )


def resolve_engine_id(
    resource: str,
    *,
    project_id: str,
    project_number: str,
    location: str,
) -> str:
    """Return the engine ID when ``resource`` names this exact project/region.

    Vertex returns reasoning-engine resource names with the project *number*,
    while every local canonical form is built from the project *ID*. Three
    separate copies of a prefix check compared against the ID form only, so
    the deployed value -- number form, straight from the create response --
    was refused as "outside the boundary" by the coordinator, the memory
    promoter, and the release probe alike (staging-20260823-04,
    memory_exact_scope_recall). Both spellings name the same project; the
    boundary is the project, not its spelling. Anything else still refuses.
    """

    for spelling in (project_id, project_number):
        prefix = f"projects/{spelling}/locations/{location}/reasoningEngines/"
        if resource.startswith(prefix):
            engine_id = resource.removeprefix(prefix)
            if not engine_id or "/" in engine_id:
                raise ValueError("Memory Bank reasoning engine resource is malformed")
            return engine_id
    raise ValueError("Memory Bank resource is outside the exact deployment scope")


class GeminiMemoryBank:
    """Reconcile exact fact and scope before calling non-idempotent create."""

    def __init__(self, *, config: MemoryBankConfiguration, api: MemoryAPI) -> None:
        self._config = config
        self._api = api

    def upsert_exact(self, *, exact_scope: MemoryScope, fact_text: str) -> MemoryBankReceipt:
        fact = fact_text.strip()
        if not fact:
            raise ValueError("Memory Bank fact cannot be empty")
        scope = self._managed_scope(exact_scope)
        try:
            existing = self._api.retrieve(name=self._config.engine_resource, scope=scope)
            for item in existing:
                self._validate(item, scope)
                if item.fact == fact:
                    return self._receipt(item, exact_scope)
            created = self._api.create(name=self._config.engine_resource, fact=fact, scope=scope)
            self._validate(created, scope)
            if created.fact != fact:
                raise MemoryBankUnavailable("Memory Bank changed the promoted fact")
            return self._receipt(created, exact_scope)
        except MemoryBankUnavailable:
            raise
        except Exception as exc:
            raise MemoryBankUnavailable("Memory Bank promotion is unavailable") from exc

    def retrieve_exact(self, *, exact_scope: MemoryScope) -> tuple[MemoryHint, ...]:
        scope = self._managed_scope(exact_scope)
        try:
            items = self._api.retrieve(name=self._config.engine_resource, scope=scope)
            hints: list[MemoryHint] = []
            for item in items:
                self._validate(item, scope)
                hints.append(
                    MemoryHint(
                        memory_resource=item.name,
                        fact_text=item.fact,
                        exact_scope=exact_scope,
                        memory_revision=item.revision,
                    )
                )
            return tuple(hints)
        except MemoryBankUnavailable:
            raise
        except Exception as exc:
            raise MemoryBankUnavailable("Memory Bank recall is unavailable") from exc

    def search(self, *, query: MemorySearchQuery) -> tuple[MemorySearchCandidate, ...]:
        scope = self._managed_scope(query.exact_scope)
        try:
            items = self._api.search(
                name=self._config.engine_resource,
                scope=scope,
                query=query.objective.strip(),
                top_k=query.maximum_results,
            )
            candidates: list[MemorySearchCandidate] = []
            for item in items:
                self._validate(item, scope)
                if item.distance is None:
                    raise MemoryBankUnavailable("Memory Bank search omitted distance")
                candidates.append(
                    MemorySearchCandidate(
                        memory_resource=item.name,
                        fact_text=item.fact,
                        exact_scope=query.exact_scope,
                        memory_revision=item.revision,
                        distance=item.distance,
                    )
                )
            return tuple(candidates)
        except MemoryBankUnavailable:
            raise
        except Exception as exc:
            raise MemoryBankUnavailable("Memory Bank semantic search is unavailable") from exc

    def _validate(self, item: PlatformMemory, scope: dict[str, str]) -> None:
        if item.scope != scope:
            raise MemoryBankUnavailable("Memory Bank returned a non-exact scope")
        prefix = f"{self._config.engine_resource}/memories/"
        if not item.name.startswith(prefix) or not item.fact.strip():
            raise MemoryBankUnavailable("Memory Bank returned an invalid memory resource")

    def _managed_scope(self, exact_scope: MemoryScope) -> dict[str, str]:
        if exact_scope.region != self._config.location:
            raise MemoryBankUnavailable("Memory scope is outside the regional engine")
        return exact_scope.canonical_dict()

    @staticmethod
    def _receipt(item: PlatformMemory, exact_scope: MemoryScope) -> MemoryBankReceipt:
        return MemoryBankReceipt(item.name, item.revision, exact_scope, item.fact)
