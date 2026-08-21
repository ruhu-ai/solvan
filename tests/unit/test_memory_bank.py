from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from solvan.application import MemoryBankUnavailable, MemoryReadGrant, MemorySearchQuery
from solvan.domain import MemoryScope, Scope
from solvan.platform import (
    GeminiMemoryBank,
    MemoryBankConfiguration,
    PlatformMemory,
    VertexMemoryAPI,
)

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
EXACT_SCOPE = MemoryScope(SCOPE, "incident-investigation", "INTERNAL", "europe-west1")
CONFIG = MemoryBankConfiguration("solvan-demo", "europe-west1", "supervisor-v1")
RESOURCE = f"{CONFIG.engine_resource}/memories/memory-1"


class FakeMemoryAPI:
    def __init__(self, memories: tuple[PlatformMemory, ...] = ()) -> None:
        self.memories = memories
        self.creates = 0

    def retrieve(self, *, name: str, scope: dict[str, str]) -> tuple[PlatformMemory, ...]:
        assert name == CONFIG.engine_resource
        return self.memories

    def create(self, *, name: str, fact: str, scope: dict[str, str]) -> PlatformMemory:
        assert name == CONFIG.engine_resource
        self.creates += 1
        created = PlatformMemory(RESOURCE, fact, scope, "2026-08-08T12:00:00Z")
        self.memories = (*self.memories, created)
        return created

    def search(
        self, *, name: str, scope: dict[str, str], query: str, top_k: int
    ) -> tuple[PlatformMemory, ...]:
        assert name == CONFIG.engine_resource
        assert query == "connection exhaustion"
        return self.memories[:top_k]


def test_reconcile_before_create_is_idempotent_for_exact_fact() -> None:
    api = FakeMemoryAPI()
    bank = GeminiMemoryBank(config=CONFIG, api=api)
    first = bank.upsert_exact(exact_scope=EXACT_SCOPE, fact_text="Verified fact")
    second = bank.upsert_exact(exact_scope=EXACT_SCOPE, fact_text="Verified fact")
    assert first == second
    assert api.creates == 1


def test_recall_labels_memory_untrusted_and_keeps_resource_id() -> None:
    api = FakeMemoryAPI(
        (PlatformMemory(RESOURCE, "Historical fact", EXACT_SCOPE.canonical_dict(), "1"),)
    )
    hints = GeminiMemoryBank(config=CONFIG, api=api).retrieve_exact(exact_scope=EXACT_SCOPE)
    assert hints[0].trust_label == "UNTRUSTED_HISTORICAL_CONTEXT"
    assert hints[0].memory_resource == RESOURCE


def test_non_exact_scope_from_platform_fails_closed() -> None:
    wrong = {**EXACT_SCOPE.canonical_dict(), "environment_id": "env_other"}
    api = FakeMemoryAPI((PlatformMemory(RESOURCE, "Fact", wrong, "1"),))
    with pytest.raises(MemoryBankUnavailable, match="non-exact"):
        GeminiMemoryBank(config=CONFIG, api=api).retrieve_exact(exact_scope=EXACT_SCOPE)


def test_vertex_adapter_unwraps_current_retrieve_pager_shape() -> None:
    sdk_memory = SimpleNamespace(
        name=RESOURCE,
        fact="Verified fact",
        scope=EXACT_SCOPE.canonical_dict(),
        update_time="2026-08-08T12:00:00Z",
    )

    class Memories:
        def retrieve(self, **kwargs):
            assert kwargs == {
                "name": CONFIG.engine_resource,
                "scope": EXACT_SCOPE.canonical_dict(),
            }
            return iter((SimpleNamespace(memory=sdk_memory),))

    api = VertexMemoryAPI.__new__(VertexMemoryAPI)
    api._memories = Memories()  # type: ignore[attr-defined]
    assert api.retrieve(
        name=CONFIG.engine_resource,
        scope=EXACT_SCOPE.canonical_dict(),
    ) == (
        PlatformMemory(
            RESOURCE,
            "Verified fact",
            EXACT_SCOPE.canonical_dict(),
            "2026-08-08T12:00:00Z",
        ),
    )


def test_semantic_search_preserves_resource_distance_and_exact_scope() -> None:
    api = FakeMemoryAPI(
        (
            PlatformMemory(
                RESOURCE,
                "Historical fact",
                EXACT_SCOPE.canonical_dict(),
                "1",
                0.125,
            ),
        )
    )
    now = datetime(2026, 8, 11, tzinfo=UTC)
    query = MemorySearchQuery(
        EXACT_SCOPE,
        MemoryReadGrant("grant:test", "evidence-agent", EXACT_SCOPE, now + timedelta(minutes=1)),
        "connection exhaustion",
        5,
        256,
        now,
    )
    candidate = GeminiMemoryBank(config=CONFIG, api=api).search(query=query)[0]
    assert candidate.memory_resource == RESOURCE
    assert candidate.distance == 0.125


def test_vertex_semantic_search_fails_whole_iteration_not_partial_results() -> None:
    sdk_memory = SimpleNamespace(
        name=RESOURCE,
        fact="Verified fact",
        scope=EXACT_SCOPE.canonical_dict(),
        update_time="2026-08-08T12:00:00Z",
    )

    class BrokenMemories:
        def retrieve(self, **kwargs):
            assert "similarity_search_params" in kwargs

            def results():
                yield SimpleNamespace(memory=sdk_memory, distance=0.2)
                raise OSError("pager failed")

            return results()

    api = VertexMemoryAPI.__new__(VertexMemoryAPI)
    api._memories = BrokenMemories()  # type: ignore[attr-defined]
    with pytest.raises(MemoryBankUnavailable, match="iteration"):
        api.search(
            name=CONFIG.engine_resource,
            scope=EXACT_SCOPE.canonical_dict(),
            query="connection exhaustion",
            top_k=5,
        )
