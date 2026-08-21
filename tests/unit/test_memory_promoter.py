from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from apps.memory_promoter.main import _engine_id, app, run_tick
from solvan.application import MemoryBankUnavailable, MemoryPromotionRecord
from solvan.domain import MemoryScope, Scope

NOW = datetime(2026, 8, 8, tzinfo=UTC)
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


class FakePromoter:
    def promote(self, *, candidate_id: str, promoter_identity: str, now: datetime):
        assert promoter_identity == "serviceAccount:solvan-memory@example.iam"
        assert now == NOW
        if candidate_id.endswith("2"):
            raise MemoryBankUnavailable("retry later")
        return MemoryPromotionRecord(
            "memp_00000000000000000000000000",
            candidate_id,
            "projects/demo/locations/europe-west1/reasoningEngines/re-1/memories/m-1",
            "revision-1",
            MemoryScope(SCOPE, "incident-investigation", "INTERNAL", "europe-west1"),
            "sha256:fact",
            NOW + timedelta(days=30),
        )


def test_tick_counts_durable_success_and_retryable_defer() -> None:
    result = run_tick(
        candidate_ids=("memc_1", "memc_2"),
        promoter=FakePromoter(),
        promoter_identity="serviceAccount:solvan-memory@example.iam",
        now=NOW,
    )
    assert result.model_dump() == {"examined": 2, "succeeded": 1, "deferred": 1}


def test_memory_tick_contract_rejects_invalid_schema_before_composition() -> None:
    response = TestClient(app).post(
        "/internal/memory/promotions/tick", json={"schema_version": 2, "limit": 20}
    )
    assert response.status_code == 422


def test_engine_id_rejects_cross_project_resource() -> None:
    try:
        _engine_id(
            "projects/other/locations/europe-west1/reasoningEngines/re-1",
            project_id="solvan-demo",
            location="europe-west1",
        )
    except RuntimeError as exc:
        assert "outside the exact deployment scope" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("cross-project Memory Bank resource was accepted")
