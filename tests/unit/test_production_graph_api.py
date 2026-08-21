from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg.errors import UndefinedTable

from apps.api.production_graph import production_graph_router
from solvan.application.production_graph_review import GraphReviewMode
from solvan.domain import Scope
from solvan.persistence.production_graph import GraphSnapshotReview


class _Transaction:
    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _UnavailableConnection:
    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _Transaction:
        return _Transaction()

    def execute(self, *_args: object, **_kwargs: object):
        raise UndefinedTable("target graph schema is unavailable")


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(
        production_graph_router(
            principal_provider=lambda _token: "user:operator@example.com",
            scope_provider=lambda: Scope(
                "org_00000000000000000000000000",
                "prj_00000000000000000000000000",
                "env_00000000000000000000000000",
            ),
            connect=_UnavailableConnection,
        )
    )
    return TestClient(app)


def _available_client(
    *, principal_provider=lambda _token: "user:operator@example.com"
) -> TestClient:
    app = FastAPI()
    app.include_router(
        production_graph_router(
            principal_provider=principal_provider,
            scope_provider=lambda: Scope(
                "org_00000000000000000000000000",
                "prj_00000000000000000000000000",
                "env_00000000000000000000000000",
            ),
            connect=_UnavailableConnection,
            runtime_configured_provider=lambda: True,
        )
    )
    return TestClient(app)


def _review() -> GraphSnapshotReview:
    return GraphSnapshotReview(
        snapshot_id="snap-1",
        snapshot_version=1,
        status="DRAFT",
        completeness="COMPLETE",
        material_hash="sha256:" + "b" * 64,
        content_hash="sha256:" + "a" * 64,
        autonomy_eligible=False,
        reconciled_at=datetime(2026, 8, 13, tzinfo=UTC),
        cell_id="cell-eu-1",
        placement_epoch=1,
        predecessor_snapshot_id=None,
        predecessor_material_hash=None,
        diff_hash=None,
        governed_change_count=None,
        diff_counts={},
        tier_status=(
            {
                "tier": 1,
                "required_for_complete": True,
                "outcome": "COMPLETE",
                "observation_count": 3,
            },
        ),
        findings=(),
        rejected_content_hashes=frozenset({"sha256:" + "f" * 64}),
    )


def test_graph_review_reports_target_schema_unavailable() -> None:
    response = _client().get(
        "/api/v1/production-graph/snap-1/review-material",
        headers={"X-Solvan-Approval-Token": "verified"},
    )

    assert response.status_code == 503
    assert "target schema" in response.json()["detail"]


def test_automatic_graph_promotion_is_not_a_human_route() -> None:
    client = _client()
    response = client.post(
        "/api/v1/production-graph/snap-1:promote",
        headers={"Idempotency-Key": "decision-1"},
        json={
            "schema_version": 1,
            "decision_id": "decision-1",
            "mode": "AUTO_PROMOTED",
            "expected_content_hash": "sha256:" + "a" * 64,
        },
    )

    assert response.status_code == 403
    assert "coordinator-only" in response.json()["detail"]


def test_reconciliation_refuses_source_configuration_for_another_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON",
        json.dumps(
            {
                "schema_version": 1,
                "scope": {
                    "organization_id": "org_00000000000000000000000009",
                    "project_id": "prj_00000000000000000000000009",
                    "environment_id": "env_00000000000000000000000009",
                },
                "sources": {
                    "asset": {
                        "kind": "ASSET_INVENTORY",
                        "search_scope": "projects/customer-project",
                    }
                },
            }
        ),
    )
    response = _client().post(
        "/api/v1/production-graph/reconciliations",
        headers={"Idempotency-Key": "request-0001"},
        json={"schema_version": 1, "request_id": "request-0001"},
    )

    assert response.status_code == 503
    assert "invalid for this scope" in response.json()["detail"]


def test_reconciliation_requires_exact_idempotency_identity() -> None:
    response = _available_client().post(
        "/api/v1/production-graph/reconciliations",
        headers={"Authorization": "Bearer verified", "Idempotency-Key": "request-0002"},
        json={"schema_version": 1, "request_id": "request-0001"},
    )

    assert response.status_code == 409
    assert "must equal" in response.json()["detail"]


def test_review_material_is_private_and_hides_rejection_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens: list[str | None] = []
    monkeypatch.setattr(
        "apps.api.production_graph.ProductionGraphRepository.review_material",
        lambda _repository, *, scope, snapshot_id: _review(),
    )
    response = _available_client(
        principal_provider=lambda token: tokens.append(token) or "user:operator@example.com"
    ).get(
        "/api/v1/production-graph/snap-1/review-material",
        headers={"X-Solvan-Approval-Token": "verified-human-token"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert "rejected_content_hashes" not in response.json()
    assert response.json()["content_hash"] == "sha256:" + "a" * 64
    assert tokens == ["verified-human-token"]


def test_promotion_refuses_stale_content_before_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "apps.api.production_graph.ProductionGraphRepository.review_material",
        lambda _repository, *, scope, snapshot_id: _review(),
    )
    response = _available_client().post(
        "/api/v1/production-graph/snap-1:promote",
        headers={
            "X-Solvan-Approval-Token": "verified-human-token",
            "Idempotency-Key": "decision-0001",
        },
        json={
            "schema_version": 1,
            "decision_id": "decision-0001",
            "mode": "HUMAN_APPROVED",
            "expected_content_hash": "sha256:" + "c" * 64,
            "reason_ref": "ref_exact-review",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "graph content hash is stale"


def test_human_promotion_binds_exact_review_and_commits_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    promoted: list[dict[str, object]] = []
    monkeypatch.setattr(
        "apps.api.production_graph.ProductionGraphRepository.review_material",
        lambda _repository, *, scope, snapshot_id: _review(),
    )
    monkeypatch.setattr(
        "apps.api.production_graph.ProductionGraphRepository.promotion_record",
        lambda _repository, *, scope, decision_id: None,
    )
    monkeypatch.setattr(
        "apps.api.production_graph.ProductionGraphRepository.promote",
        lambda _repository, **kwargs: promoted.append(kwargs),
    )
    monkeypatch.setattr(
        "apps.api.production_graph.authorize_graph_review",
        lambda **kwargs: SimpleNamespace(
            snapshot_id=kwargs["candidate"].snapshot_id,
            mode=GraphReviewMode.HUMAN_APPROVED,
            principal=kwargs["principal"],
            reason_ref=kwargs["reason_ref"],
        ),
    )
    response = _available_client().post(
        "/api/v1/production-graph/snap-1:promote",
        headers={
            "X-Solvan-Approval-Token": "verified-human-token",
            "Idempotency-Key": "decision-0001",
        },
        json={
            "schema_version": 1,
            "decision_id": "decision-0001",
            "mode": "HUMAN_APPROVED",
            "expected_content_hash": "sha256:" + "a" * 64,
            "reason_ref": "ref_exact-review",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "snapshot_id": "snap-1",
        "decision_id": "decision-0001",
        "mode": "HUMAN_APPROVED",
        "content_hash": "sha256:" + "a" * 64,
        "created": True,
    }
    assert len(promoted) == 1
    assert promoted[0]["snapshot_id"] == "snap-1"
    assert promoted[0]["principal"] == "user:operator@example.com"
