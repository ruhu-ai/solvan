from __future__ import annotations

from datetime import UTC, datetime

import pytest

from solvan.domain import Scope
from solvan.persistence.outcome_quality import OutcomeQualityError, OutcomeQualityRepository


class _Connection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, statement: str, params: dict[str, object]) -> None:
        self.calls.append((statement, params))


def _scope() -> Scope:
    return Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )


def test_quality_declaration_rejects_unsafe_window_before_sql() -> None:
    repository = OutcomeQualityRepository(_Connection())  # type: ignore[arg-type]
    with pytest.raises(OutcomeQualityError):
        repository.record_declaration(
            scope=_scope(),
            cell_id="cell-1",
            placement_epoch=1,
            declaration_id="dec-1",
            episode_id="episode-1",
            declaration_kind="VERIFICATION_PASSED",
            producer_principal="producer",
            producer_service_revision="rev-1",
            subject_ref="ver-1",
            declared_at=datetime.now(UTC),
            falsification_window_seconds=10,
        )


def test_quality_derivations_are_function_calls() -> None:
    connection = _Connection()
    repository = OutcomeQualityRepository(connection)  # type: ignore[arg-type]
    repository.build_population(
        scope=_scope(), cell_id="cell-1", placement_epoch=2, population_id="pop-1"
    )
    repository.publish_receipt(
        scope=_scope(),
        cell_id="cell-1",
        placement_epoch=2,
        population_id="pop-1",
        receipt_id="receipt-1",
    )
    repository.derive_competence(
        scope=_scope(),
        cell_id="cell-1",
        placement_epoch=2,
        action_class="PAYMENTS_POOL_RECYCLE",
        quality_receipt_id="receipt-1",
        competence_receipt_id="competence-1",
    )
    assert all("SELECT solvan_quality.quality_" in statement for statement, _ in connection.calls)
