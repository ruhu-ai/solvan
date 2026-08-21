from __future__ import annotations

import pytest

from solvan.domain import Scope
from solvan.persistence.target_purge import purge_target_derived_context


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


def test_purge_orders_quality_before_graph_with_one_exact_binding() -> None:
    connection = _Connection()

    purge_target_derived_context(
        connection,  # type: ignore[arg-type]
        scope=_scope(),
        cell_id="cell_eu",
        placement_epoch=7,
        lifecycle_job_id="job_delete_1",
        deletion_epoch=3,
    )

    assert "quality_purge_scope" in connection.calls[0][0]
    assert "graph_purge_scope" in connection.calls[1][0]
    assert connection.calls[0][1] == connection.calls[1][1]
    assert connection.calls[0][1]["placement_epoch"] == 7


@pytest.mark.parametrize("placement_epoch,deletion_epoch", [(0, 1), (1, 0)])
def test_purge_rejects_nonpositive_epochs(placement_epoch: int, deletion_epoch: int) -> None:
    with pytest.raises(ValueError, match="epochs must be positive"):
        purge_target_derived_context(
            _Connection(),  # type: ignore[arg-type]
            scope=_scope(),
            cell_id="cell_eu",
            placement_epoch=placement_epoch,
            lifecycle_job_id="job_delete_1",
            deletion_epoch=deletion_epoch,
        )
