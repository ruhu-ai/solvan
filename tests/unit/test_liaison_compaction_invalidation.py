from __future__ import annotations

from typing import Any

from apps.api.liaison_maintenance import invalidate_compactions_for_record
from solvan.domain import Scope

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


class _Result:
    def __init__(self, rows: list[tuple[str, str]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[str, str]]:
        return self._rows


class _Connection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute(self, query: str, params: dict[str, Any] | None = None) -> _Result:
        self.calls.append((query, params or {}))
        if "FROM solvan_liaison.liaison_compaction_sources" in query:
            return _Result([("prt_compaction", "lms_compaction")])
        return _Result([])


def test_source_record_change_removes_derived_compaction_and_audits_it() -> None:
    connection = _Connection()

    removed = invalidate_compactions_for_record(
        connection,
        scope=SCOPE,
        record_type="incident",
        record_id="INC-1042",
    )

    assert removed == 1
    assert any(
        "DELETE FROM solvan_liaison.liaison_message_parts" in query for query, _ in connection.calls
    )
    audit = next(
        query for query, _ in connection.calls if "TranscriptCompactionInvalidated" in query
    )
    assert "TranscriptCompactionInvalidated" in audit
