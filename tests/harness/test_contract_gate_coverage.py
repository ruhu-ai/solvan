"""The contract gate must execute every migration the runner would apply.

`scripts/check-contracts` names its target DDL by hand while
`tools/target_schema_migrations.MIGRATIONS` is what runs against a real
database. Nothing tied the two together, so a registered migration could ship
without the one gate that loads schemas into a clean PostgreSQL ever parsing
it — and the reverse, a gate that silently stopped covering a schema.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools import check_contracts
from tools.target_schema_migrations import MIGRATIONS


def test_every_registered_migration_is_loaded_by_the_gate() -> None:
    check_contracts.check_migration_gate_coverage()


def test_a_registered_migration_the_gate_ignores_fails_the_check(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    covered = "\n".join(
        f"psql < specs/artifacts/{migration.source.name}"
        for migration in MIGRATIONS
        if migration.source.name != MIGRATIONS[-1].source.name
    )
    (scripts / "check-contracts").write_text(covered, encoding="utf-8")
    monkeypatch.setattr(check_contracts, "ROOT", tmp_path)
    with pytest.raises(SystemExit) as refusal:
        check_contracts.check_migration_gate_coverage()
    assert MIGRATIONS[-1].source.name in str(refusal.value)
    assert "proves nothing" in str(refusal.value)


def test_canonical_coverage_includes_postgresql_contract_suites() -> None:
    check_script = (check_contracts.ROOT / "scripts" / "check").read_text(encoding="utf-8")
    contract_script = (check_contracts.ROOT / "scripts" / "check-contracts").read_text(
        encoding="utf-8"
    )

    assert "coverage erase" in check_script
    assert "SOLVAN_COLLECT_COVERAGE=1 scripts/check-contracts" in check_script
    assert "--cov-append --cov-report=term-missing" in check_script
    assert "SOLVAN_COLLECT_COVERAGE" in contract_script
    assert "--cov-append --cov-report= --cov-fail-under=0" in contract_script
