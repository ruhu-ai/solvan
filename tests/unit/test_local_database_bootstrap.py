from __future__ import annotations

from pathlib import Path


def test_local_start_bootstraps_authoritative_schema_before_payments_process() -> None:
    root = Path(__file__).resolve().parents[2]
    value = (root / "scripts/start").read_text(encoding="utf-8")
    bootstrap = value.index("tools/bootstrap_local_database.py")
    payments = value.index("uvicorn apps.payments_fixture.main:app")
    assert bootstrap < payments
    assert '--database-url "$PAYMENTS_DATABASE_URL"' in value


def test_local_bootstrap_seeds_the_visible_incident_as_an_authoritative_anchor() -> None:
    root = Path(__file__).resolve().parents[2]
    value = (root / "tools" / "bootstrap_local_database.py").read_text(encoding="utf-8")
    assert "_seed_local_incident_anchor(connection)" in value
    assert "'INC-1042'" in value
    assert "'liaison-local-development'" in value


def test_local_bootstrap_publishes_builtin_guidance_with_a_resolved_commit() -> None:
    root = Path(__file__).resolve().parents[2]
    value = (root / "tools" / "bootstrap_local_database.py").read_text(encoding="utf-8")
    assert "_seed_first_party_guidance(connection)" in value
    assert "from tools.load_first_party_skill_packs import load, release_commit" in value
    assert "commit=release_commit()" in value
    loader = (root / "tools" / "load_first_party_skill_packs.py").read_text(encoding="utf-8")
    assert "_ensure_release_role_bindings" in loader
    assert '"workspace"' not in loader
