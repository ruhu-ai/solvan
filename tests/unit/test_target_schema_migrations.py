from __future__ import annotations

from pathlib import Path

import yaml

from tools.target_schema_migrations import MIGRATIONS, _transactional_sql

ROOT = Path(__file__).resolve().parents[2]


def test_target_schemas_have_checksum_bound_migrations_in_dependency_order() -> None:
    assert tuple(item.schema_name for item in MIGRATIONS) == (
        "solvan_scale",
        "solvan_onboarding",
        "solvan_onboarding",
        "solvan_onboarding",
        "solvan_onboarding",
        "solvan_liaison",
        "solvan_liaison",
        "solvan_liaison",
        "solvan_liaison",
        "solvan_graph",
        "solvan_quality",
        "solvan_operability",
        "solvan_operability",
        "solvan_operability",
        "solvan_operability",
        "solvan_operability",
        "solvan_operability",
        "solvan_alerts",
        "solvan_alerts",
        "solvan_alerts",
        "solvan_alerts",
        "solvan_alerts",
        "solvan_alerts",
        "solvan_alerts",
        "solvan_relay",
        "solvan_relay",
        "solvan_relay",
        "solvan_relay",
        "solvan_relay",
        "solvan_relay",
        "solvan_relay",
        "solvan_relay",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_delivery",
        "solvan_identity",
        "solvan_identity",
        "solvan_identity",
        "solvan_identity",
        "solvan_conversation",
        "solvan_conversation",
        "solvan_conversation",
    )
    assert tuple(item.version for item in MIGRATIONS) == (
        1,  # scale
        1,
        2,
        3,
        4,  # onboarding
        1,
        2,
        3,
        4,  # liaison
        1,  # graph
        1,  # quality
        1,
        2,
        3,
        4,
        5,
        6,  # operability
        1,
        2,
        3,
        4,
        5,
        6,
        7,  # alerts
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,  # relay
        1,
        2,
        3,
        4,  # delivery
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        1,
        2,
        3,
        4,  # identity
        1,
        2,
        3,  # conversation
    )
    for migration in MIGRATIONS:
        assert migration.source.exists()
        assert migration.checksum.startswith("sha256:")
        assert _transactional_sql(migration.source).strip()


def test_target_migration_sources_are_not_release_schema() -> None:
    assert all("schema.sql" not in migration.source.name for migration in MIGRATIONS)


def test_saas_target_registry_cannot_become_a_competition_release_requirement() -> None:
    registry = yaml.safe_load(
        (ROOT / "specs/artifacts/saas-scale-target-tests.yaml").read_text(encoding="utf-8")
    )
    assert registry["status"] == "target"
    assert registry["release_gate"] is False
    assert registry["governing_spec"] == "specs/19-saas-scale-and-isolation.md"
    release_requirements = (ROOT / "specs/artifacts/requirements-tests.csv").read_text(
        encoding="utf-8"
    )
    assert "SCALE-" not in release_requirements
