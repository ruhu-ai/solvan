"""Validate executable SQL/YAML contracts against each other."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from solvan.domain import TransitionMachine
from tools.check_liaison_manifest_contract import main as check_liaison_manifest_contract

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "specs" / "artifacts"


def load_machine(filename: str) -> TransitionMachine:
    value: Any = yaml.safe_load((ARTIFACTS / filename).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{filename}: expected a mapping")
    return TransitionMachine.from_mapping(value)


def schema_states(schema: str, table: str) -> frozenset[str]:
    table_match = re.search(rf"CREATE TABLE {re.escape(table)} \((.*?)(?=\n\);)", schema, re.DOTALL)
    if table_match is None:
        raise SystemExit(f"schema.sql: missing table {table}")
    state_match = re.search(
        r"state text NOT NULL CHECK \(state IN\s*\((.*?)\)\)",
        table_match.group(1),
        re.DOTALL,
    )
    if state_match is None:
        raise SystemExit(f"schema.sql: missing state constraint for {table}")
    return frozenset(re.findall(r"'([A-Z_]+)'", state_match.group(1)))


def check_migration_gate_coverage() -> None:
    """Every registered target migration must be executed by the contract gate.

    `scripts/check-contracts` loads target DDL as a hand-written list of psql
    heredocs while `tools/target_schema_migrations.MIGRATIONS` is what actually
    runs against a real database. Two lists mean drift: a migration can be
    registered, ship, and never be parsed by the one gate that loads schemas
    into a clean PostgreSQL. Comparing them here makes the omission a check
    failure instead of a surprise at `scripts/start`.
    """

    from tools.target_schema_migrations import MIGRATIONS

    gate = (ROOT / "scripts" / "check-contracts").read_text(encoding="utf-8")
    loaded = set(re.findall(r"specs/artifacts/([A-Za-z0-9._-]+\.sql)", gate))
    registered = {migration.source.name for migration in MIGRATIONS}
    if missing := sorted(registered - loaded):
        raise SystemExit(
            "scripts/check-contracts does not load registered target migration(s) "
            f"{missing}; add them in dependency order or the gate proves nothing about them"
        )


def main() -> None:
    check_liaison_manifest_contract()
    check_migration_gate_coverage()
    schema = (ARTIFACTS / "schema.sql").read_text(encoding="utf-8")
    concurrency = (ARTIFACTS / "concurrency.sql").read_text(encoding="utf-8")
    schema_tests = (ARTIFACTS / "schema-contract-tests.sql").read_text(encoding="utf-8")
    incident = load_machine("incident-transitions.yaml")
    reliability_case = load_machine("reliability-case-transitions.yaml")
    scale_spec = (ROOT / "specs" / "19-saas-scale-and-isolation.md").read_text(encoding="utf-8")
    scale_registry: Any = yaml.safe_load(
        (ARTIFACTS / "saas-scale-target-tests.yaml").read_text(encoding="utf-8")
    )

    comparisons = {
        "incidents": incident.states,
        "reliability_cases": reliability_case.states,
    }
    for table, expected in comparisons.items():
        actual = schema_states(schema, table)
        if actual != expected:
            raise SystemExit(
                f"{table}: schema/transition state drift; "
                f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
            )

    required_tables = {
        "production_graph_snapshots",
        "production_graph_nodes",
        "production_graph_edges",
        "findings",
        "finding_evidence",
        "repair_plans",
        "patch_artifacts",
        "patch_reviews",
        "workspaces",
        "workspace_checkpoints",
        "security_events",
        "audit_events",
        "github_repositories",
        "github_webhook_events",
        "github_pull_requests",
        "github_check_runs",
        "github_operations",
    }
    declared_tables = set(re.findall(r"^CREATE TABLE ([a-z_]+)", schema, re.MULTILINE))
    if missing := sorted(required_tables - declared_tables):
        raise SystemExit(f"schema.sql: missing required tables {missing}")

    required_concurrency_contracts = (
        "Claim or reclaim inbox work",
        "Reliability Cases use the same fencing protocol",
        "Claim or reclaim a due case wake-up",
        "Heartbeat only the live reservation token",
        "Claim unpublished outbox rows with a renewable token",
        "Expiry creates reconciliation work",
    )
    if missing := [item for item in required_concurrency_contracts if item not in concurrency]:
        raise SystemExit(f"concurrency.sql: missing fenced protocols {missing}")
    if "interval '90 seconds'" in concurrency:
        raise SystemExit("concurrency.sql: fixed 90-second reservation TTL is prohibited")
    for aggregate_id in ("incident_id", "reliability_case_id"):
        cas_pattern = re.compile(
            rf"id = :{aggregate_id}.*?workflow_version = :expected_workflow_version"
            rf".*?lease_owner = :lease_owner.*?lease_token = :lease_token"
            rf".*?lease_expires_at >= now\(\)",
            re.DOTALL,
        )
        if cas_pattern.search(concurrency) is None:
            raise SystemExit(f"concurrency.sql: {aggregate_id} CAS is not lease-token fenced")
    for required_oracle in (
        "second originating incident was accepted",
        "unknown detection-rule version was accepted",
        "partial lease tuple was accepted",
    ):
        if required_oracle not in schema_tests:
            raise SystemExit(f"schema-contract-tests.sql: missing oracle {required_oracle}")

    if not isinstance(scale_registry, dict) or scale_registry.get("status") != "target":
        raise SystemExit("saas-scale-target-tests.yaml: expected target registry")
    scale_tests = scale_registry.get("tests")
    if not isinstance(scale_tests, dict):
        raise SystemExit("saas-scale-target-tests.yaml: tests must map")
    named_scale_tests = set(re.findall(r"`((?:SEC|IT|LOAD|DR|CT)-SCALE-[A-Z0-9-]+)`", scale_spec))
    if set(scale_tests) != named_scale_tests:
        raise SystemExit(
            "saas-scale target test drift; "
            f"missing={sorted(named_scale_tests - set(scale_tests))} "
            f"extra={sorted(set(scale_tests) - named_scale_tests)}"
        )
    scale_requirements = set(re.findall(r"\*\*((?:INV|REL)-SCALE-\d+)\*\*", scale_spec))
    for test_id, entry in scale_tests.items():
        if not isinstance(entry, dict) or set(entry) != {"requirements", "implementation"}:
            raise SystemExit(f"{test_id}: expected requirements and implementation")
        bound = entry["requirements"]
        if not isinstance(bound, list) or not bound or not set(bound) <= scale_requirements:
            raise SystemExit(f"{test_id}: invalid requirement mapping {bound!r}")
    mapped_scale_requirements = {
        requirement for entry in scale_tests.values() for requirement in entry["requirements"]
    }
    if mapped_scale_requirements != scale_requirements:
        raise SystemExit(
            "saas-scale requirement traceability is incomplete; "
            f"unmapped={sorted(scale_requirements - mapped_scale_requirements)}"
        )

    print(
        "Contract check passed "
        f"({len(declared_tables)} tables; "
        f"{len(incident.states)} incident states; "
        f"{len(reliability_case.states)} case states)"
    )


if __name__ == "__main__":
    main()
