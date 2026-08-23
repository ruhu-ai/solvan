import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_env(offset: int = 0) -> dict[str, str]:
    environment = {**os.environ, "SOLVAN_PORT_OFFSET": str(offset)}
    output = subprocess.run(
        [str(ROOT / "scripts/dev-env")],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(output)  # type: ignore[no-any-return]


def test_dev_environment_is_stable_and_ports_are_unique() -> None:
    first = run_env()
    second = run_env()
    assert first == second
    ports = {
        first["SOLVAN_API_PORT"],
        first["SOLVAN_CONSOLE_PORT"],
        first["SOLVAN_POSTGRES_PORT"],
        first["SOLVAN_PAYMENTS_PORT"],
    }
    assert len(ports) == 4
    assert first["SOLVAN_AUTHORITY"] == "NO_PRODUCTION_AUTHORITY"
    # Bumped whenever the authoritative DDL changes so a worktree never reuses a
    # volume built from an earlier revision. Revision 70 drops the dead third
    # `workspaces.kind` value and the unique index that only guarded that value.
    assert first["SOLVAN_SCHEMA_REVISION"] == "73"
    assert first["COMPOSE_PROJECT_NAME"].endswith("_s73")


def test_port_offset_produces_a_separate_environment() -> None:
    first = run_env()
    shifted = run_env(50)
    assert first["SOLVAN_API_PORT"] != shifted["SOLVAN_API_PORT"]
    assert first["SOLVAN_STATE_DIR"] != shifted["SOLVAN_STATE_DIR"]
    assert first["COMPOSE_PROJECT_NAME"] != shifted["COMPOSE_PROJECT_NAME"]
    assert shifted["SOLVAN_STATE_DIR"].endswith("/schema-73/offset-p50")
    assert shifted["COMPOSE_PROJECT_NAME"].endswith("_s73_offset_p50")
