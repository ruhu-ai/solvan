from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from solvan.domain import Scope
from solvan.platform.evidence_objects import ObjectReceipt
from solvan.platform.repository_snapshot import parse_repository_snapshot
from tools.workspace_fixture import (
    ALLOWED_FILE_GLOBS,
    REGRESSION_COMMAND_DEFINITION_ID,
    REPOSITORY_BINDING_ID,
    canonical_snapshot_hash,
    repository_policy,
    repository_snapshot,
)


def test_public_fixture_is_content_addressed_and_reproduces_the_leak(tmp_path: Path) -> None:
    commit = "a" * 40
    value = repository_snapshot(release_commit=commit)
    snapshot = parse_repository_snapshot(
        value,
        expected_commit_sha=commit,
        allowed_file_globs=ALLOWED_FILE_GLOBS,
    )
    for item in snapshot.files:
        target = tmp_path / item.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(item.content, encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "-q", "tests.test_payments"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert canonical_snapshot_hash(release_commit=commit).startswith("sha256:")


def test_repository_policy_is_exact_and_defaults_to_regional_adk() -> None:
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    policy = repository_policy(
        receipt=ObjectReceipt(
            uri="gs://runtime/scope/fixtures/payments-leak-v1/repository.json",
            content_hash=f"sha256:{'b' * 64}",
            generation="1",
        ),
        release_commit="a" * 40,
        runtime_bucket="runtime",
        scope=scope,
    )
    assert policy["provider"] == "GEMINI_ADK_AGENT_ENGINE"
    assert policy["repository_binding_id"] == REPOSITORY_BINDING_ID
    assert policy["regression_command_definition_id"] == REGRESSION_COMMAND_DEFINITION_ID
    assert policy["allowed_file_globs"] == list(ALLOWED_FILE_GLOBS)
