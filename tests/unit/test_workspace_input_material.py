"""Specification 12 §8.1: every workspace input names its own true source."""

from __future__ import annotations

import hashlib

import pytest

from solvan.application import RepairPlanRecord
from solvan.persistence.runtime_reservations import workspace_input_material


def _digest(content: str) -> str:
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


def _plan() -> RepairPlanRecord:
    return RepairPlanRecord(
        repair_plan_id="rep_01J0000000000000000000000A",
        reliability_case_id="rlc_01J0000000000000000000000B",
        plan_version=1,
        repository_node_id="node-1",
        repository_snapshot_uri="gs://runtime/snapshots/checkout.json",
        repository_snapshot_hash=f"sha256:{'1' * 64}",
        base_commit_sha="a" * 40,
        reproduction_command="pytest tests/test_checkout.py",
        allowed_file_globs=("src/**",),
        test_command="pytest",
        artifact_output_uri="gs://runtime/repairs/",
        confirmed_root_cause_id="cau_01J0000000000000000000000C",
        evidence_refs=(f"sha256:{'2' * 64}",),
        provider="ANTIGRAVITY_SDK_CLOUD_RUN",
        content_hash=f"sha256:{'3' * 64}",
        created=True,
    )


def test_guidance_states_its_own_object_and_provenance() -> None:
    """A guidance revision does not come from the repository snapshot.

    Inheriting the snapshot's object reference and provenance would make the
    manifest say a reviewer can read the guidance bytes somewhere they cannot,
    about material the workspace was actually handed.
    """

    plan = _plan()
    guidance_ref = "gs://guidance/checkout-drain/3.json"
    guidance_provenance = f"sha256:{'4' * 64}"
    _, artifacts = workspace_input_material(
        plan=plan,
        repository_files=[
            {"path": "src/a.py", "content": "x=1\n", "content_hash": _digest("x=1\n")}
        ],
        guidance_files=[
            {
                "path": "guidance/checkout-drain.md",
                "content": "Drain the pool first.\n",
                "content_hash": _digest("Drain the pool first.\n"),
                "object_ref": guidance_ref,
                "provenance_ref": guidance_provenance,
            }
        ],
        repository_provenance=(plan.repository_snapshot_hash,),
    )

    repository, guidance = artifacts
    assert repository.object_ref.startswith(plan.repository_snapshot_uri)
    assert repository.provenance_refs == (plan.repository_snapshot_hash,)
    assert guidance.object_ref == guidance_ref
    assert guidance.provenance_refs == (guidance_provenance,)
    assert plan.repository_snapshot_hash not in guidance.provenance_refs


def test_guidance_that_cannot_state_its_source_is_refused() -> None:
    """The shape carries the rule, so a caller cannot omit provenance quietly."""

    content = "Drain the pool first.\n"
    with pytest.raises(ValueError, match="unsupported shape"):
        workspace_input_material(
            plan=_plan(),
            repository_files=[],
            guidance_files=[
                {
                    "path": "guidance/checkout-drain.md",
                    "content": content,
                    "content_hash": _digest(content),
                }
            ],
            repository_provenance=(f"sha256:{'1' * 64}",),
        )


def test_material_whose_bytes_do_not_match_its_digest_is_refused() -> None:
    with pytest.raises(ValueError, match="does not match its content"):
        workspace_input_material(
            plan=_plan(),
            repository_files=[
                {"path": "src/a.py", "content": "x=1\n", "content_hash": _digest("x=2\n")}
            ],
            guidance_files=None,
            repository_provenance=(f"sha256:{'1' * 64}",),
        )
