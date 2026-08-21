from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from solvan.platform import evaluate_platform_preflight, topology_from_terraform_output
from solvan.platform.preflight import _REQUIRED_APIS, _REQUIRED_PROOFS
from tests.unit.test_platform_preflight import COMMIT, PROJECT, PROJECT_NUMBER, terraform_output
from tools.promote_release import build_plan, validate_preflight


def passing_preflight() -> dict[str, object]:
    topology = topology_from_terraform_output(terraform_output())
    return evaluate_platform_preflight(
        topology=topology,
        release_commit=COMMIT,
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        deployment_id="deploy-20260808",
        observed_at=datetime(2026, 8, 8, tzinfo=UTC),
        billing_enabled=True,
        enabled_apis=_REQUIRED_APIS,
        proof_results={proof: True for proof in _REQUIRED_PROOFS},
        evidence_refs=("gs://solvan-demo-evidence/preflight/proof.json",),
    ).canonical_dict()


def test_promotion_plan_is_non_mutating_by_default(tmp_path: Path) -> None:
    plan = build_plan(
        project_id=PROJECT,
        release_commit=COMMIT,
        deployment_id="deploy-20260808",
        preflight_uri="gs://solvan-demo-evidence/preflight/receipt.json",
        backend_config=tmp_path / "missing.backend",
        base_tfvars=tmp_path / "missing.tfvars",
        generated_tfvars=tmp_path / "missing.json",
        remote="origin",
        apply=False,
    )
    assert plan.mutation_mode == "PLAN_ONLY"


def test_promotion_accepts_only_hash_valid_exact_pass() -> None:
    value = passing_preflight()
    assert (
        validate_preflight(
            value,
            project_id=PROJECT,
            release_commit=COMMIT,
            deployment_id="deploy-20260808",
        )
        == "solvan-demo-evidence"
    )
    value["proof_results"]["gateway_bypass_denied"] = False  # type: ignore[index]
    with pytest.raises(ValueError, match="canonical value or content hash"):
        validate_preflight(
            value,
            project_id=PROJECT,
            release_commit=COMMIT,
            deployment_id="deploy-20260808",
        )


def test_promotion_rejects_tampered_preflight_hash() -> None:
    value = passing_preflight()
    value["enabled_apis"] = []
    with pytest.raises(ValueError, match="content hash"):
        validate_preflight(
            value,
            project_id=PROJECT,
            release_commit=COMMIT,
            deployment_id="deploy-20260808",
        )
