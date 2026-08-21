from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application import (
    EvidenceMode,
    EvidenceStatus,
    ScenarioReceipt,
    evaluate_minimum_release,
    parse_scenario_receipt,
)

COMMIT = "a" * 40
NOW = datetime(2026, 8, 8, tzinfo=UTC)


def receipt(scenario: str, mode: EvidenceMode) -> ScenarioReceipt:
    return ScenarioReceipt.create(
        scenario_id=scenario,
        mode=mode,
        status=EvidenceStatus.PASS,
        release_commit=COMMIT,
        project_id="solvan-demo",
        region="europe-west1",
        deployment_id="deploy-1",
        started_at=NOW,
        completed_at=NOW + timedelta(minutes=1),
        assertions={"deterministic_oracle": True},
        evidence_refs=(f"gs://evidence/{scenario}.json",),
    )


def test_msr_accepts_only_one_exact_deployment_bound_s1_to_s6_set() -> None:
    receipts = (
        receipt("S1", EvidenceMode.LIVE_GCP),
        *(receipt(f"S{number}", EvidenceMode.SCRIPTED_GCP) for number in range(2, 7)),
    )
    decision = evaluate_minimum_release(
        release_commit=COMMIT,
        project_id="solvan-demo",
        deployment_id="deploy-1",
        preflight_passed=True,
        receipts=receipts,
        open_p0_count=0,
        unsafe_actions=0,
        duplicate_mutations=0,
        isolation_violations=0,
    )
    assert decision.passed
    assert decision.reason_codes == ()


def test_local_or_unbound_evidence_can_never_be_promoted_to_release_pass() -> None:
    with pytest.raises(ValueError, match="S1 can pass"):
        ScenarioReceipt.create(
            scenario_id="S1",
            mode=EvidenceMode.LOCAL_CONTRACT,
            status=EvidenceStatus.PASS,
            release_commit=COMMIT,
            project_id=None,
            region="europe-west1",
            deployment_id=None,
            started_at=NOW,
            completed_at=NOW,
            assertions={"local_test": True},
            evidence_refs=(),
        )


def test_msr_reports_missing_mismatched_and_security_failures() -> None:
    decision = evaluate_minimum_release(
        release_commit=COMMIT,
        project_id="solvan-demo",
        deployment_id="deploy-1",
        preflight_passed=False,
        receipts=(receipt("S1", EvidenceMode.LIVE_GCP),),
        open_p0_count=1,
        unsafe_actions=1,
        duplicate_mutations=0,
        isolation_violations=0,
    )
    assert not decision.passed
    assert "PLATFORM_PREFLIGHT_NOT_PASSED" in decision.reason_codes
    assert "OPEN_P0" in decision.reason_codes
    assert "SECURITY_OR_DUPLICATE_EFFECT_FAILURE" in decision.reason_codes
    assert "MISSING_RECEIPT:S6" in decision.reason_codes


def test_receipt_hash_is_stable_and_rejects_false_pass_assertions() -> None:
    first = receipt("S2", EvidenceMode.SCRIPTED_GCP)
    second = receipt("S2", EvidenceMode.SCRIPTED_GCP)
    assert first.content_hash == second.content_hash
    with pytest.raises(ValueError, match="failed assertion"):
        ScenarioReceipt.create(
            scenario_id="S2",
            mode=EvidenceMode.SCRIPTED_GCP,
            status=EvidenceStatus.PASS,
            release_commit=COMMIT,
            project_id="solvan-demo",
            region="europe-west1",
            deployment_id="deploy-1",
            started_at=NOW,
            completed_at=NOW,
            assertions={"oracle": False},
            evidence_refs=("gs://evidence/S2.json",),
        )


def test_scenario_receipt_parser_round_trips_only_canonical_hash_bound_values() -> None:
    original = receipt("S3", EvidenceMode.SCRIPTED_GCP)
    parsed = parse_scenario_receipt(original.canonical_dict())
    assert parsed == original

    tampered = original.canonical_dict()
    tampered["completed_at"] = (NOW + timedelta(minutes=2)).isoformat()
    with pytest.raises(ValueError, match="content hash"):
        parse_scenario_receipt(tampered)
