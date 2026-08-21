from __future__ import annotations

import json

import pytest

from solvan.domain import Scope, new_identifier
from solvan.platform.guidance_evaluation import GcsGuidanceEvaluationVerifier

SCOPE = Scope(new_identifier("org"), new_identifier("prj"), new_identifier("env"))
DIGEST = "sha256:" + "a" * 64


def receipt() -> dict[str, object]:
    return {
        "guidance_key": "reliability.triage-latency",
        "guidance_version": "1",
        "revision_digest": DIGEST,
        "suite_version": "skills-eval/1",
        "corpus_digest": "sha256:" + "b" * 64,
        "case_set_digest": "sha256:" + "c" * 64,
        "scorer_name": "deterministic-guidance-scorer",
        "scorer_version": "1",
        "model_config_pins": {"model": "gemini-3.1-pro", "temperature": "0"},
        "repetitions": 3,
        "pass_thresholds": {"grounded": 1.0, "safe": 1.0},
        "passed_cases": 12,
        "failed_cases": 0,
        "decision": "PASS",
        "reason_codes": ["ALL_THRESHOLDS_PASSED"],
    }


def verifier(value: dict[str, object]) -> GcsGuidanceEvaluationVerifier:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return GcsGuidanceEvaluationVerifier(
        authorized_session=object(),
        allowed_buckets=frozenset({"skills-evaluations"}),
        media_get=lambda _url, params, _timeout: body
        if params == {"alt": "media", "generation": "17"}
        else b"",
    )


def test_generation_pinned_evaluation_reproduces_complete_binding() -> None:
    result = verifier(receipt()).verify(
        scope=SCOPE,
        guidance_key="reliability.triage-latency",
        version="1",
        expected_digest=DIGEST,
        receipt_ref="gs://skills-evaluations/reliability/1.json#generation=17",
    )
    assert result.object_generation == "17"
    assert result.corpus_digest == "sha256:" + "b" * 64
    assert result.repetitions == 3
    assert result.decision == "PASS"


@pytest.mark.parametrize(
    ("receipt_ref", "guidance_key", "message"),
    [
        (
            "gs://skills-evaluations/reliability/1.json",
            "reliability.triage-latency",
            "generation-pinned",
        ),
        (
            "gs://unregistered/reliability/1.json#generation=17",
            "reliability.triage-latency",
            "not registered",
        ),
        ("gs://skills-evaluations/reliability/1.json#generation=17", "platform.other", "binding"),
    ],
)
def test_evaluation_refuses_unpinned_unregistered_or_changed_material(
    receipt_ref: str, guidance_key: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        verifier(receipt()).verify(
            scope=SCOPE,
            guidance_key=guidance_key,
            version="1",
            expected_digest=DIGEST,
            receipt_ref=receipt_ref,
        )


def test_evaluation_decision_must_match_exact_case_results() -> None:
    changed = {**receipt(), "failed_cases": 1}
    with pytest.raises(ValueError, match="decision disagrees"):
        verifier(changed).verify(
            scope=SCOPE,
            guidance_key="reliability.triage-latency",
            version="1",
            expected_digest=DIGEST,
            receipt_ref="gs://skills-evaluations/reliability/1.json#generation=17",
        )
