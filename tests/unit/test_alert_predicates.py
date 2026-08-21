from __future__ import annotations

from datetime import UTC, datetime, timedelta

from solvan.application.alert_predicates import (
    DEMO_PAYMENTS_PREDICATE_KEY,
    DEMO_PAYMENTS_RECORD_KIND,
    DEMO_PAYMENTS_RULE_REF,
    PredicateFact,
    PredicateVerdict,
    RegisteredAlertPredicateContext,
    compile_registered_predicate_provenance,
    evaluate_predicate_expression,
    validated_predicate_fact,
)
from solvan.application.alert_triage import PredicateExpressionV1, PredicateNodeV1

NOW = datetime(2026, 8, 14, 12, tzinfo=UTC)


def _expression() -> PredicateExpressionV1:
    return PredicateExpressionV1.model_validate(
        {
            "root_node_id": "both",
            "on_inconclusive": "MANUAL_REVIEW",
            "nodes": [
                {"node_id": "both", "kind": "ALL_OF", "children": ["source", "fact"]},
                {
                    "node_id": "source",
                    "kind": "SOURCE_FIELD",
                    "comparator": "EQ",
                    "field_path": "provider.state",
                    "expected_value": "OPEN",
                },
                {
                    "node_id": "fact",
                    "kind": "EVIDENCE_FACT",
                    "predicate_ref": "http-error-rate@1",
                    "record_kind": "METRIC_WINDOW",
                    "comparator": "GT",
                    "field_path": "error_ratio",
                    "expected_value": 0.02,
                },
            ],
        }
    )


def test_predicate_expression_replays_from_committed_facts() -> None:
    result = evaluate_predicate_expression(
        _expression(),
        source_fields={"provider": {"state": "OPEN"}},
        committed_facts={
            "fact": PredicateFact(
                "evd_01",
                "METRIC_WINDOW",
                "sha256:" + "a" * 64,
                {"error_ratio": 0.184},
            )
        },
        evaluated_at=NOW,
    )
    assert result.verdict is PredicateVerdict.TRUE
    assert result.node_results[-1].node_id == "fact"
    assert result.node_results[-1].input_refs == ("evd_01",)


def test_missing_fact_is_inconclusive_and_never_truthy() -> None:
    result = evaluate_predicate_expression(
        _expression(),
        source_fields={"provider": {"state": "OPEN"}},
        committed_facts={},
        evaluated_at=NOW,
    )
    assert result.verdict is PredicateVerdict.INCONCLUSIVE
    assert result.on_inconclusive == "MANUAL_REVIEW"


def test_any_of_preserves_true_despite_unavailable_sibling() -> None:
    expression = PredicateExpressionV1.model_validate(
        {
            "root_node_id": "either",
            "on_inconclusive": "BLOCKED",
            "nodes": [
                {"node_id": "either", "kind": "ANY_OF", "children": ["yes", "missing"]},
                {"node_id": "yes", "kind": "CONSTANT", "constant": True},
                {
                    "node_id": "missing",
                    "kind": "APPLICATION_FACT",
                    "predicate_ref": "service-impact@1",
                    "record_kind": "SERVICE_IMPACT",
                    "comparator": "EQ",
                    "field_path": "confirmed",
                    "expected_value": True,
                },
            ],
        }
    )
    assert (
        evaluate_predicate_expression(
            expression, source_fields={}, committed_facts={}, evaluated_at=NOW
        ).verdict
        is PredicateVerdict.TRUE
    )


def test_duration_is_bounded_by_evaluation_time() -> None:
    expression = PredicateExpressionV1.model_validate(
        {
            "root_node_id": "fresh",
            "on_inconclusive": "HOLD",
            "nodes": [
                {
                    "node_id": "fresh",
                    "kind": "WITHIN_DURATION",
                    "predicate_ref": "fresh-sample@1",
                    "record_kind": "METRIC_SAMPLE",
                    "comparator": "EQ",
                    "field_path": "observed_at",
                    "expected_value": True,
                    "duration_ms": 60_000,
                }
            ],
        }
    )
    result = evaluate_predicate_expression(
        expression,
        source_fields={},
        committed_facts={
            "fresh": PredicateFact(
                "evd_02",
                "METRIC_SAMPLE",
                "sha256:" + "b" * 64,
                {"observed_at": NOW - timedelta(seconds=30)},
            )
        },
        evaluated_at=NOW,
    )
    assert result.verdict is PredicateVerdict.TRUE


def test_type_mismatch_is_inconclusive() -> None:
    result = evaluate_predicate_expression(
        _expression(),
        source_fields={"provider": {"state": "OPEN"}},
        committed_facts={
            "fact": PredicateFact(
                "evd_03",
                "METRIC_WINDOW",
                "sha256:" + "c" * 64,
                {"error_ratio": "18.4%"},
            )
        },
        evaluated_at=NOW,
    )
    assert result.verdict is PredicateVerdict.INCONCLUSIVE


def _demo_node() -> PredicateNodeV1:
    return PredicateExpressionV1.model_validate(
        {
            "root_node_id": "demo_payments_confirmed",
            "on_inconclusive": "MANUAL_REVIEW",
            "nodes": [
                {
                    "node_id": "demo_payments_confirmed",
                    "kind": "APPLICATION_FACT",
                    "predicate_ref": DEMO_PAYMENTS_PREDICATE_KEY,
                    "record_kind": DEMO_PAYMENTS_RECORD_KIND,
                    "comparator": "EQ",
                    "field_path": "confirmed",
                    "expected_value": True,
                }
            ],
        }
    ).nodes[0]


def _demo_evidence(**material_overrides: object) -> dict[str, object]:
    material: dict[str, object] = {
        "schema_version": 1,
        "predicate_key": DEMO_PAYMENTS_PREDICATE_KEY,
        "rule_ref": DEMO_PAYMENTS_RULE_REF,
        "environment_id": "env_demo",
        "provider_generation_id": "alg_demo",
        "graph_snapshot_id": "pgs_demo",
        "target_node_key": "payments-api",
        "target_node_version": "7",
        "synthetic": True,
        "calibration_receipt_ref": "ref_calibration_demo",
        "measurement": {
            "observed_error_ratio": 0.184,
            "threshold": 0.02,
            "window_ms": 60_000,
            "window_start": NOW - timedelta(seconds=70),
            "window_end": NOW - timedelta(seconds=5),
        },
    }
    material.update(material_overrides)
    return {
        "id": "evd_01K2M7Y8F90H6J1K3M5N7P9QRS",
        "content_hash": "sha256:" + "d" * 64,
        "observed_at": NOW - timedelta(seconds=4),
        "freshness_expires_at": NOW + timedelta(minutes=2),
        "provenance_json": {"registered_predicate_fact": material},
    }


def test_registered_demo_predicate_accepts_only_exact_fresh_committed_shape() -> None:
    fact = validated_predicate_fact(
        _demo_node(),
        evidence_record=_demo_evidence(),
        expected_environment_id="env_demo",
        expected_provider_generation_id="alg_demo",
        expected_graph_snapshot_id="pgs_demo",
        expected_target_node_key="payments-api",
        expected_target_node_version="7",
        allowed_calibration_receipt_refs=("ref_calibration_demo",),
        evaluated_at=NOW,
    )
    assert fact is not None
    assert fact.values == {"confirmed": True}


def test_registered_demo_predicate_rejects_stale_or_changed_authority_inputs() -> None:
    arguments = {
        "node": _demo_node(),
        "expected_environment_id": "env_demo",
        "expected_provider_generation_id": "alg_demo",
        "expected_graph_snapshot_id": "pgs_demo",
        "expected_target_node_key": "payments-api",
        "expected_target_node_version": "7",
        "allowed_calibration_receipt_refs": ("ref_calibration_demo",),
        "evaluated_at": NOW,
    }
    assert (
        validated_predicate_fact(
            evidence_record={**_demo_evidence(), "freshness_expires_at": NOW}, **arguments
        )
        is None
    )
    assert (
        validated_predicate_fact(
            evidence_record=_demo_evidence(environment_id="env_other"), **arguments
        )
        is None
    )
    assert (
        validated_predicate_fact(
            evidence_record=_demo_evidence(calibration_receipt_ref="ref_unapproved"), **arguments
        )
        is None
    )


def _predicate_context(**overrides: object) -> RegisteredAlertPredicateContext:
    values: dict[str, object] = {
        "environment_id": "env_demo",
        "provider_generation_id": "alg_demo",
        "provider_state": "OPEN",
        "graph_snapshot_id": "pgs_demo",
        "target_node_key": "payments-api",
        "target_node_version": "7",
        "expression": {
            "schema_version": 1,
            "root_node_id": "demo_payments_confirmed",
            "on_inconclusive": "MANUAL_REVIEW",
            "nodes": [_demo_node().model_dump(mode="json")],
        },
        "rule_ref": DEMO_PAYMENTS_RULE_REF,
        "signal_kind": "HTTP_5XX_RATIO",
        "comparator": "GT",
        "threshold": 0.02,
        "window_ms": 60_000,
        "calibration_receipt_ref": "ref_calibration_demo",
        "synthetic": True,
    }
    values.update(overrides)
    return RegisteredAlertPredicateContext(**values)  # type: ignore[arg-type]


def test_compiler_creates_only_the_registered_s1_provenance_shape() -> None:
    provenance = compile_registered_predicate_provenance(
        _predicate_context(),
        signal_kind="HTTP_5XX_RATIO",
        observed_value=0.184,
        window_start=NOW - timedelta(seconds=65),
        window_end=NOW,
    )
    material = provenance["registered_predicate_fact"]
    assert material["predicate_key"] == DEMO_PAYMENTS_PREDICATE_KEY
    assert material["rule_ref"] == DEMO_PAYMENTS_RULE_REF
    assert material["measurement"]["threshold"] == 0.02
    assert material["measurement"]["observed_error_ratio"] == 0.184


def test_compiler_refuses_non_synthetic_closed_or_unregistered_reads() -> None:
    inputs = {
        "signal_kind": "HTTP_5XX_RATIO",
        "observed_value": 0.184,
        "window_start": NOW - timedelta(seconds=65),
        "window_end": NOW,
    }
    assert compile_registered_predicate_provenance(None, **inputs) == {}
    assert (
        compile_registered_predicate_provenance(
            _predicate_context(provider_state="CLOSED"), **inputs
        )
        == {}
    )
    assert (
        compile_registered_predicate_provenance(_predicate_context(synthetic=False), **inputs) == {}
    )
    assert (
        compile_registered_predicate_provenance(_predicate_context(window_ms=120_000), **inputs)
        == {}
    )
