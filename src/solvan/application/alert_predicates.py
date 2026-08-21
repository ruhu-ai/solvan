"""Replayable, model-independent Alert escalation predicates."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from math import isfinite
from typing import Any

from solvan.application.alert_triage import PredicateExpressionV1, PredicateNodeV1

DEMO_PAYMENTS_PREDICATE_KEY = "demo-payments-fault-confirmed@1"
DEMO_PAYMENTS_RECORD_KIND = "DEMO_PAYMENTS_FAULT_CONFIRMATION_V1"
DEMO_PAYMENTS_RULE_REF = "payments-http-5xx-v1@1"


@dataclass(frozen=True, slots=True)
class RegisteredAlertPredicateContext:
    """Frozen application-owned inputs eligible to create one predicate fact."""

    environment_id: str
    provider_generation_id: str
    provider_state: str
    graph_snapshot_id: str
    target_node_key: str
    target_node_version: str
    expression: Mapping[str, Any]
    rule_ref: str
    signal_kind: str
    comparator: str
    threshold: float
    window_ms: int
    calibration_receipt_ref: str
    synthetic: bool


def compile_registered_predicate_provenance(
    context: RegisteredAlertPredicateContext | None,
    *,
    signal_kind: str,
    observed_value: Any,
    window_start: datetime,
    window_end: datetime,
) -> dict[str, Any]:
    """Compile a typed provider observation into the sole registered S1 shape.

    This is intentionally not a generic JSON-to-fact converter. Only a frozen
    Alert run whose approved rule and expression were resolved by the
    persistence boundary can receive workflow-relevant provenance.
    """

    if context is None:
        return {}
    try:
        expression = PredicateExpressionV1.model_validate(context.expression)
    except ValueError:
        return {}
    registered_nodes = tuple(
        node
        for node in expression.nodes
        if node.kind == "APPLICATION_FACT"
        and node.predicate_ref == DEMO_PAYMENTS_PREDICATE_KEY
        and node.record_kind == DEMO_PAYMENTS_RECORD_KIND
    )
    valid_number = (
        isinstance(observed_value, int | float)
        and not isinstance(observed_value, bool)
        and isfinite(float(observed_value))
    )
    if (
        len(registered_nodes) != 1
        or context.provider_state != "OPEN"
        or context.rule_ref != DEMO_PAYMENTS_RULE_REF
        or context.signal_kind != "HTTP_5XX_RATIO"
        or signal_kind != context.signal_kind
        or context.comparator != "GT"
        or not context.synthetic
        or not context.calibration_receipt_ref
        or context.window_ms <= 0
        or not valid_number
        or window_start.tzinfo is None
        or window_end.tzinfo is None
        or window_start >= window_end
        or int((window_end - window_start).total_seconds() * 1000) < context.window_ms
    ):
        return {}
    return {
        "registered_predicate_fact": {
            "schema_version": 1,
            "predicate_key": DEMO_PAYMENTS_PREDICATE_KEY,
            "rule_ref": context.rule_ref,
            "environment_id": context.environment_id,
            "provider_generation_id": context.provider_generation_id,
            "graph_snapshot_id": context.graph_snapshot_id,
            "target_node_key": context.target_node_key,
            "target_node_version": context.target_node_version,
            "synthetic": True,
            "calibration_receipt_ref": context.calibration_receipt_ref,
            "measurement": {
                "observed_error_ratio": float(observed_value),
                "threshold": context.threshold,
                "window_ms": context.window_ms,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
            },
        }
    }


class PredicateVerdict(StrEnum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class PredicateFact:
    """One committed input resolved before evaluation."""

    record_id: str
    record_kind: str
    record_hash: str
    values: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.record_id or not self.record_kind:
            raise ValueError("predicate fact identity is required")
        if not self.record_hash.startswith("sha256:") or len(self.record_hash) != 71:
            raise ValueError("predicate fact hash must be typed")


@dataclass(frozen=True, slots=True)
class PredicateNodeResult:
    node_id: str
    kind: str
    verdict: PredicateVerdict
    reason_code: str
    input_refs: tuple[str, ...]
    input_hash: str


@dataclass(frozen=True, slots=True)
class PredicateEvaluation:
    verdict: PredicateVerdict
    on_inconclusive: str
    node_results: tuple[PredicateNodeResult, ...]


def validated_predicate_fact(
    node: PredicateNodeV1,
    *,
    evidence_record: Mapping[str, Any],
    expected_environment_id: str,
    expected_provider_generation_id: str,
    expected_graph_snapshot_id: str,
    expected_target_node_key: str,
    expected_target_node_version: str,
    allowed_calibration_receipt_refs: tuple[str, ...],
    evaluated_at: datetime,
) -> PredicateFact | None:
    """Compile one registered evidence shape into a predicate fact.

    Evidence provenance is untrusted input.  An application validator must
    establish the meaning of every field before it can influence a workflow
    decision.  Unknown predicate keys fail closed instead of receiving a
    generic JSON-to-authority conversion.
    """

    if node.predicate_ref != DEMO_PAYMENTS_PREDICATE_KEY:
        return None
    if node.record_kind != DEMO_PAYMENTS_RECORD_KIND:
        return None
    provenance = evidence_record.get("provenance_json")
    if not isinstance(provenance, Mapping):
        return None
    material = provenance.get("registered_predicate_fact")
    if not isinstance(material, Mapping):
        return None
    measurement = material.get("measurement")
    if not isinstance(measurement, Mapping):
        return None
    observed_at = _as_datetime(evidence_record.get("observed_at"))
    freshness_expires_at = _as_datetime(evidence_record.get("freshness_expires_at"))
    window_start = _as_datetime(measurement.get("window_start"))
    window_end = _as_datetime(measurement.get("window_end"))
    observed_ratio = measurement.get("observed_error_ratio")
    threshold = measurement.get("threshold")
    window_ms = measurement.get("window_ms")
    calibration_ref = material.get("calibration_receipt_ref")
    identities_match = (
        material.get("schema_version") == 1
        and material.get("predicate_key") == DEMO_PAYMENTS_PREDICATE_KEY
        and material.get("rule_ref") == DEMO_PAYMENTS_RULE_REF
        and material.get("environment_id") == expected_environment_id
        and material.get("provider_generation_id") == expected_provider_generation_id
        and material.get("graph_snapshot_id") == expected_graph_snapshot_id
        and material.get("target_node_key") == expected_target_node_key
        and material.get("target_node_version") == expected_target_node_version
        and material.get("synthetic") is True
        and calibration_ref in allowed_calibration_receipt_refs
    )
    measurement_valid = (
        isinstance(observed_ratio, int | float)
        and not isinstance(observed_ratio, bool)
        and isinstance(threshold, int | float)
        and not isinstance(threshold, bool)
        and isinstance(window_ms, int)
        and not isinstance(window_ms, bool)
        and window_ms > 0
        and observed_at is not None
        and freshness_expires_at is not None
        and window_start is not None
        and window_end is not None
        and window_start <= window_end <= observed_at <= evaluated_at < freshness_expires_at
        and int((window_end - window_start).total_seconds() * 1000) >= window_ms
    )
    if not identities_match or not measurement_valid:
        return None
    record_id = evidence_record.get("id")
    record_hash = evidence_record.get("content_hash")
    if not isinstance(record_id, str) or not isinstance(record_hash, str):
        return None
    assert isinstance(observed_ratio, int | float)
    assert isinstance(threshold, int | float)
    return PredicateFact(
        record_id=record_id,
        record_kind=DEMO_PAYMENTS_RECORD_KIND,
        record_hash=record_hash,
        values={"confirmed": observed_ratio > threshold},
    )


def evaluate_predicate_expression(
    expression: PredicateExpressionV1,
    *,
    source_fields: Mapping[str, Any],
    committed_facts: Mapping[str, PredicateFact],
    evaluated_at: datetime,
) -> PredicateEvaluation:
    """Evaluate an accepted AST from committed facts using closed semantics."""

    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("predicate evaluation time must be timezone-aware")
    nodes = {node.node_id: node for node in expression.nodes}
    results: dict[str, PredicateNodeResult] = {}

    def visit(node_id: str) -> PredicateNodeResult:
        if node_id in results:
            return results[node_id]
        node = nodes[node_id]
        children = tuple(visit(child) for child in node.children)
        result = _evaluate_node(
            node,
            children=children,
            source_fields=source_fields,
            committed_facts=committed_facts,
            evaluated_at=evaluated_at,
        )
        results[node_id] = result
        return result

    root = visit(expression.root_node_id)
    ordered = tuple(results[node.node_id] for node in expression.nodes)
    return PredicateEvaluation(root.verdict, expression.on_inconclusive, ordered)


def _evaluate_node(
    node: PredicateNodeV1,
    *,
    children: tuple[PredicateNodeResult, ...],
    source_fields: Mapping[str, Any],
    committed_facts: Mapping[str, PredicateFact],
    evaluated_at: datetime,
) -> PredicateNodeResult:
    if node.kind == "CONSTANT":
        return _result(
            node,
            PredicateVerdict.TRUE if node.constant else PredicateVerdict.FALSE,
            "CONSTANT_TRUE" if node.constant else "CONSTANT_FALSE",
            (),
            (),
        )
    if node.kind in {"ALL_OF", "ANY_OF", "NOT"}:
        return _branch_result(node, children)

    if node.kind == "SOURCE_FIELD":
        found, observed = _resolve_path(source_fields, node.field_path or "")
        refs: tuple[str, ...] = ()
        hashes: tuple[str, ...] = ()
    else:
        fact = committed_facts.get(node.node_id)
        if fact is None or fact.record_kind != node.record_kind:
            return _result(node, PredicateVerdict.INCONCLUSIVE, "FACT_UNAVAILABLE", (), ())
        found, observed = _resolve_path(fact.values, node.field_path or "")
        refs = (fact.record_id,)
        hashes = (fact.record_hash,)
    if not found:
        return _result(node, PredicateVerdict.INCONCLUSIVE, "FIELD_UNAVAILABLE", refs, hashes)

    if node.kind == "WITHIN_DURATION":
        observed_time = _as_datetime(observed)
        if observed_time is None or observed_time > evaluated_at:
            return _result(node, PredicateVerdict.INCONCLUSIVE, "TIME_VALUE_INVALID", refs, hashes)
        observed = evaluated_at - observed_time <= timedelta(milliseconds=node.duration_ms or 0)

    compared = _compare(observed, node.comparator or "", node.expected_value)
    if compared is None:
        return _result(node, PredicateVerdict.INCONCLUSIVE, "TYPE_MISMATCH", refs, hashes)
    return _result(
        node,
        PredicateVerdict.TRUE if compared else PredicateVerdict.FALSE,
        "COMPARISON_TRUE" if compared else "COMPARISON_FALSE",
        refs,
        hashes,
    )


def _branch_result(
    node: PredicateNodeV1, children: tuple[PredicateNodeResult, ...]
) -> PredicateNodeResult:
    verdicts = tuple(child.verdict for child in children)
    if node.kind == "ALL_OF":
        verdict = (
            PredicateVerdict.FALSE
            if PredicateVerdict.FALSE in verdicts
            else PredicateVerdict.INCONCLUSIVE
            if PredicateVerdict.INCONCLUSIVE in verdicts
            else PredicateVerdict.TRUE
        )
    elif node.kind == "ANY_OF":
        verdict = (
            PredicateVerdict.TRUE
            if PredicateVerdict.TRUE in verdicts
            else PredicateVerdict.INCONCLUSIVE
            if PredicateVerdict.INCONCLUSIVE in verdicts
            else PredicateVerdict.FALSE
        )
    else:
        verdict = {
            PredicateVerdict.TRUE: PredicateVerdict.FALSE,
            PredicateVerdict.FALSE: PredicateVerdict.TRUE,
            PredicateVerdict.INCONCLUSIVE: PredicateVerdict.INCONCLUSIVE,
        }[verdicts[0]]
    refs = tuple(ref for child in children for ref in child.input_refs)
    hashes = tuple(child.input_hash for child in children)
    return _result(node, verdict, f"{node.kind}_{verdict}", refs, hashes)


def _result(
    node: PredicateNodeV1,
    verdict: PredicateVerdict,
    reason_code: str,
    refs: tuple[str, ...],
    hashes: tuple[str, ...],
) -> PredicateNodeResult:
    material = {"node_id": node.node_id, "refs": refs, "hashes": hashes}
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return PredicateNodeResult(
        node.node_id,
        node.kind,
        verdict,
        reason_code,
        refs,
        f"sha256:{digest}",
    )


def _resolve_path(values: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = values
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None and value.utcoffset() is not None else None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
    return None


def _compare(observed: Any, comparator: str, expected: Any) -> bool | None:
    if comparator == "IN":
        return observed in expected if isinstance(expected, tuple) else None
    if comparator in {"LT", "LTE", "GT", "GTE"}:
        if isinstance(observed, bool) or isinstance(expected, bool):
            return None
        if not isinstance(observed, int | float) or not isinstance(expected, int | float):
            return None
        return {
            "LT": observed < expected,
            "LTE": observed <= expected,
            "GT": observed > expected,
            "GTE": observed >= expected,
        }[comparator]
    if comparator == "EQ":
        return observed == expected if type(observed) is type(expected) else None
    if comparator == "NE":
        return observed != expected if type(observed) is type(expected) else None
    return None
