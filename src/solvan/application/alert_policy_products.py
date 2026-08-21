"""Deterministic product contracts around Alert policies and decisions."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_hashing import canonical_sha256

Mode = Literal["TRIAGE", "POLICY_ESCALATED", "FULL_INCIDENT"]

_MODE_LABELS: dict[Mode, str] = {
    "TRIAGE": "Investigate only",
    "POLICY_ESCALATED": "Investigate, then escalate by rule",
    "FULL_INCIDENT": "Open an Incident by admission rule",
}

_MODE_EXPLANATIONS: dict[Mode, str] = {
    "TRIAGE": (
        "Gather bounded evidence and stop for a person or policy-owned next step; "
        "do not open an Incident automatically."
    ),
    "POLICY_ESCALATED": (
        "Open or attach an Incident only when the named approved escalation rule evaluates true."
    ),
    "FULL_INCIDENT": (
        "Open or attach immediately only when the named approved admission rule evaluates true."
    ),
}


def operator_mode_label(mode: Mode | str) -> str:
    """Return the stable one-to-one operator label for a machine mode."""

    try:
        return _MODE_LABELS[mode]  # type: ignore[index]
    except KeyError as error:
        raise ValueError("UNKNOWN_ALERT_POLICY_MODE") from error


def operator_mode_explanation(mode: Mode | str) -> str:
    try:
        return _MODE_EXPLANATIONS[mode]  # type: ignore[index]
    except KeyError as error:
        raise ValueError("UNKNOWN_ALERT_POLICY_MODE") from error


class AlertPolicySimulationCommandV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    draft_policy_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    draft_version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    sample_provider_generation_id: str = Field(pattern=r"^alg_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    expected_draft_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_sample_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=128)

    @property
    def request_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude={"idempotency_key"}))


class AlertPolicyRecommendationDismissV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    expected_recommendation_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_decision_epoch: int = Field(ge=0)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    idempotency_key: str = Field(min_length=8, max_length=128)

    @property
    def request_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude={"idempotency_key"}))


class AlertPolicyTemplateV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    template_key: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: str
    publisher_ref: str
    policy_skeleton: dict[str, Any]
    calibration_slots: tuple[str, ...]
    example_values: dict[str, Any]
    compatibility: str
    lifecycle: Literal["ACTIVE", "RETIRED"] = "ACTIVE"

    @model_validator(mode="after")
    def calibration_is_explicit(self) -> AlertPolicyTemplateV1:
        if not self.calibration_slots:
            raise ValueError("an Alert policy template requires calibration slots")
        if len(set(self.calibration_slots)) != len(self.calibration_slots):
            raise ValueError("calibration slot names must be unique")
        return self

    @property
    def content_digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


def committed_decision_explanation(
    row: dict[str, Any], predicates: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compose a closed explanation from committed policy/disposition records."""

    mode = str(row["mode"])
    disposition_ref = row.get("disposition_id")
    if disposition_ref is None:
        return {
            "kind": "COMMITTED_DECISION",
            "disposition_ref": None,
            "policy_key": row["policy_key"],
            "policy_version": row["policy_version"],
            "policy_digest": row["policy_hash"],
            "operator_mode_label": operator_mode_label(mode),
            "machine_mode": mode,
            "result": "INCONCLUSIVE",
            "status": "STALE",
            "summary_template_id": None,
            "typed_values": {},
            "expression_digest": None,
            "authorized_node_result_refs": [],
            "authorized_input_refs": [],
            "holding_template_id": "ALERT_DECISION_STALE",
            "incident_link_decision_ref": None,
        }

    disposition = str(row.get("disposition") or "")
    reason = str(row.get("reason_code") or "")
    if mode == "TRIAGE":
        result = "NOT_APPLICABLE"
    elif disposition.startswith("ESCALATED"):
        result = "ESCALATED"
    elif "INCONCLUSIVE" in reason or disposition in {"MANUAL_REVIEW", "BLOCKED"}:
        result = "INCONCLUSIVE"
    else:
        result = "NOT_ESCALATED"
    expression_material = (
        row.get("escalation_expression_json")
        if mode == "POLICY_ESCALATED"
        else row.get("full_incident_admission_expression_json")
        if mode == "FULL_INCIDENT"
        else None
    )
    input_refs = sorted(
        {str(ref) for predicate in predicates for ref in (predicate.get("input_refs_json") or [])}
    )
    return {
        "kind": "COMMITTED_DECISION",
        "disposition_ref": disposition_ref,
        "policy_key": row["policy_key"],
        "policy_version": row["policy_version"],
        "policy_digest": row["policy_hash"],
        "operator_mode_label": operator_mode_label(mode),
        "machine_mode": mode,
        "result": result,
        "status": "ESTABLISHED",
        "summary_template_id": f"ALERT_DECISION_{result}",
        "typed_values": {
            "mode_label": operator_mode_label(mode),
            "mode_explanation": operator_mode_explanation(mode),
            "reason_code": reason,
        },
        "expression_digest": (
            canonical_sha256(expression_material) if expression_material is not None else None
        ),
        "authorized_node_result_refs": [str(item["id"]) for item in predicates],
        "authorized_input_refs": input_refs,
        "holding_template_id": None,
        "incident_link_decision_ref": (
            str(row["disposition_id"]) if row.get("incident_id") is not None else None
        ),
    }


def recommendation_is_open(row: dict[str, Any], *, now: datetime | None = None) -> bool:
    moment = now or datetime.now(UTC)
    return row.get("decision_kind") is None and row["expires_at"] > moment
