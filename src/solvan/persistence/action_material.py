"""Conversion of locked PostgreSQL action rows to immutable authority material."""

from __future__ import annotations

from typing import Any

from solvan.domain import (
    ActionType,
    AuthorizedActionMaterial,
    RiskClass,
    Scope,
    freeze_json,
)


def material_from_action(action: dict[str, Any], scope: Scope) -> AuthorizedActionMaterial:
    owner_entity_id = action["incident_id"] or action["reliability_case_id"]
    return AuthorizedActionMaterial(
        action_id=action["id"],
        scope=scope,
        owner_entity_id=owner_entity_id,
        workflow_version=action["workflow_version"],
        evidence_version=action["evidence_version"],
        action_type=ActionType(action["action_type"]),
        target_key=action["target_key"],
        expected_target_version=action["expected_target_version"],
        expected_target_epoch=action["expected_target_epoch"],
        payload=freeze_json(dict(action["payload_json"])),
        expected_effect=freeze_json(dict(action["expected_effect_json"])),
        expected_effect_hash=action["expected_effect_hash"],
        risk_class=RiskClass(action["risk_class"]),
        reversible=action["reversible"],
        rollback_plan=freeze_json(dict(action["rollback_plan_json"])),
        policy_version=action["policy_version"],
        verification_profile_id=action["verification_profile_id"],
        verification_profile_version=action["verification_profile_version"],
        expires_at=action["expires_at"],
    )
