"""Shared persistence contracts for Alert Triage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg.types.json import Jsonb


@dataclass(frozen=True, slots=True)
class SourceRegistration:
    connection_id: str
    connection_epoch: int
    scoping_project_id: str
    topic_name: str
    topic_binding_receipt_ref: str
    subscription_name: str
    push_principal: str
    oidc_audience: str
    source_material_hash: str
    configuration_digest: str
    pubsub_token_minting_receipt_ref: str
    classification: str
    retention_policy_revision: str


@dataclass(frozen=True, slots=True)
class SourceQualificationDelivery:
    source_binding_id: str
    source_binding_epoch: int
    pubsub_message_id: str
    subscription_name: str
    authenticated_push_principal: str
    oidc_audience: str
    envelope_hash: str
    configuration_digest: str


@dataclass(frozen=True, slots=True)
class AlertPolicyDraftCommit:
    policy_key: str
    version: str
    policy_hash: str
    alert_material_hash: str
    created: bool


def jsonb(value: Any) -> Any:
    """Use psycopg's JSON wrapper without exposing it in application contracts."""
    return Jsonb(dict(value))
