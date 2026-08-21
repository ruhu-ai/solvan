"""Durable detector-event handling without model authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import isfinite

from solvan.application.ports import (
    ClaimedEvent,
    IncidentOpenRequest,
    IncidentOpenResult,
    IncidentStore,
)
from solvan.domain import Scope


class DetectionContractError(ValueError):
    """Raised when a detector event is not canonical or policy-bound."""


@dataclass(frozen=True, slots=True)
class CanonicalDetectionEvent:
    rule_id: str
    rule_version: int
    service_id: str
    graph_snapshot_id: str
    incident_class: str
    deduplication_dimension: str
    window_start: datetime
    window_end: datetime
    observed_value: float
    severity: str
    action_budget: int
    repeated_action_limit: int
    state_machine_version: str = "1"

    def __post_init__(self) -> None:
        if self.rule_version < 1:
            raise DetectionContractError("rule version must be positive")
        if (
            self.window_start.tzinfo is None
            or self.window_start.utcoffset() is None
            or self.window_end.tzinfo is None
            or self.window_end.utcoffset() is None
        ):
            raise DetectionContractError("detection window must be timezone-aware")
        if self.window_end < self.window_start:
            raise DetectionContractError("detection window end precedes start")
        if self.severity not in {"SEV1", "SEV2", "SEV3", "SEV4"}:
            raise DetectionContractError("unknown incident severity")
        if self.action_budget < 1 or self.repeated_action_limit < 1:
            raise DetectionContractError("action limits must be positive")
        if not isfinite(self.observed_value):
            raise DetectionContractError("observed value must be finite")
        for label, value in (
            ("rule", self.rule_id),
            ("service", self.service_id),
            ("dimension", self.deduplication_dimension),
        ):
            if not value or ":" in value:
                raise DetectionContractError(f"{label} cannot be empty or contain ':'")

    @property
    def deduplication_key(self) -> str:
        return f"{self.rule_id}:{self.service_id}:{self.deduplication_dimension}"


@dataclass(frozen=True, slots=True)
class CanonicalTriggerIncidentEvent:
    """Frozen, human-approved incident material for one governed trigger firing."""

    policy_key: str
    policy_version: str
    service_id: str
    graph_snapshot_id: str
    incident_class: str
    deduplication_dimension: str
    observed_at: datetime
    severity: str
    action_budget: int
    repeated_action_limit: int
    state_machine_version: str = "1"

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise DetectionContractError("trigger observation time must be timezone-aware")
        if self.severity not in {"SEV1", "SEV2", "SEV3", "SEV4"}:
            raise DetectionContractError("unknown incident severity")
        if self.action_budget < 1 or self.repeated_action_limit < 1:
            raise DetectionContractError("action limits must be positive")
        if self.repeated_action_limit > self.action_budget:
            raise DetectionContractError("repeated action limit exceeds action budget")
        for label, value in (
            ("policy", self.policy_key),
            ("policy version", self.policy_version),
            ("service", self.service_id),
            ("dimension", self.deduplication_dimension),
        ):
            if not value or ":" in value:
                raise DetectionContractError(f"{label} cannot be empty or contain ':'")

    @property
    def deduplication_key(self) -> str:
        return f"{self.policy_key}:{self.service_id}:{self.deduplication_dimension}"


class IncidentCoordinator:
    """Turn one claimed detector event into one durable active incident."""

    def __init__(self, store: IncidentStore) -> None:
        self._store = store

    def process_detection(
        self,
        *,
        scope: Scope,
        claim_owner: str,
        claim: ClaimedEvent,
        event: CanonicalDetectionEvent,
    ) -> IncidentOpenResult:
        if claim.event_type != "MonitoringThresholdBreached":
            raise DetectionContractError(f"unsupported detector event {claim.event_type}")
        with self._store.transaction():
            result = self._store.open_or_attach_incident(
                scope=scope,
                request=IncidentOpenRequest(
                    state_machine_version=event.state_machine_version,
                    severity=event.severity,
                    incident_class=event.incident_class,
                    primary_service_id=event.service_id,
                    production_graph_snapshot_id=event.graph_snapshot_id,
                    detected_at=event.window_end,
                    detection_rule_id=event.rule_id,
                    detection_rule_version=event.rule_version,
                    deduplication_key=event.deduplication_key,
                    action_budget=event.action_budget,
                    repeated_action_limit=event.repeated_action_limit,
                ),
            )
            self._store.complete_inbox(
                scope=scope,
                owner=claim_owner,
                claim=claim,
                result_ref=f"incident:{result.incident_id}",
            )
        return result

    def process_trigger(
        self,
        *,
        scope: Scope,
        claim_owner: str,
        claim: ClaimedEvent,
        event: CanonicalTriggerIncidentEvent,
    ) -> IncidentOpenResult:
        """Open or attach an incident without inventing a detection-rule identity."""

        if claim.event_type != "TRIGGER_FIRING_DUE":
            raise DetectionContractError(f"unsupported trigger event {claim.event_type}")
        with self._store.transaction():
            result = self._store.open_or_attach_incident(
                scope=scope,
                request=IncidentOpenRequest(
                    state_machine_version=event.state_machine_version,
                    severity=event.severity,
                    incident_class=event.incident_class,
                    primary_service_id=event.service_id,
                    production_graph_snapshot_id=event.graph_snapshot_id,
                    detected_at=event.observed_at,
                    detection_rule_id=None,
                    detection_rule_version=None,
                    deduplication_key=event.deduplication_key,
                    action_budget=event.action_budget,
                    repeated_action_limit=event.repeated_action_limit,
                    trigger_policy_key=event.policy_key,
                    trigger_policy_version=event.policy_version,
                ),
            )
            self._store.complete_inbox(
                scope=scope,
                owner=claim_owner,
                claim=claim,
                result_ref=f"incident:{result.incident_id}",
            )
        return result
