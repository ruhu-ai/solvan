"""Cloud Scheduler-triggered 0/25/50-second detection burst."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict

from solvan.application.incidents import CanonicalDetectionEvent
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence import PostgresDetectionStore, PostgresWorkflowStore
from solvan.platform.database import connect_database
from solvan.platform.direct_gcp_detection_client import DirectGcpDetectionClient
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import (
    GoogleRestSession,
    authorized_session,
    authorized_session_from_credentials,
)
from solvan.platform.local_gcp_credentials import development_credentials


class BurstRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    offsets_seconds: tuple[int, ...]
    rule_ids: tuple[str, ...] = ()


class BurstResponse(BaseModel):
    evaluated_rules: int
    inserted_evaluations: int
    emitted_events: int
    completed_offsets: int


class Clock(Protocol):
    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...


class Sleeper(Protocol):
    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class SystemSleeper:
    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True, slots=True)
class BurstStats:
    evaluated_rules: int = 0
    inserted_evaluations: int = 0
    emitted_events: int = 0
    completed_offsets: int = 0

    def add(self, other: BurstStats) -> BurstStats:
        return BurstStats(
            self.evaluated_rules + other.evaluated_rules,
            self.inserted_evaluations + other.inserted_evaluations,
            self.emitted_events + other.emitted_events,
            self.completed_offsets + other.completed_offsets,
        )


class DetectionBurstRunner:
    def __init__(
        self,
        *,
        scope: Scope,
        evidence_bucket: str,
        clock: Clock,
        sleeper: Sleeper,
        rule_ids: tuple[str, ...] = (),
    ):
        self._scope = scope
        self._evidence_bucket = evidence_bucket
        self._clock = clock
        self._sleeper = sleeper
        self._rule_ids = _validate_rule_ids(rule_ids)

    def run(self, offsets_seconds: tuple[int, ...]) -> BurstStats:
        _validate_offsets(offsets_seconds)
        started = self._clock.monotonic()
        result = BurstStats()
        for offset in offsets_seconds:
            remaining = started + offset - self._clock.monotonic()
            if remaining > 0:
                self._sleeper.sleep(remaining)
            result = result.add(self._evaluate_once()).add(BurstStats(completed_offsets=1))
        return result

    def run_once(self) -> BurstStats:
        """Evaluate one current slot; used by the authenticated local scheduler."""

        return self._evaluate_once()

    def _evaluate_once(self) -> BurstStats:
        session = _control_plane_session()
        monitoring = DirectGcpDetectionClient()
        evidence = GcsEvidenceWriter(bucket=self._evidence_bucket, session=session)
        with connect_database() as connection:
            detection_store = PostgresDetectionStore(connection)
            workflow_store = PostgresWorkflowStore(connection)
            rules = detection_store.load_approved_rules(scope=self._scope)
            if self._rule_ids:
                requested = set(self._rule_ids)
                rules = tuple(rule for rule in rules if rule.rule_id in requested)
                found = {rule.rule_id for rule in rules}
                if found != requested:
                    missing = ",".join(sorted(requested - found))
                    raise ValueError(f"requested detection rules are not approved: {missing}")
            connection.commit()
            result = BurstStats()
            for rule in rules:
                # Release fixtures predate connection-bound target detection.
                # They are never evaluated by the connected path: absence of
                # a binding denies instead of selecting a provider default.
                if rule.source_binding is None:
                    continue
                window_end = evaluation_slot(self._clock.now(), rule.evaluation_interval_ms)
                window_ms = rule.query.get("window_ms", 60_000)
                if not isinstance(window_ms, int) or not 1_000 <= window_ms <= 300_000:
                    raise ValueError("approved detection rule has an invalid window_ms")
                window_start = window_end - timedelta(milliseconds=window_ms)
                observation = monitoring.observe(
                    rule, window_start=window_start, window_end=window_end
                )
                event = CanonicalDetectionEvent(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    service_id=rule.service_id,
                    graph_snapshot_id=rule.graph_snapshot_id,
                    incident_class=rule.incident_class,
                    deduplication_dimension=rule.deduplication_dimension,
                    window_start=window_start,
                    window_end=window_end,
                    observed_value=observation.value,
                    severity=rule.severity,
                    action_budget=rule.action_budget,
                    repeated_action_limit=rule.repeated_action_limit,
                )
                receipt_value = {
                    "schema_version": 1,
                    "kind": "SOLVAN_DETECTION_EVALUATION",
                    "scope": self._scope.canonical_dict(),
                    "rule_id": rule.rule_id,
                    "rule_version": rule.version,
                    "signal_kind": rule.signal_kind,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "observed_value": observation.value,
                    "request_ids": list(observation.request_ids),
                    "canonical_event": _event_json(event),
                }
                content = json.dumps(receipt_value, sort_keys=True, separators=(",", ":"))
                content_hash = hashlib.sha256(content.encode()).hexdigest()
                receipt = evidence.put_json(
                    object_name=(
                        f"detections/{self._scope.environment_id}/{rule.rule_id}/"
                        f"{int(window_end.timestamp())}-{content_hash}.json"
                    ),
                    value=receipt_value,
                )
                with connection.transaction():
                    inserted, became_sustained = detection_store.record_evaluation(
                        scope=self._scope,
                        rule=rule,
                        window_start=window_start,
                        window_end=window_end,
                        observed_value=observation.value,
                        query_receipt_ref=receipt.uri,
                        query_receipt_hash=receipt.content_hash,
                    )
                    emitted = 0
                    if inserted and became_sustained:
                        workflow_store.ingest_event(
                            scope=self._scope,
                            source="solvan-detector",
                            source_event_id=(
                                f"{rule.rule_id}:{rule.version}:{window_end.isoformat()}"
                            ),
                            event_type="MonitoringThresholdBreached",
                            payload_ref=receipt.uri,
                            payload_hash=receipt.content_hash,
                        )
                        emitted = 1
                result = result.add(
                    BurstStats(
                        evaluated_rules=1,
                        inserted_evaluations=int(inserted),
                        emitted_events=emitted,
                    )
                )
            return result


def _control_plane_session() -> GoogleRestSession:
    if os.environ.get("SOLVAN_LOCAL_CONNECTED_GCP") == "true":
        service_account = _required("SOLVAN_READER_SERVICE_ACCOUNT")
        return authorized_session_from_credentials(
            development_credentials(service_account=service_account)
        )
    return authorized_session()


def evaluation_slot(now: datetime, interval_ms: int) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("detector clock must be timezone-aware")
    epoch_ms = int(now.timestamp() * 1_000)
    slot_ms = epoch_ms - (epoch_ms % interval_ms)
    return datetime.fromtimestamp(slot_ms / 1_000, tz=UTC)


def _event_json(event: CanonicalDetectionEvent) -> dict[str, object]:
    return {
        "rule_id": event.rule_id,
        "rule_version": event.rule_version,
        "service_id": event.service_id,
        "graph_snapshot_id": event.graph_snapshot_id,
        "incident_class": event.incident_class,
        "deduplication_dimension": event.deduplication_dimension,
        "window_start": event.window_start.isoformat(),
        "window_end": event.window_end.isoformat(),
        "observed_value": event.observed_value,
        "severity": event.severity,
        "action_budget": event.action_budget,
        "repeated_action_limit": event.repeated_action_limit,
    }


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required detector setting {name} is missing")
    return value


def _validate_offsets(offsets: tuple[int, ...]) -> None:
    if offsets != (0, 25, 50):
        raise ValueError("detector burst offsets must be exactly 0, 25, and 50 seconds")


def _validate_rule_ids(rule_ids: tuple[str, ...]) -> tuple[str, ...]:
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("detector rule selection contains duplicates")
    if any(re.fullmatch(r"[a-z][a-z0-9-]{2,63}", item) is None for item in rule_ids):
        raise ValueError("detector rule selection is not canonical")
    return rule_ids


def create_app(*, local_authorize: Callable[[str | None], None] | None = None) -> FastAPI:
    app = FastAPI(title="Solvan Detector", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/detection/burst", response_model=BurstResponse)
    def burst(request: BurstRequest) -> BurstResponse:
        if request.schema_version != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported schema version")
        try:
            _validate_offsets(request.offsets_seconds)
            _validate_rule_ids(request.rule_ids)
        except ValueError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        runner = DetectionBurstRunner(
            scope=Scope(
                _required("SOLVAN_ORGANIZATION_ID"),
                _required("SOLVAN_SCOPE_PROJECT_ID"),
                _required("SOLVAN_ENVIRONMENT_ID"),
            ),
            evidence_bucket=_required("SOLVAN_EVIDENCE_BUCKET"),
            clock=SystemClock(),
            sleeper=SystemSleeper(),
            rule_ids=request.rule_ids,
        )
        stats = runner.run(request.offsets_seconds)
        return BurstResponse(**asdict(stats))

    if local_authorize is not None:

        @app.post("/internal/dev/detection/once", response_model=BurstResponse)
        def local_once(authorization: str | None = Header(default=None)) -> BurstResponse:
            local_authorize(authorization)
            runner = DetectionBurstRunner(
                scope=Scope(
                    _required("SOLVAN_ORGANIZATION_ID"),
                    _required("SOLVAN_SCOPE_PROJECT_ID"),
                    _required("SOLVAN_ENVIRONMENT_ID"),
                ),
                evidence_bucket=_required("SOLVAN_EVIDENCE_BUCKET"),
                clock=SystemClock(),
                sleeper=SystemSleeper(),
            )
            return BurstResponse(**asdict(runner.run_once()))

    return app


app = instrument_fastapi(create_app(), service_name="detector")
