"""Fixed S2/S4 GCP fixture jobs using the real action store and connectors."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import google.auth
import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from psycopg.types.json import Jsonb

from solvan.application import ActionActuator, HumanApprovalOnlyActionGate
from solvan.application.actuator import (
    ActuationResult,
    MutationCall,
    PredictedEffect,
    Reconciliation,
    ReservationConflict,
    TargetObservation,
)
from solvan.connectors.mutation.cloud_run import CloudRunRollbackConnector
from solvan.domain import (
    ActionPolicyError,
    ActionType,
    AuthorizedActionMaterial,
    RiskClass,
    Scope,
    derive_expected_effect,
    freeze_json,
    new_identifier,
)
from solvan.persistence import PostgresActionStore, PostgresWorkflowStore
from solvan.platform.customer_audit import CloudLoggingCustomerAuditSink
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceWriter
from solvan.platform.google_rest import GoogleRestSession, authorized_session
from tools.scenario_jobs import (
    _read_calibration,
    _record_fault_epoch,
    _required,
    _restore_known_good_epoch,
    _shift_revision,
    _shift_to_fault,
)
from tools.scripted_scenario_contracts import validate_scenario_run_id
from tools.seed_demo import GRAPH_ID, PROFILE_ID, SERVICE_ID, CalibrationReceipt


@dataclass(frozen=True, slots=True)
class PreparedActions:
    incident_ids: tuple[str, ...]
    action_ids: tuple[str, ...]
    target_key: str
    expected_epoch: int
    expected_revision: str


class GoogleAccessTokenProvider:
    def token(self, *, scopes: tuple[str, ...]) -> str:
        credentials, _project = google.auth.default(scopes=list(scopes))
        credentials.refresh(GoogleAuthRequest())  # type: ignore[no-untyped-call]
        if not credentials.token:
            raise RuntimeError("Google credentials returned no access token")
        return cast(str, credentials.token)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class PostReservationBarrier:
    """Pause the first actuator exactly after reservation and before observation."""

    def __init__(self, inner: CloudRunRollbackConnector) -> None:
        self._inner = inner
        self.reached = threading.Event()
        self.release = threading.Event()

    def observe(self, material: AuthorizedActionMaterial) -> TargetObservation:
        self.reached.set()
        if not self.release.wait(timeout=60):
            raise RuntimeError("scenario post-reservation barrier timed out")
        return self._inner.observe(material)

    def mutate(self, material: AuthorizedActionMaterial, *, idempotency_key: str) -> MutationCall:
        return self._inner.mutate(material, idempotency_key=idempotency_key)

    def dry_run(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> PredictedEffect:
        return self._inner.dry_run(material, before_state=before_state)

    def reconcile(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> Reconciliation:
        return self._inner.reconcile(material, idempotency_key=idempotency_key)


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _digest(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _allocate_display(cursor: Any, *, scope: Scope, entity_type: str) -> str:
    cursor.execute(
        """INSERT INTO solvan.display_sequences
          (organization_id, project_id, environment_id, entity_type, next_value)
          VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
            %(entity_type)s, 2)
          ON CONFLICT (organization_id, project_id, environment_id, entity_type)
          DO UPDATE SET next_value = solvan.display_sequences.next_value + 1
          RETURNING next_value - 1""",
        {**scope.canonical_dict(), "entity_type": entity_type},
    )
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("scenario display allocation failed")
    return f"{entity_type}-{int(row[0]):04d}"


def _prepare_rollback_actions(
    *,
    scenario_id: str,
    run_id: str,
    receipt: CalibrationReceipt,
    expected_revision: str,
    count: int,
) -> PreparedActions:
    if scenario_id not in {"S2", "S4"} or count not in {1, 2}:
        raise ValueError("unsupported scripted action fixture")
    scope = _scope()
    service_name = (
        f"projects/{receipt.project_id}/locations/{receipt.region}/services/"
        f"{receipt.payments_service_name}"
    )
    target_key = (
        f"{scope.organization_id}/{scope.project_id}/{scope.environment_id}/"
        "cloud-run/payments-api/deployment"
    )
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=15)
    incident_ids: list[str] = []
    action_ids: list[str] = []
    with connect_database() as connection, connection.transaction(), connection.cursor() as cursor:
        target = cursor.execute(
            """SELECT epoch, last_observed_version FROM solvan.target_epochs
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND target_key = %(target_key)s FOR UPDATE""",
            {**scope.canonical_dict(), "target_key": target_key},
        ).fetchone()
        if target is None or str(target[1]) != expected_revision:
            raise RuntimeError("scenario target epoch does not match Cloud Run fixture state")
        expected_epoch = int(target[0])
        cursor.execute(
            """INSERT INTO solvan.actor_role_bindings
              (organization_id, project_id, environment_id, principal, role, granted_by,
               expires_at)
              VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                'user:scenario-approver@solvan.invalid', 'APPROVER',
                'scenario-harness', %(expires_at)s)
              ON CONFLICT (organization_id, project_id, environment_id, principal, role)
              DO UPDATE SET expires_at = EXCLUDED.expires_at""",
            {**scope.canonical_dict(), "expires_at": expires_at},
        )
        for index in range(count):
            incident_id = new_identifier("inc")
            action_id = new_identifier("act")
            policy_id = new_identifier("pol")
            incident_ids.append(incident_id)
            action_ids.append(action_id)
            cursor.execute(
                """INSERT INTO solvan.incidents
                  (organization_id, project_id, environment_id, id, display_id,
                   state_machine_version, state, severity, incident_class,
                   primary_service_id, production_graph_snapshot_id, detected_at,
                   detection_rule_id, detection_rule_version, deduplication_key,
                   action_budget, repeated_action_limit)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(incident_id)s, %(display_id)s, '1', 'MITIGATING', 'SEV2',
                    'connection_exhaustion', %(service_id)s, %(graph_id)s, %(now)s,
                    %(rule_id)s, 1, %(deduplication_key)s, 2, 1)""",
                {
                    **scope.canonical_dict(),
                    "incident_id": incident_id,
                    "display_id": _allocate_display(cursor, scope=scope, entity_type="INC"),
                    "service_id": SERVICE_ID,
                    "graph_id": GRAPH_ID,
                    "now": now,
                    "rule_id": (
                        "payments-http-5xx-v1" if index == 0 else "payments-p95-latency-v1"
                    ),
                    "deduplication_key": f"scenario:{scenario_id.lower()}:{run_id}:{index}",
                },
            )
            policy_version = "scenario-scripted-rollback-v1"
            cursor.execute(
                """INSERT INTO solvan.policy_decisions
                  (organization_id, project_id, environment_id, id, policy_kind,
                   policy_version, input_hash, decision, reason_code)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(policy_id)s, 'ACTION', %(policy_version)s, %(input_hash)s,
                    'REQUIRE_APPROVAL', 'SCRIPTED_GCP_TARGET_RACE')""",
                {
                    **scope.canonical_dict(),
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "input_hash": _digest(
                        {"scenario_id": scenario_id, "run_id": run_id, "index": index}
                    ),
                },
            )
            payload = {
                "service_name": service_name,
                "known_good_revision": receipt.known_good_revision,
                "percent": 100,
            }
            rollback_plan = {
                "restore_revision": expected_revision,
                "requires_separate_approval": True,
            }
            expected_effect = derive_expected_effect(
                action_type=ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK,
                target_key=target_key,
                expected_target_version=expected_revision,
                payload=freeze_json(payload),
            )
            material = AuthorizedActionMaterial(
                action_id=action_id,
                scope=scope,
                owner_entity_id=incident_id,
                workflow_version=1,
                evidence_version=0,
                action_type=ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK,
                target_key=target_key,
                expected_target_version=expected_revision,
                expected_target_epoch=expected_epoch,
                payload=freeze_json(payload),
                expected_effect=expected_effect.descriptor,
                expected_effect_hash=expected_effect.content_hash,
                risk_class=RiskClass.HIGH,
                reversible=True,
                rollback_plan=freeze_json(rollback_plan),
                policy_version=policy_version,
                verification_profile_id=PROFILE_ID,
                verification_profile_version=1,
                expires_at=expires_at,
            )
            cursor.execute(
                """INSERT INTO solvan.actions
                  (organization_id, project_id, environment_id, id, display_id,
                   incident_id, workflow_version, evidence_version, action_type,
                   normalized_signature, target_key, expected_target_version,
                   expected_target_epoch, payload_json, payload_digest,
                   expected_effect_json, expected_effect_hash, risk_class,
                   reversible, rollback_plan_json, verification_profile_id,
                   verification_profile_version, policy_decision_id,
                   proposer_principal, requires_approval, status, idempotency_key,
                   expires_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(action_id)s, %(display_id)s, %(incident_id)s, 1, 0,
                    'CLOUD_RUN_TRAFFIC_ROLLBACK', %(signature)s, %(target_key)s,
                    %(expected_revision)s, %(expected_epoch)s, %(payload)s,
                    %(payload_digest)s, %(expected_effect)s,
                    %(expected_effect_hash)s, 'HIGH', true, %(rollback_plan)s,
                    %(profile_id)s, 1, %(policy_id)s, 'scenario-harness', true,
                    'AUTHORIZED', %(idempotency_key)s, %(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "action_id": action_id,
                    "display_id": _allocate_display(cursor, scope=scope, entity_type="ACT"),
                    "incident_id": incident_id,
                    "signature": _digest(
                        {"action_type": "CLOUD_RUN_TRAFFIC_ROLLBACK", "payload": payload}
                    ),
                    "target_key": target_key,
                    "expected_revision": expected_revision,
                    "expected_epoch": expected_epoch,
                    "payload": Jsonb(payload),
                    "payload_digest": _digest(payload),
                    "expected_effect": Jsonb(expected_effect.descriptor_object()),
                    "expected_effect_hash": expected_effect.content_hash,
                    "rollback_plan": Jsonb(rollback_plan),
                    "profile_id": PROFILE_ID,
                    "policy_id": policy_id,
                    "idempotency_key": f"scenario:{scenario_id.lower()}:{run_id}:{index}",
                    "expires_at": expires_at,
                },
            )
            cursor.execute(
                """INSERT INTO solvan.approvals
                  (organization_id, project_id, environment_id, id, action_id,
                   sequence_no, action_digest, target_key, expected_target_version,
                   expected_target_epoch, evidence_version, policy_version,
                   approver_principal, decision, reason, decision_request_id,
                   decided_at, expires_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(approval_id)s, %(action_id)s, 1, %(action_digest)s,
                    %(target_key)s, %(expected_revision)s, %(expected_epoch)s, 0,
                    %(policy_version)s, 'user:scenario-approver@solvan.invalid',
                    'APPROVE', 'Fixed S2/S4 scripted-GCP fixture approval',
                    %(request_id)s, %(now)s, %(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "approval_id": new_identifier("apr"),
                    "action_id": action_id,
                    "action_digest": material.approval_digest(),
                    "target_key": target_key,
                    "expected_revision": expected_revision,
                    "expected_epoch": expected_epoch,
                    "policy_version": policy_version,
                    "request_id": f"scenario:{scenario_id.lower()}:{run_id}:approval:{index}",
                    "now": now,
                    "expires_at": expires_at,
                },
            )
        if scenario_id == "S2":
            store = PostgresWorkflowStore(connection)
            event = {
                "scope": scope.canonical_dict(),
                "run_id": run_id,
                "fixture": "duplicate-source-event",
            }
            event_hash = _digest(event)
            for _attempt in range(2):
                store.ingest_event(
                    scope=scope,
                    source="scenario-harness",
                    source_event_id=f"scenario:s2:{run_id}:duplicate",
                    event_type="MonitoringThresholdBreached",
                    payload_ref=f"gcs-fixture://scenario/s2/{run_id}/duplicate",
                    payload_hash=event_hash,
                )
    return PreparedActions(
        tuple(incident_ids),
        tuple(action_ids),
        target_key,
        expected_epoch,
        expected_revision,
    )


def _connector(client: httpx.Client) -> CloudRunRollbackConnector:
    return CloudRunRollbackConnector(token_provider=GoogleAccessTokenProvider(), client=client)


def _execute(action_id: str, connector: Any) -> ActuationResult:
    with connect_database() as connection, httpx.Client(timeout=30.0) as audit_client:
        access_tokens = GoogleAccessTokenProvider()
        return ActionActuator(
            store=PostgresActionStore(connection),
            connector=connector,
            customer_audit=CloudLoggingCustomerAuditSink(
                token_provider=access_tokens,
                client=audit_client,
            ),
            clock=SystemClock(),
            actuator_id=_required("SOLVAN_ACTUATOR_ID"),
            actor_identity="spiffe://solvan/scenario-injector",
            reservation_ttl_ms=180_000,
            pre_mutation_gate=HumanApprovalOnlyActionGate(),
        ).execute(
            scope=_scope(),
            action_id=action_id,
            trace_id=hashlib.sha256(action_id.encode()).hexdigest()[:32],
        )


def _write_receipt(*, scenario_id: str, run_id: str, value: dict[str, Any]) -> str:
    document = {
        "schema_version": 1,
        "kind": f"SOLVAN_{scenario_id}_SCRIPTED_FIXTURE",
        "project_id": _required("SOLVAN_GCP_PROJECT"),
        "release_commit": _required("SOLVAN_RELEASE_COMMIT"),
        "deployment_id": _required("SOLVAN_DEPLOYMENT_ID"),
        "scenario_run_id": run_id,
        "injector_identity": _required("SOLVAN_INJECTOR_IDENTITY"),
        "completed_at": datetime.now(UTC).isoformat(),
        "agent_visible": False,
        **value,
    }
    written = GcsEvidenceWriter(
        bucket=_required("SOLVAN_EVIDENCE_BUCKET"), session=authorized_session()
    ).put_json(object_name=_required("SOLVAN_SCENARIO_OBJECT_NAME"), value=document)
    return written.uri


def _restore_fixture(session: GoogleRestSession, receipt: CalibrationReceipt) -> None:
    _shift_revision(session, receipt, target_revision=receipt.known_good_revision)
    _restore_known_good_epoch(receipt)


def inject_s2() -> bool:
    run_id = validate_scenario_run_id(_required("SOLVAN_SCENARIO_RUN_ID"))
    session = authorized_session()
    receipt = _read_calibration(session)
    try:
        _shift_to_fault(session, receipt)
        _record_fault_epoch(receipt)
        prepared = _prepare_rollback_actions(
            scenario_id="S2",
            run_id=run_id,
            receipt=receipt,
            expected_revision=receipt.fault_revision,
            count=2,
        )
    except Exception:
        _restore_fixture(session, receipt)
        raise
    first_result: list[ActuationResult] = []
    first_error: list[Exception] = []
    with httpx.Client(timeout=httpx.Timeout(10, read=120)) as first_client:
        barrier = PostReservationBarrier(_connector(first_client))

        def first_execution() -> None:
            try:
                first_result.append(_execute(prepared.action_ids[0], barrier))
            except Exception as error:
                first_error.append(error)

        thread = threading.Thread(target=first_execution, daemon=True)
        thread.start()
        if not barrier.reached.wait(timeout=30):
            barrier.release.set()
            thread.join(timeout=10)
            _restore_fixture(session, receipt)
            raise RuntimeError("S2 first actuator never reached the reservation barrier")
        loser_error: Exception | None = None
        with httpx.Client(timeout=httpx.Timeout(10, read=120)) as second_client:
            try:
                _execute(prepared.action_ids[1], _connector(second_client))
            except Exception as error:
                loser_error = error
        barrier.release.set()
        thread.join(timeout=180)
    try:
        if thread.is_alive():
            raise RuntimeError("S2 winning actuator did not complete")
        if first_error or len(first_result) != 1:
            cause = first_error[0] if first_error else None
            raise RuntimeError("S2 winning actuator failed") from cause
        if not isinstance(loser_error, ReservationConflict):
            raise RuntimeError("S2 losing actuator was not fenced by target reservation")
        uri = _write_receipt(
            scenario_id="S2",
            run_id=run_id,
            value={
                "action_ids": list(prepared.action_ids),
                "incident_ids": list(prepared.incident_ids),
                "winner_result": first_result[0].result.value,
                "loser_error_class": type(loser_error).__name__,
                "barrier_reached": True,
            },
        )
        print(f"S2_FIXTURE_WRITTEN:{uri}")
        return True
    finally:
        _restore_fixture(session, receipt)


def inject_s4() -> bool:
    run_id = validate_scenario_run_id(_required("SOLVAN_SCENARIO_RUN_ID"))
    session = authorized_session()
    receipt = _read_calibration(session)
    _restore_fixture(session, receipt)
    prepared = _prepare_rollback_actions(
        scenario_id="S4",
        run_id=run_id,
        receipt=receipt,
        expected_revision=receipt.known_good_revision,
        count=1,
    )
    execution_error: list[Exception] = []
    with httpx.Client(timeout=httpx.Timeout(10, read=120)) as client:
        barrier = PostReservationBarrier(_connector(client))

        def execution() -> None:
            try:
                _execute(prepared.action_ids[0], barrier)
            except Exception as error:
                execution_error.append(error)

        thread = threading.Thread(target=execution, daemon=True)
        thread.start()
        if not barrier.reached.wait(timeout=30):
            barrier.release.set()
            thread.join(timeout=10)
            _restore_fixture(session, receipt)
            raise RuntimeError("S4 actuator never reached the reservation barrier")
        _shift_revision(session, receipt, target_revision=receipt.fault_revision)
        barrier.release.set()
        thread.join(timeout=120)
    try:
        if thread.is_alive():
            raise RuntimeError("S4 actuator did not complete")
        if len(execution_error) != 1 or not isinstance(execution_error[0], ActionPolicyError):
            raise RuntimeError("S4 stale target did not fail closed before mutation")
        uri = _write_receipt(
            scenario_id="S4",
            run_id=run_id,
            value={
                "action_ids": list(prepared.action_ids),
                "incident_ids": list(prepared.incident_ids),
                "execution_error_class": type(execution_error[0]).__name__,
                "barrier_reached": True,
            },
        )
        print(f"S4_FIXTURE_WRITTEN:{uri}")
        return True
    finally:
        _restore_fixture(session, receipt)
