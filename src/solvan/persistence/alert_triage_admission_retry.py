"""Retry due Alert admissions without replacing their durable work identity."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol, cast

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.alert_admission import (
    AlertAdmissionInput,
    AlertAdmissionResult,
    CapacityDecision,
    evaluate_alert_admission,
)
from solvan.domain import Scope
from solvan.persistence.alert_triage_scheduling import _fence_failure
from solvan.persistence.alert_triage_scheduling_types import (
    AlertAdmissionCommit,
    AlertSchedulingError,
)
from solvan.persistence.saas_scale import SaaSScaleRepository
from solvan.persistence.saas_scale_capacity import CapacityReservationError


class _AdmissionAppender(Protocol):
    def _append_admission(
        self,
        *,
        cursor: Any,
        scope: Scope,
        episode: dict[str, Any],
        result: AlertAdmissionResult,
        work_id: str | None,
        reservation_id: str | None,
        request_hash: str | None,
        decided_at: datetime,
    ) -> AlertAdmissionCommit: ...


class AlertAdmissionRetryMixin:
    _connection: Connection[Any]

    def retry_pending_admission(
        self,
        *,
        scope: Scope,
        episode_id: str,
        evaluated_at: datetime | None = None,
    ) -> AlertAdmissionCommit:
        """Append the next decision for one due PENDING admission."""

        moment = evaluated_at or datetime.now(UTC)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("Alert admission time must be timezone-aware")
        values = {**scope.canonical_dict(), "episode_id": episode_id, "evaluated_at": moment}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"{scope.digest()}:{episode_id}:alert-admission",),
            )
            cursor.execute(
                """SELECT episode.*,generation.provider_state_projection,
                          event.observed_at,subtype.triage_budget_json,
                          admission.id AS prior_admission_id,admission.work_id,
                          admission.capacity_request_hash,admission.due_at,
                          head.policy_hash AS current_policy_hash,
                          head.head_epoch AS current_head_epoch,
                          head.placement_epoch AS current_head_placement_epoch,
                          lifecycle.availability AS policy_availability,
                          graph.snapshot_id AS current_graph_snapshot_id,
                          graph.snapshot_version AS current_graph_snapshot_version,
                          graph.cell_id AS current_cell_id,
                          graph.placement_epoch AS current_placement_epoch
                     FROM solvan_alerts.alert_episodes episode
                     JOIN solvan_alerts.alert_admission_current current
                       ON (current.organization_id,current.project_id,current.environment_id,
                           current.provider_generation_id)=
                          (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.provider_generation_id)
                     JOIN solvan_alerts.alert_admissions admission
                       ON (admission.organization_id,admission.project_id,
                           admission.environment_id,admission.id)=
                          (current.organization_id,current.project_id,
                           current.environment_id,current.admission_id)
                     JOIN solvan_alerts.alert_provider_generations generation
                       ON (generation.organization_id,generation.project_id,
                           generation.environment_id,generation.id)=
                          (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.provider_generation_id)
                     JOIN solvan_alerts.alert_events event
                       ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                          (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.last_event_id)
                     JOIN solvan_alerts.alert_policy_revisions subtype
                       ON (subtype.organization_id,subtype.project_id,subtype.environment_id,
                           subtype.policy_key,subtype.policy_version,subtype.policy_hash)=
                          (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.policy_key,episode.policy_version,episode.policy_hash)
                     LEFT JOIN solvan_operability.trigger_policy_current_heads head
                       ON (head.organization_id,head.project_id,head.environment_id,
                           head.policy_key,head.policy_version)=
                          (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.policy_key,episode.policy_version) AND head.is_current
                     LEFT JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle
                       ON (lifecycle.organization_id,lifecycle.project_id,
                           lifecycle.environment_id,lifecycle.policy_key,
                           lifecycle.policy_version,lifecycle.policy_hash)=
                          (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.policy_key,
                           episode.policy_version,episode.policy_hash)
                     LEFT JOIN solvan_graph.graph_read_current(
                       %(organization_id)s,%(project_id)s,%(environment_id)s) graph ON true
                    WHERE episode.organization_id=%(organization_id)s
                      AND episode.project_id=%(project_id)s
                      AND episode.environment_id=%(environment_id)s
                      AND episode.id=%(episode_id)s AND admission.decision='PENDING'
                      AND admission.due_at<=%(evaluated_at)s
                    FOR UPDATE OF episode,current""",
                values,
            )
            episode = cursor.fetchone()
            if episode is None:
                raise AlertSchedulingError("ALERT_PENDING_ADMISSION_NOT_DUE")
            result, reservation_id = self._retry_capacity(
                scope=scope, episode=dict(episode), moment=moment
            )
            work_id = str(episode["work_id"]) if result.decision == "PENDING" else None
            request_hash = (
                str(episode["capacity_request_hash"]) if result.decision == "PENDING" else None
            )
            if result.decision == "ADMITTED":
                work_id = str(episode["work_id"])
                request_hash = str(episode["capacity_request_hash"])
            elif result.decision != "PENDING":
                cursor.execute(
                    """UPDATE solvan_scale.tenant_work_registry SET state='TERMINAL'
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND work_kind='AGENT_RUN' AND work_id=%(work_id)s
                          AND state='PENDING'""",
                    {**values, "work_id": episode["work_id"]},
                )
            return cast(_AdmissionAppender, self)._append_admission(
                cursor=cursor,
                scope=scope,
                episode=dict(episode),
                result=result,
                work_id=work_id,
                reservation_id=reservation_id,
                request_hash=request_hash,
                decided_at=moment,
            )

    def _retry_capacity(
        self, *, scope: Scope, episode: dict[str, Any], moment: datetime
    ) -> tuple[AlertAdmissionResult, str | None]:
        budget = dict(episode["triage_budget_json"])
        common = {
            "source_state": (
                "CLOSED" if episode["provider_state_projection"] == "CLOSED" else "OPEN"
            ),
            "observed_at": episode["observed_at"],
            "evaluated_at": moment,
            "maximum_queue_age_ms": int(budget["maximum_queue_age_ms"]),
            "pending_for_target": 0,
            "maximum_pending_per_target": 1,
            "cooldown_until": None,
            "fence_failure_reason": _fence_failure(episode),
        }
        if common["fence_failure_reason"] is not None or common["source_state"] == "CLOSED":
            return evaluate_alert_admission(
                AlertAdmissionInput(
                    **common,
                    capacity_decision=CapacityDecision.RESERVED,
                    capacity_receipt_ref="preflight://capacity",
                )
            ), None
        try:
            reservation = SaaSScaleRepository(self._connection).reserve_capacity(
                scope=scope,
                work_kind="AGENT_RUN",
                work_id=str(episode["work_id"]),
                cell_id=str(episode["cell_id"]),
                placement_epoch=int(episode["placement_epoch"]),
                resource_kind="MODEL_REQUEST",
                units=1,
                idempotency_key=f"alert-triage:{episode['id']}",
                request_hash=str(episode["capacity_request_hash"]),
                ttl_seconds=min(int(budget["maximum_runtime_seconds"]) + 300, 3600),
            )
            return evaluate_alert_admission(
                AlertAdmissionInput(
                    **common,
                    capacity_decision=CapacityDecision.RESERVED,
                    capacity_receipt_ref=reservation.reservation_id,
                )
            ), reservation.reservation_id
        except CapacityReservationError as error:
            return evaluate_alert_admission(
                AlertAdmissionInput(
                    **common,
                    capacity_decision=(
                        CapacityDecision.WAITING
                        if error.reason_code == "CENTRAL_CAPACITY_WAIT"
                        else CapacityDecision.EXHAUSTED
                    ),
                    capacity_retry_at=error.retry_at,
                )
            ), None
