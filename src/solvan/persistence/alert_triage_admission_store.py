"""Append-only Alert admission decisions and mutable current projection."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection

from solvan.application.alert_admission import AlertAdmissionResult
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_triage_scheduling_types import (
    AlertAdmissionCommit,
    AlertSchedulingError,
)


class AlertAdmissionStoreMixin:
    _connection: Connection[Any]

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
    ) -> AlertAdmissionCommit:
        values = {
            **scope.canonical_dict(),
            "admission_id": new_identifier("aad"),
            "generation_id": episode["provider_generation_id"],
            "episode_id": episode["id"],
            "episode_generation": episode["episode_generation"],
            "decision": str(result.decision),
            "reason_code": result.reason_code,
            "budget_receipt_ref": result.budget_receipt_ref,
            "cooldown_until": result.cooldown_until,
            "due_at": result.due_at,
            "classification": episode["classification"],
            "retention_policy_revision": episode["retention_policy_revision"],
            "work_kind": "AGENT_RUN" if work_id is not None else None,
            "work_id": work_id,
            "reservation_id": reservation_id,
            "request_hash": request_hash,
            "decided_at": decided_at,
        }
        prior = self._locked_current_admission(cursor=cursor, values=values)
        values["previous_admission_id"] = None if prior is None else prior["admission_id"]
        values["decision_sequence"] = 1 if prior is None else int(prior["decision_sequence"]) + 1
        cursor.execute(
            """INSERT INTO solvan_alerts.alert_admissions
                (organization_id,project_id,environment_id,id,provider_generation_id,
                 episode_id,episode_generation,decision,reason_code,budget_receipt_ref,
                 cooldown_until,due_at,classification,retention_policy_revision,
                 decision_sequence,previous_admission_id,work_kind,work_id,
                 capacity_reservation_id,capacity_request_hash,decided_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                 %(admission_id)s,%(generation_id)s,%(episode_id)s,
                 %(episode_generation)s,%(decision)s,%(reason_code)s,
                 %(budget_receipt_ref)s,%(cooldown_until)s,%(due_at)s,%(classification)s,
                 %(retention_policy_revision)s,%(decision_sequence)s,
                 %(previous_admission_id)s,%(work_kind)s,%(work_id)s,
                 %(reservation_id)s,%(request_hash)s,%(decided_at)s)""",
            values,
        )
        if prior is None:
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_admission_current
                    (organization_id,project_id,environment_id,provider_generation_id,
                     admission_id,decision_sequence)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(generation_id)s,%(admission_id)s,%(decision_sequence)s)""",
                values,
            )
        else:
            cursor.execute(
                """UPDATE solvan_alerts.alert_admission_current
                      SET admission_id=%(admission_id)s,
                          decision_sequence=%(decision_sequence)s,
                          row_version=row_version+1,updated_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND provider_generation_id=%(generation_id)s
                      AND admission_id=%(previous_admission_id)s""",
                values,
            )
            if cursor.rowcount != 1:
                raise AlertSchedulingError("ALERT_ADMISSION_CURRENT_STALE")
        self._project_admission(cursor=cursor, episode=episode, values=values, prior=prior)
        return AlertAdmissionCommit(
            str(values["admission_id"]),
            str(episode["id"]),
            str(result.decision),
            result.reason_code,
            work_id,
            reservation_id,
            result.due_at,
            True,
        )

    @staticmethod
    def _current_admission(*, cursor: Any, values: dict[str, Any]) -> dict[str, Any] | None:
        cursor.execute(
            """SELECT admission.id AS admission_id,admission.episode_id,
                      admission.decision,admission.reason_code,admission.work_id,
                      admission.capacity_reservation_id,admission.capacity_request_hash,
                      admission.decision_sequence,admission.due_at
                 FROM solvan_alerts.alert_episodes episode
                 JOIN solvan_alerts.alert_admission_current current
                   ON (current.organization_id,current.project_id,current.environment_id,
                       current.provider_generation_id)=
                      (episode.organization_id,episode.project_id,episode.environment_id,
                       episode.provider_generation_id)
                 JOIN solvan_alerts.alert_admissions admission
                   ON (admission.organization_id,admission.project_id,
                       admission.environment_id,admission.id)=
                      (current.organization_id,current.project_id,
                       current.environment_id,current.admission_id)
                WHERE episode.organization_id=%(organization_id)s
                  AND episode.project_id=%(project_id)s
                  AND episode.environment_id=%(environment_id)s
                  AND episode.id=%(episode_id)s""",
            values,
        )
        row = cursor.fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _locked_current_admission(*, cursor: Any, values: dict[str, Any]) -> dict[str, Any] | None:
        cursor.execute(
            """SELECT current.admission_id,current.decision_sequence,
                      admission.work_id,admission.decision
                 FROM solvan_alerts.alert_admission_current current
                 JOIN solvan_alerts.alert_admissions admission
                   ON (admission.organization_id,admission.project_id,
                       admission.environment_id,admission.id)=
                      (current.organization_id,current.project_id,
                       current.environment_id,current.admission_id)
                WHERE current.organization_id=%(organization_id)s
                  AND current.project_id=%(project_id)s
                  AND current.environment_id=%(environment_id)s
                  AND current.provider_generation_id=%(generation_id)s
                FOR UPDATE OF current""",
            values,
        )
        row = cursor.fetchone()
        return None if row is None else dict(row)

    def _project_admission(
        self,
        *,
        cursor: Any,
        episode: dict[str, Any],
        values: dict[str, Any],
        prior: dict[str, Any] | None,
    ) -> None:
        if values["work_id"] is not None:
            self._project_work(cursor=cursor, episode=episode, values=values, prior=prior)
            return
        if prior is not None and prior["work_id"] is not None:
            cursor.execute(
                """UPDATE solvan_scale.tenant_dispatch_queue
                      SET state='CANCELLED',claim_token=NULL,lease_expires_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND work_id=%(prior_work_id)s
                      AND state IN ('QUOTA_WAIT','QUEUED')""",
                {**values, "prior_work_id": prior["work_id"]},
            )
        cursor.execute(
            """UPDATE solvan_alerts.alert_episodes
                  SET state=%(state)s,current_disposition=%(decision)s,
                      row_version=row_version+1
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(episode_id)s
                  AND state IN ('OPEN','WAITING','PROVIDER_REPORTED_CLEARED','BLOCKED')""",
            {
                **values,
                "state": "SUPPRESSED" if values["decision"] == "SUPPRESSED" else "BLOCKED",
            },
        )

    def _project_work(
        self,
        *,
        cursor: Any,
        episode: dict[str, Any],
        values: dict[str, Any],
        prior: dict[str, Any] | None,
    ) -> None:
        queue_state = "QUEUED" if values["decision"] == "ADMITTED" else "QUOTA_WAIT"
        if prior is not None and prior["work_id"] == values["work_id"]:
            cursor.execute(
                """UPDATE solvan_scale.tenant_dispatch_queue
                      SET state=%(queue_state)s,available_at=%(available_at)s,
                          claim_token=NULL,lease_expires_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND work_id=%(work_id)s AND state='QUOTA_WAIT'""",
                {
                    **values,
                    "queue_state": queue_state,
                    "available_at": values["due_at"] or values["decided_at"],
                },
            )
        else:
            cursor.execute(
                """UPDATE solvan_scale.tenant_scheduler_lanes
                      SET next_tenant_sequence=next_tenant_sequence+1,updated_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND cell_id=%(cell_id)s AND placement_epoch=%(placement_epoch)s
                  RETURNING next_tenant_sequence-1 AS tenant_sequence""",
                {
                    **values,
                    "cell_id": episode["cell_id"],
                    "placement_epoch": episode["placement_epoch"],
                },
            )
            lane = cursor.fetchone()
            if lane is None:
                raise AlertSchedulingError("ALERT_SCHEDULER_LANE_UNAVAILABLE")
            cursor.execute(
                """INSERT INTO solvan_scale.tenant_dispatch_queue
                    (organization_id,project_id,environment_id,work_id,cell_id,
                     placement_epoch,work_kind,work_class,resource_kind,cost_units,
                     tenant_sequence,state,available_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(work_id)s,%(cell_id)s,%(placement_epoch)s,'AGENT_RUN','BACKGROUND',
                     'MODEL_REQUEST',1,%(tenant_sequence)s,%(queue_state)s,%(available_at)s)""",
                {
                    **values,
                    "cell_id": episode["cell_id"],
                    "placement_epoch": episode["placement_epoch"],
                    "tenant_sequence": lane["tenant_sequence"],
                    "queue_state": queue_state,
                    "available_at": values["due_at"] or values["decided_at"],
                },
            )
        cursor.execute(
            """UPDATE solvan_alerts.alert_episodes
                  SET state='WAITING',current_disposition=NULL,row_version=row_version+1
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(episode_id)s
                  AND state IN ('OPEN','WAITING','TRIAGED','BLOCKED')""",
            values,
        )
