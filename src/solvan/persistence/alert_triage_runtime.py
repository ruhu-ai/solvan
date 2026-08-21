"""Agent Runtime projection and terminal settlement for Alert Triage."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application import RuntimeDispatch
from solvan.domain import Scope, StepBudget, new_identifier
from solvan.persistence.alert_liaison import record_alert_disposition_event
from solvan.persistence.alert_triage_scheduling_types import AlertSchedulingError
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore


class AlertTriageRuntimeMixin:
    _connection: Connection[Any]

    def alert_runtime_dispatch(self, *, scope: Scope, agent_run_id: str) -> RuntimeDispatch:
        """Rebuild the exact durable request; process memory is never authority."""

        values = {**scope.canonical_dict(), "agent_run_id": agent_run_id}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT agent.*,triage.id AS triage_run_id,triage.plan_json,
                          triage.plan_hash,triage.claim_epoch,triage.claim_token,
                          triage.target_node_key,triage.graph_snapshot_id,
                          triage.connection_id,triage.connection_epoch,
                          episode.classification,service.id AS target_service_id
                     FROM solvan.agent_runs agent
                     JOIN solvan_alerts.alert_triage_runs triage
                       ON (triage.organization_id,triage.project_id,
                           triage.environment_id,triage.agent_run_id)=
                          (agent.organization_id,agent.project_id,
                           agent.environment_id,agent.id)
                     JOIN solvan_alerts.alert_episodes episode
                       ON (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.id)=
                          (triage.organization_id,triage.project_id,
                           triage.environment_id,triage.episode_id)
                     JOIN solvan.services service
                       ON (service.organization_id,service.project_id,
                           service.environment_id,service.service_key)=
                          (episode.organization_id,episode.project_id,
                           episode.environment_id,episode.target_node_key)
                      AND service.lifecycle='ACTIVE'
                    WHERE agent.organization_id=%(organization_id)s
                      AND agent.project_id=%(project_id)s
                      AND agent.environment_id=%(environment_id)s
                      AND agent.id=%(agent_run_id)s
                      AND agent.alert_episode_id IS NOT NULL
                      AND agent.agent_key='evidence-agent'
                      AND agent.status='CREATED'
                      AND triage.status='CLAIMED'
                      AND triage.claim_expires_at>clock_timestamp()""",
                values,
            )
            row = cursor.fetchone()
        if row is None:
            raise AlertSchedulingError("ALERT_RUNTIME_REQUEST_STALE")
        effective = PostgresToolCatalogStore(self._connection).load_bound_effective_tool_set(
            scope=scope, agent_run_id=agent_run_id
        )
        context = dict(row["input_context_json"])
        context.update(
            {
                "alert_episode_id": str(row["alert_episode_id"]),
                "alert_triage_run_id": str(row["triage_run_id"]),
                "target_node_key": str(row["target_node_key"]),
                "target_service_id": str(row["target_service_id"]),
                "graph_snapshot_id": str(row["graph_snapshot_id"]),
                "connection_id": str(row["connection_id"]),
                "connection_epoch": int(row["connection_epoch"]),
                "classification": str(row["classification"]),
                "accepted_plan": dict(row["plan_json"]),
                "accepted_plan_hash": str(row["plan_hash"]),
                "effective_tool_set": effective.canonical_dict(),
                "effective_tool_set_hash": effective.effective_tool_set_hash,
            }
        )
        return RuntimeDispatch(
            run_id=str(row["id"]),
            invocation_id=str(row["invocation_id"]),
            scope=scope,
            incident_id=None,
            plan_id=str(row["triage_run_id"]),
            plan_version=1,
            step_id=str(row["triage_run_id"]),
            step_key="bounded-alert-triage",
            logical_step_key=str(row["logical_step_key"]),
            agent_key="evidence-agent",
            agent_resource=str(row["agent_resource"]),
            agent_revision=str(row["agent_revision"]),
            scope_ref="scope:alert-target",
            purpose=(
                "Read only the frozen alert target and return bounded evidence references; "
                "the coordinator decides every predicate and disposition."
            ),
            allowed_tool_names=tuple(item.tool_key for item in effective.accepted_tools),
            workflow_version=int(row["workflow_version"]),
            deadline=row["deadline"],
            budget=StepBudget(**dict(row["budget_json"])),
            input_ref=str(row["input_ref"]),
            input_hash=str(row["input_hash"]),
            trace_id=str(row["trace_id"]),
            span_id=str(row["span_id"]),
            context=context,
        )

    def mark_alert_runtime_dispatched(
        self, *, scope: Scope, agent_run_id: str, runtime_operation_name: str
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_alerts.alert_triage_runs triage
                      SET status='DISPATCHED',row_version=row_version+1
                     FROM solvan.agent_runs agent
                    WHERE triage.organization_id=%(organization_id)s
                      AND triage.project_id=%(project_id)s
                      AND triage.environment_id=%(environment_id)s
                      AND triage.agent_run_id=%(agent_run_id)s
                      AND triage.status='CLAIMED'
                      AND triage.claim_expires_at>clock_timestamp()
                      AND agent.organization_id=triage.organization_id
                      AND agent.project_id=triage.project_id
                      AND agent.environment_id=triage.environment_id
                      AND agent.id=triage.agent_run_id
                      AND agent.runtime_operation_name=%(operation)s
                      AND agent.status='DISPATCHED'""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "operation": runtime_operation_name,
                },
            )
            if cursor.rowcount != 1:
                raise AlertSchedulingError("ALERT_RUNTIME_DISPATCH_STALE")

    def alert_completion_fence(self, *, scope: Scope, agent_run_id: str) -> tuple[str, str, int]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,claim_token::text AS claim_token,claim_epoch
                     FROM solvan_alerts.alert_triage_runs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND agent_run_id=%(agent_run_id)s
                      AND status IN ('CLAIMED','DISPATCHED','RUNNING')
                      AND claim_expires_at>clock_timestamp()""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise AlertSchedulingError("ALERT_COMPLETION_FENCE_FAILED:CLAIM_STALE")
        return str(row["id"]), str(row["claim_token"]), int(row["claim_epoch"])

    def fail_alert_triage(
        self,
        *,
        scope: Scope,
        agent_run_id: str,
        error_class: str,
        failed_at: datetime | None = None,
    ) -> None:
        """Fail closed, settle central capacity, and expose one review disposition."""

        moment = failed_at or datetime.now(UTC)
        values = {
            **scope.canonical_dict(),
            "agent_run_id": agent_run_id,
            "error_class": error_class[:128],
            "failed_at": moment,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_alerts.alert_triage_runs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND agent_run_id=%(agent_run_id)s
                      AND status IN ('CLAIMED','DISPATCHED','RUNNING')
                    FOR UPDATE""",
                values,
            )
            run = cursor.fetchone()
            if run is None:
                return
            disposition_id = new_identifier("ads")
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_dispositions
                    (organization_id,project_id,environment_id,id,episode_id,
                     triage_run_id,disposition,reason_code,explanation_template_ref,
                     explanation_variables_json,evidence_refs_json,next_owner,created_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(disposition_id)s,%(episode_id)s,%(triage_run_id)s,'MANUAL_REVIEW',
                     'TRIAGE_RUNTIME_FAILED','alert-disposition:TRIAGE_RUNTIME_FAILED@1',
                     jsonb_build_object('error_class',%(error_class)s),'[]'::jsonb,
                     'service-owner',%(failed_at)s)""",
                {
                    **values,
                    "disposition_id": disposition_id,
                    "episode_id": run["episode_id"],
                    "triage_run_id": run["id"],
                },
            )
            cursor.execute(
                """UPDATE solvan_alerts.alert_triage_runs
                      SET status='FAILED',claim_token=NULL,claim_expires_at=NULL,
                          completed_at=%(failed_at)s,row_version=row_version+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(triage_run_id)s""",
                {**values, "triage_run_id": run["id"]},
            )
            cursor.execute(
                """UPDATE solvan.agent_runs SET status='FAILED',
                          error_class=%(error_class)s,completed_at=%(failed_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(agent_run_id)s
                      AND status IN ('CREATED','DISPATCHED','RUNNING')""",
                values,
            )
            cursor.execute(
                """UPDATE solvan_alerts.alert_episodes
                      SET state='BLOCKED',current_disposition='MANUAL_REVIEW',
                          row_version=row_version+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(episode_id)s""",
                {**values, "episode_id": run["episode_id"]},
            )
            self._settle_failed_alert_work(cursor=cursor, values=values, run=dict(run))
            record_alert_disposition_event(
                self._connection,
                scope=scope,
                episode_id=str(run["episode_id"]),
                disposition_id=disposition_id,
                disposition="MANUAL_REVIEW",
                occurred_at=moment,
            )

    @staticmethod
    def _settle_failed_alert_work(
        *, cursor: Any, values: dict[str, Any], run: dict[str, Any]
    ) -> None:
        cursor.execute(
            """UPDATE solvan_scale.tenant_dispatch_queue
                  SET state='FAILED',claim_token=NULL,lease_expires_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND work_id=%(work_id)s""",
            {**values, "work_id": run["work_id"]},
        )
        cursor.execute(
            """UPDATE solvan_scale.tenant_work_registry SET state='TERMINAL'
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND work_kind='AGENT_RUN' AND work_id=%(work_id)s""",
            {**values, "work_id": run["work_id"]},
        )
        cursor.execute(
            """UPDATE solvan_scale.tenant_capacity_reservations
                  SET status='SETTLED',terminal_at=%(failed_at)s
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND reservation_id=%(reservation_id)s AND status='STARTED'
              RETURNING organization_id,policy_version,resource_kind""",
            {**values, "reservation_id": run["capacity_reservation_id"]},
        )
        reservation = cursor.fetchone()
        if reservation is not None:
            cursor.execute(
                """UPDATE solvan_scale.tenant_quota_counters
                      SET active_reservations=active_reservations-1,
                          counter_epoch=counter_epoch+1
                    WHERE organization_id=%(organization_id)s
                      AND policy_version=%(policy_version)s
                      AND resource_kind=%(resource_kind)s AND active_reservations>0""",
                reservation,
            )
