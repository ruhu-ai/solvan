"""Durable Alert admission and fenced shared-scheduler claims."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.alert_admission import (
    AlertAdmissionInput,
    CapacityDecision,
    evaluate_alert_admission,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_triage_scheduling_types import (
    AlertAdmissionCommit,
    AlertAdmissionWriter,
    AlertSchedulingError,
    AlertTriageClaim,
)
from solvan.persistence.saas_scale import SaaSScaleRepository
from solvan.persistence.saas_scale_capacity import CapacityReservationError


class AlertSchedulingPersistenceMixin:
    _connection: Connection[Any]

    def admit_episode(
        self,
        *,
        scope: Scope,
        episode_id: str,
        evaluated_at: datetime | None = None,
        fence_failure_reason: str | None = None,
        force_new: bool = False,
        idempotency_suffix: str = "",
    ) -> AlertAdmissionCommit:
        """Decide, reserve, and enqueue one episode in the caller's transaction."""

        moment = evaluated_at or datetime.now(UTC)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("Alert admission time must be timezone-aware")
        values = {**scope.canonical_dict(), "episode_id": episode_id}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"{scope.digest()}:{episode_id}:alert-admission",),
            )
            writer = cast(AlertAdmissionWriter, self)
            existing = writer._current_admission(cursor=cursor, values=values)
            if existing is not None and not force_new:
                return _admission_commit(existing, created=False)
            cursor.execute(
                """SELECT episode.*,generation.provider_state_projection,
                          event.observed_at,event.observed_connection_id AS connection_id,
                          event.observed_connection_epoch AS connection_epoch,
                          subtype.triage_budget_json,subtype.maximum_pending_per_target,
                          subtype.cooldown_ms,subtype.retention_policy_revision,
                          head.policy_hash AS current_policy_hash,
                          head.head_epoch AS current_head_epoch,
                          head.placement_epoch AS current_head_placement_epoch,
                          lifecycle.availability AS policy_availability,
                          graph.snapshot_id AS current_graph_snapshot_id,
                          graph.snapshot_version AS current_graph_snapshot_version,
                          graph.cell_id AS current_cell_id,
                          graph.placement_epoch AS current_placement_epoch
                     FROM solvan_alerts.alert_episodes episode
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
                      AND episode.id=%(episode_id)s FOR UPDATE OF episode""",
                values,
            )
            episode = cursor.fetchone()
            if episode is None:
                raise AlertSchedulingError("ALERT_EPISODE_NOT_FOUND")
            derived_fence_failure = fence_failure_reason or _fence_failure(episode)
            cursor.execute(
                """SELECT count(*) AS pending
                     FROM solvan_alerts.alert_admission_current current
                     JOIN solvan_alerts.alert_admissions admission
                       ON (admission.organization_id,admission.project_id,
                           admission.environment_id,admission.id)=
                          (current.organization_id,current.project_id,
                           current.environment_id,current.admission_id)
                     JOIN solvan_alerts.alert_episodes other
                       ON (other.organization_id,other.project_id,other.environment_id,
                           other.id)=(admission.organization_id,admission.project_id,
                           admission.environment_id,admission.episode_id)
                    WHERE other.organization_id=%(organization_id)s
                      AND other.project_id=%(project_id)s
                      AND other.environment_id=%(environment_id)s
                      AND other.target_node_key=%(target_node_key)s
                      AND other.id<>%(episode_id)s
                      AND other.state IN ('WAITING','TRIAGING')
                      AND admission.decision IN ('ADMITTED','PENDING')""",
                {**values, "target_node_key": episode["target_node_key"]},
            )
            pending_row = cursor.fetchone()
            pending = 0 if pending_row is None else int(pending_row["pending"])
            cursor.execute(
                """SELECT max(admission.cooldown_until) AS cooldown_until
                     FROM solvan_alerts.alert_admissions admission
                     JOIN solvan_alerts.alert_episodes other
                       ON (other.organization_id,other.project_id,other.environment_id,
                           other.id)=(admission.organization_id,admission.project_id,
                           admission.environment_id,admission.episode_id)
                    WHERE other.organization_id=%(organization_id)s
                      AND other.project_id=%(project_id)s
                      AND other.environment_id=%(environment_id)s
                      AND other.target_node_key=%(target_node_key)s
                      AND admission.cooldown_until>%(evaluated_at)s""",
                {
                    **values,
                    "target_node_key": episode["target_node_key"],
                    "evaluated_at": moment,
                },
            )
            cooldown_row = cursor.fetchone()
            cooldown_until = None if cooldown_row is None else cooldown_row["cooldown_until"]
            budget = dict(episode["triage_budget_json"])
            preliminary = evaluate_alert_admission(
                AlertAdmissionInput(
                    source_state=(
                        "CLOSED" if episode["provider_state_projection"] == "CLOSED" else "OPEN"
                    ),
                    observed_at=episode["observed_at"],
                    evaluated_at=moment,
                    maximum_queue_age_ms=int(budget["maximum_queue_age_ms"]),
                    pending_for_target=pending,
                    maximum_pending_per_target=int(episode["maximum_pending_per_target"]),
                    cooldown_until=cooldown_until,
                    fence_failure_reason=derived_fence_failure,
                    capacity_decision=CapacityDecision.RESERVED,
                    capacity_receipt_ref="preflight://capacity",
                )
            )
            work_id: str | None = None
            reservation_id: str | None = None
            result = preliminary
            request_hash: str | None = None
            if preliminary.decision == "ADMITTED":
                work_id = new_identifier("wrk")
                request_hash = canonical_sha256(
                    {
                        "episode_id": episode_id,
                        "episode_generation": episode["episode_generation"],
                        "policy_hash": episode["policy_hash"],
                        "work_id": work_id,
                        "resource_kind": "MODEL_REQUEST",
                        "units": 1,
                    }
                )
                SaaSScaleRepository(self._connection).register_work(
                    scope=scope, work_kind="AGENT_RUN", work_id=work_id
                )
                try:
                    reservation = SaaSScaleRepository(self._connection).reserve_capacity(
                        scope=scope,
                        work_kind="AGENT_RUN",
                        work_id=work_id,
                        cell_id=str(episode["cell_id"]),
                        placement_epoch=int(episode["placement_epoch"]),
                        resource_kind="MODEL_REQUEST",
                        units=1,
                        idempotency_key=(
                            f"alert-triage:{episode_id}"
                            + (f":{idempotency_suffix}" if idempotency_suffix else "")
                        ),
                        request_hash=request_hash,
                        ttl_seconds=min(int(budget["maximum_runtime_seconds"]) + 300, 3600),
                    )
                    reservation_id = reservation.reservation_id
                    result = evaluate_alert_admission(
                        AlertAdmissionInput(
                            source_state="OPEN",
                            observed_at=episode["observed_at"],
                            evaluated_at=moment,
                            maximum_queue_age_ms=int(budget["maximum_queue_age_ms"]),
                            pending_for_target=pending,
                            maximum_pending_per_target=int(episode["maximum_pending_per_target"]),
                            cooldown_until=cooldown_until,
                            capacity_decision=CapacityDecision.RESERVED,
                            capacity_receipt_ref=reservation_id,
                        )
                    )
                except CapacityReservationError as error:
                    result = evaluate_alert_admission(
                        AlertAdmissionInput(
                            source_state="OPEN",
                            observed_at=episode["observed_at"],
                            evaluated_at=moment,
                            maximum_queue_age_ms=int(budget["maximum_queue_age_ms"]),
                            pending_for_target=pending,
                            maximum_pending_per_target=int(episode["maximum_pending_per_target"]),
                            cooldown_until=cooldown_until,
                            capacity_decision=(
                                CapacityDecision.WAITING
                                if error.reason_code == "CENTRAL_CAPACITY_WAIT"
                                else CapacityDecision.EXHAUSTED
                            ),
                            capacity_retry_at=error.retry_at,
                        )
                    )
                    if result.decision != "PENDING":
                        cursor.execute(
                            """DELETE FROM solvan_scale.tenant_work_registry
                                WHERE organization_id=%(organization_id)s
                                  AND project_id=%(project_id)s
                                  AND environment_id=%(environment_id)s
                                  AND work_kind='AGENT_RUN' AND work_id=%(work_id)s
                                  AND state='PENDING'""",
                            {**values, "work_id": work_id},
                        )
                        work_id = None
                        request_hash = None
            return writer._append_admission(
                cursor=cursor,
                scope=scope,
                episode=episode,
                result=result,
                work_id=work_id,
                reservation_id=reservation_id,
                request_hash=request_hash,
                decided_at=moment,
            )

    def claim_next_alert_triage(
        self,
        *,
        scope: Scope,
        cell_id: str,
        lease_seconds: int,
        plan_json: dict[str, Any],
        plan_hash: str,
        input_manifest: dict[str, Any],
        effective_tool_set_hash: str | None,
        agent_resource: str,
        agent_revision: str,
        binding_resolver: Callable[[Scope, str, dict[str, Any]], str] | None = None,
    ) -> AlertTriageClaim | None:
        """Claim one fair queued Alert and persist its Agent request before dispatch."""

        if not 5 <= lease_seconds <= 300:
            raise ValueError("Alert claim lease must be between 5 and 300 seconds")
        if not plan_hash.startswith("sha256:") or len(plan_hash) != 71:
            raise ValueError("Alert claim plan hash must be typed")
        if effective_tool_set_hash is not None and (
            not effective_tool_set_hash.startswith("sha256:") or len(effective_tool_set_hash) != 71
        ):
            raise ValueError("Alert claim Tool-set hash must be typed")
        if (effective_tool_set_hash is None) == (binding_resolver is None):
            raise ValueError("Alert claim requires exactly one Tool-binding source")
        if canonical_sha256(plan_json) != plan_hash:
            raise ValueError("Alert claim plan hash does not bind the accepted plan")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """WITH eligible AS (
                     SELECT queue.organization_id,queue.project_id,queue.environment_id,
                            queue.work_id,
                            row_number() OVER (
                              PARTITION BY queue.organization_id
                              ORDER BY queue.tenant_sequence) AS tenant_rank
                       FROM solvan_scale.tenant_dispatch_queue queue
                      WHERE queue.organization_id=%(organization_id)s
                        AND queue.project_id=%(project_id)s
                        AND queue.environment_id=%(environment_id)s
                        AND queue.cell_id=%(cell_id)s AND queue.state='QUEUED'
                        AND queue.available_at<=clock_timestamp()
                   ), candidate AS (
                     SELECT queue.* FROM solvan_scale.tenant_dispatch_queue queue
                     JOIN eligible USING (organization_id,project_id,environment_id,work_id)
                     ORDER BY eligible.tenant_rank,queue.available_at,
                              queue.organization_id,queue.tenant_sequence
                     FOR UPDATE OF queue SKIP LOCKED LIMIT 1
                   )
                   UPDATE solvan_scale.tenant_dispatch_queue queue
                      SET state='CLAIMED',claim_token=%(claim_token)s,
                          lease_expires_at=clock_timestamp()+
                            (%(lease_seconds)s * interval '1 second')
                     FROM candidate
                    WHERE (queue.organization_id,queue.project_id,queue.environment_id,
                           queue.work_id)=(candidate.organization_id,candidate.project_id,
                                          candidate.environment_id,candidate.work_id)
                   RETURNING queue.*""",
                {
                    **scope.canonical_dict(),
                    "cell_id": cell_id,
                    "claim_token": token,
                    "lease_seconds": lease_seconds,
                },
            )
            queue = cursor.fetchone()
            if queue is None:
                return None
            values = {
                "organization_id": queue["organization_id"],
                "project_id": queue["project_id"],
                "environment_id": queue["environment_id"],
                "work_id": queue["work_id"],
                "claim_token": token,
                "lease_expires_at": queue["lease_expires_at"],
            }
            cursor.execute(
                """SELECT admission.id AS admission_id,admission.episode_id,
                          admission.capacity_reservation_id,episode.*,
                          event.observed_connection_id AS connection_id,
                          event.observed_connection_epoch AS connection_epoch,
                          subtype.triage_budget_json,
                          target.external_project_id AS target_external_project_id,
                          target.attributes_json->>'region' AS target_workload_region,
                          head.policy_hash AS current_policy_hash,
                          head.head_epoch AS current_head_epoch,
                          head.placement_epoch AS current_head_placement_epoch,
                          lifecycle.availability AS policy_availability,
                          graph.snapshot_id AS current_graph_snapshot_id,
                          graph.snapshot_version AS current_graph_snapshot_version,
                          graph.cell_id AS current_cell_id,
                          graph.placement_epoch AS current_placement_epoch
                     FROM solvan_alerts.alert_admissions admission
                     JOIN solvan_alerts.alert_episodes episode
                       ON (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.id)=(admission.organization_id,admission.project_id,
                           admission.environment_id,admission.episode_id)
                     JOIN solvan_alerts.alert_events event
                       ON (event.organization_id,event.project_id,event.environment_id,event.id)=
                          (episode.organization_id,episode.project_id,
                          episode.environment_id,episode.last_event_id)
                     JOIN solvan_alerts.alert_policy_revisions subtype
                       ON (subtype.organization_id,subtype.project_id,subtype.environment_id,
                           subtype.policy_key,subtype.policy_version,subtype.policy_hash)=
                          (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.policy_key,episode.policy_version,episode.policy_hash)
                     JOIN solvan.production_graph_nodes target
                       ON (target.organization_id,target.project_id,target.environment_id,
                           target.snapshot_id,target.id)=
                          (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.graph_snapshot_id,episode.target_node_version)
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
                       admission.organization_id,admission.project_id,
                       admission.environment_id) graph ON true
                    WHERE admission.organization_id=%(organization_id)s
                      AND admission.project_id=%(project_id)s
                      AND admission.environment_id=%(environment_id)s
                      AND admission.work_id=%(work_id)s AND admission.decision='ADMITTED'
                    FOR UPDATE OF episode""",
                values,
            )
            episode = cursor.fetchone()
            if episode is None or _fence_failure(episode) is not None:
                raise AlertSchedulingError("ALERT_CLAIM_FENCE_FAILED")
            triage_run_id = new_identifier("aru")
            agent_run_id = new_identifier("run")
            invocation_id = new_identifier("inv")
            deadline = queue["lease_expires_at"]
            budget = dict(episode["triage_budget_json"])
            frozen_input = {
                **input_manifest,
                "alert_episode_id": str(episode["episode_id"]),
                "semantic_event_id": str(episode["last_event_id"]),
                "policy_hash": str(episode["policy_hash"]),
                "graph_snapshot_id": str(episode["graph_snapshot_id"]),
                "graph_content_hash": str(episode["graph_content_hash"]),
                "target_node_key": str(episode["target_node_key"]),
                "connection_id": str(episode["connection_id"]),
                "connection_epoch": int(episode["connection_epoch"]),
            }
            input_hash = canonical_sha256(frozen_input)
            input_ref = (
                "db://solvan-alerts/episodes/"
                f"{episode['episode_id']}/events/{episode['last_event_id']}"
            )
            step_budget = {
                "deadline_ms": min(int(budget["maximum_runtime_seconds"]) * 1000, 4_200_000),
                "max_tool_calls": int(budget["maximum_tool_calls"]),
                "max_output_bytes": min(
                    int(budget.get("maximum_output_bytes", 128_000)), 1_048_576
                ),
                "max_model_calls": int(budget["maximum_model_calls"]),
                "max_replans": 0,
            }
            trace_id = uuid4().hex
            span_id = uuid4().hex[:16]
            cursor.execute(
                """INSERT INTO solvan.agent_runs
                    (organization_id,project_id,environment_id,id,alert_episode_id,
                     logical_step_key,agent_key,agent_resource,agent_revision,invocation_id,
                     effective_tool_set_hash,workflow_version,attempt,status,deadline,
                     budget_json,input_ref,input_context_json,input_hash,trace_id,span_id)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(agent_run_id)s,%(episode_id)s,%(logical_step_key)s,'evidence-agent',
                     %(agent_resource)s,%(agent_revision)s,%(invocation_id)s,
                     %(effective_tool_set_hash)s,1,1,'CREATED',%(deadline)s,
                     %(budget)s,%(input_ref)s,%(input_context)s,%(input_hash)s,
                     %(trace_id)s,%(span_id)s)""",
                {
                    **values,
                    "agent_run_id": agent_run_id,
                    "episode_id": episode["episode_id"],
                    "logical_step_key": f"alert:{episode['episode_id']}:triage:1",
                    "agent_resource": agent_resource,
                    "agent_revision": agent_revision,
                    "invocation_id": invocation_id,
                    "effective_tool_set_hash": effective_tool_set_hash,
                    "deadline": deadline,
                    "budget": Jsonb(step_budget),
                    "input_ref": input_ref,
                    "input_context": Jsonb(
                        {
                            **frozen_input,
                            "target_external_project_id": episode["target_external_project_id"],
                            "target_workload_region": episode["target_workload_region"],
                            "policy_head_activation_id": episode["activation_id"],
                            "policy_head_epoch": episode["head_epoch"],
                            "placement_epoch": episode["placement_epoch"],
                        }
                    ),
                    "input_hash": input_hash,
                    "trace_id": trace_id,
                    "span_id": span_id,
                },
            )
            run_scope = Scope(
                str(queue["organization_id"]),
                str(queue["project_id"]),
                str(queue["environment_id"]),
            )
            if binding_resolver is not None:
                effective_tool_set_hash = binding_resolver(
                    run_scope,
                    agent_run_id,
                    {
                        "target_external_project_id": episode["target_external_project_id"],
                        "target_workload_region": episode["target_workload_region"],
                        "policy_head_activation_id": episode["activation_id"],
                        "policy_head_epoch": int(episode["head_epoch"]),
                        "placement_epoch": int(episode["placement_epoch"]),
                    },
                )
                cursor.execute(
                    """UPDATE solvan.agent_runs SET effective_tool_set_hash=%(tool_hash)s
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND id=%(agent_run_id)s AND status='CREATED'
                          AND effective_tool_set_hash IS NULL""",
                    {**values, "agent_run_id": agent_run_id, "tool_hash": effective_tool_set_hash},
                )
                if cursor.rowcount != 1:
                    raise AlertSchedulingError("ALERT_TOOL_BINDING_STALE")
            assert effective_tool_set_hash is not None
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_triage_runs
                    (organization_id,project_id,environment_id,id,episode_id,
                     episode_generation,admission_id,semantic_event_id,policy_key,
                     policy_version,policy_hash,cell_id,placement_epoch,connection_id,
                     connection_epoch,graph_snapshot_id,graph_snapshot_version,
                     graph_content_hash,target_node_key,target_node_version,plan_json,
                     plan_hash,profile_ref,effective_tool_set_hash,agent_run_id,work_id,
                     capacity_reservation_id,claim_token,claim_epoch,claim_expires_at,status)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(triage_run_id)s,%(episode_id)s,%(episode_generation)s,
                     %(admission_id)s,%(last_event_id)s,%(policy_key)s,%(policy_version)s,
                     %(policy_hash)s,%(cell_id)s,%(placement_epoch)s,%(connection_id)s,
                     %(connection_epoch)s,%(graph_snapshot_id)s,%(graph_snapshot_version)s,
                     %(graph_content_hash)s,%(target_node_key)s,%(target_node_version)s,
                     %(plan_json)s,%(plan_hash)s,'alert-triage-read-compute-v1@1',
                     %(effective_tool_set_hash)s,
                     %(agent_run_id)s,%(work_id)s,%(capacity_reservation_id)s,
                     %(claim_token)s,1,%(lease_expires_at)s,'CLAIMED')""",
                {
                    **values,
                    **episode,
                    "triage_run_id": triage_run_id,
                    "agent_run_id": agent_run_id,
                    "plan_json": Jsonb(plan_json),
                    "plan_hash": plan_hash,
                    "effective_tool_set_hash": effective_tool_set_hash,
                },
            )
            cursor.execute(
                """UPDATE solvan_scale.tenant_capacity_reservations SET status='STARTED'
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND reservation_id=%(capacity_reservation_id)s AND status='HELD'
                      AND expires_at>clock_timestamp()""",
                {**values, **episode},
            )
            if cursor.rowcount != 1:
                raise AlertSchedulingError("ALERT_CAPACITY_RESERVATION_STALE")
            cursor.execute(
                """UPDATE solvan_scale.tenant_work_registry SET state='STARTED'
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND work_kind='AGENT_RUN'
                      AND work_id=%(work_id)s AND state='PENDING'""",
                values,
            )
            cursor.execute(
                """UPDATE solvan_alerts.alert_episodes
                      SET state='TRIAGING',row_version=row_version+1
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(episode_id)s
                      AND state IN ('OPEN','WAITING')""",
                {**values, "episode_id": episode["episode_id"]},
            )
            if cursor.rowcount != 1:
                raise AlertSchedulingError("ALERT_EPISODE_STATE_STALE")
        return AlertTriageClaim(
            triage_run_id,
            agent_run_id,
            str(episode["episode_id"]),
            str(queue["work_id"]),
            str(token),
            1,
            queue["lease_expires_at"],
            False,
        )


def _admission_commit(row: dict[str, Any], *, created: bool) -> AlertAdmissionCommit:
    return AlertAdmissionCommit(
        str(row["admission_id"]),
        str(row["episode_id"]),
        str(row["decision"]),
        str(row["reason_code"]),
        None if row["work_id"] is None else str(row["work_id"]),
        None if row["capacity_reservation_id"] is None else str(row["capacity_reservation_id"]),
        row["due_at"],
        created,
    )


def _fence_failure(row: dict[str, Any]) -> str | None:
    if "policy_availability" in row and row.get("policy_availability") != "ELIGIBLE":
        return "POLICY_NOT_ELIGIBLE"
    comparisons = (
        ("current_policy_hash", "policy_hash", "POLICY_HEAD_STALE"),
        ("current_head_epoch", "head_epoch", "POLICY_HEAD_STALE"),
        ("current_head_placement_epoch", "placement_epoch", "PLACEMENT_STALE"),
        ("current_graph_snapshot_id", "graph_snapshot_id", "GRAPH_TARGET_STALE"),
        ("current_graph_snapshot_version", "graph_snapshot_version", "GRAPH_TARGET_STALE"),
        ("current_cell_id", "cell_id", "PLACEMENT_STALE"),
        ("current_placement_epoch", "placement_epoch", "PLACEMENT_STALE"),
    )
    for current, frozen, reason in comparisons:
        if current in row and row.get(current) != row.get(frozen):
            return reason
    return None
