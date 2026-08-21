"""Reader-safe Alert queue and report projections from committed records."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.alert_list import AlertCursorPosition, AlertListFilter
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.alert_triage_read_projection import (
    cursor_position as _cursor_position,
)
from solvan.persistence.alert_triage_read_projection import (
    filter_values as _filter_values,
)
from solvan.persistence.alert_triage_read_projection import (
    jsonable as _jsonable,
)
from solvan.persistence.alert_triage_read_projection import (
    list_row as _list_row,
)
from solvan.persistence.alert_triage_read_projection import (
    report_projection as _report,
)
from solvan.persistence.alert_triage_read_projection import (
    view_clause as _view_clause,
)


class AlertTriageReadMixin:
    _connection: Connection[Any]

    def list_alerts(
        self,
        *,
        scope: Scope,
        alert_filter: AlertListFilter,
        cursor_position: AlertCursorPosition | None = None,
    ) -> dict[str, Any]:
        values = {
            **scope.canonical_dict(),
            **_filter_values(alert_filter),
            "limit": alert_filter.limit + 1,
            "cursor_severity": cursor_position.severity_rank if cursor_position else None,
            "cursor_attention": cursor_position.attention_rank if cursor_position else None,
            "cursor_last_seen": cursor_position.last_seen_at if cursor_position else None,
            "cursor_id": cursor_position.alert_episode_id if cursor_position else None,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            rows = self._query_rows(cursor=cursor, values=values, view=alert_filter.view)
            counts = {
                candidate: self._count(cursor=cursor, values=values, view=candidate)
                for candidate in ("ACTIVE", "NEEDS_REVIEW", "INVESTIGATING", "ALL")
            }
            cursor.execute("SELECT clock_timestamp() AS freshness_at")
            clock = cursor.fetchone()
        has_more = len(rows) > alert_filter.limit
        rows = rows[: alert_filter.limit]
        next_position = _cursor_position(dict(rows[-1])) if has_more and rows else None
        result = {
            "schema_version": 1,
            "filter": alert_filter.canonical_dict(),
            "counts": counts,
            "rows": [_list_row(dict(row)) for row in rows],
            "next_cursor": None,
            "projection_version": 1,
            "freshness_at": clock["freshness_at"].isoformat() if clock else None,
            "placement_epoch": max((int(row["placement_epoch"]) for row in rows), default=0),
            "policy_epoch": max((int(row["head_epoch"]) for row in rows), default=0),
            "membership_epoch": 0,
        }
        result["projection_digest"] = canonical_sha256(result)
        result["_next_cursor_position"] = next_position
        return result

    def get_alert_list_context(self, *, scope: Scope, principal: str) -> dict[str, int]:
        """Resolve current access and routing epochs before accepting a cursor."""

        values = {**scope.canonical_dict(), "principal": principal}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            # `greatest(1, NULL)` is 1, not NULL: computing the epoch inline
            # admitted every principal, granted or not. Existence of the grant
            # is established first, and the cursor-fencing epoch derived after.
            cursor.execute(
                """SELECT max(granted_at) AS last_grant_at
                     FROM solvan.actor_role_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND principal=%(principal)s
                      AND role IN ('OPERATOR','APPROVER','ADMIN')
                      AND (expires_at IS NULL OR expires_at>clock_timestamp())""",
                values,
            )
            membership = cursor.fetchone()
            if membership is None or membership["last_grant_at"] is None:
                raise PermissionError("ALERT_READER_GRANT_INACTIVE")
            membership_epoch = max(
                1,
                int(membership["last_grant_at"].timestamp() * 1_000_000),
            )
            cursor.execute(
                """SELECT coalesce(
                           (SELECT max(placement_epoch) FROM solvan_scale.tenant_placements
                             WHERE organization_id=%(organization_id)s AND is_current),
                           (SELECT max(placement_epoch) FROM solvan_alerts.alert_episodes
                             WHERE organization_id=%(organization_id)s
                               AND project_id=%(project_id)s
                               AND environment_id=%(environment_id)s),1) AS placement_epoch,
                          coalesce(
                           (SELECT max(head_epoch)
                              FROM solvan_operability.trigger_policy_current_heads
                             WHERE organization_id=%(organization_id)s
                               AND project_id=%(project_id)s
                               AND environment_id=%(environment_id)s AND is_current),1)
                            AS policy_epoch""",
                values,
            )
            epochs = cursor.fetchone()
        assert epochs is not None
        return {
            "placement_epoch": int(epochs["placement_epoch"]),
            "policy_epoch": int(epochs["policy_epoch"]),
            "membership_epoch": membership_epoch,
        }

    def get_alert_report(self, *, scope: Scope, episode_id: str) -> dict[str, Any] | None:
        values = {**scope.canonical_dict(), "episode_id": episode_id}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(_ROW_QUERY + " AND episode.id=%(episode_id)s", values)
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                """SELECT result.id,result.predicate_node_id,result.predicate_kind,
                          result.result,result.reason_code,result.input_refs_json
                     FROM solvan_alerts.alert_predicate_results result
                     JOIN solvan_alerts.alert_triage_runs run
                       ON (run.organization_id,run.project_id,run.environment_id,run.id)=
                          (result.organization_id,result.project_id,
                           result.environment_id,result.triage_run_id)
                    WHERE run.organization_id=%(organization_id)s
                      AND run.project_id=%(project_id)s
                      AND run.environment_id=%(environment_id)s
                      AND run.episode_id=%(episode_id)s
                    ORDER BY result.evaluated_at,result.predicate_node_id""",
                values,
            )
            predicates = [dict(item) for item in cursor.fetchall()]
            cursor.execute(
                """SELECT id,source_kind,source_resource,window_start,window_end,
                          observed_at,content_hash,freshness_expires_at
                     FROM solvan.evidence_items
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND alert_episode_id=%(episode_id)s
                    ORDER BY ingested_at,id""",
                values,
            )
            evidence = [dict(item) for item in cursor.fetchall()]
            cursor.execute(
                """SELECT
                     (SELECT count(*) FROM solvan_alerts.alert_feedback feedback
                       WHERE feedback.organization_id=%(organization_id)s
                         AND feedback.project_id=%(project_id)s
                         AND feedback.environment_id=%(environment_id)s
                         AND feedback.episode_id=%(episode_id)s) AS feedback_count,
                     (SELECT count(*)
                        FROM solvan_alerts.alert_channel_delivery_attempts delivery
                       WHERE delivery.organization_id=%(organization_id)s
                         AND delivery.project_id=%(project_id)s
                         AND delivery.environment_id=%(environment_id)s
                         AND delivery.episode_id=%(episode_id)s) AS delivery_count""",
                values,
            )
            activity = cursor.fetchone()
        result = _report(
            dict(row),
            predicates=predicates,
            evidence=evidence,
            delivery_feedback_count=(
                int(activity["feedback_count"]) + int(activity["delivery_count"])
                if activity is not None
                else 0
            ),
        )
        result["projection_digest"] = canonical_sha256(result)
        return result

    def get_alert_subresource(
        self, *, scope: Scope, episode_id: str, kind: str
    ) -> dict[str, Any] | None:
        queries = {
            "EVENTS": """SELECT event.id AS event_id,event.lifecycle_state AS state,
                              event.observed_at,source.provider_kind AS source
                         FROM solvan_alerts.alert_episode_occurrences occurrence
                         JOIN solvan_alerts.alert_events event ON
                              (event.organization_id,event.project_id,
                               event.environment_id,event.id)=
                              (occurrence.organization_id,occurrence.project_id,
                               occurrence.environment_id,occurrence.semantic_event_id)
                         JOIN solvan_alerts.alert_provider_source_identities source
                           ON (source.organization_id,source.project_id,source.environment_id,
                               source.id)=(event.organization_id,event.project_id,
                               event.environment_id,event.provider_source_identity_id)
                        WHERE occurrence.organization_id=%(organization_id)s
                          AND occurrence.project_id=%(project_id)s
                          AND occurrence.environment_id=%(environment_id)s
                          AND occurrence.episode_id=%(episode_id)s
                        ORDER BY event.observed_at,event.id""",
            "TRIAGE_RUNS": """SELECT id AS triage_run_id,status,profile_ref,plan_hash,
                                     effective_tool_set_hash,created_at,completed_at
                                FROM solvan_alerts.alert_triage_runs
                               WHERE organization_id=%(organization_id)s
                                 AND project_id=%(project_id)s
                                 AND environment_id=%(environment_id)s
                                 AND episode_id=%(episode_id)s
                               ORDER BY created_at,id""",
            "DISPOSITIONS": """SELECT id AS disposition_id,disposition,reason_code,
                                      next_owner,next_review_at,created_at
                                 FROM solvan_alerts.alert_dispositions
                                WHERE organization_id=%(organization_id)s
                                  AND project_id=%(project_id)s
                                  AND environment_id=%(environment_id)s
                                  AND episode_id=%(episode_id)s
                                ORDER BY created_at,id""",
            "INCIDENT_LINKS": """SELECT incident_id,disposition_id,link_kind,
                                        deduplication_decision,linked_at
                                   FROM solvan_alerts.alert_incident_links
                                  WHERE organization_id=%(organization_id)s
                                    AND project_id=%(project_id)s
                                    AND environment_id=%(environment_id)s
                                    AND episode_id=%(episode_id)s
                                  ORDER BY linked_at,disposition_id""",
            "CHANNEL_DELIVERIES": """SELECT id AS delivery_attempt_id,disposition_id,
                                            channel_binding_id,binding_epoch,delivery_state,
                                            provider_receipt_ref,safe_failure_code,delivered_at
                                       FROM solvan_alerts.alert_channel_delivery_attempts
                                      WHERE organization_id=%(organization_id)s
                                        AND project_id=%(project_id)s
                                        AND environment_id=%(environment_id)s
                                        AND episode_id=%(episode_id)s
                                      ORDER BY delivered_at,id""",
        }
        if kind not in queries:
            raise ValueError("INVALID_ALERT_SUBRESOURCE")
        values = {**scope.canonical_dict(), "episode_id": episode_id}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT 1 FROM solvan_alerts.alert_episodes
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(episode_id)s""",
                values,
            )
            if cursor.fetchone() is None:
                return None
            cursor.execute(queries[kind], values)
            items = [_jsonable(dict(row)) for row in cursor.fetchall()]
        return {"schema_version": 1, "alert_episode_id": episode_id, "items": items}

    def list_alert_policies(self, *, scope: Scope) -> dict[str, Any]:
        """Project every Alert policy revision with the facts specification 21 §10.5 requires.

        The three activity counters are independent correlated subqueries, not
        joined tables. They were three aggregates over one join of episodes to
        both admissions and triage runs, which is a cartesian product per
        episode: every suppressed admission was counted once per triage run of
        the same episode, so ``suppression_count`` grew with unrelated triage
        activity. Each counter now reads exactly the rows it is counting.

        Source health is read through the policy revision's own
        ``source_connection_id``/``source_connection_epoch`` — the exact binding
        the approval digest covers and the admission path fences on. Matching
        any enabled connection of the same provider would report health for a
        connection this policy cannot admit from.
        """

        capacity = self.get_alert_capacity(scope=scope)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT policy.policy_key,policy.policy_version AS version,
                          policy.policy_hash,policy.mode,
                          revision.lifecycle,revision.author_principal,
                          revision.approved_by_principal,revision.evaluation_ref,
                          revision.approval_ref,revision.approved_at,
                          coalesce(lifecycle.availability,'UNAVAILABLE') AS availability,
                          revision.source_connection_id AS connection_id,
                          revision.source_connection_epoch AS connection_epoch,
                          connection.availability AS connection_health,
                          connection.availability_reason_code AS connection_reason_code,
                          (connection.connection_epoch IS NOT DISTINCT FROM
                           revision.source_connection_epoch) AS connection_binding_current,
                          (SELECT max(episode.last_source_time)
                             FROM solvan_alerts.alert_episodes episode
                            WHERE (episode.organization_id,episode.project_id,
                                   episode.environment_id,episode.policy_key,
                                   episode.policy_version,episode.policy_hash)=
                                  (policy.organization_id,policy.project_id,
                                   policy.environment_id,policy.policy_key,
                                   policy.policy_version,policy.policy_hash))
                            AS last_match_at,
                          (SELECT max(run.completed_at)
                             FROM solvan_alerts.alert_triage_runs run
                            WHERE (run.organization_id,run.project_id,run.environment_id,
                                   run.policy_key,run.policy_version,run.policy_hash)=
                                  (policy.organization_id,policy.project_id,
                                   policy.environment_id,policy.policy_key,
                                   policy.policy_version,policy.policy_hash))
                            AS last_triage_at,
                          (SELECT count(*)
                             FROM solvan_alerts.alert_admissions admission
                             JOIN solvan_alerts.alert_episodes episode
                               ON (episode.organization_id,episode.project_id,
                                   episode.environment_id,episode.id)=
                                  (admission.organization_id,admission.project_id,
                                   admission.environment_id,admission.episode_id)
                            WHERE admission.decision='SUPPRESSED'
                              AND (episode.organization_id,episode.project_id,
                                   episode.environment_id,episode.policy_key,
                                   episode.policy_version,episode.policy_hash)=
                                  (policy.organization_id,policy.project_id,
                                   policy.environment_id,policy.policy_key,
                                   policy.policy_version,policy.policy_hash))
                            AS suppression_count
                     FROM solvan_alerts.alert_policy_revisions policy
                     JOIN solvan_operability.trigger_policy_revisions revision
                       ON (revision.organization_id,revision.project_id,revision.environment_id,
                           revision.policy_key,revision.version,revision.policy_hash)=
                          (policy.organization_id,policy.project_id,policy.environment_id,
                           policy.policy_key,policy.policy_version,policy.policy_hash)
                     LEFT JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle
                       ON (lifecycle.organization_id,lifecycle.project_id,lifecycle.environment_id,
                           lifecycle.policy_key,lifecycle.policy_version,lifecycle.policy_hash)=
                          (policy.organization_id,policy.project_id,policy.environment_id,
                           policy.policy_key,policy.policy_version,policy.policy_hash)
                     LEFT JOIN solvan.tenant_connections connection
                       ON (connection.organization_id,connection.project_id,
                           connection.environment_id,connection.id)=
                          (revision.organization_id,revision.project_id,
                           revision.environment_id,revision.source_connection_id)
                    WHERE policy.organization_id=%(organization_id)s
                      AND policy.project_id=%(project_id)s
                      AND policy.environment_id=%(environment_id)s
                    ORDER BY policy.policy_key,policy.policy_version""",
                scope.canonical_dict(),
            )
            rows = [_jsonable(dict(row)) for row in cursor.fetchall()]
        for row in rows:
            row["current_capacity"] = capacity["status"]
            row["current_capacity_reason_code"] = capacity["reason_code"]
        return {"schema_version": 1, "rows": rows}

    def get_alert_policy_revision(
        self, *, scope: Scope, policy_key: str, version: str
    ) -> dict[str, Any] | None:
        """Project one pinned policy revision and the source connection bound to it.

        This selected ``source.connection_id`` with no ``source`` in the FROM
        clause and two principal columns that do not exist, so every call
        against a real database raised rather than returning a projection. The
        bound source is the revision's own ``source_connection_id``; evaluation
        and approval are identified by ``evaluation_ref``/``approval_ref`` and
        the approving principal, which is the shape the operability schema
        records.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT policy.*,revision.lifecycle,revision.author_principal,
                          revision.evaluation_ref,
                          revision.approved_by_principal,revision.approval_ref,
                          revision.approved_at,
                          lifecycle.availability,head.head_epoch,head.activation_id,
                          revision.source_connection_id AS connection_id,
                          revision.source_connection_epoch AS connection_epoch,
                          connection.availability AS connection_health,
                          connection.availability_reason_code AS connection_reason_code,
                          connection.lifecycle AS connection_lifecycle,
                          (connection.connection_epoch IS NOT DISTINCT FROM
                           revision.source_connection_epoch) AS connection_binding_current,
                          connection.last_probe_at,connection.last_probe_result
                     FROM solvan_alerts.alert_policy_revisions policy
                     JOIN solvan_operability.trigger_policy_revisions revision
                       ON (revision.organization_id,revision.project_id,
                           revision.environment_id,revision.policy_key,
                           revision.version,revision.policy_hash)=
                          (policy.organization_id,policy.project_id,
                           policy.environment_id,policy.policy_key,
                           policy.policy_version,policy.policy_hash)
                     LEFT JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle
                       ON (lifecycle.organization_id,lifecycle.project_id,
                           lifecycle.environment_id,lifecycle.policy_key,
                           lifecycle.policy_version,lifecycle.policy_hash)=
                          (policy.organization_id,policy.project_id,
                           policy.environment_id,policy.policy_key,
                           policy.policy_version,policy.policy_hash)
                     LEFT JOIN solvan_operability.trigger_policy_current_heads head
                       ON (head.organization_id,head.project_id,head.environment_id,
                           head.policy_key,head.policy_version)=
                          (policy.organization_id,policy.project_id,
                           policy.environment_id,policy.policy_key,
                           policy.policy_version) AND head.is_current
                     LEFT JOIN solvan.tenant_connections connection
                       ON (connection.organization_id,connection.project_id,
                           connection.environment_id,connection.id)=
                          (revision.organization_id,revision.project_id,
                           revision.environment_id,revision.source_connection_id)
                    WHERE policy.organization_id=%(organization_id)s
                      AND policy.project_id=%(project_id)s
                      AND policy.environment_id=%(environment_id)s
                      AND policy.policy_key=%(policy_key)s
                      AND policy.policy_version=%(version)s""",
                {
                    **scope.canonical_dict(),
                    "policy_key": policy_key,
                    "version": version,
                },
            )
            rows = [dict(row) for row in cursor.fetchall()]
        if not rows:
            return None
        first = rows[0]
        connections = [
            {
                "connection_id": row["connection_id"],
                "connection_epoch": row["connection_epoch"],
                "health": row["connection_health"],
                "reason_code": row["connection_reason_code"],
                "lifecycle": row["connection_lifecycle"],
                "binding_current": row["connection_binding_current"],
                "last_probe_at": _jsonable(row["last_probe_at"]),
                "last_probe_result": row["last_probe_result"],
            }
            for row in rows
            if row["connection_id"] is not None
        ]
        hidden = {
            "connection_id",
            "connection_epoch",
            "connection_health",
            "connection_reason_code",
            "connection_lifecycle",
            "connection_binding_current",
            "last_probe_at",
            "last_probe_result",
        }
        return {
            "schema_version": 1,
            "policy": _jsonable({key: value for key, value in first.items() if key not in hidden}),
            "connections": connections,
        }

    def get_alert_capacity(self, *, scope: Scope) -> dict[str, Any]:
        """Report the model-request concurrency that actually gates Alert triage.

        This summed every quota policy version's counter and ceiling, so one
        superseded revision doubled the reported limit and a policy that had
        been revoked outright still contributed headroom. Capacity resolves
        through the same authority the reservation path uses: the latest
        binding epoch, only when it activates, and only within the bound
        revision's effective window. When no policy resolves the answer is a
        closed refusal, never a fabricated ``0 of 0`` that reads as a real
        ceiling.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT limit_row.maximum_concurrent,counter.active_reservations,
                          policy.effective_at,policy.expires_at,
                          clock_timestamp() AS observed_at
                     FROM solvan_scale.tenant_quota_policy_bindings binding
                     JOIN solvan_scale.tenant_quota_policy_revisions policy
                       ON (policy.organization_id,policy.version)=
                          (binding.organization_id,binding.policy_version)
                     JOIN solvan_scale.tenant_quota_limits limit_row
                       ON (limit_row.organization_id,limit_row.policy_version,
                           limit_row.resource_kind)=
                          (binding.organization_id,binding.policy_version,'MODEL_REQUEST')
                     JOIN solvan_scale.tenant_quota_counters counter
                       ON (counter.organization_id,counter.policy_version,
                           counter.resource_kind)=
                          (limit_row.organization_id,limit_row.policy_version,
                           limit_row.resource_kind)
                    WHERE binding.organization_id=%(organization_id)s
                      AND binding.decision='ACTIVATE'
                      AND binding.binding_epoch=(
                        SELECT max(latest.binding_epoch)
                          FROM solvan_scale.tenant_quota_policy_bindings latest
                         WHERE latest.organization_id=binding.organization_id)""",
                scope.canonical_dict(),
            )
            row = cursor.fetchone()
        if row is None or row["effective_at"] > row["observed_at"]:
            return _unresolved_capacity()
        if row["expires_at"] is not None and row["expires_at"] <= row["observed_at"]:
            return _unresolved_capacity()
        active = int(row["active_reservations"])
        limit = int(row["maximum_concurrent"])
        exhausted = active >= limit
        return {
            "schema_version": 1,
            "status": "EXHAUSTED" if exhausted else "AVAILABLE",
            "reason_code": "MODEL_REQUEST_CONCURRENCY_EXHAUSTED" if exhausted else None,
            "active_reservations": active,
            "limit": limit,
        }

    @staticmethod
    def _query_rows(*, cursor: Any, values: dict[str, Any], view: str) -> list[Any]:
        cursor.execute(
            _ROW_QUERY
            + _view_clause(view)
            + _EXPLICIT_FILTER_CLAUSE
            + _CURSOR_CLAUSE
            + """ ORDER BY CASE severity_entry.value->>'solvan_severity'
                              WHEN 'SEV1' THEN 1 WHEN 'SEV2' THEN 2
                              WHEN 'SEV3' THEN 3 ELSE 4 END,
                          CASE WHEN disposition.disposition IN
                            ('MANUAL_REVIEW','BLOCKED') THEN 0 ELSE 1 END,
                          episode.last_source_time DESC,episode.id
                 LIMIT %(limit)s""",
            values,
        )
        return list(cursor.fetchall())

    @staticmethod
    def _count(*, cursor: Any, values: dict[str, Any], view: str) -> int:
        cursor.execute(
            "SELECT count(*) FROM ("
            + _ROW_QUERY
            + _view_clause(view)
            + _EXPLICIT_FILTER_CLAUSE
            + ") visible",
            values,
        )
        row = cursor.fetchone()
        return 0 if row is None else int(row["count"])


def _unresolved_capacity() -> dict[str, Any]:
    """No active, in-window quota policy resolves, so no ceiling is claimed.

    The reservation path refuses with this reason code rather than admitting
    against an assumed limit; the projection reports the same fact instead of
    presenting an absent policy as a zero ceiling.
    """

    return {
        "schema_version": 1,
        "status": "UNAVAILABLE",
        "reason_code": "QUOTA_POLICY_UNAVAILABLE",
        "active_reservations": 0,
        "limit": 0,
    }


_ROW_QUERY = """SELECT episode.id,episode.row_version,episode.state,
       episode.target_node_key,episode.provider_incident_key,episode.first_source_time,
       episode.last_source_time,episode.last_event_id,episode.provider_state_projection,
       episode.policy_key,
       episode.policy_version,episode.policy_hash,episode.cell_id,episode.placement_epoch,
       episode.head_epoch,episode.graph_snapshot_id,episode.graph_snapshot_version,
       occurrence.occurrence_count,event.provider_severity,event.resource_type,
       source.provider_kind,membership.connection_id,policy.mode,
       policy.escalation_expression_json,policy.full_incident_admission_expression_json,
       service.owner_department,
       severity_entry.value->>'solvan_severity' AS severity,
       disposition.id AS disposition_id,disposition.disposition,
       disposition.reason_code,disposition.next_owner,disposition.next_review_at,
       link.incident_id,link.link_kind,incident.display_id AS incident_display_id,
       service.display_name AS service_name
  FROM solvan_alerts.alert_episodes episode
  JOIN solvan_alerts.alert_provider_generations generation
    ON (generation.organization_id,generation.project_id,generation.environment_id,
        generation.id)=(episode.organization_id,episode.project_id,
        episode.environment_id,episode.provider_generation_id)
  JOIN LATERAL (
    SELECT count(*)::bigint AS occurrence_count
      FROM solvan_alerts.alert_provider_generation_occurrences candidate
     WHERE candidate.organization_id=generation.organization_id
       AND candidate.project_id=generation.project_id
       AND candidate.environment_id=generation.environment_id
       AND candidate.provider_generation_id=generation.id
  ) occurrence ON true
  JOIN solvan_alerts.alert_events event
    ON (event.organization_id,event.project_id,event.environment_id,event.id)=
       (episode.organization_id,episode.project_id,episode.environment_id,
        episode.last_event_id)
  JOIN solvan_alerts.alert_provider_source_identities source
    ON (source.organization_id,source.project_id,source.environment_id,source.id)=
       (episode.organization_id,episode.project_id,episode.environment_id,
        episode.provider_source_identity_id)
  JOIN solvan_alerts.alert_provider_source_current_memberships membership
    ON (membership.organization_id,membership.project_id,membership.environment_id,
        membership.source_identity_id)=(source.organization_id,source.project_id,
        source.environment_id,source.id)
  JOIN solvan_alerts.alert_policy_revisions policy
    ON (policy.organization_id,policy.project_id,policy.environment_id,
        policy.policy_key,policy.policy_version,policy.policy_hash)=
       (episode.organization_id,episode.project_id,episode.environment_id,
        episode.policy_key,episode.policy_version,episode.policy_hash)
  JOIN LATERAL jsonb_array_elements(policy.severity_mapping_json->'entries') severity_entry
    ON severity_entry.value->>'provider_value'=event.provider_severity
  LEFT JOIN LATERAL (
    SELECT candidate.* FROM solvan_alerts.alert_dispositions candidate
     WHERE candidate.organization_id=episode.organization_id
       AND candidate.project_id=episode.project_id
       AND candidate.environment_id=episode.environment_id
       AND candidate.episode_id=episode.id
     ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT 1
  ) disposition ON true
  LEFT JOIN solvan_alerts.alert_incident_links link
    ON (link.organization_id,link.project_id,link.environment_id,link.disposition_id)=
       (disposition.organization_id,disposition.project_id,
        disposition.environment_id,disposition.id)
  LEFT JOIN solvan.incidents incident
    ON (incident.organization_id,incident.project_id,incident.environment_id,incident.id)=
       (link.organization_id,link.project_id,link.environment_id,link.incident_id)
  LEFT JOIN solvan.services service
    ON (service.organization_id,service.project_id,service.environment_id,
        service.service_key)=(episode.organization_id,episode.project_id,
        episode.environment_id,episode.target_node_key)
 WHERE episode.organization_id=%(organization_id)s
   AND episode.project_id=%(project_id)s
   AND episode.environment_id=%(environment_id)s"""


_EXPLICIT_FILTER_CLAUSE = """
   AND (%(severity)s::text[]='{}' OR
        severity_entry.value->>'solvan_severity'=ANY(%(severity)s))
   AND (%(episode_state)s::text[]='{}' OR episode.state=ANY(%(episode_state)s))
   AND (%(source_provider)s::text[]='{}' OR source.provider_kind=ANY(%(source_provider)s))
   AND (%(connection_id)s::text[]='{}' OR membership.connection_id=ANY(%(connection_id)s))
   AND (%(department)s::text[]='{}' OR service.owner_department=ANY(%(department)s))
   AND (%(target_key)s::text[]='{}' OR episode.target_node_key=ANY(%(target_key)s))
   AND (%(policy_key)s::text[]='{}' OR episode.policy_key=ANY(%(policy_key)s))
   AND (%(mode)s::text[]='{}' OR policy.mode=ANY(%(mode)s))
   AND (%(provider_state)s::text[]='{}' OR
        episode.provider_state_projection=ANY(%(provider_state)s))
   AND (%(disposition)s::text[]='{}' OR disposition.disposition=ANY(%(disposition)s))
   AND (%(incident_link)s='ANY' OR (%(incident_link)s='LINKED' AND link.incident_id IS NOT NULL)
        OR (%(incident_link)s='UNLINKED' AND link.incident_id IS NULL))
   AND (%(source_time_from)s::timestamptz IS NULL OR
        episode.last_source_time >= %(source_time_from)s)
   AND (%(source_time_to)s::timestamptz IS NULL OR
        episode.last_source_time < %(source_time_to)s)
   AND (%(query)s::text IS NULL OR position(%(query)s IN lower(concat_ws(' ',
        episode.id,episode.provider_incident_key,episode.target_node_key,
        service.display_name,source.provider_kind,episode.policy_key))) > 0)
"""


_CURSOR_CLAUSE = """
   AND (%(cursor_id)s::text IS NULL OR
        (CASE severity_entry.value->>'solvan_severity'
           WHEN 'SEV1' THEN 1 WHEN 'SEV2' THEN 2 WHEN 'SEV3' THEN 3 ELSE 4 END
          > %(cursor_severity)s)
        OR (CASE severity_entry.value->>'solvan_severity'
              WHEN 'SEV1' THEN 1 WHEN 'SEV2' THEN 2 WHEN 'SEV3' THEN 3 ELSE 4 END
            = %(cursor_severity)s
            AND CASE WHEN disposition.disposition IN ('MANUAL_REVIEW','BLOCKED')
                     THEN 0 ELSE 1 END > %(cursor_attention)s)
        OR (CASE severity_entry.value->>'solvan_severity'
              WHEN 'SEV1' THEN 1 WHEN 'SEV2' THEN 2 WHEN 'SEV3' THEN 3 ELSE 4 END
            = %(cursor_severity)s
            AND CASE WHEN disposition.disposition IN ('MANUAL_REVIEW','BLOCKED')
                     THEN 0 ELSE 1 END = %(cursor_attention)s
            AND episode.last_source_time < %(cursor_last_seen)s)
        OR (CASE severity_entry.value->>'solvan_severity'
              WHEN 'SEV1' THEN 1 WHEN 'SEV2' THEN 2 WHEN 'SEV3' THEN 3 ELSE 4 END
            = %(cursor_severity)s
            AND CASE WHEN disposition.disposition IN ('MANUAL_REVIEW','BLOCKED')
                     THEN 0 ELSE 1 END = %(cursor_attention)s
            AND episode.last_source_time = %(cursor_last_seen)s
            AND episode.id > %(cursor_id)s))
"""
