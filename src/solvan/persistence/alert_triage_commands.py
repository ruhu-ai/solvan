"""Authenticated, idempotent Alert operator commands and coordinator consumption."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.alert_liaison import record_alert_disposition_event
from solvan.persistence.alert_triage_scheduling_types import AlertAdmissionCommit


class AlertCommandError(RuntimeError):
    """Closed operator-command refusal or idempotency conflict."""


@dataclass(frozen=True, slots=True)
class AlertOperatorRequestCommit:
    request_id: str
    episode_id: str
    request_kind: str
    outcome: str
    refusal_code: str | None
    created: bool


@dataclass(frozen=True, slots=True)
class AlertFeedbackCommit:
    feedback_id: str
    episode_id: str
    created: bool


class _AlertCommandHost(Protocol):
    def admit_episode(
        self,
        *,
        scope: Scope,
        episode_id: str,
        evaluated_at: datetime | None = None,
        fence_failure_reason: str | None = None,
        force_new: bool = False,
        idempotency_suffix: str = "",
    ) -> AlertAdmissionCommit: ...

    def _open_incident(
        self, *, cursor: Any, scope: Scope, run: dict[str, Any]
    ) -> tuple[str, str]: ...


class AlertCommandPersistenceMixin:
    _connection: Connection[Any]

    def record_operator_request(
        self,
        *,
        scope: Scope,
        episode_id: str,
        request_kind: str,
        expected_row_version: int,
        request_reason_code: str,
        actor_principal: str,
        idempotency_key: str,
    ) -> AlertOperatorRequestCommit:
        if request_kind not in {"RETRIAGE", "INCIDENT_CONTINUATION"}:
            raise ValueError("INVALID_ALERT_COMMAND")
        if request_reason_code not in {
            "NEED_MORE_EVIDENCE",
            "POSSIBLE_CUSTOMER_IMPACT",
            "POSSIBLE_SECURITY_IMPACT",
            "OPERATOR_REVIEW",
        }:
            raise ValueError("INVALID_ALERT_COMMAND")
        material = {
            "schema_version": 1,
            "episode_id": episode_id,
            "request_kind": request_kind,
            "expected_row_version": expected_row_version,
            "request_reason_code": request_reason_code,
        }
        request_hash = canonical_sha256(material)
        values = {
            **scope.canonical_dict(),
            **material,
            "actor_principal": actor_principal,
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,episode_id,request_kind,outcome,refusal_code,request_hash
                     FROM solvan_alerts.alert_operator_requests
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND actor_principal=%(actor_principal)s
                      AND idempotency_key=%(idempotency_key)s""",
                values,
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay["request_hash"] != request_hash:
                    raise AlertCommandError("IDEMPOTENCY_CONFLICT")
                return AlertOperatorRequestCommit(
                    str(replay["id"]),
                    str(replay["episode_id"]),
                    str(replay["request_kind"]),
                    str(replay["outcome"]),
                    replay["refusal_code"],
                    False,
                )
            cursor.execute(
                """SELECT episode.row_version,episode.state,episode.provider_state_projection,
                          lifecycle.availability AS policy_availability,
                          link.incident_id
                     FROM solvan_alerts.alert_episodes episode
                     LEFT JOIN solvan_operability.trigger_policy_current_lifecycles lifecycle
                       ON (lifecycle.organization_id,lifecycle.project_id,
                           lifecycle.environment_id,lifecycle.policy_key,
                           lifecycle.policy_version,lifecycle.policy_hash)=
                          (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.policy_key,episode.policy_version,episode.policy_hash)
                     LEFT JOIN solvan_alerts.alert_incident_links link
                       ON (link.organization_id,link.project_id,link.environment_id,
                           link.episode_id)=(episode.organization_id,episode.project_id,
                           episode.environment_id,episode.id)
                    WHERE episode.organization_id=%(organization_id)s
                      AND episode.project_id=%(project_id)s
                      AND episode.environment_id=%(environment_id)s
                      AND episode.id=%(episode_id)s FOR UPDATE OF episode""",
                values,
            )
            episode = cursor.fetchone()
            if episode is None:
                raise AlertCommandError("ALERT_NOT_FOUND")
            refusal = _command_refusal(
                row_version=int(episode["row_version"]),
                expected_row_version=expected_row_version,
                episode_state=str(episode["state"]),
                provider_state=str(episode["provider_state_projection"]),
                policy_availability=episode["policy_availability"],
                incident_id=episode["incident_id"],
                request_kind=request_kind,
            )
            request_id = new_identifier("aor")
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_operator_requests
                    (organization_id,project_id,environment_id,id,episode_id,request_kind,
                     expected_row_version,request_reason_code,actor_principal,idempotency_key,
                     request_hash,outcome,refusal_code)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(request_id)s,%(episode_id)s,%(request_kind)s,%(expected_row_version)s,
                     %(request_reason_code)s,%(actor_principal)s,%(idempotency_key)s,
                     %(request_hash)s,%(outcome)s,%(refusal_code)s)""",
                {
                    **values,
                    "request_id": request_id,
                    "outcome": "REFUSED" if refusal else "ACCEPTED",
                    "refusal_code": refusal,
                },
            )
        return AlertOperatorRequestCommit(
            request_id,
            episode_id,
            request_kind,
            "REFUSED" if refusal else "ACCEPTED",
            refusal,
            True,
        )

    def record_feedback(
        self,
        *,
        scope: Scope,
        episode_id: str,
        category: str,
        note_ref: str | None,
        actor_principal: str,
        idempotency_key: str,
    ) -> AlertFeedbackCommit:
        if category not in {
            "HELPFUL",
            "NOT_HELPFUL",
            "MISSING_EVIDENCE",
            "INCORRECT_CAUSE",
            "OTHER",
        }:
            raise ValueError("INVALID_ALERT_FEEDBACK")
        request_hash = canonical_sha256(
            {
                "schema_version": 1,
                "episode_id": episode_id,
                "category": category,
                "note_ref": note_ref,
            }
        )
        values = {
            **scope.canonical_dict(),
            "episode_id": episode_id,
            "category": category,
            "note_ref": note_ref,
            "actor_principal": actor_principal,
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,episode_id,request_hash FROM solvan_alerts.alert_feedback
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND actor_principal=%(actor_principal)s
                      AND idempotency_key=%(idempotency_key)s""",
                values,
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay["request_hash"] != request_hash:
                    raise AlertCommandError("IDEMPOTENCY_CONFLICT")
                return AlertFeedbackCommit(str(replay["id"]), str(replay["episode_id"]), False)
            cursor.execute(
                """SELECT episode.policy_key,episode.policy_version,episode.classification,
                          run.id AS triage_run_id
                     FROM solvan_alerts.alert_episodes episode
                     LEFT JOIN LATERAL (
                       SELECT candidate.id FROM solvan_alerts.alert_triage_runs candidate
                        WHERE candidate.organization_id=episode.organization_id
                          AND candidate.project_id=episode.project_id
                          AND candidate.environment_id=episode.environment_id
                          AND candidate.episode_id=episode.id
                        ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT 1
                     ) run ON true
                    WHERE episode.organization_id=%(organization_id)s
                      AND episode.project_id=%(project_id)s
                      AND episode.environment_id=%(environment_id)s
                      AND episode.id=%(episode_id)s""",
                values,
            )
            episode = cursor.fetchone()
            if episode is None:
                raise AlertCommandError("ALERT_NOT_FOUND")
            feedback_id = new_identifier("afb")
            cursor.execute(
                """INSERT INTO solvan_alerts.alert_feedback
                    (organization_id,project_id,environment_id,id,episode_id,category,note_ref,
                     actor_principal,idempotency_key,request_hash,target_policy_key,
                     target_policy_version,target_triage_run_id,classification)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(feedback_id)s,
                     %(episode_id)s,%(category)s,%(note_ref)s,%(actor_principal)s,
                     %(idempotency_key)s,%(request_hash)s,%(policy_key)s,%(policy_version)s,
                     %(triage_run_id)s,%(classification)s)""",
                {**values, **dict(episode), "feedback_id": feedback_id},
            )
        return AlertFeedbackCommit(feedback_id, episode_id, True)

    def consume_next_operator_request(self, *, scope: Scope, owner: str) -> dict[str, Any] | None:
        """Consume one request under a row lock; caller owns the transaction."""

        values = {**scope.canonical_dict(), "owner": owner, "now": datetime.now(UTC)}
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.*,episode.row_version,episode.state,
                          episode.provider_state_projection
                     FROM solvan_alerts.alert_operator_requests request
                     JOIN solvan_alerts.alert_episodes episode
                       ON (episode.organization_id,episode.project_id,episode.environment_id,
                           episode.id)=(request.organization_id,request.project_id,
                           request.environment_id,request.episode_id)
                     LEFT JOIN solvan_alerts.alert_operator_request_consumptions consumed
                       ON (consumed.organization_id,consumed.project_id,consumed.environment_id,
                           consumed.request_id)=(request.organization_id,request.project_id,
                           request.environment_id,request.id)
                    WHERE request.organization_id=%(organization_id)s
                      AND request.project_id=%(project_id)s
                      AND request.environment_id=%(environment_id)s
                      AND request.outcome='ACCEPTED' AND consumed.request_id IS NULL
                    ORDER BY request.created_at,request.id
                    FOR UPDATE OF request SKIP LOCKED LIMIT 1""",
                values,
            )
            request = cursor.fetchone()
            if request is None:
                return None
            if int(request["row_version"]) != int(request["expected_row_version"]):
                return self._record_consumption(
                    cursor=cursor,
                    values={**values, **dict(request)},
                    outcome="REFUSED",
                    result_ref=None,
                    reason_code="STALE_ROW",
                )
            host = cast(_AlertCommandHost, self)
            if request["request_kind"] == "RETRIAGE":
                admission = host.admit_episode(
                    scope=scope,
                    episode_id=str(request["episode_id"]),
                    force_new=True,
                    idempotency_suffix=str(request["id"]),
                )
                outcome = "ENQUEUED" if admission.decision in {"ADMITTED", "PENDING"} else "REFUSED"
                return self._record_consumption(
                    cursor=cursor,
                    values={**values, **dict(request)},
                    outcome=outcome,
                    result_ref=admission.admission_id,
                    reason_code=(
                        "RETRIAGE_ENQUEUED" if outcome == "ENQUEUED" else admission.reason_code
                    ),
                )
            return self._consume_continuation(
                cursor=cursor, scope=scope, values={**values, **dict(request)}, host=host
            )

    @staticmethod
    def _record_consumption(
        *,
        cursor: Any,
        values: dict[str, Any],
        outcome: str,
        result_ref: str | None,
        reason_code: str,
    ) -> dict[str, Any]:
        cursor.execute(
            """INSERT INTO solvan_alerts.alert_operator_request_consumptions
                (organization_id,project_id,environment_id,request_id,episode_id,outcome,
                 result_ref,reason_code,consumed_by,consumed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(episode_id)s,%(outcome)s,%(result_ref)s,%(reason_code)s,%(owner)s,%(now)s)""",
            {**values, "outcome": outcome, "result_ref": result_ref, "reason_code": reason_code},
        )
        return {
            "request_id": str(values["id"]),
            "episode_id": str(values["episode_id"]),
            "outcome": outcome,
            "result_ref": result_ref,
            "reason_code": reason_code,
        }

    def _consume_continuation(
        self, *, cursor: Any, scope: Scope, values: dict[str, Any], host: _AlertCommandHost
    ) -> dict[str, Any]:
        cursor.execute(
            """SELECT run.*,subtype.severity_mapping_json,subtype.incident_class,
                      subtype.action_budget,subtype.repeated_action_limit
                 FROM solvan_alerts.alert_triage_runs run
                 JOIN solvan_alerts.alert_policy_revisions subtype
                   ON (subtype.organization_id,subtype.project_id,subtype.environment_id,
                       subtype.policy_key,subtype.policy_version,subtype.policy_hash)=
                      (run.organization_id,run.project_id,run.environment_id,
                       run.policy_key,run.policy_version,run.policy_hash)
                WHERE run.organization_id=%(organization_id)s
                  AND run.project_id=%(project_id)s AND run.environment_id=%(environment_id)s
                  AND run.episode_id=%(episode_id)s AND run.status='SUCCEEDED'
                ORDER BY run.completed_at DESC,run.id DESC LIMIT 1""",
            values,
        )
        run = cursor.fetchone()
        if run is None or values["provider_state_projection"] != "OPEN":
            return self._record_consumption(
                cursor=cursor,
                values=values,
                outcome="REFUSED",
                result_ref=None,
                reason_code="POLICY_INELIGIBLE",
            )
        cursor.execute(
            """SELECT incident_id FROM solvan_alerts.alert_incident_links
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND episode_id=%(episode_id)s
                LIMIT 1""",
            values,
        )
        existing = cursor.fetchone()
        if existing is not None:
            return self._record_consumption(
                cursor=cursor,
                values=values,
                outcome="REFUSED",
                result_ref=str(existing["incident_id"]),
                reason_code="INCIDENT_ALREADY_LINKED",
            )
        incident_id, link_kind = host._open_incident(cursor=cursor, scope=scope, run=dict(run))
        disposition_id = new_identifier("ads")
        disposition = "ESCALATED_NEW" if link_kind == "CREATED" else "ESCALATED_ATTACHED"
        cursor.execute(
            """INSERT INTO solvan_alerts.alert_dispositions
                (organization_id,project_id,environment_id,id,episode_id,triage_run_id,
                 disposition,reason_code,explanation_template_ref,
                 explanation_variables_json,evidence_refs_json,next_owner,created_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(disposition_id)s,
                 %(episode_id)s,%(triage_run_id)s,%(disposition)s,
                 'HUMAN_CONTINUATION_REQUESTED','alert-disposition-v1',%(variables)s,
                 '[]'::jsonb,'incident-coordinator',%(now)s)""",
            {
                **values,
                "disposition_id": disposition_id,
                "triage_run_id": run["id"],
                "disposition": disposition,
                "variables": Jsonb({"operator_request_id": values["id"]}),
            },
        )
        cursor.execute(
            """INSERT INTO solvan_alerts.alert_incident_links
                (organization_id,project_id,environment_id,episode_id,disposition_id,
                 incident_id,link_kind,deduplication_decision,linked_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(episode_id)s,
                 %(disposition_id)s,%(incident_id)s,%(link_kind)s,%(link_kind)s,%(now)s)""",
            {
                **values,
                "disposition_id": disposition_id,
                "incident_id": incident_id,
                "link_kind": link_kind,
            },
        )
        cursor.execute(
            """UPDATE solvan_alerts.alert_episodes
                  SET state=%(state)s,current_disposition=%(disposition)s,
                      row_version=row_version+1
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(episode_id)s""",
            {
                **values,
                "state": "ESCALATED" if link_kind == "CREATED" else "ATTACHED",
                "disposition": disposition,
            },
        )
        record_alert_disposition_event(
            self._connection,
            scope=scope,
            episode_id=str(values["episode_id"]),
            disposition_id=disposition_id,
            disposition=disposition,
            occurred_at=values["now"],
        )
        return self._record_consumption(
            cursor=cursor,
            values=values,
            outcome="INCIDENT_CREATED" if link_kind == "CREATED" else "INCIDENT_ATTACHED",
            result_ref=incident_id,
            reason_code="HUMAN_CONTINUATION_PROCESSED",
        )


def _command_refusal(
    *,
    row_version: int,
    expected_row_version: int,
    episode_state: str,
    provider_state: str,
    policy_availability: Any,
    incident_id: Any,
    request_kind: str,
) -> str | None:
    if row_version != expected_row_version:
        return "STALE_ROW"
    if (
        episode_state in {"SUPPRESSED", "PROVIDER_REPORTED_CLEARED", "EXPIRED"}
        or provider_state != "OPEN"
    ):
        return "TERMINAL_EPISODE"
    if policy_availability != "ELIGIBLE":
        return "POLICY_INELIGIBLE"
    if request_kind == "INCIDENT_CONTINUATION" and incident_id is not None:
        return "INCIDENT_ALREADY_LINKED"
    if request_kind == "RETRIAGE" and episode_state in {"WAITING", "TRIAGING"}:
        return "CAPACITY_UNAVAILABLE"
    return None
