"""Reader-filtered Alert queue and answer-first report HTTP surface."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, NoReturn, cast

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from psycopg.errors import UndefinedTable
from pydantic import BaseModel, ConfigDict

from apps.api.alert_console_fixture import alert_console_fixture
from apps.api.alert_console_queries import (
    filter_alert_fixture_rows,
    raise_alert_policy_product_error,
    raise_alert_projection_error,
    validate_alert_list_query,
)
from apps.api.session_authorization import session_reader_principal
from solvan.application.alert_list import (
    AlertCursorCodec,
    AlertCursorPosition,
    AlertFilterError,
    AlertListFilter,
)
from solvan.application.alert_policy_products import (
    AlertPolicyRecommendationDismissV1,
    AlertPolicySimulationCommandV1,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.alert_policy_errors import AlertPolicyProductError
from solvan.persistence.alert_triage import AlertTriageRepository
from solvan.persistence.alert_triage_commands import AlertCommandError


class _StrictCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AlertOperatorCommand(_StrictCommand):
    schema_version: int
    expected_row_version: int
    request_reason_code: str


class AlertFeedbackCommand(_StrictCommand):
    schema_version: int
    category: str
    note_ref: str | None = None


def alert_console_router(
    *,
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
    command_principal_provider: Callable[[str | None], str] | None = None,
    connect: Callable[[], Any],
    local_mode_provider: Callable[[], bool],
    cursor_signing_key_provider: Callable[[], bytes],
) -> APIRouter:
    router = APIRouter()
    command_principal = command_principal_provider or principal_provider

    def _reader(connection: Any, request: Request, identity_token: str | None) -> str:
        """Who is reading, session first, then the audience-bound identity grant.

        The browser carries the specification 05 §4.2 session; a non-browser
        caller carries the verified token. Both derive the principal from
        verified claims — never from a header value — and the per-route grant
        check below is what admits either to a record.
        """

        return session_reader_principal(connection, request) or principal_provider(identity_token)

    @router.get("/api/alerts")
    def list_alerts(
        request: Request,
        response: Response,
        filter_value: Annotated[str | None, Query(alias="filter")] = None,
        cursor_value: Annotated[str | None, Query(alias="cursor")] = None,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        validate_alert_list_query(request)
        try:
            alert_filter = AlertListFilter.from_encoded(filter_value)
            codec = AlertCursorCodec(signing_key=cursor_signing_key_provider())
        except (AlertFilterError, ValueError) as error:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "INVALID_ALERT_FILTER"
            ) from error
        response.headers["Cache-Control"] = "private, no-store"
        if local_mode_provider():
            if cursor_value is not None:
                raise HTTPException(422, "INVALID_ALERT_FILTER")
            projection = alert_console_fixture()["list"]
            projection["filter"] = alert_filter.canonical_dict()
            projection["rows"] = filter_alert_fixture_rows(projection["rows"], alert_filter)
            projection["next_cursor"] = None
            projection["projection_digest"] = canonical_sha256(projection)
            return cast("dict[str, Any]", projection)
        try:
            with connect() as connection, connection.transaction():
                principal = _reader(connection, request, identity_token)
                scope = scope_provider()
                repository = AlertTriageRepository(connection)
                epochs = repository.get_alert_list_context(scope=scope, principal=principal)
                cursor_position = codec.decode(
                    cursor_value,
                    filter_digest=alert_filter.digest,
                    principal=principal,
                    scope=scope,
                    **epochs,
                )
                projection = repository.list_alerts(
                    scope=scope, alert_filter=alert_filter, cursor_position=cursor_position
                )
                position = projection.pop("_next_cursor_position")
                projection.update(epochs)
                projection["next_cursor"] = (
                    codec.encode(
                        position=cast("AlertCursorPosition", position),
                        filter_digest=alert_filter.digest,
                        principal=principal,
                        scope=scope,
                        **epochs,
                    )
                    if position is not None
                    else None
                )
                projection["projection_digest"] = canonical_sha256(projection)
                return projection
        except PermissionError as error:
            raise HTTPException(403, str(error)) from error
        except (AlertFilterError, ValueError, UndefinedTable) as error:
            raise_alert_projection_error(error)

    @router.get("/api/alerts/{alert_episode_id}")
    def get_alert(
        alert_episode_id: str,
        request: Request,
        response: Response,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        if local_mode_provider():
            report = alert_console_fixture()["reports"].get(alert_episode_id)
        else:
            try:
                with connect() as connection, connection.transaction():
                    principal = _reader(connection, request, identity_token)
                    scope = scope_provider()
                    _require_alert_reader(connection, scope=scope, principal=principal)
                    repository = AlertTriageRepository(connection)
                    report = repository.get_alert_report(scope=scope, episode_id=alert_episode_id)
                    if report is not None:
                        epochs = repository.get_alert_list_context(scope=scope, principal=principal)
                        header = report["header"]
                        report.update(epochs)
                        report["reader_cursor"] = AlertCursorCodec(
                            signing_key=cursor_signing_key_provider()
                        ).encode(
                            position=AlertCursorPosition(
                                severity_rank={
                                    "SEV1": 1,
                                    "SEV2": 2,
                                    "SEV3": 3,
                                    "SEV4": 4,
                                }[header["severity"]],
                                attention_rank=(0 if header["required_human_attention"] else 1),
                                last_seen_at=datetime.fromisoformat(header["last_seen_at"]),
                                alert_episode_id=alert_episode_id,
                            ),
                            filter_digest=canonical_sha256(
                                {
                                    "schema_version": 1,
                                    "kind": "ALERT_REPORT",
                                    "alert_episode_id": alert_episode_id,
                                }
                            ),
                            principal=principal,
                            scope=scope,
                            **epochs,
                        )
                        report["projection_digest"] = canonical_sha256(report)
            except UndefinedTable as error:
                raise_alert_projection_error(error)
        if report is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
        return cast("dict[str, Any]", report)

    for suffix, projection_kind in (
        ("events", "EVENTS"),
        ("triage-runs", "TRIAGE_RUNS"),
        ("dispositions", "DISPOSITIONS"),
        ("incident-links", "INCIDENT_LINKS"),
        ("channel-delivery-attempts", "CHANNEL_DELIVERIES"),
    ):
        router.add_api_route(
            f"/api/alerts/{{alert_episode_id}}/{suffix}",
            _alert_subresource_handler(
                projection_kind=projection_kind,
                scope_provider=scope_provider,
                principal_provider=principal_provider,
                connect=connect,
                local_mode_provider=local_mode_provider,
            ),
            methods=["GET"],
            name=f"get_alert_{suffix.replace('-', '_')}",
        )

    @router.post("/api/alerts/{alert_episode_id}/request-retriage", status_code=202)
    def request_retriage(
        alert_episode_id: str,
        request: AlertOperatorCommand,
        authorization: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        return _record_alert_command(
            request_kind="RETRIAGE",
            alert_episode_id=alert_episode_id,
            request=request,
            authorization=authorization,
            idempotency_key=idempotency_key,
            principal_provider=command_principal,
            scope_provider=scope_provider,
            connect=connect,
        )

    @router.post("/api/alerts/{alert_episode_id}/request-incident-continuation", status_code=202)
    def request_incident_continuation(
        alert_episode_id: str,
        request: AlertOperatorCommand,
        authorization: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        return _record_alert_command(
            request_kind="INCIDENT_CONTINUATION",
            alert_episode_id=alert_episode_id,
            request=request,
            authorization=authorization,
            idempotency_key=idempotency_key,
            principal_provider=command_principal,
            scope_provider=scope_provider,
            connect=connect,
        )

    @router.post("/api/alerts/{alert_episode_id}/feedback", status_code=202)
    def record_feedback(
        alert_episode_id: str,
        request: AlertFeedbackCommand,
        authorization: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = command_principal(authorization)
        key = _idempotency_key(idempotency_key)
        if request.schema_version != 1:
            raise HTTPException(422, "INVALID_ALERT_FEEDBACK")
        try:
            with connect() as connection, connection.transaction():
                _require_alert_operator(connection, scope=scope_provider(), principal=principal)
                result = AlertTriageRepository(connection).record_feedback(
                    scope=scope_provider(),
                    episode_id=alert_episode_id,
                    category=request.category,
                    note_ref=request.note_ref,
                    actor_principal=principal,
                    idempotency_key=key,
                )
        except (ValueError, AlertCommandError) as error:
            _raise_command_error(error)
        return {
            "schema_version": 1,
            "feedback_id": result.feedback_id,
            "alert_episode_id": result.episode_id,
            "created": result.created,
            "effect": "REVIEW_SIGNAL_ONLY",
        }

    @router.get("/api/fleet/alert-policies")
    def list_alert_policies(
        request: Request,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        if local_mode_provider():
            return cast("dict[str, Any]", alert_console_fixture()["policies"])
        with connect() as connection, connection.transaction():
            principal = _reader(connection, request, identity_token)
            _require_alert_reader(connection, scope=scope_provider(), principal=principal)
            return AlertTriageRepository(connection).list_alert_policies(scope=scope_provider())

    @router.get("/api/fleet/alert-capacity")
    def alert_capacity(
        request: Request,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        if local_mode_provider():
            return cast("dict[str, Any]", alert_console_fixture()["capacity"])
        with connect() as connection, connection.transaction():
            principal = _reader(connection, request, identity_token)
            _require_alert_reader(connection, scope=scope_provider(), principal=principal)
            return AlertTriageRepository(connection).get_alert_capacity(scope=scope_provider())

    @router.get("/api/incidents/{incident_id}/related-alerts")
    def incident_related_alerts(
        incident_id: str,
        request: Request,
        response: Response,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        if local_mode_provider():
            result = alert_console_fixture()["related_alerts"].get(incident_id)
        else:
            with connect() as connection, connection.transaction():
                principal = _reader(connection, request, identity_token)
                scope = scope_provider()
                _require_alert_reader(connection, scope=scope, principal=principal)
                repository = AlertTriageRepository(connection)
                result = repository.get_incident_related_alerts(
                    scope=scope, incident_id=incident_id
                )
                if result is not None:
                    epochs = repository.get_alert_list_context(scope=scope, principal=principal)
                    result["placement_epoch"] = epochs["placement_epoch"]
                    result["membership_epoch"] = epochs["membership_epoch"]
                    result["projection_digest"] = canonical_sha256(result)
        if result is None:
            raise HTTPException(404, "incident not found")
        return cast("dict[str, Any]", result)

    @router.get("/api/fleet/alert-policy-templates")
    def list_alert_policy_templates(
        request: Request,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        if local_mode_provider():
            return cast("dict[str, Any]", alert_console_fixture()["policy_templates"])
        with connect() as connection, connection.transaction():
            principal = _reader(connection, request, identity_token)
            scope = scope_provider()
            _require_alert_reader(connection, scope=scope, principal=principal)
            return AlertTriageRepository(connection).list_alert_policy_templates(scope=scope)

    @router.get("/api/fleet/alert-policy-recommendations")
    def list_alert_policy_recommendations(
        request: Request,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        if local_mode_provider():
            return cast("dict[str, Any]", alert_console_fixture()["recommendations"])
        with connect() as connection, connection.transaction():
            principal = _reader(connection, request, identity_token)
            scope = scope_provider()
            _require_alert_reader(connection, scope=scope, principal=principal)
            return AlertTriageRepository(connection).list_alert_policy_recommendations(scope=scope)

    @router.post("/api/fleet/alert-policy-simulations", status_code=201)
    def simulate_alert_policy(
        command: AlertPolicySimulationCommandV1,
        authorization: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        principal = command_principal(authorization)
        if local_mode_provider():
            receipt = dict(alert_console_fixture()["simulation_receipt"])
            receipt["request_hash"] = command.request_hash
            receipt["draft_policy_key"] = command.draft_policy_key
            receipt["draft_version"] = command.draft_version
            receipt["draft_digest"] = command.expected_draft_digest
            receipt["sample_provider_generation_id"] = command.sample_provider_generation_id
            receipt["sample_digest"] = command.expected_sample_digest
            return receipt
        try:
            with connect() as connection, connection.transaction():
                scope = scope_provider()
                _require_alert_policy_author(connection, scope=scope, principal=principal)
                return AlertTriageRepository(connection).simulate_alert_policy(
                    scope=scope, principal=principal, command=command
                )
        except AlertPolicyProductError as error:
            raise_alert_policy_product_error(error)

    @router.post(
        "/api/admin/alert-policy-recommendations/{recommendation_id}/dismiss",
        status_code=201,
    )
    def dismiss_alert_policy_recommendation(
        recommendation_id: str,
        command: AlertPolicyRecommendationDismissV1,
        authorization: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        principal = command_principal(authorization)
        if local_mode_provider():
            return {
                "schema_version": 1,
                "id": "ard_01K2M7Y8F90H6J1K3M5N7P9QRS",
                "decision_epoch": command.expected_decision_epoch + 1,
                "decision_kind": "DISMISSED",
                "created": True,
            }
        try:
            with connect() as connection, connection.transaction():
                scope = scope_provider()
                role = _require_alert_policy_author(connection, scope=scope, principal=principal)
                return AlertTriageRepository(connection).dismiss_alert_policy_recommendation(
                    scope=scope,
                    recommendation_id=recommendation_id,
                    principal=principal,
                    actor_role=role,
                    command=command,
                )
        except AlertPolicyProductError as error:
            raise_alert_policy_product_error(error)

    @router.get("/api/fleet/alert-policies/{policy_key}/revisions/{version}")
    def get_alert_policy_revision(
        policy_key: str,
        version: str,
        request: Request,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        if local_mode_provider():
            rows = alert_console_fixture()["policies"]["rows"]
            policy = next(
                (
                    item
                    for item in rows
                    if item["policy_key"] == policy_key and item["version"] == version
                ),
                None,
            )
            if policy is None:
                raise HTTPException(404, "alert policy not found")
            # Mirror the deployed decomposition: source facts are lifted out of
            # the policy record into the bound-connection list, so the console
            # renders the same shape here as it does against Cloud SQL.
            connection_keys = {
                "connection_id",
                "connection_epoch",
                "connection_health",
                "connection_reason_code",
                "connection_binding_current",
            }
            return {
                "schema_version": 1,
                "policy": {
                    key: value for key, value in policy.items() if key not in connection_keys
                },
                "connections": [
                    {
                        "connection_id": policy["connection_id"],
                        "connection_epoch": policy["connection_epoch"],
                        "health": policy["connection_health"],
                        "reason_code": policy["connection_reason_code"],
                        "lifecycle": "ENABLED",
                        "binding_current": policy["connection_binding_current"],
                        "last_probe_at": policy["last_triage_at"],
                        "last_probe_result": "SUCCEEDED",
                    }
                ],
            }
        with connect() as connection, connection.transaction():
            principal = _reader(connection, request, identity_token)
            _require_alert_reader(connection, scope=scope_provider(), principal=principal)
            result = AlertTriageRepository(connection).get_alert_policy_revision(
                scope=scope_provider(), policy_key=policy_key, version=version
            )
        if result is None:
            raise HTTPException(404, "alert policy not found")
        return result

    return router


def _alert_subresource_handler(
    *,
    projection_kind: str,
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
    connect: Callable[[], Any],
    local_mode_provider: Callable[[], bool],
) -> Callable[..., dict[str, Any]]:
    def handler(
        alert_episode_id: str,
        request: Request,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Identity-Token"),
    ) -> dict[str, Any]:
        if local_mode_provider():
            report = alert_console_fixture()["reports"].get(alert_episode_id)
            if report is None:
                raise HTTPException(404, "alert not found")
            return {
                "schema_version": 1,
                "alert_episode_id": alert_episode_id,
                "items": report.get("subresources", {}).get(projection_kind, []),
            }
        with connect() as connection, connection.transaction():
            principal = session_reader_principal(connection, request) or principal_provider(
                identity_token
            )
            _require_alert_reader(connection, scope=scope_provider(), principal=principal)
            result = AlertTriageRepository(connection).get_alert_subresource(
                scope=scope_provider(), episode_id=alert_episode_id, kind=projection_kind
            )
        if result is None:
            raise HTTPException(404, "alert not found")
        return result

    return handler


def _record_alert_command(
    *,
    request_kind: str,
    alert_episode_id: str,
    request: AlertOperatorCommand,
    authorization: str | None,
    idempotency_key: str | None,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
) -> dict[str, Any]:
    if request.schema_version != 1:
        raise HTTPException(422, "INVALID_ALERT_COMMAND")
    principal = principal_provider(authorization)
    key = _idempotency_key(idempotency_key)
    scope = scope_provider()
    try:
        with connect() as connection, connection.transaction():
            _require_alert_operator(connection, scope=scope, principal=principal)
            result = AlertTriageRepository(connection).record_operator_request(
                scope=scope,
                episode_id=alert_episode_id,
                request_kind=request_kind,
                expected_row_version=request.expected_row_version,
                request_reason_code=request.request_reason_code,
                actor_principal=principal,
                idempotency_key=key,
            )
    except (ValueError, AlertCommandError) as error:
        _raise_command_error(error)
    if result.outcome == "REFUSED":
        _raise_command_error(AlertCommandError(result.refusal_code or "POLICY_INELIGIBLE"))
    return {
        "schema_version": 1,
        "request_id": result.request_id,
        "alert_episode_id": result.episode_id,
        "request_kind": result.request_kind,
        "status": "ACCEPTED",
        "created": result.created,
    }


def _require_alert_operator(connection: Any, *, scope: Scope, principal: str) -> None:
    row = connection.execute(
        """SELECT 1 FROM solvan.actor_role_bindings
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND principal=%(principal)s
              AND role IN ('OPERATOR','ADMIN') AND (expires_at IS NULL OR expires_at>now())
            LIMIT 1""",
        {**scope.canonical_dict(), "principal": principal},
    ).fetchone()
    if row is None:
        raise HTTPException(403, "alert operator grant is inactive")


def _require_alert_reader(connection: Any, *, scope: Scope, principal: str) -> None:
    row = connection.execute(
        """SELECT 1 FROM solvan.actor_role_bindings
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND principal=%(principal)s
              AND role IN ('OPERATOR','APPROVER','ADMIN')
              AND (expires_at IS NULL OR expires_at>clock_timestamp())
            LIMIT 1""",
        {**scope.canonical_dict(), "principal": principal},
    ).fetchone()
    if row is None:
        raise HTTPException(403, "alert reader grant is inactive")


def _require_alert_policy_author(connection: Any, *, scope: Scope, principal: str) -> str:
    row = connection.execute(
        """SELECT role FROM solvan.actor_role_bindings
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND principal=%(principal)s
              AND role IN ('TRIGGER_POLICY_AUTHOR','OPERABILITY_ADMIN')
              AND (expires_at IS NULL OR expires_at>clock_timestamp())
            ORDER BY CASE role WHEN 'TRIGGER_POLICY_AUTHOR' THEN 0 ELSE 1 END
            LIMIT 1""",
        {**scope.canonical_dict(), "principal": principal},
    ).fetchone()
    if row is None:
        raise HTTPException(403, "trigger policy author grant is inactive")
    return str(row[0])


def _idempotency_key(value: str | None) -> str:
    if value is None or not 8 <= len(value) <= 128:
        raise HTTPException(422, "Idempotency-Key is required")
    return value


def _raise_command_error(error: Exception) -> NoReturn:
    code = str(error)
    status_code = 404 if code == "ALERT_NOT_FOUND" else 409
    if code in {"INVALID_ALERT_COMMAND", "INVALID_ALERT_FEEDBACK"}:
        status_code = 422
    if code == "CAPACITY_UNAVAILABLE":
        status_code = 429
    raise HTTPException(status_code, code) from error
