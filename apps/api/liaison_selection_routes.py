"""Reader-filtered central-Chat directory and receipt-bound attachment routes."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from apps.api.liaison_http_support import _claim_json_operation, _complete_json_operation
from apps.api.liaison_reader import SnapshotProjectionReader
from apps.api.liaison_types import request_digest
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import canonical_hash
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_selection import LiaisonSelectionStore, RecordSelectionError
from solvan.persistence.liaison_service_selection import (
    LiaisonServiceSelectionStore,
    ServiceSelectionError,
)
from solvan.persistence.liaison_store import LiaisonStore


class SelectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    record_type: str = Field(min_length=1, max_length=40)
    record_id: str = Field(min_length=1, max_length=64)


class SelectionOpenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]


class ServiceSelectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    service_key: str = Field(min_length=1, max_length=120)
    window_start: datetime
    window_end: datetime


def _service_records(
    reader: SnapshotProjectionReader, service_key: str
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (kind, identifier)
        for kind, identifier in reader.authorized_records()
        if (record := reader.read(kind, identifier)) is not None
        and str(record.get("service", "")) == service_key
    )


def _validate_window(start: datetime, end: datetime) -> None:
    now = datetime.now(UTC)
    if start.tzinfo is None or end.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "window must include timezone")
    if end <= start or end - start > timedelta(hours=24):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "window is not bounded")
    if start < now - timedelta(days=180) or end > now + timedelta(minutes=5):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "window is outside retention")


def _cursor_encode(record_type: str, record_id: str) -> str:
    raw = json.dumps([record_type, record_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _cursor_decode(cursor: str | None) -> tuple[str, str] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError
        return str(value[0]), str(value[1])
    except (ValueError, TypeError, json.JSONDecodeError) as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "directory cursor is invalid") from error


def _record_revision(record: Mapping[str, Any]) -> str:
    for key in ("workflow_version", "version", "revision", "updated_at"):
        if key in record:
            return canonical_hash(
                {
                    "identity": record.get("machine_id", record.get("id")),
                    "version": str(record[key]),
                }
            )
    return canonical_hash(dict(record))


def register_selection_routes(
    router: APIRouter,
    *,
    connect: Callable[[], Any],
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
    reader_provider: Callable[..., SnapshotProjectionReader],
) -> None:
    @router.get("/api/v1/liaison/directory")
    def directory(
        search: str = Query(default="", max_length=100),
        record_type: str = Query(default="incident", max_length=40),
        service: str | None = Query(default=None, max_length=120),
        state: str | None = Query(default=None, max_length=40),
        cursor: str | None = Query(default=None, max_length=256),
        limit: int = Query(default=20, ge=1, le=50),
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """List only records the verified reader can already address."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "directory is unavailable")
        authorized = tuple(reader.authorized_records())
        with (
            connect() as connection,
            connection.transaction(),
            projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="list_directory",
                operation_id=new_identifier("opr"),
                anchor_label="SCOPE",
                authorized_records=authorized,
            ),
        ):
            start_after = _cursor_decode(cursor)
            needle = search.strip().casefold()
            rows: list[dict[str, Any]] = []
            for candidate_type, candidate_id in sorted(authorized):
                if start_after is not None and (candidate_type, candidate_id) <= start_after:
                    continue
                if record_type and candidate_type != record_type:
                    continue
                record = reader.read(candidate_type, candidate_id)
                if record is None:
                    continue
                candidate_service = str(record.get("service", ""))
                candidate_state = str(record.get("state", record.get("status", "")))
                title = str(record.get("title", record.get("name", candidate_id)))[:200]
                if service and candidate_service != service:
                    continue
                if state and candidate_state.casefold() != state.casefold():
                    continue
                if (
                    needle
                    and needle
                    not in " ".join(
                        (candidate_id, title, candidate_service, candidate_state)
                    ).casefold()
                ):
                    continue
                rows.append(
                    {
                        "record_type": candidate_type,
                        "record_id": candidate_id,
                        "title": title,
                        "service": candidate_service,
                        "state": candidate_state,
                        "severity": str(record.get("severity", "")),
                        "revision": _record_revision(record),
                    }
                )
                if len(rows) > limit:
                    break
        has_more = len(rows) > limit
        page = rows[:limit]
        return {
            "items": page,
            "next_cursor": (
                _cursor_encode(page[-1]["record_type"], page[-1]["record_id"])
                if has_more and page
                else None
            ),
        }

    @router.get("/api/v1/liaison/services")
    def services(
        search: str = Query(default="", max_length=100),
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """Reader-filtered registry keys for explicit service-window selection."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "service directory is unavailable")
        authorized = tuple(reader.authorized_records())
        needle = search.strip().casefold()
        counts: dict[str, int] = {}
        for kind, identifier in authorized:
            record = reader.read(kind, identifier)
            key = str(record.get("service", "")) if record else ""
            if key and (not needle or needle in key.casefold()):
                counts[key] = counts.get(key, 0) + 1
        with (
            connect() as connection,
            connection.transaction(),
            projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="list_directory",
                operation_id=new_identifier("opr"),
                anchor_label="SCOPE",
                authorized_records=authorized,
            ),
        ):
            items = [
                {"service_key": key, "visible_record_count": count}
                for key, count in sorted(counts.items())
            ]
        return {"items": items}

    @router.post("/api/v1/liaison/service-selections")
    def issue_service_selection(
        request: ServiceSelectionRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        _validate_window(request.window_start, request.window_end)
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        records = _service_records(reader, request.service_key)
        if not reader.scope_authorized or not records:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "service selection is unavailable")
        operation = "liaison.service_selection.issue"
        body = {**request.model_dump(mode="json"), "principal": principal}
        with connect() as connection, connection.transaction():
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request=body,
            )
            if replay is not None:
                return replay
            selected = LiaisonServiceSelectionStore(connection).issue(
                scope=scope,
                principal=principal,
                service_key=request.service_key,
                window_start=request.window_start,
                window_end=request.window_end,
                records=records,
                request_hash=canonical_hash(body),
            )
            response = {
                "selection_receipt_id": selected.id,
                "service_key": selected.service_key,
                "window_start": selected.window_start.isoformat(),
                "window_end": selected.window_end.isoformat(),
                "expires_at": selected.expires_at.isoformat(),
            }
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key or "",
                operation=operation,
                response=response,
            )
            return response

    @router.post("/api/v1/liaison/service-selections/{receipt_id}:open")
    def open_service_selection(
        receipt_id: str,
        request: SelectionOpenRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        operation = "liaison.service_selection.open"
        body = {
            "receipt_id": receipt_id,
            "schema_version": request.schema_version,
            "principal": principal,
        }
        try:
            with connect() as connection, connection.transaction():
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request=body,
                )
                if replay is not None:
                    return replay
                selections = LiaisonServiceSelectionStore(connection)
                service_key, _start, _end, _digest = selections.candidate(
                    scope=scope, principal=principal, receipt_id=receipt_id
                )
                consumed = selections.consume(
                    scope=scope,
                    principal=principal,
                    receipt_id=receipt_id,
                    current_records=_service_records(reader, service_key),
                )
                response = {
                    "selection_receipt_id": consumed.receipt_id,
                    "thread_id": consumed.thread_id,
                    "anchor_kind": "SERVICE_WINDOW",
                    "service_key": consumed.service_key,
                    "window_start": consumed.window_start.isoformat(),
                    "window_end": consumed.window_end.isoformat(),
                }
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key or "",
                    operation=operation,
                    response=response,
                )
                return response
        except ServiceSelectionError as error:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "service selection is unavailable"
            ) from error

    @router.post("/api/v1/liaison/selections")
    def issue_selection(
        request: SelectionRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        record = reader.read(request.record_type, request.record_id)
        if (
            not reader.scope_authorized
            or record is None
            or (request.record_type, request.record_id) not in set(reader.authorized_records())
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record selection is unavailable")
        body = {**request.model_dump(), "principal": principal}
        operation = "liaison.selection.issue"
        with connect() as connection, connection.transaction():
            LiaisonStore(connection).sync_directory(
                scope=scope,
                records=[
                    (
                        request.record_type,
                        request.record_id,
                        str(record.get("service")) if record.get("service") else None,
                        str(record.get("classification", "INTERNAL")).split(" ")[0],
                    )
                ],
            )
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request=body,
            )
            if replay is not None:
                return replay
            selection = LiaisonSelectionStore(connection).issue(
                scope=scope,
                principal=principal,
                record_type=request.record_type,
                record_id=request.record_id,
                record_revision=_record_revision(record),
                request_hash=request_digest(
                    principal=principal,
                    anchor=f"{request.record_type}:{request.record_id}",
                    question="record-selection",
                    thread_id=None,
                ),
            )
            response = {
                "selection_receipt_id": selection.id,
                "record_type": selection.record_type,
                "record_id": selection.record_id,
                "record_revision": selection.record_revision,
                "expires_at": selection.expires_at,
            }
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key or "",
                operation=operation,
                response=response,
            )
            return response

    @router.post("/api/v1/liaison/selections/{receipt_id}:open")
    def open_selection(
        receipt_id: str,
        request: SelectionOpenRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        operation = "liaison.selection.open"
        body = {
            "receipt_id": receipt_id,
            "schema_version": request.schema_version,
            "principal": principal,
        }
        try:
            with connect() as connection, connection.transaction():
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request=body,
                )
                if replay is not None:
                    return replay
                selections = LiaisonSelectionStore(connection)
                record_type, record_id, _ = selections.candidate(
                    scope=scope, principal=principal, receipt_id=receipt_id
                )
                record = reader.read(record_type, record_id)
                if (
                    not reader.scope_authorized
                    or record is None
                    or (record_type, record_id) not in set(reader.authorized_records())
                ):
                    raise RecordSelectionError("record selection is unavailable")
                consumed = selections.consume(
                    scope=scope,
                    principal=principal,
                    receipt_id=receipt_id,
                    current_record_revision=_record_revision(record),
                )
                response = {
                    "selection_receipt_id": consumed.receipt_id,
                    "thread_id": consumed.thread_id,
                    "anchor_kind": "RECORD",
                    "record_type": consumed.record_type,
                    "record_id": consumed.record_id,
                }
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key or "",
                    operation=operation,
                    response=response,
                )
                return response
        except RecordSelectionError as error:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "record selection is unavailable"
            ) from error
