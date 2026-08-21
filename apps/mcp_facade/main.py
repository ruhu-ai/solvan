"""OAuth-bound MCP facade serving exactly ask, catch_up, and resolve_ref."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from contextlib import suppress
from typing import Any, Protocol, cast

from fastapi import FastAPI, Header, HTTPException, status
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apps.api.console_projection import live_console_snapshot
from apps.api.liaison import liaison_registry
from apps.api.liaison_maintenance import sync_scope_events
from apps.api.liaison_service import LiaisonService, sync_projection
from solvan.application.liaison import Anchor, AnchorError, resolve_anchor
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.observability import instrument_fastapi
from solvan.persistence.liaison_catchup import catch_up
from solvan.persistence.liaison_channels import ChannelBindingError, LiaisonChannelStore
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_sequence import Cursor
from solvan.persistence.liaison_store import LiaisonStore
from solvan.platform.database import connect_database

TOOLS = (
    {
        "name": "ask",
        "description": "Ask Solvan about one authorized durable record.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["question", "record_type", "record_id"],
            "properties": {
                "question": {"type": "string", "minLength": 1, "maxLength": 2000},
                "record_type": {"type": "string", "minLength": 1, "maxLength": 40},
                "record_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "thread_id": {"type": "string"},
            },
        },
    },
    {
        "name": "catch_up",
        "description": "Read deterministic committed deltas after an opaque cursor.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["record_type", "record_id"],
            "properties": {
                "record_type": {"type": "string", "minLength": 1, "maxLength": 40},
                "record_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "cursor": {"type": "string"},
            },
        },
    },
    {
        "name": "resolve_ref",
        "description": "Resolve authorized citation metadata, never record bodies.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["record_type", "record_id"],
            "properties": {
                "record_type": {"type": "string", "minLength": 1, "maxLength": 40},
                "record_id": {"type": "string", "minLength": 1, "maxLength": 64},
            },
        },
    },
)
TOOL_LIST_HASH = canonical_sha256(TOOLS)


class JsonRpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: str
    id: str | int | None = None
    method: str
    params: dict[str, Any] | None = None


class EnrollmentConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=16, max_length=128)


class RecordArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_type: str = Field(min_length=1, max_length=40)
    record_id: str = Field(min_length=1, max_length=64)


class AskArguments(RecordArguments):
    question: str = Field(min_length=1, max_length=2_000)
    thread_id: str | None = Field(default=None, min_length=1, max_length=64)


class CatchUpArguments(RecordArguments):
    cursor: str | None = Field(default=None, max_length=512)


class TokenVerifier(Protocol):
    def verify(self, token: str, *, audience: str) -> Mapping[str, Any]: ...


class GoogleTokenVerifier:
    def verify(self, token: str, *, audience: str) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
                token, GoogleRequest(), audience=audience
            ),
        )


class _BorrowedConnection:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def __enter__(self) -> Any:
        return self.connection

    def __exit__(self, *_args: object) -> None:
        return None


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required MCP facade setting {name} is missing")
    return value


def _scope() -> Scope:
    return Scope(
        _required("SOLVAN_ORGANIZATION_ID"),
        _required("SOLVAN_SCOPE_PROJECT_ID"),
        _required("SOLVAN_ENVIRONMENT_ID"),
    )


def _identity(authorization: str | None, verifier: TokenVerifier) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing OAuth bearer token")
    try:
        claims = verifier.verify(
            authorization.removeprefix("Bearer "), audience=_required("SOLVAN_MCP_AUDIENCE")
        )
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid OAuth bearer token") from error
    issuer, subject = claims.get("iss"), claims.get("sub")
    if not isinstance(issuer, str) or not isinstance(subject, str) or not subject:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "OAuth subject is unavailable")
    return f"mcp:{canonical_sha256({'issuer': issuer})[-16:]}:{subject}"


def _validate_tool_hash() -> None:
    if _required("SOLVAN_MCP_TOOL_LIST_HASH") != TOOL_LIST_HASH:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "registered MCP tool list drifted")


def _rpc_result(request: JsonRpcRequest, value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request.id, "result": value}


def _rpc_error(request: JsonRpcRequest, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request.id, "error": {"code": code, "message": message}}


def create_app(*, verifier: TokenVerifier | None = None) -> FastAPI:
    app = FastAPI(title="Solvan MCP Facade", version="0.1.0")
    token_verifier = verifier or GoogleTokenVerifier()

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live", "tool_list_hash": TOOL_LIST_HASH}

    @app.get("/oauth/identity")
    def oauth_identity(authorization: str | None = Header(default=None)) -> dict[str, str]:
        return {"channel_identity": _identity(authorization, token_verifier)}

    @app.post("/oauth/enrollment/confirm")
    def confirm_enrollment(
        request: EnrollmentConfirmation,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str | int]:
        identity = _identity(authorization, token_verifier)
        binding = None
        with (
            connect_database() as connection,
            connection.transaction(),
            suppress(ChannelBindingError),
        ):
            binding = LiaisonChannelStore(connection).consume_enrollment(
                scope=_scope(),
                channel_kind="MCP",
                channel_identity=identity,
                nonce=request.code,
            )
        if binding is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "enrollment proof was refused")
        return {
            "status": "ACTIVE",
            "binding_id": binding.binding_id,
            "connection_epoch": binding.epoch,
        }

    @app.post("/mcp")
    def mcp(
        request: JsonRpcRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if request.jsonrpc != "2.0":
            return _rpc_error(request, -32600, "invalid JSON-RPC version")
        _validate_tool_hash()
        identity = _identity(authorization, token_verifier)
        scope = _scope()
        with connect_database() as connection, connection.transaction():
            binding = LiaisonChannelStore(connection).lock_active_binding(
                scope=scope, channel_kind="MCP", channel_identity=identity
            )
            if binding is None:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "MCP identity is not enrolled")
            if request.method == "initialize":
                return _rpc_result(
                    request,
                    {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "solvan", "version": "0.1.0"},
                    },
                )
            if request.method == "tools/list":
                return _rpc_result(request, {"tools": list(TOOLS)})
            if request.method != "tools/call":
                return _rpc_error(request, -32601, "method not found")
            if request.id is None:
                return _rpc_error(request, -32600, "tool calls require an id")
            params = request.params or {}
            if set(params) != {"name", "arguments"}:
                return _rpc_error(request, -32602, "invalid tool call parameters")
            name, arguments = params.get("name"), params.get("arguments")
            if name not in {item["name"] for item in TOOLS} or not isinstance(arguments, dict):
                return _rpc_error(request, -32602, "invalid tool call")
            snapshot = live_console_snapshot(connection, scope=scope)
            service = LiaisonService(
                connect=lambda: _BorrowedConnection(connection),
                snapshot_provider=lambda: snapshot,
                registry_provider=liaison_registry,
            )
            # The active channel binding supplies the verified human principal;
            # never expose the full console snapshot merely because the MCP
            # request itself is authenticated.  The internal projection sync
            # below uses an unbound reader only for rebuilding the durable
            # directory, never for returning data.
            reader = service.reader(principal=binding.principal, scope=scope, connection=connection)
            if not reader.scope_authorized:
                return _rpc_error(request, -32004, "record is not addressable")
            try:
                parsed: RecordArguments
                if name == "ask":
                    parsed = AskArguments.model_validate(arguments)
                elif name == "catch_up":
                    parsed = CatchUpArguments.model_validate(arguments)
                else:
                    parsed = RecordArguments.model_validate(arguments)
            except ValidationError:
                return _rpc_error(request, -32602, "tool arguments do not match the schema")
            record_type, record_id = parsed.record_type, parsed.record_id
            if (record_type, record_id) not in reader.authorized_records():
                return _rpc_error(request, -32004, "record is not addressable")
            try:
                anchor = resolve_anchor(reader, Anchor.record(record_type, record_id))
            except AnchorError:
                return _rpc_error(request, -32004, "record is not addressable")
            if name == "resolve_ref":
                with projection_read(
                    connection,
                    scope=scope,
                    principal=binding.principal,
                    purpose="incident-investigation",
                    classification_ceiling="CONFIDENTIAL",
                    method="get_record",
                    operation_id=new_identifier("opr"),
                    anchor_label=anchor.label(),
                    authorized_records=reader.authorized_records_for_anchor(anchor),
                ):
                    record = reader.read(record_type, record_id) or {}
                    result = {
                        "record_type": record_type,
                        "record_id": record_id,
                        "service": record.get("service"),
                        "classification": record.get("classification", "INTERNAL"),
                    }
            elif name == "ask":
                assert isinstance(parsed, AskArguments)
                outcome = service.ask(
                    scope=scope,
                    principal=binding.principal,
                    anchor=anchor,
                    question=parsed.question,
                    thread_id=parsed.thread_id,
                    idempotency_key=f"mcp:{binding.binding_id}:{request.id}",
                )
                transcript = LiaisonStore(connection).transcript(
                    scope=scope,
                    thread_id=outcome.thread_id,
                    reader_principal=binding.principal,
                    authorized_records=reader.authorized_records_for_anchor(anchor),
                )
                answer = next(item for item in transcript if item.id == outcome.answer_message_id)
                result = {
                    "thread_id": outcome.thread_id,
                    "state": str(outcome.result.state),
                    "parts": [
                        {"kind": str(part.kind), "payload": part.payload} for part in answer.parts
                    ],
                    "console_url": (
                        f"{_required('SOLVAN_CONSOLE_BASE_URL')}/conversations/{outcome.thread_id}"
                    ),
                }
            else:
                assert isinstance(parsed, CatchUpArguments)
                projection_reader = service.reader()
                sync_projection(LiaisonStore(connection), scope=scope, reader=projection_reader)
                sync_scope_events(connection, scope=scope, reader=projection_reader)
                policy_epoch = current_policy_epoch(
                    connection, scope=scope, principal=binding.principal
                )
                authorized = tuple(reader.authorized_records_for_anchor(anchor))
                with projection_read(
                    connection,
                    scope=scope,
                    principal=binding.principal,
                    purpose="incident-investigation",
                    classification_ceiling="CONFIDENTIAL",
                    method="catch_up",
                    operation_id=new_identifier("opr"),
                    anchor_label=anchor.label(),
                    authorized_records=authorized,
                ):
                    brief = catch_up(
                        connection,
                        scope=scope,
                        anchor=anchor,
                        cursor=Cursor.decode(parsed.cursor, policy_epoch=policy_epoch),
                        authorized_records=authorized,
                        policy_epoch=policy_epoch,
                    )
                result = {
                    "cursor": brief.cursor.encode(),
                    "policy_changed": brief.policy_changed,
                    "remaining": brief.remaining,
                    "deltas": [
                        {
                            "sequence": item.sequence,
                            "record": f"{item.record_type}:{item.record_id}",
                            "phrase": item.phrase,
                            "authority_status": item.authority_status,
                            "reference": item.reference,
                        }
                        for item in brief.deltas
                    ],
                }
        return _rpc_result(
            request,
            {"content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}]},
        )

    return app


app = instrument_fastapi(create_app(), service_name="mcp-facade")
