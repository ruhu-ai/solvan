"""Quarantine-first attachment routes for participant-authored messages."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Header, HTTPException, UploadFile, status

from apps.api.liaison_http_support import _claim_json_operation, _complete_json_operation
from solvan.application.liaison.redaction import classify
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_store import LiaisonStore

_MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024
_TEXT_MIME = frozenset({"text/plain", "text/csv", "application/json"})
_IMAGE_SIGNATURES = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
}


def _scan_attachment(*, claimed_mime: str, content: bytes) -> tuple[str, str]:
    """Return `(verdict, classification)` without sending bytes to a model.

    This narrow local scanner deliberately cleans only inert text and two image
    formats whose magic bytes match. Archives, office documents, scripts,
    executables, malformed text, credentials, and PII are blocked until a
    separately qualified malware/DLP service exists.
    """

    if not content or len(content) > _MAX_ATTACHMENT_BYTES:
        return "BLOCKED", "RESTRICTED"
    if claimed_mime in _TEXT_MIME:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return "BLOCKED", "RESTRICTED"
        verdict = classify(text)
        if verdict.withheld:
            return "BLOCKED", str(verdict.classification)
        return "CLEAN", str(verdict.classification)
    signature = _IMAGE_SIGNATURES.get(claimed_mime)
    if signature is not None and content.startswith(signature):
        return "CLEAN", "INTERNAL"
    return "BLOCKED", "RESTRICTED"


def register_attachment_routes(
    router: APIRouter,
    *,
    connect: Callable[[], Any],
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
    quarantine_dir: Path,
) -> None:
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    @router.post("/api/v1/threads/{thread_id}/messages/{message_id}/attachments")
    async def upload_attachment(
        thread_id: str,
        message_id: str,
        attachment: Annotated[UploadFile, File()],
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        mime = (attachment.content_type or "application/octet-stream").lower().split(";", 1)[0]
        content = await attachment.read(_MAX_ATTACHMENT_BYTES + 1)
        await attachment.close()
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        scan_status, classification = _scan_attachment(claimed_mime=mime, content=content)
        attachment_id = new_identifier("att")
        target = quarantine_dir.resolve() / attachment_id

        wrote_object = False
        try:
            with connect() as connection, connection.transaction():
                operation = "liaison.attachment.upload"
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request={
                        "thread_id": thread_id,
                        "message_id": message_id,
                        "content_hash": digest,
                        "mime": mime,
                    },
                )
                if replay is not None:
                    return replay
                store = LiaisonStore(connection)
                if principal not in store.participants(scope=scope, thread_id=thread_id):
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
                message = connection.execute(
                    """SELECT 1 FROM solvan_liaison.liaison_messages
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(message_id)s
                      AND thread_id=%(thread_id)s AND role='USER'
                      AND author_principal=%(principal)s AND deleted_at IS NULL""",
                    {
                        **scope.canonical_dict(),
                        "message_id": message_id,
                        "thread_id": thread_id,
                        "principal": principal,
                    },
                ).fetchone()
                if message is None:
                    raise HTTPException(
                        status.HTTP_404_NOT_FOUND, "message not found in this scope"
                    )

                object_ref = f"blocked://{digest}"
                if scan_status == "CLEAN":
                    # The local harness is explicitly non-production. A deployed
                    # store replaces this adapter with the CMEK quarantine bucket;
                    # the database contract remains the same.
                    target.write_bytes(content)
                    wrote_object = True
                    object_ref = target.as_uri()
                connection.execute(
                    """INSERT INTO solvan_liaison.liaison_attachments (
                      organization_id,project_id,environment_id,id,message_id,object_ref,
                      content_hash,mime,size_bytes,scan_status,classification,purge_after)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(message_id)s,%(object_ref)s,%(content_hash)s,%(mime)s,%(size_bytes)s,
                      %(scan_status)s,%(classification)s,now()+interval '7 days')""",
                    {
                        **scope.canonical_dict(),
                        "id": attachment_id,
                        "message_id": message_id,
                        "object_ref": object_ref,
                        "content_hash": digest,
                        "mime": mime,
                        "size_bytes": len(content),
                        "scan_status": scan_status,
                        "classification": classification,
                    },
                )
                response = {
                    "attachment_id": attachment_id,
                    "message_id": message_id,
                    "scan_status": scan_status,
                    "classification": classification,
                    "mime": mime,
                    "size_bytes": len(content),
                }
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key or "",
                    operation=operation,
                    response=response,
                )
        except Exception:
            # Local filesystem writes cannot enlist in PostgreSQL. Compensate
            # a failed transaction so no untracked clean object survives.
            if wrote_object:
                target.unlink(missing_ok=True)
            raise
        # A blocked upload never leaves request memory. The response names only
        # its durable verdict, not bytes, filename, object path, or scanner detail.
        return response

    @router.get("/api/v1/threads/{thread_id}/messages/{message_id}/attachments")
    def list_attachments(
        thread_id: str,
        message_id: str,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        with connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            if principal not in store.participants(scope=scope, thread_id=thread_id):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            membership_epoch = store.current_membership_epoch(
                scope=scope, thread_id=thread_id, principal=principal
            )
            with projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="read_attachment",
                operation_id=new_identifier("opr"),
                anchor_label=thread.anchor.label(),
                authorized_records=(),
                membership_epoch=membership_epoch,
            ):
                rows = connection.execute(
                    """SELECT id,scan_status,classification,mime,size_bytes
                         FROM solvan_liaison.liaison_attachments
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND message_id=%(message_id)s
                          AND deleted_at IS NULL ORDER BY id""",
                    {**scope.canonical_dict(), "message_id": message_id},
                ).fetchall()
        return {
            "message_id": message_id,
            "attachments": [
                {
                    "attachment_id": str(row[0]),
                    "scan_status": str(row[1]),
                    "classification": str(row[2]),
                    "mime": str(row[3]),
                    "size_bytes": int(row[4]),
                }
                for row in rows
            ],
        }
