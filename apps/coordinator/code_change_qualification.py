"""Coordinator-owned recovery loop for Code Change qualification commands."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.application.delivery_commands import (
    DeliveryCommandKind,
    DeliveryCommandStatus,
    PrivateCommandEnvelope,
    PrivateCommandRecord,
    payload_schema_hash,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import new_identifier
from solvan.persistence.code_change_qualification_store import (
    PostgresCodeChangeQualificationStore,
    QualificationIntent,
)
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_release import (
    GitHubReleaseProviderClient,
    GoogleIdentityTokenProvider,
)
from solvan.platform.google_rest import authorized_session


def advance_code_change_qualifications(
    *, settings: CoordinatorSettings, connection: Connection[Any]
) -> None:
    """Recover intent creation and provider delivery independently of HTTP retries."""

    config = settings.github_release
    if config is None:
        return
    store = PostgresCodeChangeQualificationStore(connection)
    for pending in store.pending_approved_patches(scope=settings.scope):
        with connection.transaction():
            store.prepare_intent(
                scope=settings.scope,
                patch_artifact_id=pending.patch_artifact_id,
                requested_by_principal=pending.requested_by_principal,
                now=_now(),
            )
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    commands = PostgresDeliveryCommandStore(connection)
    with httpx.Client() as transport:
        client = GitHubReleaseProviderClient(
            config=config,
            client=transport,
            token_provider=GoogleIdentityTokenProvider(),
        )
        for intent in store.dispatchable_intents(scope=settings.scope):
            command = _load_or_prepare_command(
                settings=settings,
                intent=intent,
                commands=commands,
                reader=reader,
                writer=writer,
                connection=connection,
                provider_audience=config.audience,
            )
            client.execute_private_command(
                PrivateCommandEnvelope(
                    command_id=command.command_id, payload=command.payload
                ).model_dump(mode="json")
            )
    with connection.transaction():
        store.create_qualified_requests(
            scope=settings.scope,
            coordinator_identity=settings.coordinator_principal,
        )


def _load_or_prepare_command(
    *,
    settings: CoordinatorSettings,
    intent: QualificationIntent,
    commands: PostgresDeliveryCommandStore,
    reader: GcsEvidenceReader,
    writer: GcsEvidenceWriter,
    connection: Connection[Any],
    provider_audience: str,
) -> PrivateCommandRecord:
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT id FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind='QUALIFY_CODE_CHANGE' AND subject_id=%(intent_id)s
                ORDER BY created_at LIMIT 1""",
            {**settings.scope.canonical_dict(), "intent_id": intent.intent_id},
        )
        row = cursor.fetchone()
    if row is not None:
        return commands.load(command_id=str(row[0]), payload_reader=reader)
    payload: dict[str, object] = {}
    command_id = new_identifier("cmd")
    payload_receipt = writer.put_json(
        object_name=(
            f"{settings.scope.organization_id}/{settings.scope.project_id}/"
            f"{settings.scope.environment_id}/code-change-qualification/"
            f"{command_id}/command.json"
        ),
        value=payload,
    )
    command = PrivateCommandRecord(
        command_id=command_id,
        scope=settings.scope,
        command_kind=DeliveryCommandKind.QUALIFY_CODE_CHANGE,
        subject_id=intent.intent_id,
        material_hash=canonical_sha256(
            {
                "intent_request_hash": intent.request_hash,
                "payload_hash": payload_receipt.content_hash,
            }
        ),
        idempotency_key=f"qualify-code-change:{intent.intent_id}",
        payload_ref=payload_receipt.uri,
        payload=payload,
        payload_hash=payload_receipt.content_hash,
        payload_schema_hash=payload_schema_hash(DeliveryCommandKind.QUALIFY_CODE_CHANGE),
        admitted_caller_identity=settings.coordinator_principal,
        admitted_audience_hash=sha256_bytes(provider_audience.encode()),
        deadline=intent.expires_at,
        status=DeliveryCommandStatus.PREPARED,
    )
    with connection.transaction():
        commands.prepare(command)
    return command


def _now() -> datetime:
    return datetime.now(UTC)
