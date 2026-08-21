"""Private OIDC-bound maintenance tick for the conversational ledger."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Protocol, cast

from fastapi import FastAPI, Header, HTTPException, status
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from apps.api.console_projection import live_console_snapshot
from apps.api.liaison import liaison_registry
from apps.api.liaison_maintenance import purge_due_messages, reap_expired_turns
from apps.api.liaison_service import LiaisonService
from solvan.application.skills_retention import execute_due_deletions
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.liaison_compaction import compact_next_thread
from solvan.persistence.skills_retention_store import PostgresSkillRetentionRepository
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceDeleter
from solvan.platform.google_rest import authorized_session


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


class TickRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    maximum_compactions: int = Field(default=10, ge=1, le=50)
    maximum_turns: int = Field(default=10, ge=1, le=50)
    maximum_skill_deletions: int = Field(default=0, ge=0, le=100)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required Liaison maintenance setting {name} is missing")
    return value


def create_app(*, verifier: TokenVerifier | None = None) -> FastAPI:
    app = FastAPI(title="Solvan Liaison Maintenance", version="0.1.0")
    token_verifier = verifier or GoogleTokenVerifier()

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/tick")
    def tick(
        request: TickRequest, authorization: str | None = Header(default=None)
    ) -> dict[str, int]:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing worker identity")
        try:
            claims = token_verifier.verify(
                authorization.removeprefix("Bearer "),
                audience=_required("SOLVAN_LIAISON_MAINTENANCE_AUDIENCE"),
            )
        except Exception as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid worker identity") from error
        if claims.get("email_verified") is not True or claims.get("email") != _required(
            "SOLVAN_LIAISON_MAINTENANCE_PRINCIPAL"
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "worker identity is not authorized")
        scope = Scope(
            _required("SOLVAN_ORGANIZATION_ID"),
            _required("SOLVAN_SCOPE_PROJECT_ID"),
            _required("SOLVAN_ENVIRONMENT_ID"),
        )
        skills_bucket = os.environ.get("SOLVAN_SKILLS_BUCKET")
        if request.maximum_skill_deletions and not skills_bucket:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "skills retention bucket is not configured",
            )
        with connect_database() as connection:
            with connection.transaction():
                purged = purge_due_messages(connection, scope=scope)
                reaped = len(reap_expired_turns(connection, scope=scope))
            compacted = 0
            for _index in range(request.maximum_compactions):
                with connection.transaction():
                    receipt = compact_next_thread(connection, scope=scope)
                if receipt is None:
                    break
                compacted += 1
            skills_deleted = 0
            if request.maximum_skill_deletions:
                assert skills_bucket is not None
                skills_deleted = execute_due_deletions(
                    repository=PostgresSkillRetentionRepository(connection),
                    deleter=GcsEvidenceDeleter(
                        allowed_buckets=frozenset({skills_bucket}),
                        session=authorized_session(),
                    ),
                    scope=scope,
                    region=os.environ.get("SOLVAN_REGION", "europe-west1"),
                    limit=request.maximum_skill_deletions,
                )
            ready = connection.execute(
                """SELECT thread_id,message_id FROM solvan_liaison.liaison_turns
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND status='READY' ORDER BY queued_at NULLS FIRST,queue_sequence
                    LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": request.maximum_turns},
            ).fetchall()

        def snapshot() -> dict[str, Any]:
            """Answer from the projection the operator is reading, always.

            This returned a hand-written fixture whenever the authority mode was
            anything but `GOOGLE_CLOUD_IAM`, so on every non-production
            deployment the assistant answered from three scripted Tools — one of
            them reading `Available · Probe passed` — while the console beside it
            rendered the governed catalog. An environment variable decided which
            of two contradictory pictures a reader was given, and the
            conversational surface was the one that could be wrong without
            anybody seeing a screen disagree.

            No capability is lost by removing the branch: this worker already
            holds a database connection for the query above, so the fixture was
            never covering an absent one. The six other Liaison surfaces read the
            live projection unconditionally; this was the only one that did not.
            """

            with connect_database() as snapshot_connection:
                return live_console_snapshot(snapshot_connection, scope=scope)

        liaison = LiaisonService(
            connect=connect_database,
            snapshot_provider=snapshot,
            registry_provider=liaison_registry,
        )
        drained = 0
        for thread_id, message_id in ready:
            liaison.run_pending(
                scope=scope,
                thread_id=str(thread_id),
                target_message_id=str(message_id),
            )
            drained += 1
        return {
            "purged": purged,
            "reaped": reaped,
            "compacted": compacted,
            "drained": drained,
            "skills_deleted": skills_deleted,
        }

    return app


app = instrument_fastapi(create_app(), service_name="liaison-maintenance")
