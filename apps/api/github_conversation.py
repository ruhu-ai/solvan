"""Authenticated console boundary for the GitHub conversation surface.

Three things an operator does here: see who is asking Solvan for something and
decide whether they may, read the exact words Solvan proposes to publish, and
approve or reject that publication.

The second is the reason this router exists rather than reusing the code-change
decision routes. A code-change approval is a decision about a diff, presented
as digests; a publication approval is a decision about *sentences*, and the
operator must read them as the world will. So the rendered body travels in the
response, and the digest that binds it is computed from that same body — an
operator approving something they were not shown is the failure this prevents.

Specification 24 §4 and §5 govern.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.github_conversation import (
    ConversationActionState,
    GitHubConversationError,
    ParticipantAdmission,
)
from solvan.domain import Scope
from solvan.persistence.github_conversation_store import GitHubConversationStore
from solvan.platform.database import connect_database

#: An operator deciding a publication holds the same role as one deciding a
#: pull request. Publishing under Solvan's identity is not a lesser act than
#: opening a pull request from it.
REQUIRED_ROLE = "CODE_CHANGE_APPROVER"


class ParticipantDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    login: str = Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$")
    admission: ParticipantAdmission


class PublicationDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    #: Recomputed from the stored body and compared. A client that submits a
    #: digest for a body it edited locally has not approved the stored one.
    decision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approved: bool
    reason: str = Field(min_length=8, max_length=2_000)


class PublicationView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str
    repository_id: str
    operation: str
    review_event: str | None
    title: str | None
    #: The exact bytes that will be published. Present so the operator decides
    #: on the words, not on a digest of them.
    body: str
    body_hash: str
    template_registry_digest: str
    template_ids: list[str]
    state: str
    decision_digest: str
    required_role: str
    external_url: str | None
    expires_at: datetime


def github_conversation_router(
    *,
    session_principal: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any] = connect_database,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/github/conversation")

    @router.get("/repositories/{repository_id}/participants")
    def list_participants(
        repository_id: str,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        session_principal(human_token)
        with connect() as connection:
            rows = GitHubConversationStore(connection).list_participants(
                scope=scope_provider(), repository_id=repository_id
            )
        return {"participants": [dict(row) for row in rows]}

    @router.post("/repositories/{repository_id}/participants")
    def decide_participant(
        repository_id: str,
        request: ParticipantDecisionRequest,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, str]:
        principal = session_principal(human_token)
        try:
            with connect() as connection, connection.transaction():
                GitHubConversationStore(connection).decide_participant(
                    scope=scope_provider(),
                    repository_id=repository_id,
                    login=request.login,
                    admission=request.admission,
                    actor=principal,
                )
        except GitHubConversationError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {"login": request.login, "admission": request.admission.value}

    @router.get("/actions")
    def list_actions(
        repository_id: str | None = None,
        pending_only: bool = False,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        session_principal(human_token)
        states = (ConversationActionState.APPROVAL_PENDING.value,) if pending_only else ()
        with connect() as connection:
            rows = GitHubConversationStore(connection).list_actions(
                scope=scope_provider(), repository_id=repository_id, states=states
            )
        return {"actions": [dict(row) for row in rows]}

    @router.get("/actions/{action_id}", response_model=PublicationView)
    def read_action(
        action_id: str,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> PublicationView:
        session_principal(human_token)
        scope = scope_provider()
        try:
            with connect() as connection:
                store = GitHubConversationStore(connection)
                material, digest = store.action_decision_material(scope=scope, action_id=action_id)
                rows = store.list_actions(scope=scope, limit=500)
        except GitHubConversationError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
        row = next((item for item in rows if str(item["id"]) == action_id), None)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "action is not present")
        return PublicationView(
            action_id=action_id,
            repository_id=str(row["repository_id"]),
            operation=str(row["operation"]),
            review_event=None if row["review_event"] is None else str(row["review_event"]),
            title=None if row["title"] is None else str(row["title"]),
            body=str(material["body"]),
            body_hash=str(material["body_hash"]),
            template_registry_digest=str(material["template_registry_digest"]),
            template_ids=[str(item) for item in (row["template_ids_json"] or ())],
            state=str(row["state"]),
            decision_digest=digest,
            required_role=REQUIRED_ROLE,
            external_url=None if row["external_url"] is None else str(row["external_url"]),
            expires_at=row["expires_at"],
        )

    @router.post("/actions/{action_id}/decision")
    def decide_action(
        action_id: str,
        request: PublicationDecisionRequest,
        human_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        principal = session_principal(human_token)
        try:
            with connect() as connection, connection.transaction():
                GitHubConversationStore(connection).decide_action(
                    scope=scope_provider(),
                    action_id=action_id,
                    approved=request.approved,
                    decision_digest=request.decision_digest,
                    actor=principal,
                    now=datetime.now(UTC),
                )
        except GitHubConversationError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {
            "action_id": action_id,
            "state": (
                ConversationActionState.APPROVED.value
                if request.approved
                else ConversationActionState.REJECTED.value
            ),
        }

    return router
