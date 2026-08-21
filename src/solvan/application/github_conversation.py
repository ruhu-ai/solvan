"""Typed contracts for the governed GitHub conversation surface.

Solvan may take part in a repository's conversation — read a thread, be
addressed by a mention, publish a bounded reply — under the same discipline
that governs everything else it says: the sentence comes from the pinned claim
template registry, the publication passes a human approval bound to the exact
rendered bytes, and the provider revalidates the target before it constructs a
request.

Two refusals in this module are load-bearing rather than defensive.

`APPROVE` is not in `ReviewEvent`.  The merge gate admits a merge only when
GitHub's authoritative review decision is `APPROVED` and the approving account
matches a linked human reviewer; an App-authored approval would let Solvan
satisfy its own merge precondition.  The event is absent from the type, absent
from the database domain, and refused again before a request body is built.

A body is never accepted as text.  It arrives as a rendered claim with the
registry digest that produced it, and the digest is checked against the pinned
one at every boundary it crosses.  Specification 24 governs.

"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope

_SHA256 = r"^sha256:[0-9a-f]{64}$"
_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$")
_GIT_SHA = r"^[0-9a-f]{40}$"

#: GitHub's own ceiling on a comment body.  Enforced here so an oversized body
#: is refused before it is stored, not after GitHub rejects the publication.
MAXIMUM_BODY_BYTES = 65_536


class GitHubConversationError(ValueError):
    """A conversation payload violates a fail-closed contract."""


class ConversationOperation(StrEnum):
    CREATE_ISSUE = "CREATE_ISSUE"
    POST_ISSUE_COMMENT = "POST_ISSUE_COMMENT"
    SUBMIT_PULL_REQUEST_REVIEW = "SUBMIT_PULL_REQUEST_REVIEW"


class ReviewEvent(StrEnum):
    """The review events Solvan may emit.

    `APPROVE` is deliberately absent.  Adding it here would be sufficient to
    defeat the merge gate, so its absence is the control — there is no policy
    value, configuration key, or privileged caller that reintroduces it.
    """

    COMMENT = "COMMENT"
    REQUEST_CHANGES = "REQUEST_CHANGES"


class ThreadKind(StrEnum):
    ISSUE = "ISSUE"
    PULL_REQUEST = "PULL_REQUEST"


class ThreadState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class TriggerKind(StrEnum):
    MENTION = "MENTION"
    LABEL = "LABEL"
    SYNCHRONIZE = "SYNCHRONIZE"
    NONE = "NONE"


class ParticipantAdmission(StrEnum):
    ADMITTED = "ADMITTED"
    PARKED = "PARKED"
    DISMISSED = "DISMISSED"


class ConversationActionState(StrEnum):
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DISPATCHED = "DISPATCHED"
    PUBLISHED = "PUBLISHED"
    REFUSED = "REFUSED"
    EXPIRED = "EXPIRED"


class _ConversationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ConversationParticipant(_ConversationModel):
    """One login's standing on one repository binding.

    Standing is per binding.  A login admitted on one repository has none on
    another, because GitHub logins are global while the decision to let someone
    direct Solvan's attention is not.
    """

    scope: Scope
    participant_id: str = Field(pattern=r"^ghm_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    login: str = Field(pattern=_LOGIN.pattern)
    account_node_id: str = Field(min_length=1, max_length=128)
    admission: ParticipantAdmission
    admitted_by_principal: str | None = Field(default=None, min_length=3, max_length=255)
    admitted_at: datetime | None = None

    @model_validator(mode="after")
    def validate_admission(self) -> Self:
        if self.admission is ParticipantAdmission.ADMITTED and (
            self.admitted_by_principal is None or self.admitted_at is None
        ):
            raise GitHubConversationError("an admitted participant names its admitting operator")
        return self


class ConversationThread(_ConversationModel):
    """One observed issue or pull-request thread.

    This is a projection of an external system and is never workflow authority.
    The provider re-reads the thread before publishing rather than trusting the
    row, so a stale projection delays a publication instead of misdirecting one.
    """

    scope: Scope
    thread_id: str = Field(pattern=r"^ght_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    thread_kind: ThreadKind
    external_number: int = Field(gt=0)
    html_url: str = Field(pattern=r"^https://")
    title: str = Field(min_length=1, max_length=256)
    state: ThreadState
    locked: bool = False
    head_commit_sha: str | None = Field(default=None, pattern=_GIT_SHA)
    author_login: str | None = Field(default=None, pattern=_LOGIN.pattern)
    trigger_kind: TriggerKind | None = None
    observation_hash: str = Field(pattern=_SHA256)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_thread(self) -> Self:
        if self.thread_kind is ThreadKind.ISSUE and self.head_commit_sha is not None:
            raise GitHubConversationError("an issue thread carries no head commit")
        return self


class RenderedBody(_ConversationModel):
    """A body the claim registry produced, carrying the digest that produced it.

    The text is accepted only as the output of `compose_all`; this model exists
    so no boundary further down can be handed a bare string.  The digest travels
    with the text because a body is only trustworthy relative to the registry
    version that rendered it, and that version must still be pinned when the
    publication finally happens — often minutes later, behind a human decision.
    """

    text: str = Field(min_length=1, max_length=MAXIMUM_BODY_BYTES)
    template_registry_digest: str = Field(pattern=_SHA256)
    template_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_body(self) -> Self:
        if len(self.text.encode("utf-8")) > MAXIMUM_BODY_BYTES:
            raise GitHubConversationError("rendered body exceeds the bounded publication size")
        if len(set(self.template_ids)) != len(self.template_ids):
            raise GitHubConversationError("rendered body cites a template twice")
        return self

    @property
    def body_hash(self) -> str:
        return canonical_sha256({"schema_version": 1, "body": self.text})


class ConversationProposal(_ConversationModel):
    """What an agent returns.  It performs no mutation and carries no authority.

    The proposal names a repository, a target, an operation, and a rendered
    body.  The coordinator — never the agent — decides whether it becomes a
    durable action row, and a human decides whether that row is ever dispatched.
    """

    scope: Scope
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    operation: ConversationOperation
    body: RenderedBody
    thread_id: str | None = Field(default=None, pattern=r"^ght_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    title: str | None = Field(default=None, min_length=1, max_length=256)
    review_event: ReviewEvent | None = None
    expected_thread_state: ThreadState | None = None
    expected_head_commit_sha: str | None = Field(default=None, pattern=_GIT_SHA)
    agent_run_id: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_proposal(self) -> Self:
        if self.operation is ConversationOperation.CREATE_ISSUE:
            if self.title is None or self.thread_id is not None:
                raise GitHubConversationError("a new issue carries a title and no thread")
            if self.review_event is not None:
                raise GitHubConversationError("an issue is not a review")
        if self.operation is ConversationOperation.POST_ISSUE_COMMENT:
            if self.thread_id is None:
                raise GitHubConversationError("a comment names the thread it lands in")
            if self.review_event is not None:
                raise GitHubConversationError("a comment is not a review")
        if self.operation is ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW:
            if self.review_event is None:
                raise GitHubConversationError("a review names its event")
            if self.thread_id is None or self.expected_head_commit_sha is None:
                raise GitHubConversationError(
                    "a review binds the exact pull request and head commit it reviewed"
                )
        return self

    @property
    def proposal_hash(self) -> str:
        """The identity one agent proposal has, so it becomes at most one action."""

        return canonical_sha256(
            {
                "schema_version": 1,
                "scope": self.scope.canonical_dict(),
                "repository_id": self.repository_id,
                "operation": self.operation.value,
                "thread_id": self.thread_id,
                "title": self.title,
                "review_event": None if self.review_event is None else self.review_event.value,
                "expected_head_commit_sha": self.expected_head_commit_sha,
                "body_hash": self.body.body_hash,
                "template_registry_digest": self.body.template_registry_digest,
            }
        )


class PublishConversationCommand(_ConversationModel):
    """The approved, dispatchable publication.

    Every field here was fixed before a human decided.  The provider reads this
    record rather than any request body, so a caller cannot substitute a
    different thread, a different body, or a different review event after the
    approval was given.
    """

    scope: Scope
    action_id: str = Field(pattern=r"^gha_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    repository_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    operation: ConversationOperation
    external_number: int | None = Field(default=None, gt=0)
    title: str | None = Field(default=None, min_length=1, max_length=256)
    body: str = Field(min_length=1, max_length=MAXIMUM_BODY_BYTES)
    body_hash: str = Field(pattern=_SHA256)
    template_registry_digest: str = Field(pattern=_SHA256)
    review_event: ReviewEvent | None = None
    expected_thread_state: ThreadState | None = None
    expected_head_commit_sha: str | None = Field(default=None, pattern=_GIT_SHA)
    decision_digest: str = Field(pattern=_SHA256)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,128}$")
    actor_principal: str = Field(min_length=3, max_length=255)

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        if canonical_sha256({"schema_version": 1, "body": self.body}) != self.body_hash:
            raise GitHubConversationError("publication body does not match its approved hash")
        if self.operation is ConversationOperation.CREATE_ISSUE:
            if self.title is None or self.external_number is not None:
                raise GitHubConversationError("a new issue has a title and no existing number")
        elif self.external_number is None:
            raise GitHubConversationError("a publication into a thread names its number")
        if (self.operation is ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW) != (
            self.review_event is not None
        ):
            raise GitHubConversationError("only a review carries a review event")
        if (
            self.operation is ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW
            and self.expected_head_commit_sha is None
        ):
            raise GitHubConversationError("a review binds the head commit it reviewed")
        return self


def require_conversation_authority(
    *, allowed_operations: tuple[str, ...], operation: ConversationOperation
) -> None:
    """Refuse a publication the binding was never granted.

    Checked against the binding's own allowlist rather than a role, a feature
    flag, or the caller's identity, because the binding is what names a
    repository and an operator granted it deliberately.
    """

    if operation.value not in set(allowed_operations):
        raise GitHubConversationError(
            f"repository binding does not grant {operation.value}",
        )


def require_admitted_participant(admission: ParticipantAdmission | None) -> None:
    """Refuse to treat an event as an address from a sender with no standing.

    Absence denies: a login nobody admitted on this binding is a sighting, not
    a request, and an unrecorded login is not even that.  Passing this does not
    authorize a publication — every action still passes the approval gate in
    §5 regardless of who triggered it.

    There is deliberately no `allow_all` escape.  It appeared in an earlier
    draft of §4 as a way to admit every sender's event into a thread
    projection, but the projection is written unconditionally — an operator can
    already see who asked — so the flag could only ever have widened *acting*,
    which is the one thing it was described as not doing.  A permissive
    configuration value guarding an authority decision is what this codebase
    refuses everywhere else, so it has no column, no reader, and no parameter.
    """

    if admission is ParticipantAdmission.ADMITTED:
        return
    if admission is ParticipantAdmission.DISMISSED:
        raise GitHubConversationError("sender was dismissed on this repository")
    raise GitHubConversationError("sender is not admitted on this repository")


def review_event_or_refuse(value: str) -> ReviewEvent:
    """Parse a review event, naming the approval refusal explicitly.

    A caller that asks for `APPROVE` gets a message that says why rather than a
    generic enum error, because this refusal is a designed property and a
    reader tracing a denial should land on the reason, not on a parse failure.
    """

    normalized = value.strip().upper()
    if normalized == "APPROVE":
        raise GitHubConversationError(
            "Solvan does not emit approving reviews: an approval it authors would "
            "satisfy its own merge precondition"
        )
    try:
        return ReviewEvent(normalized)
    except ValueError as error:
        raise GitHubConversationError(f"unknown review event {value!r}") from error


def conversation_decision_material(
    *,
    action_id: str,
    repository_id: str,
    repository_policy_hash: str,
    operation: ConversationOperation,
    body: str,
    body_hash: str,
    template_registry_digest: str,
    template_ids: tuple[str, ...],
    thread_url: str | None,
    external_number: int | None,
    review_event: ReviewEvent | None,
    expected_thread_state: ThreadState | None,
    expected_head_commit_sha: str | None,
    trigger_login: str | None,
    expires_at: datetime,
) -> tuple[dict[str, object], str]:
    """Build what an operator decides against, and its digest.

    The rendered body is *in* the material, not merely hashed into it: an
    approver is deciding whether these exact words may be published under
    Solvan's identity, so the words must be what they read. The digest then
    binds them — an edited body cannot inherit the approval.
    """

    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise GitHubConversationError("conversation decision expiry must include a timezone")
    if canonical_sha256({"schema_version": 1, "body": body}) != body_hash:
        raise GitHubConversationError("decision body does not match its hash")
    material: dict[str, object] = {
        "schema_version": 1,
        "stage": "GITHUB_CONVERSATION",
        "action_id": action_id,
        "repository_binding_id": repository_id,
        "repository_policy_hash": repository_policy_hash,
        "operation": operation.value,
        "body": body,
        "body_hash": body_hash,
        "template_registry_digest": template_registry_digest,
        "template_ids": sorted(template_ids),
        "thread_url": thread_url,
        "external_number": external_number,
        "review_event": None if review_event is None else review_event.value,
        "expected_thread_state": (
            None if expected_thread_state is None else expected_thread_state.value
        ),
        "expected_head_commit_sha": expected_head_commit_sha,
        "trigger_login": trigger_login,
        "expires_at": expires_at.isoformat(),
    }
    return material, canonical_sha256(material)


def thread_observation_hash(
    *,
    thread_kind: ThreadKind,
    external_number: int,
    state: ThreadState,
    locked: bool,
    head_commit_sha: str | None,
    title: str,
) -> str:
    """Digest the thread facts a publication depends on.

    Only the facts that would invalidate a pending approval are included: a new
    comment appearing on a thread does not invalidate a queued reply, but the
    thread closing or its head moving does.
    """

    return canonical_sha256(
        {
            "schema_version": 1,
            "thread_kind": thread_kind.value,
            "external_number": external_number,
            "state": state.value,
            "locked": locked,
            "head_commit_sha": head_commit_sha,
            "title": title,
        }
    )


ConversationOperationLiteral = Literal[
    "CREATE_ISSUE", "POST_ISSUE_COMMENT", "SUBMIT_PULL_REQUEST_REVIEW"
]
