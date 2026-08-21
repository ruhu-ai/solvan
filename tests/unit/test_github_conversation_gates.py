"""The gates specification 24 names, exercised where they actually run.

Each test here corresponds to a control that was described in the
specification, named in a docstring, or declared as a constant, but had no
execution path proving it. They are grouped by the question they answer: who may
decide, what may still be published, which binding a delivery belongs to, and
how many times one install link works.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from solvan.application.github import GitHubContractError
from solvan.application.github_conversation import (
    ConversationOperation,
    GitHubConversationError,
    ParticipantAdmission,
    ReviewEvent,
    ThreadState,
)
from solvan.domain import Scope
from solvan.persistence.github_conversation_participant_store import (
    CONVERSATION_DECISION_ROLE,
    GitHubConversationParticipantStore,
)
from solvan.persistence.github_conversation_store import ClaimedConversationAction
from solvan.persistence.github_installation_store import (
    GitHubInstallationIntentError,
    GitHubInstallationIntentStore,
    state_digest,
)
from solvan.persistence.github_store import GitHubStore

SCOPE = Scope(
    organization_id="org_0000000000000000000000000A",
    project_id="prj_0000000000000000000000000A",
    environment_id="env_0000000000000000000000000A",
)


# --------------------------------------------------------------------------
# Who may decide a publication.
# --------------------------------------------------------------------------


class _RoleCursor:
    """A cursor answering only the role-binding lookup."""

    def __init__(self, holders: set[tuple[str, str]]) -> None:
        self._holders = holders
        self._row: tuple[int] | None = None
        self.seen: list[dict[str, Any]] = []

    def __enter__(self) -> _RoleCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        values = dict(parameters or {})
        assert "actor_role_bindings" in statement
        assert "expires_at IS NULL OR expires_at > now()" in statement
        self.seen.append(values)
        key = (str(values["principal"]), str(values["role"]))
        self._row = (1,) if key in self._holders else None

    def fetchone(self) -> tuple[int] | None:
        return self._row


class _RoleConnection:
    def __init__(self, holders: set[tuple[str, str]]) -> None:
        self.cursor_instance = _RoleCursor(holders)

    def cursor(self, row_factory: Any = None) -> _RoleCursor:
        return self.cursor_instance


def _role_store(holders: set[tuple[str, str]]) -> GitHubConversationParticipantStore:
    store = GitHubConversationParticipantStore()
    store._connection = _RoleConnection(holders)  # type: ignore[assignment]
    return store


def test_a_verified_identity_is_not_by_itself_permission_to_decide() -> None:
    """Authentication says who is asking; it never says that they may."""

    store = _role_store(set())
    with pytest.raises(GitHubConversationError, match=CONVERSATION_DECISION_ROLE):
        store.require_decision_role(scope=SCOPE, principal="user:stranger@example.com")


def test_a_principal_holding_the_role_may_decide() -> None:
    store = _role_store({("user:approver@example.com", CONVERSATION_DECISION_ROLE)})
    store.require_decision_role(scope=SCOPE, principal="user:approver@example.com")


def test_the_role_is_the_same_one_a_pull_request_decision_takes() -> None:
    """Publishing under Solvan's identity is not a lesser act than opening a PR."""

    assert CONVERSATION_DECISION_ROLE == "CODE_CHANGE_APPROVER"


def test_a_neighbouring_role_does_not_substitute() -> None:
    store = _role_store({("user:approver@example.com", "RELEASE_APPROVER")})
    with pytest.raises(GitHubConversationError):
        store.require_decision_role(scope=SCOPE, principal="user:approver@example.com")


def test_the_role_lookup_is_scope_bound() -> None:
    store = _role_store({("user:approver@example.com", CONVERSATION_DECISION_ROLE)})
    store.require_decision_role(scope=SCOPE, principal="user:approver@example.com")
    seen = store._connection.cursor_instance.seen[0]  # type: ignore[attr-defined]
    assert seen["organization_id"] == SCOPE.organization_id
    assert seen["project_id"] == SCOPE.project_id
    assert seen["environment_id"] == SCOPE.environment_id


def test_admitting_a_participant_takes_the_same_role() -> None:
    """Letting someone direct Solvan's attention is a decision, not a note."""

    store = _role_store(set())
    with pytest.raises(GitHubConversationError, match=CONVERSATION_DECISION_ROLE):
        store.decide_participant(
            scope=SCOPE,
            repository_id="ghr_0000000000000000000000000A",
            login="alice",
            admission=ParticipantAdmission.ADMITTED,
            actor="user:stranger@example.com",
        )


# --------------------------------------------------------------------------
# What may still be published when the approval was given minutes ago.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ObservedIssue:
    state: str = "OPEN"
    locked: bool = False
    is_pull_request: bool = True


@dataclass(frozen=True, slots=True)
class _ObservedHead:
    head_sha: str
    merged: bool = False


class _RevalidationClient:
    """A conversation client that answers exactly the two revalidation reads."""

    def __init__(self, *, issue: _ObservedIssue, head: _ObservedHead) -> None:
        self._issue = issue
        self._head = head
        self.head_reads = 0

    def issue(self, *, owner: str, name: str, number: int) -> _ObservedIssue:
        del owner, name, number
        return self._issue

    def pull_request_head(self, *, owner: str, name: str, number: int) -> _ObservedHead:
        del owner, name, number
        self.head_reads += 1
        return self._head


APPROVED_HEAD = "a" * 40


def _review_action(**overrides: Any) -> ClaimedConversationAction:
    base = ClaimedConversationAction(
        action_id="gha_0000000000000000000000000A",
        repository_id="ghr_0000000000000000000000000A",
        owner="acme",
        name="service",
        installation_id=42_991,
        api_base_url="https://api.github.com",
        operation=ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW,
        external_number=7,
        title=None,
        body="- something verified\n\n— Solvan",
        body_hash="sha256:" + "0" * 64,
        template_registry_digest="sha256:" + "1" * 64,
        review_event=ReviewEvent.REQUEST_CHANGES,
        expected_thread_state=ThreadState.OPEN,
        expected_head_commit_sha=APPROVED_HEAD,
        decision_digest="sha256:" + "2" * 64,
        operation_id="gho_0000000000000000000000000A",
    )
    return replace(base, **overrides)


def _revalidate(client: Any, action: ClaimedConversationAction) -> None:
    from apps.github_provider.conversation import _revalidate as revalidate

    revalidate(client, action)


def test_a_review_is_refused_when_the_head_moved_after_approval() -> None:
    """A review must never land on code the approver did not read.

    GitHub would accept this publication: `commit_id` names a commit that is
    still part of the pull request, and the review would be filed as outdated.
    That is precisely the outcome this refuses — a request for changes against
    code the author already replaced reads as a live objection.
    """

    client = _RevalidationClient(issue=_ObservedIssue(), head=_ObservedHead(head_sha="b" * 40))
    with pytest.raises(GitHubConversationError, match="head moved"):
        _revalidate(client, _review_action())


def test_a_review_is_published_when_the_head_is_still_the_approved_one() -> None:
    client = _RevalidationClient(issue=_ObservedIssue(), head=_ObservedHead(head_sha=APPROVED_HEAD))
    _revalidate(client, _review_action())
    assert client.head_reads == 1


def test_a_review_is_refused_when_the_pull_request_merged_after_approval() -> None:
    client = _RevalidationClient(
        issue=_ObservedIssue(), head=_ObservedHead(head_sha=APPROVED_HEAD, merged=True)
    )
    with pytest.raises(GitHubConversationError, match="merged"):
        _revalidate(client, _review_action())


def test_a_comment_needs_no_head_read_at_all() -> None:
    """A comment has no reviewed commit, so nothing about one can go stale."""

    client = _RevalidationClient(
        issue=_ObservedIssue(is_pull_request=False), head=_ObservedHead(head_sha="c" * 40)
    )
    _revalidate(
        client,
        _review_action(
            operation=ConversationOperation.POST_ISSUE_COMMENT,
            review_event=None,
            expected_head_commit_sha=None,
        ),
    )
    assert client.head_reads == 0


def test_a_locked_thread_still_refuses_before_any_head_read() -> None:
    client = _RevalidationClient(
        issue=_ObservedIssue(locked=True), head=_ObservedHead(head_sha=APPROVED_HEAD)
    )
    with pytest.raises(GitHubConversationError, match="locked"):
        _revalidate(client, _review_action())
    assert client.head_reads == 0


# --------------------------------------------------------------------------
# Which binding an inbound delivery belongs to.
# --------------------------------------------------------------------------


class _BindingCursor:
    def __init__(self, bindings: dict[tuple[str, str], str]) -> None:
        self._bindings = bindings
        self._row: tuple[str] | None = None

    def __enter__(self) -> _BindingCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        values = dict(parameters or {})
        assert "owner = %(owner)s" in statement and "name = %(name)s" in statement
        # Status is deliberately unfiltered: a binding is PENDING until the
        # provider's own probe promotes it, and its first deliveries arrive
        # before that.
        assert "status" not in statement
        found = self._bindings.get((str(values["owner"]), str(values["name"])))
        self._row = None if found is None else (found,)

    def fetchone(self) -> tuple[str] | None:
        return self._row


class _BindingConnection:
    def __init__(self, bindings: dict[tuple[str, str], str]) -> None:
        self._bindings = bindings

    def cursor(self, row_factory: Any = None) -> _BindingCursor:
        return _BindingCursor(self._bindings)


def test_a_delivery_resolves_to_the_repository_that_sent_it() -> None:
    """One App sends every bound repository to one URL.

    Taking the binding from deployment configuration meant every repository but
    the configured one had its deliveries rejected — and a webhook that keeps
    failing is one GitHub eventually disables outright.
    """

    store = GitHubStore(
        _BindingConnection(  # type: ignore[arg-type]
            {
                ("acme", "service"): "ghr_0000000000000000000000000A",
                ("acme", "gateway"): "ghr_0000000000000000000000000B",
            }
        )
    )
    assert (
        store.binding_for_delivery(scope=SCOPE, owner="acme", name="gateway")
        == "ghr_0000000000000000000000000B"
    )


def test_a_delivery_for_an_unbound_repository_is_refused() -> None:
    """Reach is not a binding: an operator has to have connected it."""

    store = GitHubStore(_BindingConnection({}))  # type: ignore[arg-type]
    with pytest.raises(GitHubContractError):
        store.binding_for_delivery(scope=SCOPE, owner="acme", name="unconnected")


# --------------------------------------------------------------------------
# How many times one install link works.
# --------------------------------------------------------------------------


class _IntentRows:
    """The intent table, with the concurrency the real one gets from a row lock."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []


class _IntentCursor:
    def __init__(self, table: _IntentRows) -> None:
        self._table = table
        self._row: dict[str, Any] | None = None
        self.rowcount = 0

    def __enter__(self) -> _IntentCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        values = dict(parameters or {})
        self._row = None
        if "INSERT INTO" in statement:
            self._table.rows.append(
                {
                    "id": values["id"],
                    "state_hash": values["state_hash"],
                    "classification": values["classification"],
                    "actor_principal": values["actor"],
                    "status": "PENDING",
                    "expires_at": values["expires_at"],
                    "claimed_at": None,
                }
            )
            self.rowcount = 1
            return
        if "SET status='CLAIMED'" in statement:
            for row in self._table.rows:
                if (
                    row["state_hash"] == values["state_hash"]
                    and row["status"] == "PENDING"
                    and row["expires_at"] > values["now"]
                ):
                    row["status"] = "CLAIMED"
                    row["claimed_at"] = values["now"]
                    self.rowcount = 1
                    self._row = dict(row)
                    return
            self.rowcount = 0
            return
        if "SET status='REFUSED'" in statement and "state_hash" in values:
            for row in self._table.rows:
                if (
                    row["state_hash"] == values["state_hash"]
                    and row["status"] == "PENDING"
                    and row["expires_at"] <= values["now"]
                ):
                    row["status"] = "REFUSED"
                    self.rowcount = 1
                    return
            self.rowcount = 0
            return
        raise AssertionError(f"unexpected statement: {statement}")

    def fetchone(self) -> dict[str, Any] | None:
        return self._row


class _IntentConnection:
    def __init__(self, table: _IntentRows) -> None:
        self._table = table

    def cursor(self, row_factory: Any = None) -> _IntentCursor:
        return _IntentCursor(self._table)


def _minted(table: _IntentRows, *, now: datetime) -> str:
    store = GitHubInstallationIntentStore(_IntentConnection(table))  # type: ignore[arg-type]
    return store.mint(
        scope=SCOPE,
        classification="INTERNAL",
        actor_principal="user:operator@example.com",
        challenge_id="ach_0000000000000000000000000A",
        now=now,
    ).state


def test_a_second_presentation_is_refused_while_the_first_is_still_in_flight() -> None:
    """The window this closes is the one the flow spends talking to GitHub.

    The first claim used to leave the row PENDING until completion, two network
    round trips later, so a double click or a link prefetch found a usable
    intent and raced to create the same bindings.
    """

    table = _IntentRows()
    now = datetime.now(UTC)
    state = _minted(table, now=now)

    first = GitHubInstallationIntentStore(_IntentConnection(table))  # type: ignore[arg-type]
    claimed = first.claim(scope=SCOPE, state=state, now=now)
    assert claimed.actor_principal == "user:operator@example.com"

    # Nothing has completed yet — the GitHub reads have not happened.
    assert table.rows[0]["status"] == "CLAIMED"

    second = GitHubInstallationIntentStore(_IntentConnection(table))  # type: ignore[arg-type]
    with pytest.raises(GitHubInstallationIntentError):
        second.claim(scope=SCOPE, state=state, now=now)


def test_an_expired_link_is_refused_and_recorded_as_expired() -> None:
    table = _IntentRows()
    now = datetime.now(UTC)
    state = _minted(table, now=now)
    later = now + timedelta(hours=1)

    store = GitHubInstallationIntentStore(_IntentConnection(table))  # type: ignore[arg-type]
    with pytest.raises(GitHubInstallationIntentError):
        store.claim(scope=SCOPE, state=state, now=later)
    assert table.rows[0]["status"] == "REFUSED"


def test_an_unknown_state_is_refused_without_touching_any_row() -> None:
    table = _IntentRows()
    now = datetime.now(UTC)
    _minted(table, now=now)

    store = GitHubInstallationIntentStore(_IntentConnection(table))  # type: ignore[arg-type]
    with pytest.raises(GitHubInstallationIntentError):
        store.claim(scope=SCOPE, state="not-a-real-state", now=now)
    assert table.rows[0]["status"] == "PENDING"


def test_the_state_itself_is_never_stored() -> None:
    """A reader of this table cannot finish somebody else's installation."""

    table = _IntentRows()
    now = datetime.now(UTC)
    state = _minted(table, now=now)
    assert table.rows[0]["state_hash"] == state_digest(state)
    assert state not in str(table.rows[0])


# --------------------------------------------------------------------------
# Whether an inbound event is an address or merely a sighting.
# --------------------------------------------------------------------------


class _IngestStore:
    """Records what the provider's projection decided, without a database."""

    def __init__(self, admission: ParticipantAdmission) -> None:
        self._admission = admission
        self.recorded_trigger: Any = "unset"
        self.repository_ids: list[str] = []

    def record_sighting(
        self, *, scope: Scope, repository_id: str, login: str, account_node_id: str
    ) -> ParticipantAdmission:
        del scope, login, account_node_id
        self.repository_ids.append(repository_id)
        return self._admission

    def upsert_thread(self, **values: Any) -> str:
        self.recorded_trigger = values["trigger_kind"]
        self.repository_ids.append(str(values["repository_id"]))
        return "ght_0000000000000000000000000A"


_MENTION_EVENT = {
    "action": "created",
    "issue": {
        "number": 12,
        "title": "Latency regression",
        "state": "open",
        "locked": False,
        "html_url": "https://github.com/acme/service/issues/12",
        "user": {"login": "maintainer", "node_id": "MDQ6VXNlcjE="},
    },
    "comment": {"id": 991, "body": "@solvan-bot please look at this"},
    "sender": {"login": "outsider", "node_id": "MDQ6VXNlcjI="},
}


def _project(admission: ParticipantAdmission) -> _IngestStore:
    import apps.github_provider.conversation_ingest as provider

    store = _IngestStore(admission)

    @dataclass(frozen=True, slots=True)
    class _Settings:
        scope: Scope = SCOPE
        app_handle: str = "solvan-bot"
        trigger_labels: tuple[str, ...] = ()

    original = provider.GitHubConversationStore
    provider.GitHubConversationStore = lambda connection: store  # type: ignore[assignment,misc]
    try:
        provider.project_conversation(
            None,
            settings=_Settings(),  # type: ignore[arg-type]
            repository_id="ghr_0000000000000000000000000B",
            payload=_MENTION_EVENT,
            event_name="issue_comment",
            event_id="ghe_0000000000000000000000000A",
        )
    finally:
        provider.GitHubConversationStore = original  # type: ignore[assignment]
    return store


def test_an_unadmitted_sender_is_seen_but_is_not_an_address() -> None:
    """Absence denies. The event is still recorded — an operator has to be able
    to see who is asking before deciding whether they may — but the thread
    records no trigger, so nothing downstream can read an instruction from it.
    """

    from solvan.application.github_conversation import TriggerKind

    store = _project(ParticipantAdmission.PARKED)
    assert store.recorded_trigger is TriggerKind.NONE


def test_a_dismissed_sender_cannot_re_address_solvan_by_asking_again() -> None:
    from solvan.application.github_conversation import TriggerKind

    store = _project(ParticipantAdmission.DISMISSED)
    assert store.recorded_trigger is TriggerKind.NONE


def test_an_admitted_sender_addresses_solvan() -> None:
    from solvan.application.github_conversation import TriggerKind

    store = _project(ParticipantAdmission.ADMITTED)
    assert store.recorded_trigger is TriggerKind.MENTION


def test_the_projection_uses_the_binding_the_delivery_resolved_to() -> None:
    """Not the one this deployment happens to be configured with."""

    store = _project(ParticipantAdmission.ADMITTED)
    assert set(store.repository_ids) == {"ghr_0000000000000000000000000B"}
