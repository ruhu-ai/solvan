"""Specification 24: the governed GitHub conversation surface.

The tests that matter most here are the refusals. A conversational surface is
easy to make work and hard to make safe, so most of what follows asserts that a
particular thing *cannot* happen: Solvan cannot approve a pull request, cannot
publish words the claim registry did not render, cannot act for a stranger, and
cannot search outside the binding it was invoked for.
"""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.github_body import (
    PINNED_REGISTRY_DIGEST,
    compose_publication_body,
    publication_registry,
)
from solvan.application.github_conversation import (
    ConversationOperation,
    ConversationParticipant,
    ConversationProposal,
    GitHubConversationError,
    ParticipantAdmission,
    RenderedBody,
    ReviewEvent,
    ThreadKind,
    ThreadState,
    conversation_decision_material,
    require_admitted_participant,
    require_conversation_authority,
    review_event_or_refuse,
    thread_observation_hash,
)
from solvan.application.liaison.claims import ClaimDraft
from solvan.domain import Scope
from solvan.platform.github import GitHubApiError
from solvan.platform.github_conversation import (
    GitHubConversationClient,
    GitHubRateLimited,
)
from solvan.platform.github_conversation_events import (
    mentions_handle,
    project_conversation_trigger,
)
from solvan.platform.github_delivery_reads import GitHubDeliveryReadClient

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
REPOSITORY = "ghr_0000000000000000000000000C"
THREAD = "ght_0000000000000000000000000A"


class Response:
    def __init__(
        self,
        value: object,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = json.dumps(value).encode()
        self.headers = headers or {}

    def json(self) -> object:
        return json.loads(self.content)


class Transport:
    """Records every request so a test can assert what reached GitHub."""

    def __init__(self, responses: dict[str, Response] | None = None) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self._responses = responses or {}

    def _match(self, url: str) -> Response:
        for fragment, response in self._responses.items():
            if fragment in url:
                return response
        return Response({})

    def get(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("GET", url, kwargs))
        return self._match(url)

    def post(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("POST", url, kwargs))
        return self._match(url)

    def put(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("PUT", url, kwargs))
        return self._match(url)


class Tokens:
    def token(self, *, installation_id: int) -> str:
        return f"ghs_installation_{installation_id}"


class Projections:
    def __init__(self, rows: dict[tuple[str, str], dict[str, object]]) -> None:
        self._rows = rows

    def read(self, record_type: str, record_id: str) -> dict[str, object] | None:
        return self._rows.get((record_type, record_id))


def client(transport: Transport) -> GitHubConversationClient:
    return GitHubConversationClient(
        transport=transport,  # type: ignore[arg-type]
        token_provider=Tokens(),
        installation_id=42,
    )


def rendered(text: str = "- Solvan received this request.") -> RenderedBody:
    return RenderedBody(
        text=text,
        template_registry_digest=PINNED_REGISTRY_DIGEST,
        template_ids=("GITHUB_ACKNOWLEDGED",),
    )


# --------------------------------------------------------------------------
# Solvan cannot approve a pull request.
# --------------------------------------------------------------------------


def test_approve_is_not_a_review_event_solvan_can_name() -> None:
    assert {item.value for item in ReviewEvent} == {"COMMENT", "REQUEST_CHANGES"}


def test_asking_for_approve_is_refused_with_the_reason() -> None:
    with pytest.raises(GitHubConversationError) as error:
        review_event_or_refuse("APPROVE")
    assert "merge precondition" in str(error.value)


def test_approve_is_refused_case_and_whitespace_insensitively() -> None:
    for value in (" approve ", "Approve", "aPPROVE"):
        with pytest.raises(GitHubConversationError):
            review_event_or_refuse(value)


def test_the_client_refuses_an_approving_review_before_any_request() -> None:
    transport = Transport()
    with pytest.raises(GitHubConversationError):
        client(transport).submit_pull_request_review(
            owner="acme",
            name="platform",
            number=8,
            event="APPROVE",  # type: ignore[arg-type]
            body="Looks good.",
            commit_id="c" * 40,
        )
    assert transport.calls == []


def test_a_review_requires_the_exact_head_commit_it_reviewed() -> None:
    transport = Transport()
    with pytest.raises(GitHubConversationError):
        client(transport).submit_pull_request_review(
            owner="acme",
            name="platform",
            number=8,
            event=ReviewEvent.COMMENT,
            body="One note.",
            commit_id="not-a-sha",
        )
    assert transport.calls == []


def test_a_submitted_review_carries_its_commit_binding() -> None:
    transport = Transport(
        {"/pulls/8/reviews": Response({"id": 7001, "html_url": "https://github.com/a/b/pull/8"})}
    )
    receipt = client(transport).submit_pull_request_review(
        owner="acme",
        name="platform",
        number=8,
        event=ReviewEvent.REQUEST_CHANGES,
        body="The retry is unbounded.",
        commit_id="c" * 40,
    )
    assert receipt.external_id == 7001
    body = transport.calls[0][2]["json"]
    assert body == {
        "body": "The retry is unbounded.",
        "event": "REQUEST_CHANGES",
        "commit_id": "c" * 40,
    }


# --------------------------------------------------------------------------
# Published words come from the registry.
# --------------------------------------------------------------------------


def test_the_publication_registry_matches_its_pinned_digest() -> None:
    assert publication_registry().digest == PINNED_REGISTRY_DIGEST


def test_a_verified_claim_renders_and_is_signed() -> None:
    reader = Projections({("incident", "inc_1"): {"id": "inc_1", "state": "OPEN"}})
    body = compose_publication_body(
        [ClaimDraft(template_id="GITHUB_ACKNOWLEDGED", subject_ref="inc_1", values={})],
        reader=reader,
    )
    assert "opened investigation inc_1" in body.text
    assert body.text.rstrip().endswith("no changes were made)")
    assert body.template_registry_digest == PINNED_REGISTRY_DIGEST


def test_a_body_with_no_surviving_claim_is_not_published() -> None:
    reader = Projections({})
    with pytest.raises(GitHubConversationError):
        compose_publication_body(
            [
                ClaimDraft(
                    template_id="GITHUB_INCIDENT_LINKED",
                    subject_ref="inc_missing",
                    values={},
                )
            ],
            reader=reader,
        )


def test_an_unknown_template_cannot_become_a_publication() -> None:
    with pytest.raises(GitHubConversationError):
        compose_publication_body(
            [ClaimDraft(template_id="ANYTHING_AT_ALL", subject_ref="inc_1", values={})],
            reader=Projections({}),
        )


def test_a_publication_carries_at_least_one_claim() -> None:
    with pytest.raises(GitHubConversationError):
        compose_publication_body([], reader=Projections({}))


def test_a_signature_outside_the_enumerated_set_is_refused() -> None:
    reader = Projections({("incident", "inc_1"): {"id": "inc_1", "state": "OPEN"}})
    with pytest.raises(GitHubConversationError):
        compose_publication_body(
            [ClaimDraft(template_id="GITHUB_ACKNOWLEDGED", subject_ref="inc_1", values={})],
            reader=reader,
            signature="— Solvan, definitely correct",
        )


# --------------------------------------------------------------------------
# Proposals and their binding.
# --------------------------------------------------------------------------


def proposal(**overrides: object) -> ConversationProposal:
    defaults: dict[str, object] = {
        "scope": SCOPE,
        "repository_id": REPOSITORY,
        "operation": ConversationOperation.POST_ISSUE_COMMENT,
        "body": rendered(),
        "thread_id": THREAD,
        "expected_thread_state": ThreadState.OPEN,
    }
    return ConversationProposal(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_a_comment_names_the_thread_it_lands_in() -> None:
    # Model-level refusals reach the caller as pydantic ValidationError, which
    # is a ValueError; the contract error is its cause.
    with pytest.raises(ValueError, match="names the thread"):
        proposal(thread_id=None)


def test_a_new_issue_carries_a_title_and_no_thread() -> None:
    with pytest.raises(ValueError, match="carries a title"):
        proposal(operation=ConversationOperation.CREATE_ISSUE, thread_id=None, title=None)
    issue = proposal(
        operation=ConversationOperation.CREATE_ISSUE,
        thread_id=None,
        title="Checkout latency regression",
        expected_thread_state=None,
    )
    assert issue.title == "Checkout latency regression"


def test_a_review_binds_its_event_and_reviewed_head() -> None:
    with pytest.raises(ValueError, match="names its event"):
        proposal(operation=ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW)
    reviewed = proposal(
        operation=ConversationOperation.SUBMIT_PULL_REQUEST_REVIEW,
        review_event=ReviewEvent.COMMENT,
        expected_head_commit_sha="c" * 40,
    )
    assert reviewed.expected_head_commit_sha == "c" * 40


def test_editing_the_body_changes_the_proposal_identity() -> None:
    first = proposal()
    second = proposal(body=rendered("- Solvan received this request, actually."))
    assert first.proposal_hash != second.proposal_hash


def test_the_decision_digest_binds_the_exact_rendered_body() -> None:
    expires = datetime.now(UTC) + timedelta(hours=1)
    material, digest = conversation_decision_material(
        action_id="gha_0000000000000000000000000A",
        repository_id=REPOSITORY,
        repository_policy_hash="sha256:" + "a" * 64,
        operation=ConversationOperation.POST_ISSUE_COMMENT,
        body="- Solvan received this request.",
        body_hash=rendered().body_hash,
        template_registry_digest=PINNED_REGISTRY_DIGEST,
        template_ids=("GITHUB_ACKNOWLEDGED",),
        thread_url="https://github.com/acme/platform/issues/7",
        external_number=7,
        review_event=None,
        expected_thread_state=ThreadState.OPEN,
        expected_head_commit_sha=None,
        trigger_login="alice",
        expires_at=expires,
    )
    # The operator reads the body, so the body is in what they decide against.
    assert material["body"] == "- Solvan received this request."
    _, other = conversation_decision_material(
        action_id="gha_0000000000000000000000000A",
        repository_id=REPOSITORY,
        repository_policy_hash="sha256:" + "a" * 64,
        operation=ConversationOperation.POST_ISSUE_COMMENT,
        body="- Solvan received this request, and it is fine.",
        body_hash=rendered("- Solvan received this request, and it is fine.").body_hash,
        template_registry_digest=PINNED_REGISTRY_DIGEST,
        template_ids=("GITHUB_ACKNOWLEDGED",),
        thread_url="https://github.com/acme/platform/issues/7",
        external_number=7,
        review_event=None,
        expected_thread_state=ThreadState.OPEN,
        expected_head_commit_sha=None,
        trigger_login="alice",
        expires_at=expires,
    )
    assert digest != other


def test_a_decision_body_that_does_not_match_its_hash_is_refused() -> None:
    with pytest.raises(GitHubConversationError):
        conversation_decision_material(
            action_id="gha_0000000000000000000000000A",
            repository_id=REPOSITORY,
            repository_policy_hash="sha256:" + "a" * 64,
            operation=ConversationOperation.POST_ISSUE_COMMENT,
            body="one thing",
            body_hash=rendered("a different thing").body_hash,
            template_registry_digest=PINNED_REGISTRY_DIGEST,
            template_ids=("GITHUB_ACKNOWLEDGED",),
            thread_url=None,
            external_number=7,
            review_event=None,
            expected_thread_state=ThreadState.OPEN,
            expected_head_commit_sha=None,
            trigger_login=None,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )


# --------------------------------------------------------------------------
# Authority: the binding grants, and absence denies.
# --------------------------------------------------------------------------


def test_a_binding_without_the_operation_cannot_publish_it() -> None:
    with pytest.raises(GitHubConversationError):
        require_conversation_authority(
            allowed_operations=("SYNC_PULL_REQUEST", "CREATE_ISSUE"),
            operation=ConversationOperation.POST_ISSUE_COMMENT,
        )
    require_conversation_authority(
        allowed_operations=("SYNC_PULL_REQUEST", "POST_ISSUE_COMMENT"),
        operation=ConversationOperation.POST_ISSUE_COMMENT,
    )


def test_merge_authority_does_not_confer_a_voice_in_a_thread() -> None:
    with pytest.raises(GitHubConversationError):
        require_conversation_authority(
            allowed_operations=("MERGE_PULL_REQUEST", "CREATE_PULL_REQUEST"),
            operation=ConversationOperation.POST_ISSUE_COMMENT,
        )


def participant(admission: ParticipantAdmission) -> ConversationParticipant:
    return ConversationParticipant(
        scope=SCOPE,
        participant_id="ghm_0000000000000000000000000A",
        repository_id=REPOSITORY,
        login="alice",
        account_node_id="MDQ6VXNlcjE=",
        admission=admission,
        admitted_by_principal=(
            "user:operator@example.com" if admission is ParticipantAdmission.ADMITTED else None
        ),
        admitted_at=(datetime.now(UTC) if admission is ParticipantAdmission.ADMITTED else None),
    )


def test_an_unknown_sender_is_denied_by_absence() -> None:
    with pytest.raises(GitHubConversationError):
        require_admitted_participant(None)


def test_a_parked_sender_has_no_standing() -> None:
    with pytest.raises(GitHubConversationError):
        require_admitted_participant(ParticipantAdmission.PARKED)


def test_a_dismissed_sender_is_denied() -> None:
    with pytest.raises(GitHubConversationError):
        require_admitted_participant(ParticipantAdmission.DISMISSED)


def test_an_admitted_sender_is_accepted() -> None:
    require_admitted_participant(ParticipantAdmission.ADMITTED)


def test_the_admission_gate_offers_no_permissive_setting() -> None:
    """No caller can widen it, because there is nothing to pass."""

    parameters = set(inspect.signature(require_admitted_participant).parameters)
    assert parameters == {"admission"}


def test_an_admitted_participant_names_who_admitted_them() -> None:
    with pytest.raises(ValueError, match="admitting operator"):
        ConversationParticipant(
            scope=SCOPE,
            participant_id="ghm_0000000000000000000000000A",
            repository_id=REPOSITORY,
            login="ghost",
            account_node_id="MDQ6VXNlcjI=",
            admission=ParticipantAdmission.ADMITTED,
        )


# --------------------------------------------------------------------------
# Inbound triggers.
# --------------------------------------------------------------------------


def test_a_mention_is_recognised_but_an_address_inside_a_word_is_not() -> None:
    assert mentions_handle("hey @solvan-bot take a look", handle="solvan-bot")
    assert not mentions_handle("write to bob@solvan-bot", handle="solvan-bot")
    assert not mentions_handle("ping @solvan-bot-staging", handle="solvan-bot")


def comment_event(body: str, action: str = "created") -> dict[str, object]:
    return {
        "action": action,
        "issue": {
            "number": 7,
            "title": "Checkout latency",
            "state": "open",
            "html_url": "https://github.com/acme/platform/issues/7",
            "user": {"login": "alice", "node_id": "MDQ6VXNlcjE="},
        },
        "comment": {"id": 991, "body": body},
        "sender": {"login": "mallory", "node_id": "MDQ6VXNlcjk="},
    }


def test_a_mention_in_a_new_comment_is_a_trigger() -> None:
    trigger = project_conversation_trigger(
        comment_event("@solvan-bot please investigate"),
        event_name="issue_comment",
        handle="solvan-bot",
    )
    assert trigger is not None
    assert trigger.trigger.value == "MENTION"
    assert trigger.sender_login == "mallory"
    assert trigger.thread_kind is ThreadKind.ISSUE


def test_editing_an_old_comment_does_not_re_fire_solvan() -> None:
    assert (
        project_conversation_trigger(
            comment_event("@solvan-bot please investigate", action="edited"),
            event_name="issue_comment",
            handle="solvan-bot",
        )
        is None
    )


def test_a_deployment_with_no_handle_answers_no_mention() -> None:
    assert (
        project_conversation_trigger(
            comment_event("@solvan-bot please investigate"),
            event_name="issue_comment",
            handle=None,
        )
        is None
    )


def test_a_label_triggers_only_when_it_is_configured() -> None:
    payload = {
        "action": "labeled",
        "issue": {
            "number": 8,
            "title": "Investigate",
            "state": "open",
            "html_url": "https://github.com/acme/platform/issues/8",
            "user": {"login": "alice", "node_id": "MDQ6VXNlcjE="},
        },
        "label": {"name": "solvan"},
        "sender": {"login": "alice", "node_id": "MDQ6VXNlcjE="},
    }
    assert project_conversation_trigger(payload, event_name="issues", handle="solvan-bot") is None
    triggered = project_conversation_trigger(
        payload,
        event_name="issues",
        handle="solvan-bot",
        trigger_labels=frozenset({"Solvan"}),
    )
    assert triggered is not None and triggered.matched_label == "solvan"


def test_an_unrelated_event_is_not_a_trigger() -> None:
    assert (
        project_conversation_trigger(
            {"action": "opened", "repository": {}},
            event_name="push",
            handle="solvan-bot",
        )
        is None
    )


def test_a_thread_observation_changes_when_the_thread_closes() -> None:
    open_hash = thread_observation_hash(
        thread_kind=ThreadKind.ISSUE,
        external_number=7,
        state=ThreadState.OPEN,
        locked=False,
        head_commit_sha=None,
        title="Checkout latency",
    )
    closed_hash = thread_observation_hash(
        thread_kind=ThreadKind.ISSUE,
        external_number=7,
        state=ThreadState.CLOSED,
        locked=False,
        head_commit_sha=None,
        title="Checkout latency",
    )
    assert open_hash != closed_hash


# --------------------------------------------------------------------------
# Reads.
# --------------------------------------------------------------------------


def test_a_search_result_set_is_bounded_and_projected() -> None:
    transport = Transport(
        {
            "/search/issues": Response(
                {
                    "items": [
                        {
                            "number": 7,
                            "title": "Checkout latency",
                            "state": "open",
                            "html_url": "https://github.com/acme/platform/issues/7",
                        },
                        {"number": "not-a-number", "html_url": "https://x/y"},
                    ]
                }
            )
        }
    )
    hits = client(transport).search(query="repo:acme/platform latency", limit=10)
    assert len(hits) == 1
    assert hits[0].identifier == "7" and hits[0].state == "OPEN"


def test_a_search_kind_outside_the_two_available_is_refused() -> None:
    with pytest.raises(GitHubApiError, match="search kind"):
        client(Transport()).search(query="anything", search_kind="code")


def test_control_characters_are_stripped_from_untrusted_text() -> None:
    transport = Transport(
        {
            "/issues/7": Response(
                {
                    "number": 7,
                    "node_id": "MDU6SXNzdWU3",
                    "title": "Checkout\x07 latency",
                    "body": "line\x00one",
                    "state": "open",
                    "locked": False,
                    "user": {"login": "alice"},
                    "html_url": "https://github.com/acme/platform/issues/7",
                    "labels": [{"name": "bug"}],
                    "comments": 2,
                }
            )
        }
    )
    issue = client(transport).issue(owner="acme", name="platform", number=7)
    assert issue.title == "Checkout latency"
    assert issue.body == "lineone"
    assert issue.labels == ("bug",)


def test_an_issue_response_for_another_thread_is_refused() -> None:
    transport = Transport({"/issues/7": Response({"number": 9, "node_id": "x", "state": "open"})})
    with pytest.raises(GitHubApiError, match="does not identify"):
        client(transport).issue(owner="acme", name="platform", number=7)


def test_a_commit_window_that_ends_before_it_begins_is_refused() -> None:
    now = datetime.now(UTC)
    with pytest.raises(GitHubApiError, match="ends before it begins"):
        client(Transport()).commit_history(
            owner="acme", name="platform", since=now, until=now - timedelta(days=1)
        )


def test_a_commit_window_bound_must_carry_a_timezone() -> None:
    with pytest.raises(GitHubApiError, match="timezone"):
        client(Transport()).commit_history(
            owner="acme", name="platform", since=datetime(2026, 8, 1)
        )


def test_commit_history_filters_reach_the_request() -> None:
    transport = Transport({"/commits": Response([])})
    client(transport).commit_history(
        owner="acme",
        name="platform",
        author="alice",
        since=datetime(2026, 8, 1, tzinfo=UTC),
        limit=10,
    )
    url = transport.calls[0][1]
    assert "author=alice" in url and "since=" in url and "per_page=10" in url


# --------------------------------------------------------------------------
# Rate limiting is retryable, not a state conflict.
# --------------------------------------------------------------------------


def test_a_secondary_rate_limit_raises_the_retryable_class() -> None:
    transport = Transport(
        {"/issues/7": Response({}, status_code=403, headers={"Retry-After": "30"})}
    )
    with pytest.raises(GitHubRateLimited) as error:
        client(transport).issue(owner="acme", name="platform", number=7)
    assert error.value.retry_after_seconds == 30


def test_an_exhausted_primary_limit_raises_the_retryable_class() -> None:
    transport = Transport(
        {"/issues/7": Response({}, status_code=403, headers={"X-RateLimit-Remaining": "0"})}
    )
    with pytest.raises(GitHubRateLimited):
        client(transport).issue(owner="acme", name="platform", number=7)


def test_an_ordinary_forbidden_response_is_not_treated_as_rate_limiting() -> None:
    transport = Transport({"/issues/7": Response({}, status_code=403)})
    with pytest.raises(GitHubApiError) as error:
        client(transport).issue(owner="acme", name="platform", number=7)
    assert not isinstance(error.value, GitHubRateLimited)


# --------------------------------------------------------------------------
# Reading a repository without cloning it.
# --------------------------------------------------------------------------


def test_the_tree_read_tool_requires_an_exact_pinned_commit() -> None:
    from solvan.agents.read_tools import github_repository_tree_read

    for bad in ("HEAD", "main", "c" * 39, "C" * 40):
        with pytest.raises(ValueError, match="exact lowercase commit SHA"):
            github_repository_tree_read(
                "inv_1",
                "svc_1",
                "pgn_1",
                commit_sha=bad,
            )


def test_the_tree_read_tool_bounds_what_it_will_return() -> None:
    from solvan.agents.read_tools import github_repository_tree_read

    with pytest.raises(ValueError, match="bounds are invalid"):
        github_repository_tree_read(
            "inv_1", "svc_1", "pgn_1", commit_sha="c" * 40, maximum_files=10_000
        )
    with pytest.raises(ValueError, match="bounds are invalid"):
        github_repository_tree_read("inv_1", "svc_1", "pgn_1", commit_sha="c" * 40, maximum_bytes=1)


def test_no_agent_tool_offers_a_clone_a_token_or_a_git_remote() -> None:
    """The clone capability is delivered as content, never as credentials.

    INV-GT-14 is not amended by this work: whatever an agent can reach, it
    reaches without a GitHub credential. A tool named for cloning, pulling, or
    fetching a token would be the visible symptom of that having changed.
    """

    from solvan.agents import read_tools

    exported = {name for name in dir(read_tools) if not name.startswith("_")}
    forbidden = {
        name
        for name in exported
        if any(word in name for word in ("clone", "pull_repo", "token", "credential", "git_remote"))
    }
    assert not forbidden, forbidden


# --------------------------------------------------------------------------
# Deployments, discussions, and merge queue.
# --------------------------------------------------------------------------


def delivery_client(transport: Transport) -> GitHubDeliveryReadClient:
    return GitHubDeliveryReadClient(
        transport=transport,  # type: ignore[arg-type]
        token_provider=Tokens(),
        installation_id=42,
    )


def test_a_deployment_carries_the_state_it_last_reported() -> None:
    """A deployment without its state answers nothing worth knowing."""

    transport = Transport(
        {
            "/deployments/501/statuses": Response(
                [{"state": "success", "description": "shipped", "target_url": "https://x/y"}]
            ),
            "/deployments?": Response(
                [
                    {
                        "id": 501,
                        "sha": "c" * 40,
                        "ref": "main",
                        "task": "deploy",
                        "environment": "production",
                        "production_environment": True,
                        "creator": {"login": "alice"},
                        "created_at": "2026-08-20T00:00:00Z",
                    }
                ]
            ),
        }
    )
    deployments = delivery_client(transport).deployments(owner="acme", name="platform")
    assert len(deployments) == 1
    assert deployments[0].state == "SUCCESS"
    assert deployments[0].production_environment is True


def test_a_deployment_filter_requires_an_exact_commit() -> None:
    with pytest.raises(GitHubApiError, match="exact commit SHA"):
        delivery_client(Transport()).deployments(owner="acme", name="platform", sha="main")


def test_discussions_are_projected_without_their_bodies() -> None:
    """The body is unbounded prose from an arbitrary author; the title is not."""

    transport = Transport(
        {
            "/graphql": Response(
                {
                    "data": {
                        "repository": {
                            "discussions": {
                                "nodes": [
                                    {
                                        "number": 12,
                                        "title": "Checkout latency\x07",
                                        "url": "https://github.com/a/b/discussions/12",
                                        "createdAt": "2026-08-01T00:00:00Z",
                                        "updatedAt": "2026-08-02T00:00:00Z",
                                        "isAnswered": True,
                                        "category": {"name": "Q&A"},
                                        "author": {"login": "alice"},
                                    }
                                ]
                            }
                        }
                    }
                }
            )
        }
    )
    discussions = delivery_client(transport).discussions(owner="acme", name="platform")
    assert len(discussions) == 1
    assert discussions[0].title == "Checkout latency"
    assert discussions[0].answered is True
    assert not hasattr(discussions[0], "body")


def test_disabled_discussions_are_an_answer_not_a_failure() -> None:
    transport = Transport({"/graphql": Response({"data": {"repository": {"discussions": None}}})})
    assert delivery_client(transport).discussions(owner="acme", name="platform") == ()


def test_a_graphql_refusal_never_carries_its_text() -> None:
    """GraphQL error messages can quote repository content."""

    transport = Transport(
        {"/graphql": Response({"errors": [{"message": "secret internal detail"}]})}
    )
    with pytest.raises(GitHubApiError) as error:
        delivery_client(transport).discussions(owner="acme", name="platform")
    assert "secret internal detail" not in str(error.value)


def test_the_merge_queue_explains_why_a_passing_pull_request_has_not_landed() -> None:
    transport = Transport(
        {
            "/graphql": Response(
                {
                    "data": {
                        "repository": {
                            "mergeQueue": {
                                "entries": {
                                    "nodes": [
                                        {
                                            "position": 2,
                                            "state": "QUEUED",
                                            "enqueuedAt": "2026-08-20T00:00:00Z",
                                            "pullRequest": {"number": 8, "title": "Bound retry"},
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            )
        }
    )
    entries = delivery_client(transport).merge_queue(owner="acme", name="platform", branch="main")
    assert len(entries) == 1
    assert entries[0].pull_request_number == 8
    assert entries[0].position == 2
    assert entries[0].state == "QUEUED"


def test_no_configured_merge_queue_is_an_answer_not_a_failure() -> None:
    transport = Transport({"/graphql": Response({"data": {"repository": {"mergeQueue": None}}})})
    assert delivery_client(transport).merge_queue(owner="a", name="b", branch="main") == ()


def test_the_delivery_client_has_no_mutation_method() -> None:
    """A read client that could write would be one refactor from a defect."""

    public = {name for name in dir(GitHubDeliveryReadClient) if not name.startswith("_")}
    assert public == {"deployments", "discussions", "merge_queue"}
