"""Project one inbound conversational event, or decide it is not one.

Split from the provider's routes because this is the code an outsider can
cause to run. Anyone who can comment on a bound repository chooses the body,
the title, and the label that reach it, so keeping it in its own module keeps
that surface small enough to read in one sitting.

It never raises. Delivery reconciliation shares the webhook transaction, and
an attacker who can open an issue must not be able to reject Solvan's own
pull-request webhooks by crafting a malformed conversational payload.

Specification 24 §4 governs.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from solvan.application.github import GitHubContractError
from solvan.application.github_conversation import (
    GitHubConversationError,
    TriggerKind,
    require_admitted_participant,
)
from solvan.domain import Scope
from solvan.persistence.github_conversation_store import GitHubConversationStore
from solvan.platform.github_conversation_events import project_conversation_trigger


class ConversationIngestSettings(Protocol):
    """What projection needs from provider settings, and nothing more."""

    @property
    def scope(self) -> Scope: ...

    @property
    def app_handle(self) -> str: ...

    @property
    def trigger_labels(self) -> tuple[str, ...]: ...


def project_conversation(
    connection: Any,
    *,
    settings: ConversationIngestSettings,
    repository_id: str,
    payload: Mapping[str, Any],
    event_name: str,
    event_id: str,
) -> str | None:
    """Record an inbound mention or label, and report the sender's standing.

    Runs inside the webhook transaction, on the payload the ingress already
    authenticated and decoded — this surface never re-parses the body, so
    there is no second reading of it that could disagree with the first.

    It never raises: a malformed or unrecognised conversational payload must
    not fail the delivery reconciliation that shares this transaction, and an
    attacker who can open an issue must not be able to reject Solvan's own
    pull-request webhooks by crafting one.

    The returned admission is an observation for the caller's benefit. It is
    not authority — an ADMITTED sender still reaches only a thread projection,
    and every publication passes the approval gate regardless.
    """

    if not settings.app_handle and not settings.trigger_labels:
        return None
    try:
        trigger = project_conversation_trigger(
            dict(payload),
            event_name=event_name,
            handle=settings.app_handle or None,
            trigger_labels=frozenset(settings.trigger_labels),
        )
        if trigger is None:
            return None
        store = GitHubConversationStore(connection)
        admission = store.record_sighting(
            scope=settings.scope,
            repository_id=repository_id,
            login=trigger.sender_login,
            account_node_id=trigger.sender_node_id,
        )
        try:
            require_admitted_participant(admission)
        except GitHubConversationError:
            # The event is still recorded and still projected — an operator has
            # to be able to see who is asking before deciding whether they may.
            # What it does not become is an address: an unadmitted sender's
            # mention is a sighting, so the thread records no trigger and
            # nothing downstream can read one from it. Absence denies.
            trigger_kind = TriggerKind.NONE
        else:
            trigger_kind = trigger.trigger
        store.upsert_thread(
            scope=settings.scope,
            repository_id=repository_id,
            thread_kind=trigger.thread_kind,
            external_number=trigger.external_number,
            title=trigger.title,
            state=trigger.state,
            locked=trigger.locked,
            html_url=trigger.html_url,
            author_login=trigger.author_login or None,
            head_commit_sha=trigger.head_commit_sha,
            trigger_kind=trigger_kind,
            event_id=event_id,
        )
        return admission.value
    except (GitHubConversationError, GitHubContractError, ValueError, TypeError, KeyError):
        return None
