"""Project conversational facts from an already-verified GitHub webhook.

`github_webhook.parse_webhook` owns authentication and the pull-request
lifecycle projection that governed delivery reconciles against.  This module
runs *after* it, on the same verified bytes, and answers a different question:
did somebody just ask Solvan to do something, and on which thread?

The separation is deliberate.  Delivery reconciliation must keep working
whatever arrives here, so nothing in this module can make a delivery webhook
fail; an unrecognised or malformed conversational payload yields "no trigger"
rather than an exception that would reject the delivery.

Everything projected here is attacker-controlled text.  Anyone who can comment
on a public repository can choose the body, the title, and the label.  So the
projection answers only bounded, structural questions — which number, which
kind, was the handle mentioned — and never lets that text decide authority.
Whether the sender may cause action is settled separately against the
participant table (specification 24 §4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from solvan.application.github_conversation import ThreadKind, ThreadState, TriggerKind

#: A mention is the handle as GitHub renders it: `@name`, not preceded by a
#: word character (so `email@handle` is not a mention) and terminated by a
#: non-name character.
_MENTION_TEMPLATE = r"(?<![A-Za-z0-9_-])@{handle}(?![A-Za-z0-9-])"

_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$")
_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?$")

#: Bodies above this size are truncated before the mention scan. A megabyte of
#: text cannot change whether a handle appears in the first 64 KB, and scanning
#: it would be a free CPU cost for anyone who can open an issue.
_MENTION_SCAN_BYTES = 65_536

_CONVERSATION_EVENTS = frozenset({"issue_comment", "issues", "pull_request_review_comment"})


@dataclass(frozen=True, slots=True)
class ConversationTrigger:
    """One inbound conversational event, projected and bounded.

    `trigger` says what kind of address this was; `sender_login` says who made
    it. Neither is authority — both are inputs to an admission decision made
    against the participant table.
    """

    thread_kind: ThreadKind
    external_number: int
    title: str
    state: ThreadState
    locked: bool
    html_url: str
    author_login: str
    sender_login: str
    sender_node_id: str
    trigger: TriggerKind
    comment_id: int | None
    comment_body: str
    head_commit_sha: str | None
    matched_label: str | None


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(character for character in value if character == "\n" or character >= " ")
    return cleaned[:limit]


def _actor(value: Any) -> tuple[str, str]:
    """Return one actor's login and node id, or empties when unusable."""

    if not isinstance(value, dict):
        return "", ""
    login = value.get("login")
    node_id = value.get("node_id")
    if not isinstance(login, str) or _LOGIN.fullmatch(login) is None:
        return "", ""
    return login, node_id[:128] if isinstance(node_id, str) else ""


def mentions_handle(body: str, *, handle: str) -> bool:
    """Whether `body` addresses `handle` as a GitHub mention.

    Deliberately not a substring test.  `@solvan-bot` inside a code fence or a
    quoted earlier comment still counts — GitHub itself would notify on it, and
    a rule that disagreed with GitHub's own notification behaviour would be
    surprising in the direction of missing real requests.
    """

    if _HANDLE.fullmatch(handle) is None:
        raise ValueError("GitHub mention handle is malformed")
    pattern = _MENTION_TEMPLATE.format(handle=re.escape(handle))
    return re.search(pattern, body[:_MENTION_SCAN_BYTES], flags=re.IGNORECASE) is not None


def project_conversation_trigger(
    payload: dict[str, Any],
    *,
    event_name: str,
    handle: str | None,
    trigger_labels: frozenset[str] = frozenset(),
) -> ConversationTrigger | None:
    """Project one conversational trigger, or nothing.

    Returns `None` for every event this surface does not act on, including
    well-formed events of the right type that simply do not address Solvan.
    """

    if event_name not in _CONVERSATION_EVENTS:
        return None
    action = payload.get("action")
    if not isinstance(action, str):
        return None

    subject = payload.get("issue")
    if not isinstance(subject, dict):
        subject = payload.get("pull_request")
    if not isinstance(subject, dict):
        return None

    number = subject.get("number")
    if not isinstance(number, int) or number <= 0:
        return None

    sender_login, sender_node_id = _actor(payload.get("sender"))
    if not sender_login:
        return None

    comment = payload.get("comment")
    comment_body = ""
    comment_id: int | None = None
    if isinstance(comment, dict):
        comment_body = _text(comment.get("body"), _MENTION_SCAN_BYTES)
        raw_id = comment.get("id")
        comment_id = raw_id if isinstance(raw_id, int) and raw_id > 0 else None

    trigger, matched_label = _classify(
        payload,
        event_name=event_name,
        action=action,
        subject=subject,
        comment_body=comment_body,
        handle=handle,
        trigger_labels=trigger_labels,
    )
    if trigger is None:
        return None

    is_pull = (
        event_name == "pull_request_review_comment"
        or isinstance(subject.get("pull_request"), dict)
        or "pull_request" in payload
    )
    head_sha: str | None = None
    if is_pull:
        head = subject.get("head")
        candidate = head.get("sha") if isinstance(head, dict) else None
        if (
            isinstance(candidate, str)
            and len(candidate) == 40
            and all(character in "0123456789abcdef" for character in candidate)
        ):
            head_sha = candidate

    state_text = _text(subject.get("state"), 32).upper()
    html_url = _text(subject.get("html_url"), 500)
    if not html_url.startswith("https://"):
        return None
    author_login, _ = _actor(subject.get("user"))

    return ConversationTrigger(
        thread_kind=ThreadKind.PULL_REQUEST if is_pull else ThreadKind.ISSUE,
        external_number=number,
        title=_text(subject.get("title"), 256) or "(untitled)",
        state=ThreadState.CLOSED if state_text == "CLOSED" else ThreadState.OPEN,
        locked=bool(subject.get("locked", False)),
        html_url=html_url,
        author_login=author_login,
        sender_login=sender_login,
        sender_node_id=sender_node_id,
        trigger=trigger,
        comment_id=comment_id,
        comment_body=comment_body[:8_000],
        head_commit_sha=head_sha,
        matched_label=matched_label,
    )


def _classify(
    payload: dict[str, Any],
    *,
    event_name: str,
    action: str,
    subject: dict[str, Any],
    comment_body: str,
    handle: str | None,
    trigger_labels: frozenset[str],
) -> tuple[TriggerKind | None, str | None]:
    """Decide what kind of address this event is, if any.

    A deployment with no configured handle recognises no mention at all. That
    is the safe reading of absent configuration: inventing a handle would make
    Solvan answer threads addressed to somebody else.
    """

    if event_name in {"issue_comment", "pull_request_review_comment"}:
        # Only a newly written comment is an address. An edit is not: treating
        # edits as triggers lets anyone re-fire Solvan on an old thread
        # arbitrarily often by toggling a character.
        if action != "created" or not comment_body or not handle:
            return None, None
        if mentions_handle(comment_body, handle=handle):
            return TriggerKind.MENTION, None
        return None, None

    if action == "labeled" and trigger_labels:
        label = payload.get("label")
        name = _text(label.get("name") if isinstance(label, dict) else "", 100)
        if name and name.lower() in {item.lower() for item in trigger_labels}:
            return TriggerKind.LABEL, name
        return None, None

    if action in {"opened", "reopened"} and handle:
        body = _text(subject.get("body"), _MENTION_SCAN_BYTES)
        if body and mentions_handle(body, handle=handle):
            return TriggerKind.MENTION, None
    return None, None
