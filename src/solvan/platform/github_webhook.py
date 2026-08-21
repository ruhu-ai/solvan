"""Bounded GitHub webhook authentication and lifecycle projection.

This ingress boundary is deliberately separate from the installation-token
client.  A webhook is authenticated with its shared secret before any JSON is
decoded, and only the lifecycle fields that the provider persists are
projected from GitHub's untrusted payload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

from solvan.application.github import GitHubContractError, GitHubWebhookEnvelope


def payload_hash(body: bytes) -> str:
    """Return the durable digest of the exact signed webhook body."""

    return "sha256:" + hashlib.sha256(body).hexdigest()


def verify_webhook_signature(*, secret: bytes, body: bytes, signature: str | None) -> bool:
    """Verify GitHub's X-Hub-Signature-256 without accepting legacy SHA-1."""

    if not secret or not signature or not signature.startswith("sha256="):
        return False
    supplied = signature.removeprefix("sha256=")
    if len(supplied) != 64:
        return False
    try:
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, supplied)


def verified_webhook_payload(
    *,
    body: bytes,
    delivery_id: str | None,
    event_name: str | None,
    signature: str | None,
    webhook_secret: bytes,
) -> dict[str, Any]:
    """Authenticate the delivery and decode it once.

    Separated from projection because a single GitHub App sends every
    repository's deliveries to one URL, so which binding a delivery belongs to
    can only be answered *after* the payload is readable — and must not be
    answered from anything but authenticated bytes.
    """

    verified = verify_webhook_signature(secret=webhook_secret, body=body, signature=signature)
    if not verified:
        raise GitHubContractError("GitHub webhook signature verification failed")
    if not delivery_id or not event_name:
        raise GitHubContractError("GitHub webhook delivery and event headers are required")
    if len(body) > 2_000_000:
        raise GitHubContractError("GitHub webhook body exceeds the bounded ingress limit")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise GitHubContractError("GitHub webhook body is not JSON") from error
    if not isinstance(value, dict):
        raise GitHubContractError("GitHub webhook body must be an object")
    return value


def webhook_repository_identity(payload: Mapping[str, Any]) -> tuple[str, str]:
    """Return the owner and name the delivery names, or refuse.

    This is a lookup key, never authority: the caller resolves it to a binding
    that must already exist in this scope, and a delivery naming a repository
    nobody bound is refused rather than bound implicitly.
    """

    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise GitHubContractError("GitHub webhook has no repository object")
    owner_value = repository.get("owner")
    owner = owner_value.get("login") if isinstance(owner_value, dict) else None
    name = repository.get("name")
    if not isinstance(owner, str) or not isinstance(name, str) or not owner or not name:
        raise GitHubContractError("GitHub webhook repository identity is incomplete")
    if len(owner) > 39 or len(name) > 100:
        raise GitHubContractError("GitHub webhook repository identity is oversized")
    return owner, name


def project_webhook(
    *,
    payload: Mapping[str, Any],
    body: bytes,
    delivery_id: str,
    event_name: str,
    repository_id: str,
) -> GitHubWebhookEnvelope:
    """Project only the bounded lifecycle fields reconciliation needs."""

    owner, name = webhook_repository_identity(payload)
    action = payload.get("action")
    sender = payload.get("sender")
    sender_login = sender.get("login") if isinstance(sender, dict) else None
    installation = payload.get("installation")
    installation_id = installation.get("id") if isinstance(installation, dict) else None
    pull = payload.get("pull_request")
    number = payload.get("number")
    if isinstance(pull, dict):
        number = number if isinstance(number, int) else pull.get("number")
        head = pull.get("head")
        base = pull.get("base")
        head_sha = head.get("sha") if isinstance(head, dict) else None
        base_sha = base.get("sha") if isinstance(base, dict) else None
        merged = pull.get("merged") if isinstance(pull.get("merged"), bool) else None
    else:
        head_sha = base_sha = None
        merged = None
    return GitHubWebhookEnvelope(
        delivery_id=delivery_id,
        event_name=event_name,
        action=action if isinstance(action, str) else None,
        repository_id=repository_id,
        owner=owner,
        name=name,
        sender_login=sender_login if isinstance(sender_login, str) else None,
        installation_id=installation_id if isinstance(installation_id, int) else None,
        payload_hash=payload_hash(body),
        signature_verified=True,
        pull_request_number=number if isinstance(number, int) and number > 0 else None,
        pull_request_head_sha=head_sha if isinstance(head_sha, str) else None,
        pull_request_base_sha=base_sha if isinstance(base_sha, str) else None,
        pull_request_merged=merged,
    )


def parse_webhook(
    *,
    body: bytes,
    delivery_id: str | None,
    event_name: str | None,
    signature: str | None,
    webhook_secret: bytes,
    repository_id: str,
) -> GitHubWebhookEnvelope:
    """Verify and project in one step, for a caller that already knows the binding."""

    payload = verified_webhook_payload(
        body=body,
        delivery_id=delivery_id,
        event_name=event_name,
        signature=signature,
        webhook_secret=webhook_secret,
    )
    return project_webhook(
        payload=payload,
        body=body,
        delivery_id=str(delivery_id),
        event_name=str(event_name),
        repository_id=repository_id,
    )
