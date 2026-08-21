"""Which operations require a step-up, and what a challenge authorizes.

Specification 05 §4.2. "Every consequential operation" is prose no test can
fail, so the operations are enumerated here and every route is mapped to an
entry or explicitly recorded as requiring none. Whether something is
consequential stops being a property a reviewer has to notice.

A challenge authorizes one decision: one actor, one session, one operation, one
material digest, once. Freshness alone authorizes nothing, because a person who
authenticated a minute ago is not thereby authorized for an unrelated action.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


def material_digest(material: str) -> str:
    """The digest of the exact thing a challenge authorizes.

    One definition, because both halves must agree byte for byte: the console
    computes it to request the step-up and the route recomputes it to spend the
    challenge. A second copy that drifted would not fail loudly — it would
    refuse every action with "the material changed", which reads like the
    control working.
    """

    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


class ActionChallengeError(RuntimeError):
    """A challenge cannot be issued or consumed as asked."""


class ChallengeState(StrEnum):
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"
    TERMINAL = "TERMINAL"


class TerminalReason(StrEnum):
    EXPIRED = "EXPIRED"
    ROLE_REMOVED = "ROLE_REMOVED"
    MATERIAL_CHANGED = "MATERIAL_CHANGED"
    SESSION_ROTATED = "SESSION_ROTATED"
    CALLBACK_FAILED = "CALLBACK_FAILED"


@dataclass(frozen=True, slots=True)
class ChallengeOperation:
    """One enumerated operation and the authority it requires."""

    key: str
    required_role: str
    summary: str


def _operation(key: str, role: str, summary: str) -> ChallengeOperation:
    return ChallengeOperation(key=key, required_role=role, summary=summary)


#: The closed set. Adding a consequential route without adding it here is caught
#: by the coverage check rather than noticed in review.
CHALLENGE_OPERATIONS: dict[str, ChallengeOperation] = {
    operation.key: operation
    for operation in (
        _operation("estate.connect", "ADMIN", "Bind a customer Google Cloud estate"),
        _operation("estate.disable", "ADMIN", "Disable an enrolled estate connection"),
        _operation("relay.disable", "ADMIN", "Disable a Solvant Relay enrollment"),
        _operation("relay.enroll", "ADMIN", "Enroll a customer-resident Relay"),
        _operation("github.bind", "ADMIN", "Bind a GitHub App repository"),
        _operation("role.grant", "ADMIN", "Grant or revoke a role binding"),
        _operation("action.approve", "APPROVER", "Approve one exact production action"),
        _operation("code_change.decide", "APPROVER", "Decide one exact code change"),
        _operation("production_graph.approve", "APPROVER", "Promote a Production Graph snapshot"),
        _operation("alert.command", "OPERATOR", "Retriage or escalate one alert"),
        _operation("alert.policy.simulate", "OPERATOR", "Simulate a draft alert policy"),
        _operation("repair.command", "OPERATOR", "Advance a reliability case"),
        _operation("guidance.author", "OPERATOR", "Author or submit a guidance revision"),
        _operation("guidance.approve", "APPROVER", "Approve one exact guidance revision"),
        _operation("guidance.lifecycle", "ADMIN", "Deprecate or retire a guidance revision"),
        _operation("trigger_policy.author", "OPERATOR", "Author or evaluate a trigger policy"),
        _operation("trigger_policy.approve", "APPROVER", "Approve one exact trigger policy"),
        _operation("trigger_policy.activate", "ADMIN", "Move a trigger policy lifecycle head"),
        _operation("skills.govern", "ADMIN", "Change skill ownership, licensing, or destinations"),
        _operation("thread.access.decide", "OPERATOR", "Decide one conversational access request"),
        _operation("relay.revoke", "ADMIN", "Revoke a Solvant Relay enrollment"),
    )
}

#: A challenge is short-lived by construction. Long enough to complete a redirect
#: and a form, short enough that an abandoned one is not lying around.
CHALLENGE_LIFETIME = timedelta(minutes=5)


def operation(key: str) -> ChallengeOperation:
    """Look up an enumerated operation, refusing anything unregistered."""

    try:
        return CHALLENGE_OPERATIONS[key]
    except KeyError as error:
        raise ActionChallengeError(
            f"{key} is not a registered challenge operation; register it rather than "
            "authorizing an operation nothing describes"
        ) from error


@dataclass(frozen=True, slots=True)
class IssuedChallenge:
    """A challenge as stored, read back for consumption."""

    challenge_id: str
    actor_id: str
    session_id: str
    operation: str
    material_digest: str
    csrf_token_hash: str
    expires_at: datetime
    status: str


def authorize_consumption(
    *,
    challenge: IssuedChallenge,
    actor_id: str,
    session_id: str,
    operation_key: str,
    material_digest: str,
    csrf_token_hash: str,
    current_roles: frozenset[str],
    now: datetime,
) -> ChallengeOperation:
    """Decide whether this challenge authorizes this exact decision, now.

    Every binding is rechecked at consumption rather than trusted from issuance.
    A role removed between the two must stop the action, which is the whole
    reason roles are not carried in the challenge.
    """

    if challenge.status != ChallengeState.ISSUED:
        raise ActionChallengeError("this challenge has already been used or ended")
    if now >= challenge.expires_at:
        raise ActionChallengeError("this challenge expired before it was used")
    if challenge.actor_id != actor_id:
        raise ActionChallengeError("this challenge belongs to another actor")
    if challenge.session_id != session_id:
        # Rotation between issuance and use is the ordinary case for a stale
        # tab, and rebinding would let a challenge outlive the session it was
        # granted within.
        raise ActionChallengeError("this challenge belongs to another session")
    if challenge.operation != operation_key:
        raise ActionChallengeError("this challenge authorizes a different operation")
    if challenge.material_digest != material_digest:
        raise ActionChallengeError(
            "the material changed after this challenge was granted; it authorizes "
            "what was shown, not what is being submitted"
        )
    if challenge.csrf_token_hash != csrf_token_hash:
        raise ActionChallengeError("cross-site request refused")
    registered = operation(operation_key)
    if registered.required_role not in current_roles:
        raise ActionChallengeError(
            f"{registered.required_role} is required for {operation_key} and is not held now"
        )
    return registered
