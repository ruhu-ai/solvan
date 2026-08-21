"""Grants: the only way the Liaison may read or propose on anyone's behalf.

The service identity must never be usable on its own account, so every
projection read and every coordinator submission carries a grant minted from
verified identity. Two kinds, because one object cannot serve both jobs:

- `ConversationReadGrant` is reusable within a single turn — a turn makes many
  reads, so a one-time nonce would be wrong — and is bound to the projection
  API audience. Each individual read still carries its own request digest.
- `SteerSubmissionGrant` is one-time, minted only after a human decision, and
  bound to the coordinator inbox audience.

The audiences are disjoint and non-interchangeable: presenting a read grant to
the coordinator is refused, which is what stops a confused deputy from turning
a question into work. Specification 14 §10.2.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from solvan.domain import Scope


class GrantError(RuntimeError):
    """A grant is absent, expired, replayed, or presented to the wrong audience."""


class Audience(StrEnum):
    PROJECTION_API = "PROJECTION_API"
    COORDINATOR_INBOX = "COORDINATOR_INBOX"


#: Read tools a conversation grant may authorize. Naming them on the grant
#: means a compromised turn cannot reach a projection the request never
#: intended, even if the registry would otherwise permit the tool.
READ_METHODS = frozenset(
    {
        "resolve_anchor",
        "read_projection",
        "list_prior_incidents",
        "search_records",
        "catch_up",
        "recall_conversation",
        "recall_memory",
    }
)

DEFAULT_READ_GRANT_TTL = timedelta(minutes=10)
DEFAULT_STEER_GRANT_TTL = timedelta(minutes=5)


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ConversationReadGrant:
    """Reusable within one turn; every read verifies its own request digest."""

    principal: str
    scope: Scope
    thread_id: str
    message_id: str
    attempt: int
    anchor_label: str
    classification_ceiling: str
    policy_epoch: int
    allowed_methods: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    anchor_entity_set_digest: str = ""
    audience: Audience = Audience.PROJECTION_API

    def __post_init__(self) -> None:
        unknown = self.allowed_methods - READ_METHODS
        if unknown:
            raise GrantError(f"grant names unknown read methods: {', '.join(sorted(unknown))}")
        if self.expires_at <= self.issued_at:
            raise GrantError("a grant must expire after it is issued")

    def request_digest(self, method: str, arguments: dict[str, object]) -> str:
        """Bind one read to this grant, so a digest cannot be reused elsewhere."""

        return _digest(
            {
                "grant": self.identity_digest(),
                "method": method,
                "arguments": arguments,
            }
        )

    def identity_digest(self) -> str:
        return _digest(
            {
                "principal": self.principal,
                "scope": self.scope.canonical_dict(),
                "thread": self.thread_id,
                "message": self.message_id,
                "attempt": self.attempt,
                "anchor": self.anchor_label,
                "anchor_entity_set_digest": self.anchor_entity_set_digest,
                "policy_epoch": self.policy_epoch,
                "audience": str(self.audience),
                "issued_at": self.issued_at,
            }
        )

    def authorize(self, method: str, *, now: datetime | None = None) -> None:
        """Refuse an expired grant or a method it never covered."""

        moment = now or datetime.now(UTC)
        if moment >= self.expires_at:
            raise GrantError("the conversation read grant has expired")
        if self.audience is not Audience.PROJECTION_API:
            raise GrantError("this grant is not addressed to the projection API")
        if method not in self.allowed_methods:
            raise GrantError(f"the grant does not authorize {method}")


@dataclass(frozen=True, slots=True)
class SteerSubmissionGrant:
    """One-time, coordinator-addressed, and bound to a specific decision."""

    parked_request_id: str
    decided_payload_hash: str
    initiating_principal: str
    confirming_principal: str
    scope: Scope
    expected_workflow_version: int | None
    expected_plan_version: int | None
    issued_at: datetime
    expires_at: datetime
    nonce: str
    audience: Audience = Audience.COORDINATOR_INBOX

    def envelope(self) -> dict[str, object]:
        """Exactly what the coordinator receives; it revalidates all of it."""

        return {
            "parked_request_id": self.parked_request_id,
            "decided_payload_hash": self.decided_payload_hash,
            "initiating_principal": self.initiating_principal,
            "confirming_principal": self.confirming_principal,
            "scope": self.scope.canonical_dict(),
            "expected_workflow_version": self.expected_workflow_version,
            "expected_plan_version": self.expected_plan_version,
            "audience": str(self.audience),
            "nonce": self.nonce,
        }

    def digest(self) -> str:
        return _digest(self.envelope())


class GrantIssuer:
    """Mints grants from verified identity and records their consumption.

    Consumption is tracked in memory here and persisted by the store; the point
    of the class is that nothing else in the service may construct a grant.
    """

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def read_grant(
        self,
        *,
        principal: str,
        scope: Scope,
        thread_id: str,
        message_id: str,
        attempt: int,
        anchor_label: str,
        anchor_entity_set_digest: str = "",
        classification_ceiling: str,
        policy_epoch: int,
        methods: frozenset[str] = READ_METHODS,
        now: datetime | None = None,
        ttl: timedelta = DEFAULT_READ_GRANT_TTL,
    ) -> ConversationReadGrant:
        issued = now or datetime.now(UTC)
        return ConversationReadGrant(
            principal=principal,
            scope=scope,
            thread_id=thread_id,
            message_id=message_id,
            attempt=attempt,
            anchor_label=anchor_label,
            anchor_entity_set_digest=anchor_entity_set_digest,
            classification_ceiling=classification_ceiling,
            policy_epoch=policy_epoch,
            allowed_methods=methods,
            issued_at=issued,
            expires_at=issued + ttl,
        )

    def steer_grant(
        self,
        *,
        parked_request_id: str,
        decided_payload_hash: str,
        initiating_principal: str,
        confirming_principal: str,
        scope: Scope,
        expected_workflow_version: int | None,
        expected_plan_version: int | None,
        nonce: str,
        now: datetime | None = None,
        ttl: timedelta = DEFAULT_STEER_GRANT_TTL,
    ) -> SteerSubmissionGrant:
        issued = now or datetime.now(UTC)
        return SteerSubmissionGrant(
            parked_request_id=parked_request_id,
            decided_payload_hash=decided_payload_hash,
            initiating_principal=initiating_principal,
            confirming_principal=confirming_principal,
            scope=scope,
            expected_workflow_version=expected_workflow_version,
            expected_plan_version=expected_plan_version,
            issued_at=issued,
            expires_at=issued + ttl,
            nonce=nonce,
        )

    def consume_steer_grant(
        self, grant: SteerSubmissionGrant, *, now: datetime | None = None
    ) -> dict[str, object]:
        """Spend a one-time grant, or refuse a replay or an expired one."""

        moment = now or datetime.now(UTC)
        if grant.audience is not Audience.COORDINATOR_INBOX:
            raise GrantError("this grant is not addressed to the coordinator inbox")
        if moment >= grant.expires_at:
            raise GrantError("the steer submission grant has expired")
        digest = grant.digest()
        if digest in self._consumed:
            raise GrantError("the steer submission grant has already been used")
        self._consumed.add(digest)
        return grant.envelope()


def verify_read_request(
    grant: ConversationReadGrant,
    *,
    method: str,
    arguments: dict[str, object],
    presented_digest: str,
    now: datetime | None = None,
) -> None:
    """The projection layer's whole authorization check, in one place."""

    grant.authorize(method, now=now)
    expected = grant.request_digest(method, arguments)
    if not hmac.compare_digest(expected, presented_digest):
        raise GrantError("the read request digest does not match its grant")
