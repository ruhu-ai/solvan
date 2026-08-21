"""Steer: a human-confirmed request for a bounded investigation step.

The whole point of Steer is that it changes nothing about who may do what. A
person asks the Liaison to look somewhere; the Liaison drafts a typed step; the
person confirms it; and the coordinator then decides, under exactly the gates it
applies to an agent's own proposal. The Liaison's contribution is a request, not
an authorization.

Three things make that true rather than merely stated. The confirmation is a
CAS, so a stale or racing decision loses. What crosses the boundary is a typed
object identified by the digest of what was displayed — never prose. And the
submission carries a one-time grant addressed to the coordinator inbox, which
is a different audience from the projection API, so a read grant can never be
presented as proof of steer authority.

Specification 14 §14-15 and §10.2.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from psycopg import Connection

from solvan.application.liaison.grants import GrantError, GrantIssuer
from solvan.application.liaison.parts import AccessMode, Part, PartKind
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import canonical_hash
from solvan.persistence.liaison_parked import (
    DecisionOutcome,
    ParkedKind,
    ParkedRequestStore,
)
from solvan.persistence.liaison_policy import current_policy_epoch


class SteerRefused(RuntimeError):
    """The steer could not proceed, with a reason a person can act on."""


@dataclass(frozen=True, slots=True)
class SteerDraft:
    """The typed step a principal is shown before anything is requested."""

    purpose: str
    agent: str
    tool_profile: tuple[str, ...]
    budget: str
    anchor_record_type: str
    anchor_record_id: str
    dependencies: tuple[str, ...] = ()

    def payload(self) -> dict[str, Any]:
        return {
            "purpose": self.purpose,
            "agent": self.agent,
            "tool_profile": list(self.tool_profile),
            "budget": self.budget,
            "anchor_record_type": self.anchor_record_type,
            "anchor_record_id": self.anchor_record_id,
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True, slots=True)
class SteerSubmission:
    """What the coordinator receives. It revalidates every field itself."""

    parked_request_id: str
    envelope: dict[str, Any]
    inbox_id: str


#: Tool profiles a steer may request. A step that could mutate anything is
#: absent by construction, so confirming a steer cannot widen the read-only
#: boundary the investigation already had.
READ_ONLY_TOOL_PROFILES = frozenset(
    {"metrics.read", "logs.read", "traces.read", "config.read", "inventory.read"}
)


def draft_is_read_only(draft: SteerDraft) -> bool:
    return bool(draft.tool_profile) and set(draft.tool_profile) <= READ_ONLY_TOOL_PROFILES


class SteerService:
    """Parks a drafted step, and submits it only after a human decides."""

    def __init__(self, *, issuer: GrantIssuer) -> None:
        self._issuer = issuer

    def park_draft(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        thread_id: str,
        message_id: str,
        draft: SteerDraft,
        principal: str,
        expected_workflow_version: int | None,
        expected_plan_version: int | None,
    ) -> str:
        """Show the typed step and wait. Nothing is requested yet."""

        if not draft_is_read_only(draft):
            raise SteerRefused("a steer may only request read-only tools; this draft asks for more")
        request_id = new_identifier("prk")
        binding_epoch = current_policy_epoch(connection, scope=scope, principal=principal)
        displayed_payload = {
            **draft.payload(),
            "kind": str(ParkedKind.STEER_CONFIRMATION),
            "request_id": request_id,
        }
        ParkedRequestStore(connection).park(
            scope=scope,
            thread_id=thread_id,
            message_id=message_id,
            kind=ParkedKind.STEER_CONFIRMATION,
            payload=displayed_payload,
            initiated_by_principal=principal,
            expected_workflow_version=expected_workflow_version,
            expected_plan_version=expected_plan_version,
            binding_id=f"principal:{principal}",
            binding_epoch=binding_epoch,
            request_id=request_id,
        )
        # The parked row is workflow authority; this typed part is its durable
        # reader projection. Both land in the caller's transaction. Without the
        # part, a reload made the confirmation vanish even though it was still
        # waiting in the ledger.
        from solvan.persistence.liaison_store import LiaisonStore

        LiaisonStore(connection).append_parts(
            scope=scope,
            message_id=message_id,
            parts=(
                Part(
                    kind=PartKind.PARKED_REQUEST,
                    sequence=0,
                    payload=displayed_payload,
                    classification="INTERNAL",
                    access_mode=AccessMode.AUTHOR_ONLY,
                    author_principal=principal,
                ),
            ),
        )
        return request_id

    def confirm(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        request_id: str,
        confirming_principal: str,
        decided_payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        current_workflow_version: int | None = None,
        current_plan_version: int | None = None,
    ) -> SteerSubmission:
        """Decide the request and, if it wins, submit it to the coordinator.

        The role is read here, in this transaction, from the authoritative
        bindings — never accepted as an argument. A caller cannot assert its own
        authority, and a binding that expired between parking and confirming is
        already gone by the time the CAS runs.
        """

        store = ParkedRequestStore(connection)
        request = store.get(scope=scope, request_id=request_id)
        if request is None or request.kind is not ParkedKind.STEER_CONFIRMATION:
            raise SteerRefused("no such steer confirmation")
        if not _holds_operator_role(connection, scope=scope, principal=confirming_principal):
            raise SteerRefused(
                "only a principal with operator role on the anchored entity may confirm a steer"
            )

        decision = store.decide(
            scope=scope,
            request_id=request_id,
            principal=confirming_principal,
            accept=True,
            decided_payload=decided_payload,
            idempotency_key=idempotency_key,
            current_workflow_version=current_workflow_version,
            current_plan_version=current_plan_version,
            binding_epoch=current_policy_epoch(
                connection, scope=scope, principal=confirming_principal
            ),
        )
        if decision.outcome in {
            DecisionOutcome.WIDENED,
            DecisionOutcome.FORBIDDEN,
            DecisionOutcome.CONFLICT,
        }:
            raise SteerRefused(decision.reason)

        if decision.outcome is DecisionOutcome.REPLAYED:
            # The decision already happened. Return what was submitted rather
            # than minting a second grant and a second inbox entry.
            stored = _stored_submission(connection, scope=scope, request_id=request_id)
            if stored is not None:
                return stored

        # A one-time grant, addressed to the coordinator inbox. The read grant
        # the turn used cannot stand in for this one: different audience.
        grant = self._issuer.steer_grant(
            parked_request_id=request_id,
            decided_payload_hash=str(decision.decided_payload_hash),
            initiating_principal=request.initiated_by_principal,
            confirming_principal=confirming_principal,
            scope=scope,
            expected_workflow_version=request.expected_workflow_version,
            expected_plan_version=request.expected_plan_version,
            nonce=new_identifier("non"),
        )
        try:
            envelope = self._issuer.consume_steer_grant(grant)
        except GrantError as error:
            raise SteerRefused(str(error)) from error

        # What actually leaves is re-checked, not assumed to be what was parked.
        # The park-time check bound the draft; this one binds the decision.
        step = decision.decided_payload or {}
        if not set(map(str, step.get("tool_profile") or ())) <= READ_ONLY_TOOL_PROFILES:
            raise SteerRefused("the decided step asks for a tool a steer may not request")
        envelope["step"] = step
        inbox_id = _submit_to_coordinator_inbox(
            connection, scope=scope, request_id=request_id, envelope=envelope
        )
        _record_grant_receipt(
            connection,
            scope=scope,
            principal=confirming_principal,
            request_id=request_id,
        )
        return SteerSubmission(request_id, envelope, inbox_id)


def _holds_operator_role(connection: Connection[Any], *, scope: Scope, principal: str) -> bool:
    """Whether this principal holds a live OPERATOR binding in this scope.

    Absence refuses. An unexpired binding is required, so a lapsed operator
    cannot confirm a steer that was parked while they still held the role.
    """

    row = connection.execute(
        """SELECT EXISTS (
             SELECT 1 FROM solvan.actor_role_bindings
             WHERE organization_id = %(organization_id)s
               AND project_id = %(project_id)s
               AND environment_id = %(environment_id)s
               AND principal = %(principal)s AND role = 'OPERATOR'
               AND (expires_at IS NULL OR expires_at > now()))""",
        {**scope.canonical_dict(), "principal": principal},
    ).fetchone()
    return bool(row and row[0])


def _stored_submission(
    connection: Connection[Any], *, scope: Scope, request_id: str
) -> SteerSubmission | None:
    """What was already submitted for this request, if anything."""

    row = connection.execute(
        """SELECT response_ref FROM solvan_liaison.liaison_operation_ledger
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND operation = 'liaison.steer.submit' AND idempotency_key = %(key)s""",
        {**scope.canonical_dict(), "key": request_id},
    ).fetchone()
    if row is None or not row[0]:
        return None
    stored = json.loads(str(row[0]))
    return SteerSubmission(request_id, stored["envelope"], stored["inbox_id"])


def _submit_to_coordinator_inbox(
    connection: Connection[Any], *, scope: Scope, request_id: str, envelope: dict[str, Any]
) -> str:
    """Hand the typed request to the coordinator, idempotently.

    The parked-request id is the idempotency key, so a retried submission after
    a crash cannot create a second step. The coordinator revalidates scope,
    role, budget, tool profile, and versions before it accepts anything.
    """

    inbox_id = new_identifier("evt")
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_operation_ledger (
              organization_id, project_id, environment_id, idempotency_key,
              operation, request_hash, status, claim_token, response_ref,
              expires_at, completed_at)
           VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
              %(key)s, 'liaison.steer.submit', %(request_hash)s, 'COMPLETED',
              gen_random_uuid(), %(response)s, now() + interval '1 hour', now())
           ON CONFLICT (organization_id, project_id, environment_id, operation,
              idempotency_key) DO NOTHING""",
        {
            **scope.canonical_dict(),
            "key": request_id,
            "request_hash": str(envelope.get("decided_payload_hash", "")),
            "response": json.dumps({"inbox_id": inbox_id, "envelope": envelope}, default=str),
        },
    )
    # If the row already existed, the stored id is the real one; returning the
    # freshly minted one would report a submission that never happened.  The
    # coordinator reads this typed, durable ledger projection directly; it is
    # intentionally not a GCS payload or a model-controlled document.
    existing = _stored_submission(connection, scope=scope, request_id=request_id)
    if existing is None:  # defensive: conflict row must be visible in this transaction
        raise SteerRefused("coordinator submission receipt could not be reloaded")
    connection.execute(
        """INSERT INTO solvan.inbox_events
              (organization_id,project_id,environment_id,id,source,source_event_id,
               event_type,payload_ref,payload_hash)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
              %(inbox_id)s,'liaison-steer',%(request_id)s,'LIAISON_STEER_CONFIRMED',
              %(payload_ref)s,%(payload_hash)s)
           ON CONFLICT (organization_id,project_id,environment_id,source,source_event_id)
           DO NOTHING""",
        {
            **scope.canonical_dict(),
            "inbox_id": existing.inbox_id,
            "request_id": request_id,
            "payload_ref": f"db://solvan_liaison/steer-submissions/{request_id}",
            "payload_hash": canonical_hash(existing.envelope),
        },
    )
    return existing.inbox_id


def _record_grant_receipt(
    connection: Connection[Any], *, scope: Scope, principal: str, request_id: str
) -> None:
    """A spent steer grant leaves a receipt, so the act is auditable."""

    grant_digest = canonical_hash(
        {"kind": "STEER_SUBMISSION", "principal": principal, "request_id": request_id}
    )
    request_hash = canonical_hash({"parked_request_id": request_id})
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_grant_receipts (
              organization_id, project_id, environment_id, id, grant_kind,
              principal, parked_request_id, audience,grant_digest,request_hash,
              policy_epoch,issued_at,expires_at,consumed_at,audit_ref)
           VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
              %(id)s, 'STEER_SUBMISSION', %(principal)s, %(request_id)s,
              'COORDINATOR_INBOX',%(grant_digest)s,%(request_hash)s,
              %(policy_epoch)s,now(),now() + interval '5 minutes',now(),%(audit)s)""",
        {
            **scope.canonical_dict(),
            "policy_epoch": current_policy_epoch(connection, scope=scope, principal=principal),
            "id": new_identifier("grt"),
            "principal": principal,
            "request_id": request_id,
            "grant_digest": grant_digest,
            "request_hash": request_hash,
            "audit": f"audit://liaison/steer/{request_id}",
        },
    )
