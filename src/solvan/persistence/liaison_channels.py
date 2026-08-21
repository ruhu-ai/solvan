"""Durable channel binding and inbound-delivery fencing for the Liaison."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.liaison import Anchor
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class ChannelBindingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ActiveChannelBinding:
    binding_id: str
    principal: str
    epoch: int
    classification_ceiling: str


@dataclass(frozen=True, slots=True)
class InboundEventCommit:
    binding: ActiveChannelBinding
    created: bool
    message_id: str | None


@dataclass(frozen=True, slots=True)
class MappedChannelThread:
    thread_id: str
    anchor: Anchor


@dataclass(frozen=True, slots=True)
class EnrollmentChallenge:
    challenge_id: str
    channel_kind: str
    channel_identity: str | None
    status: str
    issued_at: str
    expires_at: str
    attempts: int
    safe_reason_code: str | None


@dataclass(frozen=True, slots=True)
class ChannelProviderHealth:
    channel_kind: str
    status: str
    deployment_id: str
    service_revision: str
    safe_reason_code: str
    next_step_code: str
    checked_at: str
    expires_at: str
    receipt_ref: str


@dataclass(frozen=True, slots=True)
class InboundEventClaim:
    binding: ActiveChannelBinding
    external_event_id: str
    message_id: str
    thread_id: str
    claim_token: UUID


class LiaisonChannelStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def active_binding(
        self, *, scope: Scope, channel_kind: str, channel_identity: str
    ) -> ActiveChannelBinding | None:
        """Resolve channel identity only through an authoritative ACTIVE row."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,principal,connection_epoch,classification_ceiling
                     FROM solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND channel_kind=%(channel_kind)s
                      AND channel_identity=%(channel_identity)s
                      AND status='ACTIVE'""",
                {
                    **scope.canonical_dict(),
                    "channel_kind": channel_kind,
                    "channel_identity": channel_identity,
                },
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ActiveChannelBinding(
            binding_id=str(row["id"]),
            principal=str(row["principal"]),
            epoch=int(row["connection_epoch"]),
            classification_ceiling=str(row["classification_ceiling"]),
        )

    def lock_active_binding(
        self, *, scope: Scope, channel_kind: str, channel_identity: str
    ) -> ActiveChannelBinding | None:
        """Hold a share lock so revocation cannot cross an authorized operation."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,principal,connection_epoch,classification_ceiling
                     FROM solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND channel_kind=%(channel_kind)s AND channel_identity=%(identity)s
                      AND status='ACTIVE' FOR SHARE""",
                {
                    **scope.canonical_dict(),
                    "channel_kind": channel_kind,
                    "identity": channel_identity,
                },
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ActiveChannelBinding(
            str(row["id"]),
            str(row["principal"]),
            int(row["connection_epoch"]),
            str(row["classification_ceiling"]),
        )

    def issue_enrollment(
        self,
        *,
        scope: Scope,
        principal: str,
        channel_kind: str,
        channel_identity: str | None,
        nonce: str,
        callback_mechanism: str,
    ) -> str:
        if channel_kind not in {"EMAIL", "SLACK", "DISCORD", "MCP"}:
            raise ChannelBindingError("unsupported channel kind")
        if not principal or len(nonce) < 16 or not callback_mechanism:
            raise ChannelBindingError("enrollment challenge material is incomplete")
        if channel_kind in {"EMAIL", "MCP"} and not channel_identity:
            raise ChannelBindingError("this channel requires an exact enrollment identity")
        challenge_id = new_identifier("enr")
        audit_id = new_identifier("aud")
        digest = canonical_sha256({"nonce": nonce})
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_enrollment_challenges
                     (organization_id,project_id,environment_id,id,principal,channel_kind,
                      channel_identity,nonce_hash,callback_mechanism,
                      console_authenticated_at,issued_at,expires_at,audit_ref)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(principal)s,%(channel_kind)s,%(channel_identity)s,%(nonce_hash)s,
                      %(callback)s,now(),now(),now() + interval '10 minutes',%(audit_ref)s)""",
                {
                    **scope.canonical_dict(),
                    "id": challenge_id,
                    "principal": principal,
                    "channel_kind": channel_kind,
                    "channel_identity": channel_identity,
                    "nonce_hash": digest,
                    "callback": callback_mechanism,
                    "audit_ref": audit_id,
                },
            )
            cursor.execute(
                """INSERT INTO solvan.audit_events
                     (organization_id,project_id,environment_id,id,stream_type,stream_id,
                      event_type,actor_principal,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(audit_id)s,
                      'LIAISON_ENROLLMENT',%(challenge_id)s,'EnrollmentChallengeIssued',
                      %(principal)s,%(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "audit_id": audit_id,
                    "challenge_id": challenge_id,
                    "principal": principal,
                    "payload_hash": digest,
                },
            )
        return challenge_id

    def mark_enrollment_dispatched(
        self, *, scope: Scope, challenge_id: str, principal: str, receipt_ref: str
    ) -> bool:
        if not receipt_ref:
            raise ChannelBindingError("enrollment dispatch receipt is required")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_enrollment_challenges
                      SET status='DISPATCHED',dispatch_receipt_ref=%(receipt_ref)s,
                          dispatched_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(challenge_id)s AND principal=%(principal)s
                      AND status='REQUESTED' AND expires_at > now()""",
                {
                    **scope.canonical_dict(),
                    "challenge_id": challenge_id,
                    "principal": principal,
                    "receipt_ref": receipt_ref,
                },
            )
            return cursor.rowcount == 1

    def fail_enrollment(
        self, *, scope: Scope, challenge_id: str, principal: str, reason_code: str
    ) -> bool:
        if not reason_code or len(reason_code) > 80:
            raise ChannelBindingError("safe enrollment failure reason is required")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_enrollment_challenges
                      SET status='FAILED',safe_reason_code=%(reason_code)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(challenge_id)s AND principal=%(principal)s
                      AND status IN ('REQUESTED','DISPATCHED')""",
                {
                    **scope.canonical_dict(),
                    "challenge_id": challenge_id,
                    "principal": principal,
                    "reason_code": reason_code,
                },
            )
            return cursor.rowcount == 1

    def enrollment(
        self, *, scope: Scope, challenge_id: str, principal: str
    ) -> EnrollmentChallenge | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_enrollment_challenges
                      SET status='EXPIRED',safe_reason_code='CHALLENGE_EXPIRED'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(challenge_id)s AND principal=%(principal)s
                      AND status IN ('REQUESTED','DISPATCHED') AND expires_at <= now()""",
                {
                    **scope.canonical_dict(),
                    "challenge_id": challenge_id,
                    "principal": principal,
                },
            )
            cursor.execute(
                """SELECT id,channel_kind,channel_identity,status,issued_at,expires_at,
                          attempts,safe_reason_code
                     FROM solvan_liaison.liaison_enrollment_challenges
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(challenge_id)s AND principal=%(principal)s""",
                {
                    **scope.canonical_dict(),
                    "challenge_id": challenge_id,
                    "principal": principal,
                },
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return EnrollmentChallenge(
            challenge_id=str(row["id"]),
            channel_kind=str(row["channel_kind"]),
            channel_identity=(
                str(row["channel_identity"]) if row["channel_identity"] is not None else None
            ),
            status=str(row["status"]),
            issued_at=row["issued_at"].isoformat(),
            expires_at=row["expires_at"].isoformat(),
            attempts=int(row["attempts"]),
            safe_reason_code=(
                str(row["safe_reason_code"]) if row["safe_reason_code"] is not None else None
            ),
        )

    def cancel_enrollment(self, *, scope: Scope, challenge_id: str, principal: str) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_enrollment_challenges
                      SET status='CANCELLED',cancelled_at=now(),safe_reason_code='USER_CANCELLED'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(challenge_id)s AND principal=%(principal)s
                      AND status IN ('REQUESTED','DISPATCHED')""",
                {
                    **scope.canonical_dict(),
                    "challenge_id": challenge_id,
                    "principal": principal,
                },
            )
            return cursor.rowcount == 1

    def consume_enrollment(
        self,
        *,
        scope: Scope,
        channel_kind: str,
        channel_identity: str,
        nonce: str,
        classification_ceiling: str = "INTERNAL",
    ) -> ActiveChannelBinding:
        digest = canonical_sha256({"nonce": nonce})
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_enrollment_challenges
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND channel_kind=%(channel_kind)s
                      AND (channel_identity=%(identity)s OR channel_identity IS NULL)
                      AND status IN ('REQUESTED','DISPATCHED','CONSUMED')
                      AND expires_at > now() AND attempts < 5
                    ORDER BY issued_at DESC FOR UPDATE LIMIT 1""",
                {
                    **scope.canonical_dict(),
                    "channel_kind": channel_kind,
                    "identity": channel_identity,
                },
            )
            challenge = cursor.fetchone()
            if challenge is None:
                raise ChannelBindingError("enrollment challenge is absent or expired")
            if challenge["consumed_at"] is not None:
                if challenge["nonce_hash"] != digest:
                    raise ChannelBindingError("enrollment proof did not match")
                cursor.execute(
                    """SELECT id,principal,connection_epoch,classification_ceiling
                         FROM solvan_liaison.liaison_channel_bindings
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND channel_kind=%(channel_kind)s AND channel_identity=%(identity)s
                          AND identity_proof_ref=%(proof_ref)s AND status='ACTIVE'""",
                    {
                        **scope.canonical_dict(),
                        "channel_kind": channel_kind,
                        "identity": channel_identity,
                        "proof_ref": f"enrollment:{challenge['id']}",
                    },
                )
                replay = cursor.fetchone()
                if replay is None:
                    raise ChannelBindingError("enrollment binding is unavailable")
                return ActiveChannelBinding(
                    str(replay["id"]),
                    str(replay["principal"]),
                    int(replay["connection_epoch"]),
                    str(replay["classification_ceiling"]),
                )
            cursor.execute(
                """UPDATE solvan_liaison.liaison_enrollment_challenges SET attempts=attempts+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s""",
                {**scope.canonical_dict(), "id": challenge["id"]},
            )
            if challenge["nonce_hash"] != digest:
                raise ChannelBindingError("enrollment proof did not match")
            binding_id = new_identifier("chb")
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_channel_bindings
                     (organization_id,project_id,environment_id,id,channel_kind,
                      channel_identity,principal,identity_proof_ref,enrolled_at,
                      classification_ceiling,status)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(channel_kind)s,%(identity)s,%(principal)s,%(proof_ref)s,now(),
                      %(ceiling)s,'ACTIVE')
                   ON CONFLICT (organization_id,project_id,environment_id,
                                channel_kind,channel_identity)
                   DO UPDATE SET principal=EXCLUDED.principal,
                      identity_proof_ref=EXCLUDED.identity_proof_ref,enrolled_at=now(),
                      classification_ceiling=EXCLUDED.classification_ceiling,status='ACTIVE',
                      revoked_at=NULL,connection_epoch=
                        solvan_liaison.liaison_channel_bindings.connection_epoch+1
                   RETURNING id,principal,connection_epoch,classification_ceiling""",
                {
                    **scope.canonical_dict(),
                    "id": binding_id,
                    "channel_kind": channel_kind,
                    "identity": channel_identity,
                    "principal": challenge["principal"],
                    "proof_ref": f"enrollment:{challenge['id']}",
                    "ceiling": classification_ceiling,
                },
            )
            binding = cursor.fetchone()
            assert binding is not None
            cursor.execute(
                """UPDATE solvan_liaison.liaison_enrollment_challenges
                      SET consumed_at=now(),status='CONSUMED',channel_identity=%(identity)s,
                          dispatched_at=COALESCE(dispatched_at,issued_at),
                          dispatch_receipt_ref=COALESCE(dispatch_receipt_ref,'provider-command')
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s""",
                {**scope.canonical_dict(), "id": challenge["id"], "identity": channel_identity},
            )
            cursor.execute(
                """INSERT INTO solvan.audit_events
                     (organization_id,project_id,environment_id,id,stream_type,stream_id,
                      event_type,actor_principal,decision_ref,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(audit_id)s,
                      'LIAISON_CHANNEL_BINDING',%(binding_id)s,'ChannelEnrollmentConsumed',
                      %(principal)s,%(challenge_id)s,%(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "audit_id": new_identifier("aud"),
                    "binding_id": binding["id"],
                    "principal": challenge["principal"],
                    "challenge_id": challenge["id"],
                    "payload_hash": canonical_sha256(
                        {
                            "channel_kind": channel_kind,
                            "channel_identity": channel_identity,
                            "connection_epoch": binding["connection_epoch"],
                        }
                    ),
                },
            )
        return ActiveChannelBinding(
            str(binding["id"]),
            str(binding["principal"]),
            int(binding["connection_epoch"]),
            str(binding["classification_ceiling"]),
        )

    def list_bindings(self, *, scope: Scope, principal: str) -> list[dict[str, Any]]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,channel_kind,channel_identity,connection_epoch,
                          classification_ceiling,status,enrolled_at,revoked_at
                     FROM solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND principal=%(principal)s ORDER BY created_at DESC""",
                {**scope.canonical_dict(), "principal": principal},
            )
            return [dict(row) for row in cursor.fetchall()]

    def current_provider_health(self, *, scope: Scope) -> list[ChannelProviderHealth]:
        """Return the newest immutable deployed-path receipt for every provider."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT DISTINCT ON (channel_kind)
                          channel_kind,status,deployment_id,service_revision,safe_reason_code,
                          next_step_code,checked_at,expires_at,receipt_ref
                     FROM solvan_liaison.liaison_channel_provider_health_receipts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                    ORDER BY channel_kind,checked_at DESC,id DESC""",
                scope.canonical_dict(),
            )
            rows = cursor.fetchall()
        now = datetime.now(UTC)
        return [
            ChannelProviderHealth(
                channel_kind=str(row["channel_kind"]),
                status=(
                    "NEEDS_ATTENTION"
                    if row["status"] == "AVAILABLE" and row["expires_at"] <= now
                    else str(row["status"])
                ),
                deployment_id=str(row["deployment_id"]),
                service_revision=str(row["service_revision"]),
                safe_reason_code=(
                    "HEALTH_RECEIPT_EXPIRED"
                    if row["status"] == "AVAILABLE" and row["expires_at"] <= now
                    else str(row["safe_reason_code"])
                ),
                next_step_code=str(row["next_step_code"]),
                checked_at=row["checked_at"].isoformat(),
                expires_at=row["expires_at"].isoformat(),
                receipt_ref=str(row["receipt_ref"]),
            )
            for row in rows
        ]

    def record_provider_health(
        self,
        *,
        scope: Scope,
        channel_kind: str,
        deployment_id: str,
        service_revision: str,
        status: str,
        safe_reason_code: str,
        next_step_code: str,
        checked_at: datetime,
        validity_seconds: int,
        receipt_ref: str,
        receipt_hash: str,
    ) -> str:
        """Append one immutable receipt produced by the qualification runner."""

        if channel_kind not in {"EMAIL", "SLACK", "DISCORD", "MCP"}:
            raise ChannelBindingError("unsupported channel kind")
        if status not in {"AVAILABLE", "NEEDS_ATTENTION", "DISABLED"}:
            raise ChannelBindingError("unsupported provider health status")
        if checked_at.tzinfo is None:
            raise ChannelBindingError("provider health check time must be timezone-aware")
        if not 60 <= validity_seconds <= 86_400:
            raise ChannelBindingError("provider health validity is out of bounds")
        values = (
            deployment_id,
            service_revision,
            safe_reason_code,
            next_step_code,
            receipt_ref,
            receipt_hash,
        )
        if any(not value or len(value) > 1_024 for value in values):
            raise ChannelBindingError("provider health receipt material is incomplete")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", deployment_id) is None:
            raise ChannelBindingError("provider health deployment id is invalid")
        if (
            re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", safe_reason_code) is None
            or re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", next_step_code) is None
        ):
            raise ChannelBindingError("provider health reason codes are invalid")
        if (
            not receipt_ref.startswith("gs://")
            or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_hash) is None
        ):
            raise ChannelBindingError("provider health receipt reference is invalid")
        receipt_id = new_identifier("cph")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_channel_provider_health_receipts
                     (organization_id,project_id,environment_id,id,channel_kind,
                      deployment_id,service_revision,status,safe_reason_code,next_step_code,
                      checked_at,expires_at,receipt_ref,receipt_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(channel_kind)s,%(deployment_id)s,%(service_revision)s,%(status)s,
                      %(safe_reason_code)s,%(next_step_code)s,%(checked_at)s,
                      %(checked_at)s + make_interval(secs => %(validity_seconds)s),
                      %(receipt_ref)s,%(receipt_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": receipt_id,
                    "channel_kind": channel_kind,
                    "deployment_id": deployment_id,
                    "service_revision": service_revision,
                    "status": status,
                    "safe_reason_code": safe_reason_code,
                    "next_step_code": next_step_code,
                    "checked_at": checked_at,
                    "validity_seconds": validity_seconds,
                    "receipt_ref": receipt_ref,
                    "receipt_hash": receipt_hash,
                },
            )
        return receipt_id

    def revoke_binding(self, *, scope: Scope, binding_id: str, principal: str) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_channel_bindings
                      SET status='REVOKING',connection_epoch=connection_epoch+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(binding_id)s AND principal=%(principal)s
                      AND status IN ('ACTIVE','REAUTH_REQUIRED')""",
                {**scope.canonical_dict(), "binding_id": binding_id, "principal": principal},
            )
            if cursor.rowcount != 1:
                return False
            cursor.execute(
                """UPDATE solvan_liaison.liaison_deliveries
                      SET status='FENCED',lease_owner=NULL,lease_token=NULL,
                          lease_expires_at=NULL,next_attempt_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND binding_id=%(binding_id)s
                      AND status IN ('PENDING','SENDING','FAILED')""",
                {**scope.canonical_dict(), "binding_id": binding_id},
            )
            cursor.execute(
                """UPDATE solvan_liaison.liaison_subscriptions
                      SET status='ENDED',ended_at=now(),claim_owner=NULL,claim_token=NULL,
                          claim_expires_at=NULL,next_delivery_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND channel_binding_id=%(binding_id)s AND status='ACTIVE'""",
                {**scope.canonical_dict(), "binding_id": binding_id},
            )
            cursor.execute(
                """UPDATE solvan_liaison.liaison_channel_threads
                      SET status='REVOKED',stopped_at=now(),stop_reason='BINDING_REVOKED'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND binding_id=%(binding_id)s AND status='ACTIVE'""",
                {**scope.canonical_dict(), "binding_id": binding_id},
            )
            cursor.execute(
                """UPDATE solvan_liaison.liaison_channel_bindings
                      SET status='REVOKED',revoked_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(binding_id)s AND status='REVOKING'""",
                {**scope.canonical_dict(), "binding_id": binding_id},
            )
            cursor.execute(
                """INSERT INTO solvan.audit_events
                     (organization_id,project_id,environment_id,id,stream_type,stream_id,
                      event_type,actor_principal,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(audit_id)s,
                      'LIAISON_CHANNEL_BINDING',%(binding_id)s,'ChannelBindingRevoked',
                      %(principal)s,%(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "audit_id": new_identifier("aud"),
                    "binding_id": binding_id,
                    "principal": principal,
                    "payload_hash": canonical_sha256(
                        {"binding_id": binding_id, "principal": principal, "status": "REVOKED"}
                    ),
                },
            )
        return True

    def enroll_scope_thread(
        self,
        *,
        scope: Scope,
        binding: ActiveChannelBinding,
        external_conversation_id: str,
    ) -> MappedChannelThread:
        """Explicitly enroll an external conversation into a scope thread."""

        from solvan.persistence.liaison_store import LiaisonStore

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT status,connection_epoch FROM
                         solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(binding_id)s FOR UPDATE""",
                {**scope.canonical_dict(), "binding_id": binding.binding_id},
            )
            row = cursor.fetchone()
            if row is None or row[0] != "ACTIVE" or int(row[1]) != binding.epoch:
                raise ChannelBindingError("channel binding is unavailable or stale")
        try:
            return self.mapped_thread(
                scope=scope,
                binding=binding,
                external_conversation_id=external_conversation_id,
            )
        except ChannelBindingError:
            thread_id = LiaisonStore(self._connection).open_thread(
                scope=scope,
                anchor=Anchor.scope(),
                visibility="PARTICIPANTS",
                principal=binding.principal,
            )
            self._connection.execute(
                """INSERT INTO solvan_liaison.liaison_channel_threads
                     (organization_id,project_id,environment_id,binding_id,
                      binding_epoch,external_conversation_id,thread_id,status)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(binding_id)s,%(binding_epoch)s,%(external_id)s,%(thread_id)s,'ACTIVE')
                   ON CONFLICT (organization_id,project_id,environment_id,binding_id,
                                external_conversation_id)
                   DO UPDATE SET binding_epoch=EXCLUDED.binding_epoch,
                      thread_id=EXCLUDED.thread_id,status='ACTIVE',enrolled_at=now(),
                      stopped_at=NULL,stop_reason=NULL""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding.binding_id,
                    "binding_epoch": binding.epoch,
                    "external_id": external_conversation_id,
                    "thread_id": thread_id,
                },
            )
            return MappedChannelThread(thread_id, Anchor.scope())

    def stop_following(
        self,
        *,
        scope: Scope,
        binding: ActiveChannelBinding,
        external_conversation_id: str,
    ) -> bool:
        """Durably stop one exact external conversation at the current epoch."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_channel_threads ct
                      SET status='STOPPED',stopped_at=now(),stop_reason='USER_STOPPED'
                     FROM solvan_liaison.liaison_channel_bindings b
                    WHERE (b.organization_id,b.project_id,b.environment_id,b.id)=
                          (ct.organization_id,ct.project_id,ct.environment_id,ct.binding_id)
                      AND ct.organization_id=%(organization_id)s
                      AND ct.project_id=%(project_id)s
                      AND ct.environment_id=%(environment_id)s
                      AND ct.binding_id=%(binding_id)s
                      AND ct.binding_epoch=%(binding_epoch)s
                      AND ct.external_conversation_id=%(conversation_id)s
                      AND ct.status='ACTIVE' AND b.status='ACTIVE'
                      AND b.connection_epoch=%(binding_epoch)s""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding.binding_id,
                    "binding_epoch": binding.epoch,
                    "conversation_id": external_conversation_id,
                },
            )
            stopped = cursor.rowcount == 1
            if stopped:
                cursor.execute(
                    """INSERT INTO solvan.audit_events
                         (organization_id,project_id,environment_id,id,stream_type,stream_id,
                          event_type,actor_principal,payload_hash)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                          'LIAISON_CHANNEL_THREAD',%(stream_id)s,'ChannelThreadStopped',
                          %(principal)s,%(payload_hash)s)""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("aud"),
                        "stream_id": binding.binding_id,
                        "principal": binding.principal,
                        "payload_hash": canonical_sha256(
                            {
                                "binding_id": binding.binding_id,
                                "binding_epoch": binding.epoch,
                                "external_conversation_id": external_conversation_id,
                                "reason": "USER_STOPPED",
                            }
                        ),
                    },
                )
        return stopped

    def record_inbound(
        self,
        *,
        scope: Scope,
        binding: ActiveChannelBinding,
        external_event_id: str,
        payload_hash: str,
    ) -> InboundEventCommit:
        """Deduplicate an authenticated event under the current binding epoch."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT connection_epoch,status
                     FROM solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(binding_id)s
                    FOR SHARE""",
                {**scope.canonical_dict(), "binding_id": binding.binding_id},
            )
            current = cursor.fetchone()
            if (
                current is None
                or current["status"] != "ACTIVE"
                or int(current["connection_epoch"]) != binding.epoch
            ):
                raise ChannelBindingError("channel binding was revoked or superseded")
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_inbound_events
                     (organization_id,project_id,environment_id,binding_id,
                      binding_epoch,external_event_id,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(binding_id)s,%(binding_epoch)s,%(event_id)s,%(payload_hash)s)
                   ON CONFLICT DO NOTHING RETURNING message_id""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding.binding_id,
                    "binding_epoch": binding.epoch,
                    "event_id": external_event_id,
                    "payload_hash": payload_hash,
                },
            )
            inserted = cursor.fetchone()
            if inserted is not None:
                return InboundEventCommit(binding, True, None)
            cursor.execute(
                """SELECT binding_epoch,payload_hash,message_id
                     FROM solvan_liaison.liaison_inbound_events
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND binding_id=%(binding_id)s AND external_event_id=%(event_id)s""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding.binding_id,
                    "event_id": external_event_id,
                },
            )
            prior = cursor.fetchone()
            if (
                prior is None
                or int(prior["binding_epoch"]) != binding.epoch
                or prior["payload_hash"] != payload_hash
            ):
                raise ChannelBindingError("Slack event id was replayed with different material")
            return InboundEventCommit(binding, False, prior["message_id"])

    def mapped_thread(
        self,
        *,
        scope: Scope,
        binding: ActiveChannelBinding,
        external_conversation_id: str,
    ) -> MappedChannelThread:
        """Resolve an external conversation only through a durable open mapping.

        The channel payload cannot choose a Solvan thread, anchor, or principal.
        The binding must still be active at the same epoch and its principal must
        remain a current participant in the mapped thread.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT t.id,t.anchor_kind,t.anchor_record_type,t.anchor_record_id,
                          t.anchor_service_key,t.anchor_window_start,t.anchor_window_end
                     FROM solvan_liaison.liaison_channel_threads ct
                     JOIN solvan_liaison.liaison_channel_bindings b ON
                       (b.organization_id,b.project_id,b.environment_id,b.id)=
                       (ct.organization_id,ct.project_id,ct.environment_id,ct.binding_id)
                     JOIN solvan_liaison.liaison_threads t ON
                       (t.organization_id,t.project_id,t.environment_id,t.id)=
                       (ct.organization_id,ct.project_id,ct.environment_id,ct.thread_id)
                     JOIN solvan_liaison.liaison_thread_participants p ON
                       (p.organization_id,p.project_id,p.environment_id,p.thread_id)=
                       (t.organization_id,t.project_id,t.environment_id,t.id)
                    WHERE ct.organization_id=%(organization_id)s
                      AND ct.project_id=%(project_id)s
                      AND ct.environment_id=%(environment_id)s
                      AND ct.binding_id=%(binding_id)s
                      AND ct.binding_epoch=%(binding_epoch)s
                      AND ct.external_conversation_id=%(conversation_id)s
                      AND ct.status='ACTIVE'
                      AND b.status='ACTIVE' AND b.connection_epoch=%(binding_epoch)s
                      AND p.principal=%(principal)s AND p.removed_at IS NULL
                      AND t.status='OPEN'""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding.binding_id,
                    "binding_epoch": binding.epoch,
                    "principal": binding.principal,
                    "conversation_id": external_conversation_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ChannelBindingError("channel conversation is not bound to an open thread")
        kind = str(row["anchor_kind"])
        if kind == "RECORD":
            anchor = Anchor.record(str(row["anchor_record_type"]), str(row["anchor_record_id"]))
        elif kind == "SERVICE_WINDOW":
            anchor = Anchor.service(
                str(row["anchor_service_key"]),
                row["anchor_window_start"],
                row["anchor_window_end"],
            )
        else:
            anchor = Anchor.scope()
        return MappedChannelThread(thread_id=str(row["id"]), anchor=anchor)

    def external_conversation_for_thread(
        self, *, scope: Scope, binding_id: str, binding_epoch: int, thread_id: str
    ) -> str:
        row = self._connection.execute(
            """SELECT external_conversation_id
                 FROM solvan_liaison.liaison_channel_threads
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND binding_id=%(binding_id)s AND thread_id=%(thread_id)s
                  AND binding_epoch=%(binding_epoch)s AND status='ACTIVE'""",
            {
                **scope.canonical_dict(),
                "binding_id": binding_id,
                "binding_epoch": binding_epoch,
                "thread_id": thread_id,
            },
        ).fetchone()
        if row is None:
            raise ChannelBindingError("channel thread mapping no longer exists")
        return str(row[0])

    def stop_thread_for_participant(
        self,
        *,
        scope: Scope,
        thread_id: str,
        principal: str,
        reason: str,
    ) -> int:
        """Fence active channel mappings when their participant loses access."""

        if reason not in {"MEMBERSHIP_ENDED", "THREAD_ARCHIVED"}:
            raise ValueError("unsupported channel-thread stop reason")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_channel_threads ct
                      SET status='STOPPED',stopped_at=now(),stop_reason=%(reason)s
                     FROM solvan_liaison.liaison_channel_bindings b
                    WHERE (b.organization_id,b.project_id,b.environment_id,b.id)=
                          (ct.organization_id,ct.project_id,ct.environment_id,ct.binding_id)
                      AND ct.organization_id=%(organization_id)s
                      AND ct.project_id=%(project_id)s
                      AND ct.environment_id=%(environment_id)s
                      AND ct.thread_id=%(thread_id)s AND ct.status='ACTIVE'
                      AND b.principal=%(principal)s""",
                {
                    **scope.canonical_dict(),
                    "thread_id": thread_id,
                    "principal": principal,
                    "reason": reason,
                },
            )
            return cursor.rowcount

    def bind_inbound_message(
        self,
        *,
        scope: Scope,
        binding: ActiveChannelBinding,
        external_event_id: str,
        thread_id: str,
        message_id: str,
    ) -> bool:
        """Attach the durable redacted message once; a different answer loses."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_inbound_events
                      SET thread_id=%(thread_id)s,message_id=%(message_id)s,
                          status='PENDING',next_attempt_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND binding_id=%(binding_id)s
                      AND binding_epoch=%(binding_epoch)s
                      AND external_event_id=%(event_id)s AND message_id IS NULL""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding.binding_id,
                    "binding_epoch": binding.epoch,
                    "event_id": external_event_id,
                    "thread_id": thread_id,
                    "message_id": message_id,
                },
            )
            return cursor.rowcount == 1
