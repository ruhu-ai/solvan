"""Fenced, at-least-once external delivery for Liaison channels."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope, new_identifier


class LiaisonDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DeliveryClaim:
    delivery_id: str
    binding_id: str
    binding_epoch: int
    claim_token: UUID
    payload_ref: str
    payload_hash: str
    provider_idempotency_key: str


class LiaisonDeliveryStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def queue_direct(
        self,
        *,
        scope: Scope,
        source_message_id: str,
        binding_id: str,
        binding_epoch: int,
        payload_ref: str,
        payload_hash: str,
        classification: str,
        redaction_verdict_ref: str,
        access_set_hash: str,
        policy_epoch: int,
        provider_idempotency_key: str,
    ) -> str:
        """Freeze one answer delivery; retries return the existing row."""

        delivery_id = new_identifier("dly")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT status,connection_epoch,classification_ceiling
                     FROM solvan_liaison.liaison_channel_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(binding_id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "binding_id": binding_id},
            )
            binding = cursor.fetchone()
            if (
                binding is None
                or binding["status"] != "ACTIVE"
                or int(binding["connection_epoch"]) != binding_epoch
            ):
                raise LiaisonDeliveryError("channel binding is unavailable or stale")
            if _classification_rank(classification) > _classification_rank(
                str(binding["classification_ceiling"])
            ):
                raise LiaisonDeliveryError("delivery exceeds the channel classification ceiling")
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_deliveries
                     (organization_id,project_id,environment_id,id,delivery_kind,
                      source_message_id,binding_id,binding_epoch,policy_epoch,payload_ref,
                      payload_hash,classification,redaction_verdict_ref,access_set_hash,
                      provider_idempotency_key,status,next_attempt_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           'DIRECT_MESSAGE',%(source_message_id)s,%(binding_id)s,
                           %(binding_epoch)s,%(policy_epoch)s,%(payload_ref)s,%(payload_hash)s,
                           %(classification)s,%(redaction_verdict_ref)s,%(access_set_hash)s,
                           %(provider_idempotency_key)s,'PENDING',now())
                   ON CONFLICT DO NOTHING RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": delivery_id,
                    "source_message_id": source_message_id,
                    "binding_id": binding_id,
                    "binding_epoch": binding_epoch,
                    "policy_epoch": policy_epoch,
                    "payload_ref": payload_ref,
                    "payload_hash": payload_hash,
                    "classification": classification,
                    "redaction_verdict_ref": redaction_verdict_ref,
                    "access_set_hash": access_set_hash,
                    "provider_idempotency_key": provider_idempotency_key,
                },
            )
            inserted = cursor.fetchone()
            if inserted is not None:
                return str(inserted["id"])
            cursor.execute(
                """SELECT id,payload_hash,binding_epoch
                     FROM solvan_liaison.liaison_deliveries
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND delivery_kind='DIRECT_MESSAGE'
                      AND source_message_id=%(source_message_id)s
                      AND binding_id=%(binding_id)s""",
                {
                    **scope.canonical_dict(),
                    "source_message_id": source_message_id,
                    "binding_id": binding_id,
                },
            )
            prior = cursor.fetchone()
            if (
                prior is None
                or prior["payload_hash"] != payload_hash
                or int(prior["binding_epoch"]) != binding_epoch
            ):
                raise LiaisonDeliveryError("direct delivery retry changed immutable material")
            return str(prior["id"])

    def queue_subscription_delta(
        self,
        *,
        scope: Scope,
        subscription_id: str,
        binding_id: str,
        binding_epoch: int,
        from_sequence: int,
        to_sequence: int,
        payload_ref: str,
        payload_hash: str,
        classification: str,
        redaction_verdict_ref: str,
        access_set_hash: str,
        policy_epoch: int,
        provider_idempotency_key: str,
    ) -> str:
        """Freeze one authorized catch-up interval behind the binding flush lock."""

        if from_sequence < 0 or to_sequence <= from_sequence:
            raise LiaisonDeliveryError("subscription delivery interval is invalid")
        delivery_id = new_identifier("dly")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            # The exclusive binding lock is the flush gate: direct messages
            # cannot be enqueued between selecting and freezing this interval.
            cursor.execute(
                """SELECT b.status AS binding_status,b.connection_epoch,
                          b.classification_ceiling,s.status AS subscription_status,
                          s.principal
                     FROM solvan_liaison.liaison_channel_bindings b
                     JOIN solvan_liaison.liaison_subscriptions s ON
                       (s.organization_id,s.project_id,s.environment_id,s.channel_binding_id)=
                       (b.organization_id,b.project_id,b.environment_id,b.id)
                    WHERE b.organization_id=%(organization_id)s
                      AND b.project_id=%(project_id)s
                      AND b.environment_id=%(environment_id)s AND b.id=%(binding_id)s
                      AND s.id=%(subscription_id)s FOR UPDATE OF b,s""",
                {
                    **scope.canonical_dict(),
                    "binding_id": binding_id,
                    "subscription_id": subscription_id,
                },
            )
            rows = cursor.fetchone()
            if (
                rows is None
                or rows["binding_status"] != "ACTIVE"
                or rows["subscription_status"] != "ACTIVE"
                or int(rows["connection_epoch"]) != binding_epoch
            ):
                raise LiaisonDeliveryError("subscription binding is unavailable or stale")
            if _classification_rank(classification) > _classification_rank(
                str(rows["classification_ceiling"])
            ):
                raise LiaisonDeliveryError("delivery exceeds the channel classification ceiling")
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_deliveries
                     (organization_id,project_id,environment_id,id,delivery_kind,
                      subscription_id,binding_id,binding_epoch,from_sequence,to_sequence,
                      policy_epoch,payload_ref,payload_hash,classification,
                      redaction_verdict_ref,access_set_hash,provider_idempotency_key,
                      status,next_attempt_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      'SUBSCRIPTION_DELTA',%(subscription_id)s,%(binding_id)s,
                      %(binding_epoch)s,%(from_sequence)s,%(to_sequence)s,%(policy_epoch)s,
                      %(payload_ref)s,%(payload_hash)s,%(classification)s,
                      %(redaction_verdict_ref)s,%(access_set_hash)s,
                      %(provider_idempotency_key)s,'PENDING',now())
                   ON CONFLICT DO NOTHING RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": delivery_id,
                    "subscription_id": subscription_id,
                    "binding_id": binding_id,
                    "binding_epoch": binding_epoch,
                    "from_sequence": from_sequence,
                    "to_sequence": to_sequence,
                    "policy_epoch": policy_epoch,
                    "payload_ref": payload_ref,
                    "payload_hash": payload_hash,
                    "classification": classification,
                    "redaction_verdict_ref": redaction_verdict_ref,
                    "access_set_hash": access_set_hash,
                    "provider_idempotency_key": provider_idempotency_key,
                },
            )
            inserted = cursor.fetchone()
            if inserted is not None:
                return str(inserted["id"])
            cursor.execute(
                """SELECT id,payload_hash,binding_epoch
                     FROM solvan_liaison.liaison_deliveries
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND delivery_kind='SUBSCRIPTION_DELTA'
                      AND subscription_id=%(subscription_id)s
                      AND from_sequence=%(from_sequence)s AND to_sequence=%(to_sequence)s""",
                {
                    **scope.canonical_dict(),
                    "subscription_id": subscription_id,
                    "from_sequence": from_sequence,
                    "to_sequence": to_sequence,
                },
            )
            prior = cursor.fetchone()
            if (
                prior is None
                or prior["payload_hash"] != payload_hash
                or int(prior["binding_epoch"]) != binding_epoch
            ):
                raise LiaisonDeliveryError("subscription retry changed immutable material")
            return str(prior["id"])

    def claim_due(
        self,
        *,
        scope: Scope,
        channel_kind: str,
        owner: str,
        now: datetime | None = None,
        lease_seconds: int = 60,
    ) -> DeliveryClaim | None:
        moment = now or datetime.now(UTC)
        if (
            moment.tzinfo is None
            or channel_kind not in {"SLACK", "EMAIL", "DISCORD"}
            or not owner
            or not 10 <= lease_seconds <= 300
        ):
            raise LiaisonDeliveryError("delivery claim requires an owner and bounded aware lease")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT d.* FROM solvan_liaison.liaison_deliveries d
                     JOIN solvan_liaison.liaison_channel_bindings b ON
                       (b.organization_id,b.project_id,b.environment_id,b.id)=
                       (d.organization_id,d.project_id,d.environment_id,d.binding_id)
                    WHERE d.organization_id=%(organization_id)s
                      AND d.project_id=%(project_id)s
                      AND d.environment_id=%(environment_id)s
                      AND b.channel_kind=%(channel_kind)s
                      AND ((d.status IN ('PENDING','FAILED')
                            AND coalesce(d.next_attempt_at,d.created_at) <= %(now)s)
                           OR (d.status='SENDING' AND d.lease_expires_at <= %(now)s))
                      AND d.payload_purged_at IS NULL
                      AND b.status='ACTIVE' AND b.connection_epoch=d.binding_epoch
                    ORDER BY coalesce(d.next_attempt_at,d.created_at),d.id
                    FOR UPDATE OF d SKIP LOCKED LIMIT 1""",
                {**scope.canonical_dict(), "channel_kind": channel_kind, "now": moment},
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                """UPDATE solvan_liaison.liaison_deliveries
                      SET status='SENDING',attempts=attempts+1,lease_owner=%(owner)s,
                          lease_token=%(token)s,lease_expires_at=%(expires_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s""",
                {
                    **scope.canonical_dict(),
                    "id": row["id"],
                    "owner": owner,
                    "token": token,
                    "expires_at": moment + timedelta(seconds=lease_seconds),
                },
            )
        return DeliveryClaim(
            delivery_id=str(row["id"]),
            binding_id=str(row["binding_id"]),
            binding_epoch=int(row["binding_epoch"]),
            claim_token=token,
            payload_ref=str(row["payload_ref"]),
            payload_hash=str(row["payload_hash"]),
            provider_idempotency_key=str(row["provider_idempotency_key"]),
        )

    def authorize_submission(self, *, scope: Scope, claim: DeliveryClaim) -> None:
        """Fence immediately before the provider call."""

        row = self._connection.execute(
            """SELECT d.status,d.lease_token,d.lease_expires_at,b.status,b.connection_epoch
                 FROM solvan_liaison.liaison_deliveries d
                 JOIN solvan_liaison.liaison_channel_bindings b ON
                   (b.organization_id,b.project_id,b.environment_id,b.id)=
                   (d.organization_id,d.project_id,d.environment_id,d.binding_id)
                WHERE d.organization_id=%(organization_id)s
                  AND d.project_id=%(project_id)s AND d.environment_id=%(environment_id)s
                  AND d.id=%(delivery_id)s FOR SHARE OF d,b""",
            {**scope.canonical_dict(), "delivery_id": claim.delivery_id},
        ).fetchone()
        if (
            row is None
            or row[0] != "SENDING"
            or row[1] != claim.claim_token
            or row[2] <= datetime.now(UTC)
            or row[3] != "ACTIVE"
            or int(row[4]) != claim.binding_epoch
        ):
            raise LiaisonDeliveryError("delivery claim or channel epoch is stale")

    def complete(self, *, scope: Scope, claim: DeliveryClaim, provider_message_id: str) -> bool:
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_deliveries
                  SET status='DELIVERED',provider_message_id=%(provider_message_id)s,
                      delivered_at=now(),lease_owner=NULL,lease_token=NULL,
                      lease_expires_at=NULL,next_attempt_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(delivery_id)s AND status='SENDING'
                  AND lease_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "delivery_id": claim.delivery_id,
                "claim_token": claim.claim_token,
                "provider_message_id": provider_message_id,
            },
        )
        completed = cursor.rowcount == 1
        if completed:
            self._record_alert_receipts(
                scope=scope,
                delivery_id=claim.delivery_id,
                delivery_state="DELIVERED",
                provider_receipt_ref=f"provider-message:{provider_message_id}",
                safe_failure_code=None,
            )
        return completed

    def fail(self, *, scope: Scope, claim: DeliveryClaim, retry_at: datetime) -> bool:
        if retry_at.tzinfo is None:
            raise LiaisonDeliveryError("delivery retry time must be timezone-aware")
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_deliveries
                  SET status='FAILED',lease_owner=NULL,lease_token=NULL,
                      lease_expires_at=NULL,next_attempt_at=%(retry_at)s
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(delivery_id)s AND status='SENDING'
                  AND lease_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "delivery_id": claim.delivery_id,
                "claim_token": claim.claim_token,
                "retry_at": retry_at,
            },
        )
        return cursor.rowcount == 1

    def fence(self, *, scope: Scope, claim: DeliveryClaim) -> bool:
        cursor = self._connection.execute(
            """UPDATE solvan_liaison.liaison_deliveries
                  SET status='FENCED',lease_owner=NULL,lease_token=NULL,
                      lease_expires_at=NULL,next_attempt_at=NULL
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(delivery_id)s AND status='SENDING'
                  AND lease_token=%(claim_token)s""",
            {
                **scope.canonical_dict(),
                "delivery_id": claim.delivery_id,
                "claim_token": claim.claim_token,
            },
        )
        fenced = cursor.rowcount == 1
        if fenced:
            self._record_alert_receipts(
                scope=scope,
                delivery_id=claim.delivery_id,
                delivery_state="REFUSED",
                provider_receipt_ref=None,
                safe_failure_code="CHANNEL_BINDING_REVOKED_OR_STALE",
            )
        return fenced

    def _record_alert_receipts(
        self,
        *,
        scope: Scope,
        delivery_id: str,
        delivery_state: str,
        provider_receipt_ref: str | None,
        safe_failure_code: str | None,
    ) -> None:
        """Bridge a delivered Alert subscription delta to its Alert audit ledger."""

        installed = self._connection.execute(
            "SELECT to_regclass('solvan_alerts.alert_channel_delivery_attempts')"
        ).fetchone()
        if installed is None or installed[0] is None:
            return
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT d.binding_id,d.binding_epoch,d.payload_ref,d.payload_hash,
                          d.access_set_hash,d.delivered_at,e.record_id AS episode_id,
                          e.reference AS disposition_id
                     FROM solvan_liaison.liaison_deliveries d
                     JOIN solvan_liaison.liaison_subscriptions subscription
                       ON (subscription.organization_id,subscription.project_id,
                           subscription.environment_id,subscription.id)=
                          (d.organization_id,d.project_id,d.environment_id,d.subscription_id)
                     JOIN solvan_liaison.liaison_scope_events e
                       ON e.organization_id=d.organization_id
                      AND e.project_id=d.project_id
                      AND e.environment_id=d.environment_id
                      AND e.scope_sequence>d.from_sequence
                      AND e.scope_sequence<=d.to_sequence
                      AND e.record_type='alert_episode'
                      AND e.record_id=subscription.anchor_record_id
                    WHERE d.organization_id=%(organization_id)s
                      AND d.project_id=%(project_id)s
                      AND d.environment_id=%(environment_id)s
                      AND d.id=%(delivery_id)s
                      AND d.delivery_kind='SUBSCRIPTION_DELTA'
                      AND subscription.anchor_kind='RECORD'
                      AND subscription.anchor_record_type='alert_episode'
                      AND e.reference IS NOT NULL
                    ORDER BY e.scope_sequence""",
                {**scope.canonical_dict(), "delivery_id": delivery_id},
            )
            rows = cursor.fetchall()
            for row in rows:
                cursor.execute(
                    """INSERT INTO solvan_alerts.alert_channel_delivery_attempts
                         (organization_id,project_id,environment_id,id,episode_id,
                          disposition_id,channel_binding_id,binding_epoch,audience_hash,
                          payload_ref,payload_hash,delivery_state,provider_receipt_ref,
                          safe_failure_code,delivered_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(id)s,%(episode_id)s,%(disposition_id)s,%(binding_id)s,
                          %(binding_epoch)s,%(audience_hash)s,%(payload_ref)s,%(payload_hash)s,
                          %(delivery_state)s,%(provider_receipt_ref)s,%(safe_failure_code)s,
                          coalesce(%(delivered_at)s,clock_timestamp()))
                       ON CONFLICT DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("acd"),
                        "episode_id": row["episode_id"],
                        "disposition_id": row["disposition_id"],
                        "binding_id": row["binding_id"],
                        "binding_epoch": row["binding_epoch"],
                        "audience_hash": row["access_set_hash"],
                        "payload_ref": row["payload_ref"],
                        "payload_hash": row["payload_hash"],
                        "delivery_state": delivery_state,
                        "provider_receipt_ref": provider_receipt_ref,
                        "safe_failure_code": safe_failure_code,
                        "delivered_at": row["delivered_at"],
                    },
                )


def _classification_rank(value: str) -> int:
    try:
        return {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}[value]
    except KeyError as error:
        raise LiaisonDeliveryError("delivery classification is invalid") from error
