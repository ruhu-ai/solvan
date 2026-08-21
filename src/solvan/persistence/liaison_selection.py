"""Durable, receipt-bound record selection for central Chat."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.liaison import Anchor
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import canonical_hash
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_store import LiaisonStore


class RecordSelectionError(RuntimeError):
    """A selection is absent, stale, expired, or outside current authority."""


@dataclass(frozen=True, slots=True)
class RecordSelection:
    id: str
    record_type: str
    record_id: str
    record_revision: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class ConsumedSelection:
    receipt_id: str
    thread_id: str
    record_type: str
    record_id: str


class LiaisonSelectionStore:
    """Issue and consume selectors without accepting scope or principal from clients."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def issue(
        self,
        *,
        scope: Scope,
        principal: str,
        record_type: str,
        record_id: str,
        record_revision: str,
        request_hash: str,
    ) -> RecordSelection:
        policy_epoch = current_policy_epoch(self._connection, scope=scope, principal=principal)
        receipt_id = new_identifier("rsl")
        grant_digest = canonical_hash(
            {
                "principal": principal,
                "scope": scope.canonical_dict(),
                "anchor": f"{record_type}:{record_id}",
                "record_revision": record_revision,
                "policy_epoch": policy_epoch,
                "audience": "PROJECTION_API",
                "method": "read_projection",
            }
        )
        receipt_digest = canonical_hash(
            {
                "receipt_id": receipt_id,
                "principal": principal,
                "scope": scope.canonical_dict(),
                "record_type": record_type,
                "record_id": record_id,
                "record_revision": record_revision,
                "policy_epoch": policy_epoch,
                "membership_epoch": 1,
                "reader_grant_digest": grant_digest,
                "request_hash": request_hash,
            }
        )
        row = self._connection.execute(
            """INSERT INTO solvan_liaison.liaison_record_selection_receipts (
                  organization_id,project_id,environment_id,id,principal,anchor_kind,
                  record_type,record_id,record_revision,policy_epoch,membership_epoch,
                  reader_grant_digest,request_hash,receipt_digest,status,expires_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(principal)s,'RECORD',%(record_type)s,%(record_id)s,%(record_revision)s,
                  %(policy_epoch)s,1,%(grant_digest)s,%(request_hash)s,%(receipt_digest)s,
                  'ISSUED',now()+interval '5 minutes')
               RETURNING expires_at""",
            {
                **scope.canonical_dict(),
                "id": receipt_id,
                "principal": principal,
                "record_type": record_type,
                "record_id": record_id,
                "record_revision": record_revision,
                "policy_epoch": policy_epoch,
                "grant_digest": grant_digest,
                "request_hash": request_hash,
                "receipt_digest": receipt_digest,
            },
        ).fetchone()
        if row is None:
            raise RuntimeError("record selection receipt was not persisted")
        return RecordSelection(
            id=receipt_id,
            record_type=record_type,
            record_id=record_id,
            record_revision=record_revision,
            expires_at=row[0].isoformat(),
        )

    def candidate(self, *, scope: Scope, principal: str, receipt_id: str) -> tuple[str, str, str]:
        row = self._connection.execute(
            """SELECT record_type,record_id,record_revision
                 FROM solvan_liaison.liaison_record_selection_receipts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(receipt_id)s
                  AND principal=%(principal)s""",
            {**scope.canonical_dict(), "receipt_id": receipt_id, "principal": principal},
        ).fetchone()
        if row is None:
            raise RecordSelectionError("record selection is unavailable")
        return str(row[0]), str(row[1]), str(row[2])

    def consume(
        self,
        *,
        scope: Scope,
        principal: str,
        receipt_id: str,
        current_record_revision: str,
    ) -> ConsumedSelection:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_record_selection_receipts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(receipt_id)s
                      AND principal=%(principal)s FOR UPDATE""",
                {**scope.canonical_dict(), "receipt_id": receipt_id, "principal": principal},
            )
            row = cursor.fetchone()
        if row is None:
            raise RecordSelectionError("record selection is unavailable")
        if row["status"] == "CONSUMED" and row["thread_id"]:
            return ConsumedSelection(
                receipt_id=receipt_id,
                thread_id=str(row["thread_id"]),
                record_type=str(row["record_type"]),
                record_id=str(row["record_id"]),
            )
        policy_epoch = current_policy_epoch(self._connection, scope=scope, principal=principal)
        validity = self._connection.execute(
            """SELECT status='ISSUED' AND expires_at > now()
                        AND policy_epoch=%(policy_epoch)s
                        AND record_revision=%(record_revision)s
                        AND membership_epoch=1
                 FROM solvan_liaison.liaison_record_selection_receipts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(receipt_id)s
                  AND principal=%(principal)s""",
            {
                **scope.canonical_dict(),
                "receipt_id": receipt_id,
                "principal": principal,
                "policy_epoch": policy_epoch,
                "record_revision": current_record_revision,
            },
        ).fetchone()
        if validity is None or not bool(validity[0]):
            raise RecordSelectionError("record selection is unavailable")
        thread_id = LiaisonStore(self._connection).open_thread(
            scope=scope,
            anchor=Anchor.record(str(row["record_type"]), str(row["record_id"])),
            visibility="PARTICIPANTS",
            principal=principal,
        )
        membership = LiaisonStore(self._connection).current_membership_epoch(
            scope=scope, thread_id=thread_id, principal=principal
        )
        if membership != 1:
            raise RuntimeError("record selection did not create the reserved owner epoch")
        updated = self._connection.execute(
            """UPDATE solvan_liaison.liaison_record_selection_receipts
                  SET status='CONSUMED',consumed_at=now(),thread_id=%(thread_id)s
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(receipt_id)s
                  AND principal=%(principal)s AND status='ISSUED'""",
            {
                **scope.canonical_dict(),
                "receipt_id": receipt_id,
                "principal": principal,
                "thread_id": thread_id,
            },
        )
        if updated.rowcount != 1:
            raise RecordSelectionError("record selection is unavailable")
        return ConsumedSelection(
            receipt_id=receipt_id,
            thread_id=thread_id,
            record_type=str(row["record_type"]),
            record_id=str(row["record_id"]),
        )
