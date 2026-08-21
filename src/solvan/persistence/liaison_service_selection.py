"""Receipt-bound service-window selection for central Chat."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.liaison import Anchor
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import canonical_hash
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_store import LiaisonStore


class ServiceSelectionError(RuntimeError):
    """A service selection is absent, stale, expired, or outside authority."""


@dataclass(frozen=True, slots=True)
class ServiceSelection:
    id: str
    service_key: str
    window_start: datetime
    window_end: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ConsumedServiceSelection:
    receipt_id: str
    thread_id: str
    service_key: str
    window_start: datetime
    window_end: datetime


class LiaisonServiceSelectionStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    @staticmethod
    def entity_set_digest(records: tuple[tuple[str, str], ...]) -> str:
        return canonical_hash({"records": sorted(set(records))})

    def issue(
        self,
        *,
        scope: Scope,
        principal: str,
        service_key: str,
        window_start: datetime,
        window_end: datetime,
        records: tuple[tuple[str, str], ...],
        request_hash: str,
    ) -> ServiceSelection:
        if not records:
            raise ServiceSelectionError("service selection is unavailable")
        policy_epoch = current_policy_epoch(self._connection, scope=scope, principal=principal)
        receipt_id = new_identifier("ssl")
        entity_digest = self.entity_set_digest(records)
        grant_digest = canonical_hash(
            {
                "principal": principal,
                "scope": scope.canonical_dict(),
                "service_key": service_key,
                "entity_set_digest": entity_digest,
                "window_start": window_start,
                "window_end": window_end,
                "policy_epoch": policy_epoch,
                "audience": "PROJECTION_API",
            }
        )
        receipt_digest = canonical_hash(
            {
                "receipt_id": receipt_id,
                "reader_grant_digest": grant_digest,
                "request_hash": request_hash,
                "membership_epoch": 1,
            }
        )
        row = self._connection.execute(
            """INSERT INTO solvan_liaison.liaison_service_selection_receipts (
                  organization_id,project_id,environment_id,id,principal,service_key,
                  window_start,window_end,entity_set_digest,policy_epoch,membership_epoch,
                  reader_grant_digest,request_hash,receipt_digest,status,expires_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(principal)s,%(service_key)s,%(window_start)s,%(window_end)s,
                  %(entity_digest)s,%(policy_epoch)s,1,%(grant_digest)s,%(request_hash)s,
                  %(receipt_digest)s,'ISSUED',now()+interval '5 minutes')
               RETURNING expires_at""",
            {
                **scope.canonical_dict(),
                "id": receipt_id,
                "principal": principal,
                "service_key": service_key,
                "window_start": window_start,
                "window_end": window_end,
                "entity_digest": entity_digest,
                "policy_epoch": policy_epoch,
                "grant_digest": grant_digest,
                "request_hash": request_hash,
                "receipt_digest": receipt_digest,
            },
        ).fetchone()
        if row is None:
            raise RuntimeError("service selection receipt was not persisted")
        return ServiceSelection(receipt_id, service_key, window_start, window_end, row[0])

    def candidate(
        self, *, scope: Scope, principal: str, receipt_id: str
    ) -> tuple[str, datetime, datetime, str]:
        row = self._connection.execute(
            """SELECT service_key,window_start,window_end,entity_set_digest
                 FROM solvan_liaison.liaison_service_selection_receipts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(receipt_id)s
                  AND principal=%(principal)s""",
            {**scope.canonical_dict(), "receipt_id": receipt_id, "principal": principal},
        ).fetchone()
        if row is None:
            raise ServiceSelectionError("service selection is unavailable")
        return str(row[0]), row[1], row[2], str(row[3])

    def consume(
        self,
        *,
        scope: Scope,
        principal: str,
        receipt_id: str,
        current_records: tuple[tuple[str, str], ...],
    ) -> ConsumedServiceSelection:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_service_selection_receipts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(receipt_id)s
                      AND principal=%(principal)s FOR UPDATE""",
                {**scope.canonical_dict(), "receipt_id": receipt_id, "principal": principal},
            )
            row = cursor.fetchone()
        if row is None:
            raise ServiceSelectionError("service selection is unavailable")
        if row["status"] == "CONSUMED" and row["thread_id"]:
            return ConsumedServiceSelection(
                receipt_id,
                str(row["thread_id"]),
                str(row["service_key"]),
                row["window_start"],
                row["window_end"],
            )
        policy_epoch = current_policy_epoch(self._connection, scope=scope, principal=principal)
        if (
            row["status"] != "ISSUED"
            or row["expires_at"] <= datetime.now(row["expires_at"].tzinfo)
            or int(row["policy_epoch"]) != policy_epoch
            or str(row["entity_set_digest"]) != self.entity_set_digest(current_records)
            or not current_records
        ):
            raise ServiceSelectionError("service selection is unavailable")
        anchor = Anchor.service(str(row["service_key"]), row["window_start"], row["window_end"])
        store = LiaisonStore(self._connection)
        thread_id = store.open_thread(
            scope=scope, anchor=anchor, visibility="PARTICIPANTS", principal=principal
        )
        if (
            store.current_membership_epoch(scope=scope, thread_id=thread_id, principal=principal)
            != 1
        ):
            raise RuntimeError("service selection did not create the reserved owner epoch")
        updated = self._connection.execute(
            """UPDATE solvan_liaison.liaison_service_selection_receipts
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
            raise ServiceSelectionError("service selection is unavailable")
        return ConsumedServiceSelection(
            receipt_id,
            thread_id,
            str(row["service_key"]),
            row["window_start"],
            row["window_end"],
        )
