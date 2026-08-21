"""Cloud SQL claim and settlement boundary for Agent Skills retention."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection

from solvan.application.skills_retention import (
    ObjectDeleter,
    RetentionCandidate,
    RetentionRecord,
    deletion_decision,
)
from solvan.domain import Scope


class PostgresSkillRetentionRepository:
    """Claim due objects and settle only with a provider deletion receipt."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def claim_due(
        self, *, scope: Scope, region: str, now: datetime, limit: int
    ) -> tuple[RetentionCandidate, ...]:
        if limit < 1 or limit > 100:
            raise ValueError("deletion batch limit is outside policy")
        params = {
            **scope.canonical_dict(),
            "region": region,
            "now": now,
            "limit": limit,
        }
        claimed: list[RetentionCandidate] = []
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """WITH due AS (
                         SELECT object_kind, object_id
                           FROM solvan_operability.skill_retention_controls
                          WHERE organization_id=%(organization_id)s
                            AND project_id=%(project_id)s
                            AND environment_id=%(environment_id)s
                            AND storage_region=%(region)s
                            AND retention_until <= %(now)s
                            AND legal_hold_ref IS NULL
                            AND (deletion_state='RETAINED'
                                 OR (deletion_state='PENDING'
                                     AND deletion_claimed_at <= %(now)s - interval '15 minutes'))
                            AND object_uri IS NOT NULL
                          ORDER BY retention_until, object_kind, object_id
                          FOR UPDATE SKIP LOCKED
                          LIMIT %(limit)s
                       )
                       UPDATE solvan_operability.skill_retention_controls AS controls
                          SET deletion_state='PENDING',
                              deletion_job_ref='srd:' ||
                                md5(random()::text || clock_timestamp()::text),
                              deletion_claimed_at=%(now)s
                         FROM due
                        WHERE controls.organization_id=%(organization_id)s
                          AND controls.project_id=%(project_id)s
                          AND controls.environment_id=%(environment_id)s
                          AND controls.object_kind=due.object_kind
                          AND controls.object_id=due.object_id
                       RETURNING controls.object_kind, controls.object_id,
                                 controls.storage_region, controls.retention_until,
                                 controls.legal_hold_ref, controls.object_uri,
                                 controls.object_generation, controls.deletion_job_ref""",
                params,
            )
            for row in cursor.fetchall():
                claimed.append(
                    RetentionCandidate(
                        record=RetentionRecord(
                            object_kind=str(row[0]),
                            object_id=str(row[1]),
                            storage_region=str(row[2]),
                            retention_until=row[3],
                            legal_hold_ref=None if row[4] is None else str(row[4]),
                        ),
                        object_uri=str(row[5]),
                        object_generation=None if row[6] is None else str(row[6]),
                        deletion_job_ref=str(row[7]),
                    )
                )
        return tuple(claimed)

    def settle(
        self,
        *,
        scope: Scope,
        candidate: RetentionCandidate,
        deleter: ObjectDeleter,
        requested_region: str,
        now: datetime,
    ) -> str:
        if not candidate.object_uri or candidate.object_generation is None:
            raise ValueError("DELETION_RECEIPT_INVALID")
        params = {
            **scope.canonical_dict(),
            "object_kind": candidate.record.object_kind,
            "object_id": candidate.record.object_id,
            "job_ref": candidate.deletion_job_ref,
            "uri": candidate.object_uri,
            "generation": candidate.object_generation,
            "now": now,
        }
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT deletion_state, legal_hold_ref, storage_region,
                          retention_until, object_uri, deletion_job_ref
                     FROM solvan_operability.skill_retention_controls
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND object_kind=%(object_kind)s AND object_id=%(object_id)s
                    FOR UPDATE""",
                params,
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError("DELETION_RECORD_NOT_FOUND")
            if row[0] == "DELETED":
                return "ALREADY_DELETED"
            if row[0] != "PENDING" or row[5] is None or str(row[5]) != candidate.deletion_job_ref:
                return "CLAIM_SUPERSEDED"
            if row[4] is None or str(row[4]) != candidate.object_uri:
                raise ValueError("DELETION_FENCE_FAILED")
            try:
                deletion_decision(
                    RetentionRecord(
                        object_kind=candidate.record.object_kind,
                        object_id=candidate.record.object_id,
                        storage_region=str(row[2]),
                        retention_until=row[3],
                        legal_hold_ref=None if row[1] is None else str(row[1]),
                    ),
                    requested_region=requested_region,
                    now=now,
                )
            except ValueError as refusal:
                cursor.execute(
                    """UPDATE solvan_operability.skill_retention_controls
                          SET deletion_state='RETAINED', deletion_job_ref=NULL,
                              deletion_claimed_at=NULL
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND object_kind=%(object_kind)s AND object_id=%(object_id)s
                          AND deletion_state='PENDING' AND deletion_job_ref=%(job_ref)s""",
                    params,
                )
                if cursor.rowcount != 1:
                    raise ValueError("DELETION_FENCE_FAILED") from refusal
                return str(refusal)
            provider_receipt_ref = deleter.delete(
                uri=candidate.object_uri,
                expected_generation=candidate.object_generation,
            )
            if not provider_receipt_ref:
                raise ValueError("DELETION_RECEIPT_INVALID")
            params["provider_ref"] = provider_receipt_ref
            cursor.execute(
                """INSERT INTO solvan_operability.skill_deletion_receipts
                       (organization_id,project_id,environment_id,object_kind,object_id,
                        deletion_job_ref,object_uri,expected_generation,provider_receipt_ref,
                        verified_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(object_kind)s,%(object_id)s,%(job_ref)s,%(uri)s,
                               %(generation)s,%(provider_ref)s,%(now)s)
                       ON CONFLICT DO NOTHING""",
                params,
            )
            cursor.execute(
                """UPDATE solvan_operability.skill_retention_controls
                      SET deletion_state='DELETED', deleted_at=%(now)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND object_kind=%(object_kind)s AND object_id=%(object_id)s
                      AND deletion_state='PENDING' AND deletion_job_ref=%(job_ref)s
                      AND legal_hold_ref IS NULL""",
                params,
            )
            if cursor.rowcount != 1:
                raise ValueError("DELETION_FENCE_FAILED")
            return "DELETED"
