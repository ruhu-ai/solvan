"""Token- and epoch-fenced Alert Triage lease operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope
from solvan.persistence.alert_triage_scheduling_types import (
    AlertSchedulingError,
    AlertTriageClaim,
)


class AlertTriageLeasePersistenceMixin:
    _connection: Connection[Any]

    def renew_alert_triage_claim(
        self,
        *,
        scope: Scope,
        triage_run_id: str,
        claim_token: str,
        claim_epoch: int,
        lease_seconds: int,
    ) -> datetime:
        """Renew the exact live Alert claim; stale owners cannot extend it."""

        if not 5 <= lease_seconds <= 300 or claim_epoch < 1:
            raise ValueError("Alert claim renewal bounds are invalid")
        values = {
            **scope.canonical_dict(),
            "triage_run_id": triage_run_id,
            "claim_token": claim_token,
            "claim_epoch": claim_epoch,
            "lease_seconds": lease_seconds,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """UPDATE solvan_alerts.alert_triage_runs
                      SET claim_expires_at=clock_timestamp()+
                            (%(lease_seconds)s * interval '1 second'),
                          row_version=row_version+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(triage_run_id)s
                      AND claim_token=%(claim_token)s::uuid
                      AND claim_epoch=%(claim_epoch)s
                      AND status IN ('CLAIMED','DISPATCHED','RUNNING')
                      AND claim_expires_at>clock_timestamp()
                  RETURNING work_id,claim_expires_at""",
                values,
            )
            run = cursor.fetchone()
            if run is None:
                raise AlertSchedulingError("ALERT_CLAIM_STALE")
            cursor.execute(
                """UPDATE solvan_scale.tenant_dispatch_queue
                      SET lease_expires_at=%(claim_expires_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND work_id=%(work_id)s
                      AND claim_token=%(claim_token)s::uuid
                      AND state='CLAIMED'""",
                {**values, **run},
            )
            if cursor.rowcount != 1:
                raise AlertSchedulingError("ALERT_QUEUE_CLAIM_STALE")
        return cast(datetime, run["claim_expires_at"])

    def reclaim_expired_alert_triage(
        self, *, scope: Scope, cell_id: str, lease_seconds: int
    ) -> AlertTriageClaim | None:
        """Fence an expired owner and return the same durable provider request."""

        if not 5 <= lease_seconds <= 300:
            raise ValueError("Alert claim lease must be between 5 and 300 seconds")
        token = uuid4()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT run.organization_id,run.project_id,run.environment_id,
                          run.id AS triage_run_id,run.agent_run_id,run.episode_id,
                          run.work_id,run.claim_epoch
                     FROM solvan_alerts.alert_triage_runs run
                     JOIN solvan_scale.tenant_dispatch_queue queue
                       ON (queue.organization_id,queue.project_id,queue.environment_id,
                           queue.work_id)=(run.organization_id,run.project_id,
                           run.environment_id,run.work_id)
                    WHERE run.organization_id=%(organization_id)s
                      AND run.project_id=%(project_id)s
                      AND run.environment_id=%(environment_id)s
                      AND run.cell_id=%(cell_id)s
                      AND run.status IN ('CLAIMED','DISPATCHED','RUNNING')
                      AND run.claim_expires_at<=clock_timestamp()
                      AND queue.state='CLAIMED'
                    ORDER BY run.claim_expires_at,run.id
                    FOR UPDATE OF run,queue SKIP LOCKED LIMIT 1""",
                {**scope.canonical_dict(), "cell_id": cell_id},
            )
            run = cursor.fetchone()
            if run is None:
                return None
            new_epoch = int(run["claim_epoch"]) + 1
            cursor.execute(
                """UPDATE solvan_alerts.alert_triage_runs
                      SET status='CLAIMED',claim_token=%(claim_token)s,
                          claim_epoch=%(claim_epoch)s,
                          claim_expires_at=clock_timestamp()+
                            (%(lease_seconds)s * interval '1 second'),
                          row_version=row_version+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(triage_run_id)s
                  RETURNING claim_expires_at""",
                {
                    **run,
                    "claim_token": token,
                    "claim_epoch": new_epoch,
                    "lease_seconds": lease_seconds,
                },
            )
            lease = cursor.fetchone()
            if lease is None:  # pragma: no cover - row is locked above
                raise AlertSchedulingError("ALERT_RECLAIM_FAILED")
            cursor.execute(
                """UPDATE solvan_scale.tenant_dispatch_queue
                      SET claim_token=%(claim_token)s,
                          lease_expires_at=%(lease_expires_at)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND work_id=%(work_id)s AND state='CLAIMED'""",
                {**run, "claim_token": token, "lease_expires_at": lease["claim_expires_at"]},
            )
            if cursor.rowcount != 1:
                raise AlertSchedulingError("ALERT_QUEUE_RECLAIM_FAILED")
        return AlertTriageClaim(
            str(run["triage_run_id"]),
            str(run["agent_run_id"]),
            str(run["episode_id"]),
            str(run["work_id"]),
            str(token),
            new_epoch,
            lease["claim_expires_at"],
            True,
        )
