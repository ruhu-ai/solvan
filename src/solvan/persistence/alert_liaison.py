"""Safe Alert-disposition projection into the shared Liaison event ledger."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection

from solvan.domain import Scope
from solvan.persistence.liaison_catchup import record_event

_DISPOSITION_PHRASES = {
    "SUPPRESSED": "Alert was suppressed by the approved policy.",
    "TRIAGED_HOLD": "Read-only triage completed; the alert remains under observation.",
    "ESCALATED_NEW": "Alert triage opened a governed Incident investigation.",
    "ESCALATED_ATTACHED": "Alert triage attached this alert to an existing Incident.",
    "MANUAL_REVIEW": "Alert triage requires operator review.",
    "BLOCKED": "Alert triage stopped at a fail-closed policy boundary.",
}


def record_alert_disposition_event(
    connection: Connection[Any],
    *,
    scope: Scope,
    episode_id: str,
    disposition_id: str,
    disposition: str,
    occurred_at: datetime,
) -> int | None:
    """Publish one application-authored safe delta in the committing transaction."""

    phrase = _DISPOSITION_PHRASES.get(disposition)
    if phrase is None:
        raise ValueError("unsupported Alert disposition for Liaison projection")
    episode = connection.execute(
        """SELECT target_node_key,classification
             FROM solvan_alerts.alert_episodes
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(episode_id)s""",
        {**scope.canonical_dict(), "episode_id": episode_id},
    ).fetchone()
    if episode is None:
        raise ValueError("Alert episode disappeared before Liaison projection")
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_record_directory
             (organization_id,project_id,environment_id,record_type,record_id,
              service_key,classification)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   'alert_episode',%(episode_id)s,%(service_key)s,%(classification)s)
           ON CONFLICT (organization_id,project_id,environment_id,record_type,record_id)
           DO UPDATE SET service_key=EXCLUDED.service_key,
                         classification=EXCLUDED.classification""",
        {
            **scope.canonical_dict(),
            "episode_id": episode_id,
            "service_key": str(episode[0]),
            "classification": str(episode[1]),
        },
    )
    return record_event(
        connection,
        scope=scope,
        record_type="alert_episode",
        record_id=episode_id,
        event_key=f"alert-disposition:{disposition_id}",
        phrase=phrase,
        authority_status="CONFIRMED",
        reference=disposition_id,
        occurred_at=occurred_at,
    )
