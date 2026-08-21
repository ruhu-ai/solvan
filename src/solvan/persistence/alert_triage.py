"""Cloud SQL authority for Alert Triage."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.persistence.alert_policy_products import AlertPolicyProductMixin
from solvan.persistence.alert_triage_admission_retry import AlertAdmissionRetryMixin
from solvan.persistence.alert_triage_admission_store import AlertAdmissionStoreMixin
from solvan.persistence.alert_triage_commands import AlertCommandPersistenceMixin
from solvan.persistence.alert_triage_completion import AlertTriageCompletionMixin
from solvan.persistence.alert_triage_ingress import AlertIngressPersistenceMixin
from solvan.persistence.alert_triage_leases import AlertTriageLeasePersistenceMixin
from solvan.persistence.alert_triage_projection import AlertProjectionPersistenceMixin
from solvan.persistence.alert_triage_read import AlertTriageReadMixin
from solvan.persistence.alert_triage_runtime import AlertTriageRuntimeMixin
from solvan.persistence.alert_triage_scheduling import AlertSchedulingPersistenceMixin
from solvan.persistence.alert_triage_types import AlertPolicyDraftCommit, SourceRegistration

__all__ = ["AlertPolicyDraftCommit", "AlertTriageRepository", "SourceRegistration"]


class AlertTriageRepository(
    AlertPolicyProductMixin,
    AlertCommandPersistenceMixin,
    AlertTriageLeasePersistenceMixin,
    AlertAdmissionStoreMixin,
    AlertAdmissionRetryMixin,
    AlertTriageCompletionMixin,
    AlertTriageRuntimeMixin,
    AlertTriageReadMixin,
    AlertSchedulingPersistenceMixin,
    AlertProjectionPersistenceMixin,
    AlertIngressPersistenceMixin,
):
    """Scope-bound Alert authority; callers own the surrounding transaction."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection
