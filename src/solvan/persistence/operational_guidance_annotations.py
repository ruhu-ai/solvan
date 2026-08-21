"""Untrusted operator annotations and content-free selection analytics."""

from __future__ import annotations

import hashlib

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope
from solvan.persistence.operational_guidance_base import OperationalGuidanceStoreBase


class OperationalGuidanceAnnotationsMixin(OperationalGuidanceStoreBase):
    def record_operator_note(
        self,
        *,
        scope: Scope,
        invocation_request_id: str,
        note: str,
        classification: str,
        author_principal: str,
        access_mode: str = "SELECTION_READERS",
    ) -> None:
        """Persist operator text as untrusted annotation, never model context."""

        if not note.strip() or len(note) > 2_000:
            raise GuidanceError("OPERATOR_NOTE_INVALID")
        if classification not in {"INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
            raise GuidanceError("OPERATOR_NOTE_CLASSIFICATION_INVALID")
        if access_mode not in {"SELECTION_READERS", "CASE_READERS"}:
            raise GuidanceError("OPERATOR_NOTE_ACCESS_MODE_INVALID")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_operator_notes
                     (organization_id,project_id,environment_id,invocation_request_id,note_text,
                      note_classification,author_principal,access_mode)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(request_id)s,
                           %(note)s,%(classification)s,%(principal)s,%(access_mode)s)
                   ON CONFLICT (organization_id,project_id,environment_id,invocation_request_id)
                   DO NOTHING
                   RETURNING invocation_request_id""",
                {
                    **scope.canonical_dict(),
                    "request_id": invocation_request_id,
                    "note": note.strip(),
                    "classification": classification,
                    "principal": author_principal,
                    "access_mode": access_mode,
                },
            )
            if cursor.fetchone() is not None:
                return
            cursor.execute(
                """SELECT note_text,note_classification,author_principal,access_mode
                     FROM solvan_operability.guidance_operator_notes
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND invocation_request_id=%(request_id)s""",
                {**scope.canonical_dict(), "request_id": invocation_request_id},
            )
            existing = cursor.fetchone()
            if existing is None or (
                existing["note_text"],
                existing["note_classification"],
                existing["author_principal"],
                existing["access_mode"],
            ) != (note.strip(), classification, author_principal, access_mode):
                raise GuidanceError("OPERATOR_NOTE_IDEMPOTENCY_MISMATCH")

    def record_selection_analytics(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        selection_reason: str,
        outcome_code: str,
        delivery_request_id: str,
    ) -> None:
        if selection_reason not in {"MODEL_RANKED", "OPERATOR_INVOKED"}:
            raise GuidanceError("SELECTION_REASON_INVALID")
        if not outcome_code or len(outcome_code) > 80:
            raise GuidanceError("SELECTION_OUTCOME_INVALID")
        if not delivery_request_id.strip():
            raise GuidanceError("SELECTION_DELIVERY_INVALID")
        material = "\n".join((guidance_key, version, selection_reason, outcome_code))
        digest = f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"
        request_id = f"guidance-analytics:{delivery_request_id}"
        entity_ref = f"guidance-analytics:{guidance_key}@{version}"
        with self._connection.cursor(row_factory=dict_row) as cursor:
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=digest,
                    principal="service:coordinator",
                    event_type="GUIDANCE_SELECTION_COUNTED",
                )
                return
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_selection_analytics
                     (organization_id,project_id,environment_id,guidance_key,guidance_version,
                      selection_reason,outcome_code,selection_count)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(guidance_key)s,
                           %(version)s,%(reason)s,%(outcome)s,1)
                   ON CONFLICT (organization_id,project_id,environment_id,guidance_key,
                               guidance_version,selection_reason,outcome_code)
                   DO UPDATE SET selection_count=
                         solvan_operability.guidance_selection_analytics.selection_count+1,
                         updated_at=now()""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": guidance_key,
                    "version": version,
                    "reason": selection_reason,
                    "outcome": outcome_code,
                },
            )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal="service:coordinator",
                event_type="GUIDANCE_SELECTION_COUNTED",
                entity_ref=entity_ref,
                digest=digest,
                decision_request_id=request_id,
                reason_code=outcome_code,
            )
