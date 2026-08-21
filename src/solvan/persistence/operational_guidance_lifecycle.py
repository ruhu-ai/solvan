"""Separation-of-duty lifecycle transitions for Operational Guidance."""

from __future__ import annotations

from psycopg.rows import dict_row

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope, new_identifier
from solvan.persistence.operational_guidance_base import OperationalGuidanceStoreBase
from solvan.persistence.operational_guidance_types import GuidanceLifecycleCommit


class OperationalGuidanceLifecycleMixin(OperationalGuidanceStoreBase):
    def submit(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        decision_request_id: str,
    ) -> GuidanceLifecycleCommit:
        return self._transition(
            scope=scope,
            guidance_key=guidance_key,
            version=version,
            principal=principal,
            expected_digest=expected_digest,
            decision_request_id=decision_request_id,
            from_lifecycles=("DRAFT",),
            to_lifecycle="IN_REVIEW",
            roles=("GUIDANCE_AUTHOR", "OPERABILITY_ADMIN"),
            event_type="GUIDANCE_SUBMITTED",
            reason_code="SUBMITTED_FOR_INDEPENDENT_REVIEW",
        )

    def approve(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        evaluation_ref: str,
        decision_request_id: str,
        reason: str,
        known_predicates: frozenset[str],
    ) -> GuidanceLifecycleCommit:
        if not reason.strip():
            raise GuidanceError("approval reason is required")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._require_current_role_for_key(
                cursor=cursor,
                scope=scope,
                guidance_key=guidance_key,
                principal=principal,
                roles=("GUIDANCE_APPROVER", "OPERABILITY_ADMIN"),
            )
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=f"guidance:{guidance_key}@{version}",
                    digest=expected_digest,
                    principal=principal,
                    event_type="GUIDANCE_APPROVED",
                )
                cursor.execute(
                    """SELECT id FROM solvan_operability.guidance_approvals
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND decision_request_id=%(request_id)s""",
                    {**scope.canonical_dict(), "request_id": decision_request_id},
                )
                stored = cursor.fetchone()
                if stored is None:
                    raise GuidanceError("approval idempotency record is inconsistent")
                return GuidanceLifecycleCommit(
                    guidance_key, version, "APPROVED", expected_digest, str(stored["id"]), False
                )
            cursor.execute(
                """SELECT r.author_principal,d.owner_department,r.lifecycle,r.revision_hash,
                          e.id AS evaluation_ref,r.content_hash,e.decision AS evaluation_decision,
                          e.revision_digest AS evaluation_digest,
                          e.evaluator_principal,r.supersedes_version
                     FROM solvan_operability.guidance_revisions r
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                     LEFT JOIN solvan_operability.guidance_evaluations e ON
                       (e.organization_id,e.project_id,e.environment_id,e.id)=
                       (r.organization_id,r.project_id,r.environment_id,%(evaluation_ref)s)
                      AND e.guidance_key=r.guidance_key
                      AND e.guidance_version=r.version
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.guidance_key=%(guidance_key)s AND r.version=%(version)s
                    FOR UPDATE OF r""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": guidance_key,
                    "version": version,
                    "evaluation_ref": evaluation_ref,
                },
            )
            row = cursor.fetchone()
            if row is None or row["lifecycle"] != "IN_REVIEW":
                raise GuidanceError("guidance is not awaiting review")
            if row["revision_hash"] != expected_digest:
                raise GuidanceError("guidance approval digest is stale")
            if row["author_principal"] == principal:
                raise GuidanceError("a guidance author cannot approve their revision")
            if not row["evaluation_ref"]:
                raise GuidanceError("guidance has no bound evaluation")
            if row["evaluation_decision"] != "PASS" or row["evaluation_digest"] != expected_digest:
                raise GuidanceError("guidance evaluation is absent, failed, or stale")
            if row["evaluator_principal"] in {row["author_principal"], principal}:
                raise GuidanceError("guidance author, evaluator, and approver must be distinct")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("GUIDANCE_APPROVER", "OPERABILITY_ADMIN"),
                department=str(row["owner_department"]),
            )
            self._require_approval_dependencies(
                cursor=cursor,
                scope=scope,
                guidance_key=guidance_key,
                version=version,
                content_hash=str(row["content_hash"]),
                reviewable_digest=expected_digest,
                known_predicates=known_predicates,
            )
            approval_id = new_identifier("gap")
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_approvals
                     (organization_id,project_id,environment_id,id,guidance_key,
                      guidance_version,revision_digest,evaluation_ref,approver_principal,
                      decision,reason,decision_request_id)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(guidance_key)s,%(version)s,%(digest)s,%(evaluation_ref)s,
                           %(principal)s,'APPROVE',%(reason)s,%(request_id)s)""",
                {
                    **scope.canonical_dict(),
                    "id": approval_id,
                    "guidance_key": guidance_key,
                    "version": version,
                    "digest": expected_digest,
                    "evaluation_ref": row["evaluation_ref"],
                    "principal": principal,
                    "reason": reason.strip(),
                    "request_id": decision_request_id,
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.guidance_revisions
                      SET lifecycle='APPROVED',evaluation_ref=%(evaluation_ref)s,
                          approval_ref=%(approval_id)s,
                          approved_digest=%(digest)s,approved_by_principal=%(principal)s,
                          approved_at=now()
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                      AND version=%(version)s""",
                {
                    **scope.canonical_dict(),
                    "approval_id": approval_id,
                    "evaluation_ref": row["evaluation_ref"],
                    "digest": expected_digest,
                    "principal": principal,
                    "guidance_key": guidance_key,
                    "version": version,
                },
            )
            # The target Skills migration adds a scope-bound head.  Advance it
            # in the same transaction as approval, and require the predecessor
            # to still be the head so two approvals cannot silently reorder
            # lineage.  A missing target table is an explicit qualification
            # failure rather than a permissive fallback.
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_current_heads
                     (organization_id,project_id,environment_id,guidance_key,
                      approved_version,head_epoch)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(guidance_key)s,%(version)s,1)
                   ON CONFLICT (organization_id,project_id,environment_id,guidance_key)
                   DO UPDATE SET approved_version=EXCLUDED.approved_version,
                                 head_epoch=guidance_current_heads.head_epoch+1,
                                 updated_at=now()
                    WHERE guidance_current_heads.approved_version IS NOT DISTINCT FROM
                          %(supersedes_version)s
                       OR (guidance_current_heads.approved_version IS NULL
                           AND EXISTS (
                             SELECT 1 FROM solvan_operability.guidance_revisions predecessor
                              WHERE predecessor.organization_id=%(organization_id)s
                                AND predecessor.project_id=%(project_id)s
                                AND predecessor.environment_id=%(environment_id)s
                                AND predecessor.guidance_key=%(guidance_key)s
                                AND predecessor.version=%(supersedes_version)s
                                AND predecessor.lifecycle IN ('DEPRECATED','RETIRED')
                           ))
                   RETURNING head_epoch""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": guidance_key,
                    "version": version,
                    "supersedes_version": row["supersedes_version"],
                },
            )
            if cursor.fetchone() is None:
                raise GuidanceError("LINEAGE_CONFLICT")
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="GUIDANCE_APPROVED",
                entity_ref=f"guidance:{guidance_key}@{version}",
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code="INDEPENDENT_APPROVAL_RECORDED",
            )
        return GuidanceLifecycleCommit(
            guidance_key, version, "APPROVED", expected_digest, approval_id, True
        )

    def deprecate(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        decision_request_id: str,
    ) -> GuidanceLifecycleCommit:
        return self._transition(
            scope=scope,
            guidance_key=guidance_key,
            version=version,
            principal=principal,
            expected_digest=expected_digest,
            decision_request_id=decision_request_id,
            from_lifecycles=("APPROVED",),
            to_lifecycle="DEPRECATED",
            roles=("GUIDANCE_APPROVER", "OPERABILITY_ADMIN"),
            event_type="GUIDANCE_DEPRECATED",
            reason_code="REVISION_DEPRECATED",
        )

    def retire(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        decision_request_id: str,
    ) -> GuidanceLifecycleCommit:
        return self._transition(
            scope=scope,
            guidance_key=guidance_key,
            version=version,
            principal=principal,
            expected_digest=expected_digest,
            decision_request_id=decision_request_id,
            from_lifecycles=("APPROVED", "DEPRECATED"),
            to_lifecycle="RETIRED",
            roles=("GUIDANCE_APPROVER", "OPERABILITY_ADMIN"),
            event_type="GUIDANCE_RETIRED",
            reason_code="REVISION_RETIRED",
        )

    def _transition(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        principal: str,
        expected_digest: str,
        decision_request_id: str,
        from_lifecycles: tuple[str, ...],
        to_lifecycle: str,
        roles: tuple[str, ...],
        event_type: str,
        reason_code: str,
    ) -> GuidanceLifecycleCommit:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._require_current_role_for_key(
                cursor=cursor,
                scope=scope,
                guidance_key=guidance_key,
                principal=principal,
                roles=roles,
            )
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            entity_ref = f"guidance:{guidance_key}@{version}"
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=expected_digest,
                    principal=principal,
                    event_type=event_type,
                )
                return GuidanceLifecycleCommit(
                    guidance_key, version, to_lifecycle, expected_digest, None, False
                )
            cursor.execute(
                """SELECT r.lifecycle,r.revision_hash,d.owner_department,r.author_principal
                     FROM solvan_operability.guidance_revisions r
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.guidance_key=%(guidance_key)s AND r.version=%(version)s
                    FOR UPDATE OF r""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            row = cursor.fetchone()
            if row is None or str(row["lifecycle"]) not in from_lifecycles:
                raise GuidanceError("guidance lifecycle transition is not allowed")
            if row["revision_hash"] != expected_digest:
                raise GuidanceError("guidance lifecycle digest is stale")
            if to_lifecycle == "IN_REVIEW" and row["author_principal"] != principal:
                raise GuidanceError("only the exact guidance author may submit the draft")
            if (
                to_lifecycle in {"DEPRECATED", "RETIRED"}
                and str(row["author_principal"]).startswith("product:")
                and not principal.startswith("release:")
            ):
                raise GuidanceError(
                    "built-in product guidance is superseded by an application "
                    "release, not a tenant lifecycle action"
                )
            self._require_role(
                scope=scope,
                principal=principal,
                roles=roles,
                department=str(row["owner_department"]),
            )
            cursor.execute(
                """UPDATE solvan_operability.guidance_revisions SET lifecycle=%(lifecycle)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                      AND version=%(version)s""",
                {
                    **scope.canonical_dict(),
                    "lifecycle": to_lifecycle,
                    "guidance_key": guidance_key,
                    "version": version,
                },
            )
            if to_lifecycle in {"DEPRECATED", "RETIRED"}:
                cursor.execute(
                    """UPDATE solvan_operability.guidance_current_heads
                          SET approved_version=NULL,head_epoch=head_epoch+1,updated_at=now()
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND guidance_key=%(guidance_key)s
                          AND approved_version=%(version)s""",
                    {
                        **scope.canonical_dict(),
                        "guidance_key": guidance_key,
                        "version": version,
                    },
                )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type=event_type,
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code=reason_code,
            )
        return GuidanceLifecycleCommit(
            guidance_key, version, to_lifecycle, expected_digest, None, True
        )
