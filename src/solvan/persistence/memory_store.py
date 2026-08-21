"""PostgreSQL authority for governed Memory Bank promotion."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application import (
    MemoryBankReceipt,
    MemoryConflict,
    MemoryPromotionRecord,
    PromotionCandidate,
    PromotionPreparation,
    StoredMemoryCandidate,
)
from solvan.application.memory import MemoryHint, MemorySearchCandidate
from solvan.domain import MemoryCandidateStatus, MemoryScope, Scope, new_identifier


class PostgresMemoryStore:
    def __init__(self, connection: Connection[Any], *, scope: Scope) -> None:
        self._connection = connection
        self._scope = scope

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._connection.transaction():
            yield

    def promotable_candidate_ids(self, *, limit: int = 20) -> tuple[str, ...]:
        """Return the oldest approved or interrupted promotions in this scope.

        Cloud Run constrains the promoter to one instance and one concurrent
        request. ``PROMOTING`` rows are deliberately retried so a process loss
        after the external create is reconciled on the next tick.
        """

        if not 1 <= limit <= 100:
            raise ValueError("memory promotion batch limit must be between 1 and 100")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan.memory_candidates
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND status IN ('APPROVED', 'PROMOTING')
                  ORDER BY created_at, id LIMIT %(limit)s""",
                {**self._scope.canonical_dict(), "limit": limit},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def save_candidate(self, candidate: StoredMemoryCandidate) -> None:
        proposal = candidate.proposal
        if proposal.exact_scope.scope != self._scope:
            raise MemoryConflict("candidate scope differs from repository authority")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan.memory_candidates
                  (organization_id, project_id, environment_id, id, scope_json,
                   purpose, candidate_type, fact_text, content_hash, source_refs,
                   source_hashes, confirmation_status, verification_ref,
                   classification, residency, redaction_manifest_ref,
                   armor_verdict_ref, provenance_json, policy_version,
                   review_requirement, status, created_by_principal, expires_at)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(candidate_id)s, %(scope_json)s, %(purpose)s, %(candidate_type)s,
                    %(fact_text)s, %(content_hash)s, %(source_refs)s, %(source_hashes)s,
                    %(confirmation)s, %(verification_ref)s, %(classification)s,
                    %(residency)s, %(redaction_manifest_ref)s, %(armor_verdict_ref)s,
                    %(provenance)s, %(policy_version)s, %(review_requirement)s,
                    %(status)s, %(created_by_principal)s, %(expires_at)s)""",
                {
                    **self._scope.canonical_dict(),
                    "candidate_id": candidate.candidate_id,
                    "scope_json": Jsonb(proposal.exact_scope.canonical_dict()),
                    "purpose": proposal.exact_scope.purpose,
                    "candidate_type": proposal.candidate_type,
                    "fact_text": proposal.fact_text.strip(),
                    "content_hash": candidate.decision.content_hash,
                    "source_refs": Jsonb(list(proposal.source_refs)),
                    "source_hashes": Jsonb(list(proposal.source_hashes)),
                    "confirmation": proposal.confirmation,
                    "verification_ref": proposal.verification_ref,
                    "classification": proposal.classification,
                    "residency": proposal.residency,
                    "redaction_manifest_ref": proposal.redaction_manifest_ref,
                    "armor_verdict_ref": proposal.armor_verdict_ref,
                    "provenance": Jsonb(dict(proposal.provenance)),
                    "policy_version": proposal.policy_version,
                    "review_requirement": candidate.decision.review_requirement,
                    "status": candidate.decision.status,
                    "created_by_principal": proposal.created_by_principal,
                    "expires_at": proposal.expires_at,
                },
            )

    def begin_promotion(
        self, *, candidate_id: str, promoter_identity: str, now: datetime
    ) -> PromotionPreparation:
        del promoter_identity  # authorization is enforced before this repository boundary
        self._require_aware(now)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, scope_json, purpose, fact_text, content_hash, status,
                    expires_at FROM solvan.memory_candidates
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(candidate_id)s FOR UPDATE""",
                {**self._scope.canonical_dict(), "candidate_id": candidate_id},
            )
            row = cursor.fetchone()
            if row is None:
                raise MemoryConflict("memory candidate does not exist in this scope")
            if str(row["status"]) == MemoryCandidateStatus.PROMOTED:
                return PromotionPreparation(None, self._load_promotion(cursor, candidate_id))
            if row["expires_at"] <= now:
                cursor.execute(
                    """UPDATE solvan.memory_candidates SET status = 'EXPIRED'
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(candidate_id)s""",
                    {**self._scope.canonical_dict(), "candidate_id": candidate_id},
                )
                raise MemoryConflict("memory candidate expired before promotion")
            if str(row["status"]) not in {
                MemoryCandidateStatus.APPROVED,
                MemoryCandidateStatus.PROMOTING,
            }:
                raise MemoryConflict("memory candidate is not approved for promotion")
            cursor.execute(
                """UPDATE solvan.memory_candidates SET status = 'PROMOTING'
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(candidate_id)s""",
                {**self._scope.canonical_dict(), "candidate_id": candidate_id},
            )
            exact_scope = self._parse_scope(row["scope_json"], str(row["purpose"]))
            return PromotionPreparation(
                PromotionCandidate(
                    candidate_id=str(row["id"]),
                    exact_scope=exact_scope,
                    fact_text=str(row["fact_text"]),
                    content_hash=str(row["content_hash"]),
                    expires_at=row["expires_at"],
                ),
                None,
            )

    def complete_promotion(
        self,
        *,
        candidate: PromotionCandidate,
        receipt: MemoryBankReceipt,
        promoter_identity: str,
        now: datetime,
    ) -> MemoryPromotionRecord:
        self._require_aware(now)
        if receipt.exact_scope != candidate.exact_scope or receipt.fact_text != candidate.fact_text:
            raise MemoryConflict("Memory Bank receipt does not match the authorized candidate")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT status, content_hash, expires_at FROM solvan.memory_candidates
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(candidate_id)s FOR UPDATE""",
                {**self._scope.canonical_dict(), "candidate_id": candidate.candidate_id},
            )
            row = cursor.fetchone()
            if row is None:
                raise MemoryConflict("memory candidate disappeared before reconciliation")
            if str(row["status"]) == MemoryCandidateStatus.PROMOTED:
                return self._load_promotion(cursor, candidate.candidate_id)
            if str(row["status"]) != MemoryCandidateStatus.PROMOTING:
                raise MemoryConflict("memory candidate lost promotion authority")
            if str(row["content_hash"]) != candidate.content_hash:
                raise MemoryConflict("memory candidate content changed during promotion")

            promotion_id = new_identifier("memp")
            cursor.execute(
                """INSERT INTO solvan.memory_promotions
                  (organization_id, project_id, environment_id, id, candidate_id,
                   memory_resource, memory_revision, exact_scope_json,
                   promoter_identity, decision, content_hash, retention_until)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(promotion_id)s, %(candidate_id)s, %(memory_resource)s,
                    %(memory_revision)s, %(scope_json)s, %(promoter_identity)s,
                    'PROMOTED', %(content_hash)s, %(retention_until)s)""",
                {
                    **self._scope.canonical_dict(),
                    "promotion_id": promotion_id,
                    "candidate_id": candidate.candidate_id,
                    "memory_resource": receipt.memory_resource,
                    "memory_revision": receipt.memory_revision,
                    "scope_json": Jsonb(candidate.exact_scope.canonical_dict()),
                    "promoter_identity": promoter_identity,
                    "content_hash": candidate.content_hash,
                    "retention_until": row["expires_at"],
                },
            )
            cursor.execute(
                """UPDATE solvan.memory_candidates SET status = 'PROMOTED'
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s
                    AND id = %(candidate_id)s AND status = 'PROMOTING'""",
                {**self._scope.canonical_dict(), "candidate_id": candidate.candidate_id},
            )
            if cursor.rowcount != 1:
                raise MemoryConflict("memory candidate changed before promotion commit")
        return MemoryPromotionRecord(
            promotion_id,
            candidate.candidate_id,
            receipt.memory_resource,
            receipt.memory_revision,
            candidate.exact_scope,
            candidate.content_hash,
            candidate.expires_at,
        )

    def _load_promotion(self, cursor: Any, candidate_id: str) -> MemoryPromotionRecord:
        cursor.execute(
            """SELECT id, candidate_id, memory_resource, memory_revision,
                exact_scope_json, content_hash, retention_until
              FROM solvan.memory_promotions
              WHERE organization_id = %(organization_id)s
                AND project_id = %(project_id)s
                AND environment_id = %(environment_id)s
                AND candidate_id = %(candidate_id)s AND decision = 'PROMOTED'
              ORDER BY created_at DESC LIMIT 1""",
            {**self._scope.canonical_dict(), "candidate_id": candidate_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise MemoryConflict("promoted candidate has no durable promotion receipt")
        exact_scope = self._parse_scope(
            row["exact_scope_json"], str(row["exact_scope_json"]["purpose"])
        )
        return MemoryPromotionRecord(
            str(row["id"]),
            str(row["candidate_id"]),
            str(row["memory_resource"]),
            str(row["memory_revision"]) if row["memory_revision"] is not None else None,
            exact_scope,
            str(row["content_hash"]),
            row["retention_until"],
        )

    def revalidate_search_hits(
        self,
        *,
        exact_scope: MemoryScope,
        candidates: tuple[MemorySearchCandidate, ...],
        now: datetime,
    ) -> tuple[MemoryHint, ...]:
        """Resolve semantic hits to one current SQL promotion or withhold them."""

        self._require_aware(now)
        if exact_scope.scope != self._scope or not candidates:
            return ()
        resources = [candidate.memory_resource for candidate in candidates]
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.memory_resource, p.memory_revision,
                    p.exact_scope_json, p.content_hash, p.candidate_id,
                    c.fact_text, c.source_refs, c.classification, c.residency
                  FROM solvan.memory_promotions p
                  JOIN solvan.memory_candidates c
                    ON c.organization_id = p.organization_id
                   AND c.project_id = p.project_id
                   AND c.environment_id = p.environment_id
                   AND c.id = p.candidate_id
                  WHERE p.organization_id = %(organization_id)s
                    AND p.project_id = %(project_id)s
                    AND p.environment_id = %(environment_id)s
                    AND p.memory_resource = ANY(%(resources)s)
                    AND p.decision = 'PROMOTED' AND p.retention_until > %(now)s
                    AND c.status = 'PROMOTED' AND c.expires_at > %(now)s
                    AND c.classification = %(classification)s
                    AND c.residency = %(region)s
                    AND p.exact_scope_json = %(exact_scope)s
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.memory_promotions successor
                      WHERE successor.organization_id = p.organization_id
                        AND successor.project_id = p.project_id
                        AND successor.environment_id = p.environment_id
                        AND successor.candidate_id = p.candidate_id
                        AND successor.created_at > p.created_at
                        AND successor.decision = 'PURGED')
                  ORDER BY p.memory_resource, p.created_at DESC""",
                {
                    **self._scope.canonical_dict(),
                    "resources": resources,
                    "now": now,
                    "classification": exact_scope.classification,
                    "region": exact_scope.region,
                    "exact_scope": Jsonb(exact_scope.canonical_dict()),
                },
            )
            rows = cursor.fetchall()
        by_resource: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_resource.setdefault(str(row["memory_resource"]), []).append(row)
        hints: list[MemoryHint] = []
        for candidate in candidates:
            matched = by_resource.get(candidate.memory_resource, [])
            if len(matched) != 1:
                continue
            row = matched[0]
            revision = str(row["memory_revision"]) if row["memory_revision"] is not None else None
            if (
                revision != candidate.memory_revision
                or str(row["fact_text"]).strip() != candidate.fact_text.strip()
                or candidate.exact_scope != exact_scope
            ):
                continue
            hints.append(
                MemoryHint(
                    memory_resource=candidate.memory_resource,
                    fact_text=str(row["fact_text"]),
                    exact_scope=exact_scope,
                    memory_revision=revision,
                    distance=candidate.distance,
                    source_refs=tuple(str(value) for value in row["source_refs"]),
                )
            )
        return tuple(hints)

    def _parse_scope(self, value: Any, purpose: str) -> MemoryScope:
        classification = str(value.get("classification", ""))
        region = str(value.get("region", ""))
        expected = {
            **self._scope.canonical_dict(),
            "purpose": purpose,
            "classification": classification,
            "region": region,
        }
        if value != expected:
            raise MemoryConflict("stored Memory Bank scope is not exact")
        return MemoryScope(self._scope, purpose, classification, region)

    @staticmethod
    def _require_aware(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("memory persistence timestamp must be timezone-aware")
