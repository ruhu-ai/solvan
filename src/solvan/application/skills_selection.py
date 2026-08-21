"""Deterministic, coordinator-owned selection of approved Agent Skills."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from solvan.domain import Scope, new_identifier

_COMMAND = re.compile(
    r"^/(?P<selector>[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)?)(?:\s+(?P<note>.*))?$"
)
_SELECTOR_SEGMENT = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


def _canonical_skill_key(guidance_key: str) -> tuple[str, str] | None:
    """Parse the canonical ``owner.name`` shape; any other key never matches."""

    segments = guidance_key.split(".")
    if len(segments) != 2 or not all(_SELECTOR_SEGMENT.fullmatch(part) for part in segments):
        return None
    return segments[0], segments[1]


@dataclass(frozen=True, slots=True)
class ParsedSkillSelector:
    owner_slug: str | None
    skill_name: str
    note: str

    @property
    def qualified(self) -> str:
        return f"{self.owner_slug}/{self.skill_name}" if self.owner_slug else self.skill_name


@dataclass(frozen=True, slots=True)
class SkillSelectionCandidate:
    guidance_key: str
    version: str
    revision_hash: str
    owner_slug: str


@dataclass(frozen=True, slots=True)
class SkillInvocationRequest:
    request_id: str
    candidate: SkillSelectionCandidate
    status: str
    conflict_reason: str | None = None


@dataclass(frozen=True, slots=True)
class SkillAutocompleteItem:
    selector: str
    guidance_key: str
    version: str
    display_name: str
    description: str


def parse_skill_selector(text: str) -> ParsedSkillSelector:
    value = " ".join(text.strip().split())
    if len(value) > 2_322:
        raise ValueError("GUIDANCE_SELECTOR_INVALID")
    match = _COMMAND.fullmatch(value)
    if match is None:
        raise ValueError("GUIDANCE_SELECTOR_INVALID")
    selector = match.group("selector")
    pieces = selector.split("/", 1)
    note = (match.group("note") or "").strip()
    if len(note) > 2_000:
        raise ValueError("GUIDANCE_NOTE_TOO_LONG")
    return ParsedSkillSelector(
        owner_slug=pieces[0] if len(pieces) == 2 else None,
        skill_name=pieces[-1],
        note=note,
    )


class PostgresSkillSelector:
    """Resolve only the current approved head visible to the verified caller."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def _eligible_rows(
        self,
        *,
        scope: Any,
        parsed: ParsedSkillSelector,
        runtime_region: str,
        purpose: str,
        classification_ceiling: str,
        discoverable_departments: tuple[str, ...],
    ) -> tuple[tuple[Any, ...], ...]:
        if classification_ceiling not in _CLASSIFICATION_RANK:
            raise ValueError("CLASSIFICATION_INVALID")
        ceiling = _CLASSIFICATION_RANK[classification_ceiling]
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT h.guidance_key,h.approved_version,r.revision_hash,
                              r.classification,o.owner_slug,r.discoverable_departments_json
                     FROM solvan_operability.guidance_current_heads h
                     JOIN solvan_operability.guidance_revisions r ON
                       (r.organization_id,r.project_id,r.environment_id,r.guidance_key,r.version)=
                       (h.organization_id,h.project_id,h.environment_id,h.guidance_key,h.approved_version)
                     JOIN solvan_operability.skill_owner_department_slugs o ON
                       (o.organization_id,o.project_id,o.environment_id)=
                       (h.organization_id,h.project_id,h.environment_id)
                      AND split_part(h.guidance_key,'.',1)=o.owner_slug
                    WHERE h.organization_id=%(organization_id)s
                      AND h.project_id=%(project_id)s AND h.environment_id=%(environment_id)s
                      AND r.lifecycle='APPROVED' AND r.guidance_kind='SKILL'
                      AND r.purpose=%(purpose)s
                      AND r.eligible_regions_json ? %(region)s
                      AND o.retired_at IS NULL
                      AND r.classification=ANY(%(classifications)s)
                      AND r.discoverable_departments_json ?| %(departments)s
                      AND split_part(h.guidance_key,'.',2)=%(skill_name)s
                      AND split_part(h.guidance_key,'.',3)=''
                      AND (%(owner_slug)s::text IS NULL OR o.owner_slug=%(owner_slug)s::text)
                    ORDER BY r.approved_at DESC,h.guidance_key""",
                {
                    **scope.canonical_dict(),
                    "purpose": purpose,
                    "region": runtime_region,
                    "skill_name": parsed.skill_name,
                    "owner_slug": parsed.owner_slug,
                    "classifications": [
                        level
                        for level, level_rank in _CLASSIFICATION_RANK.items()
                        if level_rank <= ceiling
                    ],
                    "departments": list(discoverable_departments),
                },
            )
            rows = cursor.fetchall()
        eligible = []
        for row in rows:
            key = _canonical_skill_key(str(row[0]))
            if key is None or key != (str(row[4]), parsed.skill_name):
                continue
            if parsed.owner_slug is not None and key[0] != parsed.owner_slug:
                continue
            if _CLASSIFICATION_RANK.get(str(row[3]), 99) > ceiling:
                continue
            if not set(row[5]).intersection(discoverable_departments):
                continue
            eligible.append(row)
        return tuple(eligible)

    def resolve(
        self,
        *,
        scope: Any,
        command: str,
        runtime_region: str,
        purpose: str,
        classification_ceiling: str,
        discoverable_departments: tuple[str, ...],
    ) -> tuple[ParsedSkillSelector, SkillSelectionCandidate]:
        parsed = parse_skill_selector(command)
        rows = self._eligible_rows(
            scope=scope,
            parsed=parsed,
            runtime_region=runtime_region,
            purpose=purpose,
            classification_ceiling=classification_ceiling,
            discoverable_departments=discoverable_departments,
        )
        if not rows:
            raise ValueError("GUIDANCE_NOT_ELIGIBLE")
        if len({str(row[0]) for row in rows}) > 1:
            qualified = ", ".join(sorted({f"/{row[4]}/{parsed.skill_name}" for row in rows}))
            raise ValueError(f"GUIDANCE_SELECTOR_AMBIGUOUS:{qualified}")
        row = rows[0]
        return parsed, SkillSelectionCandidate(
            guidance_key=str(row[0]),
            version=str(row[1]),
            revision_hash=str(row[2]),
            owner_slug=str(row[4]),
        )

    def resolve_for_principal(
        self,
        *,
        scope: Scope,
        principal: str,
        command: str,
        runtime_region: str,
    ) -> tuple[ParsedSkillSelector, SkillSelectionCandidate]:
        """Resolve against explicit current reader grants; omission denies.

        Exactly one distinct lineage may match across the caller's whole grant
        scope; more than one refuses with the closed disambiguation template.
        """

        parsed = parse_skill_selector(command)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT owner_department,purpose,classification_ceiling
                     FROM solvan_operability.skill_reader_grants
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND principal=%(principal)s AND region=%(region)s
                      AND (expires_at IS NULL OR expires_at > now())
                    ORDER BY owner_department,purpose""",
                {
                    **scope.canonical_dict(),
                    "principal": principal,
                    "region": runtime_region,
                },
            )
            grants = tuple(cursor.fetchall())
        if not grants:
            raise ValueError("GUIDANCE_READER_GRANT_REQUIRED")
        candidates: dict[str, SkillSelectionCandidate] = {}
        for department, purpose, ceiling in grants:
            for row in self._eligible_rows(
                scope=scope,
                parsed=parsed,
                runtime_region=runtime_region,
                purpose=str(purpose),
                classification_ceiling=str(ceiling),
                discoverable_departments=(str(department),),
            ):
                candidates[str(row[0])] = SkillSelectionCandidate(
                    guidance_key=str(row[0]),
                    version=str(row[1]),
                    revision_hash=str(row[2]),
                    owner_slug=str(row[4]),
                )
        if not candidates:
            raise ValueError("GUIDANCE_NOT_ELIGIBLE")
        if len(candidates) > 1:
            choices = ", ".join(
                sorted(
                    f"/{candidate.owner_slug}/{parsed.skill_name}"
                    for candidate in candidates.values()
                )
            )
            raise ValueError(f"GUIDANCE_SELECTOR_AMBIGUOUS:{choices}")
        return parsed, next(iter(candidates.values()))

    def autocomplete_for_principal(
        self,
        *,
        scope: Scope,
        principal: str,
        runtime_region: str,
        query: str,
        limit: int = 20,
    ) -> tuple[SkillAutocompleteItem, ...]:
        if not 1 <= limit <= 50:
            raise ValueError("GUIDANCE_AUTOCOMPLETE_LIMIT_INVALID")
        normalized = query.strip().lower().lstrip("/")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT owner_department,purpose,classification_ceiling
                     FROM solvan_operability.skill_reader_grants
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND principal=%(principal)s AND region=%(region)s
                      AND (expires_at IS NULL OR expires_at > now())""",
                {
                    **scope.canonical_dict(),
                    "principal": principal,
                    "region": runtime_region,
                },
            )
            grants = tuple(cursor.fetchall())
            if not grants:
                return ()
            cursor.execute(
                """SELECT h.guidance_key,h.approved_version,o.owner_slug,
                          d.display_name,r.description,r.purpose,r.classification,
                          r.discoverable_departments_json
                     FROM solvan_operability.guidance_current_heads h
                     JOIN solvan_operability.guidance_revisions r ON
                       (r.organization_id,r.project_id,r.environment_id,r.guidance_key,r.version)=
                       (h.organization_id,h.project_id,h.environment_id,h.guidance_key,h.approved_version)
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                     JOIN solvan_operability.skill_owner_department_slugs o ON
                       o.organization_id=h.organization_id AND o.project_id=h.project_id
                       AND o.environment_id=h.environment_id
                       AND split_part(h.guidance_key,'.',1)=o.owner_slug
                    WHERE h.organization_id=%(organization_id)s
                      AND h.project_id=%(project_id)s AND h.environment_id=%(environment_id)s
                      AND r.lifecycle='APPROVED' AND r.guidance_kind='SKILL'
                      AND r.eligible_regions_json ? %(region)s
                      AND o.retired_at IS NULL
                      AND split_part(h.guidance_key,'.',3)=''
                      AND EXISTS (
                        SELECT 1 FROM solvan_operability.skill_reader_grants g
                         WHERE g.organization_id=h.organization_id
                           AND g.project_id=h.project_id
                           AND g.environment_id=h.environment_id
                           AND g.principal=%(principal)s AND g.region=%(region)s
                           AND (g.expires_at IS NULL OR g.expires_at > now())
                           AND g.purpose=r.purpose
                           AND r.discoverable_departments_json ? g.owner_department
                           AND array_position(%(classification_order)s,r.classification)
                               <= array_position(%(classification_order)s,
                                                 g.classification_ceiling))
                    ORDER BY r.approved_at DESC,h.guidance_key""",
                {
                    **scope.canonical_dict(),
                    "region": runtime_region,
                    "principal": principal,
                    "classification_order": list(_CLASSIFICATION_RANK),
                },
            )
            rows = tuple(cursor.fetchall())
        items: list[SkillAutocompleteItem] = []
        for row in rows:
            key = _canonical_skill_key(str(row[0]))
            if key is None or key[0] != str(row[2]):
                continue
            qualified = f"{key[0]}/{key[1]}"
            if normalized and normalized not in qualified and normalized not in str(row[3]).lower():
                continue
            if not any(
                str(row[5]) == str(purpose)
                and _CLASSIFICATION_RANK.get(str(row[6]), 99)
                <= _CLASSIFICATION_RANK.get(str(ceiling), -1)
                and str(department) in set(row[7])
                for department, purpose, ceiling in grants
            ):
                continue
            items.append(
                SkillAutocompleteItem(
                    selector=f"/{qualified}",
                    guidance_key=str(row[0]),
                    version=str(row[1]),
                    display_name=str(row[3]),
                    description=str(row[4]),
                )
            )
            if len(items) >= limit:
                break
        return tuple(items)

    def record_invocation(
        self,
        *,
        scope: Scope,
        thread_id: str,
        answer_message_id: str,
        anchor_kind: str,
        anchor_record_type: str | None,
        anchor_record_id: str | None,
        parsed: ParsedSkillSelector,
        candidate: SkillSelectionCandidate,
        principal: str,
        membership_epoch: int,
        policy_epoch: int,
        note_classification: str = "INTERNAL",
    ) -> SkillInvocationRequest:
        """Persist a coordinator candidate; this does not start or authorize a run."""

        request_id = new_identifier("gir")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (":".join((scope.digest(), thread_id, "guidance-invocation")),),
            )
            cursor.execute(
                """SELECT i.id,i.guidance_key,i.guidance_version,c.reason_code
                     FROM solvan_operability.guidance_invocation_requests i
                     JOIN solvan_operability.guidance_incompatibilities c ON
                       c.organization_id=i.organization_id AND c.project_id=i.project_id
                       AND c.environment_id=i.environment_id
                       AND ((c.declaring_guidance_key=%(guidance_key)s
                             AND c.incompatible_guidance_key=i.guidance_key)
                         OR (c.declaring_guidance_key=i.guidance_key
                             AND c.incompatible_guidance_key=%(guidance_key)s))
                    WHERE i.organization_id=%(organization_id)s
                      AND i.project_id=%(project_id)s AND i.environment_id=%(environment_id)s
                      AND i.thread_id=%(thread_id)s
                      AND i.request_status IN ('PENDING_COORDINATOR','ACCEPTED')
                    ORDER BY i.created_at LIMIT 1 FOR SHARE OF i,c""",
                {
                    **scope.canonical_dict(),
                    "thread_id": thread_id,
                    "guidance_key": candidate.guidance_key,
                },
            )
            conflict = cursor.fetchone()
            request_status = "REFUSED" if conflict is not None else "PENDING_COORDINATOR"
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_invocation_requests
                     (organization_id,project_id,environment_id,id,thread_id,answer_message_id,
                      anchor_kind,anchor_record_type,anchor_record_id,selector,guidance_key,
                      guidance_version,guidance_hash,requester_principal,request_status,
                      membership_epoch,policy_epoch)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(thread_id)s,%(answer_message_id)s,%(anchor_kind)s,
                           %(record_type)s,%(record_id)s,%(selector)s,%(guidance_key)s,
                           %(version)s,%(hash)s,%(principal)s,%(status)s,
                           %(membership_epoch)s,%(policy_epoch)s)
                   ON CONFLICT (organization_id,project_id,environment_id,answer_message_id)
                   DO NOTHING RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": request_id,
                    "thread_id": thread_id,
                    "answer_message_id": answer_message_id,
                    "anchor_kind": anchor_kind,
                    "record_type": anchor_record_type,
                    "record_id": anchor_record_id,
                    "selector": parsed.qualified,
                    "guidance_key": candidate.guidance_key,
                    "version": candidate.version,
                    "hash": candidate.revision_hash,
                    "principal": principal,
                    "status": request_status,
                    "membership_epoch": membership_epoch,
                    "policy_epoch": policy_epoch,
                },
            )
            inserted = cursor.fetchone() is not None
            if not inserted:
                cursor.execute(
                    """SELECT id,guidance_key,guidance_version,guidance_hash,request_status
                         FROM solvan_operability.guidance_invocation_requests
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND answer_message_id=%(answer_message_id)s""",
                    {**scope.canonical_dict(), "answer_message_id": answer_message_id},
                )
                stored = cursor.fetchone()
                if stored is None:
                    raise RuntimeError("guidance invocation request was not persisted")
                if (str(stored[1]), str(stored[2]), str(stored[3])) != (
                    candidate.guidance_key,
                    candidate.version,
                    candidate.revision_hash,
                ):
                    raise ValueError("GUIDANCE_INVOCATION_REPLAY_CONFLICT")
                replay_status = str(stored[4])
                replay_reason = None
                if replay_status == "REFUSED":
                    cursor.execute(
                        """SELECT reason_code
                             FROM solvan_operability.guidance_invocation_conflicts
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND invocation_request_id=%(request_id)s
                            ORDER BY detected_at,conflicting_invocation_request_id
                            LIMIT 1""",
                        {**scope.canonical_dict(), "request_id": str(stored[0])},
                    )
                    reason_row = cursor.fetchone()
                    replay_reason = None if reason_row is None else str(reason_row[0])
                return SkillInvocationRequest(
                    request_id=str(stored[0]),
                    candidate=candidate,
                    status=replay_status,
                    conflict_reason=replay_reason,
                )
            conflict_reason = None
            if conflict is not None:
                conflict_reason = str(conflict[3])
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_invocation_conflicts
                         (organization_id,project_id,environment_id,invocation_request_id,
                          conflicting_invocation_request_id,reason_code)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(request_id)s,%(conflicting_id)s,%(reason)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "request_id": request_id,
                        "conflicting_id": str(conflict[0]),
                        "reason": conflict_reason,
                    },
                )
            if parsed.note:
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_operator_notes
                         (organization_id,project_id,environment_id,invocation_request_id,
                          note_text,note_classification,author_principal,access_mode)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(request_id)s,%(note)s,%(classification)s,%(principal)s,
                               'SELECTION_READERS')""",
                    {
                        **scope.canonical_dict(),
                        "request_id": request_id,
                        "note": parsed.note,
                        "classification": note_classification,
                        "principal": principal,
                    },
                )
            outcome = "CONFLICT_REFUSED" if conflict is not None else "CANDIDATE_RECORDED"
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_selection_analytics
                     (organization_id,project_id,environment_id,guidance_key,guidance_version,
                      selection_reason,outcome_code,selection_count)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(guidance_key)s,%(version)s,'OPERATOR_INVOKED',%(outcome)s,1)
                   ON CONFLICT (organization_id,project_id,environment_id,guidance_key,
                                guidance_version,selection_reason,outcome_code)
                   DO UPDATE SET selection_count=
                     solvan_operability.guidance_selection_analytics.selection_count+1,
                     updated_at=now()""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": candidate.guidance_key,
                    "version": candidate.version,
                    "outcome": outcome,
                },
            )
        return SkillInvocationRequest(
            request_id=request_id,
            candidate=candidate,
            status=request_status,
            conflict_reason=conflict_reason,
        )
