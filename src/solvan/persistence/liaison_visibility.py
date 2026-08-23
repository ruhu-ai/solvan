"""Reader-side evaluation of stored transcript access envelopes."""

from __future__ import annotations

from typing import Any

from solvan.domain import Scope

# The two modes whose visibility is decided by the authorized record set.
# `DERIVED_SOURCES` joins to its sources as well (see reader_may_see_compaction),
# but at row level both are the same rule: an empty set denies.
_RECORD_SET_MODES = frozenset({"RECORD_SET", "DERIVED_SOURCES"})


class UnknownAccessMode(ValueError):
    """An access mode this build cannot evaluate. Never resolved into a grant."""


def reader_may_see_row(
    *,
    access_mode: str,
    author_principal: str | None,
    references: set[tuple[str, ...]],
    reader_principal: str,
    authorized: set[tuple[str, str]],
    participant_epochs: dict[str, int],
    membership_epoch: int | None,
) -> bool:
    """The stored form of the §5 rule. An empty record set denies."""

    if access_mode == "SYSTEM_PUBLIC":
        return True
    if access_mode == "AUTHOR_ONLY":
        return reader_principal == author_principal
    if access_mode == "PARTICIPANTS_AT_EPOCH":
        reader_epoch = participant_epochs.get(reader_principal)
        return (
            reader_epoch is not None
            and membership_epoch is not None
            and reader_epoch <= membership_epoch
        )
    if access_mode not in _RECORD_SET_MODES:
        # INV-C-06/§5: visibility is never granted by omission. Every mode
        # except the record-set pair used to fall through to the check below,
        # so an unrecognized value -- a typo, or a mode added to the schema
        # after this build -- was evaluated as "the authorized references
        # decide" and could return True for a mode whose rule nobody had
        # written yet. A mode this build cannot evaluate refuses instead, and
        # says which one, rather than returning a quiet False that would hide
        # the missing rule.
        raise UnknownAccessMode(f"unrecognized access mode {access_mode!r}")
    if not references:
        return False
    return all(tuple(reference) in authorized for reference in references)


def reader_may_see_compaction(
    cursor: Any,
    *,
    scope: Scope,
    part_id: str,
    reader_principal: str,
    authorized: set[tuple[str, str]],
    participant_epochs: dict[str, int],
) -> bool:
    """A summary is visible only when every original source part is visible."""

    cursor.execute(
        """SELECT p.access_mode,p.author_principal,p.membership_epoch,p.id,
                  coalesce(array_agg(a.record_type || ':' || a.record_id)
                    FILTER (WHERE a.record_type IS NOT NULL),'{}') AS access
             FROM solvan_liaison.liaison_compaction_sources s
             JOIN solvan_liaison.liaison_message_parts p ON
               (p.organization_id,p.project_id,p.environment_id,p.message_id)=
               (s.organization_id,s.project_id,s.environment_id,s.source_message_id)
             LEFT JOIN solvan_liaison.liaison_part_access a ON
               (a.organization_id,a.project_id,a.environment_id,a.part_id)=
               (p.organization_id,p.project_id,p.environment_id,p.id)
            WHERE s.organization_id=%(organization_id)s
              AND s.project_id=%(project_id)s AND s.environment_id=%(environment_id)s
              AND s.compaction_part_id=%(part_id)s
            GROUP BY p.access_mode,p.author_principal,p.membership_epoch,p.id""",
        {**scope.canonical_dict(), "part_id": part_id},
    )
    rows = cursor.fetchall()
    if not rows:
        return False
    return all(
        row["access_mode"] != "DERIVED_SOURCES"
        and reader_may_see_row(
            access_mode=str(row["access_mode"]),
            author_principal=row["author_principal"],
            references={tuple(item.split(":", 1)) for item in (row["access"] or [])},
            reader_principal=reader_principal,
            authorized=authorized,
            participant_epochs=participant_epochs,
            membership_epoch=row["membership_epoch"],
        )
        for row in rows
    )
