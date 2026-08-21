"""Scope-local event ordering: the one total order catch-up depends on.

An anchor can span several entities, and each entity numbers its own workflow
versions from one. So "everything after v12" is meaningless across a service or
a scope: v12 of one incident and v12 of another are unrelated points in time.

This module allocates a monotonic per-scope sequence inside the same transaction
as the authoritative mutation, giving every committed event one comparable
position. Gaps are permitted and mean nothing — a rolled-back transaction leaves
an inert number, and no hidden-event count may be derived from it.

Specification 14 §11 (scope-sequence contract) and §17.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection

from solvan.domain import Scope


class SequenceError(RuntimeError):
    """The scope sequence could not be allocated; nothing may claim an order."""


@dataclass(frozen=True, slots=True)
class Cursor:
    """An opaque catch-up position.

    It carries the authorization snapshot as well as the sequence, so a reader
    whose authority changed cannot silently continue against a position that was
    computed under different visibility (§17).
    """

    scope_sequence: int
    policy_epoch: int

    def encode(self) -> str:
        return f"{self.policy_epoch}:{self.scope_sequence}"

    @classmethod
    def decode(cls, value: str | None, *, policy_epoch: int) -> Cursor:
        """Parse a cursor, or start from the beginning under this epoch.

        A malformed cursor is treated as absent rather than rejected: the cost
        of restarting a brief is a repeated line, and the cost of failing is an
        operator who cannot catch up at all.
        """

        if not value:
            return cls(0, policy_epoch)
        head, _, tail = value.partition(":")
        try:
            return cls(int(tail), int(head))
        except ValueError:
            return cls(0, policy_epoch)


def allocate_scope_sequence(connection: Connection[Any], *, scope: Scope) -> int:
    """Take the next sequence for this scope, under a row lock.

    Must be called inside the transaction that commits the event it orders. The
    lock serializes allocation so two concurrent writers cannot receive the same
    position; the uniqueness constraint on the outbox is the second control.
    """

    row = connection.execute(
        """INSERT INTO solvan_liaison.scope_event_sequences (
              organization_id, project_id, environment_id, next_sequence)
           VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s, 2)
           ON CONFLICT (organization_id, project_id, environment_id) DO UPDATE
           SET next_sequence = solvan_liaison.scope_event_sequences.next_sequence + 1
           RETURNING next_sequence - 1""",
        scope.canonical_dict(),
    ).fetchone()
    if row is None:  # pragma: no cover - the upsert always returns a row
        raise SequenceError("scope sequence allocation returned nothing")
    return int(row[0])


def current_scope_sequence(connection: Connection[Any], *, scope: Scope) -> int:
    """The high-water mark, for a reader starting from now."""

    row = connection.execute(
        """SELECT next_sequence - 1 FROM solvan_liaison.scope_event_sequences
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s""",
        scope.canonical_dict(),
    ).fetchone()
    return 0 if row is None else int(row[0])
