"""Target SQL cursor persistence for the SaaS event feed."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.domain import Scope


class SaaSScaleCursorRepository:
    """Expose only the target schema's fenced cursor functions."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def recover(
        self,
        *,
        scope: Scope,
        cursor_id: str,
        reader_key_hash: str,
        cell_id: str,
        placement_epoch: int,
        policy_epoch: int,
        membership_epoch: int,
        scope_sequence: int,
        recovery_receipt_hash: str,
    ) -> str:
        if not cursor_id.startswith("cur_"):
            raise ValueError("cursor id is invalid")
        if not reader_key_hash.startswith("sha256:") or len(reader_key_hash) != 71:
            raise ValueError("reader key hash must be typed")
        if placement_epoch < 1 or policy_epoch < 1 or membership_epoch < 1:
            raise ValueError("cursor epochs must be positive")
        if scope_sequence < 0:
            raise ValueError("cursor sequence cannot be negative")
        if not recovery_receipt_hash.startswith("sha256:") or len(recovery_receipt_hash) != 71:
            raise ValueError("cursor recovery receipt must be typed")
        row = self._connection.execute(
            """SELECT solvan_scale.recover_scope_event_cursor(
                 %(organization_id)s,%(project_id)s,%(environment_id)s,%(cursor_id)s,
                 %(reader_key_hash)s,%(cell_id)s,%(placement_epoch)s,%(policy_epoch)s,
                 %(membership_epoch)s,%(scope_sequence)s,%(recovery_receipt_hash)s)""",
            {
                **scope.canonical_dict(),
                "cursor_id": cursor_id,
                "reader_key_hash": reader_key_hash,
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "policy_epoch": policy_epoch,
                "membership_epoch": membership_epoch,
                "scope_sequence": scope_sequence,
                "recovery_receipt_hash": recovery_receipt_hash,
            },
        ).fetchone()
        if row is None:
            raise RuntimeError("cursor recovery function returned no cursor")
        return str(row[0])

    def advance(
        self,
        *,
        scope: Scope,
        cursor_id: str,
        expected_sequence: int,
        next_sequence: int,
    ) -> str:
        if not cursor_id.startswith("cur_"):
            raise ValueError("cursor id is invalid")
        if expected_sequence < 0 or next_sequence <= expected_sequence:
            raise ValueError("cursor sequence must increase")
        row = self._connection.execute(
            """SELECT solvan_scale.advance_scope_event_cursor(
                 %(organization_id)s,%(project_id)s,%(environment_id)s,%(cursor_id)s,
                 %(expected_sequence)s,%(next_sequence)s)""",
            {
                **scope.canonical_dict(),
                "cursor_id": cursor_id,
                "expected_sequence": expected_sequence,
                "next_sequence": next_sequence,
            },
        ).fetchone()
        if row is None:
            raise RuntimeError("cursor advance function returned no cursor")
        return str(row[0])
