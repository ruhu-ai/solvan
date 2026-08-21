"""Typed Liaison part persistence and streaming lifecycle.

Part rows are the durable boundary between provider work and the reader
projection.  This mixin keeps the scope/thread store focused on graph and
message operations while retaining one transactional implementation for
completed, streaming, and discarded parts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from psycopg import Connection

from solvan.application.liaison.parts import Part
from solvan.domain import Scope, new_identifier


class LiaisonPartStoreMixin:
    """Part operations mixed into the scope-bound authoritative store."""

    _connection: Connection[Any]

    def record_exists(self, *, scope: Scope, record_type: str, record_id: str) -> bool:
        """Implemented by the owning store's record-directory boundary."""

        raise NotImplementedError

    def append_parts(
        self,
        *,
        scope: Scope,
        message_id: str,
        parts: Sequence[Part],
        attempt: int | None = None,
        generation: int | None = None,
    ) -> tuple[str, ...]:
        """Persist parts and their access envelopes in one transaction."""

        if (attempt is None) != (generation is None):
            raise ValueError("attempt and generation must be supplied together")
        if attempt is not None and attempt <= 0:
            raise ValueError("attempt must be positive")
        if generation is not None and generation <= 0:
            raise ValueError("generation must be positive")
        part_ids: list[str] = []
        with self._connection.cursor() as cursor:
            for part in parts:
                part_id = new_identifier("prt")
                part_ids.append(part_id)
                cursor.execute(
                    """INSERT INTO solvan_liaison.liaison_message_parts (
                          organization_id, project_id, environment_id, id, message_id,
                          sequence, kind, schema_version, status, classification,
                          access_mode, author_principal, membership_epoch,
                          payload_json, attempt, generation, completed_at)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(id)s, %(message_id)s, %(sequence)s, %(kind)s,
                          %(schema_version)s, 'COMPLETED', %(classification)s,
                          %(access_mode)s, %(author_principal)s, %(membership_epoch)s,
                          %(payload)s, %(attempt)s, %(generation)s, now())""",
                    {
                        **scope.canonical_dict(),
                        "id": part_id,
                        "message_id": message_id,
                        "sequence": part.sequence,
                        "kind": str(part.kind),
                        "schema_version": part.schema_version,
                        "classification": part.classification,
                        "access_mode": str(part.access_mode),
                        "author_principal": part.author_principal,
                        "membership_epoch": part.membership_epoch,
                        "payload": json.dumps(part.payload, default=str),
                        "attempt": attempt,
                        "generation": generation,
                    },
                )
                for reference in part.access_set:
                    # An unknown directory record is dropped rather than
                    # creating an envelope no reader can ever resolve.
                    if not self.record_exists(
                        scope=scope,
                        record_type=reference.record_type,
                        record_id=reference.record_id,
                    ):
                        continue
                    cursor.execute(
                        """INSERT INTO solvan_liaison.liaison_part_access (
                              organization_id, project_id, environment_id, part_id,
                              record_type, record_id, relation)
                           VALUES (%(organization_id)s, %(project_id)s,
                              %(environment_id)s, %(part_id)s, %(record_type)s,
                              %(record_id)s, %(relation)s)
                           ON CONFLICT DO NOTHING""",
                        {
                            **scope.canonical_dict(),
                            "part_id": part_id,
                            "record_type": reference.record_type,
                            "record_id": reference.record_id,
                            "relation": reference.relation,
                        },
                    )
                for audience_principal in sorted(part.audience_principals):
                    cursor.execute(
                        """INSERT INTO solvan_liaison.liaison_part_audience_principals (
                              organization_id, project_id, environment_id, part_id, principal)
                           VALUES (%(organization_id)s, %(project_id)s,
                              %(environment_id)s, %(part_id)s, %(principal)s)
                           ON CONFLICT DO NOTHING""",
                        {
                            **scope.canonical_dict(),
                            "part_id": part_id,
                            "principal": audience_principal,
                        },
                    )
        return tuple(part_ids)

    def begin_streaming_part(
        self,
        *,
        scope: Scope,
        message_id: str,
        attempt: int,
        generation: int,
        part: Part,
        initiating_principal: str,
    ) -> str:
        """Persist one typed in-flight part behind an author-only envelope."""

        if attempt <= 0 or generation <= 0:
            raise ValueError("streaming attempt and generation must be positive")
        if not initiating_principal.strip():
            raise ValueError("streaming parts require an initiating principal")
        part_id = new_identifier("prt")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_message_parts (
                      organization_id, project_id, environment_id, id, message_id,
                      sequence, kind, schema_version, status, classification,
                      access_mode, author_principal, membership_epoch, payload_json,
                      attempt, generation)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(id)s, %(message_id)s, %(sequence)s, %(kind)s,
                      %(schema_version)s, 'STREAMING', %(classification)s,
                      'AUTHOR_ONLY', %(principal)s, NULL, %(payload)s,
                      %(attempt)s, %(generation)s)""",
                {
                    **scope.canonical_dict(),
                    "id": part_id,
                    "message_id": message_id,
                    "sequence": part.sequence,
                    "kind": str(part.kind),
                    "schema_version": part.schema_version,
                    "classification": part.classification,
                    "principal": initiating_principal,
                    "payload": json.dumps(part.payload, default=str),
                    "attempt": attempt,
                    "generation": generation,
                },
            )
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_part_audience_principals (
                      organization_id, project_id, environment_id, part_id, principal)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(part_id)s, %(principal)s)""",
                {
                    **scope.canonical_dict(),
                    "part_id": part_id,
                    "principal": initiating_principal,
                },
            )
        return part_id

    def complete_streaming_part(
        self,
        *,
        scope: Scope,
        message_id: str,
        part_id: str,
        attempt: int,
        generation: int,
        part: Part,
        initiating_principal: str,
    ) -> bool:
        """Atomically replace an in-flight envelope with the final one."""

        if attempt <= 0 or generation <= 0:
            raise ValueError("streaming attempt and generation must be positive")
        if not initiating_principal.strip():
            raise ValueError("streaming parts require an initiating principal")
        if part.sequence < 0:
            raise ValueError("part sequence cannot be negative")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT sequence, kind, author_principal
                     FROM solvan_liaison.liaison_message_parts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(part_id)s AND message_id=%(message_id)s
                      AND attempt=%(attempt)s AND generation=%(generation)s
                      AND status='STREAMING'
                    FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "part_id": part_id,
                    "message_id": message_id,
                    "attempt": attempt,
                    "generation": generation,
                },
            )
            row = cursor.fetchone()
            if row is None:
                return False
            if int(row[0]) != part.sequence or str(row[1]) != str(part.kind):
                raise ValueError("streaming part identity changed before completion")
            if str(row[2]) != initiating_principal:
                raise ValueError("streaming part initiator changed before completion")

            accepted: list[tuple[str, str, str]] = []
            for reference in part.access_set:
                if self.record_exists(
                    scope=scope,
                    record_type=reference.record_type,
                    record_id=reference.record_id,
                ):
                    accepted.append(
                        (reference.record_type, reference.record_id, reference.relation)
                    )
            access_hash = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(sorted(accepted), separators=(",", ":")).encode("utf-8")
                ).hexdigest()
            )
            cursor.execute(
                """DELETE FROM solvan_liaison.liaison_part_access
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND part_id=%(part_id)s""",
                {**scope.canonical_dict(), "part_id": part_id},
            )
            cursor.execute(
                """DELETE FROM solvan_liaison.liaison_part_audience_principals
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND part_id=%(part_id)s""",
                {**scope.canonical_dict(), "part_id": part_id},
            )
            cursor.execute(
                """UPDATE solvan_liaison.liaison_message_parts
                      SET status='COMPLETED', classification=%(classification)s,
                          access_mode=%(access_mode)s,
                          author_principal=%(author_principal)s,
                          membership_epoch=%(membership_epoch)s,
                          payload_json=%(payload)s, access_set_hash=%(access_hash)s,
                          completed_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(part_id)s AND status='STREAMING'""",
                {
                    **scope.canonical_dict(),
                    "part_id": part_id,
                    "classification": part.classification,
                    "access_mode": str(part.access_mode),
                    "author_principal": part.author_principal,
                    "membership_epoch": part.membership_epoch,
                    "payload": json.dumps(part.payload, default=str),
                    "access_hash": access_hash,
                },
            )
            for record_type, record_id, relation in accepted:
                cursor.execute(
                    """INSERT INTO solvan_liaison.liaison_part_access (
                          organization_id, project_id, environment_id, part_id,
                          record_type, record_id, relation)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(part_id)s, %(record_type)s, %(record_id)s, %(relation)s)""",
                    {
                        **scope.canonical_dict(),
                        "part_id": part_id,
                        "record_type": record_type,
                        "record_id": record_id,
                        "relation": relation,
                    },
                )
            for audience_principal in sorted(part.audience_principals):
                cursor.execute(
                    """INSERT INTO solvan_liaison.liaison_part_audience_principals (
                          organization_id, project_id, environment_id, part_id, principal)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(part_id)s, %(principal)s)""",
                    {
                        **scope.canonical_dict(),
                        "part_id": part_id,
                        "principal": audience_principal,
                    },
                )
        return True

    def discard_streaming_parts(
        self,
        *,
        scope: Scope,
        message_id: str,
        attempt: int,
        generation: int,
    ) -> tuple[str, ...]:
        """Discard only uncompleted parts for one exact stale attempt."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM solvan_liaison.liaison_message_parts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND message_id=%(message_id)s AND attempt=%(attempt)s
                      AND generation=%(generation)s AND status='STREAMING'
                    FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "message_id": message_id,
                    "attempt": attempt,
                    "generation": generation,
                },
            )
            ids = tuple(str(row[0]) for row in cursor.fetchall())
            if not ids:
                return ()
            cursor.execute(
                """DELETE FROM solvan_liaison.liaison_part_access
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND part_id = ANY(%(part_ids)s)""",
                {**scope.canonical_dict(), "part_ids": list(ids)},
            )
            cursor.execute(
                """DELETE FROM solvan_liaison.liaison_part_audience_principals
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND part_id = ANY(%(part_ids)s)""",
                {**scope.canonical_dict(), "part_ids": list(ids)},
            )
            cursor.execute(
                """DELETE FROM solvan_liaison.liaison_message_parts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id = ANY(%(part_ids)s) AND status='STREAMING'""",
                {**scope.canonical_dict(), "part_ids": list(ids)},
            )
        return ids
