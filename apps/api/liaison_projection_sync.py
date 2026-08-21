"""Mirror the authoritative console projection into the Liaison directory."""

from __future__ import annotations

from apps.api.liaison_reader import SnapshotProjectionReader
from solvan.domain import Scope
from solvan.persistence.liaison_store import LiaisonStore


def directory_rows(
    reader: SnapshotProjectionReader,
) -> list[tuple[str, str, str | None, str]]:
    """Return every addressable record the current projection exposes."""

    rows: list[tuple[str, str, str | None, str]] = []
    for record_type, record_id in reader.authorized_records():
        record = reader.read(record_type, record_id) or {}
        service = record.get("service")
        rows.append(
            (
                record_type,
                record_id,
                str(service) if service else None,
                str(record.get("classification", "INTERNAL")).split(" ")[0],
            )
        )
    return rows


def sync_projection(store: LiaisonStore, *, scope: Scope, reader: SnapshotProjectionReader) -> None:
    """Write directory records before their graph edges."""

    store.sync_directory(scope=scope, records=directory_rows(reader))
    store.sync_edges(scope=scope, edges=reader.record_edges())
