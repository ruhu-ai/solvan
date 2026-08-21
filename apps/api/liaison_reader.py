"""A projection reader over the console snapshot.

The Liaison answers from the same typed projection the console renders — never
from a model transcript, Memory Bank, or any other non-authoritative store
(specification 14 §4). This adapter is the composition-root half of that rule:
it turns the snapshot into per-record lookups and nothing else.

It is deliberately read-only and deliberately narrow. There is no query
interface here, no filtering by principal, and no write path, because those
belong to the grant layer and the store respectively.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from solvan.application.liaison import ANCHORABLE_RECORD_TYPES, Anchor, AnchorKind, entity_set
from solvan.domain import Scope
from solvan.persistence.liaison_catchup import catch_up
from solvan.persistence.liaison_sequence import Cursor
from solvan.persistence.liaison_store import LiaisonStore

#: What a child record is to its parent. The relation is named rather than
#: implied so a catch-up brief can say *why* an event belongs to the anchor,
#: and so a new child type must be classified deliberately instead of
#: inheriting whatever the last one meant.
_EDGE_RELATIONS = {
    "evidence_item": "EVIDENCES",
    "action": "MITIGATES",
    "verification_run": "VERIFIES",
    "patch_artifact": "REPAIRS",
    "workspace": "CONTAINS",
    "reliability_case": "CONTAINS",
}


def _index_alert(
    records: dict[tuple[str, str], Mapping[str, Any]], alert: Mapping[str, Any]
) -> None:
    """Register one already reader-filtered Alert report as an anchor."""

    episode_id = str(alert.get("alert_episode_id", ""))
    if episode_id:
        records[("alert_episode", episode_id)] = alert


def _index_incident(
    records: dict[tuple[str, str], Mapping[str, Any]], incident: Mapping[str, Any]
) -> None:
    """Register an incident and every record it makes addressable."""

    display_id = str(incident.get("id", ""))
    if not display_id:
        return
    records[("incident", display_id)] = incident

    verification = incident.get("verification")
    if isinstance(verification, Mapping) and verification.get("id"):
        # The verification run carries its incident so a predicate can check
        # that a passed verdict is about *this* incident and not another.
        records[("verification_run", str(verification["id"]))] = {
            **verification,
            "incident": display_id,
        }

    actions = incident.get("actions")
    if isinstance(actions, Sequence):
        for action in actions:
            if isinstance(action, Mapping) and action.get("id"):
                records[("action", str(action["id"]))] = {**action, "incident": display_id}

    evidence = incident.get("evidence_index")
    if isinstance(evidence, Sequence):
        for item in evidence:
            if isinstance(item, Mapping) and item.get("ref"):
                records[("evidence_item", str(item["ref"]))] = {**item, "incident": display_id}


def _index_case(records: dict[tuple[str, str], Mapping[str, Any]], case: Mapping[str, Any]) -> None:
    display_id = str(case.get("id", ""))
    if not display_id:
        return
    records[("reliability_case", display_id)] = case
    artifact = case.get("patch_artifact")
    if artifact and artifact != "not proposed":
        records[("patch_artifact", str(artifact))] = case
    workspace = case.get("workspace")
    if isinstance(workspace, Mapping) and workspace.get("id"):
        records[("workspace", str(workspace["id"]))] = workspace


class SnapshotProjectionReader:
    """Resolves `(record_type, record_id)` against one console snapshot."""

    def __init__(
        self,
        snapshot: Mapping[str, Any],
        *,
        connect: Callable[[], Any] | None = None,
        scope_authorized: bool = True,
    ) -> None:
        records: dict[tuple[str, str], Mapping[str, Any]] = {}
        for incident in snapshot.get("incidents", []):
            if isinstance(incident, Mapping):
                _index_incident(records, incident)
        for case in snapshot.get("cases", []):
            if isinstance(case, Mapping):
                _index_case(records, case)
        for alert in snapshot.get("alerts", []):
            if isinstance(alert, Mapping):
                _index_alert(records, alert)
        integration = snapshot.get("integration")
        if isinstance(integration, Mapping):
            for connection in integration.get("connections", []):
                if isinstance(connection, Mapping) and connection.get("id"):
                    records[("tenant_connection", str(connection["id"]))] = connection
        self._records = records
        self._connect = connect
        # The snapshot is only a projection.  It is not itself an authorization
        # decision.  Production composition roots pass the result of the
        # verified principal/role check here; an empty result is deliberately
        # indistinguishable from an empty projection to callers.
        self._scope_authorized = scope_authorized

    @property
    def scope_authorized(self) -> bool:
        """Whether the verified principal was admitted to this scope."""

        return self._scope_authorized

    def read(self, record_type: str, record_id: str) -> Mapping[str, Any] | None:
        return self._records.get((record_type, record_id))

    # -- RecordDirectory ----------------------------------------------------

    def exists(self, record_type: str, record_id: str) -> bool:
        return (record_type, record_id) in self._records

    def children(self, record_type: str, record_id: str) -> tuple[tuple[str, str], ...]:
        """The records an anchor reaches, for context and for catch-up.

        Authority never flows along these edges; only context does. The reader
        filter is applied per record by the caller (§4).
        """

        if record_type == "scope":
            return tuple(self._records)
        if record_type == "service":
            return tuple(
                key
                for key, value in self._records.items()
                if str(value.get("service", "")) == record_id
            )
        record = self._records.get((record_type, record_id))
        if record is None:
            return ()
        reachable = [
            key
            for key, value in self._records.items()
            if key != (record_type, record_id) and str(value.get("incident", "")) == record_id
        ]
        return tuple(reachable)

    def record_edges(self) -> tuple[tuple[str, str, str, str, str], ...]:
        """The parent/child graph this snapshot implies, as durable edges.

        `children` answers the question live; this persists the same graph so a
        catch-up query can join on it. Without it, a brief anchored on an
        incident silently omits its own evidence and actions — the reader would
        be told nothing happened while the record's children moved.
        """

        edges: list[tuple[str, str, str, str, str]] = []
        for (record_type, record_id), _ in self._records.items():
            if record_type not in ANCHORABLE_RECORD_TYPES:
                continue
            for child_type, child_id in self.children(record_type, record_id):
                relation = _EDGE_RELATIONS.get(child_type)
                if relation is None:
                    continue
                edges.append((record_type, record_id, child_type, child_id, relation))
        return tuple(sorted(set(edges)))

    def authorized_records(self) -> tuple[tuple[str, str], ...]:
        """Return the scope's addressable records for the local adapter.

        Callers that hold a record or service grant must use
        ``authorized_records_for_anchor``. Keeping the unbounded scope view in
        one explicit method makes accidental use in a narrower path visible
        and testable; production authorization is applied by the grant layer.
        """

        if not self._scope_authorized:
            return ()
        return tuple(key for key in self._records if key[0] in ANCHORABLE_RECORD_TYPES)

    def authorized_records_for_anchor(self, anchor: Anchor) -> tuple[tuple[str, str], ...]:
        """Return only records reachable from the exact conversational anchor.

        Graph edges provide context, never authority: the result is still the
        reader's scope set intersected with the anchor entity set.
        """

        scope_records = set(self.authorized_records())
        if anchor.kind is AnchorKind.SCOPE:
            return tuple(key for key in self.authorized_records() if key in scope_records)
        return tuple(key for key in entity_set(self, anchor) if key in scope_records)

    # -- Closed conversational read tools ---------------------------------

    def resolve_reference(self, reference: str) -> tuple[str, str] | None:
        """Resolve one exact ``type:id`` label from the local directory."""

        record_type, separator, record_id = reference.strip().partition(":")
        normalized_type = {
            "case": "reliability_case",
            "verification": "verification_run",
        }.get(record_type, record_type)
        key = (normalized_type, record_id)
        if not separator or key not in self._records:
            return None
        return key

    def list_prior_incidents(
        self,
        *,
        service_key: str,
        window_start: datetime | None,
        window_end: datetime | None,
        authorized_records: Sequence[tuple[str, str]],
        limit: int = 20,
    ) -> tuple[Mapping[str, Any], ...]:
        """Return bounded queue rows, never full incident documents."""

        allowed = set(authorized_records)
        rows: list[Mapping[str, Any]] = []
        for (record_type, record_id), record in self._records.items():
            if record_type != "incident" or (record_type, record_id) not in allowed:
                continue
            if str(record.get("service", "")) != service_key:
                continue
            detected_at = _as_datetime(record.get("detected_at"))
            if window_start is not None and (detected_at is None or detected_at < window_start):
                continue
            if window_end is not None and (detected_at is None or detected_at >= window_end):
                continue
            rows.append(
                {
                    "record_type": "incident",
                    "record_id": record_id,
                    "title": str(record.get("title", ""))[:200],
                    "state": str(record.get("state", "")),
                    "severity": str(record.get("severity", "")),
                    "service": service_key,
                    "detected_at": record.get("detected_at"),
                }
            )
        rows.sort(key=lambda item: str(item.get("detected_at", "")), reverse=True)
        return tuple(rows[: max(0, min(limit, 20))])

    def search_records(
        self,
        *,
        service_key: str | None,
        state: str | None,
        record_type: str | None,
        window_start: datetime | None,
        window_end: datetime | None,
        authorized_records: Sequence[tuple[str, str]],
        limit: int = 20,
    ) -> tuple[Mapping[str, Any], ...]:
        """Search typed projection metadata within the already-visible set."""

        allowed = set(authorized_records)
        matches: list[Mapping[str, Any]] = []
        for (candidate_type, record_id), record in sorted(self._records.items()):
            if (candidate_type, record_id) not in allowed:
                continue
            if record_type and candidate_type != record_type:
                continue
            if service_key and str(record.get("service", "")) != service_key:
                continue
            if state and str(record.get("state", "")).upper() != state.upper():
                continue
            occurred_at = _as_datetime(record.get("detected_at") or record.get("created_at"))
            if window_start is not None and (occurred_at is None or occurred_at < window_start):
                continue
            if window_end is not None and (occurred_at is None or occurred_at >= window_end):
                continue
            matches.append(
                {
                    "record_type": candidate_type,
                    "record_id": record_id,
                    "title": str(record.get("title", record.get("name", "")))[:200],
                    "state": str(record.get("state", record.get("status", ""))),
                    "service": str(record.get("service", "")),
                }
            )
        return tuple(matches[: max(0, min(limit, 20))])

    def catch_up(
        self,
        *,
        scope: Scope,
        anchor: Anchor,
        cursor: str | None,
        authorized_records: Sequence[tuple[str, str]],
        policy_epoch: int,
    ) -> Mapping[str, Any]:
        """Read deterministic committed deltas; unavailable readers fail closed."""

        if self._connect is None:
            return {"available": False, "reason": "durable_event_reader_unavailable"}
        with self._connect() as connection:
            result = catch_up(
                connection,
                scope=scope,
                anchor=anchor,
                cursor=Cursor.decode(cursor, policy_epoch=policy_epoch),
                authorized_records=authorized_records,
                policy_epoch=policy_epoch,
            )
        return {
            "available": True,
            "deltas": [
                {
                    "sequence": item.sequence,
                    "record_type": item.record_type,
                    "record_id": item.record_id,
                    "phrase": item.phrase,
                    "authority_status": item.authority_status,
                    "reference": item.reference,
                    "occurred_at": item.occurred_at,
                }
                for item in result.deltas
            ],
            "cursor": result.cursor.encode(),
            "remaining": result.remaining,
            "policy_changed": result.policy_changed,
        }

    def recall_memory(
        self,
        *,
        scope: Scope,
        authorized_records: Sequence[tuple[str, str]],
        classification_ceiling: str,
        limit: int = 10,
    ) -> tuple[Mapping[str, Any], ...]:
        """Return current source references only, never remembered prose."""

        if self._connect is None:
            return ()
        allowed = set(authorized_records)
        levels = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
        ceiling = levels.get(classification_ceiling, -1)
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT p.id,p.candidate_id,c.source_refs,c.classification
                     FROM solvan.memory_promotions p
                     JOIN solvan.memory_candidates c ON
                       (c.organization_id,c.project_id,c.environment_id,c.id)=
                       (p.organization_id,p.project_id,p.environment_id,p.candidate_id)
                    WHERE p.organization_id=%(organization_id)s
                      AND p.project_id=%(project_id)s
                      AND p.environment_id=%(environment_id)s
                      AND p.decision='PROMOTED' AND p.retention_until > now()
                    ORDER BY p.created_at DESC LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": max(1, min(limit, 10))},
            ).fetchall()
        recalled: list[Mapping[str, Any]] = []
        for promotion_id, candidate_id, source_refs, classification in rows:
            if levels.get(str(classification), 99) > ceiling:
                continue
            references = _authorized_source_refs(source_refs, allowed)
            if references:
                recalled.append(
                    {
                        "promotion_id": str(promotion_id),
                        "candidate_id": str(candidate_id),
                        "source_refs": references,
                        "historical_hint_only": True,
                    }
                )
        return tuple(recalled)

    def recall_conversation(
        self,
        *,
        scope: Scope,
        anchor: Anchor,
        reader_principal: str,
        authorized_records: Sequence[tuple[str, str]],
        limit: int = 20,
        page_token: str | None = None,
    ) -> tuple[Mapping[str, Any], ...]:
        """Return typed references to earlier visible parts, never their text.

        Conversation recall is a fresh SQL projection, not a second memory
        store.  It is intentionally bounded and re-applies the same per-part
        reader filter used by transcript replay.
        """

        del page_token
        if self._connect is None:
            return ()
        payload = anchor.canonical_dict()
        with self._connect() as connection:
            store = LiaisonStore(connection)
            if anchor.kind is AnchorKind.SCOPE:
                rows = connection.execute(
                    """SELECT id FROM solvan_liaison.liaison_threads
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND anchor_kind='SCOPE' ORDER BY last_activity_at DESC,id
                        LIMIT %(limit)s""",
                    {**scope.canonical_dict(), "limit": max(1, min(limit, 20))},
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT id FROM solvan_liaison.liaison_threads
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND anchor_kind=%(anchor_kind)s
                          AND anchor_record_type=%(anchor_record_type)s
                          AND anchor_record_id=%(anchor_record_id)s
                        ORDER BY last_activity_at DESC,id
                        LIMIT %(limit)s""",
                    {
                        **scope.canonical_dict(),
                        **payload,
                        "limit": max(1, min(limit, 20)),
                    },
                ).fetchall()
            recalled: list[Mapping[str, Any]] = []
            for row in rows:
                thread_id = str(row[0])
                if reader_principal not in store.participants(scope=scope, thread_id=thread_id):
                    continue
                for message in store.transcript(
                    scope=scope,
                    thread_id=thread_id,
                    reader_principal=reader_principal,
                    authorized_records=authorized_records,
                    limit=20,
                ):
                    for part in message.parts:
                        if part.kind.value == "WITHHELD":
                            continue
                        recalled.append(
                            {
                                "thread_id": thread_id,
                                "message_id": message.id,
                                "part_sequence": part.sequence,
                                "part_kind": part.kind.value,
                                "reference": f"liaison-part:{message.id}:{part.sequence}",
                            }
                        )
                        if len(recalled) >= max(1, min(limit, 20)):
                            return tuple(recalled)
        return tuple(recalled)


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _authorized_source_refs(
    source_refs: Any, authorized: set[tuple[str, str]]
) -> tuple[Mapping[str, str], ...]:
    values = (
        source_refs
        if isinstance(source_refs, Sequence) and not isinstance(source_refs, str)
        else ()
    )
    result: list[Mapping[str, str]] = []
    for value in values:
        if isinstance(value, Mapping):
            record_type = str(value.get("record_type", ""))
            record_id = str(value.get("record_id", value.get("id", "")))
        elif isinstance(value, str):
            record_type, separator, record_id = value.partition(":")
            if not separator:
                continue
        else:
            continue
        if (record_type, record_id) in authorized:
            result.append({"record_type": record_type, "record_id": record_id})
    return tuple(result)
