"""Fenced turn resumption, interruption, promotion, and event replay."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import bind_provider_input as _bind_provider_input
from solvan.persistence.liaison_manifest import canonical_hash as _canonical_hash
from solvan.persistence.liaison_manifest import manifest_hash as _manifest_hash
from solvan.persistence.liaison_runtime import PreparedTurn
from solvan.persistence.liaison_stream import StreamEvent, TurnConflict, append_stream_event


def resume_answered_parked_turn(
    connection: Connection[Any], *, scope: Scope, request_id: str
) -> PreparedTurn | None:
    """Resume one accepted QUESTION as a fresh attempt at the lane tail.

    The parked attempt is immutable history. Its answer is referenced by hash
    from a new manifest; it is never copied into the authorization context.
    """

    row = connection.execute(
        """SELECT p.thread_id,p.message_id,p.decided_payload_hash,p.answer_json,
                  x.attempt,x.generation,x.request_hash,x.conversation_intent,
                  x.authority_route,m.manifest_json,m.policy_epoch,m.membership_epoch,
                  a.in_reply_to_message_id,q.payload_json
             FROM solvan_liaison.liaison_parked_requests p
             JOIN solvan_liaison.liaison_turns x ON
               (x.organization_id,x.project_id,x.environment_id,x.message_id)=
               (p.organization_id,p.project_id,p.environment_id,p.message_id)
              AND x.status='PARKED'
             JOIN solvan_liaison.liaison_turn_input_manifests m ON
               (m.organization_id,m.project_id,m.environment_id,m.message_id,m.attempt)=
               (x.organization_id,x.project_id,x.environment_id,x.message_id,x.attempt)
             JOIN solvan_liaison.liaison_messages a ON
               (a.organization_id,a.project_id,a.environment_id,a.id)=
               (x.organization_id,x.project_id,x.environment_id,x.message_id)
             JOIN solvan_liaison.liaison_message_parts q ON
               (q.organization_id,q.project_id,q.environment_id,q.message_id)=
               (a.organization_id,a.project_id,a.environment_id,a.in_reply_to_message_id)
              AND q.sequence=0 AND q.kind='text'
            WHERE p.organization_id=%(organization_id)s AND p.project_id=%(project_id)s
              AND p.environment_id=%(environment_id)s AND p.id=%(request_id)s
              AND p.kind='QUESTION' AND p.status='ANSWERED'
            FOR UPDATE OF p,x""",
        {**scope.canonical_dict(), "request_id": request_id},
    ).fetchone()
    if row is None:
        return None
    thread_id = str(row[0])
    message_id = str(row[1])
    old_attempt = int(row[4])
    old_generation = int(row[5])
    manifest = dict(row[9])
    answer_material = dict(row[3] or {})
    answer_hash = _canonical_hash(answer_material)
    decision_hash = str(row[2] or "")
    references = list(manifest.get("resolved_references", []))
    references.append(
        {
            "kind": "MESSAGE",
            "ref": f"parked-answer:{request_id}:{answer_hash}:{decision_hash}",
        }
    )
    manifest["resolved_references"] = references
    reader_principal = str(manifest["reader_principal"])
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    read_grant_id = new_identifier("grt")
    new_attempt = old_attempt + 1
    new_generation = old_generation + 1
    allowed_projection_methods = ["read_projection", "recall_conversation"]
    grant_material = {
        "grant_id": read_grant_id,
        "principal": reader_principal,
        "message_id": message_id,
        "attempt": new_attempt,
        "generation": new_generation,
        "purpose": manifest["purpose"],
        "classification_ceiling": manifest["classification_ceiling"],
        "membership_epoch": int(row[11]),
        "policy_epoch": int(row[10]),
        "audience": "PROJECTION_API",
        "allowed_projection_methods": allowed_projection_methods,
    }
    read_grant_digest = _canonical_hash(grant_material)
    read_grant_request_hash = _canonical_hash(
        {"thread_id": thread_id, "message_id": message_id, "attempt": new_attempt}
    )
    manifest["working_context"]["compiled_at"] = datetime.now(UTC).isoformat()
    manifest["working_context"]["expires_at"] = expires_at.isoformat()
    manifest["working_context"]["read_grant_digest"] = read_grant_digest

    lane = connection.execute(
        """SELECT next_turn_queue_sequence,
                  EXISTS (SELECT 1 FROM solvan_liaison.liaison_turns y
                    WHERE (y.organization_id,y.project_id,y.environment_id,y.thread_id)=
                          (t.organization_id,t.project_id,t.environment_id,t.id)
                      AND y.status IN ('READY','RUNNING'))
             FROM solvan_liaison.liaison_threads t
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(thread_id)s FOR UPDATE""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchone()
    if lane is None:
        raise TurnConflict("thread disappeared while resuming a parked turn")
    state = "QUEUED" if bool(lane[1]) else "READY"
    queue_sequence = int(lane[0]) if state == "QUEUED" else None
    if queue_sequence is not None:
        connection.execute(
            """UPDATE solvan_liaison.liaison_threads
                  SET next_turn_queue_sequence=next_turn_queue_sequence+1
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(thread_id)s""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        )

    compiler = connection.execute(
        """SELECT binding.decision,revision.compiler_version,binding.binding_epoch,
                  revision.compiler_digest,revision.tokenizer_digest
             FROM solvan_liaison.liaison_context_compiler_bindings binding
             LEFT JOIN solvan_liaison.liaison_context_compiler_revisions revision
               ON revision.compiler_version=binding.compiler_version
              AND revision.manifest_schema_version=binding.manifest_schema_version
            WHERE binding.binding_key='TURN_INPUT_MANIFEST_V2'
            ORDER BY binding.binding_epoch DESC LIMIT 1"""
    ).fetchone()
    if compiler is None or str(compiler[0]) != "ACTIVATE" or compiler[1] is None:
        raise TurnConflict("no active Liaison context compiler revision")
    manifest["working_context"]["compiler_version"] = str(compiler[1])
    manifest["working_context"]["compiler_binding_epoch"] = int(compiler[2])
    manifest["working_context"]["compiler_digest"] = str(compiler[3])
    manifest["working_context"]["tokenizer_digest"] = str(compiler[4])
    _bind_provider_input(manifest, str(dict(row[13]).get("sentence", "")))

    connection.execute(
        """UPDATE solvan_liaison.liaison_turns
              SET status='COMPLETED',terminal_reason='PARKED_ANSWER_ACCEPTED',ended_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s AND status='PARKED'""",
        {
            **scope.canonical_dict(),
            "message_id": message_id,
            "attempt": old_attempt,
            "generation": old_generation,
        },
    )
    manifest_hash = _manifest_hash(manifest, int(row[10]), int(row[11]))
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_turns (
              organization_id,project_id,environment_id,message_id,thread_id,request_hash,
              conversation_intent,authority_route,attempt,generation,queue_sequence,queued_at,status)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
              %(thread_id)s,%(request_hash)s,%(intent)s,%(route)s,%(attempt)s,%(generation)s,
              %(queue_sequence)s::bigint,
              CASE WHEN %(queue_sequence)s::bigint IS NULL THEN NULL ELSE now() END,%(state)s)""",
        {
            **scope.canonical_dict(),
            "message_id": message_id,
            "thread_id": thread_id,
            "request_hash": manifest_hash,
            "intent": str(row[7]),
            "route": str(row[8]),
            "attempt": new_attempt,
            "generation": new_generation,
            "queue_sequence": queue_sequence,
            "state": state,
        },
    )
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_grant_receipts (
              organization_id,project_id,environment_id,id,grant_kind,principal,
              thread_id,message_id,attempt,generation,purpose,classification_ceiling,
              membership_epoch,audience,allowed_projection_methods,grant_digest,
              request_hash,policy_epoch,issued_at,expires_at,audit_ref)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(grant_id)s,
              'CONVERSATION_READ',%(principal)s,%(thread_id)s,%(message_id)s,
              %(attempt)s,%(generation)s,%(purpose)s,%(classification_ceiling)s,
              %(membership_epoch)s,'PROJECTION_API',%(allowed_methods)s,
              %(grant_digest)s,%(grant_request_hash)s,%(policy_epoch)s,now(),
              %(expires_at)s,%(audit_ref)s)""",
        {
            **scope.canonical_dict(),
            "grant_id": read_grant_id,
            "principal": reader_principal,
            "thread_id": thread_id,
            "message_id": message_id,
            "attempt": new_attempt,
            "generation": new_generation,
            "purpose": manifest["purpose"],
            "classification_ceiling": manifest["classification_ceiling"],
            "membership_epoch": int(row[11]),
            "allowed_methods": allowed_projection_methods,
            "grant_digest": read_grant_digest,
            "grant_request_hash": read_grant_request_hash,
            "policy_epoch": int(row[10]),
            "expires_at": expires_at,
            "audit_ref": f"manifest:{manifest_hash}",
        },
    )
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_turn_input_manifests (
              organization_id,project_id,environment_id,message_id,attempt,generation,schema_version,
              manifest_json,manifest_hash,reader_principal,read_grant_id,compiler_version,
              compiler_binding_epoch,compiler_digest,tokenizer_digest,model_resource,
              template_registry_digest,tool_registry_digest,read_grant_digest,
              stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,
              placement_epoch,purpose,classification_ceiling,region,policy_epoch,
              membership_epoch,scope_sequence_high_water,expires_at)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
              %(attempt)s,%(generation)s,2,%(manifest)s::jsonb,%(manifest_hash)s,
              %(principal)s,%(grant_id)s,%(compiler_version)s,%(compiler_binding_epoch)s,
              %(compiler_digest)s,%(tokenizer_digest)s,%(model_resource)s,
              %(template_registry_digest)s,%(tool_registry_digest)s,%(read_grant_digest)s,
              %(stable_prefix_digest)s,%(variable_suffix_digest)s,%(context_digest)s,
              %(cell_id)s,%(placement_epoch)s,
              %(purpose)s,%(classification_ceiling)s,%(region)s,%(policy_epoch)s,
              %(membership_epoch)s,%(scope_sequence_high_water)s,%(expires_at)s)""",
        {
            **scope.canonical_dict(),
            "message_id": message_id,
            "attempt": new_attempt,
            "generation": new_generation,
            "manifest": json.dumps(manifest, sort_keys=True, default=str),
            "manifest_hash": manifest_hash,
            "principal": reader_principal,
            "grant_id": read_grant_id,
            "compiler_version": manifest["working_context"]["compiler_version"],
            "compiler_binding_epoch": int(compiler[2]),
            "compiler_digest": str(compiler[3]),
            "tokenizer_digest": str(compiler[4]),
            "model_resource": manifest["working_context"]["model_resource"],
            "template_registry_digest": manifest["working_context"]["template_registry_digest"],
            "tool_registry_digest": manifest["working_context"]["tool_registry_digest"],
            "read_grant_digest": read_grant_digest,
            "stable_prefix_digest": manifest["working_context"]["stable_prefix_digest"],
            "variable_suffix_digest": manifest["working_context"]["variable_suffix_digest"],
            "context_digest": manifest["working_context"]["context_digest"],
            "cell_id": manifest["cell_id"],
            "placement_epoch": manifest["placement_epoch"],
            "purpose": manifest["purpose"],
            "classification_ceiling": manifest["classification_ceiling"],
            "region": manifest["region"],
            "policy_epoch": int(row[10]),
            "membership_epoch": int(row[11]),
            "scope_sequence_high_water": int(manifest["scope_sequence_high_water"]),
            "expires_at": expires_at,
        },
    )
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_manifest_sources (
              organization_id,project_id,environment_id,message_id,attempt,
              record_type,record_id,source_version,source_digest,access_verdict_ref)
           SELECT organization_id,project_id,environment_id,message_id,%(new_attempt)s,
                  record_type,record_id,source_version,source_digest,%(access_verdict_ref)s
             FROM solvan_liaison.liaison_manifest_sources
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(old_attempt)s""",
        {
            **scope.canonical_dict(),
            "message_id": message_id,
            "new_attempt": new_attempt,
            "old_attempt": old_attempt,
            "access_verdict_ref": f"grant:{read_grant_id}",
        },
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET turn_state=%(state)s,completed_at=NULL
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id, "state": state},
    )
    append_stream_event(
        connection,
        scope=scope,
        thread_id=thread_id,
        event_type="turn.queued" if state == "QUEUED" else "turn.activity",
        message_id=message_id,
        attempt=new_attempt,
        generation=new_generation,
        payload={"state": state, "activity": "clarification accepted"},
    )
    return PreparedTurn(
        thread_id,
        str(row[12]),
        message_id,
        new_attempt,
        new_generation,
        state,
        queue_sequence,
    )


def reject_parked_turn(
    connection: Connection[Any], *, scope: Scope, request_id: str
) -> tuple[str, str] | None:
    """Close one rejected/expired QUESTION without touching a newer attempt."""

    row = connection.execute(
        """SELECT p.thread_id,p.message_id,x.attempt,x.generation,p.status
             FROM solvan_liaison.liaison_parked_requests p
             JOIN solvan_liaison.liaison_turns x ON
               (x.organization_id,x.project_id,x.environment_id,x.message_id)=
               (p.organization_id,p.project_id,p.environment_id,p.message_id)
              AND x.status='PARKED'
            WHERE p.organization_id=%(organization_id)s AND p.project_id=%(project_id)s
              AND p.environment_id=%(environment_id)s AND p.id=%(request_id)s
              AND p.kind='QUESTION' AND p.status IN ('REJECTED','EXPIRED')
            FOR UPDATE OF x""",
        {**scope.canonical_dict(), "request_id": request_id},
    ).fetchone()
    if row is None:
        return None
    reason = "PARKED_EXPIRED" if str(row[4]) == "EXPIRED" else "PARKED_REJECTED"
    interrupt_turn(
        connection,
        scope=scope,
        thread_id=str(row[0]),
        message_id=str(row[1]),
        attempt=int(row[2]),
        generation=int(row[3]),
        expected_state="PARKED",
        reason=reason,
    )
    return str(row[0]), str(row[1])


def promote_next_turn(connection: Connection[Any], *, scope: Scope, thread_id: str) -> str | None:
    """Move the oldest queued turn into the sole READY lane."""

    occupied = connection.execute(
        """SELECT 1 FROM solvan_liaison.liaison_turns
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
              AND status IN ('READY','RUNNING') LIMIT 1""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchone()
    if occupied is not None:
        return None
    row = connection.execute(
        """SELECT message_id FROM solvan_liaison.liaison_turns
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
              AND status='QUEUED' ORDER BY queue_sequence LIMIT 1 FOR UPDATE""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchone()
    if row is None:
        return None
    message_id = str(row[0])
    connection.execute(
        """UPDATE solvan_liaison.liaison_turns SET status='READY'
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND status='QUEUED'""",
        {**scope.canonical_dict(), "message_id": message_id},
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET turn_state='READY'
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id},
    )
    # The read grant bounds the window in which a turn may run, not the time it
    # spent waiting behind another turn. It was minted at prepare time with the
    # same five-minute lifetime as the RUNNING lease, so a turn queued behind a
    # full-lease turn became READY exactly as its grant died and was failed as
    # MANIFEST_INVALID rather than answered.
    #
    # Receipts are immutable, so the working window restarts by superseding: a
    # new receipt copies the grant material unchanged and carries a fresh
    # window. Principal, scope, audience, allowed methods and both epochs are
    # copied verbatim, so this renews time and widens nothing; epoch and
    # freshness drift are still caught by the claim fences.
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_grant_receipts (
              organization_id,project_id,environment_id,id,grant_kind,principal,
              thread_id,message_id,attempt,generation,purpose,classification_ceiling,
              membership_epoch,audience,allowed_projection_methods,grant_digest,
              request_hash,policy_epoch,issued_at,expires_at,audit_ref)
           SELECT organization_id,project_id,environment_id,%(renewal_id)s,grant_kind,principal,
              thread_id,message_id,attempt,generation,purpose,classification_ceiling,
              membership_epoch,audience,allowed_projection_methods,grant_digest,
              request_hash,policy_epoch,now(),now() + interval '5 minutes',audit_ref
             FROM solvan_liaison.liaison_grant_receipts
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND grant_kind='CONVERSATION_READ'
            ORDER BY issued_at DESC LIMIT 1""",
        {
            **scope.canonical_dict(),
            "message_id": message_id,
            "renewal_id": new_identifier("grt"),
        },
    )
    return message_id


def interrupt_turn(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    message_id: str,
    attempt: int,
    generation: int,
    expected_state: str,
    reason: str,
    promote: bool = True,
) -> bool:
    """Interrupt exactly one queued or running generation by CAS."""

    row = connection.execute(
        """UPDATE solvan_liaison.liaison_turns SET status='INTERRUPTED',
              terminal_reason=%(reason)s,ended_at=now(),lease_owner=NULL,lease_token=NULL,
              lease_expires_at=NULL,heartbeat_at=NULL
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
              AND message_id=%(message_id)s AND attempt=%(attempt)s
              AND generation=%(generation)s AND status=%(expected_state)s
        RETURNING message_id""",
        {
            **scope.canonical_dict(),
            "thread_id": thread_id,
            "message_id": message_id,
            "attempt": attempt,
            "generation": generation,
            "expected_state": expected_state,
            "reason": reason,
        },
    ).fetchone()
    if row is None:
        return False
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET turn_state='INTERRUPTED',completed_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id},
    )
    append_stream_event(
        connection,
        scope=scope,
        thread_id=thread_id,
        event_type="turn.interrupted",
        message_id=message_id,
        attempt=attempt,
        generation=generation,
        payload={"state": "INTERRUPTED", "terminal_reason": reason},
    )
    if promote:
        promote_next_turn(connection, scope=scope, thread_id=thread_id)
    return True


def visible_events(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    principal: str,
    authorized_records: tuple[tuple[str, str], ...],
    after_sequence: int,
    limit: int,
) -> tuple[StreamEvent, ...]:
    """Replay public events through the same current-reader projection gate."""

    active = connection.execute(
        """SELECT membership_epoch FROM solvan_liaison.liaison_thread_participants
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
              AND principal=%(principal)s AND removed_at IS NULL""",
        {**scope.canonical_dict(), "thread_id": thread_id, "principal": principal},
    ).fetchone()
    if active is None:
        return ()
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT * FROM solvan_liaison.liaison_stream_events
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
                  AND stream_sequence > %(after)s
                ORDER BY stream_sequence LIMIT %(limit)s""",
            {
                **scope.canonical_dict(),
                "thread_id": thread_id,
                "after": after_sequence,
                "limit": limit,
            },
        )
        rows = cursor.fetchall()
    authorized = set(authorized_records)
    events: list[StreamEvent] = []
    for row in rows:
        visible = row["access_mode"] == "SYSTEM_PUBLIC"
        if row["access_mode"] == "AUTHOR_ONLY":
            visible = row["audience_principal"] == principal
        elif row["access_mode"] == "RECORD_SET" and row["part_id"]:
            refs = connection.execute(
                """SELECT record_type,record_id FROM solvan_liaison.liaison_part_access
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND part_id=%(part_id)s""",
                {**scope.canonical_dict(), "part_id": row["part_id"]},
            ).fetchall()
            visible = bool(refs) and all(
                (str(item[0]), str(item[1])) in authorized for item in refs
            )
        elif row["access_mode"] == "PARTICIPANTS_AT_EPOCH":
            visible = row["membership_epoch"] is not None and int(active[0]) <= int(
                row["membership_epoch"]
            )
        if visible:
            events.append(
                StreamEvent(
                    sequence=int(row["stream_sequence"]),
                    event_id=str(row["event_id"]),
                    event_type=str(row["event_type"]),
                    message_id=str(row["message_id"]) if row["message_id"] else None,
                    attempt=int(row["attempt"]) if row["attempt"] else None,
                    generation=int(row["generation"]) if row["generation"] else None,
                    payload=dict(row["payload_json"] or {}),
                )
            )
    return tuple(events)
