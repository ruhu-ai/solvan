"""Durable one-lane turn scheduling and replayable public events.

The database is the scheduler. Provider calls happen only after a READY turn
and immutable input manifest are committed, and every terminal write is fenced
by the exact attempt, generation, and lease token that started the work.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from psycopg import Connection

from solvan.application.liaison.anchors import Anchor, anchor_from_mapping
from solvan.application.liaison.manifest_contract import (
    validate_manifest,
    validate_manifest_freshness,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import (
    bind_provider_input as _bind_provider_input,
)
from solvan.persistence.liaison_manifest import (
    canonical_hash as _canonical_hash,
)
from solvan.persistence.liaison_manifest import (
    compile_manifest as _manifest_material,
)
from solvan.persistence.liaison_manifest import (
    local_context_bindings as _local_context_bindings,
)
from solvan.persistence.liaison_manifest import (
    manifest_hash as _manifest_hash,
)
from solvan.persistence.liaison_manifest import provider_input_from_manifest
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_runtime_failures import fail_invalid_manifest
from solvan.persistence.liaison_store import LiaisonStore
from solvan.persistence.liaison_stream import TurnConflict, append_stream_event


@dataclass(frozen=True, slots=True)
class PreparedTurn:
    thread_id: str
    user_message_id: str
    answer_message_id: str
    attempt: int
    generation: int
    state: str
    queue_sequence: int | None


@dataclass(frozen=True, slots=True)
class TurnClaim:
    thread_id: str
    user_message_id: str
    answer_message_id: str
    attempt: int
    generation: int
    lease_token: str
    principal: str
    question: str
    provider_input: str
    provider_input_digest: str
    provider_request_id: str
    anchor: Anchor
    conversation_intent: str
    authority_route: str
    policy_epoch: int
    resolved_references: tuple[dict[str, Any], ...]
    source_versions: tuple[dict[str, Any], ...]
    scope_sequence_high_water: int


def prepare_turn(
    connection: Connection[Any],
    *,
    scope: Scope,
    principal: str,
    policy_epoch: int,
    thread_id: str,
    user_message_id: str,
    intent: str,
    authority_route: str,
    resolved_references: tuple[dict[str, Any], ...] = (),
    source_versions: tuple[dict[str, Any], ...] = (),
) -> PreparedTurn:
    """Create the answer row, immutable manifest, and ordered lane position."""

    lane = connection.execute(
        """SELECT next_turn_queue_sequence,
                  EXISTS (SELECT 1 FROM solvan_liaison.liaison_turns x
                    WHERE (x.organization_id,x.project_id,x.environment_id,x.thread_id)=
                          (t.organization_id,t.project_id,t.environment_id,t.id)
                      AND x.status IN ('READY','RUNNING')) AS occupied
             FROM solvan_liaison.liaison_threads t
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(thread_id)s
            FOR UPDATE""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchone()
    if lane is None:
        raise TurnConflict("thread disappeared before turn submission")
    occupied = bool(lane[1])
    state = "QUEUED" if occupied else "READY"
    queue_sequence = int(lane[0]) if occupied else None
    if occupied:
        connection.execute(
            """UPDATE solvan_liaison.liaison_threads
                  SET next_turn_queue_sequence=next_turn_queue_sequence+1
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(thread_id)s""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        )

    store = LiaisonStore(connection)
    answer_message_id = store.append_message(
        scope=scope,
        thread_id=thread_id,
        role="LIAISON",
        classification="INTERNAL",
        in_reply_to=user_message_id,
        turn_state=state,
    )
    manifest, membership_epoch, placement = _manifest_material(
        connection,
        scope=scope,
        thread_id=thread_id,
        user_message_id=user_message_id,
        answer_message_id=answer_message_id,
        intent=intent,
        authority_route=authority_route,
        resolved_references=resolved_references,
        source_versions=source_versions,
        reader_principal=principal,
    )
    manifest["reader_principal"] = principal
    read_grant_id = new_identifier("grt")
    allowed_projection_methods = ["read_projection", "recall_conversation"]
    grant_material = {
        "grant_id": read_grant_id,
        "principal": principal,
        "message_id": answer_message_id,
        "attempt": 1,
        "generation": 1,
        "purpose": "incident-investigation",
        "classification_ceiling": placement["classification_ceiling"],
        "membership_epoch": membership_epoch,
        "policy_epoch": policy_epoch,
        "audience": "PROJECTION_API",
        "allowed_projection_methods": allowed_projection_methods,
    }
    read_grant_digest = _canonical_hash(grant_material)
    read_grant_request_hash = _canonical_hash(
        {"thread_id": thread_id, "message_id": answer_message_id, "attempt": 1}
    )
    manifest["working_context"]["read_grant_digest"] = read_grant_digest
    question_row = connection.execute(
        """SELECT payload_json #>> '{sentence}'
             FROM solvan_liaison.liaison_message_parts
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND sequence=0 AND kind='text'""",
        {**scope.canonical_dict(), "message_id": user_message_id},
    ).fetchone()
    if question_row is None:
        raise TurnConflict("turn input lost its exact current-user part")
    question = str(question_row[0] or "")
    _bind_provider_input(manifest, question)
    placement["variable_suffix_digest"] = manifest["working_context"]["variable_suffix_digest"]
    placement["context_digest"] = manifest["working_context"]["context_digest"]
    manifest_hash = _manifest_hash(manifest, policy_epoch, membership_epoch)
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_turns (
              organization_id,project_id,environment_id,message_id,thread_id,request_hash,
              conversation_intent,authority_route,attempt,generation,queue_sequence,queued_at,status)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
              %(thread_id)s,%(request_hash)s,%(intent)s,%(authority_route)s,1,1,
              %(queue_sequence)s::bigint,
              CASE WHEN %(queue_sequence)s::bigint IS NULL THEN NULL ELSE now() END,
              %(state)s)""",
        {
            **scope.canonical_dict(),
            "message_id": answer_message_id,
            "thread_id": thread_id,
            "request_hash": manifest_hash,
            "intent": intent,
            "authority_route": authority_route,
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
              1,1,'incident-investigation',%(classification_ceiling)s,
              %(membership_epoch)s,'PROJECTION_API',%(allowed_methods)s,
              %(grant_digest)s,%(grant_request_hash)s,%(policy_epoch)s,now(),
              %(expires_at)s,%(audit_ref)s)""",
        {
            **scope.canonical_dict(),
            "grant_id": read_grant_id,
            "principal": principal,
            "thread_id": thread_id,
            "message_id": answer_message_id,
            "policy_epoch": policy_epoch,
            "classification_ceiling": placement["classification_ceiling"],
            "membership_epoch": membership_epoch,
            "allowed_methods": allowed_projection_methods,
            "grant_digest": read_grant_digest,
            "grant_request_hash": read_grant_request_hash,
            "expires_at": placement["expires_at"],
            "audit_ref": f"manifest:{manifest_hash}",
        },
    )
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_turn_input_manifests (
              organization_id,project_id,environment_id,message_id,attempt,generation,
              schema_version,
              manifest_json,manifest_hash,reader_principal,read_grant_id,compiler_version,
              compiler_binding_epoch,compiler_digest,tokenizer_digest,model_resource,
              template_registry_digest,tool_registry_digest,read_grant_digest,
              stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,
              placement_epoch,purpose,classification_ceiling,region,policy_epoch,
              membership_epoch,scope_sequence_high_water,expires_at)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
              1,1,2,%(manifest)s::jsonb,%(manifest_hash)s,%(principal)s,%(read_grant_id)s,
              %(compiler_version)s,%(compiler_binding_epoch)s,%(compiler_digest)s,
              %(tokenizer_digest)s,%(model_resource)s,%(template_registry_digest)s,
              %(tool_registry_digest)s,%(read_grant_digest)s,%(stable_prefix_digest)s,
              %(variable_suffix_digest)s,%(context_digest)s,%(cell_id)s,%(placement_epoch)s,
              'incident-investigation',%(classification_ceiling)s,%(region)s,%(policy_epoch)s,
              %(membership_epoch)s,%(scope_sequence_high_water)s,%(expires_at)s)""",
        {
            **scope.canonical_dict(),
            "message_id": answer_message_id,
            "manifest": json.dumps(manifest, sort_keys=True, default=str),
            "manifest_hash": manifest_hash,
            "principal": principal,
            "read_grant_id": read_grant_id,
            "read_grant_digest": read_grant_digest,
            **placement,
            "policy_epoch": policy_epoch,
            "membership_epoch": membership_epoch,
        },
    )
    for source in source_versions:
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_manifest_sources (
                  organization_id,project_id,environment_id,message_id,attempt,
                  record_type,record_id,source_version,source_digest,access_verdict_ref)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,1,
                  %(record_type)s,%(record_id)s,%(version)s,%(digest)s,%(access_verdict_ref)s)""",
            {
                **scope.canonical_dict(),
                "message_id": answer_message_id,
                **source,
                "access_verdict_ref": f"grant:{read_grant_id}",
            },
        )
    if state == "QUEUED":
        append_stream_event(
            connection,
            scope=scope,
            thread_id=thread_id,
            event_type="turn.queued",
            message_id=answer_message_id,
            attempt=1,
            generation=1,
            payload={"state": state, "queue_sequence": queue_sequence},
        )
    return PreparedTurn(thread_id, user_message_id, answer_message_id, 1, 1, state, queue_sequence)


def claim_ready_turn(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    owner: str,
    service_revision: str,
    process_boot_id: str,
) -> TurnClaim | None:
    """Claim the committed READY attempt after validating its exact manifest."""

    row = connection.execute(
        """SELECT x.message_id,x.attempt,x.generation,x.request_hash,
                  x.conversation_intent,x.authority_route,manifest.manifest_json,
                  manifest.manifest_hash,manifest.policy_epoch,manifest.membership_epoch,
                  u.id,u.author_principal,p.payload_json,t.*
             FROM solvan_liaison.liaison_turns x
             JOIN solvan_liaison.liaison_turn_input_manifests manifest ON
               (manifest.organization_id,manifest.project_id,manifest.environment_id,
                manifest.message_id,manifest.attempt)=
               (x.organization_id,x.project_id,x.environment_id,x.message_id,x.attempt)
             JOIN solvan_liaison.liaison_messages a ON
               (a.organization_id,a.project_id,a.environment_id,a.id)=
               (x.organization_id,x.project_id,x.environment_id,x.message_id)
             JOIN solvan_liaison.liaison_messages u ON
               (u.organization_id,u.project_id,u.environment_id,u.id)=
               (a.organization_id,a.project_id,a.environment_id,a.in_reply_to_message_id)
             JOIN solvan_liaison.liaison_message_parts p ON
               (p.organization_id,p.project_id,p.environment_id,p.message_id)=
               (u.organization_id,u.project_id,u.environment_id,u.id)
              AND p.sequence=0 AND p.kind='text'
             JOIN solvan_liaison.liaison_threads t ON
               (t.organization_id,t.project_id,t.environment_id,t.id)=
               (x.organization_id,x.project_id,x.environment_id,x.thread_id)
            WHERE x.organization_id=%(organization_id)s AND x.project_id=%(project_id)s
              AND x.environment_id=%(environment_id)s AND x.thread_id=%(thread_id)s
              AND x.status='READY'
            FOR UPDATE OF x""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchone()
    if row is None:
        return None
    manifest = dict(row[6])
    required = {
        "schema_version",
        "thread_id",
        "liaison_message_id",
        "user_message_id",
        "reader_principal",
        "scope",
        "cell_id",
        "placement_epoch",
        "purpose",
        "classification_ceiling",
        "region",
        "anchor_ref",
        "conversation_intent",
        "authority_route",
        "resolved_references",
        "source_versions",
        "scope_sequence_high_water",
        "working_context",
    }
    expected = _manifest_hash(manifest, int(row[8]), int(row[9]))
    if set(manifest) != required or row[3] != row[7] or row[7] != expected:
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    current_epoch = connection.execute(
        """SELECT membership_epoch FROM solvan_liaison.liaison_thread_participants
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
              AND principal=%(principal)s AND removed_at IS NULL""",
        {
            **scope.canonical_dict(),
            "thread_id": thread_id,
            "principal": str(row[11]),
        },
    ).fetchone()
    if current_epoch is None or int(current_epoch[0]) != int(row[9]):
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    if current_policy_epoch(connection, scope=scope, principal=str(row[11])) != int(row[8]):
        from solvan.persistence.liaison_turn_control import interrupt_turn

        interrupt_turn(
            connection,
            scope=scope,
            thread_id=thread_id,
            message_id=str(row[0]),
            attempt=int(row[1]),
            generation=int(row[2]),
            expected_state="READY",
            reason="POLICY_REVOKED",
        )
        return None
    current_placement = connection.execute(
        """SELECT cell_id,placement_epoch,home_region
             FROM solvan_scale.tenant_placements
            WHERE organization_id=%(organization_id)s AND is_current
              AND lifecycle='ACTIVE' FOR KEY SHARE""",
        scope.canonical_dict(),
    ).fetchone()
    if current_placement is None:
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    # The manifest binds the projection high-water mark at compilation.  A
    # committed ledger event after that point may correct, supersede, or
    # purge one of the selected records (or change the anchor graph).  Do not
    # rely on the manifest's own value here: read the current allocator under
    # the same transaction and fail closed before creating a provider request.
    current_high_water_row = connection.execute(
        """SELECT COALESCE(next_sequence - 1, 0)
             FROM solvan_liaison.scope_event_sequences
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
            FOR SHARE""",
        scope.canonical_dict(),
    ).fetchone()
    current_high_water = int(current_high_water_row[0]) if current_high_water_row else 0
    if current_high_water != int(manifest["scope_sequence_high_water"]):
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    compiler = connection.execute(
        """SELECT revision.compiler_version,binding.binding_epoch,
                  revision.compiler_digest,revision.tokenizer_digest
             FROM solvan_liaison.liaison_context_compiler_bindings binding
             JOIN solvan_liaison.liaison_context_compiler_revisions revision
               ON revision.compiler_version=binding.compiler_version
              AND revision.manifest_schema_version=binding.manifest_schema_version
            WHERE binding.binding_key='TURN_INPUT_MANIFEST_V2'
              AND binding.decision='ACTIVATE'
            ORDER BY binding.binding_epoch DESC LIMIT 1"""
    ).fetchone()
    grant = connection.execute(
        """SELECT grant_digest FROM solvan_liaison.liaison_grant_receipts
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s
              AND principal=%(principal)s AND expires_at > now()""",
        {
            **scope.canonical_dict(),
            "message_id": str(row[0]),
            "attempt": int(row[1]),
            "generation": int(row[2]),
            "principal": str(row[11]),
        },
    ).fetchone()
    if compiler is None or grant is None:
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    context_bindings: dict[str, str | int] = {
        "compiler_version": str(compiler[0]),
        "compiler_binding_epoch": int(compiler[1]),
        "compiler_digest": str(compiler[2]),
        "tokenizer_digest": str(compiler[3]),
        "model_resource": "gemini-3.6-flash",
        "read_grant_digest": str(grant[0]),
        **_local_context_bindings(),
    }
    try:
        validate_manifest_freshness(manifest)
        validate_manifest(
            manifest,
            expected_hash=str(row[7]),
            policy_epoch=int(row[8]),
            membership_epoch=int(row[9]),
            expected_scope=(scope.organization_id, scope.project_id, scope.environment_id),
            expected_cell_id=str(current_placement[0]),
            expected_placement_epoch=int(current_placement[1]),
            expected_reader_principal=str(row[11]),
            expected_purpose="incident-investigation",
            expected_region=str(current_placement[2]),
            expected_context_bindings=context_bindings,
            expected_scope_sequence_high_water=int(manifest["scope_sequence_high_water"]),
        )
    except (KeyError, TypeError, ValueError):
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    question = str(dict(row[12]).get("sentence", ""))
    provider_input = provider_input_from_manifest(manifest, question)
    provider_input_digest = f"sha256:{hashlib.sha256(provider_input.encode('utf-8')).hexdigest()}"
    expected_provider_digest = provider_input_digest
    if manifest["working_context"]["context_digest"] != expected_provider_digest:
        fail_invalid_manifest(connection, scope=scope, message_id=str(row[0]))
        return None
    provider_request_id = new_identifier("prq")
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_provider_requests (
              organization_id,project_id,environment_id,id,message_id,attempt,generation,
              manifest_hash,provider_input_digest,provider_input_bytes,model_resource,
              service_revision,process_boot_id,state)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(request_id)s,
              %(message_id)s,%(attempt)s,%(generation)s,%(manifest_hash)s,
              %(provider_input_digest)s,%(provider_input_bytes)s,%(model_resource)s,
              %(service_revision)s,%(process_boot_id)s,'PREPARED')""",
        {
            **scope.canonical_dict(),
            "request_id": provider_request_id,
            "message_id": str(row[0]),
            "attempt": int(row[1]),
            "generation": int(row[2]),
            "manifest_hash": str(row[7]),
            "provider_input_digest": provider_input_digest,
            "provider_input_bytes": len(provider_input.encode("utf-8")),
            "model_resource": str(manifest["working_context"]["model_resource"]),
            "service_revision": service_revision,
            "process_boot_id": process_boot_id,
        },
    )
    claimed = connection.execute(
        """UPDATE solvan_liaison.liaison_turns
              SET status='RUNNING',lease_owner=%(owner)s,lease_token=gen_random_uuid(),
                  lease_expires_at=now()+interval '5 minutes',heartbeat_at=now(),
                  started_at=COALESCE(started_at,now())
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s AND status='READY'
        RETURNING lease_token::text""",
        {
            **scope.canonical_dict(),
            "message_id": str(row[0]),
            "attempt": int(row[1]),
            "generation": int(row[2]),
            "owner": owner,
        },
    ).fetchone()
    if claimed is None:
        return None
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET turn_state='RUNNING'
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": str(row[0])},
    )
    append_stream_event(
        connection,
        scope=scope,
        thread_id=thread_id,
        event_type="turn.started",
        message_id=str(row[0]),
        attempt=int(row[1]),
        generation=int(row[2]),
        payload={
            "state": "RUNNING",
            "activity": "READING_BOUND_PROJECTION",
            "tool_identifier": "read_projection",
            "result_class": "STARTED",
            "timing_ms": 0,
        },
    )
    thread_offset = 13
    thread_columns = [
        item.name
        for item in connection.execute(
            "SELECT * FROM solvan_liaison.liaison_threads LIMIT 0"
        ).description
        or ()
    ]
    thread = dict(zip(thread_columns, row[thread_offset:], strict=True))
    return TurnClaim(
        thread_id=thread_id,
        user_message_id=str(row[10]),
        answer_message_id=str(row[0]),
        attempt=int(row[1]),
        generation=int(row[2]),
        lease_token=str(claimed[0]),
        principal=str(row[11]),
        question=question,
        provider_input=provider_input,
        provider_input_digest=provider_input_digest,
        provider_request_id=provider_request_id,
        anchor=anchor_from_mapping(thread),
        conversation_intent=str(row[4]),
        authority_route=str(row[5]),
        policy_epoch=int(row[8]),
        resolved_references=tuple(dict(item) for item in manifest["resolved_references"]),
        source_versions=tuple(dict(item) for item in manifest["source_versions"]),
        scope_sequence_high_water=int(manifest["scope_sequence_high_water"]),
    )
