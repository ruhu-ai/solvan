"""Create a fresh, fenced Liaison attempt after an input refresh."""

from __future__ import annotations

import json
from typing import Any

from psycopg import Connection

from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import (
    canonical_hash,
    compile_manifest,
    manifest_hash,
)
from solvan.persistence.liaison_runtime import PreparedTurn, TurnClaim
from solvan.persistence.liaison_stream import TurnConflict, append_stream_event


def requeue_fresh_attempt(
    connection: Connection[Any],
    *,
    scope: Scope,
    claim: TurnClaim,
    source_versions: tuple[dict[str, Any], ...],
    resolved_references: tuple[dict[str, Any], ...],
    policy_epoch: int,
) -> PreparedTurn:
    """Terminalize one stale running generation and queue its replacement.

    The old provider request and attempt remain immutable history.  The
    replacement gets a newly compiled manifest and read grant; no streamed
    row or provider session crosses this boundary.
    """

    owned = connection.execute(
        """SELECT status FROM solvan_liaison.liaison_turns
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s
              AND status='RUNNING' AND lease_token=%(lease_token)s::uuid
            FOR UPDATE""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "attempt": claim.attempt,
            "generation": claim.generation,
            "lease_token": claim.lease_token,
        },
    ).fetchone()
    if owned is None:
        raise TurnConflict("stale Liaison attempt no longer owns its lease")

    manifest, membership_epoch, placement = compile_manifest(
        connection,
        scope=scope,
        thread_id=claim.thread_id,
        user_message_id=claim.user_message_id,
        answer_message_id=claim.answer_message_id,
        intent=claim.conversation_intent,
        authority_route=claim.authority_route,
        resolved_references=resolved_references,
        source_versions=source_versions,
        reader_principal=claim.principal,
    )
    manifest["reader_principal"] = claim.principal
    read_grant_id = new_identifier("grt")
    allowed_projection_methods = ["read_projection", "recall_conversation"]
    grant_material = {
        "grant_id": read_grant_id,
        "principal": claim.principal,
        "message_id": claim.answer_message_id,
        "attempt": claim.attempt + 1,
        "generation": claim.generation + 1,
        "purpose": "incident-investigation",
        "classification_ceiling": placement["classification_ceiling"],
        "membership_epoch": membership_epoch,
        "policy_epoch": policy_epoch,
        "audience": "PROJECTION_API",
        "allowed_projection_methods": allowed_projection_methods,
    }
    read_grant_digest = canonical_hash(grant_material)
    manifest["working_context"]["read_grant_digest"] = read_grant_digest
    # compile_manifest has already bound the exact current-user bytes; update
    # the hashes after adding the fresh grant digest.
    from solvan.persistence.liaison_manifest import bind_provider_input

    bind_provider_input(manifest, claim.question)
    # bind_provider_input derives the variable suffix and context digests from
    # the final manifest.  Keep the scalar columns in lockstep with that
    # immutable JSON envelope before inserting the replacement attempt.
    placement["variable_suffix_digest"] = manifest["working_context"]["variable_suffix_digest"]
    placement["context_digest"] = manifest["working_context"]["context_digest"]
    manifest_hash_value = manifest_hash(manifest, policy_epoch, membership_epoch)
    expires_at = placement["expires_at"]
    new_attempt = claim.attempt + 1
    new_generation = claim.generation + 1

    connection.execute(
        """UPDATE solvan_liaison.liaison_turns
              SET status='INTERRUPTED',terminal_reason='INPUT_REFRESH_REQUIRED',ended_at=now(),
                  lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,heartbeat_at=NULL
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "attempt": claim.attempt,
            "generation": claim.generation,
        },
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_provider_requests
              SET state='FAILED',terminal_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(request_id)s
              AND state='DISPATCHED'""",
        {**scope.canonical_dict(), "request_id": claim.provider_request_id},
    )
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_turns (
              organization_id,project_id,environment_id,message_id,thread_id,request_hash,
              conversation_intent,authority_route,attempt,generation,queue_sequence,queued_at,status)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
              %(thread_id)s,%(request_hash)s,%(intent)s,%(route)s,%(attempt)s,%(generation)s,
              NULL,NULL,'READY')""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "thread_id": claim.thread_id,
            "request_hash": manifest_hash_value,
            "intent": claim.conversation_intent,
            "route": claim.authority_route,
            "attempt": new_attempt,
            "generation": new_generation,
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
              %(attempt)s,%(generation)s,'incident-investigation',%(classification_ceiling)s,
              %(membership_epoch)s,'PROJECTION_API',%(allowed_methods)s,%(grant_digest)s,
              %(request_hash)s,%(policy_epoch)s,now(),%(expires_at)s,%(audit_ref)s)""",
        {
            **scope.canonical_dict(),
            "grant_id": read_grant_id,
            "principal": claim.principal,
            "thread_id": claim.thread_id,
            "message_id": claim.answer_message_id,
            "attempt": new_attempt,
            "generation": new_generation,
            "membership_epoch": membership_epoch,
            "classification_ceiling": placement["classification_ceiling"],
            "allowed_methods": allowed_projection_methods,
            "grant_digest": read_grant_digest,
            "request_hash": canonical_hash(
                {
                    "thread_id": claim.thread_id,
                    "message_id": claim.answer_message_id,
                    "attempt": new_attempt,
                }
            ),
            "policy_epoch": policy_epoch,
            "expires_at": expires_at,
            "audit_ref": f"manifest:{manifest_hash_value}",
        },
    )
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_turn_input_manifests (
              organization_id,project_id,environment_id,message_id,attempt,generation,
              schema_version,manifest_json,manifest_hash,reader_principal,read_grant_id,
              compiler_version,compiler_binding_epoch,compiler_digest,tokenizer_digest,
              model_resource,template_registry_digest,tool_registry_digest,read_grant_digest,
              stable_prefix_digest,variable_suffix_digest,context_digest,cell_id,placement_epoch,
              purpose,classification_ceiling,region,policy_epoch,membership_epoch,
              scope_sequence_high_water,expires_at)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
              %(attempt)s,%(generation)s,2,%(manifest)s::jsonb,%(manifest_hash)s,%(principal)s,
              %(grant_id)s,%(compiler_version)s,%(compiler_binding_epoch)s,%(compiler_digest)s,
              %(tokenizer_digest)s,%(model_resource)s,%(template_registry_digest)s,
              %(tool_registry_digest)s,%(read_grant_digest)s,%(stable_prefix_digest)s,
              %(variable_suffix_digest)s,%(context_digest)s,%(cell_id)s,%(placement_epoch)s,
              'incident-investigation',%(classification_ceiling)s,%(region)s,%(policy_epoch)s,
              %(membership_epoch)s,%(scope_sequence_high_water)s,%(expires_at)s)""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "attempt": new_attempt,
            "generation": new_generation,
            "manifest": json.dumps(manifest, sort_keys=True, default=str),
            "manifest_hash": manifest_hash_value,
            "principal": claim.principal,
            "grant_id": read_grant_id,
            "compiler_version": placement["compiler_version"],
            "compiler_binding_epoch": placement["compiler_binding_epoch"],
            "compiler_digest": placement["compiler_digest"],
            "tokenizer_digest": placement["tokenizer_digest"],
            "model_resource": placement["model_resource"],
            "template_registry_digest": placement["template_registry_digest"],
            "tool_registry_digest": placement["tool_registry_digest"],
            "read_grant_digest": read_grant_digest,
            "stable_prefix_digest": placement["stable_prefix_digest"],
            "variable_suffix_digest": placement["variable_suffix_digest"],
            "context_digest": placement["context_digest"],
            "cell_id": placement["cell_id"],
            "placement_epoch": placement["placement_epoch"],
            "classification_ceiling": placement["classification_ceiling"],
            "region": placement["region"],
            "policy_epoch": policy_epoch,
            "membership_epoch": membership_epoch,
            # The manifest compiler reads the current scope sequence.  The
            # placement row's value is a separate placement-local counter and
            # must not be used to populate the manifest's scope fence.
            "scope_sequence_high_water": manifest["scope_sequence_high_water"],
            "expires_at": expires_at,
        },
    )
    for source in source_versions:
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_manifest_sources (
                  organization_id,project_id,environment_id,message_id,attempt,record_type,
                  record_id,source_version,source_digest,access_verdict_ref)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
                  %(attempt)s,%(record_type)s,%(record_id)s,%(version)s,%(digest)s,%(access)s)""",
            {
                **scope.canonical_dict(),
                "message_id": claim.answer_message_id,
                "attempt": new_attempt,
                **source,
                "access": f"grant:{read_grant_id}",
            },
        )
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages
              SET turn_state='READY',completed_at=NULL
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": claim.answer_message_id},
    )
    append_stream_event(
        connection,
        scope=scope,
        thread_id=claim.thread_id,
        event_type="turn.interrupted",
        message_id=claim.answer_message_id,
        attempt=claim.attempt,
        generation=claim.generation,
        payload={"state": "INTERRUPTED", "terminal_reason": "INPUT_REFRESH_REQUIRED"},
    )
    append_stream_event(
        connection,
        scope=scope,
        thread_id=claim.thread_id,
        event_type="turn.activity",
        message_id=claim.answer_message_id,
        attempt=new_attempt,
        generation=new_generation,
        payload={"state": "READY", "activity": "fresh attempt compiled after input refresh"},
    )
    return PreparedTurn(
        claim.thread_id,
        claim.user_message_id,
        claim.answer_message_id,
        new_attempt,
        new_generation,
        "READY",
        None,
    )
