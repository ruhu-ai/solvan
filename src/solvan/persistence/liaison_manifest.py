"""Compile and hash the immutable Liaison turn-input manifest."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import rfc8785
from psycopg import Connection

from solvan.application.liaison.anchors import anchor_from_mapping
from solvan.application.liaison.context_compiler import (
    CompactionCandidate,
    ContextBudget,
    ReferenceCandidate,
    TranscriptMessage,
    TranscriptPart,
    compile_context,
)
from solvan.domain import Scope
from solvan.persistence.liaison_stream import TurnConflict
from solvan.persistence.liaison_visibility import reader_may_see_row

ROOT = Path(__file__).resolve().parents[3]
LIAISON_TOOL_IDS = (
    "resolve_anchor",
    "read_projection",
    "list_prior_incidents",
    "search_records",
    "catch_up",
    "recall_conversation",
    "recall_memory",
    "ask_principal",
    "steer_draft",
)
STABLE_PREFIX_REVISION = "solvan-liaison-query-planner-v1"
COMPILER_REVISION = "liaison-context-v2-current-user-upper-bound-v1"
TOKEN_ESTIMATOR_REVISION = "utf8-byte-upper-bound-v1"


def canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode()).hexdigest()}"


def _file_hash(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def local_context_bindings() -> dict[str, str]:
    """Return digests for the exact local registries and stable prompt revision."""

    return {
        "compiler_digest": canonical_hash({"revision": COMPILER_REVISION}),
        "tokenizer_digest": canonical_hash({"revision": TOKEN_ESTIMATOR_REVISION}),
        "template_registry_digest": _file_hash(ROOT / "config" / "liaison-claim-templates.yaml"),
        "tool_registry_digest": canonical_hash({"tool_ids": list(LIAISON_TOOL_IDS)}),
        "stable_prefix_digest": canonical_hash({"revision": STABLE_PREFIX_REVISION}),
    }


def provider_input_from_manifest(manifest: dict[str, Any], question: str) -> str:
    """Serialize the exact variable provider input selected by one manifest.

    Context rows carry references and digests rather than duplicating durable
    source content. The current user item is resolved from its exact message
    row; other items remain typed references that provider tools must resolve
    again under the attempt's audience-bound read grant.
    """

    rendered_items: list[dict[str, Any]] = []
    for item in manifest["working_context"]["items"]:
        rendered = dict(item)
        if item["kind"] == "CURRENT_USER":
            rendered["content"] = question
        rendered_items.append(rendered)
    payload = {
        "schema_version": 1,
        "scope": manifest["scope"],
        "cell_id": manifest["cell_id"],
        "placement_epoch": manifest["placement_epoch"],
        "purpose": manifest["purpose"],
        "reader_principal": manifest["reader_principal"],
        "anchor_ref": manifest["anchor_ref"],
        "conversation_intent": manifest["conversation_intent"],
        "authority_route": manifest["authority_route"],
        # The stable instruction/tool envelope is bound by digest only.  Its
        # content is static and registry-derived; tenant transcript content
        # belongs exclusively in the variable suffix below.
        "stable_prefix_digest": manifest["working_context"]["stable_prefix_digest"],
        "stable_prefix_tokens": manifest["working_context"]["token_budget"]["stable_prefix_tokens"],
        "compiler_version": manifest["working_context"]["compiler_version"],
        "template_registry_digest": manifest["working_context"]["template_registry_digest"],
        "tool_registry_digest": manifest["working_context"]["tool_registry_digest"],
        "scope_sequence_high_water": manifest["scope_sequence_high_water"],
        "items": rendered_items,
        "omitted_counts": manifest["working_context"]["omitted_counts"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def bind_provider_input(manifest: dict[str, Any], question: str) -> str:
    """Bind the manifest to the exact bytes later sent to the provider."""

    provider_input = provider_input_from_manifest(manifest, question)
    digest = f"sha256:{hashlib.sha256(provider_input.encode('utf-8')).hexdigest()}"
    manifest["working_context"]["variable_suffix_digest"] = digest
    manifest["working_context"]["context_digest"] = digest
    return provider_input


def manifest_hash(manifest: dict[str, Any], policy_epoch: int, membership_epoch: int) -> str:
    """Hash the exact v2 manifest preimage from specification 14 §12.1."""

    preimage = (
        rfc8785.dumps(manifest)
        + b"\x00"
        + str(policy_epoch).encode("ascii")
        + b"\x00"
        + str(membership_epoch).encode("ascii")
    )
    return f"sha256:{hashlib.sha256(preimage).hexdigest()}"


def compile_manifest(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    user_message_id: str,
    answer_message_id: str,
    intent: str,
    authority_route: str,
    resolved_references: tuple[dict[str, Any], ...],
    source_versions: tuple[dict[str, Any], ...],
    reader_principal: str = "",
) -> tuple[dict[str, Any], int, dict[str, Any]]:
    row = connection.execute(
        """SELECT t.*,p.membership_epoch,
                  COALESCE(s.next_sequence - 1, 0) AS scope_sequence_high_water,
                  m.classification,m.content_hash,mp.payload_json
             FROM solvan_liaison.liaison_threads t
             JOIN solvan_liaison.liaison_messages m ON
               (m.organization_id,m.project_id,m.environment_id,m.thread_id)=
               (t.organization_id,t.project_id,t.environment_id,t.id)
              AND m.id=%(user_message_id)s
             JOIN solvan_liaison.liaison_thread_participants p ON
               (p.organization_id,p.project_id,p.environment_id,p.thread_id)=
               (t.organization_id,t.project_id,t.environment_id,t.id)
              AND p.principal=m.author_principal AND p.removed_at IS NULL
             LEFT JOIN solvan_liaison.scope_event_sequences s ON
               (s.organization_id,s.project_id,s.environment_id)=
               (t.organization_id,t.project_id,t.environment_id)
             JOIN solvan_liaison.liaison_message_parts mp ON
               (mp.organization_id,mp.project_id,mp.environment_id,mp.message_id)=
               (m.organization_id,m.project_id,m.environment_id,m.id)
              AND mp.sequence=0 AND mp.kind='text' AND mp.status='COMPLETED'
            WHERE t.organization_id=%(organization_id)s
              AND t.project_id=%(project_id)s AND t.environment_id=%(environment_id)s
              AND t.id=%(thread_id)s""",
        {
            **scope.canonical_dict(),
            "thread_id": thread_id,
            "user_message_id": user_message_id,
        },
    ).fetchone()
    if row is None:
        raise TurnConflict("turn input cannot be bound to an active participant")
    columns = [
        item.name
        for item in connection.execute(
            "SELECT * FROM solvan_liaison.liaison_threads LIMIT 0"
        ).description
        or ()
    ]
    thread = dict(zip(columns, row[: len(columns)], strict=True))
    anchor = anchor_from_mapping(thread)
    membership_epoch = int(row[len(columns)])
    scope_sequence_high_water = int(row[len(columns) + 1])
    classification = str(row[len(columns) + 2])
    question_digest = str(row[len(columns) + 3] or "")
    question_payload = dict(row[len(columns) + 4])
    if not question_digest.startswith("sha256:"):
        question_digest = canonical_hash(question_payload)

    # Rebuild the prior working view from the canonical ledger.  The provider
    # never receives the transcript body here; only typed turn/compaction
    # references and digests survive compilation.  Visibility is evaluated per
    # part with the same empty-set-denies rule used by transcript reads.
    history: list[TranscriptMessage] = []
    compactions: list[CompactionCandidate] = []
    participant_rows = connection.execute(
        """SELECT principal,membership_epoch
             FROM solvan_liaison.liaison_thread_participants
            WHERE (organization_id,project_id,environment_id,thread_id)=
                  (%(organization_id)s,%(project_id)s,%(environment_id)s,%(thread_id)s)
              AND removed_at IS NULL""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchall()
    participant_epochs = {str(item[0]): int(item[1]) for item in participant_rows}
    authorized_records = {
        (str(item.get("record_type")), str(item.get("record_id")))
        for item in resolved_references
        if item.get("record_type") and item.get("record_id")
    }
    message_rows = connection.execute(
        """SELECT id,role,author_principal,in_reply_to_message_id,classification,
                      turn_state,stream_position
                 FROM solvan_liaison.liaison_messages
                WHERE (organization_id,project_id,environment_id,thread_id)=
                      (%(organization_id)s,%(project_id)s,%(environment_id)s,%(thread_id)s)
                  AND deleted_at IS NULL AND turn_state='COMPLETED'
                  AND id<>%(user_message_id)s
                ORDER BY stream_position""",
        {**scope.canonical_dict(), "thread_id": thread_id, "user_message_id": user_message_id},
    ).fetchall()
    for message_row in message_rows:
        part_rows = connection.execute(
            """SELECT p.id,p.kind,p.classification,p.access_mode,p.author_principal,
                          p.membership_epoch,p.payload_json,
                          coalesce(array_agg(a.record_type || ':' || a.record_id)
                            FILTER (WHERE a.record_type IS NOT NULL),'{}')
                     FROM solvan_liaison.liaison_message_parts p
                     LEFT JOIN solvan_liaison.liaison_part_access a ON
                       (a.organization_id,a.project_id,a.environment_id,a.part_id)=
                       (p.organization_id,p.project_id,p.environment_id,p.id)
                    WHERE (p.organization_id,p.project_id,p.environment_id,p.message_id)=
                          (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s)
                      AND p.status='COMPLETED'
                    GROUP BY p.id,p.kind,p.classification,p.access_mode,p.author_principal,
                             p.membership_epoch,p.payload_json,p.sequence
                    ORDER BY p.sequence""",
            {**scope.canonical_dict(), "message_id": str(message_row[0])},
        ).fetchall()
        parts: list[TranscriptPart] = []
        message_visible = True
        for part_row in part_rows:
            access_mode = str(part_row[3])
            references = {
                tuple(str(value).split(":", 1))
                for value in (part_row[7] or ())
                if ":" in str(value)
            }
            visible = reader_may_see_row(
                access_mode=access_mode,
                author_principal=part_row[4],
                references=references,
                reader_principal=reader_principal,
                authorized=authorized_records,
                participant_epochs=participant_epochs,
                membership_epoch=part_row[5],
            )
            payload = dict(part_row[6] or {})
            text = next(
                (
                    str(payload[key])
                    for key in ("sentence", "text", "summary")
                    if isinstance(payload.get(key), str) and payload[key].strip()
                ),
                "",
            )
            part_digest = canonical_hash(payload)
            parts.append(
                TranscriptPart(
                    id=str(part_row[0]),
                    kind=str(part_row[1]),
                    digest=part_digest,
                    classification=str(part_row[2]),
                    visible=visible,
                    access_verdict_ref=f"part-access:{part_row[0]}",
                    text=text if visible else "",
                )
            )
            message_visible = message_visible and visible
        history.append(
            TranscriptMessage(
                id=str(message_row[0]),
                role=str(message_row[1]),
                turn_state=str(message_row[5]),
                stream_position=int(message_row[6]),
                classification=str(message_row[4]),
                parts=tuple(parts),
                in_reply_to_message_id=(
                    str(message_row[3]) if message_row[3] is not None else None
                ),
                visible=message_visible,
            )
        )
    compaction_rows = connection.execute(
        """SELECT p.id,p.classification,p.payload_json,p.created_at
             FROM solvan_liaison.liaison_message_parts p
             JOIN solvan_liaison.liaison_messages m ON
               (m.organization_id,m.project_id,m.environment_id,m.id)=
               (p.organization_id,p.project_id,p.environment_id,p.message_id)
            WHERE (m.organization_id,m.project_id,m.environment_id,m.thread_id)=
                  (%(organization_id)s,%(project_id)s,%(environment_id)s,%(thread_id)s)
              AND p.kind='compaction' AND p.status='COMPLETED' AND m.deleted_at IS NULL
            ORDER BY p.created_at DESC""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchall()
    for compaction_row in compaction_rows:
        source_rows = connection.execute(
            """SELECT source_message_id
                 FROM solvan_liaison.liaison_compaction_sources
                WHERE (organization_id,project_id,environment_id,compaction_part_id)=
                      (%(organization_id)s,%(project_id)s,%(environment_id)s,%(part_id)s)
                ORDER BY source_message_id""",
            {**scope.canonical_dict(), "part_id": str(compaction_row[0])},
        ).fetchall()
        source_ids = tuple(str(item[0]) for item in source_rows)
        if not source_ids:
            continue
        visible = True
        for source_id in source_ids:
            source_parts = connection.execute(
                """SELECT p.access_mode,p.author_principal,p.membership_epoch,
                              coalesce(array_agg(a.record_type || ':' || a.record_id)
                                FILTER (WHERE a.record_type IS NOT NULL),'{}')
                         FROM solvan_liaison.liaison_message_parts p
                         LEFT JOIN solvan_liaison.liaison_part_access a ON
                           (a.organization_id,a.project_id,a.environment_id,a.part_id)=
                           (p.organization_id,p.project_id,p.environment_id,p.id)
                        WHERE (p.organization_id,p.project_id,p.environment_id,p.message_id)=
                              (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s)
                          AND p.status='COMPLETED'
                        GROUP BY p.id,p.access_mode,p.author_principal,p.membership_epoch""",
                {**scope.canonical_dict(), "message_id": source_id},
            ).fetchall()
            visible = (
                visible
                and bool(source_parts)
                and all(
                    reader_may_see_row(
                        access_mode=str(item[0]),
                        author_principal=item[1],
                        references={
                            tuple(str(value).split(":", 1))
                            for value in (item[3] or ())
                            if ":" in str(value)
                        },
                        reader_principal=reader_principal,
                        authorized=authorized_records,
                        participant_epochs=participant_epochs,
                        membership_epoch=item[2],
                    )
                    for item in source_parts
                )
            )
        payload = dict(compaction_row[2] or {})
        summary = str(payload.get("summary", ""))
        compactions.append(
            CompactionCandidate(
                part_id=str(compaction_row[0]),
                digest=canonical_hash(payload),
                source_message_ids=source_ids,
                classification=str(compaction_row[1]),
                access_verdict_ref=f"compaction-access:{compaction_row[0]}",
                visible=visible,
                token_count=max(1, len(summary.encode("utf-8"))) if summary else 0,
                created_at=compaction_row[3],
            )
        )

    placement = connection.execute(
        """SELECT p.cell_id,p.placement_epoch,p.home_region,p.classification_ceiling
             FROM solvan_scale.tenant_placements p
            WHERE p.organization_id=%(organization_id)s AND p.is_current
              AND p.lifecycle IN ('ACTIVE','SUSPENDING','SUSPENDED','MOVING')""",
        scope.canonical_dict(),
    ).fetchone()
    if placement is None:
        raise TurnConflict("turn input has no current tenant placement")
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
    local_bindings = local_context_bindings()
    if (
        str(compiler[3]) != local_bindings["compiler_digest"]
        or str(compiler[4]) != local_bindings["tokenizer_digest"]
    ):
        raise TurnConflict("active Liaison compiler does not match this service revision")

    sentence = str(question_payload.get("sentence", ""))
    current_user = TranscriptMessage(
        id=user_message_id,
        role="USER",
        turn_state="COMPLETED",
        stream_position=0,
        classification=classification,
        parts=(
            TranscriptPart(
                id=f"part:{user_message_id}",
                kind="text",
                digest=question_digest,
                classification=classification,
                access_verdict_ref=f"message-access:{user_message_id}",
                text=sentence,
            ),
        ),
    )
    typed_references: list[ReferenceCandidate] = []
    allowed_reference_kinds = {
        "MESSAGE",
        "PART",
        "CLAIM_TEMPLATE",
        "SUBJECT",
        "RECORD",
        "ACTION",
        "TIME_WINDOW",
    }
    for value in resolved_references:
        kind = str(value.get("kind", "RECORD"))
        typed_references.append(
            ReferenceCandidate(
                kind=kind if kind in allowed_reference_kinds else "RECORD",
                ref=str(value.get("ref") or value.get("record_id") or "unknown"),
                digest=str(value.get("digest") or canonical_hash(value)),
                classification=str(value.get("classification", classification)),
                access_verdict_ref=str(value.get("access_verdict_ref") or "reference-access"),
                authoritative=bool(value.get("authoritative", True)),
            )
        )
    non_model_intent = intent in {"SOCIAL", "HELP", "OUT_OF_SCOPE", "ACTION_REFERENCE"}
    if non_model_intent:
        compiled = None
        compiled_at = datetime.now(UTC)
        expires_at = compiled_at + timedelta(minutes=5)
        items: list[dict[str, Any]] = []
        actual_context_tokens = 0
    else:
        compiled = compile_context(
            current_user=current_user,
            history=history,
            compactions=compactions,
            references=typed_references,
            source_versions=source_versions,
            classification_ceiling=min(
                (classification, str(placement[3])),
                key=lambda value: ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED").index(value),
            ),
            budget=ContextBudget(),
            # The registry/compiler/model digests are each carried explicitly
            # in the request and manifest.  The stable-prefix digest is the
            # immutable prompt-envelope revision, matching the service binding
            # used by the pre-dispatch semantic checker.
            stable_prefix_material={"revision": STABLE_PREFIX_REVISION},
        )
        compiled_at = compiled.compiled_at
        expires_at = compiled.expires_at
        items = [dict(item) for item in compiled.items]
        actual_context_tokens = compiled.token_budget["actual_context_tokens"]
    manifest: dict[str, Any] = {
        "schema_version": 2,
        "thread_id": thread_id,
        "liaison_message_id": answer_message_id,
        "user_message_id": user_message_id,
        "reader_principal": reader_principal,
        "scope": scope.canonical_dict(),
        "cell_id": str(placement[0]),
        "placement_epoch": int(placement[1]),
        "purpose": "incident-investigation",
        "classification_ceiling": min(
            (classification, str(placement[3])),
            key=lambda value: ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED").index(value),
        ),
        "region": str(placement[2]),
        "anchor_ref": {"kind": str(anchor.kind), "ref": anchor.label()},
        "conversation_intent": intent,
        "authority_route": authority_route,
        "resolved_references": list(resolved_references),
        "source_versions": list(source_versions),
        "scope_sequence_high_water": scope_sequence_high_water,
        "working_context": {
            "compiler_version": str(compiler[1]),
            "compiler_binding_epoch": int(compiler[2]),
            "compiler_digest": str(compiler[3]),
            "tokenizer_digest": str(compiler[4]),
            "model_resource": "gemini-3.6-flash",
            "template_registry_digest": local_bindings["template_registry_digest"],
            "tool_registry_digest": local_bindings["tool_registry_digest"],
            "read_grant_digest": "sha256:" + "0" * 64,
            "stable_prefix_digest": compiled.stable_prefix_digest
            if compiled
            else local_bindings["stable_prefix_digest"],
            "variable_suffix_digest": compiled.variable_suffix_digest
            if compiled
            else "sha256:" + "0" * 64,
            "context_digest": compiled.context_digest if compiled else "sha256:" + "0" * 64,
            "compiled_at": compiled_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "token_budget": dict(compiled.token_budget)
            if compiled
            else {
                "model_input_limit": 1_000_000,
                "stable_prefix_tokens": 0,
                "reserved_output_tokens": 8_192,
                "safety_margin_tokens": 8_192,
                "dynamic_context_ceiling": 983_616,
                "actual_context_tokens": actual_context_tokens,
            },
            "items": items,
            "omitted_counts": dict(compiled.omitted_counts)
            if compiled
            else {
                "expired_or_purged": 0,
                "superseded": 0,
                "budget": 0,
                "context_reduced_by_policy": False,
            },
        },
    }
    placement_material = {
        "cell_id": str(placement[0]),
        "placement_epoch": int(placement[1]),
        "region": str(placement[2]),
        "classification_ceiling": manifest["classification_ceiling"],
        "compiler_version": str(compiler[1]),
        "compiler_binding_epoch": int(compiler[2]),
        "compiler_digest": str(compiler[3]),
        "tokenizer_digest": str(compiler[4]),
        "model_resource": manifest["working_context"]["model_resource"],
        "template_registry_digest": manifest["working_context"]["template_registry_digest"],
        "tool_registry_digest": manifest["working_context"]["tool_registry_digest"],
        "stable_prefix_digest": manifest["working_context"]["stable_prefix_digest"],
        "variable_suffix_digest": manifest["working_context"]["variable_suffix_digest"],
        "scope_sequence_high_water": scope_sequence_high_water,
        "context_digest": manifest["working_context"]["context_digest"],
        "expires_at": expires_at,
    }
    return manifest, membership_epoch, placement_material
