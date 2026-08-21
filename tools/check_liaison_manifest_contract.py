"""Hostile contract check for the target Liaison turn-input manifest."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from solvan.application.liaison.manifest_contract import validate_manifest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "specs" / "artifacts" / "liaison-turn-input-manifest.schema.json"

CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2}


def manifest_hash(manifest: dict[str, Any], policy_epoch: int, membership_epoch: int) -> str:
    preimage = (
        rfc8785.dumps(manifest)
        + b"\x00"
        + str(policy_epoch).encode("ascii")
        + b"\x00"
        + str(membership_epoch).encode("ascii")
    )
    return f"sha256:{hashlib.sha256(preimage).hexdigest()}"


def _legacy_reference_validator(
    manifest: dict[str, Any],
    *,
    expected_hash: str,
    policy_epoch: int,
    membership_epoch: int,
    expected_scope: tuple[str, str, str] = ("org_x", "prj_x", "env_x"),
    expected_cell_id: str = "cell_eu_1",
    expected_placement_epoch: int = 7,
    expected_reader_principal: str = "principal:opaque",
    expected_purpose: str = "incident-investigation",
    expected_region: str = "europe-west1",
    expected_compiler_version: str = "liaison-context-v2",
    expected_compiler_binding_epoch: int = 1,
    expected_compiler_digest: str = (
        "sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82"
    ),
    expected_tokenizer_digest: str = (
        "sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67"
    ),
    expected_model_resource: str = "gemini-3.6-flash",
    expected_template_registry_digest: str = "sha256:" + "a" * 64,
    expected_tool_registry_digest: str = "sha256:" + "b" * 64,
    expected_read_grant_digest: str = "sha256:" + "a" * 64,
    expected_scope_sequence_high_water: int = 1442,
) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)

    items = manifest["working_context"]["items"]
    if [item["sequence"] for item in items] != list(range(1, len(items) + 1)):
        raise ValueError("context item sequence must be contiguous and start at one")

    source_keys: set[tuple[str, str]] = set()
    for source in manifest["source_versions"]:
        key = (source["record_type"], source["record_id"])
        if key in source_keys:
            raise ValueError("one record may have only one selected source version")
        source_keys.add(key)

    budget = manifest["working_context"]["token_budget"]
    usable = (
        budget["model_input_limit"]
        - budget["stable_prefix_tokens"]
        - budget["reserved_output_tokens"]
        - budget["safety_margin_tokens"]
    )
    if usable <= 0 or budget["dynamic_context_ceiling"] > usable:
        raise ValueError("dynamic context ceiling exceeds usable model input")
    if budget["actual_context_tokens"] != sum(item["token_count"] for item in items):
        raise ValueError("actual context token count does not equal selected items")
    if budget["actual_context_tokens"] > budget["dynamic_context_ceiling"]:
        raise ValueError("selected context exceeds the dynamic context ceiling")

    compiled_at = datetime.fromisoformat(manifest["working_context"]["compiled_at"])
    expires_at = datetime.fromisoformat(manifest["working_context"]["expires_at"])
    if expires_at <= compiled_at:
        raise ValueError("manifest expiry must follow compilation")

    ceiling = CLASSIFICATION_RANK[manifest["classification_ceiling"]]
    if any(CLASSIFICATION_RANK[item["classification"]] > ceiling for item in items):
        raise ValueError("selected item exceeds the manifest classification ceiling")

    scope = manifest["scope"]
    actual_scope = (
        scope["organization_id"],
        scope["project_id"],
        scope["environment_id"],
    )
    if actual_scope != expected_scope:
        raise ValueError("manifest scope does not match the attempt row")
    if manifest["cell_id"] != expected_cell_id:
        raise ValueError("manifest cell does not match the routed cell")
    if manifest["placement_epoch"] != expected_placement_epoch:
        raise ValueError("manifest placement epoch is stale")
    if manifest["reader_principal"] != expected_reader_principal:
        raise ValueError("manifest reader does not match the turn grant")
    if manifest["purpose"] != expected_purpose:
        raise ValueError("manifest purpose does not match the turn grant")
    if manifest["region"] != expected_region:
        raise ValueError("manifest region does not match the routed cell")
    context = manifest["working_context"]
    expected_context_bindings = {
        "compiler_version": expected_compiler_version,
        "compiler_binding_epoch": expected_compiler_binding_epoch,
        "compiler_digest": expected_compiler_digest,
        "tokenizer_digest": expected_tokenizer_digest,
        "model_resource": expected_model_resource,
        "template_registry_digest": expected_template_registry_digest,
        "tool_registry_digest": expected_tool_registry_digest,
        "read_grant_digest": expected_read_grant_digest,
    }
    for field, expected in expected_context_bindings.items():
        if context[field] != expected:
            raise ValueError(f"manifest {field} does not match the dispatch binding")
    if manifest["scope_sequence_high_water"] != expected_scope_sequence_high_water:
        raise ValueError("manifest source high-water does not match compilation")
    if manifest_hash(manifest, policy_epoch, membership_epoch) != expected_hash:
        raise ValueError("manifest digest mismatch")


# Hostile fixtures and production dispatch exercise the imported semantic
# implementation. The function above remains readable review history only.


def baseline() -> dict[str, Any]:
    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    return {
        "schema_version": 2,
        "thread_id": "thr_example",
        "liaison_message_id": "lms_answer",
        "user_message_id": "lms_question",
        "reader_principal": "principal:opaque",
        "scope": {
            "organization_id": "org_x",
            "project_id": "prj_x",
            "environment_id": "env_x",
        },
        "cell_id": "cell_eu_1",
        "placement_epoch": 7,
        "purpose": "incident-investigation",
        "classification_ceiling": "CONFIDENTIAL",
        "region": "europe-west1",
        "anchor_ref": {"kind": "RECORD", "ref": "incident:INC-1042"},
        "conversation_intent": "LEDGER_QUERY",
        "authority_route": "ASK",
        "resolved_references": [{"kind": "RECORD", "ref": "incident:INC-1042"}],
        "source_versions": [
            {
                "record_type": "incident",
                "record_id": "INC-1042",
                "version": "7",
                "digest": digest_a,
            }
        ],
        "scope_sequence_high_water": 1442,
        "working_context": {
            "compiler_version": "liaison-context-v2",
            "compiler_binding_epoch": 1,
            "compiler_digest": (
                "sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82"
            ),
            "tokenizer_digest": (
                "sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67"
            ),
            "model_resource": "gemini-3.6-flash",
            "template_registry_digest": digest_a,
            "tool_registry_digest": digest_b,
            "read_grant_digest": digest_a,
            "stable_prefix_digest": digest_b,
            "variable_suffix_digest": digest_a,
            "context_digest": digest_b,
            "compiled_at": "2026-08-12T02:00:00+00:00",
            "expires_at": "2026-08-12T02:05:00+00:00",
            "token_budget": {
                "model_input_limit": 100,
                "stable_prefix_tokens": 10,
                "reserved_output_tokens": 20,
                "safety_margin_tokens": 10,
                "dynamic_context_ceiling": 60,
                "actual_context_tokens": 15,
            },
            "items": [
                {
                    "sequence": 1,
                    "kind": "CURRENT_USER",
                    "ref": "message:lms_question",
                    "digest": digest_a,
                    "token_count": 10,
                    "classification": "CONFIDENTIAL",
                    "trust": "UNTRUSTED_USER_CONTENT",
                    "access_verdict_ref": "verdict:user",
                },
                {
                    "sequence": 2,
                    "kind": "RECORD",
                    "ref": "incident:INC-1042@7",
                    "digest": digest_b,
                    "token_count": 5,
                    "classification": "INTERNAL",
                    "trust": "AUTHORITATIVE_REFERENCE",
                    "access_verdict_ref": "verdict:record",
                },
            ],
            "omitted_counts": {
                "expired_or_purged": 0,
                "superseded": 0,
                "budget": 0,
                "context_reduced_by_policy": False,
            },
        },
    }


def baseline_expectations() -> dict[str, Any]:
    """The dispatch bindings the hostile fixture above is expected to carry.

    `validate_manifest` takes every expectation as a required argument, because
    a default is a binding nobody chose. This is the offline fixture's set,
    stated once here so the hostile cases below (and the unit suite) compare a
    mutated manifest against the *unmutated* expectation rather than against
    itself.
    """

    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    return {
        "expected_scope": ("org_x", "prj_x", "env_x"),
        "expected_cell_id": "cell_eu_1",
        "expected_placement_epoch": 7,
        "expected_reader_principal": "principal:opaque",
        "expected_purpose": "incident-investigation",
        "expected_region": "europe-west1",
        "expected_context_bindings": {
            "compiler_version": "liaison-context-v2",
            "compiler_binding_epoch": 1,
            "compiler_digest": (
                "sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82"
            ),
            "tokenizer_digest": (
                "sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67"
            ),
            "model_resource": "gemini-3.6-flash",
            "template_registry_digest": digest_a,
            "tool_registry_digest": digest_b,
            "read_grant_digest": digest_a,
        },
        "expected_scope_sequence_high_water": 1442,
    }


def _exceed_classification_ceiling(value: dict[str, Any]) -> None:
    value["classification_ceiling"] = "INTERNAL"
    value["working_context"]["items"][0]["classification"] = "CONFIDENTIAL"


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    good = baseline()
    good_hash = manifest_hash(good, 11, 13)
    expectations = baseline_expectations()
    validate_manifest(
        good,
        expected_hash=good_hash,
        policy_epoch=11,
        membership_epoch=13,
        **expectations,
    )

    attacks: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        (
            "current user promoted to authority",
            lambda value: value["working_context"]["items"][0].update(
                trust="AUTHORITATIVE_REFERENCE"
            ),
        ),
        (
            "memory promoted to authority",
            lambda value: value["working_context"]["items"][1].update(kind="MEMORY_REF"),
        ),
        (
            "missing access verdict",
            lambda value: value["working_context"]["items"][1].pop("access_verdict_ref"),
        ),
        (
            "duplicate selected item",
            lambda value: value["working_context"]["items"].append(
                copy.deepcopy(value["working_context"]["items"][1])
            ),
        ),
        (
            "conflicting source version",
            lambda value: value["source_versions"].append(
                {**value["source_versions"][0], "version": "8"}
            ),
        ),
        (
            "noncontiguous sequence",
            lambda value: value["working_context"]["items"][1].update(sequence=3),
        ),
        (
            "false token accounting",
            lambda value: value["working_context"]["token_budget"].update(actual_context_tokens=1),
        ),
        (
            "context over dynamic ceiling",
            lambda value: value["working_context"]["token_budget"].update(
                dynamic_context_ceiling=14
            ),
        ),
        (
            "query without current user",
            lambda value: value["working_context"].update(
                items=[value["working_context"]["items"][1]],
                token_budget={
                    **value["working_context"]["token_budget"],
                    "actual_context_tokens": 5,
                },
            ),
        ),
        ("query routed to Act", lambda value: value.update(authority_route="ACT_SURFACE_ONLY")),
        (
            "expiry before compilation",
            lambda value: value["working_context"].update(expires_at="2026-08-12T01:59:00+00:00"),
        ),
        (
            "restricted item selected",
            lambda value: value["working_context"]["items"][0].update(classification="RESTRICTED"),
        ),
        (
            "item exceeds classification ceiling",
            _exceed_classification_ceiling,
        ),
        ("stale placement", lambda value: value.update(placement_epoch=6)),
        ("wrong reader", lambda value: value.update(reader_principal="principal:attacker")),
        ("wrong purpose", lambda value: value.update(purpose="support-export")),
        ("wrong region", lambda value: value.update(region="us-central1")),
        (
            "stale compiler binding",
            lambda value: value["working_context"].update(compiler_binding_epoch=2),
        ),
        (
            "wrong compiler digest",
            lambda value: value["working_context"].update(compiler_digest="sha256:" + "e" * 64),
        ),
        (
            "wrong tokenizer digest",
            lambda value: value["working_context"].update(tokenizer_digest="sha256:" + "e" * 64),
        ),
        (
            "wrong model resource",
            lambda value: value["working_context"].update(model_resource="gemini-other"),
        ),
        (
            "wrong template registry",
            lambda value: value["working_context"].update(
                template_registry_digest="sha256:" + "e" * 64
            ),
        ),
        (
            "wrong tool registry",
            lambda value: value["working_context"].update(
                tool_registry_digest="sha256:" + "e" * 64
            ),
        ),
        (
            "wrong read grant digest",
            lambda value: value["working_context"].update(read_grant_digest="sha256:" + "e" * 64),
        ),
        ("wrong source high-water", lambda value: value.update(scope_sequence_high_water=1443)),
    ]
    for label, mutate in attacks:
        candidate = copy.deepcopy(good)
        mutate(candidate)
        try:
            validate_manifest(
                candidate,
                expected_hash=manifest_hash(candidate, 11, 13),
                policy_epoch=11,
                membership_epoch=13,
                **expectations,
            )
        except Exception:
            continue
        raise SystemExit(f"liaison manifest attack was accepted: {label}")

    vector = b'{"schema_version":2,"thread_id":"thr_example"}' + b"\x00" + b"7" + b"\x00" + b"11"
    expected_vector_hash = "b900a3c0f40325e1f3065ccbf611953d48cf70361742128952c77d0a80bfa48b"
    if hashlib.sha256(vector).hexdigest() != expected_vector_hash:
        raise SystemExit("liaison manifest canonical digest vector drifted")
    print(f"Liaison manifest contract passed ({len(attacks)} hostile cases)")


if __name__ == "__main__":
    main()
