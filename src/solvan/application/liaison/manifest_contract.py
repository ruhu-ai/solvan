"""Production semantic validation for immutable Liaison input manifests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]


def _schema_path() -> Path:
    """Locate the immutable manifest schema in source and wheel deployments.

    Hatch installs ``solvan`` below ``.venv/site-packages`` while the release
    image keeps the governing artifacts at ``/app/specs``.  Deriving the
    repository root from the module's parent chain therefore points into the
    Python installation, not the application.  Search only the two explicit
    application locations and fail closed when neither is present.
    """

    candidates = (
        Path.cwd() / "specs" / "artifacts" / "liaison-turn-input-manifest.schema.json",
        Path("/app/specs/artifacts/liaison-turn-input-manifest.schema.json"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("immutable liaison manifest schema is not present in the application image")


SCHEMA_PATH = _schema_path()
CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())


def _manifest_hash(manifest: dict[str, Any], policy_epoch: int, membership_epoch: int) -> str:
    preimage = (
        rfc8785.dumps(manifest)
        + b"\x00"
        + str(policy_epoch).encode("ascii")
        + b"\x00"
        + str(membership_epoch).encode("ascii")
    )
    return f"sha256:{hashlib.sha256(preimage).hexdigest()}"


def validate_manifest(
    manifest: dict[str, Any],
    *,
    expected_hash: str,
    policy_epoch: int,
    membership_epoch: int,
    expected_scope: tuple[str, str, str],
    expected_cell_id: str,
    expected_placement_epoch: int,
    expected_reader_principal: str,
    expected_purpose: str,
    expected_region: str,
    expected_context_bindings: dict[str, str | int],
    expected_scope_sequence_high_water: int,
) -> None:
    """Validate schema, semantic relationships, and exact dispatch bindings.

    Every expectation is required. They previously defaulted to the offline
    contract fixture — `org_x/prj_x/env_x`, `cell_eu_1`, placement epoch 7,
    `principal:opaque`, and digests of `"a"`/`"b"` — so a dispatch path that
    forgot an argument compared a production manifest against a test vector
    and called the match a binding check. An omitted expectation is now a
    `TypeError` at the call site rather than a control that silently passes.
    """

    _VALIDATOR.validate(manifest)
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
    if (scope["organization_id"], scope["project_id"], scope["environment_id"]) != expected_scope:
        raise ValueError("manifest scope does not match the attempt row")
    expected_values: dict[str, Any] = {
        "cell_id": expected_cell_id,
        "placement_epoch": expected_placement_epoch,
        "reader_principal": expected_reader_principal,
        "purpose": expected_purpose,
        "region": expected_region,
    }
    for field, expected in expected_values.items():
        if manifest[field] != expected:
            raise ValueError(f"manifest {field} does not match the dispatch binding")
    context = manifest["working_context"]
    if not expected_context_bindings:
        raise ValueError("manifest validation requires the exact compiled context bindings")
    for field, expected in expected_context_bindings.items():
        if context[field] != expected:
            raise ValueError(f"manifest {field} does not match the dispatch binding")
    if manifest["scope_sequence_high_water"] != expected_scope_sequence_high_water:
        raise ValueError("manifest source high-water does not match compilation")
    if _manifest_hash(manifest, policy_epoch, membership_epoch) != expected_hash:
        raise ValueError("manifest digest mismatch")


def validate_manifest_freshness(manifest: dict[str, Any], *, now: datetime | None = None) -> None:
    """Refuse a compiled context after its bounded working-context TTL.

    This is intentionally separate from hash/shape validation so offline
    contract fixtures can use historical timestamps while the dispatch path
    always checks the database-clock-equivalent current time.
    """

    moment = now or datetime.now(UTC)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("manifest freshness time must be timezone-aware")
    expires_at = datetime.fromisoformat(manifest["working_context"]["expires_at"])
    if expires_at <= moment:
        raise ValueError("manifest working context has expired")


def check_schema() -> None:
    Draft202012Validator.check_schema(_SCHEMA)
