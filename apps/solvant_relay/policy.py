"""Fail-closed verification of the customer-signed Relay policy."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from solvan.domain import canonical_digest, require_digest


class RelayPolicyError(ValueError):
    """The local policy cannot authorize a Relay read."""


PolicyKeyResolver = Callable[[str], bytes]


@dataclass(frozen=True, slots=True)
class RelayPolicy:
    """A verified local policy; raw policy bytes never leave this process."""

    policy_id: str
    digest: str
    policy_key_id: str
    signature_digest: str
    relay_connection_id: str
    relay_connection_epoch: int
    enrollment_id: str
    enrollment_epoch: int
    image_digest: str
    control_plane_audience: str
    region: str
    classification_ceiling: str
    connector_catalog_digest: str
    redaction_revision: str
    expires_at: datetime
    adapters: Mapping[tuple[str, str], Mapping[str, Any]]

    def adapter_for(
        self,
        *,
        adapter_key: str,
        source_connection_id: str,
        source_connection_epoch: int,
        operation: str,
    ) -> Mapping[str, Any]:
        value = self.adapters.get((adapter_key, source_connection_id))
        if value is None:
            raise RelayPolicyError("adapter or source connection is not locally authorized")
        if int(value["source_connection_epoch"]) != source_connection_epoch:
            raise RelayPolicyError("source connection epoch is not locally authorized")
        operations = value["operations"]
        if not isinstance(operations, tuple) or operation not in operations:
            raise RelayPolicyError("operation is not locally authorized")
        return value


def _policy_schema() -> dict[str, Any]:
    path = (
        Path(__file__).resolve().parents[2]
        / "specs"
        / "artifacts"
        / "relay-local-policy.schema.json"
    )
    value = __import__("json").loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):  # pragma: no cover - checked by artifact harness
        raise RuntimeError("Relay local policy schema is invalid")
    return value


def _parse_time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise RelayPolicyError(f"{field} must be an RFC-3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RelayPolicyError(f"{field} must be an RFC-3339 timestamp") from error
    if parsed.tzinfo is None:
        raise RelayPolicyError(f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def verify_local_policy(
    value: Mapping[str, Any],
    *,
    key_resolver: PolicyKeyResolver,
    now: datetime,
    expected_image_digest: str,
    expected_audience: str,
) -> RelayPolicy:
    """Validate schema, canonical digest, signature, time, and local identity.

    This accepts no permissive mode: a malformed, unsigned, expired, or
    substituted policy refuses before an adapter can be selected.
    """

    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    policy = dict(value)
    try:
        jsonschema.Draft202012Validator(_policy_schema()).validate(policy)
    except jsonschema.ValidationError as error:
        raise RelayPolicyError("local policy does not match the closed schema") from error
    signature = policy.pop("signature")
    if not isinstance(signature, Mapping):  # schema keeps this defensive branch unreachable
        raise RelayPolicyError("local policy signature is absent")
    signed_digest = signature.get("signed_digest")
    if not isinstance(signed_digest, str) or signed_digest != canonical_digest(policy):
        raise RelayPolicyError("local policy signed digest does not match canonical policy bytes")
    key_id = signature.get("key_id")
    encoded = signature.get("value_base64")
    if not isinstance(key_id, str) or not isinstance(encoded, str):
        raise RelayPolicyError("local policy signature is malformed")
    try:
        public_key = serialization.load_pem_public_key(key_resolver(key_id))
        raw_signature = base64.b64decode(encoded, validate=True)
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise RelayPolicyError("local policy key is not ECDSA P-256")
        public_key.verify(
            raw_signature,
            bytes.fromhex(signed_digest.removeprefix("sha256:")),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise RelayPolicyError("local policy signature is invalid") from error
    expires_at = _parse_time(policy["expires_at"], field="expires_at")
    valid_from = _parse_time(policy["valid_from"], field="valid_from")
    now_utc = now.astimezone(UTC)
    if valid_from > now_utc or expires_at <= now_utc:
        raise RelayPolicyError("local policy is not currently valid")
    image_digest = str(policy["relay_image_digest"])
    if image_digest != expected_image_digest:
        raise RelayPolicyError("local policy image digest does not match this Relay")
    audience = str(policy["control_plane_audience"])
    if audience != expected_audience:
        raise RelayPolicyError("local policy control-plane audience does not match")
    adapters: dict[tuple[str, str], Mapping[str, Any]] = {}
    for adapter in policy["adapters"]:
        if not isinstance(adapter, Mapping):  # pragma: no cover - schema guard
            raise RelayPolicyError("local policy adapter is malformed")
        key = (str(adapter["adapter_key"]), str(adapter["source_connection_id"]))
        if key in adapters:
            raise RelayPolicyError("local policy duplicates an adapter/source binding")
        endpoint = adapter["endpoint"]
        tls = adapter["tls_policy"]
        if not isinstance(endpoint, Mapping) or not isinstance(tls, Mapping):
            raise RelayPolicyError("local policy adapter transport is malformed")
        if endpoint.get("scheme") != "https" or endpoint.get("port") != 443:
            raise RelayPolicyError("local policy adapter endpoint is not exact HTTPS")
        if tls.get("redirects") != "DENY" or tls.get("server_name") != endpoint.get("host"):
            raise RelayPolicyError("local policy adapter TLS policy is not exact")
        adapters[key] = {
            **dict(adapter),
            "operations": tuple(adapter["operations"]),
        }
    connector_catalog_digest = str(policy["connector_catalog_digest"])
    require_digest(connector_catalog_digest, field="connector_catalog_digest")
    return RelayPolicy(
        policy_id=str(policy["policy_id"]),
        digest=canonical_digest(policy),
        policy_key_id=str(key_id),
        signature_digest=canonical_digest(dict(signature)),
        relay_connection_id=str(policy["relay_connection_id"]),
        relay_connection_epoch=int(policy["relay_connection_epoch"]),
        enrollment_id=str(policy["relay_enrollment_id"]),
        enrollment_epoch=int(policy["relay_enrollment_epoch"]),
        image_digest=image_digest,
        control_plane_audience=audience,
        region=str(policy["region"]),
        classification_ceiling=str(policy["classification_ceiling"]),
        connector_catalog_digest=connector_catalog_digest,
        redaction_revision=str(policy["redaction_revision"]),
        expires_at=expires_at,
        adapters=adapters,
    )
