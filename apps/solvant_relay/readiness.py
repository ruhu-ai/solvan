"""Customer-side verification and signing for the Relay readiness exchange.

This module does not make network calls.  It turns a control-plane-signed
nonce challenge and an already-verified local policy into one narrowly scoped
runtime proof using the customer-mounted runtime proof key.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from apps.solvant_relay.policy import RelayPolicy
from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.domain import (
    RelayReadinessChallenge,
    RelayRuntimePolicyProof,
    canonical_digest,
    new_identifier,
)

ControlKeyResolver = Callable[[str], bytes]
RuntimePrivateKeyResolver = Callable[[str], bytes]


def verify_readiness_challenge(
    envelope: Mapping[str, Any], *, key_resolver: ControlKeyResolver, now: datetime
) -> tuple[RelayReadinessChallenge, str]:
    """Verify a short-lived control-plane challenge before local policy use."""

    if now.tzinfo is None or set(envelope) != {
        "challenge",
        "signing_key_id",
        "signature_base64",
    }:
        raise RelayRuntimeError("readiness challenge envelope is malformed")
    value = envelope["challenge"]
    key_id = envelope["signing_key_id"]
    encoded_signature = envelope["signature_base64"]
    if (
        not isinstance(value, Mapping)
        or not isinstance(key_id, str)
        or not isinstance(encoded_signature, str)
    ):
        raise RelayRuntimeError("readiness challenge envelope is malformed")
    fields = dict(value)
    nonce = fields.pop("nonce", None)
    schema_version = fields.pop("schema_version", None)
    if not isinstance(nonce, str) or schema_version != 1:
        raise RelayRuntimeError("readiness challenge has no valid nonce")
    challenge_digest = fields.pop("challenge_digest", None)
    if (
        not isinstance(challenge_digest, str)
        or canonical_digest({"schema_version": schema_version, **fields}) != challenge_digest
    ):
        raise RelayRuntimeError("readiness challenge digest does not bind its fields")
    try:
        fields["issued_at"] = _parse_time(fields["issued_at"])
        fields["expires_at"] = _parse_time(fields["expires_at"])
        challenge = RelayReadinessChallenge(
            challenge_digest=challenge_digest,
            **fields,
        )
    except (TypeError, ValueError) as error:
        raise RelayRuntimeError("readiness challenge fields are malformed") from error
    nonce_hash = "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()
    if nonce_hash != challenge.nonce_hash or challenge.expires_at <= now.astimezone(UTC):
        raise RelayRuntimeError("readiness challenge is expired or substituted")
    try:
        public_key = serialization.load_pem_public_key(key_resolver(key_id))
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise RelayRuntimeError("control-plane readiness key is not ECDSA P-256")
        public_key.verify(
            base64.b64decode(encoded_signature, validate=True),
            bytes.fromhex(canonical_digest(dict(value)).removeprefix("sha256:")),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise RelayRuntimeError("control-plane readiness challenge signature is invalid") from error
    return challenge, nonce


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def build_runtime_policy_proof(
    *,
    challenge: RelayReadinessChallenge,
    policy: RelayPolicy,
    runtime_proof_key_id: str,
    private_key_resolver: RuntimePrivateKeyResolver,
    now: datetime,
) -> RelayRuntimePolicyProof:
    """Create one customer-key-signed proof that cannot widen the policy."""

    if now.tzinfo is None or now.astimezone(UTC) > challenge.expires_at:
        raise RelayRuntimeError("cannot prove an expired readiness challenge")
    if (
        runtime_proof_key_id != challenge.runtime_proof_key_id
        or policy.policy_key_id != challenge.policy_key_id
        or policy.digest != challenge.local_policy_digest
        or policy.connector_catalog_digest != challenge.connector_catalog_digest
        or policy.redaction_revision != challenge.redaction_revision
        or policy.region != challenge.region
        or policy.classification_ceiling != challenge.classification_ceiling
        or policy.enrollment_id != challenge.enrollment_id
        or policy.enrollment_epoch != challenge.enrollment_epoch
        or policy.image_digest != challenge.image_digest
        or policy.control_plane_audience != challenge.expected_audience
    ):
        raise RelayRuntimeError("local policy does not exactly match readiness challenge")
    verified_at = now.astimezone(UTC)
    provisional = RelayRuntimePolicyProof(
        proof_id=new_identifier("rpf"),
        challenge_id=challenge.challenge_id,
        challenge_digest=challenge.challenge_digest,
        enrollment_id=challenge.enrollment_id,
        enrollment_epoch=challenge.enrollment_epoch,
        placement_epoch=challenge.placement_epoch,
        principal_claims_hash=challenge.principal_claims_hash,
        expected_audience=challenge.expected_audience,
        process_boot_id=challenge.process_boot_id,
        image_digest=challenge.image_digest,
        local_policy_digest=policy.digest,
        local_policy_signature_digest=policy.signature_digest,
        policy_key_id=policy.policy_key_id,
        connector_catalog_digest=policy.connector_catalog_digest,
        redaction_revision=policy.redaction_revision,
        runtime_proof_key_id=runtime_proof_key_id,
        runtime_proof_key_digest=challenge.runtime_proof_key_digest,
        region=policy.region,
        classification_ceiling=policy.classification_ceiling,
        local_policy_verified=True,
        proof_digest="sha256:" + "0" * 64,
        signature_base64="pending",
        verified_at=verified_at,
        expires_at=challenge.expires_at,
    )
    unsigned = provisional.unsigned_projection()
    unsigned.pop("proof_digest")
    digest = canonical_digest(unsigned)
    try:
        private_key = serialization.load_pem_private_key(
            private_key_resolver(runtime_proof_key_id), password=None
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, ec.SECP256R1
        ):
            raise RelayRuntimeError("runtime proof key is not ECDSA P-256")
        signature = private_key.sign(
            bytes.fromhex(digest.removeprefix("sha256:")),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (TypeError, ValueError) as error:
        raise RelayRuntimeError("runtime proof private key is unavailable") from error
    return replace(
        provisional,
        proof_digest=digest,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )
