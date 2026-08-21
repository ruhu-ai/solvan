"""Verification of control-plane-signed Relay job envelopes."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.domain import canonical_digest

ControlKeyResolver = Callable[[str], bytes]


class EcdsaJobVerifier:
    """Accept exactly one canonical signed control-plane job envelope."""

    def __init__(self, *, key_resolver: ControlKeyResolver) -> None:
        self._key_resolver = key_resolver

    def verify(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(envelope) != {"job", "job_digest", "signing_key_id", "signature_base64"}:
            raise RelayRuntimeError("control-plane job envelope is malformed")
        job = envelope["job"]
        job_digest = envelope["job_digest"]
        key_id = envelope["signing_key_id"]
        signature = envelope["signature_base64"]
        if not isinstance(job, Mapping) or not all(
            isinstance(value, str) for value in (job_digest, key_id, signature)
        ):
            raise RelayRuntimeError("control-plane job envelope is malformed")
        unsigned_job = dict(job)
        if (
            str(unsigned_job.pop("job_digest", "")) != job_digest
            or canonical_digest(unsigned_job) != job_digest
        ):
            raise RelayRuntimeError("control-plane job digest does not bind the exact job")
        try:
            public_key = serialization.load_pem_public_key(self._key_resolver(key_id))
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                public_key.curve, ec.SECP256R1
            ):
                raise RelayRuntimeError("control-plane signing key is not ECDSA P-256")
            public_key.verify(
                base64.b64decode(signature, validate=True),
                bytes.fromhex(job_digest.removeprefix("sha256:")),
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        except (InvalidSignature, ValueError, TypeError) as error:
            raise RelayRuntimeError("control-plane job signature is invalid") from error
        return {"job": dict(job)}
