"""Small KMS signing boundary shared by Relay control-plane components."""

from __future__ import annotations

import base64
from typing import Protocol

from solvan.platform.google_rest import authorized_session


class KmsSigner(Protocol):
    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes: ...


class GoogleKmsSigner:
    """Sign fixed SHA-256 Relay envelopes with one configured KMS key version."""

    def sign_sha256(self, digest: bytes, *, key_version: str) -> bytes:
        response = authorized_session().post(
            f"https://cloudkms.googleapis.com/v1/{key_version}:asymmetricSign",
            json={"digest": {"sha256": base64.b64encode(digest).decode("ascii")}},
            timeout=30,
        )
        response.raise_for_status()
        value = response.json()
        encoded = value.get("signature") if isinstance(value, dict) else None
        if not isinstance(encoded, str):
            raise RuntimeError("Cloud KMS returned no Relay protocol signature")
        return base64.b64decode(encoded, validate=True)
