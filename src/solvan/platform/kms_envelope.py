"""Small Cloud KMS envelope boundary for short-lived OAuth ceremony material."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

from solvan.platform.google_rest import GoogleRestSession

_KEY = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/keyRings/"
    r"[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$"
)


@dataclass(frozen=True, slots=True)
class EncryptedValue:
    ciphertext: str
    key_version: str


class KmsEnvelopeCipher:
    def __init__(self, *, key: str, session: GoogleRestSession) -> None:
        if _KEY.fullmatch(key) is None:
            raise ValueError("Cloud KMS key resource is invalid")
        self._key = key
        self._session = session

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> EncryptedValue:
        if not plaintext or len(plaintext) > 1024 or not aad or len(aad) > 4096:
            raise ValueError("KMS envelope input is empty or outside its byte ceiling")
        response = self._session.post(
            f"https://cloudkms.googleapis.com/v1/{self._key}:encrypt",
            json={
                "plaintext": base64.b64encode(plaintext).decode("ascii"),
                "additionalAuthenticatedData": base64.b64encode(aad).decode("ascii"),
            },
            timeout=10,
        )
        response.raise_for_status()
        body: Any = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("Cloud KMS returned no encryption response")
        ciphertext = body.get("ciphertext")
        key_version = body.get("name")
        if not isinstance(ciphertext, str) or not isinstance(key_version, str):
            raise RuntimeError("Cloud KMS returned incomplete encryption material")
        base64.b64decode(ciphertext, validate=True)
        if not key_version.startswith(f"{self._key}/cryptoKeyVersions/"):
            raise RuntimeError("Cloud KMS used an unexpected key version")
        return EncryptedValue(ciphertext=ciphertext, key_version=key_version)

    def decrypt(self, ciphertext: str, *, key_version: str, aad: bytes) -> bytes:
        if not key_version.startswith(f"{self._key}/cryptoKeyVersions/"):
            raise ValueError("encrypted material names an unexpected KMS key")
        base64.b64decode(ciphertext, validate=True)
        response = self._session.post(
            f"https://cloudkms.googleapis.com/v1/{self._key}:decrypt",
            json={
                "ciphertext": ciphertext,
                "additionalAuthenticatedData": base64.b64encode(aad).decode("ascii"),
            },
            timeout=10,
        )
        response.raise_for_status()
        body: Any = response.json()
        encoded = body.get("plaintext") if isinstance(body, dict) else None
        if not isinstance(encoded, str):
            raise RuntimeError("Cloud KMS returned no plaintext")
        value = base64.b64decode(encoded, validate=True)
        if not value or len(value) > 1024:
            raise RuntimeError("Cloud KMS plaintext is empty or oversized")
        return value
