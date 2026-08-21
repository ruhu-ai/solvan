"""Canonical integrity hashes shared by workspace boundary contracts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def canonical_sha256(value: Mapping[str, Any] | list[Any] | tuple[Any, ...]) -> str:
    """Hash canonical UTF-8 JSON; reject non-finite or non-serializable values."""

    return sha256_bytes(canonical_json_bytes(value))


def canonical_json_bytes(value: Mapping[str, Any] | list[Any] | tuple[Any, ...]) -> bytes:
    """Serialize the exact canonical bytes used by digest and signature contracts."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
