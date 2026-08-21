"""Opaque type-prefixed ULID identifiers used by persistence and APIs."""

from __future__ import annotations

import re
import secrets
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PREFIX = re.compile(r"^[a-z]{2,4}$")
_IDENTIFIER = re.compile(r"^(?P<prefix>[a-z]{2,4})_(?P<ulid>[0-7][0-9A-HJKMNP-TV-Z]{25})$")


class IdentifierError(ValueError):
    """Raised when an identifier cannot satisfy the Solvan contract."""


def new_identifier(
    prefix: str,
    *,
    timestamp_ms: int | None = None,
    randomness: bytes | None = None,
) -> str:
    """Create a canonical prefix plus a 48-bit-time/80-bit-random ULID."""

    if _PREFIX.fullmatch(prefix) is None:
        raise IdentifierError("prefix must contain two to four lowercase ASCII letters")
    resolved_timestamp = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if not 0 <= resolved_timestamp < 2**48:
        raise IdentifierError("timestamp_ms must fit in 48 unsigned bits")
    resolved_randomness = secrets.token_bytes(10) if randomness is None else randomness
    if len(resolved_randomness) != 10:
        raise IdentifierError("randomness must contain exactly 10 bytes")
    value = (resolved_timestamp << 80) | int.from_bytes(resolved_randomness)
    encoded = "".join(_CROCKFORD[(value >> shift) & 31] for shift in range(125, -1, -5))
    return f"{prefix}_{encoded}"


def validate_identifier(value: str, *, expected_prefix: str | None = None) -> str:
    """Return a canonical identifier or fail closed."""

    match = _IDENTIFIER.fullmatch(value)
    if match is None:
        raise IdentifierError("identifier must be a type-prefixed uppercase ULID")
    if expected_prefix is not None and match.group("prefix") != expected_prefix:
        raise IdentifierError(
            f"identifier prefix {match.group('prefix')} does not match {expected_prefix}"
        )
    return value
