"""Per-start authentication for worktree-local Unix/loopback services."""

from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path


def read_local_service_token() -> str:
    value = os.environ.get("SOLVAN_LOCAL_READER_TOKEN_PATH")
    if not value:
        raise RuntimeError("local service token path is not configured")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError("local service token path is unsafe")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise RuntimeError("local service token path is unsafe")
        mode = stat.S_IMODE(metadata.st_mode)
        with os.fdopen(descriptor, "r", encoding="ascii") as handle:
            descriptor = None
            token = handle.read(257).strip()
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError("local service token is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if mode & 0o077 or not 43 <= len(token) <= 256:
        raise RuntimeError("local service token is outside the security bound")
    return token


def local_bearer_matches(authorization: str | None) -> bool:
    if authorization is None or not authorization.startswith("Bearer "):
        return False
    supplied = authorization.removeprefix("Bearer ").strip()
    return hmac.compare_digest(supplied, read_local_service_token())
