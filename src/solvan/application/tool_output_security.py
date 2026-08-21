"""Deterministic validation for untrusted connector and MCP output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_INSTRUCTION_PATTERNS = (
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?"),
    re.compile(r"(?i)(?:system|developer)\s+message\s*:"),
    re.compile(r"(?i)reveal\s+(?:the\s+)?(?:secret|token|credential|prompt)"),
    re.compile(r"(?i)(?:call|invoke|use)\s+(?:the\s+)?(?:tool|shell|terminal)\s+to"),
)
_TOKEN = re.compile(r"(?i)\b(?:bearer|token|api[_ -]?key|password)\s*[:=]\s*[^\s,;]{6,}")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True, slots=True)
class SecuredToolOutput:
    value: dict[str, Any]
    reason_codes: tuple[str, ...]


def secure_tool_output(value: dict[str, Any]) -> SecuredToolOutput:
    """Redact PII/secrets and withhold instruction-like strings recursively."""

    reasons: set[str] = set()

    def visit(item: Any, *, depth: int = 0) -> Any:
        if depth > 12:
            reasons.add("OUTPUT_DEPTH_EXCEEDED")
            return "[WITHHELD_DEPTH_LIMIT]"
        if isinstance(item, str):
            bounded = item[:16_000]
            if len(item) > len(bounded):
                reasons.add("OUTPUT_STRING_TRUNCATED")
            if any(pattern.search(bounded) for pattern in _INSTRUCTION_PATTERNS):
                reasons.add("INSTRUCTION_LIKE_CONTENT_WITHHELD")
                return "[WITHHELD_INSTRUCTION_LIKE_CONTENT]"
            secured = _TOKEN.sub("[SECRET]", bounded)
            secured = _EMAIL.sub("[EMAIL]", secured)
            secured = _IP.sub("[IP]", secured)
            if secured != bounded:
                reasons.add("SENSITIVE_CONTENT_REDACTED")
            return secured
        if isinstance(item, dict):
            if len(item) > 200:
                reasons.add("OUTPUT_OBJECT_TRUNCATED")
            return {
                str(key)[:256]: visit(child, depth=depth + 1)
                for key, child in list(item.items())[:200]
            }
        if isinstance(item, list):
            if len(item) > 1_000:
                reasons.add("OUTPUT_LIST_TRUNCATED")
            return [visit(child, depth=depth + 1) for child in item[:1_000]]
        if item is None or isinstance(item, bool | int | float):
            return item
        reasons.add("OUTPUT_TYPE_WITHHELD")
        return "[WITHHELD_UNSUPPORTED_TYPE]"

    secured = visit(value)
    if not isinstance(secured, dict):
        raise TypeError("secured tool output must remain an object")
    return SecuredToolOutput(value=secured, reason_codes=tuple(sorted(reasons)))
