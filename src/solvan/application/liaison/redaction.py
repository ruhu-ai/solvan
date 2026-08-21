"""Deterministic classification of inbound text, before anything else sees it.

Specification 14 §11.1 requires classification and redaction to *precede*
persistence and model exposure, not follow them. The ordering is the whole
control: a secret written to the transcript and redacted a moment later has
already been stored, replicated, and — if a channel was subscribed — sent.

So this module is deliberately dull. It is regular expressions and a Luhn
check, run in-process, with no model and no network. A detector that has to
succeed before a secret is durable cannot be one that might time out. Anything
it flags is withheld whole: the surface stores a digest, a verdict, and a
placeholder, and the model is handed nothing at all.

The detectors are shape-based, so they are neither exhaustive nor clever. That
is the correct trade for a gate on the write path — the failure it must never
have is letting a recognisable credential through, and a false positive costs a
person one rephrase.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

#: Shapes that are credentials by construction. Each is anchored tightly enough
#: that ordinary prose does not match it; a looser pattern here would refuse
#: real questions, which trains people to route around the surface entirely.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}\b")),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"')),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*\S{8,}"
        ),
    ),
)

#: Long digit runs that pass Luhn. Checked rather than matched, because a
#: request id and a card number look identical to a regular expression.
_DIGIT_RUN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


class Classification(StrEnum):
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass(frozen=True, slots=True)
class Verdict:
    """What the gate decided, and everything downstream is allowed to know."""

    classification: Classification
    #: The detector names that fired. Never the matched text.
    findings: tuple[str, ...]
    #: Of the original input, so a purge leaves something checkable behind.
    digest: str
    #: What may be persisted and shown. Empty text is never the original.
    text: str
    verdict_ref: str

    @property
    def withheld(self) -> bool:
        return self.classification is Classification.RESTRICTED

    def placeholder(self) -> str:
        """What a reader sees instead of the message they sent."""

        return (
            "This message was withheld because it appears to contain a credential. "
            "Nothing was stored, shown to the model, or sent to a channel. "
            "Rephrase it without the secret and ask again."
        )


def _passes_luhn(digits: str) -> bool:
    total = 0
    for index, character in enumerate(reversed(digits)):
        value = int(character)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def classify(text: str) -> Verdict:
    """Decide what may be done with this text, before anything is done with it.

    Confidential is the floor, never the ceiling: inbound content is
    participant-scoped by default and escalates to restricted on any finding.
    There is no third outcome — a message that "probably" carries a credential
    is treated exactly like one that certainly does.
    """

    digest = f"sha256:{hashlib.sha256(text.encode()).hexdigest()}"
    findings = [name for name, pattern in _SECRET_PATTERNS if pattern.search(text)]

    for candidate in _DIGIT_RUN.findall(text):
        digits = re.sub(r"[ -]", "", candidate)
        if 13 <= len(digits) <= 19 and _passes_luhn(digits):
            findings.append("payment_card")
            break

    if findings:
        return Verdict(
            classification=Classification.RESTRICTED,
            findings=tuple(sorted(set(findings))),
            digest=digest,
            text="",
            verdict_ref=f"redaction://{digest.removeprefix('sha256:')[:32]}",
        )
    return Verdict(
        classification=Classification.CONFIDENTIAL,
        findings=(),
        digest=digest,
        text=text,
        verdict_ref=f"redaction://{digest.removeprefix('sha256:')[:32]}",
    )
