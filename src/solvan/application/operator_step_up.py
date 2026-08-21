"""Transaction-bound operator presence proof (specification 05 §4.2).

Google establishes the operator's durable identity.  It cannot be asked to
reauthenticate the account, so a consequential action uses a separate,
short-lived email possession proof sent only to the verified email already
bound to that Google actor.  The proof cannot sign somebody in and cannot name
or change its actor, scope, operation, material, or session.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

CODE_DIGITS = 8
CODE_LIFETIME = timedelta(minutes=5)
MAX_ATTEMPTS = 5
ISSUANCE_WINDOW = timedelta(minutes=10)
MAX_ISSUANCES_PER_WINDOW = 3
MINIMUM_PEPPER_BYTES = 32


class OperatorStepUpError(RuntimeError):
    """A presence proof cannot be issued or trusted."""


def _pepper_bytes(pepper: str | bytes) -> bytes:
    value = pepper.encode("utf-8") if isinstance(pepper, str) else pepper
    if len(value) < MINIMUM_PEPPER_BYTES:
        raise OperatorStepUpError("the operator step-up pepper is not strong enough")
    return value


def verifier(*, pepper: str | bytes, step_up_transaction_id: str, code: str) -> str:
    """Return the keyed verifier stored instead of the low-entropy code.

    A plain SHA digest of a numeric code is reversible by trying the complete
    code space.  HMAC makes an offline database copy insufficient: the separate
    Secret Manager value is also required.  Binding the transaction identifier
    prevents a verifier copied between rows from being useful.
    """

    digest = hmac.new(
        _pepper_bytes(pepper),
        f"solvan-step-up:v1:{step_up_transaction_id}:{code}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


@dataclass(frozen=True, slots=True)
class IssuedPresenceCode:
    code: str
    verifier_hmac: str
    expires_at: datetime


def issue_code(
    *, now: datetime, step_up_transaction_id: str, pepper: str | bytes
) -> IssuedPresenceCode:
    code = f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"
    return IssuedPresenceCode(
        code=code,
        verifier_hmac=verifier(
            pepper=pepper, step_up_transaction_id=step_up_transaction_id, code=code
        ),
        expires_at=now + CODE_LIFETIME,
    )


def matches(
    *,
    submitted: str,
    stored_verifier: str,
    step_up_transaction_id: str,
    pepper: str | bytes,
) -> bool:
    if len(submitted) != CODE_DIGITS or not submitted.isdigit():
        return False
    expected = verifier(
        pepper=pepper, step_up_transaction_id=step_up_transaction_id, code=submitted
    )
    return hmac.compare_digest(expected, stored_verifier)


def masked_email(address: str) -> str:
    """Enough destination context for the operator, without disclosing it."""

    local, separator, domain = address.strip().lower().partition("@")
    if not separator or not local or not domain:
        raise OperatorStepUpError("the verified Google identity has no usable email")
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(3, len(local) - len(visible))}@{domain}"


__all__ = [
    "CODE_DIGITS",
    "CODE_LIFETIME",
    "ISSUANCE_WINDOW",
    "MAX_ATTEMPTS",
    "MAX_ISSUANCES_PER_WINDOW",
    "IssuedPresenceCode",
    "OperatorStepUpError",
    "issue_code",
    "masked_email",
    "matches",
    "verifier",
]
