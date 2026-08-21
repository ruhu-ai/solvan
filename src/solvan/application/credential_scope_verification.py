"""Prove a stored vendor key is read-only scoped, or refuse to hold it.

Specification 13 §3.3 lets Solvan hold a long-lived customer key only when
onboarding has verified the key is read-only scoped. That fact is concluded
here from the vendor's own declaration of what the key may do. It is never
accepted from a caller: a boolean in a request body records that somebody
ticked a box, not that the key cannot write.

Two rules keep the key value out of everything this module produces. The value
travels in an opaque holder that cannot be printed, formatted, or serialized,
and is handed only to the inspector that must present it to the vendor. A
vendor scope token never leaves the module at all: a token this code cannot
classify refuses rather than being echoed into an explanation the console would
render, because a vendor response is untrusted data and could name the key
itself.

Every outcome is a verdict, including failure. A raised exception would collapse
"this key can write" and "the vendor timed out" into one unusable error, and the
first must refuse onboarding permanently while the second must not.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from solvan.application.tenant_integration import (
    ConnectionPolicyError,
    CredentialScopeReason,
    CredentialScopeState,
    CredentialScopeVerdict,
    RemediationKind,
)


class OpaqueCredential:
    """A resolved vendor key that cannot be printed, formatted, or serialized.

    The key value has exactly one legitimate destination: the vendor request
    that asks what the key is scoped to. Every other route out — a log line, an
    f-string, an exception repr, a JSON dump — is closed here rather than by
    asking each call site to remember.
    """

    __slots__ = ("_value",)

    def __init__(self, material: bytes) -> None:
        value = material.decode("utf-8").strip()
        if not value:
            raise ConnectionPolicyError("the resolved credential is empty")
        self._value = value

    def present(self) -> str:
        """Hand the value to the one caller that must send it to the vendor."""

        return self._value

    def __repr__(self) -> str:
        return "<OpaqueCredential redacted>"

    def __str__(self) -> str:
        return self.__repr__()


#: What a bounded scope inspection established, before any judgement about it.
ScopeOutcome = Literal[
    "OBSERVED",
    "NO_INTROSPECTION",
    "ENDPOINT_UNKNOWN",
    "INTROSPECTION_REFUSED",
    "UNREACHABLE",
]


@dataclass(frozen=True, slots=True)
class ScopeReport:
    """What a vendor said the presented key is scoped to. Never its payload."""

    provider: str
    outcome: ScopeOutcome
    scopes: tuple[str, ...] = ()


class SecretResolver(Protocol):
    """Resolve a Secret Manager reference. Implemented by SecretManagerReader."""

    def access(self, resource: str, *, max_bytes: int = ...) -> bytes: ...


class VendorScopeInspector(Protocol):
    """Ask one vendor what a key carries, without concluding anything from it."""

    def supports(self, provider: str) -> bool: ...

    def inspect(self, *, provider: str, credential: OpaqueCredential) -> ScopeReport: ...


class ScopeInspectionTransport(Protocol):
    """The minimal surface an inspection needs. Implemented by an HTTP client."""

    def get(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class _ScopeInspection:
    """How one vendor declares what the key presenting the request may do."""

    path: str
    credential_header: str
    credential_prefix: str
    #: Host is matched against the vendor's own domains, never accepted free
    #: form. A deployment that could point inspection at any host could point it
    #: at a server that answers "read only" for a key that writes.
    host: re.Pattern[str]
    default_host: str | None
    read_scope: re.Pattern[str]
    write_scope: re.Pattern[str]


#: Only the vendors whose key scope Solvan can actually observe appear here.
#: `NEW_RELIC` and `PROMETHEUS` are deliberately absent: a New Relic user key is
#: introspected by key id, which no connection record carries, and the Prometheus
#: HTTP API has no authorization model of its own to interrogate. Absence means
#: a stored long-lived key for them is refused, not assumed harmless.
_INSPECTIONS: dict[str, _ScopeInspection] = {
    # Datadog reports the scopes of every application key the authenticating
    # user owns. The presented key is one of them, so "every reported key is
    # read-only" proves the presented key is read-only. The converse is not
    # claimed: this over-refuses rather than guessing which entry is in hand.
    # Datadog also requires the account API key alongside the application key,
    # which a connection record cannot yet hold, so this refuses with
    # INTROSPECTION_REFUSED until that second reference exists.
    "DATADOG": _ScopeInspection(
        path="/api/v2/current_user/application_keys",
        credential_header="DD-APPLICATION-KEY",
        credential_prefix="",
        host=re.compile(r"api\.(?:[a-z0-9]+\.)?(?:datadoghq\.com|datadoghq\.eu|ddog-gov\.com)"),
        default_host="api.datadoghq.com",
        read_scope=re.compile(r"(?:[a-z0-9_]+_read|logs_read_[a-z0-9_]+|timeseries_query)"),
        write_scope=re.compile(
            r"(?:[a-z0-9_]+_(?:write|manage|delete|create|edit|execute|update)"
            r"|logs_(?:write|delete|modify)_[a-z0-9_]+)"
        ),
    ),
    # Grafana answers for the exact token presenting the request. Every stack
    # has its own host, so there is no default: an unconfigured stack is
    # unverifiable rather than inspected against somebody else's Grafana.
    "GRAFANA": _ScopeInspection(
        path="/api/access-control/user/permissions",
        credential_header="Authorization",
        credential_prefix="Bearer ",
        host=re.compile(r"[a-z0-9-]{1,50}\.grafana\.net"),
        default_host=None,
        read_scope=re.compile(r"[a-z0-9._-]+:(?:read|query|list)"),
        write_scope=re.compile(
            r"[a-z0-9._-]+:(?:write|create|delete|add|remove|admin|enable"
            r"|disable|execute|set|start|stop|grant|revoke)"
        ),
    ),
}


#: Specification 13 §3.3. Why a stored key was not proven read-only, and what
#: the operator does next. Closed, because each value sends them somewhere
#: different: reissue a narrower key, fix the deployment, or accept that this
#: estate cannot be reached with a stored key at all.
_REASON: dict[CredentialScopeReason, tuple[str, RemediationKind]] = {
    "WRITE_SCOPE_PRESENT": (
        "the vendor reports this key carries a write scope, so Solvan will not "
        "hold it; issue a key limited to read scopes and register that instead",
        "REGISTER_CREDENTIAL",
    ),
    "SCOPE_NOT_RECOGNIZED": (
        "the vendor reports a scope Solvan cannot classify, so read-only is not "
        "proven; issue a key limited to the provider's documented read scopes",
        "REGISTER_CREDENTIAL",
    ),
    "SCOPES_NOT_REPORTED": (
        "the vendor reported no scope for this key, which means it inherits its "
        "owner's permissions rather than a read-only set",
        "REGISTER_CREDENTIAL",
    ),
    "NO_SCOPE_INTROSPECTION": (
        "this provider exposes no way to inspect a key's scope, so a stored "
        "long-lived key cannot be proven read-only; reach this estate through "
        "Solvant Relay or the customer-side collector",
        "CONTACT_PROVIDER",
    ),
    "VENDOR_ENDPOINT_UNKNOWN": (
        "this deployment has no recorded API endpoint for the provider, so the "
        "key was never inspected",
        "FIX_CONFIGURATION",
    ),
    "INTROSPECTION_REFUSED": (
        "the vendor refused to tell this key what it is scoped to, so nothing "
        "about its scope is proven",
        "REGISTER_CREDENTIAL",
    ),
    "VENDOR_UNREACHABLE": (
        "the bounded scope inspection could not reach or read the vendor, so no "
        "scope conclusion was drawn",
        "RETRY_PROBE",
    ),
    "CREDENTIAL_UNREADABLE": (
        "the Secret Manager reference could not be resolved, so the key was never inspected",
        "FIX_CONFIGURATION",
    ),
    "VERIFIER_UNAVAILABLE": (
        "read-only scope verification is unavailable in this deployment, so a "
        "stored long-lived key cannot be accepted",
        "FIX_CONFIGURATION",
    ),
}

_OUTCOME_REASON: dict[ScopeOutcome, CredentialScopeReason] = {
    "NO_INTROSPECTION": "NO_SCOPE_INTROSPECTION",
    "ENDPOINT_UNKNOWN": "VENDOR_ENDPOINT_UNKNOWN",
    "INTROSPECTION_REFUSED": "INTROSPECTION_REFUSED",
    "UNREACHABLE": "VENDOR_UNREACHABLE",
}


def _evidence_ref(provider: str, credential_secret_ref: str, state: str, at: datetime) -> str:
    """Cite the inspection a verdict came from. The reference is never the key."""

    digest = hashlib.sha256(
        json.dumps(
            {
                "provider": provider,
                "credential_secret_ref": credential_secret_ref,
                "state": state,
                "evaluated_at": at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return f"scope://{provider.lower()}#sha256:{digest}"


def scope_verdict(
    *,
    provider: str,
    credential_secret_ref: str,
    state: CredentialScopeState,
    reason_code: CredentialScopeReason | None = None,
    observed_scope_count: int = 0,
) -> CredentialScopeVerdict:
    """Build one verdict with the explanation and next step its reason implies."""

    at = datetime.now(UTC)
    explanation, remediation = (None, None) if reason_code is None else _REASON[reason_code]
    return CredentialScopeVerdict(
        state=state,
        provider=provider,
        evaluated_at=at,
        evidence_ref=_evidence_ref(provider, credential_secret_ref, state, at),
        reason_code=reason_code,
        explanation=explanation,
        remediation_kind=remediation,
        observed_scope_count=observed_scope_count,
    ).validated()


def unverifiable_scope(
    *, provider: str, credential_secret_ref: str, reason_code: CredentialScopeReason
) -> CredentialScopeVerdict:
    """State that nothing was proven, for a composition root that cannot verify."""

    return scope_verdict(
        provider=provider,
        credential_secret_ref=credential_secret_ref,
        state="UNVERIFIABLE",
        reason_code=reason_code,
    )


def _declared_scopes(provider: str, body: object) -> tuple[str, ...] | None:
    """Read the scope tokens out of one vendor's answer, or refuse its shape."""

    if provider == "DATADOG":
        if not isinstance(body, dict) or not isinstance(body.get("data"), list):
            return None
        collected: list[str] = []
        for item in body["data"]:
            if not isinstance(item, dict) or not isinstance(item.get("attributes"), dict):
                return None
            declared = item["attributes"].get("scopes")
            if declared is None:
                # An unscoped Datadog application key inherits its owner's
                # permissions. Reporting the other keys' scopes would describe a
                # key that is not the one in hand.
                return ()
            if not isinstance(declared, list) or not all(
                isinstance(scope, str) for scope in declared
            ):
                return None
            collected.extend(declared)
        return tuple(collected)
    if provider == "GRAFANA":
        if not isinstance(body, dict) or not all(isinstance(action, str) for action in body):
            return None
        return tuple(body)
    return None


class HttpVendorScopeInspector:
    """Read a vendor's own declaration of what the presented key may do.

    One bounded read per registration, against the vendor's own domain, with the
    key in a request header and never in a URL, query string, or body that a
    proxy or access log would retain.
    """

    def __init__(
        self, transport: ScopeInspectionTransport, *, hosts: Mapping[str, str] | None = None
    ) -> None:
        self._transport = transport
        resolved: dict[str, str] = {}
        for provider, host in (hosts or {}).items():
            inspection = _INSPECTIONS.get(provider)
            if inspection is None or not inspection.host.fullmatch(host):
                raise ConnectionPolicyError(
                    f"the configured scope inspection host for {provider} is not a "
                    f"{provider} endpoint"
                )
            resolved[provider] = host
        self._hosts = resolved

    def supports(self, provider: str) -> bool:
        return provider in _INSPECTIONS

    def inspect(self, *, provider: str, credential: OpaqueCredential) -> ScopeReport:
        inspection = _INSPECTIONS.get(provider)
        if inspection is None:
            return ScopeReport(provider=provider, outcome="NO_INTROSPECTION")
        host = self._hosts.get(provider) or inspection.default_host
        if host is None:
            return ScopeReport(provider=provider, outcome="ENDPOINT_UNKNOWN")
        try:
            response = self._transport.get(
                f"https://{host}{inspection.path}",
                headers={
                    inspection.credential_header: (
                        f"{inspection.credential_prefix}{credential.present()}"
                    )
                },
                timeout=15,
            )
            status_code = int(getattr(response, "status_code", 0))
            if status_code in (401, 403):
                return ScopeReport(provider=provider, outcome="INTROSPECTION_REFUSED")
            if not 200 <= status_code < 300:
                return ScopeReport(provider=provider, outcome="UNREACHABLE")
            body = response.json()
        except Exception:
            # A transport or parse failure is not a scope answer. Reporting it as
            # anything else would either accept an uninspected key or send the
            # operator to reissue a key that is already correct.
            return ScopeReport(provider=provider, outcome="UNREACHABLE")
        scopes = _declared_scopes(provider, body)
        if scopes is None:
            return ScopeReport(provider=provider, outcome="UNREACHABLE")
        return ScopeReport(provider=provider, outcome="OBSERVED", scopes=scopes)


def _classifications(provider: str, scopes: tuple[str, ...]) -> set[str]:
    inspection = _INSPECTIONS[provider]
    seen: set[str] = set()
    for scope in scopes:
        if inspection.write_scope.fullmatch(scope):
            seen.add("WRITE")
        elif inspection.read_scope.fullmatch(scope):
            seen.add("READ")
        else:
            seen.add("UNKNOWN")
    return seen


def verify_read_only_scope(
    *,
    provider: str,
    credential_secret_ref: str,
    secrets: SecretResolver,
    inspector: VendorScopeInspector,
) -> CredentialScopeVerdict:
    """Conclude whether one stored vendor key is read-only scoped."""

    def refused(reason_code: CredentialScopeReason, count: int = 0) -> CredentialScopeVerdict:
        return scope_verdict(
            provider=provider,
            credential_secret_ref=credential_secret_ref,
            state="REFUSED_WRITE_SCOPE" if reason_code == "WRITE_SCOPE_PRESENT" else "UNVERIFIABLE",
            reason_code=reason_code,
            observed_scope_count=count,
        )

    if not credential_secret_ref:
        return refused("CREDENTIAL_UNREADABLE")
    # Asked before the secret is resolved: a key Solvan can never inspect is a
    # key Solvan has no reason to read out of the customer's project.
    if not inspector.supports(provider):
        return refused("NO_SCOPE_INTROSPECTION")
    try:
        credential = OpaqueCredential(secrets.access(credential_secret_ref))
    except Exception:
        return refused("CREDENTIAL_UNREADABLE")
    try:
        report = inspector.inspect(provider=provider, credential=credential)
    except Exception:
        return refused("VENDOR_UNREACHABLE")
    if report.outcome != "OBSERVED":
        return refused(_OUTCOME_REASON[report.outcome])
    if not report.scopes:
        return refused("SCOPES_NOT_REPORTED")
    classified = _classifications(provider, report.scopes)
    count = len(report.scopes)
    # A proven write scope outranks an unclassifiable one: it is a decision the
    # operator can act on, where an unrecognized token only means Solvan cannot
    # conclude. Both refuse; they do not refuse for the same reason.
    if "WRITE" in classified:
        return refused("WRITE_SCOPE_PRESENT", count)
    if "UNKNOWN" in classified:
        return refused("SCOPE_NOT_RECOGNIZED", count)
    return scope_verdict(
        provider=provider,
        credential_secret_ref=credential_secret_ref,
        state="VERIFIED_READ_ONLY",
        observed_scope_count=count,
    )
