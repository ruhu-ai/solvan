"""Typed tenant-integration contracts for observation and actuation.

Credential posture and host eligibility are decided here, in one place, so that
neither becomes an implicit property of a call site. Specification 13 §2 states
the governing constants; this module is their executable form.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, cast


class ConnectionPolicyError(RuntimeError):
    """A connection or actuator registration violates its integration contract."""


class CredentialPosture(StrEnum):
    FEDERATED_SHORT_LIVED = "FEDERATED_SHORT_LIVED"
    STORED_LONG_LIVED = "STORED_LONG_LIVED"
    CUSTOMER_SIDE_NONE = "CUSTOMER_SIDE_NONE"


class ConnectionAuthenticationMode(StrEnum):
    """Closed authentication mechanisms for a customer connection.

    Credential posture answers where a credential lives. It is deliberately not
    used as a proxy for authentication protocol: doing so is how the retired
    WIF pool fields allowed a Google-to-Google read path to be misdescribed.
    """

    GCP_SERVICE_ACCOUNT_IMPERSONATION = "GCP_SERVICE_ACCOUNT_IMPERSONATION"
    STORED_SECRET_REFERENCE = "STORED_SECRET_REFERENCE"
    CUSTOMER_SIDE_NONE = "CUSTOMER_SIDE_NONE"


class GcpResourceKind(StrEnum):
    GCP_PROJECT = "GCP_PROJECT"
    GCP_FOLDER = "GCP_FOLDER"
    GCP_ORGANIZATION = "GCP_ORGANIZATION"


@dataclass(frozen=True, slots=True)
class ExternalResourceScope:
    """One immutable external Google Cloud read boundary."""

    resource_kind: GcpResourceKind
    resource_id: str
    workload_region: str
    metrics_scoping_project_id: str | None
    decision_ref: str

    def validated(self) -> ExternalResourceScope:
        if not self.decision_ref:
            raise ConnectionPolicyError("an external resource scope requires a decision reference")
        if not re.fullmatch(r"[a-z]+(?:-[a-z0-9]+)*", self.workload_region):
            raise ConnectionPolicyError("an external resource scope requires one workload region")
        if self.resource_kind is GcpResourceKind.GCP_PROJECT:
            if not re.fullmatch(r"[a-z][a-z0-9-]{4,61}", self.resource_id):
                raise ConnectionPolicyError(
                    "a GCP project scope requires a Google Cloud project id"
                )
            if self.metrics_scoping_project_id is not None:
                raise ConnectionPolicyError(
                    "a GCP project scope cannot name a metrics scoping project"
                )
        elif not self.metrics_scoping_project_id or not re.fullmatch(
            r"[a-z][a-z0-9-]{4,61}", self.metrics_scoping_project_id
        ):
            raise ConnectionPolicyError(
                "a folder or organization scope requires an exact metrics scoping project"
            )
        return self


class HostKind(StrEnum):
    CLOUD_RUN = "CLOUD_RUN"
    GKE = "GKE"
    ONPREM_FEDERATED = "ONPREM_FEDERATED"
    ONPREM_KEYFILE = "ONPREM_KEYFILE"
    DEV_LOCAL = "DEV_LOCAL"


class ActuatorPosture(StrEnum):
    COLLECTOR = "COLLECTOR"
    REMEDIATE = "REMEDIATE"


#: Hosts whose identity is a Google-signed assertion rather than key material.
#: `ONPREM_KEYFILE` is deliberately absent: it is production eligible only with
#: an explicit recorded risk acceptance (specification 13 §3.2).
KEYLESS_HOSTS = frozenset({HostKind.CLOUD_RUN, HostKind.GKE, HostKind.ONPREM_FEDERATED})

#: Strength ordering used by the console and by policy comparisons. A weaker
#: posture is never silently substituted for a stronger one.
POSTURE_STRENGTH = {
    CredentialPosture.CUSTOMER_SIDE_NONE: 3,
    CredentialPosture.FEDERATED_SHORT_LIVED: 2,
    CredentialPosture.STORED_LONG_LIVED: 1,
}


@dataclass(frozen=True, slots=True)
class ConnectionRegistration:
    """An intent to register one customer read or execute relationship."""

    display_name: str
    kind: str
    provider: str
    credential_posture: CredentialPosture
    residency_region: str
    classification: str
    authentication_mode: ConnectionAuthenticationMode
    solvan_delegator_principal: str | None = None
    customer_reader_principal: str | None = None
    delegation_condition_digest: str | None = None
    token_lifetime_seconds: int | None = None
    resource_scope: ExternalResourceScope | None = None
    credential_secret_ref: str | None = None
    credential_cmek_key_ref: str | None = None
    #: The concluded scope verification, not an assertion that one happened.
    #: There is no boolean here on purpose: the one that used to be here was
    #: filled from the request body, so the schema's "read-only verified"
    #: constraint proved only that a caller had said so.
    scope_verification: CredentialScopeVerdict | None = None

    @property
    def read_only_scope_verified(self) -> bool:
        """Derived from the verification, never supplied by whoever registers."""

        return self.scope_verification is not None and self.scope_verification.read_only

    def validated(self) -> ConnectionRegistration:
        """Reject a registration the database would reject, with a usable reason.

        The schema enforces the same rules as CHECK constraints. Duplicating
        them here is deliberate: an operator gets an explanatory failure at the
        API boundary instead of a constraint violation, and the database
        remains the control that cannot be bypassed.
        """

        if self.kind == "RELAY":
            if self.provider != "SOLVAN_RELAY":
                raise ConnectionPolicyError("a Relay transport must use the SOLVAN_RELAY provider")
            if self.credential_posture is not CredentialPosture.CUSTOMER_SIDE_NONE:
                raise ConnectionPolicyError(
                    "a Relay transport must be customer-side credentialless"
                )
        elif self.provider == "SOLVAN_RELAY":
            raise ConnectionPolicyError("SOLVAN_RELAY is reserved for Relay transport connections")
        if self.credential_posture is CredentialPosture.FEDERATED_SHORT_LIVED:
            if (
                self.authentication_mode
                is not ConnectionAuthenticationMode.GCP_SERVICE_ACCOUNT_IMPERSONATION
            ):
                raise ConnectionPolicyError(
                    "a direct GCP connection must use service-account impersonation"
                )
            if self.kind != "GCP_NATIVE":
                raise ConnectionPolicyError(
                    "service-account impersonation is limited to GCP_NATIVE"
                )
            if self.resource_scope is None:
                raise ConnectionPolicyError(
                    "a direct GCP connection requires an external resource scope"
                )
            self.resource_scope.validated()
            if not all(
                (
                    self.solvan_delegator_principal,
                    self.customer_reader_principal,
                    self.delegation_condition_digest,
                    self.token_lifetime_seconds,
                )
            ):
                raise ConnectionPolicyError(
                    "a direct GCP connection requires exact delegator, customer reader, "
                    "delegation condition, and token lifetime"
                )
            assert self.solvan_delegator_principal is not None
            assert self.customer_reader_principal is not None
            assert self.delegation_condition_digest is not None
            assert self.token_lifetime_seconds is not None
            if not self.solvan_delegator_principal.startswith("serviceAccount:"):
                raise ConnectionPolicyError(
                    "the Solvan delegator must be a serviceAccount principal"
                )
            if not self.customer_reader_principal.startswith("serviceAccount:"):
                raise ConnectionPolicyError(
                    "the customer reader must be a serviceAccount principal"
                )
            if not self.delegation_condition_digest.startswith("sha256:"):
                raise ConnectionPolicyError("the delegation condition must be digest-pinned")
            if not 1 <= self.token_lifetime_seconds <= 900:
                raise ConnectionPolicyError(
                    "a direct GCP token lifetime must be between 1 and 900 seconds"
                )
            if self.credential_secret_ref:
                raise ConnectionPolicyError("a federated connection must not carry a stored secret")
        if self.credential_posture is CredentialPosture.STORED_LONG_LIVED:
            if self.authentication_mode is not ConnectionAuthenticationMode.STORED_SECRET_REFERENCE:
                raise ConnectionPolicyError("a stored credential must use STORED_SECRET_REFERENCE")
            if not self.credential_secret_ref or not self.credential_cmek_key_ref:
                raise ConnectionPolicyError(
                    "a stored credential requires a Secret Manager reference and a "
                    "customer-managed encryption key"
                )
            if self.scope_verification is None:
                raise ConnectionPolicyError(
                    "a stored credential must be verified read-only before registration"
                )
            verdict = self.scope_verification.validated()
            if verdict.provider != self.provider:
                raise ConnectionPolicyError(
                    "the scope verification names a different provider than this connection"
                )
            if not verdict.read_only:
                raise ConnectionPolicyError(f"{verdict.reason_code}: {verdict.explanation}")
        if self.credential_posture is CredentialPosture.CUSTOMER_SIDE_NONE:
            if self.authentication_mode is not ConnectionAuthenticationMode.CUSTOMER_SIDE_NONE:
                raise ConnectionPolicyError(
                    "a customer-side connection must use CUSTOMER_SIDE_NONE"
                )
            if any(
                (
                    self.credential_secret_ref,
                    self.solvan_delegator_principal,
                    self.customer_reader_principal,
                    self.delegation_condition_digest,
                    self.token_lifetime_seconds,
                )
            ):
                raise ConnectionPolicyError(
                    "a customer-side connection must hand Solvan no credential"
                )
        if self.credential_posture is not CredentialPosture.FEDERATED_SHORT_LIVED and any(
            (
                self.solvan_delegator_principal,
                self.customer_reader_principal,
                self.delegation_condition_digest,
                self.token_lifetime_seconds,
            )
        ):
            raise ConnectionPolicyError("only direct GCP connections may carry delegation material")
        if (
            self.credential_posture is not CredentialPosture.FEDERATED_SHORT_LIVED
            and self.resource_scope
        ):
            raise ConnectionPolicyError(
                "only direct GCP connections may carry an external resource scope"
            )
        if (
            self.credential_posture is not CredentialPosture.STORED_LONG_LIVED
            and self.scope_verification is not None
        ):
            raise ConnectionPolicyError(
                "only a stored credential carries a read-only scope verification"
            )
        return self


@dataclass(frozen=True, slots=True)
class ActuatorRegistration:
    """An intent to register one customer-deployed actuator."""

    connection_id: str
    host_kind: HostKind
    principal_email: str
    expected_audience: str
    posture: ActuatorPosture
    image_digest: str
    actuator_version: str
    risk_acceptance_ref: str | None = None
    policy_hash: str | None = None
    policy_source_ref: str | None = None
    customer_audit_sink_ref: str | None = None
    #: Left unset, eligibility is derived. Development and key-file hosts are
    #: never production eligible by default (specification 13): a key-file host
    #: reintroduces a long-lived credential, so its eligibility must be an
    #: explicit, separately recorded decision rather than a consequence of not
    #: being `DEV_LOCAL`. Setting this True for a development host is refused.
    production_eligible_override: bool | None = None

    @property
    def production_eligible(self) -> bool:
        if self.production_eligible_override is not None:
            return self.production_eligible_override
        return self.host_kind not in {HostKind.DEV_LOCAL, HostKind.ONPREM_KEYFILE}

    def validated(self) -> ActuatorRegistration:
        if self.host_kind is HostKind.ONPREM_KEYFILE and not self.risk_acceptance_ref:
            raise ConnectionPolicyError(
                "a key-file host reintroduces a long-lived credential and requires "
                "a recorded risk acceptance"
            )
        if self.production_eligible and self.host_kind is HostKind.DEV_LOCAL:
            raise ConnectionPolicyError("a development host can never be production eligible")
        if not self.expected_audience.startswith("https://"):
            raise ConnectionPolicyError("the actuator audience must be an HTTPS identity")
        if self.posture is ActuatorPosture.REMEDIATE:
            if not self.production_eligible:
                raise ConnectionPolicyError(
                    "a development host can never hold production mutation capability"
                )
            if not self.policy_hash:
                raise ConnectionPolicyError(
                    "mutation posture requires a customer-authored policy; absence refuses"
                )
            if not self.customer_audit_sink_ref:
                raise ConnectionPolicyError(
                    "mutation posture requires a customer-owned audit sink so receipts "
                    "are not held only by Solvan"
                )
        return self


#: Specification 13 §4. Why one probe answered as it did. A refused permission,
#: an unreachable provider, and a disabled API need three different actions from
#: the customer, so they are three values rather than one sentence.
CapabilityOutcome = Literal["GRANTED", "DENIED", "UNREACHABLE", "MISCONFIGURED", "NOT_PROBED"]

#: The closed availability vocabulary of specification 13 §4.
ConnectionAvailability = Literal[
    "NOT_CONFIGURED",
    "PROBING",
    "READY",
    "DEGRADED",
    "MISCONFIGURED",
    "DENIED",
    "UNREACHABLE",
    "STALE",
    "DISABLED",
]

RemediationKind = Literal[
    "GRANT_ROLE",
    "ENABLE_API",
    "FIX_CONFIGURATION",
    "REGISTER_CREDENTIAL",
    "RETRY_PROBE",
    "REENABLE_CONNECTION",
    "CONTACT_PROVIDER",
]

#: Specification 13 §3.3. What onboarding established about a stored key's
#: scope. Three values, not a boolean: "proven read-only" and "not provable"
#: are different facts, and collapsing them is what let an unverified key be
#: recorded as verified.
CredentialScopeState = Literal["VERIFIED_READ_ONLY", "REFUSED_WRITE_SCOPE", "UNVERIFIABLE"]

#: Why a stored key was not proven read-only. Closed, because each value sends
#: an operator somewhere different.
CredentialScopeReason = Literal[
    "WRITE_SCOPE_PRESENT",
    "SCOPE_NOT_RECOGNIZED",
    "SCOPES_NOT_REPORTED",
    "NO_SCOPE_INTROSPECTION",
    "VENDOR_ENDPOINT_UNKNOWN",
    "INTROSPECTION_REFUSED",
    "VENDOR_UNREACHABLE",
    "CREDENTIAL_UNREADABLE",
    "VERIFIER_UNAVAILABLE",
]


@dataclass(frozen=True, slots=True)
class CredentialScopeVerdict:
    """One concluded read-only scope verification, and why it concluded that.

    The verdict deliberately carries no vendor payload and no scope token. A
    vendor response is untrusted data: routing it into an explanation the
    console renders would give a hostile or broken provider a path to place the
    key value itself into Cloud SQL. A count and a closed reason are enough to
    act on and cannot carry a secret.
    """

    state: CredentialScopeState
    provider: str
    evaluated_at: datetime
    evidence_ref: str
    reason_code: CredentialScopeReason | None = None
    explanation: str | None = None
    remediation_kind: RemediationKind | None = None
    observed_scope_count: int = 0

    @property
    def read_only(self) -> bool:
        return self.state == "VERIFIED_READ_ONLY"

    def validated(self) -> CredentialScopeVerdict:
        if self.read_only != (self.reason_code is None):
            raise ConnectionPolicyError("a scope verdict and its reason code disagree")
        if not self.read_only and not (self.explanation and self.remediation_kind):
            raise ConnectionPolicyError(
                "an unproven scope verdict must carry an explanation and a next step"
            )
        if not self.evidence_ref:
            raise ConnectionPolicyError("a scope verdict must cite the inspection it came from")
        if self.observed_scope_count < 0:
            raise ConnectionPolicyError("an observed scope count cannot be negative")
        return self


@dataclass(frozen=True, slots=True)
class CapabilityObservation:
    """One probed capability and, when unavailable, the exact missing grant."""

    capability: str
    available: bool
    missing_grant: str | None
    probe_receipt_ref: str
    #: Required, with no default. A default would let an unavailable capability
    #: be constructed as GRANTED, which is the contradiction `validated`
    #: exists to catch.
    outcome: CapabilityOutcome

    def validated(self) -> CapabilityObservation:
        if not self.available and not self.missing_grant:
            raise ConnectionPolicyError(
                "an unavailable capability must name the grant that is missing"
            )
        if self.available != (self.outcome == "GRANTED"):
            raise ConnectionPolicyError("capability availability and probe outcome disagree")
        return self


@dataclass(frozen=True, slots=True)
class AvailabilityVerdict:
    """The derived availability of one connection and why it is not READY.

    Specification 13 §4 requires every non-READY result to carry a stable reason
    code, a safe explanation, the exact missing grant when disclosable, a
    remediation kind, and a receipt reference. Constructing those together with
    the state keeps a state from ever being recorded without its reason.
    """

    availability: ConnectionAvailability
    reason_code: str | None = None
    explanation: str | None = None
    missing_grant: str | None = None
    remediation_kind: RemediationKind | None = None
    receipt_ref: str | None = None


#: Precedence when capabilities disagree. An unreachable provider is decided
#: first because it is the only outcome that proves nothing either way: a
#: connection that could not be reached has not been refused, and reporting it
#: as denied would send the customer to fix a permission that is already
#: correct.
_OUTCOME_PRECEDENCE: tuple[CapabilityOutcome, ...] = (
    "UNREACHABLE",
    "MISCONFIGURED",
    "NOT_PROBED",
    "DENIED",
)

_OUTCOME_REASON: dict[CapabilityOutcome, tuple[str, RemediationKind, str]] = {
    "UNREACHABLE": (
        "PROVIDER_UNREACHABLE",
        "RETRY_PROBE",
        "the bounded probe could not reach or authenticate the provider "
        "conclusively, so no permission conclusion was drawn",
    ),
    "MISCONFIGURED": (
        "API_NOT_ENABLED",
        "ENABLE_API",
        "the provider reported the API is not enabled on this project",
    ),
    "NOT_PROBED": (
        "NOT_PROBEABLE_HERE",
        "REGISTER_CREDENTIAL",
        "this provider reports its own capability and was not probed by Solvan",
    ),
    "DENIED": (
        "PERMISSION_DENIED",
        "GRANT_ROLE",
        "verified identity reached the provider and the required permission was refused",
    ),
}


def derive_availability(
    *,
    lifecycle: str,
    observations: Sequence[CapabilityObservation],
    probe_in_flight: bool = False,
    proof_expired: bool = False,
    receipt_ref: str | None = None,
) -> AvailabilityVerdict:
    """Derive one connection's availability from lifecycle and observed probes.

    Pure, so the nine-state vocabulary can be exercised without a database or a
    provider. Order matters: an administrator's decision outranks any probe, an
    absent probe outranks an expired one, and among capability outcomes the
    least conclusive wins.
    """

    if lifecycle in ("DISABLED", "REVOKED"):
        return AvailabilityVerdict(
            "DISABLED",
            "CONNECTION_DISABLED",
            "an authorized configuration change disabled this connection",
            None,
            "REENABLE_CONNECTION",
            receipt_ref or "lifecycle://disabled",
        )
    if probe_in_flight:
        return AvailabilityVerdict(
            "PROBING",
            "PROBE_IN_FLIGHT",
            "one fenced minimal probe is running",
            None,
            "RETRY_PROBE",
            receipt_ref or "probe://in-flight",
        )
    if not observations:
        return AvailabilityVerdict(
            "NOT_CONFIGURED",
            "NEVER_PROBED",
            "this connection has never been probed, so nothing about it is proven",
            None,
            "RETRY_PROBE",
            receipt_ref or "probe://absent",
        )
    if proof_expired:
        return AvailabilityVerdict(
            "STALE",
            "PROOF_EXPIRED",
            "prior proof expired or its identity, epoch, policy, revision, or "
            "region binding changed",
            None,
            "RETRY_PROBE",
            receipt_ref or "probe://expired",
        )

    checked = [observation.validated() for observation in observations]
    receipt = receipt_ref or checked[0].probe_receipt_ref
    granted = [item for item in checked if item.outcome == "GRANTED"]
    if len(granted) == len(checked):
        return AvailabilityVerdict("READY", receipt_ref=receipt)

    for outcome in _OUTCOME_PRECEDENCE:
        failing = [item for item in checked if item.outcome == outcome]
        if not failing:
            continue
        code, remediation, explanation = _OUTCOME_REASON[outcome]
        # Some capabilities working and some not is DEGRADED, which names the
        # incomplete profile rather than the provider. A wholly refused
        # connection keeps the sharper state.
        if granted:
            return AvailabilityVerdict(
                "DEGRADED",
                "PARTIAL_CAPABILITY",
                f"{len(granted)} of {len(checked)} capabilities are proven; "
                f"{failing[0].capability} is not, because {explanation}",
                failing[0].missing_grant,
                remediation,
                receipt,
            )
        return AvailabilityVerdict(
            "UNREACHABLE"
            if outcome == "UNREACHABLE"
            else "MISCONFIGURED"
            if outcome == "MISCONFIGURED"
            else "NOT_CONFIGURED"
            if outcome == "NOT_PROBED"
            else "DENIED",
            code,
            explanation,
            failing[0].missing_grant,
            remediation,
            receipt,
        )
    raise ConnectionPolicyError("probe outcomes could not be classified")


#: Capability identifiers probed per provider. Each maps to the IAM role a
#: customer must grant, which is what the console renders when a probe fails.
PROVIDER_CAPABILITIES: dict[str, tuple[tuple[str, str], ...]] = {
    "CLOUD_MONITORING": (("metrics.read", "roles/monitoring.viewer"),),
    "CLOUD_LOGGING": (("logs.read", "roles/logging.viewer"),),
    "CLOUD_AUDIT": (("audit.read", "roles/logging.privateLogViewer"),),
    "ERROR_REPORTING": (("errors.read", "roles/errorreporting.viewer"),),
    "CLOUD_TRACE": (("traces.read", "roles/cloudtrace.user"),),
    "ASSET_INVENTORY": (("inventory.read", "roles/cloudasset.viewer"),),
    "MANAGED_PROMETHEUS": (("promql.read", "roles/monitoring.viewer"),),
}


@dataclass(frozen=True, slots=True)
class ConnectableProvider:
    """One customer system the onboarding flow may offer to connect."""

    provider: str
    kind: Literal["GCP_NATIVE", "VENDOR_API", "COLLECTOR"]
    label: str


#: Connection kind and operator-facing label per provider. Kind decides the
#: resulting credential posture, so it is enumerated rather than inferred from
#: the provider name: a heuristic that read "CLOUD_*" as Google-native would
#: silently promote a vendor connection to a keyless posture it has not earned.
_PROVIDER_PRESENTATION: dict[str, tuple[str, str]] = {
    "CLOUD_MONITORING": ("GCP_NATIVE", "Cloud Monitoring"),
    "CLOUD_LOGGING": ("GCP_NATIVE", "Cloud Logging"),
    "CLOUD_AUDIT": ("GCP_NATIVE", "Cloud Audit Logs"),
    "ERROR_REPORTING": ("GCP_NATIVE", "Error Reporting"),
    "CLOUD_TRACE": ("GCP_NATIVE", "Cloud Trace"),
    "ASSET_INVENTORY": ("GCP_NATIVE", "Cloud Asset Inventory"),
    "MANAGED_PROMETHEUS": ("GCP_NATIVE", "Managed Service for Prometheus"),
}

if _PROVIDER_PRESENTATION.keys() != PROVIDER_CAPABILITIES.keys():
    raise ConnectionPolicyError(
        "every connectable provider must have both a probed capability set and a "
        "declared kind and label; the two registries disagree on "
        f"{sorted(_PROVIDER_PRESENTATION.keys() ^ PROVIDER_CAPABILITIES.keys())}"
    )

#: The closed catalog the console offers under "Connect an estate". It is
#: derived from `PROVIDER_CAPABILITIES` so the flow can never offer a provider
#: Solvan has no probe for: onboarding a connection whose capability can never
#: be observed would leave a permanently unprovable estate in the projection.
CONNECTABLE_PROVIDERS: tuple[ConnectableProvider, ...] = tuple(
    ConnectableProvider(
        provider=provider,
        kind=cast(
            Literal["GCP_NATIVE", "VENDOR_API", "COLLECTOR"],
            _PROVIDER_PRESENTATION[provider][0],
        ),
        label=_PROVIDER_PRESENTATION[provider][1],
    )
    for provider in PROVIDER_CAPABILITIES
)


def connectable_provider_projection() -> list[dict[str, str]]:
    """The connectable catalog as the console consumes it.

    One function serves both the live projection and the local fixture, so the
    two paths cannot drift into offering different providers.
    """

    return [
        {"provider": item.provider, "kind": item.kind, "label": item.label}
        for item in CONNECTABLE_PROVIDERS
    ]
