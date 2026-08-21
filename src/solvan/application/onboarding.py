"""Generate the exact grants a customer must apply to connect an estate.

Onboarding never asks for a credential. Direct Google Cloud observation uses a
customer-owned reader service account: the exact Solvan Cloud Run identity may
mint a short-lived token for that one account, and the reader account holds the
provider read roles. For a stored vendor key the operator supplies a Secret
Manager *reference*, never the key value, so the secret has no path into
Solvan's database, logs, or UI.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from solvan.application.tenant_integration import (
    CONNECTABLE_PROVIDERS,
    PROVIDER_CAPABILITIES,
    ConnectionPolicyError,
    CredentialPosture,
)


@dataclass(frozen=True, slots=True)
class GrantStep:
    """One command the customer runs, and why it is needed."""

    purpose: str
    command: str


@dataclass(frozen=True, slots=True)
class OnboardingPlan:
    posture: CredentialPosture
    summary: str
    steps: tuple[GrantStep, ...]
    secret_required: bool
    delegation_condition_digest: str | None = None


#: Why a consolidated estate selection was refused. Closed, because each value
#: sends the operator to a different correction, and the console renders the
#: code rather than a sentence assembled from whatever the API returned.
EstateSelectionReason = Literal[
    "ESTATE_SELECTION_EMPTY",
    "ESTATE_PROVIDER_UNKNOWN",
    "ESTATE_PROVIDER_DUPLICATED",
    "ESTATE_PROVIDER_NOT_DIRECT_GCP",
    "ESTATE_PROJECT_REQUIRED",
    "ESTATE_READER_REQUIRED",
    "ESTATE_READER_NOT_A_SERVICE_ACCOUNT",
]


class EstateSelectionError(ConnectionPolicyError):
    """A refused estate selection, carrying the code rather than only prose.

    It remains a `ConnectionPolicyError` so every existing caller that already
    refuses on one keeps refusing; the code is what the console maps to a
    sentence it wrote itself.
    """

    def __init__(self, reason_code: EstateSelectionReason, explanation: str) -> None:
        super().__init__(f"{reason_code}: {explanation}")
        self.reason_code = reason_code
        self.explanation = explanation


#: What an incident investigation actually reads: what changed, what the
#: application said, who changed it, what broke, and where the latency went.
#: Asset inventory and managed Prometheus are offered but not ticked — neither
#: is needed to establish what happened, so pre-ticking them would ask a
#: customer to grant a role for nothing.
INVESTIGATION_PROVIDERS: tuple[str, ...] = (
    "CLOUD_MONITORING",
    "CLOUD_LOGGING",
    "CLOUD_AUDIT",
    "ERROR_REPORTING",
    "CLOUD_TRACE",
)


@dataclass(frozen=True, slots=True)
class EstateOnboardingPlan:
    """One grant plan covering every capability an operator ticked at once.

    Per-capability connections stay separate records; only the grants are
    consolidated, so a customer runs one set of commands for one reader service
    account instead of the same two commands once per telemetry source.
    """

    posture: CredentialPosture
    providers: tuple[str, ...]
    roles: tuple[str, ...]
    summary: str
    steps: tuple[GrantStep, ...]
    secret_required: bool
    delegation_condition_digest: str


def _roles_for(provider: str) -> tuple[str, ...]:
    declared = PROVIDER_CAPABILITIES.get(provider)
    if not declared:
        raise ConnectionPolicyError(f"provider {provider} declares no capability")
    seen: list[str] = []
    for _, grant in declared:
        if grant.startswith("roles/") and grant not in seen:
            seen.append(grant)
    return tuple(seen)


def _direct_gcp_grants(
    *,
    roles: Sequence[str],
    customer_project_id: str,
    solvan_service_account: str,
    customer_reader_service_account: str,
) -> tuple[tuple[GrantStep, ...], str]:
    """The role bindings and the one delegation, in the order the customer runs them.

    One place builds these commands so a consolidated plan cannot drift into a
    different grant from the one a single-provider plan produces for the same
    role.
    """

    # The allow policy is attached to this exact service-account resource, so
    # the resource itself is the boundary. IAM Conditions' resource.name is
    # unavailable for IAM resources; adding that expression makes
    # iam.serviceAccounts.getAccessToken impossible rather than narrower. Keep
    # a digest of the exact unconditioned binding as the application contract.
    binding_material = json.dumps(
        {
            "resource": (
                f"projects/{customer_project_id}/serviceAccounts/{customer_reader_service_account}"
            ),
            "member": f"serviceAccount:{solvan_service_account}",
            "role": "roles/iam.serviceAccountTokenCreator",
            "condition": None,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    binding_digest = "sha256:" + hashlib.sha256(binding_material.encode()).hexdigest()
    role_steps = tuple(
        GrantStep(
            purpose=(
                f"Allow only the customer reader to read {role.removeprefix('roles/')} "
                "in this project."
            ),
            command=(
                f"gcloud projects add-iam-policy-binding {customer_project_id} \\\n"
                f"  --member='serviceAccount:{customer_reader_service_account}' \\\n"
                f"  --role='{role}' \\\n"
                f"  --condition=None"
            ),
        )
        for role in roles
    )
    delegation_step = GrantStep(
        purpose=(
            "Allow exactly the recorded Solvan reader identity to mint a short-lived "
            "token for this one customer reader service account."
        ),
        command=(
            "gcloud iam service-accounts add-iam-policy-binding \\\n"
            f"  {customer_reader_service_account} --project={customer_project_id} \\\n"
            f"  --member='serviceAccount:{solvan_service_account}' \\\n"
            "  --role='roles/iam.serviceAccountTokenCreator' \\\n"
            "  --condition=None"
        ),
    )
    return (*role_steps, delegation_step), binding_digest


def onboarding_plan(
    *,
    provider: str,
    posture: CredentialPosture,
    customer_project_id: str,
    solvan_service_account: str,
    customer_reader_service_account: str | None = None,
) -> OnboardingPlan:
    """Produce the copy-paste grants for one connection, or state why there are none."""

    if not customer_project_id:
        raise ConnectionPolicyError("a customer project is required to generate grants")

    if posture is CredentialPosture.FEDERATED_SHORT_LIVED:
        roles = _roles_for(provider)
        if not roles:
            raise ConnectionPolicyError(
                f"provider {provider} has no Google IAM role to grant; "
                "use a vendor key or the customer-side collector"
            )
        if not customer_reader_service_account:
            raise ConnectionPolicyError(
                "a customer reader service account is required for direct GCP onboarding"
            )
        if not customer_reader_service_account.endswith(".iam.gserviceaccount.com"):
            raise ConnectionPolicyError(
                "the customer reader must be a Google service-account email"
            )
        steps, binding_digest = _direct_gcp_grants(
            roles=roles,
            customer_project_id=customer_project_id,
            solvan_service_account=solvan_service_account,
            customer_reader_service_account=customer_reader_service_account,
        )
        return OnboardingPlan(
            posture=posture,
            summary=(
                "Run these in your own project. Solvan receives only a short-lived token "
                "for the customer reader and never holds a key; revoke by removing the "
                "service-account binding."
            ),
            steps=steps,
            secret_required=False,
            delegation_condition_digest=binding_digest,
        )

    if posture is CredentialPosture.STORED_LONG_LIVED:
        return OnboardingPlan(
            posture=posture,
            summary=(
                "Create a read-only vendor key, store it in Secret Manager under a "
                "customer-managed key, and give Solvan the reference. The key value "
                "is never sent to Solvan and never leaves your project."
            ),
            steps=(
                GrantStep(
                    purpose="Store the read-only vendor key under your own CMEK.",
                    command=(
                        f"gcloud secrets create solvan-{provider.lower()}-read \\\n"
                        f"  --project={customer_project_id} \\\n"
                        f"  --kms-key-name=projects/{customer_project_id}/locations/us/"
                        "keyRings/solvan/cryptoKeys/connections \\\n"
                        "  --data-file=./read-only-key.txt"
                    ),
                ),
                GrantStep(
                    purpose="Allow Solvan to read that one secret version, nothing else.",
                    command=(
                        f"gcloud secrets add-iam-policy-binding solvan-{provider.lower()}-read \\\n"
                        f"  --project={customer_project_id} \\\n"
                        f"  --member='serviceAccount:{solvan_service_account}' \\\n"
                        "  --role='roles/secretmanager.secretAccessor'"
                    ),
                ),
            ),
            secret_required=True,
        )

    return OnboardingPlan(
        posture=posture,
        summary=(
            "Deploy the Solvan actuator into your own project. It polls outbound, "
            "exposes no ingress, and holds every credential locally — Solvan stores "
            "nothing and can reach nothing."
        ),
        steps=(
            GrantStep(
                purpose="Deploy the actuator with its own service account.",
                command=(
                    "terraform apply \\\n"
                    '  -var="solvan_tenant=<your tenant id>" \\\n'
                    f'  -var="project_id={customer_project_id}" \\\n'
                    "  -target=module.solvan_actuator"
                ),
            ),
            GrantStep(
                purpose="Register the actuator identity so Solvan can verify its token.",
                command=(
                    f"gcloud iam service-accounts describe solvan-actuator@"
                    f"{customer_project_id}.iam.gserviceaccount.com \\\n"
                    "  --format='value(email)'"
                ),
            ),
        ),
        secret_required=False,
    )


def estate_onboarding_plan(
    *,
    providers: Sequence[str],
    customer_project_id: str,
    solvan_service_account: str,
    customer_reader_service_account: str | None = None,
) -> EstateOnboardingPlan:
    """Produce one grant plan for every direct-GCP capability chosen at once.

    Investigating an incident needs metrics and logs and audit and errors and
    traces, and each is its own connection so one can be revoked without losing
    the others. Their grants, however, are the same two commands against the
    same reader service account, so the customer receives them once: the roles
    are deduplicated, every one is bound to that single reader, and one exact
    service-account policy binding names the permitted Solvan identity.
    """

    chosen = tuple(providers)
    if not chosen:
        raise EstateSelectionError(
            "ESTATE_SELECTION_EMPTY", "at least one telemetry source must be chosen"
        )
    catalog = {item.provider: item.kind for item in CONNECTABLE_PROVIDERS}
    seen: set[str] = set()
    for provider in chosen:
        if provider in seen:
            raise EstateSelectionError(
                "ESTATE_PROVIDER_DUPLICATED", f"{provider} was chosen more than once"
            )
        seen.add(provider)
        if provider not in catalog:
            raise EstateSelectionError(
                "ESTATE_PROVIDER_UNKNOWN", f"{provider} is not offered for connection"
            )
        if catalog[provider] != "GCP_NATIVE" or not _roles_for(provider):
            raise EstateSelectionError(
                "ESTATE_PROVIDER_NOT_DIRECT_GCP",
                f"{provider} is not read through a customer reader service account",
            )
    if not customer_project_id:
        raise EstateSelectionError(
            "ESTATE_PROJECT_REQUIRED", "a customer project is required to generate grants"
        )
    if not customer_reader_service_account:
        raise EstateSelectionError(
            "ESTATE_READER_REQUIRED",
            "a customer reader service account is required for direct GCP onboarding",
        )
    if not customer_reader_service_account.endswith(".iam.gserviceaccount.com"):
        raise EstateSelectionError(
            "ESTATE_READER_NOT_A_SERVICE_ACCOUNT",
            "the customer reader must be a Google service-account email",
        )

    roles: list[str] = []
    for provider in chosen:
        for role in _roles_for(provider):
            if role not in roles:
                roles.append(role)
    steps, binding_digest = _direct_gcp_grants(
        roles=roles,
        customer_project_id=customer_project_id,
        solvan_service_account=solvan_service_account,
        customer_reader_service_account=customer_reader_service_account,
    )
    return EstateOnboardingPlan(
        posture=CredentialPosture.FEDERATED_SHORT_LIVED,
        providers=chosen,
        roles=tuple(roles),
        summary=(
            f"Run these once in your own project. One customer reader holds all "
            f"{len(roles)} role(s) for the {len(chosen)} source(s) you chose, Solvan "
            "receives only a short-lived token for that one account and never holds a "
            "key, and each source stays a separate connection: remove one role to "
            "revoke one capability, or the service-account binding to revoke them all."
        ),
        steps=steps,
        secret_required=False,
        delegation_condition_digest=binding_digest,
    )
