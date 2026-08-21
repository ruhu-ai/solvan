"""Capability is observed, grants are generated, and no credential is accepted.

These cover the three claims the Integrations surface makes: that a capability
matrix reports a probe result rather than configuration, that onboarding hands
the customer commands instead of asking them for a secret, and that the
registration route cannot be used to smuggle a key value into Solvan.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from apps.api import connections as connections_api
from apps.api.connections import ConnectionRequest
from solvan.application.onboarding import (
    INVESTIGATION_PROVIDERS,
    EstateOnboardingPlan,
    EstateSelectionError,
    estate_onboarding_plan,
    onboarding_plan,
)
from solvan.application.tenant_integration import (
    PROVIDER_CAPABILITIES,
    ConnectionPolicyError,
    CredentialPosture,
)
from solvan.platform.capability_probe import ProbeTarget, probe_connection


@dataclass
class _Response:
    status_code: int


class _Transport:
    """Records every request so a probe cannot silently mutate or page."""

    def __init__(self, codes: dict[str, int]) -> None:
        self._codes = codes
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def _answer(self, method: str, url: str, **kwargs: object) -> _Response:
        self.calls.append((method, url, kwargs))
        for fragment, code in self._codes.items():
            if fragment in url:
                return _Response(code)
        return _Response(200)

    def get(self, url: str, **kwargs: object) -> _Response:
        return self._answer("GET", url, **kwargs)

    def post(self, url: str, **kwargs: object) -> _Response:
        return self._answer("POST", url, **kwargs)


def test_probe_reports_the_exact_missing_grant_on_denial() -> None:
    transport = _Transport({"logging.googleapis.com": 403})
    observed = probe_connection(
        transport, target=ProbeTarget(provider="CLOUD_LOGGING", gcp_project_id="acme-prod")
    )
    assert len(observed) == 1
    assert observed[0].capability == "logs.read"
    assert observed[0].available is False
    assert observed[0].missing_grant == "roles/logging.viewer"


def test_probe_reports_availability_only_from_a_successful_response() -> None:
    transport = _Transport({})
    observed = probe_connection(
        transport, target=ProbeTarget(provider="CLOUD_MONITORING", gcp_project_id="acme-prod")
    )
    assert observed[0].available is True
    assert observed[0].missing_grant is None
    assert observed[0].probe_receipt_ref.startswith("probe://cloud_monitoring/metrics.read#sha256:")


def test_probe_never_confuses_an_unreachable_provider_with_a_denial() -> None:
    class _Broken:
        def get(self, url: str, **kwargs: object) -> _Response:
            raise TimeoutError("network unreachable")

        def post(self, url: str, **kwargs: object) -> _Response:
            raise TimeoutError("network unreachable")

    observed = probe_connection(
        _Broken(), target=ProbeTarget(provider="CLOUD_TRACE", gcp_project_id="acme-prod")
    )
    assert observed[0].available is False
    assert "could not reach the provider" in (observed[0].missing_grant or "")


def test_probe_distinguishes_a_disabled_api_from_a_missing_role() -> None:
    transport = _Transport({"clouderrorreporting": 404})
    observed = probe_connection(
        transport, target=ProbeTarget(provider="ERROR_REPORTING", gcp_project_id="acme-prod")
    )
    assert "API not enabled" in (observed[0].missing_grant or "")


def test_probe_requests_one_item_and_never_mutates() -> None:
    transport = _Transport({})
    probe_connection(
        transport, target=ProbeTarget(provider="CLOUD_MONITORING", gcp_project_id="acme-prod")
    )
    method, _, kwargs = transport.calls[0]
    assert method == "GET"
    assert kwargs["params"] == {"pageSize": 1}


@pytest.mark.parametrize("provider", ["SOLVAN_COLLECTOR", "KUBERNETES"])
def test_a_withdrawn_provider_is_refused_before_any_probe_is_issued(provider: str) -> None:
    """Neither could ever report an available capability, so neither is offered.

    Kubernetes had no entry in the probe table and the collector was excluded
    from Google probing, so each resolved NOT_PROBED, then NOT_CONFIGURED, and
    could never reach READY however it was configured. The refusal they now get
    is the earlier and better one: it happens before a call is made, so nothing
    can interpret a response as a capability.
    """

    transport = _Transport({})
    with pytest.raises(ConnectionPolicyError, match="declares no capability"):
        probe_connection(transport, target=ProbeTarget(provider=provider, gcp_project_id="acme"))
    assert transport.calls == [], "a withdrawn provider must not be probed against Google"


def test_federated_onboarding_asks_for_no_secret_and_emits_exact_grants() -> None:
    plan = onboarding_plan(
        provider="CLOUD_AUDIT",
        posture=CredentialPosture.FEDERATED_SHORT_LIVED,
        customer_project_id="acme-prod",
        solvan_service_account="solvan-reader@solvan.iam.gserviceaccount.com",
        customer_reader_service_account="solvan-reader@acme-prod.iam.gserviceaccount.com",
    )
    assert plan.secret_required is False
    joined = "\n".join(step.command for step in plan.steps)
    assert "add-iam-policy-binding acme-prod" in joined
    assert "roles/logging.privateLogViewer" in joined
    assert "solvan-reader@solvan.iam.gserviceaccount.com" in joined
    assert "solvan-reader@acme-prod.iam.gserviceaccount.com" in joined
    assert "resource.name" not in joined
    assert "--condition=None" in joined
    assert plan.delegation_condition_digest is not None


_SOLVAN_READER = "solvan-reader@solvan.iam.gserviceaccount.com"
_CUSTOMER_READER = "solvan-reader@acme-prod.iam.gserviceaccount.com"


def _estate(providers: Sequence[str]) -> EstateOnboardingPlan:
    return estate_onboarding_plan(
        providers=providers,
        customer_project_id="acme-prod",
        solvan_service_account=_SOLVAN_READER,
        customer_reader_service_account=_CUSTOMER_READER,
    )


def test_one_estate_plan_binds_every_chosen_role_to_the_one_customer_reader() -> None:
    """Seven passes over the same dialog produced seven identical delegations.

    The connections stay separate; only the grants are consolidated. Every role
    must therefore name the one reader, one delegation must name it too, and no
    command may appear twice — Managed Prometheus and Cloud Monitoring both
    require roles/monitoring.viewer, which is the case that would repeat.
    """

    plan = _estate(("CLOUD_MONITORING", "CLOUD_LOGGING", "CLOUD_AUDIT", "MANAGED_PROMETHEUS"))

    assert plan.posture is CredentialPosture.FEDERATED_SHORT_LIVED
    assert plan.roles == (
        "roles/monitoring.viewer",
        "roles/logging.viewer",
        "roles/logging.privateLogViewer",
    )
    commands = [step.command for step in plan.steps]
    assert len(commands) == len(set(commands)) == 4
    assert all(_CUSTOMER_READER in command for command in commands)
    assert sum(1 for command in commands if "serviceAccountTokenCreator" in command) == 1
    assert plan.delegation_condition_digest.startswith("sha256:")


def test_the_consolidated_grants_are_the_same_commands_a_single_source_produces() -> None:
    """One plan for many sources may not become a second, divergent grant shape."""

    one = onboarding_plan(
        provider="CLOUD_AUDIT",
        posture=CredentialPosture.FEDERATED_SHORT_LIVED,
        customer_project_id="acme-prod",
        solvan_service_account=_SOLVAN_READER,
        customer_reader_service_account=_CUSTOMER_READER,
    )
    many = _estate(("CLOUD_AUDIT",))

    assert [step.command for step in many.steps] == [step.command for step in one.steps]
    assert many.delegation_condition_digest == one.delegation_condition_digest


def test_the_default_selection_is_what_an_incident_investigation_reads() -> None:
    """Metrics, logs, audit, errors, and traces. Inventory and PromQL are extra.

    Pre-ticking a source an investigation does not read would ask a customer to
    grant a role for nothing, and leaving one out would send an operator back
    through onboarding mid-incident.
    """

    assert INVESTIGATION_PROVIDERS == (
        "CLOUD_MONITORING",
        "CLOUD_LOGGING",
        "CLOUD_AUDIT",
        "ERROR_REPORTING",
        "CLOUD_TRACE",
    )
    assert set(INVESTIGATION_PROVIDERS) <= set(PROVIDER_CAPABILITIES)
    assert set(PROVIDER_CAPABILITIES) - set(INVESTIGATION_PROVIDERS) == {
        "ASSET_INVENTORY",
        "MANAGED_PROMETHEUS",
    }
    plan = _estate(INVESTIGATION_PROVIDERS)
    assert plan.roles == (
        "roles/monitoring.viewer",
        "roles/logging.viewer",
        "roles/logging.privateLogViewer",
        "roles/errorreporting.viewer",
        "roles/cloudtrace.user",
    )


@pytest.mark.parametrize(
    ("providers", "reason_code"),
    [
        ((), "ESTATE_SELECTION_EMPTY"),
        (("CLOUD_MONITORING", "DATADOG"), "ESTATE_PROVIDER_UNKNOWN"),
        (("SOLVAN_COLLECTOR",), "ESTATE_PROVIDER_UNKNOWN"),
        (("KUBERNETES",), "ESTATE_PROVIDER_UNKNOWN"),
        (("CLOUD_LOGGING", "CLOUD_LOGGING"), "ESTATE_PROVIDER_DUPLICATED"),
    ],
)
def test_an_unusable_selection_is_refused_with_a_closed_reason_code(
    providers: tuple[str, ...], reason_code: str
) -> None:
    """Each refusal sends the operator somewhere different, so each has a code."""

    with pytest.raises(EstateSelectionError) as refusal:
        _estate(providers)

    assert refusal.value.reason_code == reason_code
    assert isinstance(refusal.value, ConnectionPolicyError)


@pytest.mark.parametrize(
    ("reader", "reason_code"),
    [
        (None, "ESTATE_READER_REQUIRED"),
        ("", "ESTATE_READER_REQUIRED"),
        ("solvan-reader@acme-prod.example.com", "ESTATE_READER_NOT_A_SERVICE_ACCOUNT"),
    ],
)
def test_a_missing_or_unusable_customer_reader_refuses_the_whole_plan(
    reader: str | None, reason_code: str
) -> None:
    with pytest.raises(EstateSelectionError) as refusal:
        estate_onboarding_plan(
            providers=("CLOUD_MONITORING",),
            customer_project_id="acme-prod",
            solvan_service_account=_SOLVAN_READER,
            customer_reader_service_account=reader,
        )

    assert refusal.value.reason_code == reason_code


def test_an_estate_plan_without_a_project_grants_nothing() -> None:
    with pytest.raises(EstateSelectionError) as refusal:
        estate_onboarding_plan(
            providers=("CLOUD_MONITORING",),
            customer_project_id="",
            solvan_service_account=_SOLVAN_READER,
            customer_reader_service_account=_CUSTOMER_READER,
        )

    assert refusal.value.reason_code == "ESTATE_PROJECT_REQUIRED"


def test_stored_key_onboarding_requires_a_reference_and_never_the_value() -> None:
    plan = onboarding_plan(
        provider="DATADOG",
        posture=CredentialPosture.STORED_LONG_LIVED,
        customer_project_id="acme-prod",
        solvan_service_account="solvan-reader@solvan.iam.gserviceaccount.com",
    )
    assert plan.secret_required is True
    assert "never sent to Solvan" in plan.summary
    assert any("secretmanager.secretAccessor" in step.command for step in plan.steps)


def test_collector_onboarding_grants_solvan_nothing() -> None:
    plan = onboarding_plan(
        provider="SOLVAN_COLLECTOR",
        posture=CredentialPosture.CUSTOMER_SIDE_NONE,
        customer_project_id="acme-prod",
        solvan_service_account="solvan-reader@solvan.iam.gserviceaccount.com",
    )
    assert plan.secret_required is False
    assert "polls outbound" in plan.summary
    assert not any("add-iam-policy-binding" in step.command for step in plan.steps)


def test_onboarding_refuses_a_provider_that_is_not_registered() -> None:
    """An unregistered provider has no capability set, so it cannot be planned.

    Refusing here is what keeps the console from offering a source that could
    be selected and onboarded and could then never be probed into use.
    """

    with pytest.raises(ConnectionPolicyError, match="declares no capability"):
        onboarding_plan(
            provider="DATADOG",
            posture=CredentialPosture.FEDERATED_SHORT_LIVED,
            customer_project_id="acme-prod",
            solvan_service_account="solvan-reader@solvan.iam.gserviceaccount.com",
        )


def test_registration_rejects_a_pasted_key_and_accepts_only_a_reference() -> None:
    base: dict[str, object] = {
        "schema_version": 1,
        "display_name": "Checkout observability",
        "kind": "VENDOR_API",
        "provider": "DATADOG",
        "credential_posture": "STORED_LONG_LIVED",
        "authentication_mode": "STORED_SECRET_REFERENCE",
        "residency_region": "europe-west1",
        "classification": "INTERNAL",
    }
    with pytest.raises(ValidationError):
        # A raw key must not satisfy the credential field.
        ConnectionRequest(**base, credential_secret_ref="dd-api-key-0123456789abcdef")
    accepted = ConnectionRequest(
        **base, credential_secret_ref="projects/acme/secrets/datadog-read/versions/3"
    )
    assert accepted.credential_secret_ref == "projects/acme/secrets/datadog-read/versions/3"


@pytest.mark.parametrize("alias", ["latest", "LATEST", "current"])
def test_a_floating_secret_version_cannot_be_registered(alias: str) -> None:
    """An alias would let a write-capable key replace a verified one unseen.

    A version's payload is immutable, so pinning one means the key whose scope
    was proved read-only is the key every later read resolves. An alias follows
    the newest payload, and nothing in Solvan would change or be re-checked.
    """

    base = {
        "schema_version": 1,
        "display_name": "Checkout observability",
        "kind": "VENDOR_API",
        "provider": "DATADOG",
        "credential_posture": "STORED_LONG_LIVED",
        "authentication_mode": "STORED_SECRET_REFERENCE",
        "residency_region": "europe-west1",
        "classification": "INTERNAL",
    }
    with pytest.raises(ValidationError):
        ConnectionRequest(
            **base, credential_secret_ref=f"projects/acme/secrets/datadog-read/versions/{alias}"
        )


_STORED_KEY_REQUEST: dict[str, object] = {
    "schema_version": 1,
    "display_name": "Checkout observability",
    "kind": "VENDOR_API",
    "provider": "GRAFANA",
    "credential_posture": "STORED_LONG_LIVED",
    "authentication_mode": "STORED_SECRET_REFERENCE",
    "residency_region": "europe-west1",
    "classification": "INTERNAL",
    "credential_secret_ref": "projects/acme-prod/secrets/grafana-read/versions/3",
    "credential_cmek_key_ref": "projects/acme-prod/locations/eu/keyRings/r/cryptoKeys/k",
}


def test_registration_refuses_a_caller_asserted_read_only_verification() -> None:
    """The control that justifies holding a long-lived key is not a request field.

    It was one: the schema's "read-only verified" constraint therefore proved
    only that whoever registered the connection had ticked a box.
    """

    assert "read_only_scope_verified" not in ConnectionRequest.model_fields
    with pytest.raises(ValidationError, match="read_only_scope_verified"):
        ConnectionRequest(**_STORED_KEY_REQUEST, read_only_scope_verified=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="read_only_scope_verified"):
        ConnectionRequest(**_STORED_KEY_REQUEST, read_only_scope_verified=False)  # type: ignore[arg-type]


def test_a_deployment_that_cannot_verify_a_stored_key_refuses_it() -> None:
    """Absence of a verifier is not evidence of a read-only key."""

    def _refuse() -> object:
        raise RuntimeError("no application default credentials")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(connections_api, "authorized_session", _refuse)
        verdict = connections_api._stored_key_scope_verdict(
            provider="GRAFANA", credential_secret_ref="projects/acme-prod/secrets/g/versions/1"
        )

    assert verdict.state == "UNVERIFIABLE"
    assert verdict.reason_code == "VERIFIER_UNAVAILABLE"
    assert verdict.remediation_kind == "FIX_CONFIGURATION"


def test_an_inspection_host_outside_the_vendor_domain_refuses_the_registration() -> None:
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("SOLVAN_GRAFANA_API_HOST", "grafana.attacker.example")
        verdict = connections_api._stored_key_scope_verdict(
            provider="GRAFANA", credential_secret_ref="projects/acme-prod/secrets/g/versions/1"
        )

    assert verdict.reason_code == "VERIFIER_UNAVAILABLE"


def test_the_registration_route_derives_the_verdict_from_the_vendor_itself() -> None:
    """The wiring is real: the route inspects the key rather than trusting anyone."""

    key = "glsa-not-a-real-token-0123456789"
    requested: list[str] = []

    class _SecretResponse:
        def raise_for_status(self) -> None: ...

        def json(self) -> object:
            return {"payload": {"data": base64.b64encode(key.encode()).decode()}}

    class _Session:
        def get(self, url: str, *, timeout: int) -> _SecretResponse:
            requested.append(url)
            return _SecretResponse()

    class _VendorResponse:
        status_code = 200

        def json(self) -> object:
            return {"dashboards:read": ["dashboards:*"], "teams:write": ["teams:*"]}

    def _vendor_get(url: str, **kwargs: Any) -> _VendorResponse:
        requested.append(url)
        assert kwargs["headers"] == {"Authorization": f"Bearer {key}"}
        return _VendorResponse()

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("SOLVAN_GRAFANA_API_HOST", "acme.grafana.net")
        patch.setattr(connections_api, "authorized_session", _Session)
        patch.setattr(httpx, "get", _vendor_get)
        verdict = connections_api._stored_key_scope_verdict(
            provider="GRAFANA",
            credential_secret_ref="projects/acme-prod/secrets/grafana-read/versions/3",
        )

    assert verdict.state == "REFUSED_WRITE_SCOPE"
    assert verdict.reason_code == "WRITE_SCOPE_PRESENT"
    assert all(key not in url for url in requested)
    assert "acme.grafana.net/api/access-control/user/permissions" in requested[-1]


def test_registration_refuses_unknown_fields_so_a_secret_cannot_ride_along() -> None:
    with pytest.raises(ValidationError):
        ConnectionRequest(
            schema_version=1,
            display_name="Payments telemetry",
            kind="GCP_NATIVE",
            provider="CLOUD_MONITORING",
            credential_posture="FEDERATED_SHORT_LIVED",
            residency_region="europe-west1",
            classification="INTERNAL",
            api_key="super-secret",  # type: ignore[call-arg]
        )
