"""Fail-closed rules for tenant connections and customer-deployed actuators.

These are the executable form of specification 13 §8 invariants INV-T-01,
INV-T-04, INV-T-09, INV-T-10 and INV-T-12. Every case asserts that absence or
weakness refuses, never that it silently degrades.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from solvan.application.tenant_integration import (
    POSTURE_STRENGTH,
    PROVIDER_CAPABILITIES,
    ActuatorPosture,
    ActuatorRegistration,
    CapabilityObservation,
    ConnectionAuthenticationMode,
    ConnectionPolicyError,
    ConnectionRegistration,
    CredentialPosture,
    CredentialScopeVerdict,
    ExternalResourceScope,
    GcpResourceKind,
    HostKind,
    connectable_provider_projection,
    derive_availability,
)


def _verdict(**overrides: object) -> CredentialScopeVerdict:
    base: dict[str, object] = {
        "state": "VERIFIED_READ_ONLY",
        "provider": "DATADOG",
        "evaluated_at": datetime.now(UTC),
        "evidence_ref": "scope://datadog#sha256:" + "a" * 64,
        "observed_scope_count": 2,
    }
    base.update(overrides)
    return CredentialScopeVerdict(**base)  # type: ignore[arg-type]


def _refused(reason_code: str = "WRITE_SCOPE_PRESENT") -> CredentialScopeVerdict:
    return _verdict(
        state="REFUSED_WRITE_SCOPE",
        reason_code=reason_code,
        explanation="the vendor reports this key carries a write scope",
        remediation_kind="REGISTER_CREDENTIAL",
    )


def _connection(**overrides: object) -> ConnectionRegistration:
    base: dict[str, object] = {
        "display_name": "Payments telemetry",
        "kind": "GCP_NATIVE",
        "provider": "CLOUD_MONITORING",
        "credential_posture": CredentialPosture.FEDERATED_SHORT_LIVED,
        "residency_region": "europe-west1",
        "classification": "INTERNAL",
        "authentication_mode": ConnectionAuthenticationMode.GCP_SERVICE_ACCOUNT_IMPERSONATION,
        "solvan_delegator_principal": "serviceAccount:reader@solvan.iam.gserviceaccount.com",
        "customer_reader_principal": "serviceAccount:reader@customer.iam.gserviceaccount.com",
        "delegation_condition_digest": f"sha256:{'a' * 64}",
        "token_lifetime_seconds": 900,
        "resource_scope": ExternalResourceScope(
            resource_kind=GcpResourceKind.GCP_PROJECT,
            resource_id="payments-prod",
            workload_region="europe-west1",
            metrics_scoping_project_id=None,
            decision_ref="decision://tenant/payments-prod",
        ),
    }
    base.update(overrides)
    return ConnectionRegistration(**base)  # type: ignore[arg-type]


def _actuator(**overrides: object) -> ActuatorRegistration:
    base: dict[str, object] = {
        "connection_id": "con_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "host_kind": HostKind.CLOUD_RUN,
        "principal_email": "solvan-actuator@customer.iam.gserviceaccount.com",
        "expected_audience": "https://api.solvan.dev/actuator",
        "posture": ActuatorPosture.COLLECTOR,
        "image_digest": f"sha256:{'a' * 64}",
        "actuator_version": "0.1.0",
    }
    base.update(overrides)
    return ActuatorRegistration(**base)  # type: ignore[arg-type]


def test_direct_gcp_connection_must_be_exact_short_lived_impersonation() -> None:
    assert _connection().validated().credential_posture is CredentialPosture.FEDERATED_SHORT_LIVED
    with pytest.raises(ConnectionPolicyError, match="requires exact delegator"):
        _connection(customer_reader_principal=None).validated()
    with pytest.raises(ConnectionPolicyError, match="between 1 and 900"):
        _connection(token_lifetime_seconds=901).validated()
    with pytest.raises(ConnectionPolicyError, match="must not carry a stored secret"):
        _connection(credential_secret_ref="projects/p/secrets/s/versions/1").validated()
    with pytest.raises(ConnectionPolicyError, match="workload region"):
        _connection(
            resource_scope=ExternalResourceScope(
                resource_kind=GcpResourceKind.GCP_PROJECT,
                resource_id="payments-prod",
                workload_region="Europe West 2",
                metrics_scoping_project_id=None,
                decision_ref="decision://tenant/payments-prod",
            )
        ).validated()


def test_stored_vendor_key_requires_cmek_and_verified_read_only_scope() -> None:
    stored: dict[str, object] = {
        "credential_posture": CredentialPosture.STORED_LONG_LIVED,
        "provider": "DATADOG",
        "kind": "VENDOR_API",
        "authentication_mode": ConnectionAuthenticationMode.STORED_SECRET_REFERENCE,
        "solvan_delegator_principal": None,
        "customer_reader_principal": None,
        "delegation_condition_digest": None,
        "token_lifetime_seconds": None,
        "resource_scope": None,
    }
    with pytest.raises(ConnectionPolicyError, match="Secret Manager reference"):
        _connection(**stored).validated()
    with pytest.raises(ConnectionPolicyError, match="verified read-only"):
        _connection(
            **stored,
            credential_secret_ref="projects/p/secrets/s/versions/1",
            credential_cmek_key_ref="projects/p/locations/us/keyRings/r/cryptoKeys/k",
        ).validated()
    accepted = _connection(
        **stored,
        credential_secret_ref="projects/p/secrets/s/versions/1",
        credential_cmek_key_ref="projects/p/locations/us/keyRings/r/cryptoKeys/k",
        scope_verification=_verdict(),
    ).validated()
    assert accepted.credential_posture is CredentialPosture.STORED_LONG_LIVED
    assert accepted.read_only_scope_verified is True


def _stored(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "credential_posture": CredentialPosture.STORED_LONG_LIVED,
        "provider": "DATADOG",
        "kind": "VENDOR_API",
        "authentication_mode": ConnectionAuthenticationMode.STORED_SECRET_REFERENCE,
        "solvan_delegator_principal": None,
        "customer_reader_principal": None,
        "delegation_condition_digest": None,
        "token_lifetime_seconds": None,
        "resource_scope": None,
        "credential_secret_ref": "projects/p/secrets/s/versions/1",
        "credential_cmek_key_ref": "projects/p/locations/us/keyRings/r/cryptoKeys/k",
    }
    base.update(overrides)
    return base


def test_read_only_verification_cannot_be_asserted_by_whoever_registers() -> None:
    """The fact is derived from a verdict; there is no field to claim it with.

    This is the defect the field existed as: a caller-supplied boolean made the
    schema's read-only constraint prove only that somebody had ticked a box.
    """

    with pytest.raises(TypeError):
        _connection(**_stored(), read_only_scope_verified=True)

    assert _connection(**_stored()).read_only_scope_verified is False


def test_a_key_proven_to_carry_write_scope_is_refused_with_its_reason() -> None:
    with pytest.raises(ConnectionPolicyError, match="WRITE_SCOPE_PRESENT"):
        _connection(**_stored(), scope_verification=_refused()).validated()


def test_a_key_whose_scope_could_not_be_established_is_never_recorded_verified() -> None:
    unverifiable = _verdict(
        state="UNVERIFIABLE",
        provider="NEW_RELIC",
        reason_code="NO_SCOPE_INTROSPECTION",
        explanation="this provider exposes no way to inspect a key's scope",
        remediation_kind="CONTACT_PROVIDER",
        observed_scope_count=0,
    )
    registration = _connection(**_stored(provider="NEW_RELIC"), scope_verification=unverifiable)

    assert registration.read_only_scope_verified is False
    with pytest.raises(ConnectionPolicyError, match="NO_SCOPE_INTROSPECTION"):
        registration.validated()


def test_a_verification_for_another_provider_does_not_clear_this_connection() -> None:
    with pytest.raises(ConnectionPolicyError, match="different provider"):
        _connection(
            **_stored(provider="GRAFANA"), scope_verification=_verdict(provider="DATADOG")
        ).validated()


def test_only_a_stored_credential_carries_a_scope_verification() -> None:
    with pytest.raises(ConnectionPolicyError, match="only a stored credential"):
        _connection(scope_verification=_verdict(provider="CLOUD_MONITORING")).validated()


def test_a_scope_verdict_cannot_claim_read_only_while_naming_a_refusal() -> None:
    with pytest.raises(ConnectionPolicyError, match="disagree"):
        _verdict(reason_code="WRITE_SCOPE_PRESENT").validated()
    with pytest.raises(ConnectionPolicyError, match="disagree"):
        _verdict(state="UNVERIFIABLE").validated()
    with pytest.raises(ConnectionPolicyError, match="explanation and a next step"):
        CredentialScopeVerdict(
            state="UNVERIFIABLE",
            provider="DATADOG",
            evaluated_at=datetime.now(UTC),
            evidence_ref="scope://datadog#sha256:" + "a" * 64,
            reason_code="VENDOR_UNREACHABLE",
        ).validated()
    with pytest.raises(ConnectionPolicyError, match="cite the inspection"):
        _verdict(evidence_ref="").validated()


def test_customer_side_connection_hands_solvan_nothing() -> None:
    customer_side: dict[str, object] = {
        "credential_posture": CredentialPosture.CUSTOMER_SIDE_NONE,
        "provider": "SOLVAN_COLLECTOR",
        "kind": "COLLECTOR",
        "authentication_mode": ConnectionAuthenticationMode.CUSTOMER_SIDE_NONE,
        "solvan_delegator_principal": None,
        "customer_reader_principal": None,
        "delegation_condition_digest": None,
        "token_lifetime_seconds": None,
        "resource_scope": None,
    }
    assert _connection(**customer_side).validated()
    with pytest.raises(ConnectionPolicyError, match="hand Solvan no credential"):
        _connection(
            **{
                **customer_side,
                "solvan_delegator_principal": (
                    "serviceAccount:reader@solvan.iam.gserviceaccount.com"
                ),
            }
        ).validated()


def test_relay_transport_is_a_customer_side_only_reserved_connection() -> None:
    transport = _connection(
        provider="SOLVAN_RELAY",
        kind="RELAY",
        credential_posture=CredentialPosture.CUSTOMER_SIDE_NONE,
        authentication_mode=ConnectionAuthenticationMode.CUSTOMER_SIDE_NONE,
        solvan_delegator_principal=None,
        customer_reader_principal=None,
        delegation_condition_digest=None,
        token_lifetime_seconds=None,
        resource_scope=None,
    ).validated()
    assert transport.kind == "RELAY"
    with pytest.raises(ConnectionPolicyError, match="must use the SOLVAN_RELAY provider"):
        _connection(
            provider="CLOUD_MONITORING",
            kind="RELAY",
            credential_posture=CredentialPosture.CUSTOMER_SIDE_NONE,
            authentication_mode=ConnectionAuthenticationMode.CUSTOMER_SIDE_NONE,
            solvan_delegator_principal=None,
            customer_reader_principal=None,
            delegation_condition_digest=None,
            token_lifetime_seconds=None,
            resource_scope=None,
        ).validated()


def test_customer_side_posture_is_the_strongest_and_stored_keys_the_weakest() -> None:
    assert (
        POSTURE_STRENGTH[CredentialPosture.CUSTOMER_SIDE_NONE]
        > POSTURE_STRENGTH[CredentialPosture.FEDERATED_SHORT_LIVED]
        > POSTURE_STRENGTH[CredentialPosture.STORED_LONG_LIVED]
    )


def test_development_host_can_never_hold_production_mutation_capability() -> None:
    assert _actuator(host_kind=HostKind.DEV_LOCAL).production_eligible is False
    assert _actuator(host_kind=HostKind.DEV_LOCAL).validated()
    with pytest.raises(ConnectionPolicyError, match="development host can never"):
        _actuator(
            host_kind=HostKind.DEV_LOCAL,
            posture=ActuatorPosture.REMEDIATE,
            policy_hash=f"sha256:{'b' * 64}",
            customer_audit_sink_ref="projects/p/logs/solvan",
        ).validated()


def test_key_file_host_requires_a_recorded_risk_acceptance() -> None:
    with pytest.raises(ConnectionPolicyError, match="recorded risk acceptance"):
        _actuator(host_kind=HostKind.ONPREM_KEYFILE).validated()
    accepted = _actuator(
        host_kind=HostKind.ONPREM_KEYFILE, risk_acceptance_ref="RISK-2026-014"
    ).validated()
    # A recorded risk acceptance permits registration; it does not by itself
    # confer production eligibility (specification 13).
    assert accepted.production_eligible is False


def test_key_file_host_is_not_production_eligible_until_explicitly_decided() -> None:
    """Eligibility for a long-lived-credential host is a decision, not a default.

    The schema previously stated INV-T-09 as an equality, which forced every
    host that was not `DEV_LOCAL` to be eligible — a key-file host could not be
    registered as ineligible even though the invariant says it is not eligible
    by default.
    """

    opted_in = _actuator(
        host_kind=HostKind.ONPREM_KEYFILE,
        risk_acceptance_ref="RISK-2026-014",
        production_eligible_override=True,
    ).validated()
    assert opted_in.production_eligible is True
    with pytest.raises(ConnectionPolicyError, match="development host can never"):
        _actuator(host_kind=HostKind.DEV_LOCAL, production_eligible_override=True).validated()


def test_mutation_posture_refuses_without_customer_policy_and_customer_audit() -> None:
    with pytest.raises(ConnectionPolicyError, match="customer-authored policy; absence refuses"):
        _actuator(posture=ActuatorPosture.REMEDIATE).validated()
    with pytest.raises(ConnectionPolicyError, match="customer-owned audit sink"):
        _actuator(posture=ActuatorPosture.REMEDIATE, policy_hash=f"sha256:{'b' * 64}").validated()
    assert _actuator(
        posture=ActuatorPosture.REMEDIATE,
        policy_hash=f"sha256:{'b' * 64}",
        customer_audit_sink_ref="projects/p/logs/solvan",
    ).validated()


def test_actuator_audience_must_be_an_https_identity() -> None:
    with pytest.raises(ConnectionPolicyError, match="HTTPS identity"):
        _actuator(expected_audience="http://api.solvan.dev/actuator").validated()


def test_unavailable_capability_must_name_the_missing_grant() -> None:
    with pytest.raises(ConnectionPolicyError, match="grant that is missing"):
        CapabilityObservation(
            capability="audit.read",
            available=False,
            missing_grant=None,
            probe_receipt_ref="gs://probe/1",
            outcome="DENIED",
        ).validated()
    observed = CapabilityObservation(
        capability="audit.read",
        available=False,
        missing_grant="roles/logging.privateLogViewer",
        probe_receipt_ref="gs://probe/1",
        outcome="DENIED",
    ).validated()
    assert observed.missing_grant == "roles/logging.privateLogViewer"


def _observation(capability: str, outcome: str) -> CapabilityObservation:
    return CapabilityObservation(
        capability=capability,
        available=outcome == "GRANTED",
        missing_grant=None if outcome == "GRANTED" else f"roles/{capability}",
        probe_receipt_ref=f"gs://probe/{capability}",
        outcome=outcome,  # type: ignore[arg-type]
    )


def test_every_capability_granted_is_ready_and_carries_no_remediation() -> None:
    verdict = derive_availability(
        lifecycle="ENABLED",
        observations=(_observation("metrics.read", "GRANTED"),),
    )

    assert verdict.availability == "READY"
    assert verdict.reason_code is None
    assert verdict.remediation_kind is None


@pytest.mark.parametrize(
    ("outcome", "availability", "reason_code", "remediation"),
    [
        ("DENIED", "DENIED", "PERMISSION_DENIED", "GRANT_ROLE"),
        ("UNREACHABLE", "UNREACHABLE", "PROVIDER_UNREACHABLE", "RETRY_PROBE"),
        ("MISCONFIGURED", "MISCONFIGURED", "API_NOT_ENABLED", "ENABLE_API"),
        ("NOT_PROBED", "NOT_CONFIGURED", "NOT_PROBEABLE_HERE", "REGISTER_CREDENTIAL"),
    ],
)
def test_each_failing_outcome_keeps_its_own_state_and_next_step(
    outcome: str, availability: str, reason_code: str, remediation: str
) -> None:
    """Specification 13 §4.

    A permission refused, a provider unreachable, and an API not enabled need
    three different actions from the customer. Collapsing them into one state
    tells an operator that something failed without telling them what to do.
    """
    verdict = derive_availability(
        lifecycle="ENABLED", observations=(_observation("metrics.read", outcome),)
    )

    assert verdict.availability == availability
    assert verdict.reason_code == reason_code
    assert verdict.remediation_kind == remediation
    assert verdict.explanation
    assert verdict.receipt_ref


def test_an_unreachable_probe_never_reports_a_denial() -> None:
    """An unreachable provider has refused nothing.

    Reporting it as DENIED would send the customer to grant a role that is
    already granted, so the least conclusive outcome decides.
    """
    verdict = derive_availability(
        lifecycle="ENABLED",
        observations=(
            _observation("logs.read", "DENIED"),
            _observation("metrics.read", "UNREACHABLE"),
        ),
    )

    assert verdict.availability == "UNREACHABLE"


def test_some_capabilities_proven_is_degraded_and_names_the_incomplete_one() -> None:
    verdict = derive_availability(
        lifecycle="ENABLED",
        observations=(
            _observation("metrics.read", "GRANTED"),
            _observation("audit.read", "DENIED"),
        ),
    )

    assert verdict.availability == "DEGRADED"
    assert verdict.reason_code == "PARTIAL_CAPABILITY"
    assert "audit.read" in (verdict.explanation or "")
    assert verdict.missing_grant == "roles/audit.read"


def test_an_administrator_decision_outranks_any_probe() -> None:
    verdict = derive_availability(
        lifecycle="REVOKED",
        observations=(_observation("metrics.read", "GRANTED"),),
    )

    assert verdict.availability == "DISABLED"
    assert verdict.remediation_kind == "REENABLE_CONNECTION"


def test_never_probed_and_expired_proof_are_different_states() -> None:
    never = derive_availability(lifecycle="ENABLED", observations=())
    expired = derive_availability(
        lifecycle="ENABLED",
        observations=(_observation("metrics.read", "GRANTED"),),
        proof_expired=True,
    )

    assert never.availability == "NOT_CONFIGURED"
    assert expired.availability == "STALE"


def test_a_capability_cannot_claim_availability_its_outcome_denies() -> None:
    with pytest.raises(ConnectionPolicyError, match="disagree"):
        CapabilityObservation(
            capability="metrics.read",
            available=True,
            missing_grant=None,
            probe_receipt_ref="gs://probe/1",
            outcome="DENIED",
        ).validated()


def test_every_connectable_provider_has_a_probe_and_a_declared_kind() -> None:
    """The console may only offer what Solvan can actually observe.

    Offering a provider with no probed capability would let an operator
    onboard an estate whose availability can never be established, leaving a
    permanently unprovable connection in the projection.
    """

    offered = {item["provider"] for item in connectable_provider_projection()}

    assert offered == set(PROVIDER_CAPABILITIES)
    for item in connectable_provider_projection():
        assert item["kind"] in {"GCP_NATIVE", "VENDOR_API", "COLLECTOR"}
        assert item["label"]


def test_the_catalog_offers_exactly_the_seven_google_sources_solvan_can_probe() -> None:
    """A source that can never become usable is not an offer, it is a dead end.

    Kubernetes declared a capability with no probe, and the Solvan collector was
    excluded from Google probing, so each resolved NOT_PROBED, then
    NOT_CONFIGURED, and could never reach READY however it was configured — the
    same dead end for which the four vendor sources were withdrawn. Withdrawing
    an offer is not deleting a value: the schema still accepts both, so an
    existing connection keeps rendering and nothing that worked stopped working.
    """

    offered = {item["provider"] for item in connectable_provider_projection()}

    assert offered == {
        "CLOUD_MONITORING",
        "CLOUD_LOGGING",
        "CLOUD_AUDIT",
        "ERROR_REPORTING",
        "CLOUD_TRACE",
        "ASSET_INVENTORY",
        "MANAGED_PROMETHEUS",
    }
    assert {"KUBERNETES", "SOLVAN_COLLECTOR"}.isdisjoint(offered)
    assert {"KUBERNETES", "SOLVAN_COLLECTOR"} <= _schema_connection_providers()
    assert all(item["kind"] == "GCP_NATIVE" for item in connectable_provider_projection())


def test_the_connectable_catalog_only_names_providers_the_schema_accepts() -> None:
    """A catalog entry the DDL would reject is an unusable offer."""

    accepted = _schema_connection_providers()

    for item in connectable_provider_projection():
        assert item["provider"] in accepted


def _schema_connection_providers() -> set[str]:
    import re
    from pathlib import Path

    ddl = Path("specs/artifacts/schema.sql").read_text(encoding="utf-8")
    table = ddl.split("CREATE TABLE tenant_connections", 1)[1]
    clause = table.split("provider text NOT NULL CHECK (provider IN", 1)[1]
    return set(re.findall(r"'([A-Z_]+)'", clause.split("))", 1)[0]))
