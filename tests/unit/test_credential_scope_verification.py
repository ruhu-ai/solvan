"""Read-only scope is proven against the vendor, or the key is refused.

Specification 13 §3.3 permits Solvan to hold a long-lived customer key only
after onboarding has verified the key is read-only scoped. Every case here
asserts that an unproven key refuses with a reason an operator can act on, and
that the key value has no path into a verdict, an explanation, or a request URL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from solvan.application.credential_scope_verification import (
    HttpVendorScopeInspector,
    OpaqueCredential,
    ScopeReport,
    verify_read_only_scope,
)
from solvan.application.tenant_integration import ConnectionPolicyError

_KEY = "glsa-Z2E1bWJsZS1zZWNyZXQtdmFsdWU-0123456789"
_KEY_BYTES = _KEY.encode()
_SECRET_REF = "projects/acme/secrets/grafana-read/versions/3"


@dataclass
class _Response:
    status_code: int
    body: object = None

    def json(self) -> object:
        if self.body is None:
            raise ValueError("no JSON body")
        return self.body


class _Transport:
    """Records every request so a leak into a URL or a mutation cannot hide."""

    def __init__(self, response: _Response | Exception) -> None:
        self._response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append((url, kwargs))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


class _Secrets:
    def __init__(self, material: bytes | Exception = _KEY_BYTES) -> None:
        self._material = material
        self.requested: list[str] = []

    def access(self, resource: str, *, max_bytes: int = 16_384) -> bytes:
        self.requested.append(resource)
        if isinstance(self._material, Exception):
            raise self._material
        return self._material


class _Inspector:
    def __init__(self, report: ScopeReport | Exception, *, supported: bool = True) -> None:
        self._report = report
        self._supported = supported

    def supports(self, provider: str) -> bool:
        return self._supported

    def inspect(self, *, provider: str, credential: OpaqueCredential) -> ScopeReport:
        if isinstance(self._report, Exception):
            raise self._report
        return self._report


def _verify(report: ScopeReport | Exception, **kwargs: Any) -> Any:
    secrets = kwargs.pop("secrets", _Secrets())
    return verify_read_only_scope(
        provider=kwargs.pop("provider", "GRAFANA"),
        credential_secret_ref=kwargs.pop("credential_secret_ref", _SECRET_REF),
        secrets=secrets,
        inspector=_Inspector(report, **kwargs),
    )


def test_a_key_the_vendor_reports_as_read_only_is_accepted() -> None:
    verdict = _verify(
        ScopeReport(
            provider="GRAFANA",
            outcome="OBSERVED",
            scopes=("dashboards:read", "datasources:query", "annotations:read"),
        )
    )

    assert verdict.state == "VERIFIED_READ_ONLY"
    assert verdict.read_only is True
    assert verdict.reason_code is None
    assert verdict.observed_scope_count == 3
    assert verdict.evidence_ref.startswith("scope://grafana#sha256:")


def test_a_key_carrying_a_write_scope_is_refused_with_a_closed_reason() -> None:
    verdict = _verify(
        ScopeReport(
            provider="GRAFANA",
            outcome="OBSERVED",
            scopes=("dashboards:read", "dashboards:write"),
        )
    )

    assert verdict.state == "REFUSED_WRITE_SCOPE"
    assert verdict.reason_code == "WRITE_SCOPE_PRESENT"
    assert verdict.remediation_kind == "REGISTER_CREDENTIAL"
    assert verdict.read_only is False


def test_a_scope_solvan_cannot_classify_refuses_rather_than_passing() -> None:
    """An unrecognized token is not evidence of harmlessness.

    It is also the shape an echoed credential would arrive in, which is why the
    token itself never reaches the verdict.
    """

    verdict = _verify(
        ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=("dashboards:read", _KEY))
    )

    assert verdict.state == "UNVERIFIABLE"
    assert verdict.reason_code == "SCOPE_NOT_RECOGNIZED"
    assert _KEY not in (verdict.explanation or "")


def test_a_proven_write_scope_outranks_an_unclassifiable_one() -> None:
    verdict = _verify(
        ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=("teams:write", "something-odd"))
    )

    assert verdict.reason_code == "WRITE_SCOPE_PRESENT"


def test_a_key_the_vendor_reports_no_scope_for_is_not_read_only() -> None:
    verdict = _verify(ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=()))

    assert verdict.state == "UNVERIFIABLE"
    assert verdict.reason_code == "SCOPES_NOT_REPORTED"


@pytest.mark.parametrize(
    ("outcome", "reason_code", "remediation"),
    [
        ("NO_INTROSPECTION", "NO_SCOPE_INTROSPECTION", "CONTACT_PROVIDER"),
        ("ENDPOINT_UNKNOWN", "VENDOR_ENDPOINT_UNKNOWN", "FIX_CONFIGURATION"),
        ("INTROSPECTION_REFUSED", "INTROSPECTION_REFUSED", "REGISTER_CREDENTIAL"),
        ("UNREACHABLE", "VENDOR_UNREACHABLE", "RETRY_PROBE"),
    ],
)
def test_each_inconclusive_inspection_keeps_its_own_reason_and_next_step(
    outcome: str, reason_code: str, remediation: str
) -> None:
    verdict = _verify(ScopeReport(provider="GRAFANA", outcome=outcome))  # type: ignore[arg-type]

    assert verdict.state == "UNVERIFIABLE"
    assert verdict.reason_code == reason_code
    assert verdict.remediation_kind == remediation
    assert verdict.explanation


def test_a_provider_with_no_scope_introspection_never_resolves_the_secret() -> None:
    """A key Solvan can never inspect is a key it has no reason to read."""

    secrets = _Secrets()
    verdict = _verify(
        ScopeReport(provider="NEW_RELIC", outcome="NO_INTROSPECTION"),
        provider="NEW_RELIC",
        supported=False,
        secrets=secrets,
    )

    assert verdict.state == "UNVERIFIABLE"
    assert verdict.reason_code == "NO_SCOPE_INTROSPECTION"
    assert secrets.requested == []


def test_an_unresolvable_or_empty_secret_is_unverifiable_not_verified() -> None:
    unreadable = _verify(
        ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=("dashboards:read",)),
        secrets=_Secrets(RuntimeError("Secret Manager returned no payload")),
    )
    empty = _verify(
        ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=("dashboards:read",)),
        secrets=_Secrets(b"   "),
    )
    absent = _verify(
        ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=("dashboards:read",)),
        credential_secret_ref="",
    )

    for verdict in (unreadable, empty, absent):
        assert verdict.state == "UNVERIFIABLE"
        assert verdict.reason_code == "CREDENTIAL_UNREADABLE"


def test_an_inspector_that_raises_never_becomes_a_verified_key() -> None:
    verdict = _verify(TimeoutError("vendor timed out"))

    assert verdict.state == "UNVERIFIABLE"
    assert verdict.reason_code == "VENDOR_UNREACHABLE"


def test_the_credential_value_reaches_the_vendor_header_and_nowhere_else() -> None:
    transport = _Transport(_Response(200, {"dashboards:read": ["dashboards:*"]}))
    inspector = HttpVendorScopeInspector(transport, hosts={"GRAFANA": "acme.grafana.net"})
    verdict = verify_read_only_scope(
        provider="GRAFANA",
        credential_secret_ref=_SECRET_REF,
        secrets=_Secrets(),
        inspector=inspector,
    )

    assert verdict.state == "VERIFIED_READ_ONLY"
    url, kwargs = transport.calls[0]
    assert url == "https://acme.grafana.net/api/access-control/user/permissions"
    assert kwargs["headers"] == {"Authorization": f"Bearer {_KEY}"}
    assert _KEY not in url
    assert "params" not in kwargs and "json" not in kwargs
    rendered = f"{verdict!r} {verdict.evidence_ref} {verdict.explanation}"
    assert _KEY not in rendered


def test_an_opaque_credential_cannot_be_printed_formatted_or_serialized() -> None:
    credential = OpaqueCredential(_KEY.encode())

    assert _KEY not in repr(credential)
    assert _KEY not in str(credential)
    assert _KEY not in f"{credential}"
    assert _KEY not in "{}".format(credential)  # noqa: UP032
    assert credential.present() == _KEY
    with pytest.raises(ConnectionPolicyError, match="empty"):
        OpaqueCredential(b"\n")


def test_a_refusal_message_an_operator_reads_never_carries_the_key() -> None:
    """The reason is legible; the key is not in it."""

    verdict = _verify(
        ScopeReport(provider="GRAFANA", outcome="OBSERVED", scopes=("dashboards:write", _KEY))
    )
    message = f"{verdict.reason_code}: {verdict.explanation}"

    assert message.startswith("WRITE_SCOPE_PRESENT: ")
    assert _KEY not in message
    assert "read scopes" in message


def test_a_configured_inspection_host_outside_the_vendor_domain_refuses() -> None:
    """A deployment that could aim inspection anywhere could fake any answer."""

    with pytest.raises(ConnectionPolicyError, match="not a GRAFANA endpoint"):
        HttpVendorScopeInspector(_Transport(_Response(200)), hosts={"GRAFANA": "evil.example.com"})
    with pytest.raises(ConnectionPolicyError, match="not a DATADOG endpoint"):
        HttpVendorScopeInspector(
            _Transport(_Response(200)), hosts={"DATADOG": "api.datadoghq.com.evil.test"}
        )
    with pytest.raises(ConnectionPolicyError, match="not a PROMETHEUS endpoint"):
        HttpVendorScopeInspector(_Transport(_Response(200)), hosts={"PROMETHEUS": "metrics.acme"})


def test_a_grafana_stack_this_deployment_does_not_record_is_never_inspected() -> None:
    transport = _Transport(_Response(200, {"dashboards:read": []}))
    report = HttpVendorScopeInspector(transport).inspect(
        provider="GRAFANA", credential=OpaqueCredential(_KEY.encode())
    )

    assert report.outcome == "ENDPOINT_UNKNOWN"
    assert transport.calls == []


@pytest.mark.parametrize(
    ("status_code", "outcome"),
    [(401, "INTROSPECTION_REFUSED"), (403, "INTROSPECTION_REFUSED"), (500, "UNREACHABLE")],
)
def test_a_vendor_that_refuses_introspection_proves_nothing(status_code: int, outcome: str) -> None:
    inspector = HttpVendorScopeInspector(
        _Transport(_Response(status_code)), hosts={"GRAFANA": "acme.grafana.net"}
    )
    report = inspector.inspect(provider="GRAFANA", credential=OpaqueCredential(_KEY.encode()))

    assert report.outcome == outcome


def test_a_vendor_answer_solvan_cannot_read_is_never_an_observation() -> None:
    for body in ({"data": "not-a-list"}, ["not", "a", "mapping"], {"data": [{"attributes": 1}]}):
        inspector = HttpVendorScopeInspector(
            _Transport(_Response(200, body)), hosts={"DATADOG": "api.datadoghq.eu"}
        )
        report = inspector.inspect(provider="DATADOG", credential=OpaqueCredential(b"dd-app-key"))
        assert report.outcome == "UNREACHABLE"


def test_datadog_is_read_only_only_when_every_key_the_user_owns_is() -> None:
    """The presented key is one of the owner's keys, so all of them must be read.

    Datadog reports scopes per application key rather than for the key
    presenting the request, so accepting a mixed set would prove read-only for a
    key that is not the one in hand.
    """

    def _report(*scope_sets: list[str] | None) -> ScopeReport:
        body = {"data": [{"attributes": {"scopes": scopes}} for scopes in scope_sets]}
        inspector = HttpVendorScopeInspector(
            _Transport(_Response(200, body)), hosts={"DATADOG": "api.datadoghq.com"}
        )
        return inspector.inspect(provider="DATADOG", credential=OpaqueCredential(b"dd-app-key"))

    read_only = _report(["metrics_read", "timeseries_query"], ["dashboards_read"])
    mixed = _report(["metrics_read"], ["dashboards_write"])
    unscoped = _report(["metrics_read"], None)

    assert read_only.outcome == "OBSERVED"
    assert read_only.scopes == ("metrics_read", "timeseries_query", "dashboards_read")
    assert mixed.scopes == ("metrics_read", "dashboards_write")
    assert unscoped.scopes == ()


def test_datadog_write_and_read_vocabularies_are_classified_not_guessed() -> None:
    def _state(*scopes: str) -> str:
        return _verify(
            ScopeReport(provider="DATADOG", outcome="OBSERVED", scopes=scopes), provider="DATADOG"
        ).state

    assert _state("metrics_read", "logs_read_data", "timeseries_query") == "VERIFIED_READ_ONLY"
    assert _state("metrics_read", "monitors_write") == "REFUSED_WRITE_SCOPE"
    assert _state("metrics_read", "logs_write_archives") == "REFUSED_WRITE_SCOPE"
    assert _state("metrics_read", "user_access_manage") == "REFUSED_WRITE_SCOPE"
    assert _state("metrics_read", "something_else") == "UNVERIFIABLE"
