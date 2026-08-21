from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import solvan.platform.google_rest as google_rest
from apps.evidence_broker import main as broker_main
from apps.evidence_broker.contracts import ServiceArgs
from apps.evidence_broker.main import (
    _AGENT_TOOLS,
    AuditLogArgs,
    DirectReadBindingUnavailable,
    ErrorReportingArgs,
    MonitoringArgs,
    cloud_build_trigger,
    cloud_sql_resource,
    create_app,
    github_repository_id,
    google_resource,
)
from apps.evidence_broker.projections import (
    error_reporting_period,
    redact,
    sanitize_audit_entry,
    sanitize_error_group,
    trace_ids,
)
from apps.evidence_broker.reader import TypedEvidenceReader
from solvan.agents.read_tools import cloud_run_read
from solvan.domain import Scope
from solvan.persistence import ToolAuthorizationError
from solvan.persistence.evidence_types import EvidenceToolReservation
from solvan.platform.service_identity import VerifiedCaller


def test_broker_route_rejects_agent_identity_tool_confusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "AGENT_IDENTITY_IAM_GATEWAY")
    monkeypatch.setenv(
        "SOLVAN_EVIDENCE_AGENT_PRINCIPAL",
        "principal://agents.global.project-123.system.id.goog/resources/aiplatform/"
        "projects/123/locations/europe-west1/reasoningEngines/evidence-1",
    )
    # The caller's token is now verified in process, so a literal string no
    # longer reaches the route. Stand in a verified caller to keep this test on
    # its subject: the tool-confusion ceiling, not the identity gate.
    monkeypatch.setattr(
        broker_main,
        "verify_service_caller",
        lambda authorization, *, audience_variable: VerifiedCaller(
            subject=(
                "principal://agents.global.project-123.system.id.goog/resources/aiplatform/"
                "projects/123/locations/europe-west1/reasoningEngines/evidence-1"
            ),
            email=None,
            audience="https://evidence.invalid",
            issuer="https://accounts.google.com",
        ),
    )
    response = TestClient(create_app()).post(
        "/internal/v1/evidence/evidence-agent:query",
        headers={"Authorization": "Bearer certificate-bound-agent-token"},
        json={
            "schema_version": 1,
            "invocation_id": "unguessable-runtime-invocation",
            "tool_name": "cloud_run_read",
            "arguments": {"service_id": "svc_00000000000000000000000000"},
        },
    )

    assert response.status_code == 403
    assert "identity ceiling" in response.json()["detail"]


def test_broker_window_and_resource_bounds() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="15 minutes"):
        MonitoringArgs(
            service_id="svc_00000000000000000000000000",
            signal_kind="HTTP_5XX_RATIO",
            window_start=now - timedelta(minutes=16),
            window_end=now,
        ).checked_window()
    with pytest.raises(ToolAuthorizationError, match="invalid Google resource"):
        google_resource(
            "projects/attacker/locations/europe-west1/services/payments",
            "solvan-demo",
            "services",
        )


def test_broker_redacts_sensitive_provider_strings() -> None:
    value = redact("alice@example.com connected from 10.1.2.3 with Bearer secret.token-value")
    assert value == "[EMAIL] connected from [IP] with Bearer [TOKEN]"


def test_trace_ids_are_derived_only_from_same_project_log_evidence() -> None:
    assert trace_ids(
        {
            "entries": [
                {"trace": f"projects/solvan-demo/traces/{'a' * 32}"},
                {"trace": f"projects/attacker/traces/{'b' * 32}"},
            ]
        },
        "solvan-demo",
    ) == ("a" * 32,)


def test_agent_tool_uses_identity_specific_broker_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_ENVIRONMENT", "staging")
    monkeypatch.setenv("SOLVAN_EVIDENCE_BROKER_URL", "https://evidence.example")
    monkeypatch.setenv("SOLVAN_EVIDENCE_AUDIENCE", "https://evidence.example")
    monkeypatch.setenv("SOLVAN_AGENT_KEY", "infrastructure-agent")
    monkeypatch.setattr(
        "solvan.agents.read_tools.private_service_headers",
        lambda *, audience_variable: {"Authorization": "Bearer runtime-token"},
    )
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> httpx.Response:
        calls.append({"url": url, **kwargs})
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "evidence_ref": "evd_00000000000000000000000000",
                "content_ref": "gs://evidence/item.json",
                "content_hash": f"sha256:{'a' * 64}",
                "bounded_summary": "{}",
                "classification": "INTERNAL",
                "armor_verdict_ref": None,
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    cloud_run_read(
        "projects/p/locations/europe-west1/reasoningEngines/r/operations/unguessable",
        "svc_00000000000000000000000000",
    )

    assert calls[0]["url"].endswith("/internal/v1/evidence/infrastructure-agent:query")


def test_change_history_windows_are_bounded_and_entry_capped() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="exceeds 24 hours"):
        AuditLogArgs(
            service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            window_start=now - timedelta(hours=25),
            window_end=now,
            maximum_entries=10,
        ).checked_window()
    with pytest.raises(ValidationError):
        AuditLogArgs(
            service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            window_start=now - timedelta(hours=1),
            window_end=now,
            maximum_entries=51,
        )
    with pytest.raises(ValidationError):
        ErrorReportingArgs(
            service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            window_start=now - timedelta(hours=1),
            window_end=now,
            maximum_groups=21,
        )
    start, end = AuditLogArgs(
        service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        window_start=now - timedelta(hours=6),
        window_end=now,
        maximum_entries=50,
    ).checked_window()
    assert end - start == timedelta(hours=6)


def test_audit_actor_reports_service_accounts_and_pseudonymizes_people() -> None:
    robot = sanitize_audit_entry(
        {
            "timestamp": "2026-08-09T10:00:00Z",
            "protoPayload": {
                "authenticationInfo": {
                    "principalEmail": "deployer@solvan-demo.iam.gserviceaccount.com"
                },
                "methodName": "google.cloud.run.v2.Services.UpdateService",
                "resourceName": "namespaces/solvan-demo/services/payments-api",
                "status": {"code": 0},
            },
        }
    )
    assert robot["actor"] == "deployer@solvan-demo.iam.gserviceaccount.com"
    assert robot["method_name"] == "google.cloud.run.v2.Services.UpdateService"

    human = sanitize_audit_entry(
        {"protoPayload": {"authenticationInfo": {"principalEmail": "alex.park@example.com"}}}
    )
    assert human["actor"].startswith("principal:")
    assert "alex.park" not in str(human)
    assert "@example.com" not in str(human)

    same = sanitize_audit_entry(
        {"protoPayload": {"authenticationInfo": {"principalEmail": "alex.park@example.com"}}}
    )
    assert same["actor"] == human["actor"], "pseudonym must be stable for correlation"
    other = sanitize_audit_entry(
        {"protoPayload": {"authenticationInfo": {"principalEmail": "sam.patel@example.com"}}}
    )
    assert other["actor"] != human["actor"]


def test_error_group_projection_is_bounded_and_redacted() -> None:
    group = sanitize_error_group(
        {
            "group": {"groupId": "leak-signature"},
            "count": "412",
            "firstSeenTime": "2026-08-09T11:18:00Z",
            "lastSeenTime": "2026-08-09T11:59:00Z",
            "representative": {
                "message": "QueuePool limit reached for admin@example.com from 10.1.2.3 "
                + "x" * 4_000
            },
        }
    )
    assert group["group_id"] == "leak-signature"
    assert group["first_seen_time"] == "2026-08-09T11:18:00Z"
    message = group["representative_message"]
    assert isinstance(message, str) and len(message) <= 1_000
    assert "[EMAIL]" in message and "[IP]" in message


def test_error_reporting_period_covers_the_requested_window() -> None:
    assert error_reporting_period(timedelta(minutes=30)) == "PERIOD_1_HOUR"
    assert error_reporting_period(timedelta(hours=5)) == "PERIOD_6_HOURS"
    assert error_reporting_period(timedelta(hours=20)) == "PERIOD_1_DAY"


def test_change_history_tools_stay_inside_the_evidence_agent_ceiling() -> None:
    assert "cloud_audit_log_query" in _AGENT_TOOLS["evidence-agent"]
    assert "error_reporting_query" in _AGENT_TOOLS["evidence-agent"]
    assert "cloud_audit_log_query" not in _AGENT_TOOLS["infrastructure-agent"]
    assert "error_reporting_query" not in _AGENT_TOOLS["infrastructure-agent"]


def test_infrastructure_inventory_and_build_tools_are_bounded_and_registered() -> None:
    assert "cloud_asset_inventory_search" in _AGENT_TOOLS["infrastructure-agent"]
    assert "cloud_build_history_read" in _AGENT_TOOLS["infrastructure-agent"]
    assert cloud_build_trigger(
        "projects/solvan-demo/locations/europe-west1/triggers/ruhu-release",
        "solvan-demo",
    ) == ("europe-west1", "ruhu-release")
    with pytest.raises(ToolAuthorizationError, match="invalid Cloud Build trigger"):
        cloud_build_trigger(
            "projects/attacker/locations/europe-west1/triggers/ruhu-release",
            "solvan-demo",
        )


def test_github_tools_require_an_exact_graph_bound_repository() -> None:
    repository_id = "ghr_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    assert github_repository_id(f"github://{repository_id}") == repository_id
    with pytest.raises(ToolAuthorizationError, match="invalid GitHub repository"):
        github_repository_id("https://github.com/acme/payments")
    assert {
        "github_commit_range_read",
        "github_pr_diff_read",
        "github_workflow_run_read",
    }.issubset(_AGENT_TOOLS["infrastructure-agent"])


def test_a_resource_is_addressed_at_the_project_its_own_graph_node_names() -> None:
    """Specification 13 §4.2.

    A database in a different project than its service is ordinary, not
    exceptional. The reader used to pair the database node's resource with the
    *service's* project, which fails closed but blames the production graph for
    an entry that is perfectly valid and simply lives elsewhere. Pairing each
    resource with the project its own node names is what makes the cross-project
    estate readable at all.
    """
    database = "projects/acme-data-prod/instances/payments"

    with pytest.raises(ToolAuthorizationError, match="invalid Cloud SQL resource"):
        cloud_sql_resource(database, "acme-payments-prod")

    assert cloud_sql_resource(database, "acme-data-prod") == database


def test_a_build_trigger_is_addressed_at_its_own_project_too() -> None:
    trigger = "projects/acme-build-prod/locations/europe-west1/triggers/payments"

    with pytest.raises(ToolAuthorizationError, match="invalid Cloud Build trigger"):
        cloud_build_trigger(trigger, "acme-payments-prod")

    assert cloud_build_trigger(trigger, "acme-build-prod") == ("europe-west1", "payments")


SOLVAN_DELEGATOR = "serviceAccount:solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com"
CUSTOMER_READER = "serviceAccount:solvan-reader@acme-payments-prod.iam.gserviceaccount.com"
COMPLETE_BINDING = (
    "GCP_SERVICE_ACCOUNT_IMPERSONATION",
    SOLVAN_DELEGATOR,
    CUSTOMER_READER,
    "sha256:" + "a" * 64,
    900,
)


class _BindingCursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row
        self.statement = ""
        self.parameters: dict[str, Any] = {}

    def __enter__(self) -> _BindingCursor:
        return self

    def __exit__(self, *_exception: Any) -> bool:
        return False

    def execute(self, statement: str, parameters: dict[str, Any]) -> None:
        self.statement = statement
        self.parameters = parameters

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _BindingConnection:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self.opened = _BindingCursor(row)

    def cursor(self) -> _BindingCursor:
        return self.opened


def _reservation() -> EvidenceToolReservation:
    return EvidenceToolReservation(
        call_id="tcl_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        scope=Scope(
            "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ),
        run_id="run_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        incident_id="inc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        alert_episode_id=None,
        service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        service_key="payments-api",
        platform_kind="CLOUD_RUN",
        platform_resource="projects/acme-payments-prod/locations/europe-west1/services/payments",
        graph_snapshot_id="pgs_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        service_project_id="acme-payments-prod",
        tool_name="cloud_run_read",
        tool_version="1",
        profile_key="read-only",
        profile_version="1",
        binding_kind="POLICY_SOURCE_CONNECTION",
        capability_key="RESOURCE_METADATA_READ",
        connection_id="con_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        connection_epoch=7,
        identity_ref="serviceAccount:evidence@solvan.iam.gserviceaccount.com",
        gateway_policy_ref="gateway://policy/1",
        input_bytes=64,
        otel_span_id="0000000000000001",
        arguments_hash="sha256:" + "b" * 64,
        max_output_bytes=262_144,
        maximum_aggregate_evidence_bytes=1_048_576,
    )


def test_every_evidence_read_assumes_the_frozen_connection_customer_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specification 13 §1.1/§3.4.

    The broker serves every read connector. Calling the authorization boundary
    bare left those reads on Solvan's own runtime identity, against Solvan's own
    project, while onboarding kept asking customers to grant a reader account
    nothing ever assumed.
    """
    monkeypatch.setenv(
        "SOLVAN_READER_SERVICE_ACCOUNT", "solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com"
    )
    minted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        broker_main, "authorized_session", lambda **kwargs: minted.append(kwargs) or object()
    )
    connection = _BindingConnection(COMPLETE_BINDING)
    reservation = _reservation()

    broker_main._customer_reader_session(connection=connection, reservation=reservation)

    assert minted == [
        {
            "delegator_principal": SOLVAN_DELEGATOR,
            "target_principal": CUSTOMER_READER,
            "lifetime_seconds": 900,
            "delegate_principals": (SOLVAN_DELEGATOR,),
        }
    ]
    assert connection.opened.parameters == {
        "organization_id": "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "project_id": "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "environment_id": "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "connection_id": "con_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "connection_epoch": 7,
    }
    assert "connection_epoch=%(connection_epoch)s" in connection.opened.statement


@pytest.mark.parametrize(
    ("row", "reader_identity"),
    [
        (COMPLETE_BINDING, ""),
        (None, "solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com"),
        (
            ("STORED_SECRET_REFERENCE", None, None, None, None),
            "solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com",
        ),
        (
            (
                "GCP_SERVICE_ACCOUNT_IMPERSONATION",
                SOLVAN_DELEGATOR,
                None,
                "sha256:" + "a" * 64,
                900,
            ),
            "solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com",
        ),
        (
            ("GCP_SERVICE_ACCOUNT_IMPERSONATION", SOLVAN_DELEGATOR, CUSTOMER_READER, None, 900),
            "solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com",
        ),
        (
            (
                "GCP_SERVICE_ACCOUNT_IMPERSONATION",
                SOLVAN_DELEGATOR,
                CUSTOMER_READER,
                "sha256:" + "a" * 64,
                None,
            ),
            "solvan-direct-gcp-reader@solvan.iam.gserviceaccount.com",
        ),
        (COMPLETE_BINDING, "someone-else@solvan.iam.gserviceaccount.com"),
    ],
)
def test_an_absent_or_partial_binding_refuses_instead_of_using_ambient_credentials(
    monkeypatch: pytest.MonkeyPatch, row: tuple[Any, ...] | None, reader_identity: str
) -> None:
    monkeypatch.setenv("SOLVAN_READER_SERVICE_ACCOUNT", reader_identity)
    monkeypatch.setattr(
        broker_main,
        "authorized_session",
        lambda **_kwargs: pytest.fail("an incomplete binding must never mint a session"),
    )

    with pytest.raises(DirectReadBindingUnavailable):
        broker_main._customer_reader_session(
            connection=_BindingConnection(row), reservation=_reservation()
        )


class _ProviderResponse:
    headers: ClassVar[dict[str, str]] = {"x-request-id": "provider-request-1"}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"name": "payments", "uid": "u1", "generation": 3, "latestReadyRevision": "r1"}


class _RecordingCustomerSession:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str, **_kwargs: Any) -> _ProviderResponse:
        self.urls.append(url)
        return _ProviderResponse()


class _ForbiddenObjectSession:
    def get(self, url: str, **_kwargs: Any) -> _ProviderResponse:
        raise AssertionError("a provider read must never use the Solvan object identity")


def test_provider_reads_address_the_customer_estate_not_the_runtime_identity() -> None:
    customer = _RecordingCustomerSession()
    reader = TypedEvidenceReader(
        provider_session=lambda: customer,
        object_session=_ForbiddenObjectSession(),
        store=object(),
        bucket="solvan-evidence",
    )

    _value, request_ids, _start, _end, source_kind = reader.read(
        _reservation(), ServiceArgs(service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV")
    )

    assert source_kind == "CLOUD_RUN_METADATA"
    assert request_ids == ("provider-request-1",)
    assert customer.urls == [
        "https://run.googleapis.com/v2/"
        "projects/acme-payments-prod/locations/europe-west1/services/payments"
    ]


def test_a_provider_read_without_a_binding_refuses_rather_than_falling_back() -> None:
    def refuse() -> Any:
        raise DirectReadBindingUnavailable("frozen connection revision carries no complete binding")

    reader = TypedEvidenceReader(
        provider_session=refuse,
        object_session=_ForbiddenObjectSession(),
        store=object(),
        bucket="solvan-evidence",
    )

    with pytest.raises(DirectReadBindingUnavailable):
        reader.read(_reservation(), ServiceArgs(service_id="svc_01ARZ3NDEKTSV4RRFFQ69G5FAV"))


class _RuntimeCredentials:
    def __init__(self, service_account_email: str | None) -> None:
        if service_account_email is not None:
            self.service_account_email = service_account_email


@pytest.fixture
def impersonation(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    minted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        google_rest.google.auth,
        "default",
        lambda **_kwargs: (
            _RuntimeCredentials("solvan-evidence@solvan.iam.gserviceaccount.com"),
            "solvan",
        ),
    )
    monkeypatch.setattr(
        google_rest.impersonated_credentials,
        "Credentials",
        lambda **kwargs: minted.append(kwargs) or object(),
    )
    monkeypatch.setattr(google_rest, "AuthorizedSession", lambda _credentials: object())
    return minted


def test_the_minted_token_is_the_customer_reader_minted_by_the_recorded_delegator(
    impersonation: list[dict[str, Any]],
) -> None:
    google_rest.authorized_session(
        delegator_principal=SOLVAN_DELEGATOR,
        target_principal=CUSTOMER_READER,
        lifetime_seconds=900,
        delegate_principals=(SOLVAN_DELEGATOR,),
    )

    assert impersonation[0]["target_principal"] == CUSTOMER_READER.removeprefix("serviceAccount:")
    assert impersonation[0]["delegates"] == [SOLVAN_DELEGATOR.removeprefix("serviceAccount:")]
    assert impersonation[0]["lifetime"] == 900


def test_the_token_ceiling_and_runtime_identity_assertions_still_hold(
    impersonation: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="between 1 and 900 seconds"):
        google_rest.authorized_session(
            delegator_principal=SOLVAN_DELEGATOR,
            target_principal=CUSTOMER_READER,
            lifetime_seconds=901,
            delegate_principals=(SOLVAN_DELEGATOR,),
        )
    with pytest.raises(RuntimeError, match="does not end at the recorded Solvan delegator"):
        google_rest.authorized_session(
            delegator_principal=SOLVAN_DELEGATOR,
            target_principal=CUSTOMER_READER,
            lifetime_seconds=900,
            delegate_principals=("serviceAccount:attacker@evil.iam.gserviceaccount.com",),
        )
    with pytest.raises(ValueError, match="complete impersonation binding"):
        google_rest.authorized_session(target_principal=CUSTOMER_READER)
    with pytest.raises(RuntimeError, match="does not match the recorded Solvan delegator"):
        google_rest.authorized_session(
            delegator_principal=SOLVAN_DELEGATOR,
            target_principal=CUSTOMER_READER,
            lifetime_seconds=900,
        )
    monkeypatch.setattr(
        google_rest.google.auth, "default", lambda **_kwargs: (_RuntimeCredentials(None), "solvan")
    )
    with pytest.raises(RuntimeError, match="do not attest a service-account identity"):
        google_rest.authorized_session(
            delegator_principal=SOLVAN_DELEGATOR,
            target_principal=CUSTOMER_READER,
            lifetime_seconds=900,
            delegate_principals=(SOLVAN_DELEGATOR,),
        )
    assert impersonation == []
