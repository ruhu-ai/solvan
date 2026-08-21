"""Connecting one estate registers N connections at once, or none of them.

Investigating an incident needs metrics and logs and audit and errors and
traces, and each is its own connection so one can be revoked without losing the
others. That is why an operator used to walk the connect dialog seven times for
one estate. These cover what replaces it: that the grants are asked for once,
that the set is registered in one transaction so a half-connected estate is
never presented as connected, that every connection is registered unprobed and
then probed on its own, and that the request body cannot name the principal,
the scope, or the identity permitted to impersonate the customer reader.

Nothing here reaches a database, a Google API, or the direct reader service.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.api import connections as connections_api
from apps.api import estate_onboarding_flow as estate_flow
from apps.api import session_authorization
from apps.api.connections import EstateConnectionRequest, ProbeResponse, connection_router
from solvan.domain import Scope

_SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
_ADMIN = {"X-Solvan-Approval-Token": "Bearer verified"}
_SOLVAN_READER = "solvan-reader@solvan-control.iam.gserviceaccount.com"
_CUSTOMER_READER = "solvan-reader@acme-prod.iam.gserviceaccount.com"
_INVESTIGATION = [
    "CLOUD_MONITORING",
    "CLOUD_LOGGING",
    "CLOUD_AUDIT",
    "ERROR_REPORTING",
    "CLOUD_TRACE",
]


class _Cursor:
    def __init__(self, database: _Database) -> None:
        self._database = database
        self._row: tuple[Any, ...] | None = None

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        values = dict(parameters or {})
        self._database.statements.append((statement, values))
        if "actor_role_bindings" in statement:
            self._row = (self._database.administrator,)
        elif "INSERT INTO solvan.tenant_connections" in statement:
            if values["provider"] == self._database.refuse_provider:
                raise RuntimeError("tenant_connections rejected this row")
            self._database.pending.append(values)
            self._row = None
        elif "connection_external_resource_scopes" in statement:
            self._database.pending.append(values)
            self._row = None
        elif "SELECT connection_epoch" in statement:
            registered = [
                row for row in self._database.pending if row.get("id") == values["connection_id"]
            ]
            # A newly inserted row carries the schema's defaults, which are what
            # an unprobed connection means: authored but proven nothing.
            self._row = (
                (1, self._database.registered_lifecycle, self._database.registered_availability)
                if registered
                else None
            )
        else:
            self._row = None

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Transaction:
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> _Transaction:
        return self

    def __exit__(self, kind: object, *_args: object) -> None:
        if kind is None:
            self._database.rows.extend(self._database.pending)
        else:
            self._database.rolled_back += 1
        self._database.pending.clear()


class _Connection:
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return _Cursor(self._database)

    def transaction(self) -> _Transaction:
        return _Transaction(self._database)


class _Database:
    """Committed rows survive; rows written inside a failed transaction do not."""

    def __init__(
        self,
        *,
        administrator: bool = True,
        refuse_provider: str | None = None,
        registered_lifecycle: str = "PENDING",
        registered_availability: str = "NOT_CONFIGURED",
    ) -> None:
        self.administrator = administrator
        self.refuse_provider = refuse_provider
        self.registered_lifecycle = registered_lifecycle
        self.registered_availability = registered_availability
        self.rows: list[dict[str, Any]] = []
        self.pending: list[dict[str, Any]] = []
        self.statements: list[tuple[str, dict[str, Any]]] = []
        self.rolled_back = 0

    @property
    def connections(self) -> list[dict[str, Any]]:
        return [row for row in self.rows if "provider" in row]

    def __call__(self) -> _Connection:
        return _Connection(self)


class _Probe:
    def __init__(self, *, result: str = "SUCCEEDED", refuse: bool = False) -> None:
        self._result = result
        self._refuse = refuse
        self.probed: list[str] = []

    def __call__(self, *, scope: Scope, connection_id: str) -> ProbeResponse:
        self.probed.append(connection_id)
        if self._refuse:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "direct GCP reader is not configured"
            )
        return ProbeResponse(
            connection_id=connection_id,
            connection_epoch=1,
            result=self._result,  # type: ignore[arg-type]
            capabilities=[],
        )


def _client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    database: _Database | None = None,
    probe: _Probe | None = None,
    reader_identity: str | None = _SOLVAN_READER,
    challenge_spends: bool = True,
) -> tuple[TestClient, _Database, _Probe]:
    store = database or _Database()
    prober = probe or _Probe()
    monkeypatch.setattr(connections_api, "connect_database", store)
    monkeypatch.setattr(connections_api, "_direct_gcp_probe", prober)
    # The estate flow and the identity check moved out of `connections`, so
    # patching only that module left them reaching a real database.
    monkeypatch.setattr(estate_flow, "connect_database", store)
    monkeypatch.setattr(session_authorization, "connect_database", store)

    # Connecting an estate spends a challenge rather than accepting a pasted
    # token. The route's own authorization is exercised by the challenge tests;
    # here it is stubbed so these cases stay about estate registration.
    def _spend(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        if not challenge_spends:
            raise HTTPException(401, "this action requires a challenge")
        return SimpleNamespace(actor_id="act_operator")

    monkeypatch.setattr(estate_flow, "spend_challenge", _spend)
    monkeypatch.setattr(estate_flow, "recorded_principal", lambda *_a: "user:operator@example.com")
    monkeypatch.setattr(connections_api, "require_administrator", lambda *_a: "act_operator")
    if reader_identity is None:
        monkeypatch.delenv("SOLVAN_READER_SERVICE_ACCOUNT", raising=False)
    else:
        monkeypatch.setenv("SOLVAN_READER_SERVICE_ACCOUNT", reader_identity)
    monkeypatch.setenv("SOLVAN_REGION", "europe-west1")
    app = FastAPI()
    app.include_router(
        connection_router(
            principal_provider=lambda _token: "user:operator@example.com",
            scope_provider=lambda: _SCOPE,
        )
    )
    return TestClient(app), store, prober


def _body(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "display_name": "Payments production",
        "providers": _INVESTIGATION,
        "classification": "INTERNAL",
        "customer_project_id": "acme-prod",
        "customer_reader_service_account": _CUSTOMER_READER,
        "workload_region": "europe-west2",
        "scope_decision_ref": "console/direct-gcp-onboarding",
        **overrides,
    }


def test_one_request_registers_one_connection_per_capability_each_probed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, database, probe = _client(monkeypatch)

    response = client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body())

    assert response.status_code == 200
    registered = response.json()["registered"]
    assert [item["provider"] for item in registered] == _INVESTIGATION
    # Distinct rows with distinct identifiers, not one row observing five things.
    assert len({item["connection_id"] for item in registered}) == 5
    assert [item["connection_epoch"] for item in registered] == [1, 1, 1, 1, 1]
    assert all(item["probe_result"] == "SUCCEEDED" for item in registered)
    assert all(item["probe_reason_code"] is None for item in registered)
    # Each connection was probed on its own; none inherited another's proof.
    assert probe.probed == [item["connection_id"] for item in registered]
    assert [row["provider"] for row in database.connections] == _INVESTIGATION


def test_every_registered_connection_carries_the_one_delegation_and_one_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The estate is one grant plan, so every row names the same reader and condition."""

    client, database, _ = _client(monkeypatch)

    response = client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body())

    digest = response.json()["delegation_condition_digest"]
    assert digest.startswith("sha256:")
    for row in database.connections:
        assert row["customer_reader_principal"] == f"serviceAccount:{_CUSTOMER_READER}"
        assert row["solvan_delegator_principal"] == f"serviceAccount:{_SOLVAN_READER}"
        assert row["delegation_condition_digest"] == digest
        assert row["credential_posture"] == "FEDERATED_SHORT_LIVED"
        assert row["credential_secret_ref"] is None


def test_a_refused_row_leaves_no_connection_and_probes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A half-connected estate presented as connected is worse than a refusal.

    The fourth source fails here, so the three already inserted must not
    survive: an operator would otherwise own an estate the console reports as
    connected while the evidence an investigation needs is silently absent.
    """

    database = _Database(refuse_provider="ERROR_REPORTING")
    client, store, probe = _client(monkeypatch, database=database)

    with pytest.raises(RuntimeError, match="rejected this row"):
        client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body())

    assert store.connections == []
    assert store.rolled_back == 1
    assert probe.probed == []


def test_a_connection_that_came_back_already_proven_refuses_the_whole_estate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registration may never produce a connection that skipped its probe.

    Reading the row back rather than assuming it means this route cannot report
    an estate as connected on the strength of having inserted a row.
    """

    database = _Database(registered_lifecycle="ENABLED", registered_availability="READY")
    client, store, probe = _client(monkeypatch, database=database)

    response = client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body())

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail == "a newly registered connection must be unprobed and unproven"
    assert store.connections == []
    assert probe.probed == []


def test_a_connection_that_could_not_be_probed_is_reported_unproven_not_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connections exist; none of them claims a capability it has not shown."""

    client, database, _ = _client(monkeypatch, probe=_Probe(refuse=True))

    response = client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body())

    assert response.status_code == 200
    registered = response.json()["registered"]
    assert len(database.connections) == 5
    assert all(item["probe_result"] is None for item in registered)
    assert all(item["probe_reason_code"] == "PROBE_UNAVAILABLE" for item in registered)


@pytest.mark.parametrize(
    ("providers", "reason_code"),
    [
        (["CLOUD_MONITORING", "DATADOG"], "ESTATE_PROVIDER_UNKNOWN"),
        (["SOLVAN_COLLECTOR"], "ESTATE_PROVIDER_UNKNOWN"),
        (["KUBERNETES"], "ESTATE_PROVIDER_UNKNOWN"),
        (["CLOUD_LOGGING", "CLOUD_LOGGING"], "ESTATE_PROVIDER_DUPLICATED"),
    ],
)
def test_an_unusable_selection_refuses_before_anything_is_written(
    monkeypatch: pytest.MonkeyPatch, providers: list[str], reason_code: str
) -> None:
    client, database, probe = _client(monkeypatch)

    response = client.post(
        "/api/v1/connections/estates", headers=_ADMIN, json=_body(providers=providers)
    )

    assert response.status_code == 422
    assert response.json()["detail"] == reason_code
    assert database.connections == []
    assert probe.probed == []


def test_an_empty_selection_is_refused_by_the_request_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing selected registers nothing, so it never reaches the store."""

    client, database, probe = _client(monkeypatch)

    response = client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body(providers=[]))

    assert response.status_code == 422
    assert database.connections == []
    assert probe.probed == []
    with pytest.raises(ValidationError):
        EstateConnectionRequest(**_body(providers=[]))


def test_the_request_cannot_name_the_principal_scope_or_delegator() -> None:
    """Authority is never taken from a body: `extra="forbid"` refuses the name.

    A caller that could state the delegator would be choosing which identity is
    allowed to mint tokens for the customer reader, which is the whole control.
    """

    for smuggled in (
        {"actor": "user:attacker@example.com"},
        {"organization_id": "org_11111111111111111111111111"},
        {"solvan_delegator_principal": "serviceAccount:attacker@evil.iam.gserviceaccount.com"},
        {"delegation_condition_digest": f"sha256:{'a' * 64}"},
        {"residency_region": "us-central1"},
    ):
        with pytest.raises(ValidationError):
            EstateConnectionRequest(**_body(**smuggled))


def test_an_estate_registration_without_a_challenge_registers_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Holding ADMIN is necessary and not sufficient.

    Connecting an estate binds Solvan to a customer's Google Cloud project, so
    it requires a re-authentication bound to that exact estate. This replaced a
    pasted identity token, which carried no freshness, no binding, and no single
    use — the same token connected any estate, repeatedly, for as long as it
    lived.
    """

    client, database, probe = _client(monkeypatch, challenge_spends=False)

    response = client.post("/api/v1/connections/estates", json=_body())

    assert response.status_code == 401
    # Refused before anything durable exists, so a retry is a clean retry.
    assert database.connections == []
    assert probe.probed == []


def test_a_deployment_with_no_recorded_reader_identity_refuses_to_register(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence of the delegator is not a reason to register without one."""

    client, database, probe = _client(monkeypatch, reader_identity=None)

    response = client.post("/api/v1/connections/estates", headers=_ADMIN, json=_body())

    assert response.status_code == 503
    assert database.connections == []
    assert probe.probed == []


def test_the_consolidated_grant_plan_is_one_delegation_for_every_chosen_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = _client(monkeypatch)

    response = client.get(
        "/api/v1/connections/estate-grant-plan",
        headers=_ADMIN,
        params={
            "provider": _INVESTIGATION,
            "customer_project_id": "acme-prod",
            "customer_reader_service_account": _CUSTOMER_READER,
        },
    )

    assert response.status_code == 200
    plan = response.json()
    assert plan["providers"] == _INVESTIGATION
    assert plan["roles"] == [
        "roles/monitoring.viewer",
        "roles/logging.viewer",
        "roles/logging.privateLogViewer",
        "roles/errorreporting.viewer",
        "roles/cloudtrace.user",
    ]
    commands = [step["command"] for step in plan["steps"]]
    assert len(commands) == len(set(commands)) == 6
    assert all(_CUSTOMER_READER in command for command in commands)
    assert plan["secret_required"] is False


def test_the_consolidated_grant_plan_refuses_an_empty_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = _client(monkeypatch)

    response = client.get(
        "/api/v1/connections/estate-grant-plan",
        headers=_ADMIN,
        params={
            "customer_project_id": "acme-prod",
            "customer_reader_service_account": _CUSTOMER_READER,
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "ESTATE_SELECTION_EMPTY"


def test_the_console_proxy_accepts_both_routes_the_connect_flow_commands() -> None:
    """A route the proxy refuses fails in production and nowhere else.

    `apps/console/server.mjs` strips the human identity token on any path
    outside its allowlist, and the local harness does not run the proxy. Both
    of these paths therefore have to sit inside an existing entry, which is why
    the estate registration lives under `/api/v1/connections/` rather than
    beside it.
    """

    server = (Path(__file__).resolve().parents[2] / "apps" / "console" / "server.mjs").read_text(
        encoding="utf-8"
    )
    block = re.search(r"const humanTokenRoutes = \[(.*?)^\];", server, re.DOTALL | re.MULTILINE)
    assert block is not None, "server.mjs no longer declares humanTokenRoutes"
    allowlist = [
        re.compile(raw[1:-1])
        for raw in re.findall(r"^\s*(/\^.*\$/),\s*$", block.group(1), re.MULTILINE)
    ]

    for path in ("/api/v1/connections/estates", "/api/v1/connections/estate-grant-plan"):
        assert any(pattern.match(path) for pattern in allowlist), (
            f"the console commands {path} but the proxy would refuse its identity token"
        )


def test_a_probe_runs_under_the_session_and_csrf_not_a_pasted_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The probe is a read-only check: session plus current ADMIN, no challenge.

    The pasted-token header is gone from this route: the registry records the
    probe as granting nothing, so a challenge would be ceremony, but what a
    customer delegation can reach is disclosed only to a signed-in
    administrator.
    """

    client, _store, prober = _client(monkeypatch)
    client.cookies.set("__Host-solvan_csrf", "token")
    response = client.post(
        "/api/v1/connections/con_01J00000000000000000000000:probe",
        headers={"X-Solvan-CSRF": "token"},
    )
    assert response.status_code == 200
    assert prober.probed == ["con_01J00000000000000000000000"]


def test_a_probe_without_the_double_submit_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _store, prober = _client(monkeypatch)
    response = client.post("/api/v1/connections/con_01J00000000000000000000000:probe")
    assert response.status_code == 403
    assert prober.probed == []
