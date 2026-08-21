"""One-click connect, and the narrow path that widens a binding.

The design claim under test is that the shape follows the stakes. Binding a
repository so Solvan can only *read* it asks nothing per repository, because
`SYNC_PULL_REQUEST` changes nothing on GitHub and there is no per-repository
judgement to make. Granting it authorship, merge, or a voice in a thread asks
for exactly one repository at a time, because an App installation grants reach
and has no way to express any of those.

So most of what follows checks that the cheap path stays cheap *and* stays
read-only, and that widening cannot happen by accident, in bulk, or without an
operator re-authenticating against the exact authority being granted.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from psycopg.errors import UniqueViolation

from apps.api.github_app_configuration import GitHubAppConfiguration
from apps.api.github_binding_material import (
    binding_material,
    connect_all_material,
    regrant_material,
)
from apps.api.github_connect import github_connect_router
from solvan.platform.github import GitHubAppClient, GitHubClient
from solvan.platform.github_app_auth import StaticGitHubTokenProvider
from tests.unit.test_github_onboarding import (
    _APP_JWT,
    _INSTALLATION_TOKEN,
    _SCOPE,
    _configuration,
    _Database,
    _GitHubTransport,
)

_ADMITTED = "user:operator@example.com"


class _RegrantDatabase(_Database):
    """A fake carrying one already-bound repository that can be re-granted."""

    def __init__(self, *, allowed: tuple[str, ...] = ("SYNC_PULL_REQUEST",)) -> None:
        super().__init__()
        self.allowed = allowed
        self.regrants: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []

    def __call__(self) -> Any:
        return _RegrantConnection(self)


class _RegrantCursor:
    def __init__(self, database: _RegrantDatabase) -> None:
        self._database = database
        self._row: Any = None
        self.rowcount = 0

    def __enter__(self) -> _RegrantCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        self._database.statements.append((statement, dict(parameters or {})))
        values = dict(parameters or {})
        if "FROM solvan.github_repositories" in statement and "FOR UPDATE" in statement:
            self._row = {
                "id": values.get("id"),
                "installation_id": 42_991,
                "owner": "acme",
                "name": "platform",
                "default_branch": "main",
                "api_base_url": "https://api.github.com",
                "classification": "INTERNAL",
                "policy_hash": "sha256:" + "a" * 64,
                "allowed_operations_json": list(self._database.allowed),
                "status": "ACTIVE",
            }
            self.rowcount = 1
        elif "UPDATE solvan.github_repositories" in statement:
            self._database.regrants.append(values)
            self.rowcount = 1
            self._row = None
        elif "INSERT INTO solvan.audit_events" in statement:
            self._database.audit.append(values)
            self.rowcount = 1
            self._row = None
        elif "INSERT INTO solvan.github_repositories" in statement:
            identity = (values["owner"], values["name"])
            if identity in {(row["owner"], row["name"]) for row in self._database.bindings}:
                raise UniqueViolation("github repository binding already exists")
            self._database.bindings.append(values)
            self.rowcount = 1
            self._row = None
        elif "actor_role_bindings" in statement:
            self._row = (self._database.administrator,)
        else:
            self._row = None

    def fetchone(self) -> Any:
        return self._row


class _RegrantConnection:
    def __init__(self, database: _RegrantDatabase) -> None:
        self._database = database

    def __enter__(self) -> _RegrantConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self, row_factory: Any = None) -> _RegrantCursor:
        return _RegrantCursor(self._database)

    def transaction(self) -> _RegrantConnection:
        return self


def _client(
    *,
    database: Any = None,
    configuration: GitHubAppConfiguration | None = None,
    administrator: Any = None,
) -> tuple[TestClient, Any, _GitHubTransport]:
    store = database if database is not None else _RegrantDatabase()
    api = _GitHubTransport()
    api.installation_ids = []
    settings = configuration or _configuration()

    def _app_client(active: GitHubAppConfiguration) -> GitHubAppClient:
        return GitHubAppClient(
            transport=api, app_jwt_provider=lambda: _APP_JWT, api_base_url=active.api_base_url
        )

    def _installation_client(active: GitHubAppConfiguration, installation_id: int) -> GitHubClient:
        api.installation_ids.append(installation_id)
        return GitHubClient(
            transport=api,
            token_provider=StaticGitHubTokenProvider(_INSTALLATION_TOKEN),
            installation_id=installation_id,
            api_base_url=active.api_base_url,
        )

    app = FastAPI()
    app.include_router(
        github_connect_router(
            scope_provider=lambda: _SCOPE,
            configuration_provider=lambda: settings,
            app_client_factory=_app_client,
            installation_client_factory=_installation_client,
            connect=store,
            administrator=administrator or (lambda _request, _scope: _ADMITTED),
            authorize=lambda _connection, _request, **_kwargs: _ADMITTED,
        )
    )
    return TestClient(app), store, api


# --------------------------------------------------------------------------
# The cheap path stays cheap, and stays read-only.
# --------------------------------------------------------------------------


def test_connecting_an_installation_binds_every_repository_investigate_only() -> None:
    client, database, _ = _client()
    response = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={"schema_version": 1, "installation_id": 42_991},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["bound"] >= 1
    assert body["account_login"]
    # Every binding created without asking a question grants exactly the one
    # operation that changes nothing on GitHub.
    for binding in database.bindings:
        assert binding["allowed_operations_json"] == '["SYNC_PULL_REQUEST"]'
        assert binding["status"] == "PENDING"


def test_a_bulk_connect_cannot_be_asked_for_write_authority() -> None:
    """There is no field for it, so `extra="forbid"` refuses the attempt."""

    client, database, _ = _client()
    response = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={
            "schema_version": 1,
            "installation_id": 42_991,
            "allowed_operations": ["MERGE_PULL_REQUEST"],
        },
    )
    assert response.status_code == 422
    assert database.bindings == []


def test_a_bulk_connect_cannot_classify_everything_as_restricted() -> None:
    client, _, _ = _client()
    response = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={"schema_version": 1, "installation_id": 42_991, "classification": "RESTRICTED"},
    )
    assert response.status_code == 422


def test_a_path_and_body_that_disagree_are_refused() -> None:
    client, database, transport = _client()
    response = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={"schema_version": 1, "installation_id": 999},
    )
    assert response.status_code == 422
    assert database.bindings == []
    assert transport.calls == []


def test_an_already_bound_repository_is_reported_and_left_alone() -> None:
    client, database, _ = _client()
    first = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={"schema_version": 1, "installation_id": 42_991},
    )
    assert first.status_code == 200
    created = len(database.bindings)
    second = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={"schema_version": 1, "installation_id": 42_991},
    )
    assert second.status_code == 200
    body = second.json()
    assert body["bound"] == 0
    assert body["already_bound"] >= 1
    # Re-running the bulk connect neither duplicates a binding nor rewrites one.
    assert len(database.bindings) == created
    assert all(item["outcome"] == "ALREADY_BOUND" for item in body["repositories"])


def test_an_unauthenticated_caller_reaches_no_github_read() -> None:
    def _refuse(_request: Any, _scope: Any) -> str:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")

    client, database, transport = _client(administrator=_refuse)
    response = client.post(
        "/api/v1/github/installations/42991:connect-all",
        json={"schema_version": 1, "installation_id": 42_991},
    )
    assert response.status_code == 401
    assert transport.calls == []
    assert database.bindings == []


# --------------------------------------------------------------------------
# Widening asks, one repository at a time.
# --------------------------------------------------------------------------


def _regrant(client: TestClient, **overrides: Any) -> Any:
    body: dict[str, Any] = {
        "schema_version": 1,
        "allowed_operations": ["SYNC_PULL_REQUEST", "POST_ISSUE_COMMENT"],
        "classification": "INTERNAL",
    }
    body.update(overrides)
    return client.post(
        "/api/v1/github/repositories/ghr_0000000000000000000000000C/authority", json=body
    )


def test_widening_records_the_new_authority_and_sends_it_back_for_probing() -> None:
    client, database, _ = _client()
    response = _regrant(client)
    assert response.status_code == 200
    body = response.json()
    assert body["previous_operations"] == ["SYNC_PULL_REQUEST"]
    assert body["allowed_operations"] == ["POST_ISSUE_COMMENT", "SYNC_PULL_REQUEST"]
    assert body["grants_conversation"] is True
    assert body["investigate_only"] is False
    # An ACTIVE binding whose authority changed is not still ACTIVE: the probe
    # on record confirmed the previous policy.
    assert body["status"] == "PENDING"
    assert database.regrants and database.regrants[0]["policy_hash"] != "sha256:" + "a" * 64


def test_widening_is_recorded_as_an_append_only_change() -> None:
    client, database, _ = _client()
    assert _regrant(client).status_code == 200
    assert len(database.audit) == 1
    assert database.audit[0]["actor"] == _ADMITTED


def test_merge_authority_over_a_restricted_repository_is_refused() -> None:
    # The release posture is on, so the refusal under test is the
    # classification one rather than the posture gate that would fire first.
    client, database, _ = _client(configuration=_configuration(release_enabled=True))
    response = _regrant(
        client,
        allowed_operations=["SYNC_PULL_REQUEST", "MERGE_PULL_REQUEST"],
        classification="RESTRICTED",
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "GITHUB_BINDING_REFUSED"
    assert database.regrants == []


def test_write_authority_is_refused_while_the_release_posture_is_off() -> None:
    client, database, _ = _client(configuration=_configuration(release_enabled=False))
    response = _regrant(client, allowed_operations=["SYNC_PULL_REQUEST", "CREATE_PULL_REQUEST"])
    assert response.status_code == 409
    assert response.json()["detail"] == "GITHUB_RELEASE_POSTURE_DISABLED"
    assert database.regrants == []


def test_an_empty_authority_set_is_refused() -> None:
    client, database, _ = _client()
    assert _regrant(client, allowed_operations=[]).status_code == 422
    assert database.regrants == []


def test_widening_refuses_an_unauthenticated_caller_before_reading_anything() -> None:
    def _refuse(_request: Any, _scope: Any) -> str:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")

    client, database, transport = _client(administrator=_refuse)
    assert _regrant(client).status_code == 401
    assert database.regrants == []
    assert transport.calls == []


# --------------------------------------------------------------------------
# What a step-up is bound to.
# --------------------------------------------------------------------------


def test_the_bulk_material_names_the_installation_and_read_only_authority() -> None:
    material = connect_all_material(installation_id=42_991, classification="INTERNAL")
    assert "github-connect-all:v1" in material
    assert "42991" in material
    assert material.endswith("SYNC_PULL_REQUEST")


def test_the_bulk_material_changes_with_the_installation() -> None:
    first = connect_all_material(installation_id=1, classification="INTERNAL")
    second = connect_all_material(installation_id=2, classification="INTERNAL")
    assert first != second


def test_the_widening_material_carries_the_exact_authority() -> None:
    """A page altered while the operator re-authenticates cannot reuse the challenge."""

    shown = regrant_material(
        repository_id="ghr_0000000000000000000000000C",
        allowed_operations=("SYNC_PULL_REQUEST",),
        classification="INTERNAL",
    )
    widened = regrant_material(
        repository_id="ghr_0000000000000000000000000C",
        allowed_operations=("SYNC_PULL_REQUEST", "MERGE_PULL_REQUEST"),
        classification="INTERNAL",
    )
    assert shown != widened


def test_the_widening_material_is_order_independent() -> None:
    """The same authority is the same material however the client ordered it."""

    forward = regrant_material(
        repository_id="ghr_1",
        allowed_operations=("CREATE_PULL_REQUEST", "SYNC_PULL_REQUEST"),
        classification="INTERNAL",
    )
    reversed_order = regrant_material(
        repository_id="ghr_1",
        allowed_operations=("SYNC_PULL_REQUEST", "CREATE_PULL_REQUEST"),
        classification="INTERNAL",
    )
    assert forward == reversed_order


def test_binding_material_distinguishes_repositories_and_authority() -> None:
    def material(name: str, operations: tuple[str, ...]) -> str:
        return binding_material(
            installation_id=42_991,
            owner="acme",
            name=name,
            classification="INTERNAL",
            allowed_operations=operations,  # type: ignore[arg-type]
        )

    assert material("platform", ("SYNC_PULL_REQUEST",)) != material("other", ("SYNC_PULL_REQUEST",))
    assert material("platform", ("SYNC_PULL_REQUEST",)) != material(
        "platform", ("SYNC_PULL_REQUEST", "MERGE_PULL_REQUEST")
    )


def test_every_material_form_is_distinguishable_from_the_others() -> None:
    """One challenge cannot be replayed against a different kind of decision."""

    forms = {
        connect_all_material(installation_id=1, classification="INTERNAL"),
        regrant_material(
            repository_id="ghr_1",
            allowed_operations=("SYNC_PULL_REQUEST",),
            classification="INTERNAL",
        ),
        binding_material(
            installation_id=1,
            owner="acme",
            name="platform",
            classification="INTERNAL",
            allowed_operations=("SYNC_PULL_REQUEST",),
        ),
    }
    assert len(forms) == 3


@pytest.mark.parametrize("classification", ["PUBLIC", "INTERNAL", "CONFIDENTIAL"])
def test_the_bulk_material_carries_its_classification(classification: str) -> None:
    material = connect_all_material(installation_id=42_991, classification=classification)
    assert classification in material


# --------------------------------------------------------------------------
# One deployment serves every connected repository.
# --------------------------------------------------------------------------


def test_a_connected_repository_is_probed_so_it_does_not_sit_pending() -> None:
    """Connecting asks for the observation that promotes a binding.

    A binding is written PENDING and only the provider's own observation may
    promote it. Without the request an operator who pressed Connect would watch
    every repository stay PENDING until somebody ran release tooling by hand.
    """

    import apps.api.github_connect as connect

    asked: list[str] = []
    original = connect._request_probes
    connect._request_probes = lambda ids: (asked.extend(ids) or dict.fromkeys(ids, "ACTIVE"))
    try:
        client, database, _ = _client()
        response = client.post(
            "/api/v1/github/installations/42991:connect-all",
            json={"schema_version": 1, "installation_id": 42_991},
        )
    finally:
        connect._request_probes = original
    assert response.status_code == 200
    assert asked, "no probe was requested for a newly connected repository"
    assert len(asked) == len(database.bindings)
    assert all(item["status"] == "PENDING" for item in database.bindings)


def test_an_unreachable_provider_leaves_the_binding_pending_not_failed() -> None:
    """The bindings are committed and correct; only confirmation is missing.

    Raising here would report a failed connect for repositories that were in
    fact bound, and PENDING already says exactly what is true of them.
    """

    import apps.api.github_connect as connect

    original = connect._request_probes
    connect._request_probes = lambda ids: dict.fromkeys(ids, "PROBE_FAILED")
    try:
        client, database, _ = _client()
        response = client.post(
            "/api/v1/github/installations/42991:connect-all",
            json={"schema_version": 1, "installation_id": 42_991},
        )
    finally:
        connect._request_probes = original
    assert response.status_code == 200
    assert response.json()["bound"] >= 1
    assert database.bindings


def test_an_unconfigured_provider_is_reported_rather_than_raised() -> None:
    import apps.api.github_connect as connect

    outcomes = connect._request_probes(["ghr_0000000000000000000000000C"])
    assert outcomes == {"ghr_0000000000000000000000000C": "PROVIDER_NOT_CONFIGURED"}


# --------------------------------------------------------------------------
# One continuous install: begin, install on GitHub, land back here.
# --------------------------------------------------------------------------


class _IntentDatabase(_RegrantDatabase):
    """A fake carrying the install-intent lifecycle."""

    def __init__(self) -> None:
        super().__init__()
        self.intents: dict[str, dict[str, Any]] = {}

    def __call__(self) -> Any:
        return _IntentConnection(self)


class _IntentCursor(_RegrantCursor):
    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        values = dict(parameters or {})
        database = self._database
        if "INSERT INTO solvan_conversation.github_installation_intents" in statement:
            if any(
                item["state_hash"] == values["state_hash"]
                for item in database.intents.values()  # type: ignore[attr-defined]
            ):
                raise UniqueViolation("state already minted")
            database.intents[values["id"]] = {**values, "status": "PENDING"}  # type: ignore[attr-defined]
            self.rowcount = 1
            self._row = None
            return
        if "SET status='CLAIMED'" in statement:
            # The atomic claim: one presentation of a link wins, and only while
            # the intent is pending and unexpired.
            match = next(
                (
                    item
                    for item in database.intents.values()  # type: ignore[attr-defined]
                    if item["state_hash"] == values.get("state_hash")
                    and item["status"] == "PENDING"
                    and item["expires_at"] > values["now"]
                ),
                None,
            )
            if match is None:
                self.rowcount = 0
                self._row = None
                return
            match["status"] = "CLAIMED"
            match["claimed_at"] = values["now"]
            self.rowcount = 1
            self._row = {
                "id": match["id"],
                "classification": match["classification"],
                "actor_principal": match["actor"],
            }
            return
        if "UPDATE solvan_conversation.github_installation_intents" in statement:
            if "state_hash" in values:
                # The expiry sweep the refused claim performs.
                match = next(
                    (
                        item
                        for item in database.intents.values()  # type: ignore[attr-defined]
                        if item["state_hash"] == values["state_hash"]
                        and item["status"] == "PENDING"
                        and item["expires_at"] <= values["now"]
                    ),
                    None,
                )
                if match is not None:
                    match["status"] = "REFUSED"
                self.rowcount = 1 if match is not None else 0
                self._row = None
                return
            item = database.intents.get(values.get("id", ""))  # type: ignore[attr-defined]
            claimable = {"CLAIMED"} if "CONSUMED" in statement else {"PENDING", "CLAIMED"}
            if item is not None and item["status"] in claimable:
                item["status"] = "CONSUMED" if "CONSUMED" in statement else "REFUSED"
                self.rowcount = 1
            else:
                self.rowcount = 0
            self._row = None
            return
        super().execute(statement, parameters)


class _IntentConnection(_RegrantConnection):
    def cursor(self, row_factory: Any = None) -> _IntentCursor:
        return _IntentCursor(self._database)


def _install_client(
    *, database: Any = None, administrator: Any = None
) -> tuple[TestClient, Any, list[list[str]]]:
    from apps.api.github_install_flow import github_install_router

    store = database if database is not None else _IntentDatabase()
    api = _GitHubTransport()
    api.installation_ids = []
    settings = _configuration()
    probed: list[list[str]] = []

    def _app_client_factory(active: GitHubAppConfiguration) -> GitHubAppClient:
        return GitHubAppClient(
            transport=api, app_jwt_provider=lambda: _APP_JWT, api_base_url=active.api_base_url
        )

    def _installation_client_factory(
        active: GitHubAppConfiguration, installation_id: int
    ) -> GitHubClient:
        api.installation_ids.append(installation_id)
        return GitHubClient(
            transport=api,
            token_provider=StaticGitHubTokenProvider(_INSTALLATION_TOKEN),
            installation_id=installation_id,
            api_base_url=active.api_base_url,
        )

    app = FastAPI()
    app.include_router(
        github_install_router(
            scope_provider=lambda: _SCOPE,
            configuration_provider=lambda: settings,
            app_client_factory=_app_client_factory,
            installation_client_factory=_installation_client_factory,
            connect=store,
            administrator=administrator or (lambda _request, _scope: _ADMITTED),
            authorize=lambda _connection, _request, **_kwargs: _ADMITTED,
            probe=lambda ids: (probed.append(list(ids)) or dict.fromkeys(ids, "ACTIVE")),
        )
    )
    return TestClient(app, follow_redirects=False), store, probed


def _begin(client: TestClient) -> str:
    response = client.post("/api/v1/github/installations:begin", json={"schema_version": 1})
    assert response.status_code == 200
    url = response.json()["install_url"]
    return url.split("state=", 1)[1]


def test_beginning_an_install_returns_the_github_url_carrying_one_state() -> None:
    client, _, _ = _install_client()
    response = client.post("/api/v1/github/installations:begin", json={"schema_version": 1})
    assert response.status_code == 200
    url = response.json()["install_url"]
    assert "/apps/solvan-reliability/installations/new?state=" in url


def test_the_returning_redirect_binds_everything_the_installation_reaches() -> None:
    client, database, probed = _install_client()
    state = _begin(client)
    response = client.get(
        "/api/v1/github/installations/callback",
        params={"state": state, "installation_id": 42_991, "setup_action": "install"},
    )
    assert response.status_code == 303
    assert "github_install=CONNECTED" in response.headers["location"]
    assert database.bindings
    assert all(
        item["allowed_operations_json"] == '["SYNC_PULL_REQUEST"]' for item in database.bindings
    )
    assert probed and probed[0]


def test_an_install_link_completes_exactly_once() -> None:
    """A replayed redirect must not produce a second set of bindings."""

    client, database, _ = _install_client()
    state = _begin(client)
    params = {"state": state, "installation_id": 42_991, "setup_action": "install"}
    first = client.get("/api/v1/github/installations/callback", params=params)
    assert "github_install=CONNECTED" in first.headers["location"]
    created = len(database.bindings)
    second = client.get("/api/v1/github/installations/callback", params=params)
    assert "github_install=REFUSED" in second.headers["location"]
    assert len(database.bindings) == created


def test_an_unknown_state_is_refused_without_reaching_github() -> None:
    client, database, _ = _install_client()
    response = client.get(
        "/api/v1/github/installations/callback",
        params={"state": "not-a-real-state", "installation_id": 42_991},
    )
    assert "github_install=REFUSED" in response.headers["location"]
    assert "reason=LINK_NOT_VALID" in response.headers["location"]
    assert database.bindings == []


def test_absent_expired_and_used_links_are_one_outcome() -> None:
    """Distinguishing them would make this endpoint an oracle for valid states."""

    client, _, _ = _install_client()
    state = _begin(client)
    params = {"state": state, "installation_id": 42_991, "setup_action": "install"}
    client.get("/api/v1/github/installations/callback", params=params)
    used = client.get("/api/v1/github/installations/callback", params=params)
    unknown = client.get(
        "/api/v1/github/installations/callback",
        params={"state": "nope", "installation_id": 42_991},
    )
    assert "reason=LINK_NOT_VALID" in used.headers["location"]
    assert "reason=LINK_NOT_VALID" in unknown.headers["location"]


def test_a_forged_installation_id_can_only_select_a_real_installation() -> None:
    """The number is a selector verified against GitHub, never a fact."""

    client, database, _ = _install_client()
    state = _begin(client)
    response = client.get(
        "/api/v1/github/installations/callback",
        params={"state": state, "installation_id": 999_999, "setup_action": "install"},
    )
    assert "github_install=REFUSED" in response.headers["location"]
    assert database.bindings == []


def test_a_redirect_with_no_installation_is_refused() -> None:
    client, database, _ = _install_client()
    state = _begin(client)
    response = client.get("/api/v1/github/installations/callback", params={"state": state})
    assert "reason=NO_INSTALLATION" in response.headers["location"]
    assert database.bindings == []


def test_beginning_an_install_refuses_a_non_administrator() -> None:
    def _refuse(_request: Any, _scope: Any) -> str:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")

    client, database, _ = _install_client(administrator=_refuse)
    response = client.post("/api/v1/github/installations:begin", json={"schema_version": 1})
    assert response.status_code == 401
    assert database.bindings == []


def test_the_install_material_names_authority_but_not_the_account() -> None:
    """The account is chosen on GitHub after the challenge is spent."""

    from apps.api.github_install_flow import install_material

    material = install_material(classification="INTERNAL")
    assert material == "github-install:v1:INTERNAL:SYNC_PULL_REQUEST"
    assert install_material(classification="PUBLIC") != material
