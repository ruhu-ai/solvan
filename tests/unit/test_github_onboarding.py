"""Connecting GitHub from the console observes GitHub; it never takes dictation.

The onboarding routes exist because the only prior path to a repository binding
was a nine-variable admin tool. What replaces it has to be worth more than the
convenience: these cover that installations and repositories come from the API
rather than from the request, that the recorded binding is PENDING and
investigate-only unless an administrator says otherwise, that an unconfigured
App refuses instead of half-working, and that no route accepts a credential or
returns a token.

Every transport here is a fake. Nothing in this file may reach github.com.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from psycopg.errors import UniqueViolation

from apps.api.github_onboarding import (
    INVESTIGATE_ONLY,
    GitHubAppConfiguration,
    GitHubOnboardingError,
    configured_github_app,
    github_onboarding_router,
)
from solvan.domain import Scope
from solvan.platform.github import (
    GitHubApiError,
    GitHubAppClient,
    GitHubClient,
)
from solvan.platform.github_app_auth import StaticGitHubTokenProvider

_SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
_ADMIN = {"X-Solvan-Approval-Token": "Bearer verified"}
#: Distinct sentinels so a test can tell which credential reached which
#: endpoint, and so a leak check has something exact to search a response for.
_APP_JWT = "app-jwt-sentinel-value"
_INSTALLATION_TOKEN = "ghs_installation-token-sentinel-value"

_SECRET_PREFIX = "projects/solvan-release/secrets"
_APP_ID_REF = f"{_SECRET_PREFIX}/github-app-id/versions/3"
_PRIVATE_KEY_REF = f"{_SECRET_PREFIX}/github-app-private-key/versions/7"
_WEBHOOK_REF = f"{_SECRET_PREFIX}/github-webhook-secret/versions/2"


def _configuration(*, release_enabled: bool = False) -> GitHubAppConfiguration:
    return GitHubAppConfiguration(
        app_slug="solvan-reliability",
        app_id_secret_ref=_APP_ID_REF,
        private_key_secret_ref=_PRIVATE_KEY_REF,
        credential_secret_ref=_PRIVATE_KEY_REF,
        webhook_secret_ref=_WEBHOOK_REF,
        api_base_url="https://api.github.com",
        web_base_url="https://github.com",
        release_enabled=release_enabled,
    )


class _Response:
    def __init__(self, value: object, status_code: int = 200) -> None:
        self.status_code = status_code
        self.content = json.dumps(value).encode()

    def json(self) -> Any:
        return json.loads(self.content)


_INSTALLATIONS = [
    {
        "id": 42_991,
        "account": {"login": "acme-platform", "type": "Organization"},
        "target_type": "Organization",
        "repository_selection": "selected",
        "html_url": "https://github.com/organizations/acme-platform/settings/installations/42991",
        "suspended_at": None,
    },
    {
        "id": 42_992,
        "account": {"login": "acme-suspended", "type": "Organization"},
        "target_type": "Organization",
        "repository_selection": "all",
        "html_url": "https://github.com/organizations/acme-suspended/settings/installations/42992",
        "suspended_at": "2026-08-01T00:00:00Z",
    },
]

_REPOSITORIES = {
    42_991: [
        {
            "owner": {"login": "acme-platform"},
            "name": "checkout-service",
            "default_branch": "release",
            "private": True,
            "archived": False,
            "html_url": "https://github.com/acme-platform/checkout-service",
        },
        {
            "owner": {"login": "acme-platform"},
            "name": "archived-billing",
            "default_branch": "main",
            "private": True,
            "archived": True,
            "html_url": "https://github.com/acme-platform/archived-billing",
        },
        # Dropped by the platform reader: no default branch means no binding
        # this repository could legally support.
        {"owner": {"login": "acme-platform"}, "name": "unusable"},
    ],
    42_992: [],
}


class _GitHubTransport:
    """Answers only the two read paths onboarding uses, and records both."""

    def __init__(self, *, installations: list[dict[str, Any]] | None = None) -> None:
        self._installations = _INSTALLATIONS if installations is None else installations
        self.calls: list[tuple[str, dict[str, Any]]] = []
        #: Appended by the installation client factory, so the transport can
        #: answer for whichever installation the route authenticated as.
        self.installation_ids: list[int] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append((url, kwargs))
        # Every onboarding read is bounded and refuses redirects, matching how
        # this client already fetches repository content.
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == 30
        authorization = kwargs["headers"]["Authorization"]
        if url.startswith("https://api.github.com/app/installations"):
            assert authorization == f"Bearer {_APP_JWT}"
            return _Response(self._installations if "page=1" in url else [])
        if url.startswith("https://api.github.com/installation/repositories"):
            assert authorization == f"Bearer {_INSTALLATION_TOKEN}"
            installation_id = self.installation_ids[-1]
            page = _REPOSITORIES.get(installation_id, []) if "page=1" in url else []
            return _Response({"total_count": len(page), "repositories": page})
        raise AssertionError(f"onboarding reached an unexpected GitHub path: {url}")


class _Cursor:
    def __init__(self, database: _Database) -> None:
        self._database = database
        self._row: tuple[Any, ...] | None = None

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: dict[str, Any] | None = None) -> None:
        self._database.statements.append((statement, dict(parameters or {})))
        if "INSERT INTO solvan.github_repositories" in statement:
            assert parameters is not None
            identity = (parameters["owner"], parameters["name"])
            if identity in {(row["owner"], row["name"]) for row in self._database.bindings}:
                raise UniqueViolation("github repository binding already exists")
            self._database.bindings.append(dict(parameters))
            self._row = None
        elif "actor_role_bindings" in statement:
            self._row = (self._database.administrator,)
        else:
            self._row = None

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Connection:
    def __init__(self, database: _Database) -> None:
        self._database = database

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return _Cursor(self._database)

    def transaction(self) -> _Connection:
        return self


class _Database:
    def __init__(self, *, administrator: bool = True) -> None:
        self.administrator = administrator
        self.bindings: list[dict[str, Any]] = []
        self.statements: list[tuple[str, dict[str, Any]]] = []

    def __call__(self) -> _Connection:
        return _Connection(self)


def _client(
    *,
    database: _Database | None = None,
    configuration: GitHubAppConfiguration | None = None,
    transport: _GitHubTransport | None = None,
    principal_provider: Any = None,
    unconfigured: bool = False,
) -> tuple[TestClient, _Database, _GitHubTransport]:
    store = database or _Database()
    api = transport or _GitHubTransport()
    api.installation_ids = []
    settings = configuration or _configuration()

    def _configuration_provider() -> GitHubAppConfiguration:
        if unconfigured:
            raise GitHubOnboardingError(
                "GITHUB_APP_NOT_CONFIGURED", http_status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        return settings

    def _app_client(active: GitHubAppConfiguration) -> GitHubAppClient:
        return GitHubAppClient(
            transport=api,
            app_jwt_provider=lambda: _APP_JWT,
            api_base_url=active.api_base_url,
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
        github_onboarding_router(
            principal_provider=principal_provider or (lambda _request: "user:operator@example.com"),
            # The step-up spender needs a live session, a CSRF pair, and an
            # unspent challenge, none of which exist against this fake
            # database. The seam supplies the principal the challenge would
            # have established; every other property under test is unaffected.
            authorize=lambda _connection, _request, **_kwargs: "user:operator@example.com",
            scope_provider=lambda: _SCOPE,
            configuration_provider=_configuration_provider,
            app_client_factory=_app_client,
            installation_client_factory=_installation_client,
            connect=store,
        )
    )
    return TestClient(app), store, api


def _bind(client: TestClient, **overrides: Any) -> Any:
    body = {
        "schema_version": 1,
        "installation_id": 42_991,
        "owner": "acme-platform",
        "name": "checkout-service",
        **overrides,
    }
    return client.post("/api/v1/github/repositories", headers=_ADMIN, json=body)


def test_installations_are_listed_from_github_rather_than_from_the_request() -> None:
    client, _, transport = _client()

    response = client.get("/api/v1/github/installations", headers=_ADMIN)

    assert response.status_code == 200
    assert [item["installation_id"] for item in response.json()] == [42_991, 42_992]
    assert response.json()[0]["account_login"] == "acme-platform"
    assert response.json()[1]["suspended"] is True
    # The App JWT is what reached /app/installations; the transport asserts it.
    assert any("/app/installations" in url for url, _ in transport.calls)


def test_repositories_are_listed_with_that_installations_own_token() -> None:
    client, _, transport = _client()

    response = client.get("/api/v1/github/installations/42991/repositories", headers=_ADMIN)

    assert response.status_code == 200
    assert [item["name"] for item in response.json()] == ["checkout-service", "archived-billing"]
    assert response.json()[0]["default_branch"] == "release"
    assert transport.installation_ids == [42_991]


def test_an_installation_the_app_does_not_own_is_refused() -> None:
    client, _, transport = _client()

    response = client.get("/api/v1/github/installations/999/repositories", headers=_ADMIN)

    assert response.status_code == 404
    assert response.json()["detail"] == "GITHUB_INSTALLATION_NOT_FOUND"
    # No installation token was minted for an identifier GitHub never listed.
    assert transport.installation_ids == []


def test_a_binding_is_recorded_pending_and_investigate_only_by_default() -> None:
    client, database, _ = _client()

    response = _bind(client)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "PENDING"
    assert body["investigate_only"] is True
    assert tuple(body["allowed_operations"]) == INVESTIGATE_ONLY
    assert "CREATE_PULL_REQUEST" not in body["allowed_operations"]
    assert "MERGE_PULL_REQUEST" not in body["allowed_operations"]
    recorded = database.bindings[0]
    assert recorded["status"] == "PENDING"
    assert json.loads(recorded["allowed_operations_json"]) == list(INVESTIGATE_ONLY)
    assert recorded["actor"] == "user:operator@example.com"


def test_the_recorded_identity_is_githubs_answer_not_the_operators() -> None:
    client, database, _ = _client()

    # Different case, and a default branch the request has no way to state.
    response = _bind(client, owner="ACME-Platform", name="Checkout-Service")

    assert response.status_code == 200
    assert response.json()["owner"] == "acme-platform"
    assert response.json()["name"] == "checkout-service"
    assert response.json()["default_branch"] == "release"
    recorded = database.bindings[0]
    assert (recorded["owner"], recorded["name"]) == ("acme-platform", "checkout-service")
    assert recorded["default_branch"] == "release"
    assert recorded["installation_id"] == 42_991


def test_a_repository_the_installation_cannot_reach_is_refused() -> None:
    client, database, _ = _client()

    response = _bind(client, name="secret-internal-tooling")

    assert response.status_code == 404
    assert response.json()["detail"] == "GITHUB_REPOSITORY_NOT_REACHABLE"
    assert database.bindings == []


def test_a_suspended_installation_cannot_back_a_binding() -> None:
    client, database, _ = _client()

    response = _bind(client, installation_id=42_992)

    assert response.status_code == 409
    assert response.json()["detail"] == "GITHUB_INSTALLATION_SUSPENDED"
    assert database.bindings == []


def test_a_repository_is_only_bindable_through_the_installation_that_reaches_it() -> None:
    """The same name under a live installation that lists nothing is refused."""

    live = [{**_INSTALLATIONS[1], "suspended_at": None}]
    client, database, _ = _client(transport=_GitHubTransport(installations=live))

    response = _bind(client, installation_id=42_992)

    assert response.status_code == 404
    assert response.json()["detail"] == "GITHUB_REPOSITORY_NOT_REACHABLE"
    assert database.bindings == []


def test_chosen_operations_are_recorded_when_the_release_posture_permits_them() -> None:
    client, database, _ = _client(configuration=_configuration(release_enabled=True))

    response = _bind(client, allowed_operations=["CREATE_PULL_REQUEST", "SYNC_PULL_REQUEST"])

    assert response.status_code == 200
    assert response.json()["investigate_only"] is False
    assert response.json()["status"] == "PENDING"
    assert json.loads(database.bindings[0]["allowed_operations_json"]) == [
        "CREATE_PULL_REQUEST",
        "SYNC_PULL_REQUEST",
    ]


def test_write_authority_is_refused_while_the_release_posture_is_off() -> None:
    client, database, _ = _client()

    response = _bind(client, allowed_operations=["CREATE_PULL_REQUEST"])

    assert response.status_code == 409
    assert response.json()["detail"] == "GITHUB_RELEASE_POSTURE_DISABLED"
    assert database.bindings == []


def test_an_archived_repository_cannot_receive_write_authority() -> None:
    client, database, _ = _client(configuration=_configuration(release_enabled=True))

    refused = _bind(client, name="archived-billing", allowed_operations=["MERGE_PULL_REQUEST"])
    permitted = _bind(client, name="archived-billing")

    assert refused.status_code == 409
    assert refused.json()["detail"] == "GITHUB_REPOSITORY_ARCHIVED"
    assert permitted.status_code == 200
    assert [row["name"] for row in database.bindings] == ["archived-billing"]


def test_an_empty_or_repeated_allowlist_is_refused() -> None:
    client, database, _ = _client()

    empty = _bind(client, allowed_operations=[])
    repeated = _bind(client, allowed_operations=["SYNC_PULL_REQUEST", "SYNC_PULL_REQUEST"])

    assert empty.status_code == 422
    assert empty.json()["detail"] == "GITHUB_OPERATIONS_INVALID"
    assert repeated.status_code == 422
    assert repeated.json()["detail"] == "GITHUB_OPERATIONS_INVALID"
    assert database.bindings == []


def test_an_operation_outside_the_closed_vocabulary_never_reaches_the_store() -> None:
    client, database, _ = _client()

    response = _bind(client, allowed_operations=["DELETE_REPOSITORY"])

    assert response.status_code == 422
    assert database.bindings == []


def test_a_repeated_binding_is_a_named_conflict() -> None:
    client, database, _ = _client()

    assert _bind(client).status_code == 200
    repeated = _bind(client)

    assert repeated.status_code == 409
    assert repeated.json()["detail"] == "GITHUB_BINDING_EXISTS"
    assert len(database.bindings) == 1


def test_an_unauthenticated_caller_is_refused_before_any_github_read() -> None:
    def _refuse(_request: Any) -> str:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing Google identity token")

    client, database, transport = _client(principal_provider=_refuse)

    for response in (
        client.get("/api/v1/github/app"),
        client.get("/api/v1/github/installations"),
        client.get("/api/v1/github/installations/42991/repositories"),
        client.post(
            "/api/v1/github/repositories",
            json={"schema_version": 1, "installation_id": 42_991, "owner": "a", "name": "b"},
        ),
    ):
        assert response.status_code == 401

    assert transport.calls == []
    assert database.bindings == []


def test_a_non_administrator_is_refused_before_any_github_read() -> None:
    client, database, transport = _client(database=_Database(administrator=False))

    for path in ("/api/v1/github/app", "/api/v1/github/installations"):
        response = client.get(path, headers=_ADMIN)
        assert response.status_code == 403
        assert response.json()["detail"] == "GITHUB_ADMINISTRATOR_REQUIRED"

    assert _bind(client).status_code == 403
    assert transport.calls == []
    assert database.bindings == []


def test_an_unconfigured_app_refuses_every_route() -> None:
    client, database, transport = _client(unconfigured=True)

    for response in (
        client.get("/api/v1/github/app", headers=_ADMIN),
        client.get("/api/v1/github/installations", headers=_ADMIN),
        client.get("/api/v1/github/installations/42991/repositories", headers=_ADMIN),
        _bind(client),
    ):
        assert response.status_code == 503
        assert response.json()["detail"] == "GITHUB_APP_NOT_CONFIGURED"

    assert transport.calls == []
    assert database.bindings == []


def test_no_credential_or_secret_reference_is_accepted_from_the_request() -> None:
    client, database, _ = _client()

    for smuggled in (
        {"credential_secret_ref": f"{_SECRET_PREFIX}/attacker-key/versions/1"},
        {"webhook_secret_ref": f"{_SECRET_PREFIX}/attacker-webhook/versions/1"},
        {"credential_secret_ref": "-----BEGIN RSA PRIVATE KEY-----"},
        {"status": "ACTIVE"},
        {"last_probe_result": "SUCCEEDED"},
        {"policy_hash": "sha256:" + "0" * 64},
        {"default_branch": "attacker-controlled"},
        {"api_base_url": "https://api.github.internal"},
    ):
        response = _bind(client, **smuggled)
        assert response.status_code == 422, smuggled

    assert database.bindings == []
    # The accepted request records this deployment's own references.
    assert _bind(client).status_code == 200
    assert database.bindings[0]["credential_secret_ref"] == _PRIVATE_KEY_REF
    assert database.bindings[0]["webhook_secret_ref"] == _WEBHOOK_REF


def test_no_route_can_create_an_active_binding() -> None:
    client, database, _ = _client(configuration=_configuration(release_enabled=True))

    responses = [
        _bind(client),
        _bind(client, name="archived-billing", allowed_operations=["SYNC_PULL_REQUEST"]),
    ]

    assert all(response.json()["status"] == "PENDING" for response in responses)
    assert {row["status"] for row in database.bindings} == {"PENDING"}
    # Nothing this router writes touches the probe columns the ACTIVE check
    # depends on, so promotion remains the release provider's decision alone.
    for statement, _parameters in database.statements:
        assert "last_probe_result" not in statement
        assert "'ACTIVE'" not in statement


def test_no_response_carries_a_token_a_jwt_or_a_private_key() -> None:
    client, _, _ = _client(configuration=_configuration(release_enabled=True))

    bodies = [
        client.get("/api/v1/github/app", headers=_ADMIN).text,
        client.get("/api/v1/github/installations", headers=_ADMIN).text,
        client.get("/api/v1/github/installations/42991/repositories", headers=_ADMIN).text,
        _bind(client).text,
        _bind(client).text,
        _bind(client, name="nonexistent").text,
    ]

    for body in bodies:
        assert _APP_JWT not in body
        assert _INSTALLATION_TOKEN not in body
        assert "PRIVATE KEY" not in body
        assert _APP_ID_REF not in body
        assert _PRIVATE_KEY_REF not in body
        assert _WEBHOOK_REF not in body


def test_the_app_posture_surfaces_the_install_link_the_operator_needs() -> None:
    client, _, _ = _client()

    body = client.get("/api/v1/github/app", headers=_ADMIN).json()

    assert body["install_url"] == "https://github.com/apps/solvan-reliability/installations/new"
    assert body["app_url"] == "https://github.com/apps/solvan-reliability"
    assert body["release_enabled"] is False
    assert tuple(body["investigate_only_operations"]) == INVESTIGATE_ONLY
    assert set(body["write_operations"]) == {
        "CREATE_PULL_REQUEST",
        "MERGE_PULL_REQUEST",
        "CLOSE_PULL_REQUEST",
    }


@pytest.mark.parametrize(
    "missing",
    [
        "SOLVAN_GITHUB_APP_SLUG",
        "SOLVAN_GITHUB_APP_ID_SECRET_REF",
        "SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF",
        "SOLVAN_GITHUB_WEBHOOK_SECRET_REF",
    ],
)
def test_partial_provisioning_refuses_rather_than_half_working(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    for name, value in (
        ("SOLVAN_GITHUB_APP_SLUG", "solvan-reliability"),
        ("SOLVAN_GITHUB_APP_ID_SECRET_REF", _APP_ID_REF),
        ("SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF", _PRIVATE_KEY_REF),
        ("SOLVAN_GITHUB_WEBHOOK_SECRET_REF", _WEBHOOK_REF),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SOLVAN_GITHUB_CREDENTIAL_SECRET_REF", raising=False)
    monkeypatch.delenv("SOLVAN_GITHUB_RELEASE_ENABLED", raising=False)
    assert configured_github_app().credential_secret_ref == _PRIVATE_KEY_REF
    assert configured_github_app().release_enabled is False

    monkeypatch.delenv(missing)

    with pytest.raises(GitHubOnboardingError) as refusal:
        configured_github_app()
    assert refusal.value.reason == "GITHUB_APP_NOT_CONFIGURED"


def test_a_pasted_private_key_can_never_become_a_configured_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in (
        ("SOLVAN_GITHUB_APP_SLUG", "solvan-reliability"),
        ("SOLVAN_GITHUB_APP_ID_SECRET_REF", _APP_ID_REF),
        ("SOLVAN_GITHUB_APP_PRIVATE_KEY_SECRET_REF", _PRIVATE_KEY_REF),
        ("SOLVAN_GITHUB_WEBHOOK_SECRET_REF", _WEBHOOK_REF),
        ("SOLVAN_GITHUB_CREDENTIAL_SECRET_REF", "-----BEGIN RSA PRIVATE KEY-----\nMII"),
    ):
        monkeypatch.setenv(name, value)

    with pytest.raises(GitHubOnboardingError) as refusal:
        configured_github_app()
    assert refusal.value.reason == "GITHUB_APP_NOT_CONFIGURED"


class _PagedTransport:
    """One full page followed by a short one, so pagination has to terminate."""

    def __init__(self, pages: list[object]) -> None:
        self._pages = pages
        self.urls: list[str] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.urls.append(url)
        index = int(url.rsplit("page=", 1)[1]) - 1
        return _Response(self._pages[index] if index < len(self._pages) else [])


def _repository_page(count: int, *, offset: int = 0) -> list[dict[str, Any]]:
    return [
        {
            "owner": {"login": "acme-platform"},
            "name": f"service-{index + offset}",
            "default_branch": "main",
        }
        for index in range(count)
    ]


def test_installation_repository_listing_pages_until_github_runs_short() -> None:
    transport = _PagedTransport(
        [
            {"repositories": _repository_page(100)},
            {"repositories": _repository_page(3, offset=100)},
        ]
    )
    client = GitHubClient(
        transport=transport,
        token_provider=StaticGitHubTokenProvider(_INSTALLATION_TOKEN),
        installation_id=42_991,
    )

    observed = client.installation_repositories()

    assert len(observed) == 103
    assert [url.rsplit("page=", 1)[1] for url in transport.urls] == ["1", "2"]


def test_an_oversized_page_is_refused_rather_than_truncated() -> None:
    transport = _PagedTransport([{"repositories": _repository_page(101)}])
    client = GitHubClient(
        transport=transport,
        token_provider=StaticGitHubTokenProvider(_INSTALLATION_TOKEN),
        installation_id=42_991,
    )

    with pytest.raises(GitHubApiError):
        client.installation_repositories()

    app_client = GitHubAppClient(
        transport=_PagedTransport([_INSTALLATIONS * 60]), app_jwt_provider=lambda: _APP_JWT
    )
    with pytest.raises(GitHubApiError):
        app_client.installations()


def test_an_installation_listing_drops_an_entry_it_cannot_trust() -> None:
    app_client = GitHubAppClient(
        transport=_PagedTransport(
            [
                [
                    {"id": 0, "account": {"login": "acme-platform"}},
                    {"id": 7, "account": {"login": "acme-platform", "type": "Organization"}},
                    {"id": 8, "account": None},
                ]
            ]
        ),
        app_jwt_provider=lambda: _APP_JWT,
    )

    assert [item.installation_id for item in app_client.installations()] == [7]


def test_an_empty_app_assertion_is_refused_before_a_request_is_made() -> None:
    transport = _PagedTransport([[]])
    app_client = GitHubAppClient(transport=transport, app_jwt_provider=lambda: "")

    with pytest.raises(GitHubApiError):
        app_client.installations()
    assert transport.urls == []
