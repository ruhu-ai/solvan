from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest

from solvan.application.code_change_transform import CanonicalPatchTransform, TransformOperation
from solvan.application.github import (
    GitHubContractError,
    GitHubRepositoryBinding,
    ensure_scope,
    operation_hash,
    validate_ref,
)
from solvan.application.workspace_hashing import sha256_bytes
from solvan.domain import Scope
from solvan.platform.github import (
    GitHubApiError,
    GitHubClient,
    parse_webhook,
    verify_webhook_signature,
)
from solvan.platform.github_code_change import GitHubCodeChangeClient
from solvan.platform.github_evidence import (
    GitHubEvidenceProviderClient,
    GitHubEvidenceProviderConfiguration,
)
from solvan.platform.github_release import (
    GitHubReleaseProviderClient,
    GitHubReleaseProviderConfiguration,
)
from solvan.platform.github_repository_qualification import (
    GitHubRepositoryQualificationReader,
)


class Response:
    def __init__(self, value: object, status_code: int = 200) -> None:
        self.status_code = status_code
        self.content = json.dumps(value).encode()

    def json(self) -> object:
        return json.loads(self.content)


class Transport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("GET", url, kwargs))
        if "/git/trees/" in url:
            return Response(
                {
                    "truncated": False,
                    "tree": [
                        {
                            "path": "guidance/SKILL.md",
                            "type": "blob",
                            "mode": "100644",
                            "sha": "a" * 40,
                        },
                        {
                            "path": "guidance/references/runbook.md",
                            "type": "blob",
                            "mode": "100644",
                            "sha": "b" * 40,
                        },
                        {
                            "path": "other.txt",
                            "type": "blob",
                            "mode": "100644",
                            "sha": "c" * 40,
                        },
                    ],
                }
            )
        if "/git/blobs/" in url:
            content = base64.b64encode(b"---\nname: demo\ndescription: x\n---\n").decode()
            return Response({"encoding": "base64", "content": content})
        if "/compare/" in url:
            return Response(
                {
                    "status": "ahead",
                    "ahead_by": 1,
                    "behind_by": 0,
                    "total_commits": 1,
                    "commits": [{"sha": "b" * 40}],
                    "files": [
                        {
                            "filename": "src/payments.py",
                            "status": "modified",
                            "additions": 2,
                            "deletions": 1,
                        }
                    ],
                }
            )
        if url.endswith("/pulls/42/files?per_page=100"):
            return Response(
                [
                    {
                        "filename": "src/payments.py",
                        "status": "modified",
                        "additions": 2,
                        "deletions": 1,
                        "patch": "@@ -1 +1 @@",
                    }
                ]
            )
        if url.endswith("/check-runs/10/annotations?per_page=50"):
            return Response(
                [
                    {
                        "path": "src/payments.py",
                        "start_line": 5,
                        "end_line": 5,
                        "annotation_level": "failure",
                        "message": "test failed",
                    }
                ]
            )
        if url.endswith("/check-runs/10"):
            return Response(
                {
                    "id": 10,
                    "name": "CI",
                    "status": "completed",
                    "conclusion": "failure",
                    "head_sha": "b" * 40,
                }
            )
        if "/git/ref/heads/" in url:
            return Response({"object": {"sha": "b" * 40}})
        if url.endswith("/check-runs"):
            return Response(
                {
                    "check_runs": [
                        {
                            "id": 10,
                            "name": "CI",
                            "status": "completed",
                            "conclusion": "success",
                            "head_sha": "b" * 40,
                        }
                    ]
                }
            )
        return Response(
            {
                "number": 42,
                "node_id": "PR_node_42",
                "html_url": "https://github.com/acme/payments/pull/42",
                "head": {"sha": "b" * 40},
                "base": {"sha": "a" * 40},
                "state": "open",
                "merged": False,
                "title": "Repair",
                "draft": False,
            }
        )

    def post(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("POST", url, kwargs))
        return Response(
            {
                "number": 42,
                "node_id": "PR_node_42",
                "html_url": "https://github.com/acme/payments/pull/42",
                "head": {"sha": "b" * 40},
                "base": {"sha": "a" * 40},
                "state": "open",
                "merged": False,
                "title": "Repair",
                "draft": False,
            },
            201,
        )

    def put(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("PUT", url, kwargs))
        return Response({"merged": True, "sha": "c" * 40, "message": "merged"})


class Tokens:
    def token(self, *, installation_id: int) -> str:
        assert installation_id > 0
        return "token"


class ReleaseResponse:
    status_code = 202

    def json(self) -> object:
        return {"status": "accepted"}


class ReleaseHttpClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object], dict[str, str]]] = []

    def post(self, url: str, **kwargs: object) -> ReleaseResponse:
        self.calls.append((url, kwargs.get("json", {}), kwargs.get("headers", {})))
        return ReleaseResponse()


class ReleaseTokens:
    def token(self, *, audience: str) -> str:
        assert audience.startswith("https://")
        return "coordinator-token"


def test_webhook_signature_is_sha256_only() -> None:
    secret = b"secret"
    body = b'{"action":"opened"}'
    signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(secret=secret, body=body, signature=signature)
    assert not verify_webhook_signature(secret=secret, body=body, signature="sha1=bad")
    assert not verify_webhook_signature(secret=secret, body=body + b"x", signature=signature)


def test_webhook_parser_extracts_bounded_pull_request_fields() -> None:
    body = json.dumps(
        {
            "action": "synchronize",
            "number": 4,
            "installation": {"id": 22},
            "sender": {"login": "octocat"},
            "repository": {"name": "payments", "owner": {"login": "acme"}},
            "pull_request": {
                "number": 4,
                "merged": False,
                "head": {"sha": "b" * 40},
                "base": {"sha": "a" * 40},
            },
        }
    ).encode()
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    envelope = parse_webhook(
        body=body,
        delivery_id="delivery-1234",
        event_name="pull_request",
        signature=signature,
        webhook_secret=b"secret",
        repository_id="ghr_01J00000000000000000000000",
    )
    assert envelope.pull_request_number == 4
    assert envelope.pull_request_head_sha == "b" * 40
    assert envelope.payload_hash.startswith("sha256:")


def test_webhook_parser_rejects_invalid_signature() -> None:
    with pytest.raises(GitHubContractError):
        parse_webhook(
            body=b"{}",
            delivery_id="delivery-1234",
            event_name="ping",
            signature="sha256=" + "0" * 64,
            webhook_secret=b"secret",
            repository_id="ghr_01J00000000000000000000000",
        )


def test_client_uses_allowlisted_api_operations_and_pinned_sha() -> None:
    class CodeChangeTransport(Transport):
        def get(self, url: str, **kwargs: object) -> Response:
            self.calls.append(("GET", url, kwargs))
            if "/git/commits/" in url:
                return Response({"tree": {"sha": "b" * 40}})
            if "/git/ref/heads/" in url:
                return Response({}, 404)
            if "/pulls?" in url:
                return Response([])
            return super().get(url, **kwargs)

        def post(self, url: str, **kwargs: object) -> Response:
            self.calls.append(("POST", url, kwargs))
            if url.endswith("/git/blobs"):
                return Response({"sha": "c" * 40}, 201)
            if url.endswith("/git/trees"):
                return Response({"sha": "d" * 40}, 201)
            if url.endswith("/git/commits"):
                return Response({"sha": "e" * 40}, 201)
            if url.endswith("/git/refs"):
                return Response({"ref": "refs/heads/solvan/ccr/x"}, 201)
            return Response(
                {
                    "number": 42,
                    "node_id": "PR_node_42",
                    "html_url": "https://github.com/acme/payments/pull/42",
                    "head": {"sha": "e" * 40},
                    "base": {"sha": "a" * 40},
                    "state": "open",
                    "merged": False,
                    "title": "Repair",
                    "draft": True,
                },
                201,
            )

    transport = CodeChangeTransport()
    client = GitHubCodeChangeClient(
        transport=transport, token_provider=Tokens(), installation_id=22
    )
    content = b"new\n"
    transform = CanonicalPatchTransform(
        "solvan-regular-tree-transform/v1",
        "a" * 40,
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
        (
            TransformOperation(
                "CREATE",
                "src/new.py",
                None,
                None,
                sha256_bytes(content),
                "100644",
                base64.b64encode(content).decode(),
            ),
        ),
    )
    prepared = client.prepare_commit(
        owner="acme",
        name="payments",
        base_commit_sha="a" * 40,
        transform=transform,
        committed_at=datetime(2026, 8, 17, tzinfo=UTC),
        message="Solvan governed repair",
    )
    client.create_branch(
        owner="acme", name="payments", branch="solvan/ccr/request", commit_sha=prepared.commit_sha
    )
    created = client.create_pull_request(
        owner="acme",
        name="payments",
        branch="solvan/ccr/request",
        base="main",
        title="Repair",
        body="body",
    )
    assert created.number == 42
    assert prepared.commit_sha == "e" * 40
    assert transport.calls[0][2]["headers"]["Authorization"] == "Bearer token"


def test_client_fetches_only_the_allowlisted_pinned_subtree() -> None:
    transport = Transport()
    client = GitHubClient(transport=transport, token_provider=Tokens(), installation_id=22)
    archive = client.subtree_archive(
        owner="acme", name="payments", commit_sha="a" * 40, subdirectory="guidance"
    )
    assert archive.startswith(b"PK")
    assert any("/git/blobs/" in url for method, url, _ in transport.calls if method == "GET")


def test_code_change_merge_is_sha_and_method_fenced() -> None:
    transport = Transport()
    client = GitHubCodeChangeClient(
        transport=transport, token_provider=Tokens(), installation_id=22
    )
    result = client.merge_pull_request(
        owner="acme",
        name="payments",
        number=42,
        expected_head_sha="b" * 40,
        merge_method="squash",
    )
    assert result.merged is True
    assert result.merge_commit_sha == "c" * 40
    method, url, kwargs = transport.calls[-1]
    assert method == "PUT"
    assert url.endswith("/pulls/42/merge")
    assert kwargs["json"] == {"sha": "b" * 40, "merge_method": "squash"}
    with pytest.raises(GitHubApiError, match="merge parameters"):
        client.merge_pull_request(
            owner="acme",
            name="payments",
            number=42,
            expected_head_sha="b" * 40,
            merge_method="fast-forward",
        )


def test_client_reads_a_complete_regular_tree_and_verifies_git_object_ids() -> None:
    content = b"print('safe')\n"
    git_sha = hashlib.sha1(
        b"blob " + str(len(content)).encode() + b"\0" + content,
        usedforsecurity=False,
    ).hexdigest()

    class RegularTreeTransport(Transport):
        def get(self, url: str, **kwargs: object) -> Response:
            self.calls.append(("GET", url, kwargs))
            if "/git/trees/" in url:
                return Response(
                    {
                        "truncated": False,
                        "tree": [
                            {"path": "src", "type": "tree", "mode": "040000", "sha": "b" * 40},
                            {
                                "path": "src/app.py",
                                "type": "blob",
                                "mode": "100644",
                                "sha": git_sha,
                            },
                        ],
                    }
                )
            if "/git/blobs/" in url:
                return Response(
                    {"encoding": "base64", "content": base64.b64encode(content).decode()}
                )
            return super().get(url, **kwargs)

    tree = GitHubRepositoryQualificationReader(
        transport=RegularTreeTransport(), token_provider=Tokens(), installation_id=22
    ).regular_file_tree(owner="acme", name="payments", commit_sha="a" * 40)

    assert tree[0].path == "src/app.py"
    assert tree[0].content == content
    assert tree[0].content_hash == "sha256:" + hashlib.sha256(content).hexdigest()


def test_client_refuses_non_regular_objects_during_qualification() -> None:
    class UnsafeTreeTransport(Transport):
        def get(self, url: str, **kwargs: object) -> Response:
            if "/git/trees/" in url:
                return Response(
                    {
                        "truncated": False,
                        "tree": [
                            {
                                "path": "vendor/module",
                                "type": "commit",
                                "mode": "160000",
                                "sha": "b" * 40,
                            }
                        ],
                    }
                )
            return super().get(url, **kwargs)

    client = GitHubRepositoryQualificationReader(
        transport=UnsafeTreeTransport(), token_provider=Tokens(), installation_id=22
    )
    with pytest.raises(GitHubApiError, match="non-regular"):
        client.regular_file_tree(owner="acme", name="payments", commit_sha="a" * 40)


def test_client_accepts_the_default_root_subdirectory() -> None:
    class RootTransport(Transport):
        def get(self, url: str, **kwargs: object) -> Response:
            if "/git/trees/" in url:
                self.calls.append(("GET", url, kwargs))
                return Response(
                    {
                        "truncated": False,
                        "tree": [
                            {"path": "SKILL.md", "type": "blob", "mode": "100644", "sha": "a" * 40},
                            {
                                "path": "references/runbook.md",
                                "type": "blob",
                                "mode": "100644",
                                "sha": "b" * 40,
                            },
                        ],
                    }
                )
            return super().get(url, **kwargs)

    client = GitHubClient(transport=RootTransport(), token_provider=Tokens(), installation_id=22)
    assert client.subtree_tree_hash(owner="acme", name="payments", commit_sha="a" * 40).startswith(
        "sha256:"
    )
    archive = client.subtree_archive(owner="acme", name="payments", commit_sha="a" * 40)
    assert archive.startswith(b"PK")


def test_client_metadata_reads_refuse_redirects() -> None:
    transport = Transport()
    client = GitHubClient(transport=transport, token_provider=Tokens(), installation_id=22)
    client.repository(owner="acme", name="payments")
    client.branch_head(owner="acme", name="payments", branch="main")
    client.subtree_tree_hash(
        owner="acme", name="payments", commit_sha="b" * 40, subdirectory="guidance"
    )
    assert transport.calls
    for _method, url, kwargs in transport.calls:
        assert kwargs.get("allow_redirects") is False, url


def test_github_contracts_are_scope_and_ref_bound() -> None:
    scope = Scope(
        "org_01J00000000000000000000000",
        "prj_01J00000000000000000000000",
        "env_01J00000000000000000000000",
    )
    binding = GitHubRepositoryBinding(
        scope=scope,
        repository_id="ghr_01J00000000000000000000000",
        installation_id=22,
        owner="acme",
        name="payments",
        default_branch="main",
        api_base_url="https://api.github.com",
        classification="INTERNAL",
        policy_hash="sha256:" + "a" * 64,
        allowed_operations=("CREATE_PULL_REQUEST", "SYNC_PULL_REQUEST"),
    )
    assert binding.repository_id.startswith("ghr_")
    assert validate_ref("solvan/repair/pool-leak")
    assert operation_hash({"repository_id": binding.repository_id}).startswith("sha256:")
    ensure_scope(scope, scope)
    with pytest.raises(GitHubContractError):
        validate_ref("../unsafe")
    with pytest.raises(GitHubContractError):
        ensure_scope(
            scope, Scope(scope.organization_id, scope.project_id, "env_01J00000000000000000000001")
        )


def test_client_reads_branch_checks_and_repository_and_rejects_bad_sha() -> None:
    transport = Transport()
    client = GitHubClient(transport=transport, token_provider=Tokens(), installation_id=22)
    assert client.branch_head(owner="acme", name="payments", branch="solvan/repair/x") == "b" * 40
    assert client.subtree_tree_hash(
        owner="acme", name="payments", commit_sha="b" * 40, subdirectory="guidance"
    ).startswith("sha256:")
    assert client.repository(owner="acme", name="payments")["number"] == 42
    assert client.pull_request(owner="acme", name="payments", number=42).head_sha == "b" * 40
    assert client.check_runs(owner="acme", name="payments", ref="b" * 40)[0].conclusion == "SUCCESS"
    comparison = client.compare_commits(
        owner="acme", name="payments", base_sha="a" * 40, head_sha="b" * 40
    )
    assert comparison["changed_paths"][0]["path"] == "src/payments.py"
    assert client.pull_request_diff(owner="acme", name="payments", number=42)["files"][0][
        "patch"
    ].startswith("@@")
    check = client.check_run_detail(
        owner="acme", name="payments", check_run_id=10, expected_head_sha="b" * 40
    )
    assert check["annotations"][0]["level"] == "failure"

    class BadTransport(Transport):
        def get(self, url: str, **kwargs: object) -> Response:
            if "/git/ref/heads/" in url:
                return Response({"object": {"sha": "not-a-sha"}})
            return super().get(url, **kwargs)

    with pytest.raises(GitHubApiError):
        GitHubClient(
            transport=BadTransport(), token_provider=Tokens(), installation_id=22
        ).branch_head(owner="acme", name="payments", branch="solvan/repair/x")


def test_coordinator_release_client_uses_google_audience_and_typed_routes() -> None:
    transport = ReleaseHttpClient()
    client = GitHubReleaseProviderClient(
        config=GitHubReleaseProviderConfiguration(
            base_url="https://github-provider.example",
            audience="https://github-provider.example",
            repository_id="ghr_01J00000000000000000000000",
        ),
        client=transport,  # type: ignore[arg-type]
        token_provider=ReleaseTokens(),
    )
    assert client.probe_repository()["status"] == "accepted"
    assert (
        client.execute_private_command(
            {
                "schema_version": 1,
                "command_id": "cmd_01J00000000000000000000000",
                "payload": {},
            }
        )["status"]
        == "accepted"
    )
    assert all(call[2]["Authorization"] == "Bearer coordinator-token" for call in transport.calls)
    assert any(call[0].endswith("/internal/v1/commands:execute") for call in transport.calls)


def test_evidence_broker_client_uses_private_typed_github_read_routes() -> None:
    transport = ReleaseHttpClient()
    client = GitHubEvidenceProviderClient(
        config=GitHubEvidenceProviderConfiguration(
            base_url="https://github-provider.example",
            audience="https://github-provider.example",
            repository_id="ghr_01J00000000000000000000000",
        ),
        client=transport,  # type: ignore[arg-type]
        token_provider=ReleaseTokens(),
    )
    client.commit_range(base_sha="a" * 40, head_sha="b" * 40)
    client.pull_request_diff(pull_request_number=42, maximum_patch_bytes=20_000)
    client.workflow_run(check_run_id=10, expected_head_sha="b" * 40)
    assert [call[0] for call in transport.calls] == [
        "https://github-provider.example/internal/github/evidence/commit-range",
        "https://github-provider.example/internal/github/evidence/pull-request-diff",
        "https://github-provider.example/internal/github/evidence/workflow-run",
    ]
    assert all(call[2]["Authorization"] == "Bearer coordinator-token" for call in transport.calls)
