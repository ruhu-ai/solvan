"""The console proxy must accept every route the console actually commands.

`apps/console/server.mjs` refuses a human identity token on any path outside
its allowlist. That is the right posture, but the allowlist and the client are
two hand-maintained lists in two languages: when they drifted, the deployed
console sent the header on a dozen routes the proxy rejected with 400, so every
operator command failed before reaching the API while the local harness — which
does not run the proxy — stayed green.

This binds them. It reads the paths the client attaches an identity header to
and requires the proxy to accept each one. It cannot prove the reverse (an
allowlist entry with no caller is harmless), so it only fails closed.

The reader-identity allowlist is bound to the API rather than to the client,
because binding it to the client proves nothing while no component sends the
header: the required set is every route whose handler resolves a principal from
`X-Solvan-Identity-Token`, which is a fact about the API and cannot go vacuous.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "apps" / "console"
SERVER = CONSOLE / "server.mjs"
ALERT_CONSOLE_API = ROOT / "apps" / "api" / "alert_console.py"

#: Paths the console commands with a human token, as concrete examples rather
#: than patterns: a literal is what the proxy will actually receive.
COMMANDED_PATHS = (
    "/api/v1/actions/act_01ARZ3NDEKTSV4RRFFQ69G5FAV:approve",
    "/api/v1/patches/pat_01ARZ3NDEKTSV4RRFFQ69G5FAV:review",
    "/api/alerts/ale_01ARZ3NDEKTSV4RRFFQ69G5FAV/request-retriage",
    "/api/alerts/ale_01ARZ3NDEKTSV4RRFFQ69G5FAV/request-incident-continuation",
    "/api/alerts/ale_01ARZ3NDEKTSV4RRFFQ69G5FAV/feedback",
    "/api/fleet/alert-policy-simulations",
    "/api/v1/liaison:ask",
    "/api/v1/liaison/questions",
    "/api/v1/liaison/catchup",
    "/api/v1/threads",
    "/api/v1/threads/thr_01ARZ3NDEKTSV4RRFFQ69G5FAV/messages",
    "/api/v1/threads/thr_01ARZ3NDEKTSV4RRFFQ69G5FAV/read-cursor",
    "/api/v1/threads/thr_01ARZ3NDEKTSV4RRFFQ69G5FAV/turns/msg_01ARZ3ND:stop-and-send",
    "/api/v1/skills/autocomplete",
    "/api/v1/skills/governance/owners",
    "/api/v1/production-graph/pgs_01ARZ3NDEKTSV4RRFFQ69G5FAV/review-material",
    "/api/v1/production-graph/pgs_01ARZ3NDEKTSV4RRFFQ69G5FAV:promote",
    "/api/v1/production-graph/status",
    "/api/v1/production-graph/reconciliations",
    "/api/v1/connections",
    "/api/v1/connections/grant-plan",
    "/api/v1/actuators",
    "/api/v1/relays",
    "/api/v1/channels/bindings",
    "/api/v1/channels/enrollments",
    "/api/v1/channels/providers",
)

#: Paths that must keep refusing the header, so the allowlist stays a boundary.
REFUSED_PATHS = (
    "/api/console/snapshot",
    "/api/harness",
    "/api/v1/actions/act_01ARZ3ND",
)


def _javascript_regexes(block: str) -> list[re.Pattern[str]]:
    """Translate the proxy's literal route patterns into Python equivalents.

    The patterns are deliberately restricted to syntax that means the same
    thing in both languages: character classes, anchors, non-capturing groups
    and quantifiers. A pattern that needs translation is a pattern this test
    cannot honestly check, so anything unexpected fails rather than passes.
    """

    patterns: list[re.Pattern[str]] = []
    for raw in re.findall(r"^\s*(/\^.*\$/),\s*$", block, re.MULTILINE):
        source = raw[1:-1]
        if "(?<" in source or "\\p{" in source:
            pytest.fail(f"route pattern uses syntax this check cannot translate: {source}")
        patterns.append(re.compile(source))
    return patterns


def _allowlist(name: str = "humanTokenRoutes") -> list[re.Pattern[str]]:
    source = SERVER.read_text(encoding="utf-8")
    match = re.search(rf"const {name} = \[(.*?)^\];", source, re.DOTALL | re.MULTILINE)
    assert match is not None, f"server.mjs no longer declares {name}"
    return _javascript_regexes(match.group(1))


def _reader_identity_routes() -> list[str]:
    """Every API path whose handler resolves a principal from the reader header.

    Derived from the API rather than declared here, so a new reader route joins
    the required set by existing rather than by being remembered.
    """

    module = ast.parse(ALERT_CONSOLE_API.read_text(encoding="utf-8"))
    paths: list[str] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.FunctionDef):
            continue
        defaults = node.args.defaults + [
            default for default in node.args.kw_defaults if default is not None
        ]
        reads_identity = any(
            isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id == "Header"
            and any(
                keyword.arg == "alias"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == "X-Solvan-Identity-Token"
                for keyword in default.keywords
            )
            for default in defaults
        )
        if not reads_identity:
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                paths.append(decorator.args[0].value)
    assert paths, "no alert route reads the reader identity header; this check is stale"
    return paths


def _concrete(path: str) -> str:
    """Substitute one literal segment per path parameter."""

    return re.sub(r"\{[^}]+\}", "sample-01ARZ3NDEKTSV4RRFFQ69G5FAV", path)


def test_every_commanded_route_is_accepted_by_the_proxy() -> None:
    allowlist = _allowlist()
    refused = [
        path for path in COMMANDED_PATHS if not any(pattern.match(path) for pattern in allowlist)
    ]
    assert not refused, (
        "the console sends a human identity token to these routes but the proxy "
        f"refuses them: {refused}"
    )


def test_the_allowlist_is_still_a_boundary() -> None:
    allowlist = _allowlist()
    accepted = [path for path in REFUSED_PATHS if any(pattern.match(path) for pattern in allowlist)]
    assert not accepted, f"these routes must not accept a human identity token: {accepted}"


def test_every_client_header_site_is_covered_by_the_allowlist() -> None:
    """Find header-attaching components and require each to have a listed route.

    A component that starts sending the header to a brand-new path is the drift
    this test exists to catch; it fails here rather than in production.
    """

    attaching = sorted(
        path.name
        for path in (CONSOLE / "src").rglob("*.tsx")
        if "X-Solvan-Approval-Token" in path.read_text(encoding="utf-8")
    )
    assert attaching, "no console component attaches an approval token; the check is stale"
    # AlertSourceSetup, GitHubRepositorySetup, and ReleaseAuthority were split
    # out of Integrations.tsx, which was sheltering them under a size exception
    # granted for something else. They send what they always sent, to the routes
    # they always sent it to; only the file holding the call changed.
    known = {
        "Alerts.tsx",
        "AlertSourceSetup.tsx",
        "Ask.tsx",
        "ChannelSettings.tsx",
        "Fleet.tsx",
        "FleetSkills.tsx",
        "GitHubConversation.tsx",
        "GitHubRepositorySetup.tsx",
        "IncidentActions.tsx",
        "IncidentRepair.tsx",
        "Integrations.tsx",
        "ProductionGraphPanel.tsx",
        "ReleaseAuthority.tsx",
    }
    unreviewed = sorted(set(attaching) - known)
    assert not unreviewed, (
        "these components newly send a human identity token; add their routes to "
        f"humanTokenRoutes in server.mjs and to this check: {unreviewed}"
    )


def test_every_reader_identity_route_is_accepted_by_the_proxy() -> None:
    """The proxy must forward the reader header to every route that requires it.

    `identityHeaderRoutes` listed only `/api/alerts...`, so the four Fleet
    Alert-policy reads and the Incident related-alerts read would have been
    refused with 400 by the console's own transport before reaching an API that
    resolves their principal from exactly the header it denied them.
    """

    allowlist = _allowlist("identityHeaderRoutes")
    refused = [
        path
        for path in _reader_identity_routes()
        if not any(pattern.match(_concrete(path)) for pattern in allowlist)
    ]
    assert not refused, (
        "these API routes resolve a principal from X-Solvan-Identity-Token but the "
        f"console proxy refuses the header on them: {refused}"
    )


def test_the_reader_identity_allowlist_is_still_a_boundary() -> None:
    allowlist = _allowlist("identityHeaderRoutes")
    accepted = [path for path in REFUSED_PATHS if any(pattern.match(path) for pattern in allowlist)]
    assert not accepted, f"these routes must not accept a reader identity token: {accepted}"


def test_the_proxy_does_not_shadow_its_workload_token_minter() -> None:
    """`identityToken` names the function that mints the workload token.

    Rebinding that name inside `proxyApi` to a request header made
    `await identityToken()` call a string: every proxied API request threw and
    the listener's catch reported a bare 502, which is indistinguishable from an
    unreachable upstream. A transport exercise that reads 502 as "forwarded"
    cannot catch this, so the shadowing itself is what gets refused here.
    """

    source = SERVER.read_text(encoding="utf-8")
    assert "async function identityToken()" in source, (
        "server.mjs no longer declares the workload token minter; update this check"
    )
    shadows = re.findall(r"^\s*(?:const|let|var)\s+identityToken\b", source, re.MULTILINE)
    assert not shadows, (
        "a local binding named identityToken shadows the workload token minter, so "
        "await identityToken() calls a value instead of the function"
    )
