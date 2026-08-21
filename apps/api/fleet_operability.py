"""Reader-safe Agent Fleet Tool Catalog and Guidance projections."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, Response, status

from apps.api.session_authorization import SESSION_COOKIE, session_reader_principal

#: Built-in packs ship in the repository; the console reads them only through
#: this authenticated projection, never through an object URL (spec 17 §11).
GUIDANCE_ROOT = Path(__file__).resolve().parents[2] / "guidance"
_PACK_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*$")
_MAX_CONTENT_BYTES = 64 * 1024
#: Stated on every capability response. Reading this catalog resolves nothing:
#: a run still binds an exact profile, revalidates identity, Gateway route,
#: connection, region and classification, and freezes an effective set.
_DISCOVERY_NOTICE = "Discovery is not authorization; a run must bind an exact profile."


def first_party_pack_files(guidance_key: str) -> list[dict[str, str]]:
    """The exact checked-in files of one built-in pack, SKILL.md first."""

    if _PACK_KEY.fullmatch(guidance_key) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Guidance pack was not found")
    family, _, name = guidance_key.partition(".")
    pack = (GUIDANCE_ROOT / family / name).resolve()
    if not pack.is_relative_to(GUIDANCE_ROOT) or not (pack / "SKILL.md").is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Guidance pack was not found")
    files: list[dict[str, str]] = []
    for path in sorted(pack.rglob("*")):
        if not path.is_file():
            continue
        raw = path.read_bytes()[:_MAX_CONTENT_BYTES]
        files.append(
            {
                "name": path.relative_to(pack).as_posix(),
                "content": raw.decode("utf-8", errors="replace"),
            }
        )
    files.sort(key=lambda item: (item["name"] != "SKILL.md", item["name"]))
    return files


def fleet_operability_router(
    *,
    snapshot_provider: Callable[[], dict[str, Any]],
    principal_provider: Callable[[str | None], str],
    connect: Callable[[], Any],
) -> APIRouter:
    """Expose read-only catalog routes; discovery never grants invocation."""

    router = APIRouter()

    def _fleet(request: Request, token: str | None) -> dict[str, Any]:
        # Who is reading: the §4.2 session a browser carries, else the
        # audience-bound grant a non-browser caller presents. The snapshot
        # itself holds durable fleet records, so an identity is required; the
        # cookie check comes first so a session-less request never costs a
        # connection.
        principal: str | None = None
        if request.cookies.get(SESSION_COOKIE):
            with connect() as connection:
                principal = session_reader_principal(connection, request)
        if principal is None:
            principal_provider(token)
        fleet = snapshot_provider().get("fleet")
        if not isinstance(fleet, dict):
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "fleet projection unavailable")
        return fleet

    @router.get("/api/fleet/tools")
    def tools(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        fleet = _fleet(request, authorization)
        return {
            "tools": fleet.get("tools", []),
            "status_definitions": fleet.get("tool_status_definitions", {}),
        }

    @router.get("/api/fleet/tools/{tool_key}")
    def tool_detail(
        tool_key: str,
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        items = _fleet(request, authorization).get("tools", [])
        item = next((value for value in items if value.get("key") == tool_key), None)
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tool was not found")
        return dict(item)

    @router.get("/api/fleet/tools/{tool_key}/revisions/{version}")
    def tool_revision(
        tool_key: str,
        version: str,
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        items = _fleet(request, authorization).get("tools", [])
        item = next(
            (
                value
                for value in items
                if value.get("key") == tool_key and value.get("version") == version
            ),
            None,
        )
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tool revision was not found")
        return dict(item)

    @router.get("/api/fleet/tool-profiles")
    def profiles(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        return {"profiles": _fleet(request, authorization).get("tool_profiles", [])}

    @router.get("/api/fleet/tool-profiles/{profile_key}/revisions/{version}")
    def profile_revision(
        profile_key: str,
        version: str,
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        items = _fleet(request, authorization).get("tool_profiles", [])
        item = next(
            (
                value
                for value in items
                if value.get("key") == profile_key and value.get("version") == version
            ),
            None,
        )
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tool profile was not found")
        return dict(item)

    @router.get("/api/fleet/tool-probes")
    def probes(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        return {"probes": _fleet(request, authorization).get("tool_probes", [])}

    @router.get("/api/fleet/guidance")
    def guidance(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        return {"guidance": _fleet(request, authorization).get("guidance", [])}

    @router.get("/api/fleet/guidance/{guidance_key}/revisions/{version}/content")
    def guidance_content(
        guidance_key: str,
        version: str,
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        item = next(
            (
                value
                for value in _fleet(request, authorization).get("guidance", [])
                if value.get("key") == guidance_key and value.get("version") == version
            ),
            None,
        )
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Guidance revision was not found")
        if item.get("source_kind") != "SOLVAN_AUTHORED":
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Imported content is served from the quarantine store after compile",
            )
        return {"files": first_party_pack_files(guidance_key)}

    @router.get("/api/fleet/guidance/{guidance_key}/revisions/{version}")
    def guidance_revision(
        guidance_key: str,
        version: str,
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        item = next(
            (
                value
                for value in _fleet(request, authorization).get("guidance", [])
                if value.get("key") == guidance_key and value.get("version") == version
            ),
            None,
        )
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Guidance revision was not found")
        return dict(item)

    @router.get("/api/fleet/trigger-policies")
    def trigger_policies(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        return {"trigger_policies": _fleet(request, authorization).get("trigger_policies", [])}

    @router.get("/api/fleet/trigger-firings")
    def trigger_firings(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "private, no-store"
        return {"trigger_firings": _fleet(request, authorization).get("trigger_firings", [])}

    @router.get("/api/fleet/capabilities")
    def capabilities(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Every governed capability with the chain that decided it."""

        response.headers["Cache-Control"] = "private, no-store"
        return {
            "schema_version": 1,
            "capabilities": _fleet(request, authorization).get("capabilities", []),
            "notice": _DISCOVERY_NOTICE,
        }

    @router.get("/api/fleet/agents/{agent_key}/effective-tools")
    def effective_tools(
        agent_key: str,
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """What this Agent may actually reach, and what it may not.

        This filtered the Tool catalog by `agent_keys`, which is the set of
        revisions naming the Agent as an allowed requester — the larger,
        declared set. Dispatch resolves profile membership instead, so the
        endpoint returned nine capabilities for an Agent that could reach four,
        under a name asserting the opposite. `effective_tools` now holds only
        capabilities that resolve to `ALLOWED`; every capability the Agent is
        associated with, and the authority that withheld each, stays available
        beside it rather than being silently dropped.
        """

        response.headers["Cache-Control"] = "private, no-store"
        fleet = _fleet(request, authorization)
        decisions = [
            item for item in fleet.get("capabilities", []) if item.get("agent_key") == agent_key
        ]
        registered = any(item.get("key") == agent_key for item in fleet.get("agents", []))
        if not decisions and not registered:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent is not registered")
        return {
            "schema_version": 1,
            "agent_key": agent_key,
            "effective_tools": [item for item in decisions if item.get("verdict") == "ALLOWED"],
            "capabilities": decisions,
            "notice": _DISCOVERY_NOTICE,
        }

    return router
