"""Pure normalization helpers for governed Production Graph sources."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from solvan.application.production_graph_types import GraphEdge, GraphNode
from solvan.platform.production_graph_source_errors import GraphSourceUnavailable

_PROJECT_IN_URI = re.compile(r"(?:^|/)projects/([a-z][a-z0-9-]{4,61})(?:/|$)")
_SAFE_TEXT = re.compile(r"^[\w .:/@-]{1,200}$")


def project_from_uri(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = _PROJECT_IN_URI.search(value)
    return match.group(1) if match is not None else None


def location_from_name(value: str) -> str | None:
    parts = value.split("/")
    try:
        location = parts[parts.index("locations") + 1]
    except (ValueError, IndexError):
        return None
    return location if location else None


def attribute_type(attributes: Any, key: str) -> str | None:
    value = attributes.get(key) if isinstance(attributes, dict) else None
    typed = value.get("type") if isinstance(value, dict) else None
    if not isinstance(typed, str) or typed == "TYPE_UNSPECIFIED":
        return None
    return typed


def owner(attributes: Any) -> str | None:
    owners = attributes.get("operatorOwners") if isinstance(attributes, dict) else None
    if not isinstance(owners, list):
        return None
    for item in owners:
        display = item.get("displayName") if isinstance(item, dict) else None
        if isinstance(display, str) and _SAFE_TEXT.fullmatch(display):
            return display
    return None


def resource_node_key(resource: str) -> str | None:
    lowered = resource.lower()
    if "run.googleapis.com" in lowered or "/services/" in lowered:
        return f"service:{resource}"
    if "sqladmin.googleapis.com" in lowered or "/instances/" in lowered:
        return f"database:{resource}"
    if "pubsub.googleapis.com" in lowered and (
        "/topics/" in lowered or "/subscriptions/" in lowered
    ):
        return f"queue:{resource}"
    return None


def dedupe_nodes(values: Sequence[GraphNode]) -> tuple[GraphNode, ...]:
    result: dict[str, GraphNode] = {}
    for value in values:
        existing = result.get(value.node_key)
        if existing is not None and existing != value:
            raise GraphSourceUnavailable(f"App Hub returned conflicting node {value.node_key}")
        result[value.node_key] = value
    return tuple(result.values())


def dedupe_edges(values: Sequence[GraphEdge]) -> tuple[GraphEdge, ...]:
    result: dict[str, GraphEdge] = {}
    for value in values:
        existing = result.get(value.edge_key)
        if existing is not None and existing != value:
            raise GraphSourceUnavailable(f"graph source returned conflicting edge {value.edge_key}")
        result[value.edge_key] = value
    return tuple(result.values())


def digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def exact_fields(value: Mapping[str, Any], allowed: set[str]) -> None:
    if set(value) != allowed:
        raise ValueError("graph source configuration fields are not exact")


def required_text(value: Mapping[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"graph source configuration requires {field}")
    return item


def text_sequence(value: Mapping[str, Any], field: str) -> tuple[str, ...]:
    item = value.get(field)
    if (
        not isinstance(item, list)
        or not item
        or any(not isinstance(entry, str) or not entry for entry in item)
    ):
        raise ValueError(f"graph source configuration requires a non-empty {field}")
    return tuple(item)


def text_mapping(value: Mapping[str, Any], field: str) -> dict[str, str]:
    item = value.get(field)
    if not isinstance(item, dict) or any(
        not isinstance(key, str) or not key or not isinstance(mapped, str) or not mapped
        for key, mapped in item.items()
    ):
        raise ValueError(f"graph source configuration requires a text map for {field}")
    return dict(item)
