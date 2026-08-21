"""Reader-safe registry-manifest facts for the Agents tab.

Each registered principal is digest-pinned to the checked-in agent manifest
(``specs/artifacts/agent-manifests.yaml``) through
``catalog_principals.manifest_hash``. The Fleet cards render the manifest's
per-agent facts — owner department, discoverable departments, framework and
model, approval and lifecycle — only when that pin verifies against the
current file; a principal registered from a superseded manifest withholds the
facts rather than presenting stale ones. This follows the spec 17 §11
precedent of serving checked-in artifacts through the authenticated
projection instead of a second store.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from solvan.application.workspace_hashing import canonical_sha256

MANIFEST_PATH = Path(__file__).resolve().parents[2] / "specs" / "artifacts" / "agent-manifests.yaml"


def _facts(entry: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    platform = manifest.get("platform") or {}
    framework = f"{platform.get('framework', '')} {platform.get('framework_version', '')}".strip()
    return {
        "manifest_version": str(manifest.get("manifest_version", "")),
        "owner_department": str(entry.get("owner_department", "")) or None,
        "discoverable_departments": [str(item) for item in entry.get("discoverable_by") or []],
        "framework": framework or None,
        "model": str(platform.get("model_resource", "")) or None,
        "lifecycle": str(entry.get("lifecycle", "")) or None,
        "approval_status": str(entry.get("approval_status", "")) or None,
        "permission_ceiling": str(entry.get("permission_ceiling", "")) or None,
    }


def agent_manifest_facts(
    registered: dict[str, str], *, manifest_path: Path = MANIFEST_PATH
) -> dict[str, dict[str, Any] | None]:
    """Manifest facts per principal key, or None where the pin does not verify.

    ``registered`` maps each principal key to its registered manifest hash.
    Local publication pins each entry canonically; the deployment publisher
    pins the whole file bytes — either exact match proves the facts are the
    ones this principal was registered from. A missing or unparsable manifest
    withholds every fact rather than failing the snapshot: the cards degrade
    to their registry-only state.
    """

    try:
        raw = manifest_path.read_bytes()
        manifest = yaml.safe_load(raw.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("agent manifest is not a mapping")
    except Exception:
        return dict.fromkeys(registered)
    file_hash = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    entries: dict[str, dict[str, Any]] = {}
    for section in ("agents", "optional_agents", "deterministic_services"):
        for entry in manifest.get(section) or []:
            key = str(entry.get("agent_key") or entry.get("service_key") or "")
            if key:
                entries[key] = entry
    projected: dict[str, dict[str, Any] | None] = {}
    for key, registered_hash in registered.items():
        entry = entries.get(key)
        if entry is not None and registered_hash in (canonical_sha256(entry), file_hash):
            projected[key] = _facts(entry, manifest)
        else:
            projected[key] = None
    return projected
