"""Request-local bridge for coordinator-signed operational guidance."""

from __future__ import annotations

from pathlib import Path

from solvan.application import WorkspaceTaskInvocation

GUIDANCE_PREFIX = "guidance/"


def materialize_guidance(invocation: WorkspaceTaskInvocation, *, root: Path) -> list[str]:
    """Materialize signed guidance without granting the provider storage authority."""

    written = False
    for material in invocation.input_materials:
        if not material.path.startswith(GUIDANCE_PREFIX):
            continue
        target = root / material.path[len(GUIDANCE_PREFIX) :]
        resolved = target.resolve()
        if not resolved.is_relative_to(root.resolve()):
            raise ValueError("guidance material escapes the request-local root")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(material.content, encoding="utf-8")
        resolved.chmod(0o400)
        written = True
    return [str(root)] if written else []
