"""Verify the isolated Antigravity image's installed closure and provenance."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import logging
import tomllib
from pathlib import Path
from typing import Any

EXPECTED_SDK_VERSION = "0.1.13"
EXPECTED_LINUX_WHEEL_HASH = (
    "sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992"
)
FORBIDDEN_DISTRIBUTIONS = ("google-adk", "google-cloud-aiplatform")
LOGGER = logging.getLogger(__name__)


def _configuration_smoke() -> None:
    """Construct the exact 0.1.13 control surfaces without starting a model."""

    antigravity = importlib.import_module("google.antigravity")
    hooks = importlib.import_module("google.antigravity.hooks")
    policy = importlib.import_module("google.antigravity.hooks.policy")
    types = importlib.import_module("google.antigravity.types")

    @hooks.pre_tool_call_decide  # type: ignore[misc]
    def pre_tool(tool_call: Any) -> Any:
        return types.HookResult(allow=getattr(tool_call, "name", None) == "finish")

    @hooks.on_session_start  # type: ignore[misc]
    def session_start() -> None:
        return None

    @hooks.on_session_end  # type: ignore[misc]
    def session_end() -> None:
        return None

    capabilities = types.CapabilitiesConfig(
        enable_subagents=False,
        agent_behavior=types.AgentBehavior.AUTONOMOUS,
        enabled_tools=[types.BuiltinTools.FINISH],
        run_command_config=types.RunCommandConfig(enable_daemons=False, timeout_seconds=1),
    )
    config = antigravity.LocalAgentConfig(
        vertex=True,
        project="runtime-verification-only",
        location="global",
        model="gemini-3.1-pro-preview",
        system_instructions="configuration verification only",
        capabilities=capabilities,
        tools=[],
        policies=[policy.deny_all(), policy.allow("finish")],
        hooks=[pre_tool, session_start, session_end],
        triggers=[],
        mcp_servers=[],
        subagents=[],
        workspaces=[],
        response_schema={"type": "object", "properties": {}},
        retry_config=types.RetryConfig(
            api_retry=types.ModelAPIRetryConfig(max_retries=0),
            model_output_retry=types.ModelOutputRetryConfig(max_retries=0),
        ),
        budget_config=types.BudgetConfig(max_model_calls=1, max_tool_calls=1),
    )
    agent = antigravity.Agent(config)
    if agent is None or config.capabilities is None or config.budget_config is None:
        raise RuntimeError("Antigravity 0.1.13 configuration smoke failed")
    if config.capabilities.agent_behavior is not types.AgentBehavior.AUTONOMOUS:
        raise RuntimeError("Antigravity agent behavior was not explicit")
    if types.BuiltinTools.RUN_COMMAND in (config.capabilities.enabled_tools or []):
        raise RuntimeError("Antigravity command execution was enabled")


def verify(lock_path: Path) -> None:
    installed = importlib.metadata.version("google-antigravity")
    if installed != EXPECTED_SDK_VERSION:
        raise RuntimeError(
            f"installed google-antigravity {installed} != approved {EXPECTED_SDK_VERSION}"
        )
    for distribution in FORBIDDEN_DISTRIBUTIONS:
        try:
            importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            continue
        raise RuntimeError(f"isolated Antigravity runtime contains forbidden {distribution}")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = [
        package
        for package in lock.get("package", [])
        if package.get("name") == "google-antigravity"
    ]
    if len(packages) != 1 or packages[0].get("version") != EXPECTED_SDK_VERSION:
        raise RuntimeError("Antigravity runtime lock does not bind the approved SDK version")
    linux_wheels = [
        wheel
        for wheel in packages[0].get("wheels", [])
        if "manylinux_2_17_x86_64.whl" in str(wheel.get("url", ""))
    ]
    if len(linux_wheels) != 1 or linux_wheels[0].get("hash") != EXPECTED_LINUX_WHEEL_HASH:
        raise RuntimeError("Antigravity runtime lock lacks the approved Linux wheel digest")
    importlib.import_module("google.antigravity")
    imported = importlib.import_module("apps.antigravity_workspace.main")
    if installed != imported.SDK_VERSION:
        raise RuntimeError("provider does not report the installed distribution version")
    _configuration_smoke()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    args = parser.parse_args()
    verify(args.lock)
    LOGGER.info(
        "Antigravity runtime verified: "
        f"google-antigravity {EXPECTED_SDK_VERSION}, Linux wheel {EXPECTED_LINUX_WHEEL_HASH}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
