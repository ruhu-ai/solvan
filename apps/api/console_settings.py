"""Versioned, secret-free settings projections for the operator console."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class _StrictProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserPreferencesProjection(_StrictProjection):
    theme: Literal["SYSTEM", "LIGHT", "DARK"]
    density: Literal["COMFORTABLE", "COMPACT"]
    motion: Literal["SYSTEM", "REDUCED", "FULL"]
    timezone_mode: Literal["BROWSER", "UTC", "NAMED"]
    timezone: str | None


class NamedContextProjection(_StrictProjection):
    id: str
    name: str


class OperatorContextProjection(_StrictProjection):
    state: Literal["LOCAL_DEVELOPMENT", "AUTHENTICATED", "AUTHENTICATION_REQUIRED"]
    principal: str | None
    display_name: str
    email: str | None
    avatar_url: str | None
    initials: str
    identity_provider: Literal["LOCAL", "GOOGLE"] | None
    managed_by: Literal["SOLVAN", "GOOGLE"] | None
    organization: NamedContextProjection | None
    team: NamedContextProjection | None
    roles: list[Literal["VIEWER", "OPERATOR", "APPROVER", "ADMIN"]]
    session_expires_at: str | None


class AvailableScopeProjection(_StrictProjection):
    scope_key: str
    name: str
    project_id: str
    region: str
    classification: Literal["LOCAL", "DEVELOPMENT", "STAGING", "PRODUCTION"]


class EnvironmentSettingsProjection(AvailableScopeProjection):
    environment_id: str
    data_status: str
    authority: str
    generated_at: str
    available_scopes: list[AvailableScopeProjection]


class RuntimeSettingsProjection(_StrictProjection):
    provider: str
    model_resource: str
    model_display_name: str
    model_revision: str | None
    model_location: str
    region: str
    framework: str
    framework_version: str
    runtime_sdk: str
    runtime_sdk_version: str
    agent_manifest_version: str
    release_commit: str
    deployment_id: str | None
    source: Literal["BOUND_RELEASE", "MANIFEST_TARGET", "LOCAL_FIXTURE"]
    evidence_status: str
    fallback_status: Literal["NONE", "ACTIVE", "UNAVAILABLE"]


class GovernanceSettingsProjection(_StrictProjection):
    autonomy_state: str
    autonomy_reason: str
    autonomy_next_step: str
    mutation_authority: str
    policy_version: str
    approval_mode: str
    gateway_status: str
    model_armor_status: str
    identity_status: str
    retention_summary: str
    configuration_source: str
    last_verified_at: str | None


class AboutSettingsProjection(_StrictProjection):
    console_version: str
    api_version: str
    build_commit: str
    deployment_id: str | None
    settings_schema_version: str
    snapshot_schema_version: str
    projection_generated_at: str
    api_status: str
    documentation_url: str | None
    privacy_url: str | None
    notices_url: str | None


class SettingsCapabilitiesProjection(_StrictProjection):
    edit_preferences: bool
    switch_environment: bool
    sign_out: bool
    manage_members: bool
    manage_security: bool
    manage_runtime: bool
    view_audit: bool
    export_diagnostics: bool


class SettingsProjectionResponse(_StrictProjection):
    schema_version: Literal[1]
    generated_at: str
    data_status: str
    preference_version: int
    operator: OperatorContextProjection
    preferences: UserPreferencesProjection
    environment: EnvironmentSettingsProjection
    runtime: RuntimeSettingsProjection
    governance: GovernanceSettingsProjection
    about: AboutSettingsProjection
    capabilities: SettingsCapabilitiesProjection


def _platform_health(snapshot: dict[str, Any], name: str) -> str:
    platform = snapshot.get("fleet", {}).get("platform", [])
    for item in platform:
        if item.get("name") == name:
            return str(item.get("health", "UNKNOWN"))
    return "UNKNOWN"


def _runtime_source(snapshot: dict[str, Any]) -> str:
    release = snapshot.get("release", {})
    if release.get("cloud") == "BOUND_GCP_EVIDENCE_COMPLETE" and release.get("deployment_id"):
        return "BOUND_RELEASE"
    if snapshot.get("authority") == "GOOGLE_CLOUD_IAM":
        return "MANIFEST_TARGET"
    return "LOCAL_FIXTURE"


def console_settings_projection(snapshot: dict[str, Any], *, api_version: str) -> dict[str, Any]:
    """Project effective console settings without accepting client authority.

    The production identity/session surface is intentionally truthful: until
    the console has a verified browser session, it reports that authentication
    is required instead of inventing a profile from request headers.
    """

    now = datetime.now(UTC).isoformat()
    local = snapshot.get("authority") != "GOOGLE_CLOUD_IAM"
    environment = snapshot.get("environment", {})
    release = snapshot.get("release", {})
    project_id = (
        "local-development" if local else os.environ.get("SOLVAN_GCP_PROJECT", "unbound-project")
    )
    environment_id = (
        "local-development"
        if local
        else os.environ.get("SOLVAN_ENVIRONMENT_ID", "unbound-environment")
    )
    classification = (
        "LOCAL" if local else os.environ.get("SOLVAN_ENVIRONMENT_CLASSIFICATION", "STAGING").upper()
    )
    if classification not in {"LOCAL", "DEVELOPMENT", "STAGING", "PRODUCTION"}:
        classification = "STAGING"

    if local:
        operator = {
            "state": "LOCAL_DEVELOPMENT",
            "principal": "local-development-reader",
            "display_name": "Local development reader",
            "email": None,
            "avatar_url": None,
            "initials": "LD",
            "identity_provider": "LOCAL",
            "managed_by": "SOLVAN",
            "organization": None,
            "team": None,
            "roles": ["VIEWER"],
            "session_expires_at": None,
        }
    else:
        operator = {
            "state": "AUTHENTICATION_REQUIRED",
            "principal": None,
            "display_name": "Sign in required",
            "email": None,
            "avatar_url": None,
            "initials": "?",
            "identity_provider": "GOOGLE",
            "managed_by": "GOOGLE",
            "organization": None,
            "team": None,
            "roles": [],
            "session_expires_at": None,
        }

    scope = {
        "scope_key": f"{project_id}:{environment_id}",
        "name": str(environment.get("name", "Unknown environment")),
        "project_id": project_id,
        "region": str(environment.get("region", "unknown")),
        "classification": classification,
    }
    runtime_source = _runtime_source(snapshot)
    evidence_status = (
        "BOUND_GCP_EVIDENCE_COMPLETE"
        if runtime_source == "BOUND_RELEASE"
        else str(release.get("cloud", "UNVERIFIED"))
    )
    release_commit = str(
        release.get("commit") or os.environ.get("SOLVAN_RELEASE_COMMIT", "unbound")
    )
    deployment_id = release.get("deployment_id") or os.environ.get("SOLVAN_DEPLOYMENT_ID")

    projection = {
        "schema_version": 1,
        "generated_at": now,
        "data_status": str(snapshot.get("data_status", "UNKNOWN")),
        "preference_version": 0,
        "operator": operator,
        "preferences": {
            "theme": "SYSTEM",
            "density": "COMFORTABLE",
            "motion": "SYSTEM",
            "timezone_mode": "BROWSER",
            "timezone": None,
        },
        "environment": {
            **scope,
            "environment_id": environment_id,
            "data_status": str(snapshot.get("data_status", "UNKNOWN")),
            "authority": str(snapshot.get("authority", "UNKNOWN")),
            "generated_at": str(snapshot.get("generated_at", now)),
            "available_scopes": [scope],
        },
        "runtime": {
            "provider": os.environ.get("SOLVAN_MODEL_PROVIDER", "Google Vertex AI"),
            "model_resource": os.environ.get("SOLVAN_MODEL_RESOURCE", "gemini-3.6-flash"),
            "model_display_name": os.environ.get("SOLVAN_MODEL_DISPLAY_NAME", "Gemini 3.6 Flash"),
            "model_revision": os.environ.get("SOLVAN_MODEL_REVISION"),
            "model_location": os.environ.get("SOLVAN_MODEL_LOCATION", "eu"),
            "region": str(environment.get("region", "europe-west1")),
            "framework": os.environ.get("SOLVAN_AGENT_FRAMEWORK", "google-adk"),
            "framework_version": os.environ.get("SOLVAN_AGENT_FRAMEWORK_VERSION", "2.7.1"),
            "runtime_sdk": os.environ.get("SOLVAN_RUNTIME_SDK", "google-cloud-aiplatform"),
            "runtime_sdk_version": os.environ.get("SOLVAN_RUNTIME_SDK_VERSION", "1.165.1"),
            "agent_manifest_version": os.environ.get(
                "SOLVAN_AGENT_MANIFEST_VERSION", "2026-08-08.1"
            ),
            "release_commit": release_commit,
            "deployment_id": str(deployment_id) if deployment_id else None,
            "source": runtime_source,
            "evidence_status": evidence_status,
            "fallback_status": "NONE",
        },
        "governance": {
            "autonomy_state": "UNAVAILABLE",
            "autonomy_reason": (
                "Local development has no production authority or earned-autonomy receipt."
                if local
                else "No current earned-autonomy receipt is bound to this environment."
            ),
            "autonomy_next_step": (
                "Deploy a qualified target environment and complete the independent "
                "evaluation period."
            ),
            "mutation_authority": (
                "POLICY_BOUND_GOOGLE_CLOUD_IAM" if not local else "NO_PRODUCTION_AUTHORITY"
            ),
            "policy_version": os.environ.get("SOLVAN_POLICY_VERSION", "release-policy-v1"),
            "approval_mode": "EXACT_DIGEST_AND_LIVE_RBAC",
            "gateway_status": _platform_health(snapshot, "Agent Gateway"),
            "model_armor_status": _platform_health(snapshot, "Model Armor"),
            "identity_status": _platform_health(snapshot, "Agent Identity"),
            "retention_summary": os.environ.get(
                "SOLVAN_RETENTION_SUMMARY", "Evidence and audit retention are policy-bound"
            ),
            "configuration_source": (
                "Bound release receipts"
                if runtime_source == "BOUND_RELEASE"
                else "Reviewed manifests"
            ),
            "last_verified_at": str(snapshot.get("generated_at", now)),
        },
        "about": {
            "console_version": api_version,
            "api_version": api_version,
            "build_commit": release_commit,
            "deployment_id": str(deployment_id) if deployment_id else None,
            "settings_schema_version": "1",
            "snapshot_schema_version": str(snapshot.get("schema_version", "unknown")),
            "projection_generated_at": now,
            "api_status": "ready",
            "documentation_url": os.environ.get("SOLVAN_DOCUMENTATION_URL"),
            "privacy_url": os.environ.get("SOLVAN_PRIVACY_URL"),
            "notices_url": os.environ.get("SOLVAN_NOTICES_URL"),
        },
        "capabilities": {
            "edit_preferences": True,
            "switch_environment": False,
            "sign_out": False,
            "manage_members": False,
            "manage_security": False,
            "manage_runtime": False,
            "view_audit": local,
            "export_diagnostics": False,
        },
    }
    return SettingsProjectionResponse.model_validate(projection).model_dump(mode="json")
