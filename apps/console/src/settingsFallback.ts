import type { ConsoleSnapshot, OperatorContext, SettingsProjection } from "./types";

function platformHealth(snapshot: ConsoleSnapshot, name: string): string {
  return snapshot.fleet.platform.find((item) => item.name === name)?.health ?? "UNKNOWN";
}

function fallbackOperator(snapshot: ConsoleSnapshot): OperatorContext {
  if (snapshot.authority !== "GOOGLE_CLOUD_IAM") {
    return {
      state: "LOCAL_DEVELOPMENT",
      principal: "local-development-reader",
      display_name: "Local development reader",
      email: null,
      avatar_url: null,
      initials: "LD",
      identity_provider: "LOCAL",
      managed_by: "SOLVAN",
      organization: null,
      team: null,
      roles: ["VIEWER"],
      session_expires_at: null,
    };
  }
  return {
    state: "AUTHENTICATION_REQUIRED",
    principal: null,
    display_name: "Sign in required",
    email: null,
    avatar_url: null,
    initials: "?",
    identity_provider: "GOOGLE",
    managed_by: "GOOGLE",
    organization: null,
    team: null,
    roles: [],
    session_expires_at: null,
  };
}

/**
 * Safe rolling-deployment fallback. It projects only fields already present in
 * the main console snapshot and marks everything else unavailable; it never
 * infers model, identity, policy, or authority configuration in the browser.
 */
export function settingsFallbackFromSnapshot(snapshot: ConsoleSnapshot): SettingsProjection {
  const local = snapshot.authority !== "GOOGLE_CLOUD_IAM";
  const scopeKey = local ? "local-development:local-development" : "settings-service-unavailable";
  const classification = local ? "LOCAL" : "UNKNOWN";
  const unavailable = "Not reported by this API version";
  return {
    schema_version: 1,
    generated_at: snapshot.generated_at,
    data_status: `${snapshot.data_status} · SETTINGS_FALLBACK`,
    preference_version: 0,
    operator: fallbackOperator(snapshot),
    preferences: {
      theme: "SYSTEM",
      density: "COMFORTABLE",
      motion: "SYSTEM",
      timezone_mode: "BROWSER",
      timezone: null,
    },
    environment: {
      scope_key: scopeKey,
      name: snapshot.environment.name,
      environment_id: local ? "local-development" : unavailable,
      project_id: local ? "local-development" : unavailable,
      region: snapshot.environment.region,
      classification,
      data_status: snapshot.data_status,
      authority: snapshot.authority,
      generated_at: snapshot.generated_at,
      available_scopes: [{
        scope_key: scopeKey,
        name: snapshot.environment.name,
        project_id: local ? "local-development" : unavailable,
        region: snapshot.environment.region,
        classification,
      }],
    },
    runtime: {
      provider: unavailable,
      model_resource: unavailable,
      model_display_name: unavailable,
      model_revision: null,
      model_location: unavailable,
      region: snapshot.environment.region,
      framework: unavailable,
      framework_version: "—",
      runtime_sdk: unavailable,
      runtime_sdk_version: "—",
      agent_manifest_version: unavailable,
      release_commit: snapshot.release.commit,
      deployment_id: snapshot.release.deployment_id ?? null,
      source: "UNAVAILABLE",
      evidence_status: snapshot.release.cloud,
      fallback_status: "UNAVAILABLE",
    },
    governance: {
      autonomy_state: "NOT_REPORTED",
      autonomy_reason: "The settings service did not return an earned-autonomy decision.",
      autonomy_next_step: "Retry settings or inspect the bound release evidence.",
      mutation_authority: snapshot.authority,
      policy_version: unavailable,
      approval_mode: unavailable,
      gateway_status: platformHealth(snapshot, "Agent Gateway"),
      model_armor_status: platformHealth(snapshot, "Model Armor"),
      identity_status: platformHealth(snapshot, "Agent Identity"),
      retention_summary: unavailable,
      configuration_source: "Snapshot fallback; settings service unavailable",
      last_verified_at: snapshot.generated_at,
    },
    about: {
      console_version: unavailable,
      api_version: unavailable,
      build_commit: snapshot.release.commit,
      deployment_id: snapshot.release.deployment_id ?? null,
      settings_schema_version: "1",
      snapshot_schema_version: String(snapshot.schema_version),
      projection_generated_at: snapshot.generated_at,
      api_status: "SETTINGS_SERVICE_UNAVAILABLE",
      documentation_url: null,
      privacy_url: null,
      notices_url: null,
    },
    capabilities: {
      edit_preferences: true,
      switch_environment: false,
      sign_out: false,
      manage_members: false,
      manage_security: false,
      manage_runtime: false,
      view_audit: false,
      export_diagnostics: false,
    },
  };
}
