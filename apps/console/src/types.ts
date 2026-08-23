import type { ActuatorRegistration, ConnectableProvider, DensityMode, MotionMode, PlatformEvidence, PlatformHealth, StatusTone, TenantConnection, ThemeMode, TimezoneMode } from "./operabilityTypes";
import type { FleetProjection } from "./fleetTypes";
export type { CapabilityDecision, CapabilityLayer, CapabilityLayerOutcome, CapabilityVerdict, FleetProjection } from "./fleetTypes";
export type { ActuatorRegistration, Capability, ConnectableProvider, DensityMode, GrantPlan, GrantStep, MotionMode, PlatformEvidence, PlatformHealth, ProductionGraphReview, ProductionGraphStatus, StatusTone, TenantConnection, ThemeMode, TimezoneMode } from "./operabilityTypes";
export type UserPreferences = {
  theme: ThemeMode;
  density: DensityMode;
  motion: MotionMode;
  timezone_mode: TimezoneMode;
  timezone?: string | null;
};

export type OperatorContext = {
  state: "LOCAL_DEVELOPMENT" | "AUTHENTICATED" | "AUTHENTICATION_REQUIRED";
  principal: string | null;
  display_name: string;
  email: string | null;
  avatar_url: string | null;
  initials: string;
  identity_provider: "LOCAL" | "GOOGLE" | null;
  managed_by: "SOLVAN" | "GOOGLE" | null;
  organization: { id: string; name: string } | null;
  team: { id: string; name: string } | null;
  roles: Array<"VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN">;
  session_expires_at: string | null;
};

export type SettingsProjection = {
  schema_version: 1;
  generated_at: string;
  data_status: string;
  preference_version: number;
  operator: OperatorContext;
  preferences: UserPreferences;
  environment: {
    scope_key: string;
    name: string;
    environment_id: string;
    project_id: string;
    region: string;
    classification: "LOCAL" | "DEVELOPMENT" | "STAGING" | "PRODUCTION" | "UNKNOWN";
    data_status: string;
    authority: string;
    generated_at: string;
    available_scopes: Array<{
      scope_key: string;
      name: string;
      project_id: string;
      region: string;
      classification: string;
    }>;
  };
  runtime: {
    provider: string;
    model_resource: string;
    model_display_name: string;
    model_revision: string | null;
    model_location: string;
    region: string;
    framework: string;
    framework_version: string;
    runtime_sdk: string;
    runtime_sdk_version: string;
    agent_manifest_version: string;
    release_commit: string;
    deployment_id: string | null;
    source: "BOUND_RELEASE" | "MANIFEST_TARGET" | "LOCAL_FIXTURE" | "UNAVAILABLE";
    evidence_status: string;
    fallback_status: "NONE" | "ACTIVE" | "UNAVAILABLE";
  };
  governance: {
    autonomy_state: string;
    autonomy_reason: string;
    autonomy_next_step: string;
    mutation_authority: string;
    policy_version: string;
    approval_mode: string;
    gateway_status: string;
    model_armor_status: string;
    identity_status: string;
    retention_summary: string;
    configuration_source: string;
    last_verified_at: string | null;
  };
  about: {
    console_version: string;
    api_version: string;
    build_commit: string;
    deployment_id: string | null;
    settings_schema_version: string;
    snapshot_schema_version: string;
    projection_generated_at: string;
    api_status: string;
    documentation_url: string | null;
    privacy_url: string | null;
    notices_url: string | null;
  };
  capabilities: {
    edit_preferences: boolean;
    switch_environment: boolean;
    sign_out: boolean;
    manage_members: boolean;
    manage_security: boolean;
    manage_runtime: boolean;
    view_audit: boolean;
    export_diagnostics: boolean;
  };
};

export type Action = {
  id: string;
  name: string;
  status: string;
  phase: string;
  target: string;
  change: string;
  risk: string;
  blast_radius: string;
  policy: string;
  receipt?: string;
  verification: string;
  digest?: string;
  expected_version?: string;
  evidence_version?: string;
  expires?: string;
  rollback_plan?: string;
  expected_effect?: string;
  expected_effect_hash?: string;
};

/** What kind of thing an evidence record is. A citation that cannot say this
 *  is not provenance, it is decoration. */
export type EvidenceKind = "metric" | "log" | "trace" | "config" | "code" | "receipt" | "synthetic" | "record";

/** One resolvable evidence record, addressed by the short ref a finding cites. */
export type EvidenceItem = {
  ref: string;
  kind: EvidenceKind;
  label: string;
  source: string;
  window: string;
  freshness: string;
  classification: string;
  content_ref: string;
};

/** One measured consequence. `scope` names what it happened to, so impact is
 *  never a single unattributed percentage. */
export type ImpactLine = {
  metric: string;
  scope: string;
  detail: string;
  citation?: string;
};

export type Incident = {
  id: string;
  machine_id: string;
  title: string;
  severity: string;
  service: string;
  state: string;
  owner: string;
  age: string;
  next_action: string;
  /** Queue-scannable consequence, so the list can be triaged without opening rows. */
  impact_summary: string;
  /** True only when the next durable step is blocked on a person. */
  waiting_on_human: boolean;
  environment: string;
  workflow_version: number;
  detected_at: string;
  agent_council: Array<{
    name: string;
    role: string;
    status: string;
    detail: string;
    identity: string;
    budget: string;
  }>;
  causal_chain: Array<{
    label: string;
    detail: string;
    status: "observed" | "inferred" | "action" | "verified";
    source?: string;
  }>;
  brief: {
    situation: string;
    impact: string;
    impact_lines: ImpactLine[];
    customer_window: string;
    data_loss: string;
    last_verified: string;
    root_cause: string;
    attention: string;
    next: string;
    freshness: string;
    citations: string[];
    memories: string[];
  };
  /** Every ref cited anywhere on this incident, resolved once. */
  evidence_index: EvidenceItem[];
  /** Committed feed position, so the timeline stops asserting hard-coded numbers. */
  feed: { sequence: string; last_event: number; lease: string };
  plan: {
    version: number;
    progress: string;
    steps: Array<{
      marker: string;
      name: string;
      purpose: string;
      agent: string;
      status: string;
      dependencies: string;
      budget: string;
      evidence_delta: string;
      trace: string;
    }>;
  };
  guidance?: {
    selection_id: string;
    revision: string;
    name: string;
    role: "PRIMARY" | "SUPPORTING";
    revision_hash: string;
    profile: string;
    steps: Array<{
      key: string;
      title: string;
      kind: "OBSERVE" | "COMPUTE" | "PROPOSE" | "CHECKPOINT";
      status: string;
      predicate: string;
      reason: string | null;
      citations: string[];
      tool_receipts: string[];
    }>;
  };
  findings: {
    validated: Finding[];
    inferred: Finding[];
  };
  hypotheses: Array<{ state: string; label: string; confidence: string; score: string; rule: string }>;
  actions: Action[];
  verification: {
    id: string;
    verdict: string;
    profile: string;
    owner: string;
    binding: string;
    /** Verification phases across the recovery — baseline, fault, mutation,
     *  warmup, observation. A narrative of how the signal moved. */
    intervals: Array<{ name: string; window: string; error_ratio: string; p95: string; result: string }>;
    /** One observed signal beside the objective it was measured against. A
     *  different table from `intervals`: this is the readout the verification
     *  record actually holds. The console states the observation and the
     *  objective and adjudicates neither — the verdict is the verifier's and
     *  is rendered once, on the panel. */
    signals: Array<{
      signal: string;
      provider_kind: string;
      observed_value: number | null;
      observed_at: string;
      objective: string;
      citations: string[];
    }>;
    window: string;
    threshold: string;
    synthetic: string;
  };
  /** One annotated axis for the incident, composed from consecutive bounded
   *  evidence items. Empty when no metric evidence has been accepted — the
   *  console draws nothing rather than inventing a shape. Points are never
   *  interpolated across a gap between items, because a gap is a real gap in
   *  observation. */
  series: {
    signal_kind: string;
    points: Array<{ observed_at: string; value: number }>;
    markers: Array<{ kind: string; label: string; at: string; committed: string }>;
    window_band: { start: string; end: string; label: string } | null;
    objective: string;
    evidence_refs: string[];
  };
  phase_rail: Array<{ name: string; duration: string; state: "done" | "current" }>;
  timeline: Array<{ time: string; actor: string; event: string; state: string; kind: StatusTone }>;
};

/** A parsed, bounded unified diff. `note` is non-empty when the change shown
 *  is not the whole change, so the reviewer is never quietly given a sample. */
export type PatchDiff = {
  added: number;
  removed: number;
  truncated: boolean;
  note: string;
  files: Array<{
    path: string;
    added: number;
    removed: number;
    lines: Array<{ kind: "add" | "remove" | "context" | "meta"; old_line: number | null; new_line: number | null; text: string }>;
  }>;
};

export type Finding = { title: string; statement: string; source: string; citations: string[] };

export type WorkspaceCognition = {
  id: string;
  kind: string;
  status: string;
  provider: string;
  implementation_sdk: string;
  implementation_sdk_version: string;
  provider_revision: string;
  registry_agent_key: string;
  classification: string;
  synthetic: boolean;
  eligibility_decision: string;
  input_manifest_hash: string;
  network_policy_hash: string;
  task_runs: Array<{ id: string; task: string; status: string; attempt: number; request_hash: string; output_hash: string; provider_boot_hash: string; provider_service_revision: string }>;
  checkpoints: Array<{ id: string; event: string; sequence: number; artifact_manifest_hash: string; provider_boot_hash: string }>;
  repair_cognition: {
    patch_artifact_id: string;
    status: string;
    trust_class: "PROPOSED";
    mechanism: string;
    hypotheses: Array<{
      hypothesis_key: string;
      statement: string;
      supporting_citations: string[];
      contradicting_citations: string[];
      leading: boolean;
    }>;
    artifact_ref: string;
    artifact_hash: string;
    reproduction: { command: string; exit_code: number; output_ref: string; output_hash: string };
    regression: { command: string; exit_code: number; output_ref: string; output_hash: string };
  } | null;
  denied_authorities: string[];
};

export type ConsoleSnapshot = {
  schema_version: number;
  data_status: string;
  authority: string;
  generated_at: string;
  environment: { name: string; region: string };
  overview: {
    /** A stat tile: the figure, the signed change over a named period, and the
     *  trend it moved along. `delta` is derived from durable records, never
     *  from a window the console did not observe. */
    metrics: Array<{
      label: string;
      value: string;
      detail: string;
      delta: number;
      delta_period: string;
      trend: number[];
    }>;
    queue: Record<string, number>;
  };
  incidents: Incident[];
  cases: Array<{
    id: string;
    service: string;
    state: string;
    incident: string;
    age: string;
    repair: string;
    repair_plan: string;
    provider: string;
    commit: string;
    patch_status: string;
    patch_artifact: string;
    patch_digest: string;
    patch_ref: string;
    patch_diff: PatchDiff;
    test_ref: string;
    residual_risks: string[];
    next: string;
    owner: string;
    phases: string[];
    checkpoints: Array<{ day: string; events: string[] }>;
    workspace: WorkspaceCognition | null;
  }>;
  fleet: FleetProjection;
  integration: {
    local_connected_development?: boolean;
    providers: ConnectableProvider[];
    connections: TenantConnection[];
    actuators: ActuatorRegistration[];
    github: {
      repositories: Array<{
        id: string;
        owner: string;
        name: string;
        default_branch: string;
        classification: string;
        status: string;
        last_probe_result: string | null;
        policy_hash: string;
        allowed_operations_json: string[];
      }>;
      pull_requests: Array<{
        id: string;
        repository_id: string;
        owner: string;
        name: string;
        external_number: number;
        html_url: string;
        branch_name: string;
        base_commit_sha: string;
        head_commit_sha: string;
        title: string;
        status: string;
        latest_checks_state: string;
        mergeable_state: string | null;
        merge_commit_sha: string | null;
        patch_artifact_id: string;
        patch_digest: string;
        created_at: string;
        updated_at: string;
      }>;
      operations: Array<{
        id: string;
        repository_id: string;
        pull_request_id: string | null;
        operation: string;
        status: string;
        external_number: number | null;
        response_hash: string | null;
        receipt_ref: string | null;
        error_class: string | null;
        actor_principal: string;
        created_at: string;
        completed_at: string | null;
      }>;
      webhooks: Array<{
        event_name: string;
        action: string | null;
        processing_status: string;
        received_at: string;
        processed_at: string | null;
      }>;
    };
  };
  release: {
    scenarios: Array<{ id: string; name: string; status: string }>;
    commit: string;
    cloud: string;
    gate: string;
    deployment_id?: string; invalid_receipt_count?: number;
  };
  settings?: SettingsProjection;
};
