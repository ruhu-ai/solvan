export type StatusTone = "success" | "warning" | "danger" | "info" | "agent" | "neutral" | "provenance";
export type PlatformHealth = "HEALTHY" | "DEGRADED" | "BLOCKED" | "UNKNOWN";
export type PlatformEvidence = "LOCAL_VERIFIED" | "CLOUD_VERIFIED" | "UNVERIFIED";

export type ThemeMode = "SYSTEM" | "LIGHT" | "DARK";
export type DensityMode = "COMFORTABLE" | "COMPACT";
export type MotionMode = "SYSTEM" | "REDUCED" | "FULL";
export type TimezoneMode = "BROWSER" | "UTC" | "NAMED";

/** Specification 13 §4: why one probe answered as it did, typed. */
export type CapabilityOutcome = "GRANTED" | "DENIED" | "UNREACHABLE" | "MISCONFIGURED" | "NOT_PROBED";

export type Capability = {
  capability: string;
  available: boolean;
  outcome: CapabilityOutcome;
  missing_grant: string | null;
};

/** The closed availability vocabulary of specification 13 §4. */
export type ConnectionAvailability =
  | "NOT_CONFIGURED"
  | "PROBING"
  | "READY"
  | "DEGRADED"
  | "MISCONFIGURED"
  | "DENIED"
  | "UNREACHABLE"
  | "STALE"
  | "DISABLED";

export type RemediationKind =
  | "GRANT_ROLE"
  | "ENABLE_API"
  | "FIX_CONFIGURATION"
  | "REGISTER_CREDENTIAL"
  | "RETRY_PROBE"
  | "REENABLE_CONNECTION"
  | "CONTACT_PROVIDER";

export type TenantConnection = {
  id: string;
  connection_epoch: number;
  display_name: string;
  kind: "GCP_NATIVE" | "VENDOR_API" | "COLLECTOR" | "RELAY";
  provider: string;
  credential_posture: "FEDERATED_SHORT_LIVED" | "STORED_LONG_LIVED" | "CUSTOMER_SIDE_NONE";
  classification: string;
  residency_region: string;
  external_resource_kind?: "GCP_PROJECT" | "GCP_FOLDER" | "GCP_ORGANIZATION" | null;
  external_resource_id?: string | null;
  workload_region?: string | null;
  /** Authored: what an administrator decided about this connection. */
  lifecycle: "PENDING" | "ENABLED" | "DISABLED" | "REVOKED";
  /** Derived: what Solvan can actually do with it right now. */
  availability: ConnectionAvailability;
  availability_reason_code: string | null;
  availability_explanation: string | null;
  availability_missing_grant: string | null;
  availability_remediation_kind: RemediationKind | null;
  availability_reference: string | null;
  availability_receipt_ref: string | null;
  last_probe_result: string | null;
  last_success_at: string | null;
  proof_expires_at: string | null;
  holds_stored_secret: boolean;
  read_only_scope_verified: boolean;
  capabilities: Capability[];
};

export type ActuatorRegistration = {
  id: string;
  connection_id: string;
  host_kind: "CLOUD_RUN" | "GKE" | "ONPREM_FEDERATED" | "ONPREM_KEYFILE" | "DEV_LOCAL";
  production_eligible: boolean;
  risk_accepted: boolean;
  principal_email: string;
  posture: "COLLECTOR" | "REMEDIATE";
  image_digest: string;
  actuator_version: string;
  policy_hash: string | null;
  customer_audit_configured: boolean;
  kill_switch_engaged: boolean;
  status: "REGISTERED" | "ACTIVE" | "DISABLED" | "REVOKED";
  last_poll_at: string | null;
};

export type ConnectableProvider = {
  provider: string;
  kind: "GCP_NATIVE" | "VENDOR_API" | "COLLECTOR";
  label: string;
};

export type GrantStep = { purpose: string; command: string };

export type GrantPlan = {
  posture: string;
  summary: string;
  secret_required: boolean;
  delegation_condition_digest?: string | null;
  solvan_delegator_principal?: string | null;
  steps: GrantStep[];
};

export type ProductionGraphStatus = {
  placement: {
    cell_id: string;
    placement_epoch: number;
    region: string;
    classification_ceiling: string;
  } | null;
  sources: Array<{
    source_key: string;
    source_revision: number;
    tier: number;
    required_for_complete: boolean;
    policy_hash: string;
  }>;
  runs: Array<{
    run_id: string;
    state: "PENDING" | "RUNNING" | "COMPLETED" | "DEGRADED" | "FAILED" | "CANCELLED";
    requested_by: string;
    requested_at: string;
    started_at: string | null;
    ended_at: string | null;
    source_policy_set_hash: string;
  }>;
  snapshots: Array<{
    snapshot_id: string;
    snapshot_version: number;
    status: "DRAFT" | "APPROVED" | "RETIRED";
    completeness: "COMPLETE" | "INCOMPLETE" | null;
    content_hash: string | null;
    reconciled_at: string;
    autonomy_eligible: boolean;
  }>;
  execution_configured: boolean;
};

export type ProductionGraphReview = {
  snapshot_id: string;
  snapshot_version: number;
  status: "DRAFT" | "APPROVED" | "RETIRED";
  completeness: "COMPLETE" | "INCOMPLETE" | null;
  material_hash: string | null;
  content_hash: string | null;
  autonomy_eligible: boolean;
  reconciled_at: string;
  cell_id: string;
  placement_epoch: number;
  predecessor_snapshot_id: string | null;
  predecessor_material_hash: string | null;
  diff_hash: string | null;
  governed_change_count: number | null;
  diff_counts: Record<string, number>;
  tier_status: Array<{
    tier: number;
    required_for_complete: boolean;
    outcome: string;
    observation_count: number;
  }>;
  findings: Array<{
    finding_id: string;
    finding_kind: string;
    subject_node_key: string | null;
    subject_edge_key: string | null;
    detail_ref: string;
    status: string;
  }>;
};
