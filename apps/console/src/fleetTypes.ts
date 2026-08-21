/** The Agent Fleet projection: who is registered, what each seat may reach, and
 *  the record that decided it.
 *
 *  Split out of `types.ts` when the capability decision landed. The fleet block
 *  is the part of the snapshot that grows, and the file it lived in had reached
 *  its size ceiling.
 */
import type { PlatformEvidence, PlatformHealth } from "./operabilityTypes";

/** One authority in the chain that decides a capability, and what it said.
 *
 *  `NOT_APPLICABLE` and `NOT_EVALUATED` are not decoration. A capability that
 *  binds no connection can hold no probe receipt, and a scope with no platform
 *  preflight receipt has nothing to say about a Gateway route. Collapsing either
 *  into a refusal is what made fourteen of twenty-three rows read `Denied`
 *  permanently.
 */
export type CapabilityLayerOutcome = {
  layer:
    | "PROFILE_MEMBERSHIP"
    | "REQUESTER_DECLARATION"
    | "REVISION_LIFECYCLE"
    | "CLASSIFICATION_AND_REGION"
    | "GATEWAY_ROUTE"
    | "CONNECTION_BINDING"
    | "CAPABILITY_PROBE";
  state: "SATISFIED" | "REFUSED" | "NOT_APPLICABLE" | "NOT_EVALUATED";
  /** The record a reader can open: a profile revision, an approval, a receipt. */
  reference: string;
  observed_at: string | null;
  detail: string;
};

export type CapabilityLayer = CapabilityLayerOutcome["layer"];
export type CapabilityVerdict = "ALLOWED" | "DENIED" | "NOT_REGISTERED" | "NOT_EVALUATED";

/** What one Agent may do at one destination, and the layer that decided it. */
export type CapabilityDecision = {
  agent_key: string;
  agent: string;
  tool_key: string;
  version: string;
  tool: string;
  destination: string;
  registry_resource: string;
  permission_class: string;
  verdict: CapabilityVerdict;
  winning_layer: CapabilityLayer;
  winning_reference: string;
  layers: CapabilityLayerOutcome[];
};

export type FleetProjection = {
  /** One decision per (Agent, Tool revision), derived by the same rule the run
   *  binder applies. The `tools` list below answers what the catalog holds; this
   *  answers what each Agent may reach, and the two are no longer allowed to
   *  disagree. */
  capabilities: CapabilityDecision[];
  deterministic_services: Array<{
    name: string;
    key: string;
    capabilities: string;
    model_backed: false;
    allowed_operations: string[];
    identity: string;
    region: string;
  }>;
  agents: Array<{
    name: string;
    key: string;
    capabilities: string;
    execution_role: string;
    model_backed: boolean;
    tool_count: number;
    declared_tool_count: number;
    deployment: "DEPLOYED" | "NOT_DEPLOYED";
    region: string;
    manifest_hash?: string;
    registered_at?: string;
    /** Digest-verified facts from the registered agent manifest. `null` means
     *  the principal's pin no longer matches the checked-in manifest
     *  (superseded — facts withheld); absent means an older API. */
    manifest?: {
      manifest_version: string;
      owner_department: string | null;
      discoverable_departments: string[];
      framework: string | null;
      model: string | null;
      lifecycle: string | null;
      approval_status: string | null;
      permission_ceiling: string | null;
    } | null;
  }>;
  /** The durable run ledger the coordinator writes; a bounded recent window,
   *  newest first. Refs and hashes stay server-side. Optional because the
   *  console and API deploy as separate services: an API one revision older
   *  serves a snapshot without this key, and a missing ledger must degrade to
   *  an empty one, never blank the Agents tab. */
  agent_runs?: Array<{
    id: string;
    agent_key: string;
    agent: string;
    revision: string;
    status: string;
    attempt: number;
    incident_id: string | null;
    case_id: string | null;
    workspace_id: string | null;
    step: string;
    error_class: string | null;
    workflow_version: number;
    deadline: string;
    started_at: string | null;
    completed_at: string | null;
    trace: string | null;
  }>;
  tool_status_definitions: Record<string, string>;
  tools: Array<{
    key: string;
    version: string;
    name: string;
    owner: string;
    agent_keys: string[];
    agents: string[];
    permission_class: "READ" | "COMPUTE" | "PROPOSE" | "MUTATE";
    integration: string;
    connection: string;
    lifecycle: "Draft" | "Approved" | "Deprecated" | "Retired";
    availability: "Available" | "Not configured" | "Unavailable" | "Degraded" | "Disabled";
    evidence: "Not probed" | "Probe passed" | "Probe failed" | "Probe stale";
    deployment: "Implemented" | "Deployed" | "Release-qualified";
    registry: string;
    identity: string;
    gateway: string;
    armor: string;
    region: string;
    last_probe: string;
    probe_expiry: string;
    call_budget: number;
    timeout_ms: number;
    max_payload_bytes: number;
    last_call: string;
    trace: string;
    why: string;
    next_step: string;
  }>;
  tool_profiles: Array<{
    key: string;
    version: string;
    agent_key: string;
    lifecycle: string;
    tool_count: number;
    connection_count: number;
    maximum_calls: number;
    region: string;
  }>;
  tool_probes: Array<Record<string, unknown>>;
  guidance: Array<{
    key: string;
    version: string;
    name: string;
    description: string;
    owner: string;
    source_kind: "SOLVAN_AUTHORED" | "CUSTOMER_AUTHORED" | "IMPORTED";
    source_ref: string;
    author_principal: string;
    recorded_at: string;
    kind: string;
    purpose: string;
    classification: string;
    regions: string[];
    agent_keys: string[];
    profile_revisions: string[];
    lifecycle: string;
    availability: "Available" | "Unavailable" | "Degraded" | "Disabled";
    evidence: "Not evaluated" | "Evaluated" | "Evaluation stale";
    why: string;
    next_step: string;
    revision_hash: string;
  }>;
  trigger_policies: Array<Record<string, unknown>>;
  trigger_firings: Array<Record<string, unknown>>;
  memory: Array<{ id: string; type: string; scope: string; status: string; decision: string; purpose: string; classification: string; review: string; created_at: string; retention: string; source_count: number }>;
  security: Array<{ id: string; control: string; severity: string; event: string; summary: string; actor: string; destination: string; incident: string | null; policy: string | null; occurred_at: string; trace: string }>;
  audit: Array<{ sequence: number; id: string; time: string; principal: string; event: string; stream_type: string; stream_id: string; decision: string | null; trace: string | null; hash: string }>;
  platform: Array<{
    name: string;
    lifecycle: string;
    health: PlatformHealth;
    evidence: PlatformEvidence;
    detail: string;
    last_checked: string;
    next_step: string;
  }>;
};
