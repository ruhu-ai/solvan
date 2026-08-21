import { useEffect, useState } from "react";
import type { ActuatorRegistration, Capability, ConnectableProvider, ConsoleSnapshot, GrantPlan, StatusTone, TenantConnection } from "./types";
import { LabelValue, MonoChip, PageHeader, StatusBadge } from "./components";
import { ProductionGraphPanel } from "./ProductionGraphPanel";
import { GcpConnectionGuide } from "./GcpConnectionGuide";
import { GitHubConversationPanel } from "./GitHubConversation";
import { GitHubConnectFlow } from "./GitHubIntegration";
import { ReleaseAuthoritySetup } from "./ReleaseAuthority";
import { DirectGcpAlertSourceWizard, LocalMonitoringTest } from "./AlertSourceSetup";
import { CodeDeliveryProfileSetup, GitHubReviewerIdentitySetup, RepairCommandSetup } from "./GitHubRepositorySetup";
import { challengeHeaders, csrfHeaders, digest, requestStepUp } from "./session";
import type { StepUpStart } from "./session";
import { StepUpDialog } from "./StepUpDialog";

const postureCopy: Record<TenantConnection["credential_posture"], { label: string; tone: StatusTone; detail: string }> = {
  CUSTOMER_SIDE_NONE: { label: "No credential held", tone: "provenance", detail: "Reads run inside the customer estate. Solvan stores nothing." },
  FEDERATED_SHORT_LIVED: { label: "Federated · short-lived", tone: "provenance", detail: "Workload Identity Federation. No key material exists." },
  STORED_LONG_LIVED: { label: "Stored key · long-lived", tone: "warning", detail: "Read-only vendor key held under per-tenant CMEK. Rotate on schedule." },
};

// Specification 13 §4. Nine states, because the five diagnostic ones are
// exactly what separates "you typed the project wrong" from "you forgot a
// role" from "the probe timed out". Collapsing them tells an operator that
// something failed without telling them what to do about it.
const availabilityCopy: Record<TenantConnection["availability"], { label: string; tone: StatusTone; fallback: string }> = {
  READY: { label: "Ready", tone: "success", fallback: "Every required capability has fresh proof." },
  NOT_CONFIGURED: { label: "Never probed", tone: "neutral", fallback: "Nothing about this connection is proven yet." },
  PROBING: { label: "Probing", tone: "neutral", fallback: "One fenced minimal probe is running." },
  DEGRADED: { label: "Degraded", tone: "warning", fallback: "Some capabilities are proven and the selected profile is incomplete." },
  MISCONFIGURED: { label: "Misconfigured", tone: "warning", fallback: "Configuration is present but invalid." },
  DENIED: { label: "Permission denied", tone: "warning", fallback: "Solvan reached the provider and the permission was refused." },
  UNREACHABLE: { label: "Unreachable", tone: "warning", fallback: "The probe could not reach the provider conclusively, so nothing is proven either way." },
  STALE: { label: "Proof expired", tone: "warning", fallback: "Prior proof expired or its binding changed." },
  DISABLED: { label: "Disabled", tone: "neutral", fallback: "An authorized configuration change disabled this connection." },
};

// Each state ends in one concrete next step, so the operator never has to infer
// the action from the diagnosis.
const remediationCopy: Record<NonNullable<TenantConnection["availability_remediation_kind"]>, string> = {
  GRANT_ROLE: "Grant this role, then re-probe",
  ENABLE_API: "Enable this API on the project, then re-probe",
  FIX_CONFIGURATION: "Correct the configuration, then re-probe",
  REGISTER_CREDENTIAL: "Register the credential for this provider",
  RETRY_PROBE: "Verify again",
  REENABLE_CONNECTION: "Re-enable this connection to use it",
  CONTACT_PROVIDER: "Contact the provider — Solvan cannot resolve this",
};

const outcomeCopy: Record<Capability["outcome"], { label: string; tone: StatusTone }> = {
  GRANTED: { label: "Available", tone: "success" },
  DENIED: { label: "Denied", tone: "warning" },
  UNREACHABLE: { label: "Unreachable", tone: "warning" },
  MISCONFIGURED: { label: "API not enabled", tone: "warning" },
  NOT_PROBED: { label: "Not probed here", tone: "neutral" },
};

const hostCopy: Record<ActuatorRegistration["host_kind"], { label: string; eligible: string }> = {
  CLOUD_RUN: { label: "Cloud Run", eligible: "Workload Identity · no key" },
  GKE: { label: "GKE", eligible: "Workload Identity · reaches private targets" },
  ONPREM_FEDERATED: { label: "On-prem · federated", eligible: "Customer OIDC issuer" },
  ONPREM_KEYFILE: { label: "On-prem · key file", eligible: "Long-lived key · risk acceptance required" },
  DEV_LOCAL: { label: "Development", eligible: "Never production eligible" },
};

const postureForKind: Record<ConnectableProvider["kind"], TenantConnection["credential_posture"]> = {
  GCP_NATIVE: "FEDERATED_SHORT_LIVED",
  VENDOR_API: "STORED_LONG_LIVED",
  COLLECTOR: "CUSTOMER_SIDE_NONE",
};

type RelayEnrollment = {
  enrollment_id: string;
  lifecycle: string;
  enrollment_epoch: number;
  host_kind: string;
  region: string;
  classification_ceiling: string;
  relay_version: string;
  safe_reason_code: string | null;
  last_poll_at: string | null;
  last_receipt_at: string | null;
};

type RelayDeploymentProfile = {
  deployment_profile_id: string;
  relay_connection_id: string;
  host_kind: string;
  region: string;
  classification_ceiling: string;
  image_attestation_id: string;
  relay_version: string;
  expires_at: string;
  review_state: string;
};

const relayLifecycleCopy: Record<string, { detail: string; next: string }> = {
  REGISTERED: {
    detail: "Enrollment is recorded but no current runtime-policy proof has been accepted.",
    next: "Start the customer Relay with its signed policy to complete attestation.",
  },
  READY: {
    detail: "A current identity-bound runtime-policy proof permits bounded read-only polling.",
    next: "Monitor the customer-owned Relay and disable it here if reads must stop.",
  },
  DEGRADED: {
    detail: "The last safe health receipt was not sufficient to keep the Relay ready.",
    next: "Restore the customer Relay and let it submit a fresh signed runtime proof.",
  },
  STALE: {
    detail: "A binding, policy, or epoch changed after the prior readiness receipt.",
    next: "Re-attest from the customer Relay; readiness cannot be restored from this console.",
  },
  DISABLED: {
    detail: "An administrator disabled the enrollment; no new work can be claimed.",
    next: "Re-enroll with a new epoch, bindings, and runtime proof if customer policy permits.",
  },
  REVOKED: {
    detail: "The enrollment is permanently revoked and prior material remains unusable.",
    next: "Create a new customer-approved enrollment; a revoked Relay cannot be re-enabled.",
  },
};

function RelayOperations({ apiUrl, connections }: { apiUrl: string; connections: TenantConnection[] }): React.JSX.Element {
  const [identityToken, setIdentityToken] = useState("");
  const [enrollments, setEnrollments] = useState<RelayEnrollment[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function request(path: string, method = "GET"): Promise<void> {
    const token = identityToken.trim();
    if (!token) {
      setNotice("Enter a verified administrator identity token to inspect or change Relay state.");
      return;
    }
    setBusy(true);
    try {
      const response = await fetch(`${apiUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-Solvan-Approval-Token": token,
          "Idempotency-Key": crypto.randomUUID(),
        },
        ...(method === "POST" ? { body: JSON.stringify({ schema_version: 1 }) } : {}),
      });
      if (!response.ok) throw new Error(`Relay request refused (${response.status})`);
      if (method === "GET") setEnrollments((await response.json()) as RelayEnrollment[]);
      else {
        const result = (await response.json()) as { lifecycle: string };
        setNotice(`Relay lifecycle is now ${result.lifecycle}. A disabled Relay cannot read until it is freshly re-enrolled and attested.`);
        await request("/api/v1/relays");
      }
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : "Relay request failed");
    } finally {
      setBusy(false);
    }
  }

  // Only fetch once an identity exists. Firing on mount guaranteed a refusal,
  // which set a notice saying an identity is required directly beneath the
  // empty state already saying it — the panel opened by telling the operator
  // the same thing twice.
  useEffect(() => {
    if (identityToken.trim()) void request("/api/v1/relays");
  }, [identityToken]); // eslint-disable-line react-hooks/exhaustive-deps

  return <section className="card" aria-labelledby="relay-operations-heading">
    <div className="section-heading"><div><p className="eyebrow">Customer-resident evidence</p><h2 id="relay-operations-heading">Solvant Relay</h2></div><StatusBadge label="Read-only control plane" tone="provenance" /></div>
    <p className="section-note">Relay processes run in the customer estate with a local kill switch. Solvan cannot receive their credentials or invoke a customer provider directly.</p>
    <label className="field-label">Administrator identity token<input type="password" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} placeholder="Bearer …" autoComplete="off" /></label>
    <div className="settings-actions"><button className="secondary-button" type="button" disabled={busy} onClick={() => void request("/api/v1/relays")}>{busy ? "Working…" : "Refresh Relay status"}</button></div>
    {!enrollments ? <p className="inline-notice" role="status">Relay state is only read under an operator's own identity, so it is not shown until one is supplied. Nothing has failed.</p> : enrollments.length === 0 ? <p className="inline-notice" role="status">No Relay is enrolled for this scope.</p> : <div className="responsive-table"><table><caption className="visually-hidden">Solvant Relay enrollments</caption><thead><tr><th>Enrollment</th><th>Runtime</th><th>Region / ceiling</th><th>Health</th><th>Control</th></tr></thead><tbody>{enrollments.map((relay) => { const lifecycle = relayLifecycleCopy[relay.lifecycle] ?? { detail: "The lifecycle is not recognized by this console version.", next: "Do not operate this Relay; refresh after updating the console." }; return <tr key={relay.enrollment_id}><td data-label="Enrollment"><MonoChip>{relay.enrollment_id}</MonoChip><span className="cell-detail">Epoch {relay.enrollment_epoch} · {relay.host_kind}</span></td><td data-label="Runtime">{relay.relay_version}</td><td data-label="Region / ceiling">{relay.region}<span className="cell-detail">{relay.classification_ceiling}</span></td><td data-label="Health"><StatusBadge label={relay.lifecycle} tone={relay.lifecycle === "READY" ? "success" : relay.lifecycle === "REVOKED" ? "danger" : "warning"} /><span className="cell-detail">{relay.safe_reason_code ?? lifecycle.detail}</span><span className="cell-detail">Next: {lifecycle.next}</span>{relay.last_poll_at && <span className="cell-detail">Last poll {relay.last_poll_at}</span>}</td><td data-label="Control">{["REGISTERED", "READY", "DEGRADED", "STALE"].includes(relay.lifecycle) && <button className="secondary-button" type="button" disabled={busy} onClick={() => void request(`/api/v1/relays/${encodeURIComponent(relay.enrollment_id)}:disable`, "POST")}>Disable</button>}</td></tr>; })}</tbody></table></div>}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
    <RelaySetupWizard apiUrl={apiUrl} connections={connections} administratorToken={identityToken} />
  </section>;
}

type RelayAdapterChoice = {
  key: "cloud-monitoring.v1" | "managed-prometheus.v1" | "cloud-logging.v1" | "cloud-trace.v1" | "kubernetes-metadata.v1";
  label: string;
  provider: string;
  capability: string;
  deploymentRequirement: string;
};

const relayAdapterChoices: RelayAdapterChoice[] = [
  { key: "cloud-monitoring.v1", label: "Cloud Monitoring", provider: "CLOUD_MONITORING", capability: "metrics.read", deploymentRequirement: "Grant only roles/monitoring.viewer." },
  { key: "managed-prometheus.v1", label: "Managed Prometheus", provider: "MANAGED_PROMETHEUS", capability: "promql.read", deploymentRequirement: "Grant only roles/monitoring.viewer and register the permitted metric templates in the signed policy." },
  { key: "cloud-logging.v1", label: "Cloud Logging", provider: "CLOUD_LOGGING", capability: "logs.read", deploymentRequirement: "Grant only roles/logging.viewer and register the permitted log signatures in the signed policy." },
  { key: "cloud-trace.v1", label: "Cloud Trace", provider: "CLOUD_TRACE", capability: "traces.read", deploymentRequirement: "Grant only roles/cloudtrace.user; Relay reads a trace only after it is discovered in the incident evidence." },
  { key: "kubernetes-metadata.v1", label: "Kubernetes metadata", provider: "KUBERNETES", capability: "kubernetes.metadata.read", deploymentRequirement: "Grant namespace-scoped GET/LIST RBAC only; register the permitted namespaces and workload kinds in the signed policy." },
];

function RelaySetupWizard({ apiUrl, connections, administratorToken }: { apiUrl: string; connections: TenantConnection[]; administratorToken: string }): React.JSX.Element {
  const [enrollmentId, setEnrollmentId] = useState("");
  const [adapterKey, setAdapterKey] = useState<RelayAdapterChoice["key"]>("cloud-monitoring.v1");
  const [sourceConnectionId, setSourceConnectionId] = useState("");
  const [profiles, setProfiles] = useState<RelayDeploymentProfile[] | null>(null);
  const [deploymentProfileId, setDeploymentProfileId] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [adapterRevision, setAdapterRevision] = useState("1");
  const selectedAdapter = relayAdapterChoices.find((choice) => choice.key === adapterKey)!;
  const eligibleConnections = connections.filter((connection) => connection.provider === selectedAdapter.provider && connection.availability === "READY" && connection.credential_posture === "CUSTOMER_SIDE_NONE");
  const selectedProfile = profiles?.find((profile) => profile.deployment_profile_id === deploymentProfileId);

  async function post(path: string, body: object): Promise<Record<string, string>> {
    if (!administratorToken.trim()) throw new Error("Enter a verified administrator identity token first.");
    const response = await fetch(`${apiUrl}${path}`, { method: "POST", headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": administratorToken.trim(), "Idempotency-Key": crypto.randomUUID() }, body: JSON.stringify({ schema_version: 1, ...body }) });
    if (!response.ok) throw new Error(`Relay setup request refused (${response.status}).`);
    return (await response.json()) as Record<string, string>;
  }

  async function loadProfiles(): Promise<void> {
    setBusy(true); setNotice(null);
    try {
      if (!administratorToken.trim()) throw new Error("Enter a verified administrator identity token first.");
      const response = await fetch(`${apiUrl}/api/v1/relay-deployment-profiles`, { headers: { "X-Solvan-Approval-Token": administratorToken.trim() } });
      if (!response.ok) throw new Error(`Deployment profiles are unavailable (${response.status}).`);
      setProfiles((await response.json()) as RelayDeploymentProfile[]);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Relay transport registration failed."); }
    finally { setBusy(false); }
  }

  async function createEnrollment(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null);
    try { const result = await post("/api/v1/relays", { deployment_profile_id: deploymentProfileId }); setEnrollmentId(result.enrollment_id); setNotice(`Enrollment ${result.enrollment_id} is registered from the reviewed customer deployment profile. Deploy the generated bundle, then bind each approved source.`); }
    catch (reason) { setNotice(reason instanceof Error ? reason.message : "Relay enrollment failed."); }
    finally { setBusy(false); }
  }

  async function bindSource(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null);
    try {
      if (!enrollmentId) throw new Error("Create or enter an enrollment ID before binding a source.");
      const result = await post(`/api/v1/relays/${encodeURIComponent(enrollmentId)}/source-bindings`, { adapter_revision: adapterRevision, source_connection_id: sourceConnectionId, adapter_key: adapterKey });
      setNotice(`Source binding ${result.source_binding_id} is READY. It remains unusable until the customer Relay presents its runtime proof.`);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Relay source binding failed."); }
    finally { setBusy(false); }
  }

  function downloadBundle(): void {
    const bundle = {
      schema_version: 1,
      kind: "solvant-relay-customer-deployment-bundle",
      generated_at: new Date().toISOString(),
      enrollment: {
        enrollment_id: enrollmentId || null,
        deployment_profile_id: deploymentProfileId || null,
        relay_connection_id: selectedProfile?.relay_connection_id ?? null,
        host_kind: selectedProfile?.host_kind ?? null,
        region: selectedProfile?.region ?? null,
        image_attestation_id: selectedProfile?.image_attestation_id ?? null,
        relay_version: selectedProfile?.relay_version ?? null,
      },
      selected_adapter: {
        adapter_key: selectedAdapter.key,
        provider: selectedAdapter.provider,
        capability: selectedAdapter.capability,
        source_connection_id: sourceConnectionId || null,
        requirement: selectedAdapter.deploymentRequirement,
      },
      artifacts: ["gke-cronjob.yaml", "cloud-run-job.yaml", "onprem-compose.yaml", "qualification-receipt.template.json"],
      required_customer_controls: ["customer-owned workload identity", "read-only local credential mount", "signed read-narrowing policy", "exact TLS egress allowlist", "persistent encrypted attempt ledger", "customer-owned kill switch", "customer-signed qualification evidence"],
      prohibited: ["inbound Service or Ingress", "Solvan-held credential", "mutation permission", "arbitrary HTTP or query proxy", "remote policy override"],
    };
    const objectUrl = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = "solvant-relay-deployment-bundle.json";
    link.click();
    URL.revokeObjectURL(objectUrl);
    setNotice("Downloaded a safe deployment bundle. Add local secret references and the signed policy only inside the customer deployment.");
  }

  return <details className="card connection-card" aria-label="Relay setup wizard">
    <summary><strong>Set up a Relay</strong><span className="cell-detail">Secret-free customer deployment and source binding</span></summary>
    <p className="section-note">The customer deployment process submits a signed, short-lived profile through the authenticated control plane. This console only reviews and consumes that stored profile; it never accepts credentials, private keys, policy bodies, identity claims, or security-critical digests.</p>
    <ol className="checklist">
      <li>Customer deployment tooling submits a signed profile after it has selected the host, workload identity, image, policy, egress, ledger, and kill switch.</li>
      <li>Review one stored profile and bind only READY, customer-side source connections.</li>
      <li>Deploy using the customer-owned GKE, Cloud Run Job, or on-prem template; enforce egress and the kill switch.</li>
      <li>Wait for the signed runtime proof, then record the customer qualification receipt.</li>
    </ol>
    <form className="connect-form" onSubmit={(event) => void createEnrollment(event)}>
      <h3>1. Review customer deployment profile</h3>
      <div className="form-grid">
        <div className="settings-actions"><button className="secondary-button" type="button" disabled={busy || !administratorToken.trim()} onClick={() => void loadProfiles()}>Load deployment profiles</button></div>
        <label className="field-label">Customer deployment profile<select required value={deploymentProfileId} onChange={(event) => setDeploymentProfileId(event.target.value)}><option value="">Choose a pending customer profile</option>{profiles?.filter((profile) => profile.review_state === "PENDING_REVIEW").map((profile) => <option value={profile.deployment_profile_id} key={profile.deployment_profile_id}>{profile.host_kind} · {profile.region} · {profile.deployment_profile_id}</option>)}</select></label>
        {selectedProfile && <p className="inline-notice">Transport <MonoChip>{selectedProfile.relay_connection_id}</MonoChip> · image attestation <MonoChip>{selectedProfile.image_attestation_id}</MonoChip> · ceiling {selectedProfile.classification_ceiling} · expires {selectedProfile.expires_at}</p>}
      </div>
      {!profiles && <p className="inline-notice">Load profiles after entering the administrator token above. A missing profile must be created by the customer's authenticated deployment tooling, not by typing values here.</p>}
      <button className="primary-button" type="submit" disabled={busy || !deploymentProfileId}>{busy ? "Registering…" : "Approve and register Relay"}</button>
    </form>
    <form className="connect-form" onSubmit={(event) => void bindSource(event)}>
      <h3>2. Bind approved read sources</h3>
      <label className="field-label">Enrollment ID<input required value={enrollmentId} onChange={(event) => setEnrollmentId(event.target.value)} placeholder="ren_…" /></label>
      <label className="field-label">Read adapter<select value={adapterKey} onChange={(event) => { const next = event.target.value as RelayAdapterChoice["key"]; setAdapterKey(next); setSourceConnectionId(""); }}>{relayAdapterChoices.map((choice) => <option value={choice.key} key={choice.key}>{choice.label}</option>)}</select></label>
      <p className="inline-notice">Requires <MonoChip>{selectedAdapter.provider}</MonoChip> with <MonoChip>{selectedAdapter.capability}</MonoChip>. {selectedAdapter.deploymentRequirement}</p>
      <label className="field-label">Approved source connection<select required value={sourceConnectionId} onChange={(event) => setSourceConnectionId(event.target.value)}><option value="">Choose a READY customer-side connection</option>{eligibleConnections.map((connection) => <option value={connection.id} key={connection.id}>{connection.display_name} · {connection.id}</option>)}</select></label>
      {eligibleConnections.length === 0 && <p className="inline-notice">No eligible connection is visible here. Create and successfully probe the real provider connection first; do not paste a credential into this wizard.</p>}
      <div className="form-grid"><label className="field-label">Adapter revision<input required value={adapterRevision} onChange={(event) => setAdapterRevision(event.target.value)} /></label></div>
      <button className="primary-button" type="submit" disabled={busy || !sourceConnectionId}>{busy ? "Binding…" : "Bind source"}</button>
    </form>
    <details className="inline-notice"><summary>3. Customer deployment bundle</summary><p>Use the release-attested customer-owned template for your selected host: <MonoChip>infra/customer-relay/gke-cronjob.yaml</MonoChip>, <MonoChip>cloud-run-job.yaml</MonoChip>, or <MonoChip>onprem-compose.yaml</MonoChip>. Configure only your local secret mounts, signed policy, workload identity, egress allowlist, persistent encrypted ledger, and kill switch. Do not add a Service, ingress, Solvan credential, mutation permission, arbitrary query proxy, or remote policy override.</p><button className="secondary-button" type="button" onClick={downloadBundle}>Download deployment bundle</button><p>After readiness is <MonoChip>READY</MonoChip>, customer deployment tooling submits <MonoChip>qualification-receipt.template.json</MonoChip> over the authenticated control-plane route. The control plane verifies the registered customer runtime-key signature, exact enrollment epoch, deployment-profile egress digest, enabled kill switch, and receipt expiry; a browser upload is never accepted.</p></details>
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </details>;
}

// What each source answers during an incident, in the operator's terms. The
// five that an investigation actually reads are ticked; the other two are
// offered unticked, because neither is needed to establish what happened and
// pre-ticking one would ask a customer to grant a role for nothing.
const investigationProviders = ["CLOUD_MONITORING", "CLOUD_LOGGING", "CLOUD_AUDIT", "ERROR_REPORTING", "CLOUD_TRACE"];

const capabilityCopy: Record<string, string> = {
  CLOUD_MONITORING: "Metric series and alert context — what changed, and when.",
  CLOUD_LOGGING: "Application and platform logs across the incident window.",
  CLOUD_AUDIT: "Who changed what, which is usually the answer to a sudden regression.",
  ERROR_REPORTING: "Grouped exception signatures and when each one first appeared.",
  CLOUD_TRACE: "Request-level latency attribution across services.",
  ASSET_INVENTORY: "Resource inventory and configuration history. Not required to investigate.",
  MANAGED_PROMETHEUS: "PromQL over Google Managed Service for Prometheus. Not required to investigate.",
};

// The API answers a refused selection with a closed code and no prose, so the
// sentence shown here is written here. An unrecognized code is reported as
// itself rather than given an invented friendlier meaning.
const estateRefusalCopy: Record<string, string> = {
  ESTATE_SELECTION_EMPTY: "Tick at least one telemetry source. An estate with nothing selected would register nothing and prove nothing.",
  ESTATE_PROVIDER_UNKNOWN: "One of the selected sources is not offered for connection. Reload this page: the catalog changed under you.",
  ESTATE_PROVIDER_DUPLICATED: "The same source was submitted twice. Reload this page and select it once.",
  ESTATE_PROVIDER_NOT_DIRECT_GCP: "One of the selected sources is not read through a customer reader service account, so it cannot share this estate's grants.",
  ESTATE_PROJECT_REQUIRED: "Enter the Google Cloud project the telemetry lives in.",
  ESTATE_READER_REQUIRED: "Enter the customer read-only service account Solvan should impersonate.",
  ESTATE_READER_NOT_A_SERVICE_ACCOUNT: "The customer reader must be a Google service-account email ending in .iam.gserviceaccount.com.",
};

type EstateGrantPlan = GrantPlan & { providers: string[]; roles: string[] };

type EstateOutcome = {
  provider: string;
  connection_id: string;
  connection_epoch: number;
  probe_result: "SUCCEEDED" | "PARTIAL" | "FAILED" | null;
  probe_reason_code: "PROBE_UNAVAILABLE" | "PROBE_REFUSED" | null;
};

const probeOutcomeCopy: Record<string, { label: string; tone: StatusTone }> = {
  SUCCEEDED: { label: "Every capability proven", tone: "success" },
  PARTIAL: { label: "Partly proven", tone: "warning" },
  FAILED: { label: "Nothing proven", tone: "warning" },
  PROBE_UNAVAILABLE: { label: "Not probed — reader unavailable", tone: "neutral" },
  PROBE_REFUSED: { label: "Not probed — reader refused", tone: "warning" },
};

/** Onboarding hands the customer commands to run; it never asks for a secret. */
function ConnectFlow({ providers, onChanged, onOpenGuide }: { providers: ConnectableProvider[]; onChanged: () => void; onOpenGuide: () => void }): React.JSX.Element | null {
  const [open, setOpen] = useState(false);
  const connectable = providers.filter((item) => item.kind === "GCP_NATIVE");
  const [selection, setSelection] = useState<string[]>(() => connectable.filter((item) => investigationProviders.includes(item.provider)).map((item) => item.provider));
  const [project, setProject] = useState("");
  const [workloadRegion, setWorkloadRegion] = useState("");
  const [plan, setPlan] = useState<EstateGrantPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [customerReader, setCustomerReader] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [registered, setRegistered] = useState<EstateOutcome[] | null>(null);
  const [pendingEstate, setPendingEstate] = useState<PendingEstate | null>(null);
  const [stepUpRequest, setStepUpRequest] = useState<StepUpStart | null>(null);
  // Every source that can be connected is read with one short-lived token for
  // one customer reader, so the posture is a property of the flow rather than
  // of whichever box was ticked last.
  const posture = postureForKind.GCP_NATIVE;
  const apiUrl = "";

  function refusal(code: string | undefined, status: number): Error {
    if (code && estateRefusalCopy[code]) return new Error(estateRefusalCopy[code]);
    return new Error(code ?? `Request refused (${status})`);
  }

  function toggle(value: string): void {
    setPlan(null);
    setRegistered(null);
    setSelection((current) => (current.includes(value) ? current.filter((item) => item !== value) : [...current, value]));
  }

  async function requestPlan(): Promise<void> {
    setBusy(true);
    setError(null);
    setPlan(null);
    setRegistered(null);
    try {
      const query = new URLSearchParams({
        customer_project_id: project.trim(),
        customer_reader_service_account: customerReader.trim(),
      });
      for (const item of selection) query.append("provider", item);
      const response = await fetch(`${apiUrl}/api/v1/connections/estate-grant-plan?${query}`, {
        credentials: "include",
      });
      const value = (await response.json().catch(() => null)) as (EstateGrantPlan & { detail?: string }) | null;
      if (!response.ok || !value?.delegation_condition_digest) throw refusal(value?.detail, response.status);
      setPlan(value);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Grant plan unavailable");
    } finally {
      setBusy(false);
    }
  }

  /** The estate a challenge authorizes, byte for byte as the API rebuilds it. */
  function estateMaterial(): string {
    const providers = [...selection].sort().join(",");
    return `estate:v1:${project.trim()}:${customerReader.trim()}:${workloadRegion.trim()}:INTERNAL:${providers}`;
  }

  /** Re-authenticate for this one estate, then come back and connect it.
   *
   *  Replaces a pasted `gcloud auth print-identity-token`, which carried no
   *  freshness, no binding to the estate, and no single use. The estate is
   *  frozen before leaving, so what returns connects what was shown rather than
   *  whatever this form holds afterwards.
   */
  async function connectEstate(): Promise<void> {
    if (!plan?.delegation_condition_digest) return;
    setBusy(true); setError(null);
    try {
      const intent: PendingEstate = {
        displayName: displayName.trim(), project: project.trim(),
        customerReader: customerReader.trim(), workloadRegion: workloadRegion.trim(),
        selection,
      };
      const started = await requestStepUp(
        apiUrl, "estate.connect", await digest(estateMaterial())
      );
      setPendingEstate(intent);
      setStepUpRequest(started);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "This connection could not be prepared");
    } finally {
      setBusy(false);
    }
  }

  async function registerAndProbe(challenge: string, intent: PendingEstate): Promise<void> {
    setBusy(true); setError(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/connections/estates`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
          ...challengeHeaders(challenge),
        },
        body: JSON.stringify({
          schema_version: 1,
          display_name: intent.displayName || `${intent.project} estate`,
          // Selectors only. The delegator identity and the delegation
          // condition are derived by the API from its own recorded reader and
          // the plan it generated; sending either from a browser would let
          // this page name who may impersonate the customer reader.
          providers: intent.selection,
          classification: "INTERNAL",
          customer_project_id: intent.project,
          customer_reader_service_account: intent.customerReader,
          workload_region: intent.workloadRegion,
          scope_decision_ref: "console/direct-gcp-onboarding",
        }),
      });
      const value = (await response.json().catch(() => null)) as { registered?: EstateOutcome[]; detail?: string } | null;
      if (!response.ok || !value?.registered) throw refusal(value?.detail, response.status);
      setRegistered(value.registered);
      onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Connection registration failed");
      throw reason;
    } finally { setBusy(false); }
  }

  // Visibility is never granted by omission: an absent catalog offers nothing
  // rather than an empty picker that would let an operator submit a blank
  // provider and read the refusal as a Solvan fault.
  if (connectable.length === 0) return null;
  if (!open) {
    return <button className="primary-button" onClick={() => setOpen(true)}>Connect an estate</button>;
  }
  return (
    <section className="card connect-flow" aria-label="Connect a customer estate">
      {stepUpRequest && <StepUpDialog apiUrl={apiUrl} request={stepUpRequest}
        onCancel={() => { setStepUpRequest(null); setPendingEstate(null); }}
        onVerified={async (challenge) => {
          if (!pendingEstate) throw new Error("The estate being verified is no longer available.");
          await registerAndProbe(challenge, pendingEstate);
          setStepUpRequest(null);
          setPendingEstate(null);
        }} />}
      <div className="section-heading">
        <div>
          <p className="eyebrow">Connect an estate</p>
          <h2>Solvan asks for grants, never for a credential</h2>
        </div>
        <button className="secondary-button" onClick={() => setOpen(false)}>Cancel</button>
      </div>
      <div className="connect-guide-link"><button className="text-button" type="button" onClick={onOpenGuide}>How to find these details and configure Google Cloud</button></div>
      <div className="connect-fields">
        <label>
          Customer read-only service account
          <input value={customerReader} onChange={(event) => { setCustomerReader(event.target.value); setPlan(null); setRegistered(null); }} placeholder="solvan-reader@your-project.iam.gserviceaccount.com" autoComplete="off" spellCheck={false} />
        </label>
        <label>
          Your Google Cloud project
          <input
            value={project}
            onChange={(event) => { setProject(event.target.value); setPlan(null); setRegistered(null); }}
            placeholder="acme-production"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label>
          Workload region
          <input
            value={workloadRegion}
            onChange={(event) => { setWorkloadRegion(event.target.value); setPlan(null); setRegistered(null); }}
            placeholder="europe-west2"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <div className="connect-posture">
          <span className="phase-name">Resulting posture</span>
          <StatusBadge
            label={postureCopy[posture].label}
            tone={postureCopy[posture].tone}
            machine={posture}
          />
        </div>
      </div>
      {/* Telemetry is a set, not a choice: an investigation reads metrics and
          logs and audit and errors and traces. Each stays its own connection
          with its own probe and expiry, so one can be revoked without losing
          the rest — only the grants are asked for once. */}
      <div className="connect-capabilities">
        <fieldset className="operation-choice">
          <legend>Telemetry this estate should expose</legend>
          {connectable.map((item) => (
            <label key={item.provider} className="choice-option">
              <input type="checkbox" name="estate-capability" value={item.provider} checked={selection.includes(item.provider)} onChange={() => toggle(item.provider)} />
              <span><strong>{item.label}</strong><span className="cell-detail">{capabilityCopy[item.provider] ?? "Read-only telemetry from this Google source."}</span></span>
            </label>
          ))}
        </fieldset>
        <p className="cell-detail">{selection.length === 0 ? "Nothing is selected, so there is nothing to grant." : `${selection.length} connection${selection.length === 1 ? "" : "s"}, one per capability, each probed on its own.`}</p>
      </div>
      <div className="connect-actions">
        <button className="primary-button" disabled={busy || selection.length === 0 || !project.trim() || !customerReader.trim() || !workloadRegion.trim()} onClick={() => void requestPlan()}>
          {busy ? "Preparing…" : "Show me the grants"}
        </button>
      </div>
      {error && <p className="inline-notice" role="alert">{error}</p>}
      {plan && (
        <div className="grant-plan">
          <p className="grant-summary">{plan.summary}</p>
          <ol className="grant-steps">
            {plan.steps.map((step) => (
              <li key={step.command}>
                <p className="grant-purpose">{step.purpose}</p>
                <pre className="grant-command"><code>{step.command}</code></pre>
              </li>
            ))}
          </ol>
          <p className="inline-notice" role="status">
            Run these once in your own project, then register the estate. Each capability becomes
            its own connection, and capability is recorded from what its probe actually observes.
          </p>
          <div className="connect-fields">
            <label>Connection display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder={`${project} estate`} /></label>
            <button className="primary-button" type="button" disabled={busy || !plan.delegation_condition_digest} onClick={() => void connectEstate()}>
              {busy ? "Verifying…" : `Register and verify ${plan.providers.length} connection${plan.providers.length === 1 ? "" : "s"}`}
            </button>
          </div>
          {registered && <div className="responsive-table">
            <table>
              <caption className="visually-hidden">Registered estate connections and their probe outcomes</caption>
              <thead><tr><th>Source</th><th>Connection</th><th>Probe</th></tr></thead>
              <tbody>{registered.map((outcome) => {
                const observed = probeOutcomeCopy[outcome.probe_result ?? outcome.probe_reason_code ?? "PROBE_UNAVAILABLE"];
                return <tr key={outcome.connection_id}>
                  <td data-label="Source">{connectable.find((item) => item.provider === outcome.provider)?.label ?? outcome.provider}</td>
                  <td data-label="Connection"><MonoChip>{outcome.connection_id}</MonoChip><span className="cell-detail">Epoch {outcome.connection_epoch}</span></td>
                  <td data-label="Probe"><StatusBadge label={observed.label} tone={observed.tone} machine={outcome.probe_result ?? outcome.probe_reason_code ?? undefined} /></td>
                </tr>;
              })}</tbody>
            </table>
          </div>}
          {registered && <p className="inline-notice" role="status">Registration is one transaction: every connection above exists, or none would. A connection reaches Ready only from what its own probe observed — refresh this page to read each one's capability matrix.</p>}
        </div>
      )}
    </section>
  );
}

function ConnectionProbeAction({ apiUrl, connection, onChanged }: { apiUrl: string; connection: TenantConnection; onChanged: () => void }): React.JSX.Element | null {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  if (connection.kind !== "GCP_NATIVE" || connection.lifecycle === "DISABLED" || connection.lifecycle === "REVOKED") return null;

  /* A bounded read-only observation, so the registry records no challenge —
     but it runs under the live session and a current ADMIN role, never a
     pasted identity token. */
  async function verify(): Promise<void> {
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/connections/${encodeURIComponent(connection.id)}:probe`, {
        method: "POST",
        credentials: "include",
        headers: { ...csrfHeaders() },
      });
      const value = (await response.json().catch(() => null)) as { result?: string; detail?: string } | null;
      if (!response.ok || !value?.result) throw new Error(value?.detail ?? `Verification refused (${response.status})`);
      setNotice(`Probe completed: ${value.result}. Capability and availability were derived from the observed result.`);
      onChanged();
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : "Verification failed");
    } finally { setBusy(false); }
  }

  return <div className="settings-actions">
    <button className="secondary-button" type="button" disabled={busy} onClick={() => void verify()}>{busy ? "Verifying…" : connection.availability === "READY" ? "Verify again" : "Verify connection"}</button>
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </div>;
}

type PendingEstate = {
  displayName: string;
  project: string;
  customerReader: string;
  workloadRegion: string;
  selection: string[];
};

export function Integrations({ integration, apiUrl, onChanged }: { integration: ConsoleSnapshot["integration"]; apiUrl: string; onChanged: () => void }): React.JSX.Element {
  // Every collection is defaulted. A projection that predates one of these
  // keys must render the rest of the page, not throw during the render that
  // reads it: this route is where an operator goes to find out why a
  // connection is failing, so it is the worst page to lose to a shape change.
  const { connections = [], actuators = [], github, providers = [] } = integration;
  const stored = connections.filter((item) => item.credential_posture === "STORED_LONG_LIVED").length;
  const [showGcpGuide, setShowGcpGuide] = useState(() => new URLSearchParams(window.location.search).get("guide") === "gcp-connection");

  function setGuide(open: boolean): void {
    const url = new URL(window.location.href);
    if (open) url.searchParams.set("guide", "gcp-connection");
    else url.searchParams.delete("guide");
    window.history.pushState({}, "", url);
    setShowGcpGuide(open);
  }

  useEffect(() => {
    const restoreGuide = () => setShowGcpGuide(new URLSearchParams(window.location.search).get("guide") === "gcp-connection");
    window.addEventListener("popstate", restoreGuide);
    return () => window.removeEventListener("popstate", restoreGuide);
  }, []);

  if (showGcpGuide) return <GcpConnectionGuide onBack={() => setGuide(false)} />;
  return (
    <>
      <PageHeader
        eyebrow="Customer estates"
        title="Integrations"
        description="Capability is observed by probe, never assumed. Credential posture is always visible."
        actions={<ConnectFlow providers={providers} onChanged={onChanged} onOpenGuide={() => setGuide(true)} />}
      />
      <section className="card">
        <div className="section-heading">
          <div><p className="eyebrow">Connections</p><h2>{connections.length} registered</h2></div>
          {stored > 0 && <StatusBadge label={`${stored} holding a stored key`} tone="warning" />}
        </div>
        {connections.length === 0 && (
          <p className="inline-notice">No estate is connected. Use <strong>Connect an estate</strong> to generate the IAM and delegation commands the customer runs in their own project; Solvan never receives a credential.</p>
        )}
        <div className="connection-grid">
          {connections.map((connection) => {
            const posture = postureCopy[connection.credential_posture];
            const missing = connection.capabilities.filter((item) => !item.available);
            return (
              <article key={connection.id} className="card connection-card">
                <div className="connection-head">
                  <div>
                    <h3>{connection.display_name}</h3>
                    <p className="connection-meta">
                      <MonoChip>{connection.provider}</MonoChip> · {connection.kind.replace("_", " ").toLowerCase()}
                    </p>
                    <p className="connection-scope">{connection.external_resource_id ? <>GCP project <MonoChip>{connection.external_resource_id}</MonoChip> · </> : null}Workload <strong>{connection.workload_region ?? "not recorded"}</strong> · Control data <strong>{connection.residency_region}</strong></p>
                  </div>
                  <StatusBadge
                    label={availabilityCopy[connection.availability].label}
                    tone={availabilityCopy[connection.availability].tone}
                    machine={connection.availability}
                  />
                </div>
                {connection.availability !== "READY" && (
                  <div className="availability-reason" role="status">
                    <p className="availability-explanation">
                      {connection.availability_explanation ?? availabilityCopy[connection.availability].fallback}
                    </p>
                    <p className="availability-next">
                      <strong>{remediationCopy[connection.availability_remediation_kind ?? "RETRY_PROBE"]}</strong>
                      {connection.availability_missing_grant ? <> — <MonoChip>{connection.availability_missing_grant}</MonoChip></> : null}
                    </p>
                    {connection.availability_reason_code ? (
                      <p className="availability-code muted">
                        <MonoChip>{connection.availability_reason_code}</MonoChip>
                        {connection.availability_receipt_ref ? <> · receipt <MonoChip>{connection.availability_receipt_ref}</MonoChip></> : null}
                      </p>
                    ) : null}
                  </div>
                )}
                <div className="posture-row">
                  <StatusBadge label={posture.label} tone={posture.tone} machine={connection.credential_posture} />
                  <span>{posture.detail}</span>
                </div>
                {/* A capability row exists only once a probe has observed one,
                    so before the first probe the header would stand over
                    nothing and read as a table that failed to load. */}
                {connection.capabilities.length === 0 ? (
                  <p className="cell-detail">No capability has been observed yet. A probe records what this connection can actually read; nothing is assumed from its configuration.</p>
                ) : (
                <div className="capability-scroll">
                <table className="capability-matrix">
                  <caption className="visually-hidden">Observed capabilities for {connection.display_name}</caption>
                  <thead><tr><th>Capability</th><th>Observed</th><th>Missing grant</th></tr></thead>
                  <tbody>
                    {connection.capabilities.map((item) => (
                      <tr key={item.capability}>
                        <td data-label="Capability"><MonoChip>{item.capability}</MonoChip></td>
                        <td data-label="Observed">
                          <StatusBadge
                            label={outcomeCopy[item.outcome].label}
                            tone={outcomeCopy[item.outcome].tone}
                            machine={item.outcome}
                          />
                        </td>
                        <td data-label="Missing grant">{item.missing_grant ? <MonoChip>{item.missing_grant}</MonoChip> : <span className="muted">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
                )}
                {connection.availability !== "READY" && (
                  <p className="inline-notice" role="status">
                    This connection has no fresh successful proof and cannot back an incident.
                  </p>
                )}
                {missing.length > 0 && connection.availability === "READY" && (
                  <p className="inline-notice" role="status">
                    {missing.length === 1 ? "1 capability is unavailable. Grant the listed role, then re-probe." : `${missing.length} capabilities are unavailable. Grant the listed roles, then re-probe.`}
                  </p>
                )}
                <ConnectionProbeAction apiUrl={apiUrl} connection={connection} onChanged={onChanged} />
              </article>
            );
          })}
        </div>
      </section>

      {integration.local_connected_development && <LocalMonitoringTest apiUrl={apiUrl} connections={connections} onChanged={onChanged} />}

      <DirectGcpAlertSourceWizard apiUrl={apiUrl} connections={connections} />

      <ProductionGraphPanel apiUrl={apiUrl} />

      <RelayOperations apiUrl={apiUrl} connections={connections} />

      <section className="card" aria-labelledby="github-release-heading">
        <div className="section-heading">
          <div>
            {/* Not "release provider": a binding is the root of three separate
                capabilities now — investigating a repository, delivering code
                changes to it, and taking part in its conversation. Only the
                middle one is a release concern, and naming the whole section
                after it made connecting a read-only repository look like a
                release decision. */}
            <p className="eyebrow">Source integration</p>
            <h2 id="github-release-heading">GitHub</h2>
          </div>
          <StatusBadge
            label={
              github.repositories.some((item) => item.status === "ACTIVE") ? "Connected"
                : github.repositories.length ? "Awaiting probe"
                : "Not connected"
            }
            tone={github.repositories.some((item) => item.status === "ACTIVE") ? "success" : github.repositories.length ? "warning" : "neutral"}
          />
        </div>
        <p className="section-note">
          Connect a repository once, then choose per repository what Solvan may do with it: investigate pull-request state, deliver code changes, or take part in its conversation. The App private key and webhook secret stay in Secret Manager; agents and browsers never receive a credential or merge authority.
        </p>
        <GitHubConnectFlow apiUrl={apiUrl} repositories={github.repositories} onChanged={onChanged} />
        <GitHubConversationPanel
          apiUrl={apiUrl}
          repositoryId={github.repositories.find((item) => item.status === "ACTIVE")?.id ?? null}
        />
        <CodeDeliveryProfileSetup apiUrl={apiUrl} repositories={github.repositories} />
        <GitHubReviewerIdentitySetup apiUrl={apiUrl} repositories={github.repositories} />
        <RepairCommandSetup apiUrl={apiUrl} repositories={github.repositories} />
        <ReleaseAuthoritySetup apiUrl={apiUrl} />
        {github.repositories.length === 0 ? (
          <p className="inline-notice" role="status">No GitHub repository binding is configured for this scope.</p>
        ) : (
          <div className="connection-grid">
            {github.repositories.map((repository) => (
              <article key={repository.id} className="card connection-card">
                <div className="connection-head">
                  <div>
                    <h3>{repository.owner}/{repository.name}</h3>
                    <p className="connection-meta"><MonoChip>{repository.id}</MonoChip> · default branch <code>{repository.default_branch}</code></p>
                  </div>
                  <StatusBadge
                    label={repository.status}
                    tone={repository.status === "ACTIVE" ? "success" : repository.status === "DEGRADED" ? "warning" : "neutral"}
                  />
                </div>
                <div className="posture-row">
                  {/* What this binding can do is the first thing an operator
                      needs, and it is a property of the allowlist rather than
                      of the integration existing. A binding that cannot open a
                      pull request cannot change anything, whatever else it
                      holds. */}
                  {repository.allowed_operations_json.some((operation) => operation === "CREATE_PULL_REQUEST" || operation === "MERGE_PULL_REQUEST") ? (
                    <StatusBadge label="Can open pull requests" tone="warning" />
                  ) : (
                    <StatusBadge label="Investigate only · cannot open pull requests" tone="provenance" />
                  )}
                  <span>{repository.last_probe_result === "SUCCEEDED" ? "Repository probe passed" : "Repository probe required"}</span>
                </div>
                <div className="capability-scroll">
                  <table className="capability-matrix">
                    <caption className="visually-hidden">GitHub operations for {repository.owner}/{repository.name}</caption>
                    <thead><tr><th>Operation</th><th>Policy</th></tr></thead>
                    <tbody>{repository.allowed_operations_json.map((operation) => <tr key={operation}><td data-label="Operation"><MonoChip>{operation}</MonoChip></td><td data-label="Policy"><StatusBadge label="Allowlisted" tone="info" /></td></tr>)}</tbody>
                  </table>
                </div>
                <p className="cell-detail">Policy {repository.policy_hash} · classification {repository.classification}</p>
              </article>
            ))}
          </div>
        )}
        <div className="section-heading integration-subheading"><div><p className="eyebrow">Pull-request lifecycle</p><h3>{github.pull_requests.length} tracked pull request{github.pull_requests.length === 1 ? "" : "s"}</h3></div></div>
        {github.pull_requests.length > 0 && <div className="responsive-table"><table><caption className="visually-hidden">GitHub pull-request lifecycle</caption><thead><tr><th>Pull request</th><th>Patch</th><th>Checks</th><th>State</th><th>Head</th></tr></thead><tbody>{github.pull_requests.map((pullRequest) => <tr key={pullRequest.id}><td data-label="Pull request"><a href={pullRequest.html_url} target="_blank" rel="noreferrer">{pullRequest.owner}/{pullRequest.name}#{pullRequest.external_number}</a><span className="cell-detail">{pullRequest.title}</span></td><td data-label="Patch"><MonoChip>{pullRequest.patch_digest}</MonoChip></td><td data-label="Checks"><StatusBadge label={pullRequest.latest_checks_state} tone={pullRequest.latest_checks_state === "PASSING" ? "success" : pullRequest.latest_checks_state === "FAILING" ? "danger" : "warning"} /></td><td data-label="State"><StatusBadge label={pullRequest.status} tone={pullRequest.status === "MERGED" ? "success" : pullRequest.status === "OPEN" ? "info" : "warning"} /></td><td data-label="Head"><MonoChip>{pullRequest.head_commit_sha.slice(0, 12)}</MonoChip></td></tr>)}</tbody></table></div>}
        {github.pull_requests.length === 0 && <p className="inline-notice" role="status">Patch artifacts remain reviewable inside Solvan until one is promoted. Promotion opens a draft pull request on a branch CI already published; Solvan never pushes a commit.</p>}
        <div className="section-heading integration-subheading"><div><p className="eyebrow">Provider evidence</p><h3>{github.operations.length} operation{github.operations.length === 1 ? "" : "s"} · {github.webhooks.length} webhook event{github.webhooks.length === 1 ? "" : "s"}</h3></div></div>
        {github.operations.length > 0 && <div className="responsive-table"><table><caption className="visually-hidden">GitHub provider operations</caption><thead><tr><th>Operation</th><th>Status</th><th>Actor</th><th>Receipt</th></tr></thead><tbody>{github.operations.slice(0, 10).map((operation) => <tr key={operation.id}><td data-label="Operation"><MonoChip>{operation.operation}</MonoChip><span className="cell-detail">{operation.id}</span></td><td data-label="Status"><StatusBadge label={operation.status} tone={operation.status === "SUCCEEDED" ? "success" : operation.status === "FAILED" || operation.status === "REJECTED" ? "danger" : "warning"} /></td><td data-label="Actor"><MonoChip>{operation.actor_principal}</MonoChip></td><td data-label="Receipt">{operation.receipt_ref ? <MonoChip>{operation.receipt_ref}</MonoChip> : <span className="muted">pending</span>}</td></tr>)}</tbody></table></div>}
        {github.webhooks.length > 0 && <p className="inline-notice" role="status">Last webhook: {github.webhooks[0].event_name}{github.webhooks[0].action ? ` · ${github.webhooks[0].action}` : ""} · {github.webhooks[0].processing_status}.</p>}
      </section>

      <section className="card">
        <div className="section-heading">
          <div><p className="eyebrow">Customer-deployed actuators</p><h2>Production capability lives here, not in Solvan</h2></div>
        </div>
        <p className="section-note">
          Solvan holds authorization. The actuator the customer deploys holds capability, bound by their own policy, budget, and kill switch.
        </p>
        {actuators.length === 0 && (
          <p className="inline-notice" role="status">
            No actuator is registered, so nothing anywhere holds production mutation capability. A customer registers one from their own estate; it is never deployed from here.
          </p>
        )}
        {actuators.length > 0 && <div className="responsive-table">
          <table>
            <thead>
              <tr><th>Principal</th><th>Host</th><th>Posture</th><th>Customer policy</th><th>Audit sink</th><th>State</th></tr>
            </thead>
            <tbody>
              {actuators.map((actuator) => {
                const host = hostCopy[actuator.host_kind];
                return (
                  <tr key={actuator.id}>
                    <td data-label="Principal"><MonoChip>{actuator.principal_email}</MonoChip></td>
                    <td data-label="Host">
                      {host.label}
                      <span className="cell-detail">{host.eligible}</span>
                    </td>
                    <td data-label="Posture">
                      <StatusBadge
                        label={actuator.posture === "REMEDIATE" ? "Remediate" : "Collector"}
                        tone={actuator.posture === "REMEDIATE" ? "warning" : "provenance"}
                        machine={actuator.posture}
                      />
                    </td>
                    <td data-label="Customer policy">
                      {actuator.policy_hash
                        ? <MonoChip>{actuator.policy_hash}</MonoChip>
                        : <StatusBadge label="Absent · refuses" tone="warning" />}
                    </td>
                    <td data-label="Audit sink">
                      {actuator.customer_audit_configured
                        ? <StatusBadge label="Dual-written" tone="success" />
                        : <span className="muted">Not configured</span>}
                    </td>
                    <td data-label="State">
                      <StatusBadge
                        label={actuator.kill_switch_engaged ? "Kill switch engaged" : actuator.status === "ACTIVE" ? "Active" : "Registered"}
                        tone={actuator.kill_switch_engaged ? "danger" : actuator.status === "ACTIVE" ? "success" : "neutral"}
                        machine={actuator.status}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>}
        {actuators.length > 0 && actuators.every((actuator) => actuator.posture === "COLLECTOR") && (
          <p className="inline-notice" role="status">
            Every registered actuator is a collector, so none holds mutation capability. Enabling it is a customer policy change, not a new deployment.
          </p>
        )}
      </section>
    </>
  );
}
