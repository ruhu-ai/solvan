import { useState } from "react";
import type { TenantConnection } from "./types";
import { LabelValue, MonoChip, StatusBadge } from "./components";
import { csrfHeaders, digest } from "./session";

/* Alert-source onboarding: proving a local monitoring pipeline end to end, and
   registering a direct GCP alert source against an already-connected estate.
   Its own module because it configures where alerts come from rather than
   whether an estate is connected at all, and specification 21 governs it
   separately from the connection surface it sits next to. */

type LocalMonitoringRule = {
  rule_id: string;
  rule_version: number;
  service_id: string;
  connection_id: string;
  connection_epoch: number;
  project_id: string;
  resource_name: string;
  signal_kind: string;
  comparator: string;
  threshold: number;
};

type LocalPipelineResult = {
  evaluated_rules: number;
  inserted_evaluations: number;
  emitted_events: number;
  inbox_claimed: number;
  inbox_completed: number;
};


export function LocalMonitoringTest({ apiUrl, connections, onChanged }: { apiUrl: string; connections: TenantConnection[]; onChanged: () => void }): React.JSX.Element {
  const eligible = connections.filter((connection) => connection.kind === "GCP_NATIVE" && connection.provider === "CLOUD_MONITORING" && connection.availability === "READY");
  const [connectionId, setConnectionId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [resourceName, setResourceName] = useState("");
  const [signalKind, setSignalKind] = useState<"HTTP_5XX_RATIO" | "HTTP_P95_LATENCY" | "SQL_CONNECTIONS">("HTTP_5XX_RATIO");
  const [comparator, setComparator] = useState<"GT" | "GTE" | "LT" | "LTE">("GT");
  const [threshold, setThreshold] = useState("0.05");
  const [sustainedWindows, setSustainedWindows] = useState("1");
  const [severity, setSeverity] = useState<"SEV1" | "SEV2" | "SEV3" | "SEV4">("SEV3");
  const [rules, setRules] = useState<LocalMonitoringRule[]>([]);
  const [result, setResult] = useState<LocalPipelineResult | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const selected = eligible.find((connection) => connection.id === connectionId);

  async function loadRules(): Promise<void> {
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/local-development/monitoring-rules`, { credentials: "include" });
      const value = (await response.json().catch(() => null)) as LocalMonitoringRule[] | { detail?: string } | null;
      if (!response.ok || !Array.isArray(value)) throw new Error(!Array.isArray(value) && value?.detail ? value.detail : `Rules unavailable (${response.status})`);
      setRules(value);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Rules unavailable"); }
    finally { setBusy(false); }
  }

  async function createRule(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null); setResult(null);
    try {
      if (!selected) throw new Error("Choose a current READY Cloud Monitoring connection.");
      const response = await fetch(`${apiUrl}/api/v1/local-development/monitoring-rules`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", ...csrfHeaders(), "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({ schema_version: 1, connection_id: selected.id, expected_connection_epoch: selected.connection_epoch, display_name: displayName.trim(), resource_name: resourceName.trim(), signal_kind: signalKind, comparator, threshold: Number(threshold), sustained_windows: Number(sustainedWindows), severity }),
      });
      const value = (await response.json().catch(() => null)) as LocalMonitoringRule & { detail?: string };
      if (!response.ok || !value.rule_id) throw new Error(value.detail ?? `Rule refused (${response.status})`);
      setNotice(`Bound ${value.rule_id}@${value.rule_version} to ${value.project_id}. It has local-development evidence only and grants no production authority.`);
      await loadRules();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Rule creation failed"); setBusy(false); }
  }

  async function runPipeline(): Promise<void> {
    setBusy(true); setNotice(null); setResult(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/local-development/pipeline:run`, { method: "POST", credentials: "include", headers: { ...csrfHeaders() } });
      const value = (await response.json().catch(() => null)) as LocalPipelineResult & { detail?: string };
      if (!response.ok || typeof value.evaluated_rules !== "number") throw new Error(value.detail ?? `Pipeline refused (${response.status})`);
      setResult(value);
      setNotice(value.emitted_events > 0 ? "A threshold breach entered the durable inbox and the incident transition completed." : "The read completed, but no new threshold breach was emitted. This is expected when the threshold does not match or the current evaluation slot was already recorded.");
      if (value.inbox_completed > 0) onChanged();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Pipeline run failed"); }
    finally { setBusy(false); }
  }

  return <section className="card" aria-labelledby="local-monitoring-test-heading">
    <div className="section-heading"><div><p className="eyebrow">Local-connected development</p><h2 id="local-monitoring-test-heading">Exercise a real GCP read and incident</h2></div><StatusBadge label="No production authority" tone="provenance" /></div>
    <p className="section-note">This local backend uses the Solvan development reader identity, impersonates only the customer reader recorded on the selected connection, stores evidence in the development bucket, and runs the normal detector and durable incident transition. It cannot mutate the target project.</p>
    <div className="settings-actions"><button className="secondary-button" type="button" disabled={busy} onClick={() => void loadRules()}>{busy ? "Working…" : "Load local monitoring rules"}</button><button className="primary-button" type="button" disabled={busy || rules.length === 0} onClick={() => void runPipeline()}>{busy ? "Running…" : "Run detector and incident pipeline"}</button></div>
    <form className="connect-form" onSubmit={(event) => void createRule(event)}>
      <h3>Bind one exact monitored resource</h3>
      <div className="form-grid">
        <label className="field-label">READY Cloud Monitoring connection<select required value={connectionId} onChange={(event) => setConnectionId(event.target.value)}><option value="">Choose a verified connection</option>{eligible.map((connection) => <option key={connection.id} value={connection.id}>{connection.display_name} · epoch {connection.connection_epoch}</option>)}</select></label>
        <label className="field-label">Display name<input required value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="Ruhu Atlas" /></label>
        <label className="field-label">Signal<select value={signalKind} onChange={(event) => setSignalKind(event.target.value as typeof signalKind)}><option value="HTTP_5XX_RATIO">Cloud Run 5xx ratio</option><option value="HTTP_P95_LATENCY">Cloud Run p95 latency</option><option value="SQL_CONNECTIONS">Cloud SQL connections</option></select></label>
        <label className="field-label">Exact resource name<input required value={resourceName} onChange={(event) => setResourceName(event.target.value)} placeholder={signalKind === "SQL_CONNECTIONS" ? "project-id:instance-name" : "cloud-run-service-name"} /></label>
        <label className="field-label">Comparator<select value={comparator} onChange={(event) => setComparator(event.target.value as typeof comparator)}><option value="GT">Greater than</option><option value="GTE">Greater than or equal</option><option value="LT">Less than</option><option value="LTE">Less than or equal</option></select></label>
        <label className="field-label">Threshold<input required type="number" step="any" value={threshold} onChange={(event) => setThreshold(event.target.value)} /></label>
        <label className="field-label">Consecutive windows<input required type="number" min="1" max="12" value={sustainedWindows} onChange={(event) => setSustainedWindows(event.target.value)} /></label>
        <label className="field-label">Severity<select value={severity} onChange={(event) => setSeverity(event.target.value as typeof severity)}><option value="SEV1">SEV1</option><option value="SEV2">SEV2</option><option value="SEV3">SEV3</option><option value="SEV4">SEV4</option></select></label>
      </div>
      <button className="secondary-button" type="submit" disabled={busy || !selected}>Create and bind local rule</button>
    </form>
    {rules.length > 0 && <div className="responsive-table"><table><caption>Local connection-bound monitoring rules</caption><thead><tr><th>Rule</th><th>Target</th><th>Condition</th></tr></thead><tbody>{rules.map((rule) => <tr key={`${rule.rule_id}@${rule.rule_version}`}><td><MonoChip>{rule.rule_id}@{rule.rule_version}</MonoChip></td><td>{rule.project_id} · {rule.resource_name}</td><td>{rule.signal_kind} {rule.comparator} {rule.threshold}</td></tr>)}</tbody></table></div>}
    {result && <div className="verification-summary"><LabelValue label="Rules evaluated" value={String(result.evaluated_rules)} /><LabelValue label="Breaches emitted" value={String(result.emitted_events)} /><LabelValue label="Inbox completed" value={`${result.inbox_completed}/${result.inbox_claimed}`} /></div>}
    {eligible.length === 0 && <p className="inline-notice">Connect and successfully probe Cloud Monitoring first. An unproven connection cannot back a detection rule.</p>}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </section>;
}

export function DirectGcpAlertSourceWizard({ apiUrl, connections }: { apiUrl: string; connections: TenantConnection[] }): React.JSX.Element {
  const eligible = connections.filter((connection) => connection.kind === "GCP_NATIVE" && connection.provider === "CLOUD_MONITORING" && connection.availability === "READY");
  const [token, setToken] = useState("");
  const [connectionId, setConnectionId] = useState("");
  const [connectionEpoch, setConnectionEpoch] = useState("1");
  const [scopingProject, setScopingProject] = useState("");
  const [topic, setTopic] = useState("");
  const [subscription, setSubscription] = useState("");
  const [pushPrincipal, setPushPrincipal] = useState("");
  const [audience, setAudience] = useState("");
  const [sourceHash, setSourceHash] = useState("");
  const [configurationDigest, setConfigurationDigest] = useState("");
  const [topicReceipt, setTopicReceipt] = useState("");
  const [tokenReceipt, setTokenReceipt] = useState("");
  const [binding, setBinding] = useState<{ source_binding_id: string; source_binding_epoch: number; status: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function createBinding(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/direct-gcp-alert-sources`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim(), "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          schema_version: 1, connection_id: connectionId, connection_epoch: Number(connectionEpoch),
          scoping_project_id: scopingProject, topic_name: topic, topic_binding_receipt_ref: topicReceipt,
          subscription_name: subscription, push_principal: pushPrincipal, oidc_audience: audience,
          source_material_hash: sourceHash, configuration_digest: configurationDigest,
          pubsub_token_minting_receipt_ref: tokenReceipt, classification: "INTERNAL",
          retention_policy_revision: "retention/alert-v1",
        }),
      });
      const value = (await response.json().catch(() => null)) as { detail?: string; source_binding_id?: string; source_binding_epoch?: number; status?: string } | null;
      if (!response.ok || !value?.source_binding_id || !value.source_binding_epoch || !value.status) throw new Error(value?.detail ?? `Source binding refused (${response.status})`);
      setBinding({ source_binding_id: value.source_binding_id, source_binding_epoch: value.source_binding_epoch, status: value.status });
      setNotice("Configuration is recorded. Apply the displayed customer Pub/Sub setup, then send the dedicated qualification delivery. No alert is admitted until that proof arrives.");
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Source binding failed."); }
    finally { setBusy(false); }
  }

  async function qualify(): Promise<void> {
    if (!binding) return;
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/direct-gcp-pilot:qualify`, {
        method: "POST", headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim() },
        body: JSON.stringify({ schema_version: 1, connection_id: connectionId, source_binding_id: binding.source_binding_id, source_binding_epoch: binding.source_binding_epoch }),
      });
      const value = (await response.json().catch(() => null)) as { detail?: string; receipt_id?: string } | null;
      if (!response.ok || !value?.receipt_id) throw new Error(value?.detail ?? `Qualification is not complete (${response.status})`);
      setNotice(`Independent qualification receipt ${value.receipt_id} was written. It expires and is superseded automatically when its bound evidence changes.`);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Qualification request failed."); }
    finally { setBusy(false); }
  }

  return <details className="card connection-card" aria-label="Direct GCP Alert Ingress setup">
    <summary><strong>Set up Cloud Monitoring Alert Ingress</strong><span className="cell-detail">Exact Pub/Sub push binding · no customer credential</span></summary>
    <p className="section-note">This records the intended source only. Run the generated IAM and Pub/Sub configuration in the customer project; Solvan never creates it or receives its credentials.</p>
    <form className="connect-form" onSubmit={(event) => void createBinding(event)}>
      <label className="field-label">Administrator identity token<input required type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer …" autoComplete="off" /></label>
      <label className="field-label">READY Cloud Monitoring connection<select required value={connectionId} onChange={(event) => setConnectionId(event.target.value)}><option value="">Choose a verified connection</option>{eligible.map((connection) => <option key={connection.id} value={connection.id}>{connection.display_name} · {connection.id}</option>)}</select></label>
      <div className="form-grid">
        <label className="field-label">Connection epoch<input required inputMode="numeric" value={connectionEpoch} onChange={(event) => setConnectionEpoch(event.target.value)} /></label>
        <label className="field-label">Scoping project<input required value={scopingProject} onChange={(event) => setScopingProject(event.target.value)} placeholder="customer-monitoring-project" /></label>
        <label className="field-label">Topic<input required value={topic} onChange={(event) => setTopic(event.target.value)} placeholder="projects/PROJECT/topics/solvan-alerts" /></label>
        <label className="field-label">Subscription<input required value={subscription} onChange={(event) => setSubscription(event.target.value)} placeholder="projects/PROJECT/subscriptions/solvan-alerts" /></label>
        <label className="field-label">Push service account<input required value={pushPrincipal} onChange={(event) => setPushPrincipal(event.target.value)} placeholder="solvan-alert-push@PROJECT.iam.gserviceaccount.com" /></label>
        <label className="field-label">OIDC audience<input required value={audience} onChange={(event) => setAudience(event.target.value)} placeholder="https://alert-ingress-…run.app" /></label>
        <label className="field-label">Source material digest<input required value={sourceHash} onChange={(event) => setSourceHash(event.target.value)} placeholder="sha256:…" /></label>
        <label className="field-label">Configuration digest<input required value={configurationDigest} onChange={(event) => setConfigurationDigest(event.target.value)} placeholder="sha256:…" /></label>
        <label className="field-label">Topic binding receipt reference<input required value={topicReceipt} onChange={(event) => setTopicReceipt(event.target.value)} placeholder="receipt://…" /></label>
        <label className="field-label">Pub/Sub token-minting receipt reference<input required value={tokenReceipt} onChange={(event) => setTokenReceipt(event.target.value)} placeholder="receipt://…" /></label>
      </div>
      <button className="primary-button" type="submit" disabled={busy || eligible.length === 0}>{busy ? "Recording…" : "Record pending source binding"}</button>
    </form>
    {binding && <div className="settings-actions"><StatusBadge label={binding.status.replaceAll("_", " ")} tone="warning" /><button className="secondary-button" type="button" disabled={busy} onClick={() => void qualify()}>Request independent qualification</button></div>}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </details>;
}


