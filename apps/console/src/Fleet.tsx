/** The Agent Fleet page: who is registered, what each seat may reach, and the one
 *  seat that can change production.
 */
import { Fragment, useEffect, useMemo, useState } from "react";
import { ChevronLeft, CircleCheck, CircleHelp, Code, Eye, FilePenLine, FileText, GitBranch, Plus, Search, X } from "lucide-react";
import type { ConsoleSnapshot, StatusTone } from "./types";
import { LabelValue, MonoChip, PageHeader, StatusBadge, platformEvidenceLabel, platformHealthLabel, platformHealthTone } from "./components";
import { AgentCatalog } from "./FleetAgents";
import { CapabilitiesView } from "./FleetCapabilities";
import { AuditView, MemoryView, SecurityView } from "./FleetGovernance";
import { SkillsInterchangePanel } from "./FleetSkills";
import { ToolsView } from "./FleetTools";
import { formatRecordedAt } from "./fleetFormat";

type FleetTab = "Agents" | "Tools" | "Skills" | "Alert policies" | "Capabilities & Policy" | "Memory" | "Security" | "Audit" | "Platform";

const fleetTabs: FleetTab[] = ["Agents", "Tools", "Skills", "Alert policies", "Capabilities & Policy", "Memory", "Security", "Audit", "Platform"];

/** The one seat that can change production, shown beside the six that cannot.
 *  It is registered and identified like an agent but carries no model, so it
 *  never takes the agent tone. */
/** The Action Actuator is a fleet seat, so it sits in the fleet grid.
 *
 *  It used to lead the page as a card headed "No model holds production
 *  mutation" with a paragraph explaining itself. The sentence was true and the
 *  placement made it an essay: an operator opening Agent Fleet is looking for
 *  who is registered and what each may reach. That claim is now structural
 *  rather than asserted — every seat states the capability it holds, and this
 *  is the only one whose capability is mutation.
 */
const slug = (item: FleetTab): string => item.toLowerCase().replaceAll(/[^a-z]+/g, "-");

export function Fleet({ fleet, apiUrl, region }: { fleet: ConsoleSnapshot["fleet"]; apiUrl: string; region: string }): React.JSX.Element {
  // The tab is URL-addressable (`?fleet=<slug>`), so an audit row, a runbook,
  // or a colleague's link can open one governance surface directly.
  const [tab, setTabState] = useState<FleetTab>(() => {
    const requested = new URLSearchParams(window.location.search).get("fleet");
    return fleetTabs.find((item) => slug(item) === requested) ?? "Agents";
  });
  const setTab = (next: FleetTab): void => {
    setTabState(next);
    const url = new URL(window.location.href);
    url.searchParams.set("fleet", slug(next));
    window.history.replaceState({}, "", url);
  };
  // The tab pattern was `role="tab"` and `aria-selected` alone: no panel
  // association and no arrow-key movement, so assistive technology could see
  // which tab was selected but not what it controlled, and a keyboard user
  // tabbed through nine buttons to reach the panel.
  const move = (index: number, step: number): void => {
    const next = fleetTabs[(index + step + fleetTabs.length) % fleetTabs.length];
    setTab(next);
    document.getElementById(`fleet-tab-${slug(next)}`)?.focus();
  };
  return <div className="agent-fleet-page"><PageHeader eyebrow="Fortified enterprise fleet" title="Agent Fleet" description="Catalog, permissions, context, security, and audit for every registered agent." /><div className="tabs fleet-tabs" role="tablist" aria-label="Agent Fleet views">{fleetTabs.map((item, index) => <button key={item} id={`fleet-tab-${slug(item)}`} role="tab" aria-selected={tab === item} aria-controls="fleet-tab-panel" tabIndex={tab === item ? 0 : -1} className={tab === item ? "tab active" : "tab"} onClick={() => setTab(item)} onKeyDown={(event) => { if (event.key === "ArrowRight") { event.preventDefault(); move(index, 1); } if (event.key === "ArrowLeft") { event.preventDefault(); move(index, -1); } }}>{item}</button>)}</div><section role="tabpanel" id="fleet-tab-panel" aria-labelledby={`fleet-tab-${slug(tab)}`} tabIndex={-1} className="tab-panel">{tab === "Agents" ? <AgentCatalog agents={fleet.agents} seats={fleet.deterministic_services} runs={fleet.agent_runs ?? []} /> : tab === "Tools" ? <ToolsView tools={fleet.tools} definitions={fleet.tool_status_definitions} /> : tab === "Skills" ? <SkillsView apiUrl={apiUrl} guidance={fleet.guidance} region={region} /> : tab === "Alert policies" ? <AlertPoliciesView apiUrl={apiUrl} triggerPolicies={fleet.trigger_policies} triggerFirings={fleet.trigger_firings} /> : tab === "Capabilities & Policy" ? <CapabilitiesView capabilities={fleet.capabilities} region={region} /> : tab === "Memory" ? <MemoryView memory={fleet.memory} /> : tab === "Security" ? <SecurityView events={fleet.security} /> : tab === "Audit" ? <AuditView events={fleet.audit} /> : <PlatformView platform={fleet.platform} />}</section></div>;
}

type AlertPolicyRow = {
  policy_key: string;
  version: string;
  mode: string;
  lifecycle: string;
  /** `ELIGIBLE` or `RETIRED` from the lifecycle head, `UNAVAILABLE` when none is
   *  current. This was compared against `"AVAILABLE"`, a value the schema never
   *  emits, so every policy in a deployment rendered as an exception. */
  availability: string;
  connection_id: string | null;
  connection_epoch: number | null;
  connection_health: string | null;
  connection_reason_code: string | null;
  connection_binding_current: boolean | null;
  approved_by_principal: string | null;
  approval_ref: string | null;
  evaluation_ref: string | null;
  current_capacity: string;
  current_capacity_reason_code: string | null;
  last_match_at: string | null;
  last_triage_at: string | null;
  suppression_count: number;
};

type AlertPolicyDetail = { schema_version: number; policy: Record<string, unknown>; connections: Array<Record<string, unknown>> };
type AlertPolicyTemplate = { template_key: string; version: string; calibration_slots: string[]; example_values_label: string; compatibility: string; lifecycle: string; creates: string };
type AlertPolicyRecommendation = { id: string; policy_key: string; predecessor_version: string; source_incident_id: string; recommendation_digest: string; rationale_values_json: Record<string, unknown>; expires_at: string; decision_epoch: number };

function AlertPoliciesView({ apiUrl, triggerPolicies, triggerFirings }: { apiUrl: string; triggerPolicies: ConsoleSnapshot["fleet"]["trigger_policies"]; triggerFirings: ConsoleSnapshot["fleet"]["trigger_firings"] }): React.JSX.Element {
  const [query, setQuery] = useState("");
  const [policies, setPolicies] = useState<AlertPolicyRow[]>([]);
  const [capacity, setCapacity] = useState<{ status: string; reason_code: string | null; active_reservations: number; limit: number } | null>(null);
  const [provenance, setProvenance] = useState<string | null>(null);
  const [selected, setSelected] = useState<AlertPolicyRow | null>(null);
  const [detail, setDetail] = useState<AlertPolicyDetail | null>(null);
  const [templates, setTemplates] = useState<AlertPolicyTemplate[]>([]);
  const [recommendations, setRecommendations] = useState<AlertPolicyRecommendation[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      fetch(`${apiUrl}/api/fleet/alert-policies`, { credentials: "include", signal: controller.signal }),
      fetch(`${apiUrl}/api/fleet/alert-capacity`, { credentials: "include", signal: controller.signal }),
      fetch(`${apiUrl}/api/fleet/alert-policy-templates`, { credentials: "include", signal: controller.signal }),
      fetch(`${apiUrl}/api/fleet/alert-policy-recommendations`, { credentials: "include", signal: controller.signal }),
    ]).then(async ([policyResponse, capacityResponse, templateResponse, recommendationResponse]) => {
      const responses = [policyResponse, capacityResponse, templateResponse, recommendationResponse];
      // A 403 is a permissions answer, not an outage; reporting both as
      // "unavailable" sent operators debugging the projection instead of
      // asking for the grant.
      if (responses.some((response) => response.status === 403)) throw new Error("Your session lacks an alert reader grant in this scope. Ask an administrator for the OPERATOR, APPROVER, or ADMIN role.");
      if (responses.some((response) => !response.ok)) throw new Error("Alert policy projection is unavailable");
      const policyPayload = await policyResponse.json() as { rows: AlertPolicyRow[]; data_status?: string };
      const capacityPayload = await capacityResponse.json() as { status: string; reason_code: string | null; active_reservations: number; limit: number };
      const templatePayload = await templateResponse.json() as { rows: AlertPolicyTemplate[] };
      const recommendationPayload = await recommendationResponse.json() as { rows: AlertPolicyRecommendation[] };
      setPolicies(policyPayload.rows); setCapacity(capacityPayload); setTemplates(templatePayload.rows); setRecommendations(recommendationPayload.rows);
      // The projection says whether it is scripted development data. Rendering
      // lifecycle, approval and source health without that qualifier presents a
      // fixture as governed state on the screen consulted to learn what is real.
      setProvenance(policyPayload.data_status ?? null); setError(null);
    }).catch((reason: unknown) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Alert policy projection is unavailable"); });
    return () => controller.abort();
  }, [apiUrl, refresh]);
  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    const controller = new AbortController();
    fetch(`${apiUrl}/api/fleet/alert-policies/${encodeURIComponent(selected.policy_key)}/revisions/${encodeURIComponent(selected.version)}`, { credentials: "include", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(`Policy detail returned ${response.status}`); return await response.json() as AlertPolicyDetail; })
      .then((payload) => { setDetail(payload); setError(null); })
      .catch((reason: unknown) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Policy detail unavailable"); });
    return () => controller.abort();
  }, [apiUrl, selected]);
  const visible = useMemo(() => { const needle = query.trim().toLowerCase(); return needle ? policies.filter((policy) => `${policy.policy_key} ${policy.lifecycle} ${policy.availability}`.toLowerCase().includes(needle)) : policies; }, [policies, query]);
  return <>
    <section className="card alert-policy-intro"><div className="section-heading"><div><p className="eyebrow">Governed alert admission</p><h2>Alert policies</h2><p>These revisions decide which verified source observations may receive bounded triage. They do not grant incident or mutation authority.</p></div><button className="secondary-button" type="button" onClick={() => setRefresh((value) => value + 1)}>Refresh</button></div>{provenance && provenance !== "LIVE" && <p className="inline-notice" role="status">Scripted development data · <code>{provenance}</code>. No lifecycle, approval, source-health or capacity fact on this page describes a deployment.</p>}<div className="alert-policy-capacity"><StatusBadge label={capacity?.status ?? "Unknown"} tone={capacity?.status === "AVAILABLE" ? "success" : "warning"} machine={capacity?.reason_code ?? undefined} /><span>{capacityLabel(capacity)}</span></div><label className="skills-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Search alert policies</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search policy, lifecycle, or availability" /></label></section>
    {error && <p className="danger-panel" role="alert">{error}</p>}
    {(templates.length > 0 || recommendations.length > 0) && <section className="alert-policy-design-aids" aria-labelledby="alert-policy-design-aids-title"><div className="section-heading"><div><p className="eyebrow">Design aids · never authority</p><h2 id="alert-policy-design-aids-title">Calibrated starts and outcome suggestions</h2><p>Templates create drafts only. Machine suggestions still require deliberate authoring, evaluation, independent approval, and activation.</p></div></div><div className="alert-policy-aid-grid">{templates.map((template) => <article className="card alert-policy-aid" key={`${template.template_key}@${template.version}`}><div className="section-heading"><div><p className="eyebrow">Policy template · {template.version}</p><h3>{template.template_key}</h3></div><StatusBadge label="Draft only" tone="info" /></div><p><strong>{template.example_values_label}</strong></p><p>{template.calibration_slots.length} required tenant calibration slots · {template.compatibility}</p><div className="alert-policy-slot-list">{template.calibration_slots.map((slot) => <MonoChip key={slot}>{slot}</MonoChip>)}</div></article>)}{recommendations.map((recommendation) => <article className="card alert-policy-aid recommendation" key={recommendation.id}><div className="section-heading"><div><p className="eyebrow">Machine-proposed · requires author review</p><h3>Review {recommendation.policy_key}</h3></div><StatusBadge label="No authority" tone="warning" /></div><p>{String(recommendation.rationale_values_json.outcome ?? "A bounded outcome pattern may justify a successor draft review.")}</p><dl><LabelValue label="Source Incident" value={recommendation.source_incident_id} /><LabelValue label="Current lineage" value={`${recommendation.policy_key}@${recommendation.predecessor_version}`} /><LabelValue label="Expires" value={new Date(recommendation.expires_at).toLocaleString()} /></dl></article>)}</div></section>}
    <div className="alert-policy-grid">{visible.map((policy) => {
      const admission = policyAdmission(policy);
      return <button className={`card alert-policy-card ${selected?.policy_key === policy.policy_key && selected.version === policy.version ? "selected" : ""}`} type="button" key={`${policy.policy_key}@${policy.version}`} onClick={() => setSelected(policy)}>
        <div className="section-heading"><div><p className="eyebrow">Revision {policy.version}</p><h3>{policy.policy_key}</h3></div><StatusBadge label={admission.label} tone={admission.tone} machine={`${policy.lifecycle} · ${policy.availability} · ${policy.current_capacity}`} /></div>
        <p className="alert-policy-mode">{policyModeLabel(policy.mode)}</p>
        <div className="alert-policy-status-row"><StatusBadge label={policy.lifecycle} tone={policy.lifecycle === "APPROVED" ? "info" : "neutral"} /><span>{sourceHealthLabel(policy)}</span></div>
        {admission.blocker && <div className="platform-next-step"><strong>Blocked by</strong><span>{admission.blocker}</span></div>}
        <dl className="tool-facts"><LabelValue label="Last matched" value={formatPolicyTime(policy.last_match_at)} /><LabelValue label="Last triaged" value={formatPolicyTime(policy.last_triage_at)} /><LabelValue label="Suppressed" value={String(policy.suppression_count)} /><LabelValue label="Approved by" value={policy.approved_by_principal ?? "Not approved"} /></dl>
      </button>;
    })}</div>
    {policies.length > 0 && visible.length === 0 && <div className="card skills-empty-state"><Search size={20} /><strong>No alert policies match this search.</strong></div>}
    {!error && policies.length === 0 && <div className="card skills-empty-state"><strong>No alert policy exists in this scope.</strong><span>Create a draft from a calibrated template above; deliberate authoring, evaluation, and independent approval still gate admission.</span></div>}
    <section className="card guidance-trigger-summary"><div className="section-heading"><div><p className="eyebrow">Durable triggers</p><h2>Trigger policy ledger</h2><p>Triggers enqueue coordinator work; they never invoke an Agent directly.</p></div><StatusBadge label={`${triggerPolicies.length} policies · ${triggerFirings.length} firings`} tone="neutral" /></div>
      {triggerPolicies.length === 0
        ? <p className="inline-notice">No trigger policy is approved in this scope.</p>
        : <div className="responsive-table"><table><caption>Trigger policy revisions</caption><thead><tr><th scope="col">Policy</th><th scope="col">Kind</th><th scope="col">Lifecycle</th><th scope="col">Guidance</th><th scope="col">Region</th></tr></thead><tbody>{triggerPolicies.map((policy, index) => <tr key={`${String(policy.policy_key)}@${String(policy.version)}-${index}`}><td data-label="Policy"><code>{String(policy.policy_key)}@{String(policy.version)}</code></td><td data-label="Kind">{String(policy.trigger_kind ?? "—")}</td><td data-label="Lifecycle">{String(policy.lifecycle ?? "—")}</td><td data-label="Guidance">{policy.guidance_key ? <code>{String(policy.guidance_key)}@{String(policy.guidance_version ?? "")}</code> : "—"}</td><td data-label="Region">{String(policy.region ?? "—")}</td></tr>)}</tbody></table></div>}
      {triggerFirings.length > 0 && <div className="responsive-table"><table><caption>Recent trigger firings</caption><thead><tr><th scope="col">Firing</th><th scope="col">Policy</th><th scope="col">Status</th><th scope="col">Due</th><th scope="col">Decision reason</th></tr></thead><tbody>{triggerFirings.map((firing, index) => <tr key={`${String(firing.id)}-${index}`}><td data-label="Firing"><code>{String(firing.id)}</code></td><td data-label="Policy"><code>{String(firing.policy_key)}@{String(firing.policy_version ?? "")}</code></td><td data-label="Status">{String(firing.status ?? "—")}</td><td data-label="Due">{firing.due_at ? new Date(String(firing.due_at)).toLocaleString() : "—"}</td><td data-label="Decision reason">{String(firing.decision_reason ?? "—")}</td></tr>)}</tbody></table></div>}
    </section>
    {selected && <section className="card alert-policy-detail"><div className="section-heading"><div><p className="eyebrow">Pinned policy revision</p><h2>{selected.policy_key}@{selected.version}</h2><p>Lifecycle, source health, policy digest, admission mode, budgets, predicates, and evidence are shown separately.</p></div><button className="icon-button" type="button" aria-label="Close policy detail" onClick={() => setSelected(null)}><X size={18} /></button></div>{detail ? <><dl className="skill-detail-facts">{Object.entries(detail.policy).filter(([key]) => !key.endsWith("_json")).slice(0, 18).map(([key, value]) => <LabelValue key={key} label={key.replaceAll("_", " ")} value={formatPolicyValue(value)} />)}</dl><div className="alert-policy-connections"><h3>Eligible source connections</h3>{detail.connections.length ? detail.connections.map((connection, index) => <div className="platform-next-step" key={String(connection.connection_id ?? index)}><strong>{String(connection.connection_id ?? "Connection")}</strong><span>{String(connection.health ?? "UNKNOWN")} · epoch {String(connection.connection_epoch ?? "—")} · {String(connection.reason_code ?? "no current reason")}</span></div>) : <p className="inline-notice">No enabled, exact-provider source connection is currently bound.</p>}</div><AlertPolicySimulationPanel apiUrl={apiUrl} policy={detail.policy} fallbackKey={selected.policy_key} fallbackVersion={selected.version} /></> : <p aria-busy="true">Loading pinned policy evidence…</p>}</section>}
  </>;
}

function AlertPolicySimulationPanel({ apiUrl, policy, fallbackKey, fallbackVersion }: { apiUrl: string; policy: Record<string, unknown>; fallbackKey: string; fallbackVersion: string }): React.JSX.Element {
  const [sampleId, setSampleId] = useState("");
  const [sampleDigest, setSampleDigest] = useState("");
  const [identityToken, setIdentityToken] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const draftDigest = String(policy.policy_hash ?? "");
  const run = async (): Promise<void> => {
    setBusy(true); setResult(null);
    try {
      const response = await fetch(`${apiUrl}/api/fleet/alert-policy-simulations`, { method: "POST", headers: { "content-type": "application/json", "X-Solvan-Approval-Token": identityToken }, body: JSON.stringify({ schema_version: 1, draft_policy_key: String(policy.policy_key ?? fallbackKey), draft_version: String(policy.policy_version ?? fallbackVersion), sample_provider_generation_id: sampleId, expected_draft_digest: draftDigest, expected_sample_digest: sampleDigest, idempotency_key: crypto.randomUUID() }) });
      const payload = await response.json() as { result?: string; detail?: string };
      if (!response.ok) throw new Error(payload.detail ?? `Simulation refused (${response.status})`);
      setResult(`HYPOTHETICAL — NO WORKFLOW EFFECT · ${(payload.result ?? "UNKNOWN").replaceAll("_", " ").toLowerCase()}`);
    } catch (cause) { setResult(cause instanceof Error ? cause.message : "Simulation refused"); }
    finally { setBusy(false); }
  };
  return <details className="alert-policy-simulation"><summary>Test a draft against an authorized historical sample</summary><p>A simulation writes an audit receipt but cannot open an Incident, approve this revision, or change the active policy.</p><div className="alert-policy-simulation-fields"><label>Provider generation ID<input value={sampleId} onChange={(event) => setSampleId(event.target.value)} placeholder="alg_…" /></label><label>Exact sample digest<input value={sampleDigest} onChange={(event) => setSampleDigest(event.target.value)} placeholder="sha256:…" /></label><label>One-time author token<input type="password" autoComplete="off" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} /></label></div><button className="secondary-button" type="button" disabled={busy || !sampleId || !sampleDigest || !identityToken || !draftDigest} onClick={() => void run()}>{busy ? "Evaluating…" : "Run hypothetical simulation"}</button>{result && <p className="inline-notice" role="status">{result}</p>}</details>;
}

function formatPolicyTime(value: string | null): string { return value ? new Date(value).toLocaleString() : "Never"; }
function formatPolicyValue(value: unknown): string { if (value === null || value === undefined) return "Not recorded"; if (typeof value === "object") return JSON.stringify(value); return String(value); }

/** Capacity is a ceiling or it is absent; an absent one is never rendered as zero. */
function capacityLabel(capacity: { status: string; reason_code: string | null; active_reservations: number; limit: number } | null): string {
  if (!capacity) return "Capacity evidence loading";
  if (capacity.status === "UNAVAILABLE") return "No active quota policy resolves a model-request ceiling";
  return `${capacity.active_reservations} of ${capacity.limit} model-request reservations active`;
}

/** What the policy does, in the operator's words rather than the schema's. */
function policyModeLabel(mode: string): string {
  if (mode === "TRIAGE") return "Investigate only · never opens an Incident";
  if (mode === "POLICY_ESCALATED") return "Investigate, then escalate by rule";
  if (mode === "FULL_INCIDENT") return "Open an Incident on admission";
  return mode.replaceAll("_", " ").toLowerCase();
}

function sourceHealthLabel(policy: AlertPolicyRow): string {
  if (!policy.connection_health) return "No source connection is bound";
  if (policy.connection_binding_current === false) return `Source ${policy.connection_health.toLowerCase()} · binding superseded`;
  return `Source ${policy.connection_health.toLowerCase()}`;
}

/** Restate the conjunction the admission path enforces, from committed fields.
 *
 *  The card previously asserted "Approved policy head and current source
 *  conditions are eligible" from the availability string alone — a causal claim
 *  about admission with no predicate behind it, written here rather than
 *  derived from a record. Each clause below names the exact field that refuses,
 *  and nothing is claimed when every field is silent.
 */
function policyAdmission(policy: AlertPolicyRow): { label: string; tone: StatusTone; blocker: string | null } {
  if (policy.lifecycle !== "APPROVED") return { label: "Not admitting", tone: "neutral", blocker: "This revision is not approved. Independent evaluation and approval are still required." };
  if (policy.availability !== "ELIGIBLE") return { label: "Not admitting", tone: "warning", blocker: policy.availability === "RETIRED" ? "This revision is retired." : "No current lifecycle head marks this revision eligible." };
  if (!policy.connection_id) return { label: "Not admitting", tone: "warning", blocker: "No source connection is bound to this revision." };
  if (policy.connection_binding_current === false) return { label: "Not admitting", tone: "warning", blocker: `The bound connection is at a superseded epoch (${policy.connection_epoch}); admission fences on the bound epoch.` };
  if (policy.connection_health !== "READY") return { label: "Not admitting", tone: "warning", blocker: `The bound source connection is ${String(policy.connection_health).toLowerCase()}${policy.connection_reason_code ? ` (${policy.connection_reason_code})` : ""}.` };
  if (policy.current_capacity !== "AVAILABLE") return { label: "Waiting on capacity", tone: "warning", blocker: policy.current_capacity_reason_code ?? "Model-request capacity is not available." };
  return { label: "Admitting", tone: "success", blocker: null };
}

type SkillItem = ConsoleSnapshot["fleet"]["guidance"][number];

function skillGroupTitle(item: SkillItem): string {
  if (item.source_kind === "IMPORTED" || item.source_kind === "CUSTOMER_AUTHORED") return "Imported · quarantine to approval";
  const slug = item.key.split(".")[0];
  if (slug === "reliability") return "Reliability triage flows";
  if (slug === "platform") return "Platform lookups";
  if (slug === "payments") return "Payments workload knowledge";
  if (slug === "reporting") return "Reporting templates";
  return item.owner;
}

function skillIsActive(item: SkillItem): boolean {
  return item.lifecycle === "Approved" && item.availability === "Available";
}

function skillException(item: SkillItem): { label: string; tone: "success" | "warning" | "danger" | "neutral" } | null {
  if (item.lifecycle !== "Approved") return { label: item.lifecycle, tone: lifecycleTone(item.lifecycle) };
  if (item.availability !== "Available") return { label: "Not selectable here", tone: "neutral" };
  return null;
}

function SkillsView({ apiUrl, guidance, region }: { apiUrl: string; guidance: ConsoleSnapshot["fleet"]["guidance"]; region: string }): React.JSX.Element {
  const [query, setQuery] = useState("");
  const [attention, setAttention] = useState<"ALL" | "ACTIVE" | "ATTENTION">("ALL");
  const [selected, setSelected] = useState<SkillItem | null>(null);
  const [showImport, setShowImport] = useState(false);
  const filtered = guidance.filter((item) => {
    const haystack = `${item.name} ${item.key} ${item.owner} ${item.source_ref} ${item.description}`.toLowerCase();
    const matchesQuery = !query.trim() || haystack.includes(query.trim().toLowerCase());
    const matchesAttention = attention === "ALL" || (attention === "ACTIVE" ? skillIsActive(item) : !skillIsActive(item));
    return matchesQuery && matchesAttention;
  });
  const groups: Array<{ title: string; items: SkillItem[] }> = [];
  for (const item of filtered) {
    const title = skillGroupTitle(item);
    const group = groups.find((candidate) => candidate.title === title);
    if (group) group.items.push(item);
    else groups.push({ title, items: [item] });
  }
  if (selected) {
    return <SkillDetail
      apiUrl={apiUrl}
      item={selected}
      onClose={() => setSelected(null)}
      onOpenImport={() => { setSelected(null); setShowImport(true); }}
    />;
  }
  return <>
    <section className="card skills-catalog-shell" aria-labelledby="skills-catalog-title">
      <div className="section-heading skills-catalog-heading"><div><p className="eyebrow">Reusable operational knowledge</p><h2 id="skills-catalog-title">Skills</h2><p>Skills are data, never authority.</p></div><button className="button primary" type="button" onClick={() => setShowImport((value) => !value)}><Plus size={17} strokeWidth={2} /> {showImport ? "Close import" : "Add / import skill"}</button></div>
      <div className="skills-catalog-toolbar" role="search"><label className="skills-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Search skills</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search skills, owners, or sources" /></label><div className="skills-attention-filter" role="group" aria-label="Filter skills">{([["ALL", "All"], ["ACTIVE", "Active"], ["ATTENTION", "Needs attention"]] as const).map(([value, label]) => <button key={value} type="button" aria-pressed={attention === value} className={attention === value ? "active" : ""} onClick={() => setAttention(value)}>{label}</button>)}</div></div>
      <p className="skills-result-count" role="status">{filtered.length} {filtered.length === 1 ? "skill" : "skills"}</p>
    </section>
    {groups.length > 0 ? groups.map((group) => <section key={group.title} className="skills-group" aria-label={group.title}>
      <h3 className="skills-group-title">{group.title}</h3>
      <div className="skills-catalog-grid">
        {group.items.map((item) => {
          const exception = skillException(item);
          return <button className="card skill-card" type="button" key={`${item.key}@${item.version}`} onClick={() => setSelected(item)}>
            <div className="skill-card-heading"><span className="skill-source-icon" aria-hidden="true">{item.source_kind === "IMPORTED" ? <GitBranch size={19} strokeWidth={1.75} /> : <FilePenLine size={19} strokeWidth={1.75} />}</span><div><h3>{item.name}</h3></div>{exception && <StatusBadge label={exception.label} tone={exception.tone} />}</div>
            <p className="skill-card-description">{item.description}</p>
          </button>;
        })}
      </div>
    </section>)
      : <div className="card skills-empty-state"><Search size={20} /><strong>No skills match these filters.</strong><span>Clear a filter or import a governed skill into quarantine.</span></div>}
    {showImport && <SkillsInterchangePanel apiUrl={apiUrl} region={region} />}
  </>;
}

function sourceLabel(source: string): string { return source === "IMPORTED" ? "Imported repository" : source === "CUSTOMER_AUTHORED" ? "Customer authored" : "Solvan authored"; }
function lifecycleTone(lifecycle: string): "success" | "warning" | "danger" | "neutral" { return lifecycle === "Approved" ? "success" : lifecycle === "In review" ? "warning" : lifecycle === "Deprecated" || lifecycle === "Retired" ? "danger" : "neutral"; }

type PackFile = { name: string; content: string };

function renderSkillMarkdown(content: string): React.JSX.Element[] {
  const body = content.startsWith("---\n") ? content.split("---\n").slice(2).join("---\n") : content;
  const blocks: React.JSX.Element[] = [];
  let list: string[] = [];
  let ordered = false;
  let key = 0;
  const flush = () => {
    if (!list.length) return;
    const items = list.map((entry, index) => <li key={index}>{renderInline(entry)}</li>);
    blocks.push(ordered ? <ol key={key++}>{items}</ol> : <ul key={key++}>{items}</ul>);
    list = [];
  };
  const renderInline = (text: string): React.ReactNode[] =>
    text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean).map((part, index) => {
      if (part.startsWith("**") && part.endsWith("**")) return <strong key={index}>{part.slice(2, -2)}</strong>;
      if (part.startsWith("`") && part.endsWith("`")) return <code key={index}>{part.slice(1, -1)}</code>;
      return <Fragment key={index}>{part}</Fragment>;
    });
  let paragraph: string[] = [];
  const flushParagraph = () => {
    if (!paragraph.length) return;
    blocks.push(<p key={key++}>{renderInline(paragraph.join(" "))}</p>);
    paragraph = [];
  };
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    const heading = /^(#{1,4})\s+(.*)$/.exec(trimmed);
    const bullet = /^[-*]\s+(.*)$/.exec(trimmed);
    const numbered = /^\d+\.\s+(.*)$/.exec(trimmed);
    if (heading) {
      flush(); flushParagraph();
      const level = heading[1].length;
      blocks.push(level <= 2 ? <h4 key={key++}>{renderInline(heading[2])}</h4> : <h5 key={key++}>{renderInline(heading[2])}</h5>);
    } else if (bullet) {
      flushParagraph();
      if (ordered) flush();
      ordered = false; list.push(bullet[1]);
    } else if (numbered) {
      flushParagraph();
      if (!ordered) flush();
      ordered = true; list.push(numbered[1]);
    } else if (!trimmed) {
      flush(); flushParagraph();
    } else {
      paragraph.push(trimmed);
    }
  }
  flush(); flushParagraph();
  return blocks;
}

function SkillContentViewer({ apiUrl, item }: { apiUrl: string; item: ConsoleSnapshot["fleet"]["guidance"][number] }): React.JSX.Element {
  const [files, setFiles] = useState<PackFile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState("SKILL.md");
  const [mode, setMode] = useState<"rendered" | "source">("rendered");
  useEffect(() => {
    const controller = new AbortController();
    setFiles(null); setError(null); setActive("SKILL.md"); setMode("rendered");
    fetch(`${apiUrl}/api/fleet/guidance/${encodeURIComponent(item.key)}/revisions/${encodeURIComponent(item.version)}/content`, { credentials: "include", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(`Content returned ${response.status}`); return await response.json() as { files: PackFile[] }; })
      .then((payload) => setFiles(payload.files))
      .catch((reason: unknown) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Content unavailable"); });
    return () => controller.abort();
  }, [apiUrl, item.key, item.version]);
  if (error) return <p className="inline-notice">Pack content is unavailable here: {error}</p>;
  if (!files) return <p aria-busy="true">Loading pack content…</p>;
  const current = files.find((file) => file.name === active) ?? files[0];
  const markdown = current.name.endsWith(".md");
  return <div className="skill-content-viewer">
    <div className="skill-content-files" role="tablist" aria-label="Pack files">
      {files.map((file) => <button key={file.name} type="button" role="tab" aria-selected={file.name === current.name} className={file.name === current.name ? "active" : ""} onClick={() => setActive(file.name)}><FileText size={14} aria-hidden="true" /> {file.name}</button>)}
    </div>
    <div className="skill-content-pane">
      <div className="skill-content-toolbar" role="group" aria-label="Content view mode">
        <button type="button" aria-label="Rendered view" aria-pressed={mode === "rendered"} className={mode === "rendered" ? "active" : ""} disabled={!markdown} onClick={() => setMode("rendered")}><Eye size={15} /></button>
        <button type="button" aria-label="Source view" aria-pressed={mode === "source"} className={mode === "source" ? "active" : ""} onClick={() => setMode("source")}><Code size={15} /></button>
      </div>
      {mode === "rendered" && markdown
        ? <div className="skill-content-rendered">{renderSkillMarkdown(current.content)}</div>
        : <pre className="skill-content-source">{current.content.split("\n").map((line, index) => <span key={index} className="skill-source-line">{line}{"\n"}</span>)}</pre>}
    </div>
  </div>;
}

function SkillDetail({ apiUrl, item, onClose, onOpenImport }: { apiUrl: string; item: ConsoleSnapshot["fleet"]["guidance"][number]; onClose: () => void; onOpenImport: () => void }): React.JSX.Element {
  return <section className="card skill-detail skill-detail-page" aria-labelledby="skill-detail-title"><button className="skill-detail-back" type="button" onClick={onClose}><ChevronLeft size={17} aria-hidden="true" /> Back to skills</button><div className="section-heading"><div><p className="eyebrow">Skill detail · {item.key}@{item.version}</p><h2 id="skill-detail-title">{item.name}</h2><p>{item.description}</p></div></div><div className="skill-detail-status"><StatusBadge label={item.lifecycle} tone={lifecycleTone(item.lifecycle)} /><StatusBadge label={item.availability} tone={item.availability === "Available" ? "success" : "neutral"} /><StatusBadge label={item.evidence} tone={item.evidence === "Evaluated" ? "info" : "neutral"} /></div><dl className="skill-detail-facts"><LabelValue label="Usable by" value={item.agent_keys.join(", ")} /><LabelValue label="Region" value={item.regions.join(", ")} /></dl>{item.source_kind === "SOLVAN_AUTHORED" ? <SkillContentViewer apiUrl={apiUrl} item={item} /> : <p className="inline-notice">Imported content stays in the quarantine store; it becomes readable here after compile, evaluation, and approval.</p>}{item.source_kind === "SOLVAN_AUTHORED" ? <p className="inline-notice">Built into Solvan and published at a pinned release. It changes only with an application release.</p> : <div className="dialog-actions"><button className="secondary-button" type="button" onClick={onOpenImport}>Open lifecycle controls</button></div>}<details className="skill-detail-provenance"><summary>Provenance and governance</summary><dl className="skill-detail-facts"><LabelValue label="Source" value={item.source_ref} /><LabelValue label="Source type" value={sourceLabel(item.source_kind)} /><LabelValue label="Owner / author" value={`${item.owner} · ${item.author_principal}`} /><LabelValue label="Recorded" value={formatRecordedAt(item.recorded_at)} /><LabelValue label="Classification" value={item.classification} /><LabelValue label="Revision digest" value={item.revision_hash} /></dl><p>{item.why} Selection still requires exact scope, region, purpose, profile, and coordinator revalidation.</p></details></section>;
}

/** What a component's state means for running production work.
 *
 *  Health and lifecycle were shown as independent axes and were in fact
 *  perfectly correlated, while evidence was identical on every card — three
 *  columns carrying one fact. Worse, four components read "Healthy" while
 *  nothing was deployed, because health was computed from local checks. On a
 *  readiness screen "Healthy" is read as "this works".
 *
 *  Readiness is therefore derived from where a component was actually verified.
 *  Health only becomes the headline once there is a cloud receipt to have an
 *  opinion about; before that, the health of an undeployed component is not a
 *  fact about production. */
function platformReadiness(item: ConsoleSnapshot["fleet"]["platform"][number]): {
  label: string;
  tone: StatusTone;
  ready: boolean;
} {
  if (item.evidence === "CLOUD_VERIFIED") {
    if (item.health === "HEALTHY") return { label: "Verified in cloud", tone: "success", ready: true };
    if (item.health === "DEGRADED") return { label: "Degraded in cloud", tone: "warning", ready: false };
    if (item.health === "BLOCKED") return { label: "Blocked in cloud", tone: "danger", ready: false };
    return { label: "Deployed · state unknown", tone: "neutral", ready: false };
  }
  if (item.evidence === "UNVERIFIED") return { label: "Not verified", tone: "neutral", ready: false };
  if (item.lifecycle.toLowerCase().includes("planned")) {
    return { label: "Specified only", tone: "neutral", ready: false };
  }
  return { label: "Built · not deployed", tone: "info", ready: false };
}

function PlatformView({ platform }: { platform: ConsoleSnapshot["fleet"]["platform"] }): React.JSX.Element {
  const readiness = platform.map((item) => ({ item, state: platformReadiness(item) }));
  const verified = readiness.filter((row) => row.state.ready).length;
  const blocked = readiness.filter((row) => row.state.tone === "danger").length;
  return <>
    <section className="card platform-summary" aria-labelledby="platform-summary-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Platform readiness</p>
          <h2 id="platform-summary-title">{verified} of {platform.length} components verified in the cloud</h2>
          <p>{verified === platform.length
            ? "Every component has a bound cloud receipt."
            : "A component is ready when a cloud receipt binds it. Local checks prove the contract, not the deployment."}</p>
        </div>
        <StatusBadge
          label={verified === platform.length ? "Release ready" : "Not release ready"}
          tone={verified === platform.length ? "success" : blocked > 0 ? "danger" : "warning"}
          machine={`${verified}/${platform.length} CLOUD_VERIFIED`}
        />
      </div>
    </section>
    <section className="card" aria-labelledby="platform-reading-guide-title">
      <div className="section-heading"><div><p className="eyebrow">Reading guide</p><h2 id="platform-reading-guide-title">How to read platform status</h2></div></div>
      <div className="tool-status-legend">
        <div><strong>Lifecycle</strong><span>How far a component has progressed: planned, implemented, provisioned, deployed. It says what exists, not whether it works.</span></div>
        <div><strong>Derived health</strong><span>Healthy, degraded, blocked, or unknown — always computed from checks. The console never offers a manual “mark healthy”.</span></div>
        <div><strong>Evidence scope</strong><span>Where the proof was captured. A local check proves the contract on this machine; only a cloud receipt proves the deployment, and local evidence is never presented as cloud proof.</span></div>
      </div>
    </section>
    <div className="platform-detail-grid">
      {readiness.map(({ item, state }) => <article className="card platform-health-card" key={item.name}>
        <div className="platform-card-title">
          <span className={`platform-icon platform-icon-${state.tone}`} aria-hidden="true">
            {state.ready ? <CircleCheck size={18} strokeWidth={1.75} /> : <CircleHelp size={18} strokeWidth={1.75} />}
          </span>
          <h2>{item.name}</h2>
          <StatusBadge label={state.label} tone={state.tone} machine={`${item.health} · ${item.evidence}`} />
        </div>
        <p>{item.detail}</p>
        <div className="platform-next-step"><strong>Next safe step</strong><span>{item.next_step}</span></div>
        <details className="platform-provenance">
          <summary>How this was determined</summary>
          <dl className="platform-health-facts">
            <div><dt>Lifecycle</dt><dd>{item.lifecycle}</dd></div>
            <div><dt>Verified at</dt><dd>{platformEvidenceLabel(item.evidence)}</dd></div>
            <div><dt>Last check</dt><dd>{item.last_checked}</dd></div>
          </dl>
        </details>
      </article>)}
    </div>
  </>;
}
