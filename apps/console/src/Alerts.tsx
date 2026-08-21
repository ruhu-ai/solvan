import { useDeferredValue, useEffect, useRef, useState } from "react";
import { ArrowLeft, BellRing, ChevronRight, Copy, MessageSquareText, RefreshCw, Search, X } from "lucide-react";
import { AskRail } from "./Ask";
import { MonoChip, PageHeader, StatusBadge } from "./components";
import type { StatusTone } from "./types";

type AlertRow = {
  alert_episode_id: string;
  row_version: number;
  title: string;
  target: string;
  severity: "SEV1" | "SEV2" | "SEV3" | "SEV4";
  source_provider: string;
  provider_state: "OPEN" | "CLOSED";
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  investigation_state: string;
  disposition: string | null;
  reason_code: string | null;
  required_human_attention: boolean;
  next_action: string;
  incident: { id: string; display_id: string } | null;
  policy: string;
  mode: string;
  mode_label: string;
  mode_explanation: string;
};

type AlertListProjection = {
  counts: Record<"ACTIVE" | "NEEDS_REVIEW" | "INVESTIGATING" | "ALL", number>;
  rows: AlertRow[];
  next_cursor?: string | null;
  freshness_at: string;
  data_status?: string;
};

type ReportSection = {
  section_id: "WHAT_HAPPENED" | "IMPACT" | "LIKELY_CAUSE" | "KEY_EVIDENCE" | "NEXT_STEP";
  ordinal: number;
  status: string;
  claims: Array<{
    claim_template_id: string;
    typed_values: Record<string, unknown>;
    source_status_kind: string;
    citation_refs: string[];
  }>;
  holding_template_id: string | null;
};

type AlertReport = {
  alert_episode_id: string;
  row_version: number;
  header: AlertRow;
  sections: ReportSection[];
  technical_disclosures: Array<{ kind: string; count: number }>;
  primary_control: { kind: string; episode_id?: string; incident_id?: string; expected_row_version?: number } | null;
  secondary_controls: string[];
  decision_explanation: {
    kind: "COMMITTED_DECISION";
    disposition_ref: string | null;
    policy_key: string;
    policy_version: string;
    policy_digest: string;
    operator_mode_label: string;
    machine_mode: string;
    result: string;
    status: string;
    summary_template_id: string | null;
    typed_values: Record<string, unknown>;
    expression_digest: string | null;
    authorized_node_result_refs: string[];
    authorized_input_refs: string[];
    holding_template_id: string | null;
  };
};

const viewLabels = {
  ACTIVE: "Active",
  NEEDS_REVIEW: "Needs review",
  INVESTIGATING: "Investigating",
  ALL: "All",
} as const;
type AlertView = keyof typeof viewLabels;

const sectionLabels: Record<ReportSection["section_id"], string> = {
  WHAT_HAPPENED: "What happened",
  IMPACT: "Impact",
  LIKELY_CAUSE: "Likely cause",
  KEY_EVIDENCE: "Key evidence",
  NEXT_STEP: "Recommended next step",
};

export function Alerts({ apiUrl, authority, onOpenIncident, initialAlertId = null, onInitialAlertConsumed }: { apiUrl: string; authority: string; onOpenIncident: (incidentId: string) => void; initialAlertId?: string | null; onInitialAlertConsumed?: () => void }): React.JSX.Element {
  const [view, setView] = useState<AlertView>("ACTIVE");
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [projection, setProjection] = useState<AlertListProjection | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [report, setReport] = useState<AlertReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [detailRefresh, setDetailRefresh] = useState(0);
  const requestGeneration = useRef(0);

  useEffect(() => {
    if (!initialAlertId) return;
    setSelected(initialAlertId);
    onInitialAlertConsumed?.();
  }, [initialAlertId, onInitialAlertConsumed]);

  useEffect(() => {
    requestGeneration.current += 1;
    const controller = new AbortController();
    const encodedFilter = encodeAlertFilter(view, deferredQuery);
    fetch(`${apiUrl}/api/alerts?filter=${encodeURIComponent(encodedFilter)}`, { credentials: "include", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Alerts API returned ${response.status}`);
        return await response.json() as AlertListProjection;
      })
      .then((value) => { setProjection(value); setError(null); })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Alert queue unavailable");
      });
    return () => controller.abort();
  }, [apiUrl, deferredQuery, refresh, view]);

  useEffect(() => {
    if (!selected) { setReport(null); return; }
    const controller = new AbortController();
    fetch(`${apiUrl}/api/alerts/${selected}`, { credentials: "include", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Alert report API returned ${response.status}`);
        return await response.json() as AlertReport;
      })
      .then((value) => { setReport(value); setError(null); })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Alert report unavailable");
      });
    return () => controller.abort();
  }, [apiUrl, detailRefresh, selected]);

  const rows = projection?.rows ?? [];
  const loadMore = async (): Promise<void> => {
    if (!projection?.next_cursor || loadingMore) return;
    const generation = requestGeneration.current;
    setLoadingMore(true);
    try {
      const encodedFilter = encodeAlertFilter(view, deferredQuery);
      const response = await fetch(`${apiUrl}/api/alerts?filter=${encodeURIComponent(encodedFilter)}&cursor=${encodeURIComponent(projection.next_cursor)}`, { credentials: "include" });
      if (!response.ok) throw new Error(`Alerts API returned ${response.status}`);
      const page = await response.json() as AlertListProjection;
      if (generation !== requestGeneration.current) return;
      setProjection((current) => current ? { ...page, rows: [...current.rows, ...page.rows] } : page);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "More alerts could not be loaded");
    } finally { setLoadingMore(false); }
  };

  if (selected) {
    return <AlertDetail report={report} error={error} apiUrl={apiUrl} authority={authority} onOpenIncident={onOpenIncident} onChanged={() => { setDetailRefresh((value) => value + 1); setRefresh((value) => value + 1); }} onBack={() => setSelected(null)} />;
  }

  return <section className="alerts-page">
    <PageHeader eyebrow="Alert triage" title="Alerts" description="Verified source observations are investigated here before they become Incidents." actions={<button className="secondary-button" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={15} aria-hidden="true" /> Refresh</button>} />
    {error && <div className="danger-panel alert-inline-error" role="alert">{error}</div>}
    <div className="alert-summary" aria-label="Alert queue summary">
      {(Object.keys(viewLabels) as AlertView[]).map((key) => <button key={key} className={view === key ? "alert-summary-card selected" : "alert-summary-card"} onClick={() => setView(key)} aria-pressed={view === key}><strong>{projection?.counts[key] ?? "—"}</strong><span>{viewLabels[key]}</span></button>)}
    </div>
    <div className="card table-card alert-queue-card">
      <div className="table-toolbar">
        <label><span>Search visible alerts</span><span className="alert-search"><Search size={15} aria-hidden="true" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Rule, target, policy, or alert ID" /></span></label>
        <span>{rows.length} visible · last committed state {projection ? relativeTime(projection.freshness_at) : "loading"}</span>
      </div>
      <div className="responsive-table">
        <table>
          <thead><tr><th>Alert and target</th><th>Severity / source</th><th>Observed</th><th>Investigation</th><th>Next action</th><th><span className="sr-only">Open</span></th></tr></thead>
          <tbody>{rows.map((row) => <tr key={row.alert_episode_id}>
            <td><button className="alert-title-button" onClick={() => setSelected(row.alert_episode_id)}><strong>{row.title}</strong><span>{row.target} · <code>{shortId(row.alert_episode_id)}</code></span></button></td>
            <td><div className="alert-cell-stack"><StatusBadge label={row.severity} tone={severityTone(row.severity)} /><span>{providerLabel(row.source_provider)} · provider {row.provider_state.toLowerCase()}</span></div></td>
            <td><div className="alert-cell-stack"><strong>{row.occurrence_count} occurrence{row.occurrence_count === 1 ? "" : "s"}</strong><span>Last seen {relativeTime(row.last_seen_at)}</span></div></td>
            <td><div className="alert-cell-stack"><StatusBadge label={stateLabel(row.investigation_state)} tone={stateTone(row)} /><span>{reasonLabel(row.reason_code)}</span><small title={`${row.mode} · ${row.mode_explanation}`}>{row.mode_label}</small></div></td>
            <td><strong>{row.next_action}</strong>{row.incident && <span className="alert-incident-link">{row.incident.display_id}</span>}</td>
            <td><button className="icon-button" aria-label={`Open ${row.title}`} onClick={() => setSelected(row.alert_episode_id)}><ChevronRight size={17} aria-hidden="true" /></button></td>
          </tr>)}</tbody>
        </table>
        {projection && rows.length === 0 && <div className="alert-empty"><BellRing size={24} aria-hidden="true" /><strong>No alerts match this view</strong><span>Changing a view never changes an alert’s durable state.</span></div>}
      </div>
      {projection?.next_cursor && <div className="alert-pagination"><button className="secondary-button" type="button" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? "Loading…" : "Load more alerts"}</button></div>}
    </div>
  </section>;
}

function AlertDetail({ report, error, apiUrl, authority, onOpenIncident, onChanged, onBack }: { report: AlertReport | null; error: string | null; apiUrl: string; authority: string; onOpenIncident: (incidentId: string) => void; onChanged: () => void; onBack: () => void }): React.JSX.Element {
  const [askOpen, setAskOpen] = useState(() => !window.matchMedia("(max-width: 1040px)").matches);
  const commandDialog = useRef<HTMLDialogElement>(null);
  const feedbackDialog = useRef<HTMLDialogElement>(null);
  const [commandKind, setCommandKind] = useState<"INCIDENT_CONTINUATION" | "RETRIAGE">("INCIDENT_CONTINUATION");
  const [reason, setReason] = useState("OPERATOR_REVIEW");
  const [identityToken, setIdentityToken] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [commandStatus, setCommandStatus] = useState<string | null>(null);
  const [feedbackCategory, setFeedbackCategory] = useState("HELPFUL");
  const [feedbackToken, setFeedbackToken] = useState("");
  if (error) return <section><button className="back-button" onClick={onBack}><ArrowLeft size={15} aria-hidden="true" /> All alerts</button><div className="danger-panel" role="alert">{error}</div></section>;
  if (!report) return <section className="state-page" aria-busy="true"><span className="spinner" /><h1>Loading alert investigation</h1></section>;
  const header = report.header;
  const live = authority === "GOOGLE_CLOUD_IAM";
  const openCommand = (kind: "INCIDENT_CONTINUATION" | "RETRIAGE"): void => { setCommandKind(kind); setCommandStatus(null); commandDialog.current?.showModal(); };
  const copyLocator = async (): Promise<void> => {
    const locator = `${window.location.origin}${window.location.pathname}?alert=${encodeURIComponent(report.alert_episode_id)}`;
    await navigator.clipboard.writeText(locator);
    setCommandStatus("Alert locator copied. The link carries no visibility or command authority.");
  };
  const submitCommand = async (): Promise<void> => {
    if (!live || !identityToken.trim()) return;
    setSubmitting(true);
    setCommandStatus(null);
    const path = commandKind === "RETRIAGE" ? "request-retriage" : "request-incident-continuation";
    try {
      const response = await fetch(`${apiUrl}/api/alerts/${encodeURIComponent(report.alert_episode_id)}/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "X-Solvan-Approval-Token": identityToken.trim() },
        body: JSON.stringify({ schema_version: 1, expected_row_version: report.row_version, request_reason_code: reason }),
      });
      const payload = await response.json() as { status?: string; detail?: string };
      if (!response.ok) throw new Error(payload.detail ?? `Request refused (${response.status})`);
      setCommandStatus(commandKind === "RETRIAGE" ? "Read-only triage request accepted." : "Incident continuation request accepted for coordinator revalidation.");
      setIdentityToken("");
      commandDialog.current?.close();
      onChanged();
    } catch (cause) {
      setCommandStatus(cause instanceof Error ? cause.message : "Alert request was refused.");
    } finally { setSubmitting(false); }
  };
  const submitFeedback = async (): Promise<void> => {
    if (!live || !feedbackToken.trim()) return;
    setSubmitting(true);
    setCommandStatus(null);
    try {
      const response = await fetch(`${apiUrl}/api/alerts/${encodeURIComponent(report.alert_episode_id)}/feedback`, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "X-Solvan-Approval-Token": feedbackToken.trim() },
        body: JSON.stringify({ schema_version: 1, category: feedbackCategory, note_ref: null }),
      });
      const payload = await response.json() as { detail?: string };
      if (!response.ok) throw new Error(payload.detail ?? `Feedback refused (${response.status})`);
      setCommandStatus("Feedback recorded for independent review; it changed no policy or authority.");
      setFeedbackToken("");
      feedbackDialog.current?.close();
      onChanged();
    } catch (cause) {
      setCommandStatus(cause instanceof Error ? cause.message : "Feedback was refused.");
    } finally { setSubmitting(false); }
  };
  return <section className={askOpen ? "alert-detail with-ask" : "alert-detail"}>
    <div className="alert-report-column">
      <button className="back-button" onClick={onBack}><ArrowLeft size={15} aria-hidden="true" /> All alerts</button>
      <header className="alert-detail-header">
        <div><div className="alert-header-badges"><MonoChip>{shortId(header.alert_episode_id)}</MonoChip><StatusBadge label={header.severity} tone={severityTone(header.severity)} /><StatusBadge label={`Provider ${header.provider_state.toLowerCase()}`} tone="neutral" /></div><h1>{header.title}</h1><p>{header.target} · {providerLabel(header.source_provider)} · last seen {relativeTime(header.last_seen_at)}</p></div>
        <div className="alert-header-actions"><button className="secondary-button" type="button" onClick={() => void copyLocator()}><Copy size={16} aria-hidden="true" /> Copy safe link</button><button className="secondary-button" onClick={() => setAskOpen(!askOpen)}><MessageSquareText size={16} aria-hidden="true" /> {askOpen ? "Hide conversation" : "Ask about this alert"}</button></div>
      </header>
      <section className={`card alert-decision-explanation ${report.decision_explanation.status === "ESTABLISHED" ? "established" : "holding"}`} aria-labelledby="alert-decision-title">
        <div className="section-heading"><div><p className="eyebrow">Committed decision · not a simulation</p><h2 id="alert-decision-title">Why this Alert {report.decision_explanation.result === "ESCALATED" ? "became an Incident" : "did not become an Incident"}</h2></div><StatusBadge label={decisionResultLabel(report.decision_explanation.result)} tone={report.decision_explanation.result === "ESCALATED" ? "success" : report.decision_explanation.result === "INCONCLUSIVE" ? "warning" : "neutral"} /></div>
        {report.decision_explanation.status === "ESTABLISHED" ? <><p>{String(report.decision_explanation.typed_values.mode_explanation ?? header.mode_explanation)}</p><dl className="alert-decision-facts"><div><dt>Policy mode</dt><dd>{report.decision_explanation.operator_mode_label}</dd></div><div><dt>Rule result</dt><dd>{decisionResultLabel(report.decision_explanation.result)}</dd></div><div><dt>Policy revision</dt><dd>{report.decision_explanation.policy_key}@{report.decision_explanation.policy_version}</dd></div><div><dt>Committed inputs</dt><dd>{report.decision_explanation.authorized_input_refs.length}</dd></div></dl><details><summary>Technical decision proof</summary><p><code>{report.decision_explanation.machine_mode}</code> · <code>{shortId(report.decision_explanation.policy_digest)}</code>{report.decision_explanation.expression_digest ? <> · expression <code>{shortId(report.decision_explanation.expression_digest)}</code></> : null}</p></details></> : <p className="alert-holding">This decision explanation is {report.decision_explanation.status.toLowerCase()}; no partial inputs are shown.</p>}
      </section>
      <article className="card alert-answer-first" aria-label="Alert investigation report">
        {report.sections.sort((a, b) => a.ordinal - b.ordinal).map((section) => <section key={section.section_id} className="alert-report-section">
          <div className="alert-report-number" aria-hidden="true">{section.ordinal}</div>
          <div><div className="alert-section-heading"><h2>{sectionLabels[section.section_id]}</h2><StatusBadge label={section.status === "ESTABLISHED" ? "Established" : holdingLabel(section.status)} tone={section.status === "ESTABLISHED" ? "provenance" : "neutral"} /></div>
          {section.claims.length > 0 ? section.claims.map((claim) => <div key={claim.claim_template_id} className="alert-claim"><p>{String(claim.typed_values.sentence ?? "Committed alert fact")}</p><div className="alert-claim-meta"><span>{sourceStatusLabel(claim.source_status_kind)}</span>{claim.citation_refs.map((citation) => <button type="button" className="source-chip" key={citation} title={citation}>Source · {shortId(citation)}</button>)}</div></div>) : <p className="alert-holding">{holdingCopy(section.section_id, section.status)}</p>}</div>
        </section>)}
      </article>
      <details className="card alert-technical"><summary>Technical details</summary><div className="alert-disclosure-grid">{report.technical_disclosures.map((item) => <div key={item.kind}><strong>{item.count}</strong><span>{item.kind.replaceAll("_", " ").toLowerCase()}</span></div>)}</div><div className="alert-secondary-controls">{report.secondary_controls.includes("RUN_TRIAGE_AGAIN") && <button className="secondary-button" type="button" disabled={!live} onClick={() => openCommand("RETRIAGE")}>Run triage again</button>}{report.secondary_controls.includes("GIVE_FEEDBACK") && <button className="secondary-button" type="button" disabled={!live} onClick={() => feedbackDialog.current?.showModal()}>Give feedback</button>}</div><p className="muted-copy">Feedback informs review; it does not change this policy or future authority automatically.</p></details>
      <div className="alert-primary-action card"><div><p className="eyebrow">Current eligible control</p><h2>{controlLabel(report.primary_control?.kind)}</h2><p>This request is revalidated against current policy, scope, capacity, and row version before work is admitted.</p>{!live && <span className="muted-copy">Local development has no cloud identity or command authority.</span>}</div><button className="primary-button" disabled={!report.primary_control || (!live && report.primary_control.kind !== "OPEN_INCIDENT")} onClick={() => { if (report.primary_control?.kind === "OPEN_INCIDENT" && report.primary_control.incident_id) onOpenIncident(report.primary_control.incident_id); else openCommand("INCIDENT_CONTINUATION"); }}>{report.primary_control?.kind === "OPEN_INCIDENT" ? "Open linked Incident" : live ? "Continue investigation" : "Unavailable in local development"}</button></div>
      {commandStatus && <p className="inline-notice" role="status">{commandStatus}</p>}
      <dialog ref={commandDialog} className="approval-dialog alert-command-dialog"><form method="dialog" onSubmit={(event) => { event.preventDefault(); void submitCommand(); }}><div className="dialog-header"><div><p className="eyebrow">Authenticated operator request</p><h2>{commandKind === "RETRIAGE" ? "Run read-only triage again?" : "Continue into Incident investigation?"}</h2></div><button className="icon-button" value="cancel" aria-label="Close alert request"><X size={18} aria-hidden="true" /></button></div><p>{commandKind === "RETRIAGE" ? "The coordinator will recheck the source, policy, target, capacity, and current row before admitting a new read-only evidence run." : "The coordinator will recheck policy and normal Incident deduplication before creating or attaching an Incident."}</p><label className="token-field">Reason<select value={reason} onChange={(event) => setReason(event.target.value)}><option value="OPERATOR_REVIEW">Operator review</option><option value="NEED_MORE_EVIDENCE">Need more evidence</option><option value="POSSIBLE_CUSTOMER_IMPACT">Possible customer impact</option><option value="POSSIBLE_SECURITY_IMPACT">Possible security impact</option></select></label><label className="token-field">One-time Google identity token<input type="password" autoComplete="off" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} required /><small>Held only in this dialog and verified for the exact operator role and environment.</small></label><div className="dialog-actions"><button className="secondary-button" type="button" onClick={() => commandDialog.current?.close()}>Cancel</button><button className="primary-button" type="submit" disabled={!identityToken.trim() || submitting}>{submitting ? "Revalidating…" : "Submit exact request"}</button></div></form></dialog>
      <dialog ref={feedbackDialog} className="approval-dialog alert-command-dialog"><form method="dialog" onSubmit={(event) => { event.preventDefault(); void submitFeedback(); }}><div className="dialog-header"><div><p className="eyebrow">Review signal only</p><h2>Give feedback on this triage</h2></div><button className="icon-button" value="cancel" aria-label="Close feedback"><X size={18} aria-hidden="true" /></button></div><p>Your selection is stored as untrusted review input. It cannot change a policy, disposition, memory, or future authority.</p><label className="token-field">Feedback<select value={feedbackCategory} onChange={(event) => setFeedbackCategory(event.target.value)}><option value="HELPFUL">Helpful</option><option value="NOT_HELPFUL">Not helpful</option><option value="MISSING_EVIDENCE">Missing evidence</option><option value="INCORRECT_CAUSE">Incorrect cause</option><option value="OTHER">Other</option></select></label><label className="token-field">One-time Google identity token<input type="password" autoComplete="off" value={feedbackToken} onChange={(event) => setFeedbackToken(event.target.value)} required /></label><div className="dialog-actions"><button className="secondary-button" type="button" onClick={() => feedbackDialog.current?.close()}>Cancel</button><button className="primary-button" type="submit" disabled={!feedbackToken.trim() || submitting}>{submitting ? "Recording…" : "Record feedback"}</button></div></form></dialog>
    </div>
    {askOpen && <aside className="alert-ask-column" aria-label="Ask about this alert"><AskRail recordType="alert_episode" recordId={report.alert_episode_id} title={`About ${shortId(report.alert_episode_id)}`} apiUrl={apiUrl} authority={authority} renderApprovalPart={() => null} onClose={() => setAskOpen(false)} /></aside>}
  </section>;
}

function severityTone(value: AlertRow["severity"]): StatusTone { return value === "SEV1" ? "danger" : value === "SEV2" ? "warning" : "neutral"; }
function stateTone(row: AlertRow): StatusTone { return row.required_human_attention ? "warning" : row.investigation_state === "TRIAGING" ? "agent" : "info"; }
function stateLabel(value: string): string { return ({ OPEN: "New", WAITING: "Waiting for capacity", TRIAGING: "Investigating", TRIAGED: "Triage complete", BLOCKED: "Blocked", ESCALATED: "Incident opened", ATTACHED: "Attached to incident", PROVIDER_REPORTED_CLEARED: "Provider reports cleared", EXPIRED: "Expired", SUPPRESSED: "Suppressed" } as Record<string, string>)[value] ?? value.replaceAll("_", " ").toLowerCase(); }
function providerLabel(value: string): string { return value === "CLOUD_MONITORING" ? "Cloud Monitoring" : value.replaceAll("_", " ").toLowerCase(); }
function reasonLabel(value: string | null): string { return value ? value.replaceAll("_", " ").toLowerCase() : "Awaiting a committed disposition"; }
function sourceStatusLabel(value: string): string { return ({ PROVIDER_REPORTED: "Provider reported", SOLVAN_OBSERVED: "Solvan observed", INDEPENDENTLY_VERIFIED: "Independently verified" } as Record<string, string>)[value] ?? value; }
function holdingLabel(value: string): string { return value.replaceAll("_", " ").toLowerCase(); }
function holdingCopy(section: ReportSection["section_id"], status: string): string { const subject = section === "IMPACT" ? "Impact" : section === "LIKELY_CAUSE" ? "Cause" : sectionLabels[section]; return status === "WITHHELD" ? `${subject} is withheld for this reader.` : status === "STALE" ? `${subject} needs fresh evidence.` : status === "CONTRADICTORY" ? `${subject} has contradictory evidence.` : `${subject} is not established.`; }
function controlLabel(kind: string | undefined): string { return kind === "OPEN_INCIDENT" ? "Open linked Incident" : kind === "CONTINUE_INVESTIGATION" ? "Continue investigation" : "No action available"; }
function decisionResultLabel(value: string): string { return ({ ESCALATED: "Rule passed · Incident opened", NOT_ESCALATED: "Rule did not pass", INCONCLUSIVE: "Rule inconclusive", NOT_APPLICABLE: "No automatic rule" } as Record<string, string>)[value] ?? value.replaceAll("_", " ").toLowerCase(); }
function shortId(value: string): string { return value.length <= 14 ? value : `${value.slice(0, 4)}…${value.slice(-5)}`; }
function relativeTime(value: string): string { const delta = Math.max(0, Date.now() - new Date(value).getTime()); const minutes = Math.floor(delta / 60_000); if (minutes < 1) return "just now"; if (minutes < 60) return `${minutes}m ago`; const hours = Math.floor(minutes / 60); if (hours < 24) return `${hours}h ago`; return new Date(value).toLocaleString(); }

function encodeAlertFilter(view: AlertView, query: string): string {
  const normalized = query.trim().replace(/\s+/g, " ").toLowerCase();
  const payload = JSON.stringify({
    connection_id: [],
    department: [],
    disposition: [],
    episode_state: [],
    incident_link: "ANY",
    limit: 50,
    mode: [],
    policy_key: [],
    provider_state: [],
    query: normalized || null,
    schema_version: 1,
    severity: [],
    source_provider: [],
    source_time_from: null,
    source_time_to: null,
    target_key: [],
    view,
  });
  const bytes = new TextEncoder().encode(payload);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
