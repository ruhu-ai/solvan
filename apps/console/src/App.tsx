import { useEffect, useState } from "react";
import { SignIn } from "./SignIn";
import { signOut, useOperatorSession } from "./session";
import {
  Activity,
  BellRing,
  Circle,
  CircleCheck,
  CircleDot,
  CircleHelp,
  CircleX,
  FolderClock,
  House,
  Info,
  Menu,
  MessageSquare,
  Plug,
  Receipt,
  Settings as SettingsIcon,
  ShieldX,
  TriangleAlert,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import type { ConsoleSnapshot, Finding, Incident, OperatorContext, SettingsProjection, StatusTone } from "./types";
import { AskRail } from "./Ask";
import { Alerts } from "./Alerts";
import { CentralChat } from "./CentralChat";
import { conversationEvidence } from "./conversationEvidence";
import { Integrations } from "./Integrations";
import { ActionCard, Actions } from "./IncidentActions";
import { EvidenceProvider, Evidence, IncidentStateBadge, IncidentsList, OperatorBrief, RecoveryTimingRail, SourceChip, Timeline } from "./Incidents";
import { LabelValue, MonoChip, PageHeader, SolvanMark, StatusBadge, phaseClass, platformEvidenceLabel, platformHealthLabel, platformHealthTone, statusIcon } from "./components";
import { Cases, PermanentRepair, VerificationPanel } from "./IncidentRepair";
import { Fleet } from "./Fleet";
import { OperatorControl } from "./OperatorControl";
import { RelatedAlertsPanel } from "./RelatedAlerts";
import { RouteBoundary } from "./RouteBoundary";
import { Settings } from "./Settings";
import { settingsFallbackFromSnapshot } from "./settingsFallback";

type Route = "Overview" | "Chat" | "Alerts" | "Incidents" | "Reliability Cases" | "Integrations" | "Agent Fleet" | "Release Evidence" | "Settings";
type IncidentTab = "Timeline" | "Evidence" | "Actions" | "Verification" | "Permanent Repair";

const routes: Route[] = ["Overview", "Chat", "Alerts", "Incidents", "Reliability Cases", "Integrations", "Agent Fleet", "Release Evidence", "Settings"];
const incidentTabs: IncidentTab[] = ["Timeline", "Evidence", "Actions", "Verification", "Permanent Repair"];

export function App(): React.JSX.Element {
  const [snapshot, setSnapshot] = useState<ConsoleSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [route, setRoute] = useState<Route>(() => { const query = new URLSearchParams(window.location.search); return query.has("section") ? "Settings" : query.has("alert") ? "Alerts" : query.has("incident") ? "Incidents" : query.has("fleet") ? "Agent Fleet" : query.get("guide") === "gcp-connection" ? "Integrations" : "Overview"; });
  const [selectedIncident, setSelectedIncident] = useState<string | null>(() => new URLSearchParams(window.location.search).get("incident"));
  const [selectedAlert, setSelectedAlert] = useState<string | null>(() => new URLSearchParams(window.location.search).get("alert"));
  const [mobileNav, setMobileNav] = useState(false);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [settingsProjection, setSettingsProjection] = useState<SettingsProjection | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [settingsRefreshVersion, setSettingsRefreshVersion] = useState(0);
  // The console and the API are one origin: `apps/console/server.mjs` serves
  // these assets and proxies `/api` when deployed, and the Vite dev server does
  // the same locally. Naming the API's own origin here is what made development
  // exercise a cross-origin session the deployment never used.
  const apiUrl = "";
  const { state: sessionState, refresh: refreshSession } = useOperatorSession(apiUrl);
  const [signedOutNotice, setSignedOutNotice] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiUrl}/api/console/snapshot`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Projection API returned ${response.status}`);
        return (await response.json()) as ConsoleSnapshot;
      })
      .then((value) => {
        setSnapshot(value);
        setError(null);
        setSettingsProjection(value.settings ?? settingsFallbackFromSnapshot(value));
        setSettingsError(value.settings ? null : "The current console API did not include settings details.");
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Unknown projection failure");
      });
    return () => controller.abort();
  }, [apiUrl, refreshVersion]);

  useEffect(() => {
    if (!snapshot || snapshot.settings) return;
    const controller = new AbortController();
    fetch(`${apiUrl}/api/console/settings`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Settings API returned ${response.status}`);
        return (await response.json()) as SettingsProjection;
      })
      .then((value) => {
        setSettingsProjection(value);
        setSettingsError(null);
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setSettingsError(reason instanceof Error ? reason.message : "Unknown settings projection failure");
      });
    return () => controller.abort();
  }, [apiUrl, settingsRefreshVersion, snapshot]);

  useEffect(() => {
    const restoreDeepLink = () => {
      if (new URLSearchParams(window.location.search).has("section")) {
        setSelectedIncident(null);
        setRoute("Settings");
      } else if (new URLSearchParams(window.location.search).has("alert")) {
        setSelectedIncident(null);
        setSelectedAlert(new URLSearchParams(window.location.search).get("alert"));
        setRoute("Alerts");
      } else if (new URLSearchParams(window.location.search).has("incident")) {
        setSelectedIncident(new URLSearchParams(window.location.search).get("incident"));
        setRoute("Incidents");
      } else if (new URLSearchParams(window.location.search).has("fleet")) {
        setSelectedIncident(null);
        setRoute("Agent Fleet");
      } else if (new URLSearchParams(window.location.search).get("guide") === "gcp-connection") {
        setSelectedIncident(null);
        setRoute("Integrations");
      } else {
        setRoute((current) => current === "Settings" ? "Overview" : current);
      }
      setMobileNav(false);
    };
    window.addEventListener("popstate", restoreDeepLink);
    return () => window.removeEventListener("popstate", restoreDeepLink);
  }, []);

  function navigate(next: Route): void {
    const url = new URL(window.location.href);
    url.searchParams.delete("guide");
    if (next !== "Incidents") url.searchParams.delete("incident");
    if (next !== "Agent Fleet") url.searchParams.delete("fleet");
    if (next !== "Settings") {
      url.searchParams.delete("section");
      if (next !== "Alerts") url.searchParams.delete("alert");
      window.history.pushState({}, "", url);
    } else if (!url.searchParams.has("section")) {
      url.searchParams.set("section", "personal");
      window.history.pushState({}, "", url);
    }
    setRoute(next);
    setSelectedIncident(null);
    if (next !== "Alerts") setSelectedAlert(null);
    setMobileNav(false);
  }

  function openSettings(section: string): void {
    const url = new URL(window.location.href);
    url.searchParams.set("section", section);
    window.history.pushState({}, "", url);
    navigate("Settings");
  }

  function openIncident(id: string): void {
    setRoute("Incidents");
    setSelectedIncident(id);
  }

  function openAlert(id: string): void {
    const url = new URL(window.location.href);
    url.searchParams.delete("section");
    url.searchParams.set("alert", id);
    window.history.pushState({}, "", url);
    setSelectedIncident(null);
    setSelectedAlert(id);
    setRoute("Alerts");
  }

  // Nothing is rendered before the browser has an identity. A console that
  // renders first and authenticates later has shown a scope to somebody it has
  // not identified.
  async function endSession(): Promise<void> {
    try {
      await signOut(apiUrl);
      setSignedOutNotice("You are signed out. Your session was ended on this device.");
    } catch (cause) {
      // The session may still be live, so say so rather than showing a sign-in
      // page that implies it is not.
      setSignedOutNotice(cause instanceof Error ? cause.message : "Sign-out failed.");
    }
    refreshSession();
  }

  if (sessionState.status === "loading") {
    return <main className="sign-in-page"><p aria-busy="true">Checking your session…</p></main>;
  }
  if (sessionState.status === "unavailable") {
    return <main className="sign-in-page"><section className="card sign-in-card" role="alert"><p className="eyebrow">Identity unavailable</p><h1>This console cannot establish who you are</h1><p>{sessionState.reason}</p><p className="muted-copy">Nothing is shown rather than guessed. No work is lost.</p></section></main>;
  }
  if (sessionState.status === "signed-out") {
    return <SignIn apiUrl={apiUrl} returnPath={window.location.pathname + window.location.search} reason={signedOutNotice ?? sessionState.reason} provider={sessionState.provider} providerIsProduction={sessionState.providerIsProduction} />;
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className={mobileNav ? "sidebar sidebar-open" : "sidebar"} aria-label="Primary navigation">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true"><SolvanMark size={19} /></span>
          <div><strong>Solvan</strong><span>Reliability control plane</span></div>
        </div>
        <nav aria-label="Primary">
          {routes.map((item) => (
            <button key={item} className={route === item ? "nav-item active" : "nav-item"} onClick={() => navigate(item)} aria-current={route === item ? "page" : undefined}>
              <span className="nav-icon" aria-hidden="true">{routeIcon(item)}</span>{item}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" aria-hidden="true" />
          {/* Environment and authority are two separate facts. The name comes
              from the projected environment record; the sentence under it
              states whether this deployment carries control authority. Deriving
              both from `authority` conflated them. */}
          <div><strong>{snapshot?.environment.name ?? "Environment unavailable"}</strong><span>{snapshot?.authority === "GOOGLE_CLOUD_IAM" ? "Scoped control authority" : "No production authority"}</span></div>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <button className="icon-button menu-button" aria-label="Open navigation" onClick={() => setMobileNav(!mobileNav)}><Menu size={20} strokeWidth={1.75} aria-hidden="true" /></button>
          {/* Autonomy off is the safe default and the sidebar already names the
              scope; a standing amber badge for the ordinary case trains the eye
              to skip the one state that matters. Autonomy active means the
              system may act without a person, so only that is announced here.
              The environment name and every governance detail stay in Settings,
              where they are the subject and can be stated exactly. */}
          {settingsProjection?.governance.autonomy_state === "ACTIVE" && (
            <div className="global-state"><StatusBadge label="Autonomy active" tone="success" /></div>
          )}
          <OperatorControl operator={settingsProjection?.operator ?? null} onOpenSettings={openSettings} onSignOut={() => void endSession()} />
        </header>
        {/* No standing banner. Whether anything has been verified on Google
            Cloud is answered where it is the subject — Release Evidence, the
            Platform tab, the environment card — and enforced where it could
            cause harm: the approval path refuses outside the deployment. A
            warning that is always true is read once and never again, and it
            was the fifth restatement of a fact the sidebar already carries. */}
        <main id="main-content" tabIndex={-1}>
          <RouteBoundary route={selectedIncident ? "Incident workspace" : route}>
          {error ? <ErrorState message={error} /> : !snapshot ? <LoadingState /> : selectedIncident ? (
            <IncidentDetail incident={snapshot.incidents.find((item) => item.id === selectedIncident || item.machine_id === selectedIncident) ?? snapshot.incidents[0]} caseRecord={snapshot.cases[0]} authority={snapshot.authority} apiUrl={apiUrl} onOpenAlert={openAlert} onChanged={() => setRefreshVersion((value) => value + 1)} onBack={() => setSelectedIncident(null)} />
          ) : route === "Overview" ? <Overview snapshot={snapshot} openIncident={openIncident} navigate={navigate} />
            : route === "Chat" ? <CentralChat apiUrl={apiUrl} authority={snapshot.authority} />
            : route === "Alerts" ? <Alerts apiUrl={apiUrl} authority={snapshot.authority} initialAlertId={selectedAlert} onInitialAlertConsumed={() => setSelectedAlert(null)} onOpenIncident={(incidentId) => { setSelectedIncident(incidentId); setRoute("Incidents"); }} />
            : route === "Incidents" ? <IncidentsList incidents={snapshot.incidents} openIncident={openIncident} />
            : route === "Reliability Cases" ? <Cases cases={snapshot.cases} authority={snapshot.authority} apiUrl={apiUrl} onChanged={() => setRefreshVersion((value) => value + 1)} />
            : route === "Integrations" ? <Integrations integration={snapshot.integration} apiUrl={apiUrl} onChanged={() => setRefreshVersion((value) => value + 1)} />
            : route === "Agent Fleet" ? <Fleet fleet={snapshot.fleet} apiUrl={apiUrl} region={snapshot.environment.region} />
            : route === "Release Evidence" ? <ReleaseEvidence release={snapshot.release} />
            : <Settings projection={settingsProjection} error={settingsError} retry={() => setSettingsRefreshVersion((value) => value + 1)} navigate={navigate} apiUrl={apiUrl} />}
          </RouteBoundary>
        </main>
      </div>
      {mobileNav && <button className="scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    </div>
  );
}

function routeIcon(route: Route): React.JSX.Element {
  const Icon = routeIcons[route];
  return <Icon size={16} strokeWidth={1.75} aria-hidden="true" />;
}

const routeIcons: Record<Route, LucideIcon> = {
  Overview: House,
  Chat: MessageSquare,
  Alerts: BellRing,
  Incidents: TriangleAlert,
  "Reliability Cases": FolderClock,
  "Agent Fleet": Workflow,
  Integrations: Plug,
  "Release Evidence": Receipt,
  Settings: SettingsIcon,
};

function LoadingState(): React.JSX.Element {
  return <section className="state-page" aria-busy="true"><span className="spinner" /><h1>Loading durable projections</h1><p>Connecting to the local, non-authoritative API.</p></section>;
}

function ErrorState({ message }: { message: string }): React.JSX.Element {
  return <section className="state-page danger-panel" role="alert"><span className="state-symbol"><CircleX size={24} strokeWidth={1.75} aria-hidden="true" /></span><h1>Console projection unavailable</h1><p>Work remains safe. The console will not infer state while the API is unavailable.</p><code>{message}</code></section>;
}

const incidentStateLabels: Record<string, { label: string; tone: StatusTone }> = {
  DETECTED: { label: "Detected", tone: "danger" },
  TRIAGING: { label: "Investigating", tone: "agent" },
  INVESTIGATING: { label: "Investigating", tone: "agent" },
  DIAGNOSING: { label: "Diagnosing", tone: "agent" },
  MITIGATION_PROPOSED: { label: "Mitigation proposed", tone: "info" },
  AWAITING_APPROVAL: { label: "Approval required", tone: "warning" },
  MITIGATING: { label: "Executing mitigation", tone: "agent" },
  VERIFYING_MITIGATION: { label: "Verifying recovery", tone: "info" },
  MITIGATED: { label: "Service restored · repair open", tone: "success" },
  RESOLVED: { label: "Resolved and verified", tone: "success" },
  ESCALATED: { label: "Human ownership accepted", tone: "warning" },
  UNRESOLVABLE: { label: "No safe action available", tone: "warning" },
  FALSE_POSITIVE: { label: "False positive", tone: "neutral" },
  CANCELLED: { label: "Cancelled", tone: "neutral" },
};

function Overview({ snapshot, openIncident, navigate }: { snapshot: ConsoleSnapshot; openIncident: (id: string) => void; navigate: (route: Route) => void }): React.JSX.Element {
  // The operator queue is derived, never asserted. Anything shown here is a
  // durable record the operator can open; a count with no rows behind it would
  // be an invented queue.
  const queued = snapshot.incidents.flatMap((record) => record.actions.map((action) => ({ action, incidentId: record.id })));
  const awaitingApproval = queued.filter(({ action }) => action.status === "AWAITING_APPROVAL");
  const executing = queued.filter(({ action }) => action.status === "APPROVED" || action.status === "EXECUTING" || action.status === "RECONCILING");
  const verified = queued.filter(({ action }) => action.status === "VERIFIED");
  const wakeups = snapshot.cases.filter((record) => record.next);
  const incident = snapshot.incidents[0];
  if (!incident) return <><PageHeader eyebrow="Operations overview" title="Production reliability, with proof" description="No incidents are committed in this environment." /><section className="state-page"><span className="state-symbol"><CircleCheck size={24} strokeWidth={1.75} aria-hidden="true" /></span><h2>No incident work</h2><p>The durable queue is empty.</p></section></>;
  return <>
    <PageHeader eyebrow="Operations overview" title="Production reliability, with proof" description="One active incident is mitigated. Permanent repair still needs an exact human decision." actions={<button className="secondary-button" onClick={() => navigate("Release Evidence")}>View release evidence</button>} />
    <div className="overview-grid">
      <section className="overview-main">
        <div className="metric-grid" aria-label="Operational metrics">
          {snapshot.overview.metrics.map((metric) => <article className="metric-card" key={metric.label}><span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small></article>)}
        </div>
        <section className="card active-incident-card" aria-labelledby="active-incident-title">
          <div className="section-heading"><div><p className="eyebrow">Active incident</p><h2 id="active-incident-title">{incident.title}</h2></div><IncidentStateBadge state={incident.state} /></div>
          <div className="incident-meta"><MonoChip>{incident.id}</MonoChip><span>{incident.severity}</span><span>{incident.service}</span><span>{incident.environment}</span></div>
          <p className="situation">{incident.brief.situation}</p>
          <div className="brief-grid"><LabelValue label="Last verified fact" value={incident.brief.last_verified} /><LabelValue label="Human attention" value={incident.brief.attention} /><LabelValue label="Next owner" value={incident.brief.next} /></div>
          <button className="primary-button" onClick={() => openIncident(incident.id)}>Open incident workspace <span aria-hidden="true">→</span></button>
        </section>
        <section className="card"><div className="section-heading"><div><p className="eyebrow">Durable execution</p><h2>Work queue health</h2></div><span className="muted">Cloud SQL projection</span></div><div className="queue-grid">{Object.entries(snapshot.overview.queue).map(([name, count]) => <div key={name}><strong>{count}</strong><span>{name}</span></div>)}</div></section>
        <section className="card"><div className="section-heading"><div><p className="eyebrow">Institutional fleet</p><h2>Google agent platform readiness</h2></div><button className="text-button" onClick={() => navigate("Agent Fleet")}>Inspect Agent Fleet →</button></div><div className="platform-list">{snapshot.fleet.platform.slice(0, 4).map((item) => <div key={item.name}><span className="platform-icon" aria-hidden="true">{item.health === "HEALTHY" ? <CircleCheck size={18} strokeWidth={1.75} /> : <CircleHelp size={18} strokeWidth={1.75} />}</span><div><strong>{item.name}</strong><span>{item.detail}</span><small>Evidence: {platformEvidenceLabel(item.evidence)}</small></div><StatusBadge label={platformHealthLabel(item.health)} tone={platformHealthTone(item.health)} machine={item.health} /></div>)}</div></section>
      </section>
      <aside className="attention-rail" aria-label="Operator attention">
        <p className="eyebrow">Attention</p><h2>Your operational queue</h2>
        <AttentionGroup title="Needs approval" count={awaitingApproval.length} open>{awaitingApproval.length === 0 ? <p className="empty-copy">No action is waiting on an exact approval.</p> : awaitingApproval.map(({ action, incidentId }) => <button className="attention-card" key={action.id} onClick={() => openIncident(incidentId)}><span><MonoChip>{action.id}</MonoChip>{action.expires && <StatusBadge label={action.expires} tone="warning" />}</span><strong>{action.name}</strong><small>Exact {action.risk} approval</small></button>)}</AttentionGroup>
        <AttentionGroup title="Executing" count={executing.length}>{executing.length === 0 ? <p className="empty-copy">No authorized action is executing.</p> : executing.map(({ action, incidentId }) => <button className="attention-card" key={action.id} onClick={() => openIncident(incidentId)}><span><MonoChip>{action.id}</MonoChip><StatusBadge label={action.phase} tone="info" machine={action.status} /></span><strong>{action.name}</strong></button>)}</AttentionGroup>
        <AttentionGroup title="Scheduled wake-ups" count={wakeups.length}>{wakeups.length === 0 ? <p className="empty-copy">No Reliability Case has a scheduled wake-up.</p> : wakeups.map((record) => <button className="attention-card" key={record.id} onClick={() => navigate("Reliability Cases")}><span><MonoChip>{record.id}</MonoChip></span><strong>{record.next}</strong><small>Owner {record.owner}</small></button>)}</AttentionGroup>
        <AttentionGroup title="Recently verified" count={verified.length}>{verified.length === 0 ? <p className="empty-copy">No mitigation has been independently verified yet.</p> : verified.map(({ action, incidentId }) => <button className="attention-card" key={action.id} onClick={() => openIncident(incidentId)}><span><MonoChip>{action.id}</MonoChip><StatusBadge label="Verified" tone="success" machine={action.status} /></span><strong>{action.name}</strong></button>)}</AttentionGroup>
      </aside>
    </div>
  </>;
}

function AttentionGroup({ title, count, open = false, children }: { title: string; count: number; open?: boolean; children: React.ReactNode }): React.JSX.Element {
  return <details className="attention-group" open={open}><summary><span>{title}</span><strong>{count}</strong></summary><div>{children}</div></details>;
}

function IncidentDetail({ incident, caseRecord, authority, apiUrl, onOpenAlert, onChanged, onBack }: { incident: Incident; caseRecord: ConsoleSnapshot["cases"][number] | undefined; authority: string; apiUrl: string; onOpenAlert: (alertId: string) => void; onChanged: () => void; onBack: () => void }): React.JSX.Element {
  const [tab, setTab] = useState<IncidentTab>("Timeline");
  const [askOpen, setAskOpen] = useState(false);
  return <EvidenceProvider items={conversationEvidence(incident)}>
    <button className="back-button" onClick={onBack}>← All incidents</button>
    <header className="incident-header"><div><div className="incident-title-row"><MonoChip>{incident.id}</MonoChip><StatusBadge label={incident.severity} tone="danger" /><IncidentStateBadge state={incident.state} /></div><h1>{incident.title}</h1><p>{incident.service} · {incident.environment} · detected {incident.detected_at}</p></div><div className="incident-controls"><span className="lease-health"><span className="status-dot" />Owned by {incident.owner} · {incident.feed.lease}</span><button className="ask-open-button" aria-expanded={askOpen} onClick={() => setAskOpen((open) => !open)}><MessageSquare size={15} strokeWidth={1.75} aria-hidden="true" />Ask the ledger</button></div></header>
    <RecoveryTimingRail phases={incident.phase_rail} />
    <OperatorBrief incident={incident} />
    <RelatedAlertsPanel incident={incident} apiUrl={apiUrl} onOpenAlert={onOpenAlert} />
    <div className="tabs" role="tablist" aria-label="Incident views">{incidentTabs.map((item) => <button key={item} role="tab" aria-selected={tab === item} className={tab === item ? "tab active" : "tab"} onClick={() => setTab(item)}>{item}</button>)}</div>
    <section role="tabpanel" className="tab-panel">
      {tab === "Timeline" ? <Timeline incident={incident} /> : tab === "Evidence" ? <Evidence incident={incident} /> : tab === "Actions" ? <Actions actions={incident.actions} authority={authority} apiUrl={apiUrl} environment={incident.environment} onChanged={onChanged} /> : tab === "Verification" ? <VerificationPanel incident={incident} /> : caseRecord ? <PermanentRepair caseRecord={caseRecord} authority={authority} apiUrl={apiUrl} onChanged={onChanged} /> : <section className="state-page"><h2>Case not opened yet</h2><p>A Reliability Case appears only after mitigation is independently verified.</p></section>}
    </section>
    {askOpen && (
      <AskRail
        recordType="incident"
        recordId={incident.id}
        apiUrl={apiUrl}
        authority={authority}
        renderApprovalPart={(actionId) => {
          const action = incident.actions.find((candidate) => candidate.id === actionId);
          return action
            ? <ActionCard action={action} authority={authority} apiUrl={apiUrl} environment={incident.environment} onChanged={onChanged} />
            : <p className="ask-withheld">The referenced action is not visible to this reader.</p>;
        }}
        onClose={() => setAskOpen(false)}
      />
    )}
  </EvidenceProvider>;
}

function ReleaseEvidence({ release }: { release: ConsoleSnapshot["release"] }): React.JSX.Element {
  const cloudComplete = release.cloud === "BOUND_GCP_EVIDENCE_COMPLETE";
  return <><PageHeader eyebrow="Competition release" title="Release evidence" description={cloudComplete ? "Exact, hash-validated GCP receipts are bound to this immutable deployment." : "Only deterministic receipts mark scenarios passed. Cloud claims remain unverified until deployed."} /><div className="release-summary"><article className="card"><p className="eyebrow">Current gate</p><h2>{release.gate}</h2><p>{release.commit}{release.deployment_id ? ` · ${release.deployment_id}` : ""}</p></article><article className={cloudComplete ? "card" : "card danger-outline"}><p className="eyebrow">Google Cloud proof</p><h2>{release.cloud}</h2><p>{cloudComplete ? "Bound platform preflight and the exact S1–S6 cloud evidence set are complete. Local and submission gates remain separate." : "Deployment, platform preflight, and the complete S1–S6 receipt set are still required."}</p></article></div><section className="scenario-list"><div className="section-heading"><div><p className="eyebrow">Acceptance scenarios</p><h2>S1–S6 evidence matrix</h2></div></div>{release.scenarios.map((scenario) => { const passed = scenario.status.includes("PASS"); return <article key={scenario.id}><span className="scenario-id">{scenario.id}</span><div><h3>{scenario.name}</h3><p>{passed ? "Hash-validated receipt matches the displayed immutable release." : "No promotable bound receipt is available for this scenario."}</p></div><StatusBadge label={scenario.status} tone={passed ? "info" : scenario.status.includes("NOT") ? "warning" : "neutral"} /></article>; })}</section></>;
}
