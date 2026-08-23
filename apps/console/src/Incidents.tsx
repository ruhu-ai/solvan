/** The incident queue and the read surfaces of one incident.
 *
 *  The organising rule here is that a citation must resolve. Every evidence ref
 *  shown anywhere on an incident is looked up in the incident's own evidence
 *  index and rendered with its kind, source, window and freshness; a ref with no
 *  record renders as unresolved rather than as a confident-looking chip.
 */
import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Code,
  FileCog,
  FileText,
  FlaskConical,
  Receipt,
  Route,
  ScrollText,
  Search,
  X,
  type LucideIcon,
} from "lucide-react";
import type { EvidenceItem, EvidenceKind, Finding, Incident, StatusTone } from "./types";
import { LabelValue, MonoChip, PageHeader, StatusBadge, statusIcon } from "./components";
import { Timeseries } from "./Timeseries";

const evidenceIcons: Record<EvidenceKind | "record", LucideIcon> = {
  metric: Activity,
  log: ScrollText,
  trace: Route,
  config: FileCog,
  code: Code,
  receipt: Receipt,
  synthetic: FlaskConical,
  record: FileText,
};

const evidenceKindLabels: Record<EvidenceKind | "record", string> = {
  metric: "Metric",
  log: "Log",
  trace: "Trace",
  config: "Config",
  code: "Code",
  receipt: "Receipt",
  synthetic: "Synthetic probe",
  record: "Record",
};

type EvidenceLookup = {
  resolve: (ref: string) => EvidenceItem | undefined;
  open: (ref: string) => void;
};

const EvidenceContext = createContext<EvidenceLookup>({ resolve: () => undefined, open: () => {} });

/** Holds the resolved evidence index and the one open record, so every citation
 *  on the page opens the same contextual drawer. */
export function EvidenceProvider({ items, children }: { items: EvidenceItem[]; children: React.ReactNode }): React.JSX.Element {
  const [openRef, setOpenRef] = useState<string | null>(null);
  const byRef = useMemo(() => new Map(items.map((item) => [item.ref, item])), [items]);
  const lookup = useMemo<EvidenceLookup>(
    () => ({ resolve: (ref) => byRef.get(ref), open: (ref) => setOpenRef(ref) }),
    [byRef],
  );
  const open = openRef === null ? undefined : byRef.get(openRef);
  return (
    <EvidenceContext.Provider value={lookup}>
      {children}
      {open && <EvidenceDrawer item={open} onClose={() => setOpenRef(null)} />}
    </EvidenceContext.Provider>
  );
}

function EvidenceDrawer({ item, onClose }: { item: EvidenceItem; onClose: () => void }): React.JSX.Element {
  const Icon = evidenceIcons[item.kind] ?? FileText;
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    // The drawer is a dialog: it takes focus so a keyboard reader is not left
    // behind on the page, and Escape always dismisses it.
    closeRef.current?.focus();
    function onKey(event: KeyboardEvent): void {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-scrim" onClick={onClose} aria-hidden="true" />
      <aside className="evidence-drawer" role="dialog" aria-modal="true" aria-labelledby="evidence-drawer-title">
        <header>
          <div>
            <p className="eyebrow">{evidenceKindLabels[item.kind] ?? "Record"}</p>
            <h2 id="evidence-drawer-title">{item.label}</h2>
          </div>
          <button ref={closeRef} className="icon-button" onClick={onClose} aria-label="Close evidence">
            <X size={18} strokeWidth={1.75} />
          </button>
        </header>
        <p className="drawer-kind">
          <span className="evidence-icon" aria-hidden="true"><Icon size={16} strokeWidth={1.75} /></span>
          {item.source}
        </p>
        <dl>
          <LabelValue label="Evidence ID" value={<code>{item.ref}</code>} />
          <LabelValue label="Observation window" value={item.window} />
          <LabelValue label="Freshness" value={item.freshness} />
          <LabelValue label="Classification" value={item.classification} />
          <LabelValue label="Stored content" value={<code>{item.content_ref}</code>} />
        </dl>
        <p className="drawer-note">
          Solvan shows the stored reference and its provenance. Raw content is
          fetched only through an authorized, redacted read.
        </p>
      </aside>
    </>
  );
}

/** A citation. Carries its kind and a human label, and opens the record.
 *  `compact` drops the label where the surrounding line already states the
 *  fact, so the chip stays an address rather than repeating the sentence. */
export function SourceChip({ refId, compact = false }: { refId: string; compact?: boolean }): React.JSX.Element {
  const { resolve, open } = useContext(EvidenceContext);
  const item = resolve(refId);
  if (!item) {
    return (
      <span className="source-chip unresolved" title="No stored evidence record resolves this reference">
        <FileText size={13} strokeWidth={1.75} aria-hidden="true" />
        {refId} · unresolved
      </span>
    );
  }
  const Icon = evidenceIcons[item.kind] ?? FileText;
  return (
    <button
      className={compact ? "source-chip compact" : "source-chip"}
      onClick={() => open(refId)}
      title={`${item.label} — ${item.source} · ${item.window}`}
      aria-label={`Open evidence ${item.ref}: ${item.label}`}
    >
      <Icon size={13} strokeWidth={1.75} aria-hidden="true" />
      {!compact && <span className="chip-label">{item.label}</span>}
      <span className="chip-ref">{item.ref}</span>
    </button>
  );
}

function EvidenceCount({ refs }: { refs: string[] }): React.JSX.Element | null {
  const { resolve } = useContext(EvidenceContext);
  const resolved = refs.filter((ref) => resolve(ref) !== undefined).length;
  if (refs.length === 0) return null;
  return (
    <span className="evidence-count">
      {resolved} of {refs.length} {refs.length === 1 ? "citation" : "citations"} resolved
    </span>
  );
}

export function IncidentStateBadge({ state }: { state: string }): React.JSX.Element {
  const labels: Record<string, string> = {
    DETECTED: "Detected",
    TRIAGING: "Triaging",
    INVESTIGATING: "Investigating",
    DIAGNOSING: "Diagnosing",
    MITIGATION_PROPOSED: "Fix proposed",
    AWAITING_APPROVAL: "Awaiting your approval",
    MITIGATING: "Applying fix",
    VERIFYING_MITIGATION: "Verifying recovery",
    MITIGATED: "Service restored · repair open",
    ESCALATED: "Escalated to humans",
    RESOLVED: "Resolved",
    CLOSED: "Closed",
  };
  const tone: StatusTone =
    state === "MITIGATED" || state === "RESOLVED" || state === "CLOSED"
      ? "success"
      : state === "AWAITING_APPROVAL" || state === "ESCALATED"
        ? "warning"
        : "agent";
  // A settled state takes the square glyph of specification 10 section 5, so it
  // is a different shape from one still in flight. MITIGATED is not terminal:
  // the service is restored but the repair is still open.
  const terminal = state === "RESOLVED" || state === "CLOSED";
  return <StatusBadge label={labels[state] ?? state} tone={tone} machine={state} terminal={terminal} />;
}

export function IncidentsList({ incidents, openIncident }: { incidents: Incident[]; openIncident: (id: string) => void }): React.JSX.Element {
  const [query, setQuery] = useState("");
  const [waitingOnly, setWaitingOnly] = useState(false);
  const needle = query.trim().toLowerCase();
  const visible = incidents.filter((incident) => {
    if (waitingOnly && !incident.waiting_on_human) return false;
    if (needle === "") return true;
    return [incident.id, incident.service, incident.state, incident.title, incident.owner]
      .join(" ")
      .toLowerCase()
      .includes(needle);
  });
  const waiting = incidents.filter((incident) => incident.waiting_on_human).length;
  return (
    <>
      <PageHeader
        eyebrow="Incident queue"
        title="Incidents"
        description="Committed operational state ordered by severity and age."
        actions={
          <button
            className={waitingOnly ? "secondary-button active" : "secondary-button"}
            aria-pressed={waitingOnly}
            onClick={() => setWaitingOnly((value) => !value)}
          >
            Waiting on a person ({waiting})
          </button>
        }
      />
      <section className="card table-card">
        <div className="table-toolbar">
          <label>
            <span className="visually-hidden">Search incidents</span>
            <span className="search-field">
              <Search size={15} strokeWidth={1.75} aria-hidden="true" />
              <input type="search" placeholder="ID, service, or state" value={query} onChange={(event) => setQuery(event.target.value)} />
            </span>
          </label>
          <span>
            {visible.length} of {incidents.length} {incidents.length === 1 ? "incident" : "incidents"}
          </span>
        </div>
        <div className="responsive-table">
          <table className="queue-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Service</th>
                <th>State</th>
                <th>Customer impact</th>
                <th>Current owner</th>
                <th>Age</th>
                <th>Next action</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((incident) => (
                <tr key={incident.id} className={incident.waiting_on_human ? "row-needs-human" : undefined} onClick={() => openIncident(incident.id)}>
                  <td data-label="ID"><button className="table-link" onClick={() => openIncident(incident.id)}>{incident.id}</button></td>
                  <td data-label="Severity"><StatusBadge label={incident.severity} tone="danger" /></td>
                  <td data-label="Service">{incident.service}</td>
                  <td data-label="State"><IncidentStateBadge state={incident.state} /></td>
                  <td data-label="Customer impact">{incident.impact_summary}</td>
                  <td data-label="Current owner">{incident.owner}</td>
                  <td data-label="Age">{incident.age}</td>
                  <td data-label="Next action">
                    {incident.waiting_on_human ? <strong>{incident.next_action}</strong> : incident.next_action}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {visible.length === 0 && <p className="empty-copy">No incident matches this filter.</p>}
      </section>
    </>
  );
}

export function RecoveryTimingRail({ phases }: { phases: Incident["phase_rail"] }): React.JSX.Element | null {
  if (phases.length === 0) return null;
  return (
    <ol className="timing-rail" aria-label="Time spent in each phase of the recovery loop">
      {phases.map((phase) => (
        <li
          key={phase.name}
          className={[
            "timing-phase",
            phase.state === "current" ? "current" : "",
            // Human latency is called out because it is the one interval Solvan
            // does not control and must never be mistaken for system time.
            phase.name === "Await approval" ? "human" : "",
          ].filter(Boolean).join(" ")}
        >
          <span className="phase-name">{phase.name}</span>
          <span className="phase-duration">{phase.duration}</span>
          {phase.state === "current" && <span className="visually-hidden">in progress</span>}
        </li>
      ))}
    </ol>
  );
}

function councilStatusTone(status: string): StatusTone {
  if (status === "COMPLETE") return "success";
  if (status === "ACTIVE" || status === "RUNNING") return "agent";
  if (status === "PROPOSED" || status === "AWAITING_APPROVAL") return "warning";
  return "info";
}

function causalStatusTone(status: Incident["causal_chain"][number]["status"]): StatusTone {
  if (status === "verified") return "success";
  if (status === "inferred") return "warning";
  if (status === "action") return "info";
  return "provenance";
}

function AgentCouncil({ seats }: { seats: Incident["agent_council"] }): React.JSX.Element {
  return <section className="card agent-council" aria-labelledby="agent-council-title">
    <div className="section-heading"><div><p className="eyebrow">Incident team</p><h2 id="agent-council-title">Who is working this incident</h2><p>Each seat has a named identity and bounded responsibility. The coordinator alone dispatches durable work.</p></div><span className="muted">No agent has direct mutation authority</span></div>
    <div className="agent-council-grid">{seats.map((seat) => <article className="agent-seat" key={seat.identity}>
      <div className="agent-seat-top"><strong>{seat.name}</strong><StatusBadge label={seat.status.replaceAll("_", " ")} tone={councilStatusTone(seat.status)} machine={seat.status} /></div>
      <p>{seat.role}</p>
      <span className="agent-seat-detail">{seat.detail}</span>
      <dl><div><dt>Identity</dt><dd><code>{seat.identity}</code></dd></div><div><dt>Budget</dt><dd>{seat.budget}</dd></div></dl>
    </article>)}</div>
  </section>;
}

function CausalChain({ steps }: { steps: Incident["causal_chain"] }): React.JSX.Element {
  return <section className="card causal-chain" aria-labelledby="causal-chain-title">
    <div className="section-heading"><div><p className="eyebrow">Causal chain</p><h2 id="causal-chain-title">What happened and what happens next</h2><p>Observed facts, proposed actions, and independent verification are shown as different states.</p></div><span className="muted">Evidence-backed sequence</span></div>
    <ol className="causal-chain-list">{steps.map((step, index) => <li className="causal-step" key={`${step.label}-${step.detail}`}>
      <span className="causal-marker" aria-hidden="true">{index + 1}</span>
      <div><div className="causal-step-heading"><strong>{step.label}</strong><StatusBadge label={step.status} tone={causalStatusTone(step.status)} /></div><p>{step.detail}</p><small>{step.source ?? "Durable projection"}</small></div>
    </li>)}</ol>
  </section>;
}

/** Impact with shape: one row per measured signal, each naming what it happened
 *  to. A single unattributed percentage cannot be triaged. */
function ImpactBlock({ brief }: { brief: Incident["brief"] }): React.JSX.Element {
  if (brief.impact_lines.length === 0) {
    return <p className="impact-fallback">{brief.impact}</p>;
  }
  return (
    <div className="impact-block">
      <p className="impact-window">{brief.customer_window}</p>
      <ul className="impact-lines">
        {brief.impact_lines.map((line) => (
          <li key={`${line.metric}-${line.scope}`}>
            <strong>{line.metric}</strong>
            <code>{line.scope}</code>
            <span>{line.detail}</span>
            {line.citation && <SourceChip refId={line.citation} compact />}
          </li>
        ))}
      </ul>
      {brief.data_loss && <p className="impact-dataloss">{brief.data_loss}</p>}
    </div>
  );
}

export function OperatorBrief({ incident }: { incident: Incident }): React.JSX.Element {
  return (
    <section className="operator-brief" aria-labelledby="operator-brief-title">
      <div className="brief-top">
        <div>
          <p className="eyebrow">Operator brief</p>
          <h2 id="operator-brief-title">{incident.brief.situation}</h2>
        </div>
        <span className="freshness">{incident.brief.freshness}</span>
      </div>
      <ImpactBlock brief={incident.brief} />
      <div className="brief-columns">
        <LabelValue label="Last verified fact" value={incident.brief.last_verified} />
        <LabelValue label="Diagnosis" value={incident.brief.root_cause} />
        <LabelValue label="Human attention" value={incident.brief.attention} />
        <LabelValue label="Next step / owner" value={incident.brief.next} />
      </div>
      <div className="provenance-row">
        {incident.brief.citations.map((citation) => <SourceChip key={citation} refId={citation} />)}
        {incident.brief.memories.map((memory) => <span className="memory-chip" key={memory}>Recalled · {memory}</span>)}
      </div>
    </section>
  );
}

export function Timeline({ incident }: { incident: Incident }): React.JSX.Element {
  return <div className="incident-timeline-view"><AgentCouncil seats={incident.agent_council} /><CausalChain steps={incident.causal_chain} /><div className="content-with-aside"><section><div className="section-heading"><div><p className="eyebrow">Committed event feed</p><h2>Timeline</h2></div><span className="muted">sequence {incident.feed.sequence} · exact order</span></div><ol className="timeline">{incident.timeline.map((item) => <li key={`${item.time}-${item.event}`}><div className={`timeline-marker status-${item.kind}`} aria-hidden="true">{statusIcon(item.kind)}</div><article><div className="event-eyebrow"><strong>{item.actor}</strong><time>{item.time} UTC</time></div><p>{item.event}</p><code>{item.state}</code></article></li>)}</ol></section><aside className="context-card"><p className="eyebrow">Current ownership</p><h3>{incident.owner}</h3><p>The incident is mitigated but remains open until its permanent repair is independently verified.</p><dl><div><dt>Workflow version</dt><dd>{incident.workflow_version}</dd></div><div><dt>Last event</dt><dd>{incident.feed.last_event}</dd></div><div><dt>Lease</dt><dd>{incident.feed.lease}</dd></div></dl></aside></div></div>;
}

function planStepTone(status: string): StatusTone {
  if (status === "COMPLETED" || status === "SUCCEEDED") return "success";
  if (status === "RUNNING" || status === "DISPATCHED") return "agent";
  if (status === "AWAITING_APPROVAL" || status === "BLOCKED") return "warning";
  if (status === "FAILED") return "danger";
  return "neutral";
}

export function Evidence({ incident }: { incident: Incident }): React.JSX.Element {
  return <div className="evidence-layout"><section className="card full-span"><div className="section-heading"><div><p className="eyebrow">Accepted durable plan · version {incident.plan.version}</p><h2>Investigation map</h2><p>{incident.plan.progress}</p></div></div><ol className="plan-list">{incident.plan.steps.map((step) => <li key={step.name} className={`plan-step plan-${step.status.toLowerCase()}`}><span className="plan-marker" aria-hidden="true">[{step.marker}]</span><div><div className="plan-title"><strong>{step.name}</strong><StatusBadge label={step.status.replaceAll("_", " ")} tone={planStepTone(step.status)} /></div><p>{step.purpose}</p><dl className="inline-facts"><div><dt>Agent</dt><dd>{step.agent}</dd></div><div><dt>Depends on</dt><dd>{step.dependencies}</dd></div><div><dt>Budget</dt><dd>{step.budget}</dd></div><div><dt>Evidence</dt><dd>{step.evidence_delta}</dd></div><div><dt>Trace</dt><dd>{step.trace}</dd></div></dl></div></li>)}</ol></section>
    {incident.guidance && <GuidanceChecklist guidance={incident.guidance} />}
    {/* Under the findings, not above them: the verified claim is the evidence
        and the axis shows the shape behind it. */}
    <section className="card full-span"><div className="section-heading"><div><p className="eyebrow">Signal over the incident</p><h2>Observed window</h2><p>Composed from consecutive bounded evidence items. Gaps between them are not interpolated.</p></div></div><Timeseries incident={incident} /></section>
    <FindingGroup title="Validated" description="Every statement resolves to stored evidence." findings={incident.findings.validated} validated />
    <FindingGroup title="Inferred — not validated" description="Context for investigation only; excluded from the last verified fact." findings={incident.findings.inferred} />
    <EvidenceLedger items={incident.evidence_index} />
    <section className="card full-span"><div className="section-heading"><div><p className="eyebrow">Diagnosis</p><h2>Hypotheses</h2></div></div><div className="hypothesis-grid">{incident.hypotheses.map((item) => <article className="hypothesis-card" key={item.label}><div><StatusBadge label={item.state} tone={item.state === "CONFIRMED" ? "provenance" : "danger"} /><span className="confidence">{item.confidence} · <code>{item.score}</code></span></div><h3>{item.label}</h3><p>Evidence rule: {item.rule}</p></article>)}</div></section></div>;
}

function GuidanceChecklist({ guidance }: { guidance: NonNullable<Incident["guidance"]> }): React.JSX.Element {
  return <section className="card full-span guidance-checklist" aria-labelledby="incident-guidance-title">
    <div className="section-heading"><div><p className="eyebrow">Selected operational guidance · {guidance.role.toLowerCase()}</p><h2 id="incident-guidance-title">{guidance.name}</h2><p>Step status comes from registered predicates over committed records, never Agent narration.</p></div><StatusBadge label={guidance.revision} tone="info" /></div>
    <dl className="inline-facts guidance-binding"><div><dt>Selection</dt><dd><code>{guidance.selection_id}</code></dd></div><div><dt>Frozen profile</dt><dd><code>{guidance.profile}</code></dd></div><div><dt>Revision digest</dt><dd><code>{guidance.revision_hash}</code></dd></div></dl>
    <ol>{guidance.steps.map((step) => <li key={step.key}><div className="guidance-step-title"><div><span className="guidance-kind">{step.kind}</span><strong>{step.title}</strong></div><StatusBadge label={step.status.replaceAll("_", " ")} tone={planStepTone(step.status)} machine={step.status} /></div><dl className="inline-facts"><div><dt>Predicate</dt><dd><code>{step.predicate}</code></dd></div><div><dt>Tool receipts</dt><dd>{step.tool_receipts.length ? step.tool_receipts.map((receipt) => <code key={receipt}>{receipt}</code>) : "None"}</dd></div>{step.reason && <div><dt>Why blocked</dt><dd>{step.reason}</dd></div>}</dl><div className="provenance-row">{step.citations.map((citation) => <SourceChip key={citation} refId={citation} />)}</div></li>)}</ol>
  </section>;
}

/** Every record this incident stands on, counted and typed. */
function EvidenceLedger({ items }: { items: EvidenceItem[] }): React.JSX.Element | null {
  const { open } = useContext(EvidenceContext);
  if (items.length === 0) return null;
  return (
    <section className="card full-span evidence-ledger">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Evidence</p>
          <h2>{items.length} stored {items.length === 1 ? "record" : "records"}</h2>
          <p>Each was read once, within a bounded window, and is addressable by ID.</p>
        </div>
      </div>
      <ul className="evidence-ledger-list">
        {items.map((item) => {
          const Icon = evidenceIcons[item.kind] ?? FileText;
          return (
            <li key={item.ref}>
              <button onClick={() => open(item.ref)}>
                <span className="evidence-icon" aria-hidden="true"><Icon size={16} strokeWidth={1.75} /></span>
                <span className="evidence-ledger-label">
                  <strong>{item.label}</strong>
                  <small>{item.source} · {item.window} · {item.freshness}</small>
                </span>
                <MonoChip>{item.ref}</MonoChip>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function FindingGroup({ title, description, findings, validated = false }: { title: string; description: string; findings: Finding[]; validated?: boolean }): React.JSX.Element {
  return (
    <section className={validated ? "finding-group card" : "finding-group card inferred-group"}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">{title}</p>
          <h2>{findings.length} finding{findings.length === 1 ? "" : "s"}</h2>
          <p>{description}</p>
        </div>
      </div>
      {findings.map((finding) => (
        <article className="finding-block" key={finding.title}>
          <div className="event-eyebrow">
            <strong>{finding.source}</strong>
            <span>{validated ? <EvidenceCount refs={finding.citations} /> : "model inference"}</span>
          </div>
          <h3>{finding.title}</h3>
          <p>{finding.statement}</p>
          <div className="provenance-row">{finding.citations.map((citation) => <SourceChip key={citation} refId={citation} />)}</div>
        </article>
      ))}
    </section>
  );
}
