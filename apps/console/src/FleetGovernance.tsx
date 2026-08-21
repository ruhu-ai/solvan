/** The Fleet governance evidence tabs: memory candidates by queue, security
 *  events by the control that refused, and the immutable audit sequence.
 *  All three satisfy PR-044 — inspection with exact scope and provenance,
 *  never raw sensitive content.
 */
import { useState } from "react";
import { Search } from "lucide-react";
import type { ConsoleSnapshot, StatusTone } from "./types";
import { LabelValue, StatusBadge } from "./components";
import { TimeWindowFilter, formatRecordedAt, withinTimeWindow } from "./fleetFormat";
import type { TimeWindow } from "./fleetFormat";

const memoryQueues = ["ALL", "PENDING", "QUARANTINED", "REJECTED", "PROMOTED", "EXPIRED"] as const;

function memoryTone(status: string): StatusTone {
  if (status === "PROMOTED") return "provenance";
  if (status === "REJECTED") return "danger";
  if (status === "QUARANTINED") return "warning";
  if (status === "EXPIRED") return "neutral";
  return "info";
}

export function MemoryView({ memory }: { memory: ConsoleSnapshot["fleet"]["memory"] }): React.JSX.Element {
  const [queue, setQueue] = useState<(typeof memoryQueues)[number]>("ALL");
  const [query, setQuery] = useState("");
  const [timeWindow, setTimeWindow] = useState<TimeWindow>("ALL");
  if (memory.length === 0) {
    return <div className="card skills-empty-state"><strong>No memory candidate exists in this scope.</strong><span>Promotion-gated learning writes candidates here as investigations conclude; nothing has been proposed yet.</span></div>;
  }
  const visible = memory.filter((item) => {
    const haystack = `${item.id} ${item.type} ${item.purpose} ${item.classification} ${item.decision} ${item.scope}`.toLowerCase();
    return (queue === "ALL" || item.status === queue)
      && (!query.trim() || haystack.includes(query.trim().toLowerCase()))
      && withinTimeWindow(item.created_at, timeWindow);
  });
  return <>
    <section className="card">
      <div className="section-heading"><div><p className="eyebrow">Promotion-gated learning</p><h2>Memory candidates</h2><p>Context ranking only — a memory is never permission. Lists carry metadata; candidate content stays scope-bound.</p></div><StatusBadge label={`${visible.length} of ${memory.length} shown`} tone="neutral" /></div>
      <div className="skills-catalog-toolbar" role="search">
        <label className="skills-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Search memory candidates</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search purpose, classification, decision, or scope" /></label>
        <div className="skills-attention-filter" role="group" aria-label="Filter by queue">{memoryQueues.map((value) => <button key={value} type="button" aria-pressed={queue === value} className={queue === value ? "active" : ""} onClick={() => setQueue(value)}>{value === "ALL" ? "All" : value.charAt(0) + value.slice(1).toLowerCase()}</button>)}</div>
        <TimeWindowFilter value={timeWindow} onChange={setTimeWindow} label="Filter memory candidates by time" />
      </div>
    </section>
    {visible.length === 0
      ? <div className="card skills-empty-state"><Search size={20} /><strong>No memory candidate matches these filters.</strong></div>
      : <div className="memory-list">{visible.map((item) => <article className="memory-card" key={item.id}>
        <div className="section-heading"><div><p className="eyebrow">{item.type} · {item.purpose}</p><h2>{item.id}</h2></div><StatusBadge label={item.status} tone={memoryTone(item.status)} machine={item.decision} /></div>
        <dl>
          <LabelValue label="Decision" value={item.decision} />
          <LabelValue label="Exact scope" value={item.scope} />
          <LabelValue label="Classification" value={item.classification} />
          <LabelValue label="Review requirement" value={item.review} />
          <LabelValue label="Proposed" value={formatRecordedAt(item.created_at)} />
          <LabelValue label="Retention" value={item.retention} />
          <LabelValue label="Sources" value={`${item.source_count} resolvable references`} />
        </dl>
      </article>)}</div>}
  </>;
}

const securitySeverities = ["ALL", "CRITICAL", "HIGH", "WARNING", "INFO"] as const;

function securityTone(severity: string): StatusTone {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "WARNING") return "warning";
  return "neutral";
}

export function SecurityView({ events }: { events: ConsoleSnapshot["fleet"]["security"] }): React.JSX.Element {
  const [severity, setSeverity] = useState<(typeof securitySeverities)[number]>("ALL");
  const [query, setQuery] = useState("");
  const [timeWindow, setTimeWindow] = useState<TimeWindow>("ALL");
  if (events.length === 0) {
    return <div className="card skills-empty-state"><strong>No security event is recorded in this scope.</strong><span>A Gateway denial, Model Armor block, or scope refusal writes an event here the moment it happens.</span></div>;
  }
  const visible = events.filter((event) => {
    const haystack = `${event.control} ${event.event} ${event.actor} ${event.destination} ${event.incident ?? ""} ${event.summary}`.toLowerCase();
    return (severity === "ALL" || event.severity === severity)
      && (!query.trim() || haystack.includes(query.trim().toLowerCase()))
      && withinTimeWindow(event.occurred_at, timeWindow);
  });
  const groups: Array<{ control: string; items: typeof events }> = [];
  for (const event of visible) {
    const group = groups.find((candidate) => candidate.control === event.control);
    if (group) group.items.push(event);
    else groups.push({ control: event.control, items: [event] });
  }
  return <>
    <section className="card">
      <div className="section-heading"><div><p className="eyebrow">Enforced controls</p><h2>Security events</h2><p>What each control denied and why, grouped by the control that refused. The blocked content itself is never rendered.</p></div><StatusBadge label={`${visible.length} of ${events.length} shown`} tone="neutral" /></div>
      <div className="skills-catalog-toolbar" role="search">
        <label className="skills-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Search security events</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incident, agent, destination, or control" /></label>
        <div className="skills-attention-filter" role="group" aria-label="Filter by severity">{securitySeverities.map((value) => <button key={value} type="button" aria-pressed={severity === value} className={severity === value ? "active" : ""} onClick={() => setSeverity(value)}>{value === "ALL" ? "All" : value.charAt(0) + value.slice(1).toLowerCase()}</button>)}</div>
        <TimeWindowFilter value={timeWindow} onChange={setTimeWindow} label="Filter security events by time" />
      </div>
    </section>
    {visible.length === 0
      ? <div className="card skills-empty-state"><Search size={20} /><strong>No security event matches these filters.</strong></div>
      : groups.map((group) => <section key={group.control} className="skills-group" aria-label={group.control}>
        <h3 className="skills-group-title">{group.control.replaceAll("_", " ")}</h3>
        <div className="security-grid">{group.items.map((event) => <article className="security-card" key={event.id ?? event.trace}>
          <div><StatusBadge label={event.severity} tone={securityTone(event.severity)} machine={event.event} /><span>{formatRecordedAt(event.occurred_at)}</span></div>
          <h2>{event.summary}</h2>
          <dl>
            <LabelValue label="Actor" value={event.actor} />
            <LabelValue label="Denied destination" value={event.destination} />
            {event.incident && <LabelValue label="Incident" value={event.incident} />}
            {event.policy && <LabelValue label="Policy" value={event.policy} />}
            <LabelValue label="Trace" value={event.trace} />
          </dl>
        </article>)}</div>
      </section>)}
  </>;
}

/** The console surface that displays this stream's record, when one exists.
 *  Links go to the surface, which enforces its own read authorization;
 *  streams without a surface stay citable text rather than dead anchors. */
function auditStreamHref(streamType: string, streamId: string): string | null {
  if (streamType === "INCIDENT") return `/?incident=${encodeURIComponent(streamId)}`;
  if (streamType === "ALERT_EPISODE") return `/?alert=${encodeURIComponent(streamId)}`;
  if (streamType === "MEMORY_CANDIDATE") return "/?fleet=memory";
  if (streamType === "SECURITY_EVENT") return "/?fleet=security";
  if (streamType === "AGENT_RUN") return "/?fleet=agents";
  return null;
}

export function AuditView({ events }: { events: ConsoleSnapshot["fleet"]["audit"] }): React.JSX.Element {
  const [query, setQuery] = useState("");
  const [stream, setStream] = useState("ALL");
  const [timeWindow, setTimeWindow] = useState<TimeWindow>("ALL");
  if (events.length === 0) {
    return <div className="card skills-empty-state"><strong>No audit event is recorded in this scope.</strong><span>Every governed decision appends to this immutable sequence; nothing has happened here yet.</span></div>;
  }
  // Field access tolerates an API one revision older than this console: the
  // two deploy as separate services, and rows without the stream columns must
  // degrade to "—", never blank the tab.
  const streams = ["ALL", ...new Set(events.map((event) => event.stream_type).filter(Boolean))];
  const visible = events.filter((event) => {
    const haystack = `${event.principal} ${event.event} ${event.stream_type ?? ""} ${event.stream_id ?? ""} ${event.decision ?? ""}`.toLowerCase();
    return (stream === "ALL" || event.stream_type === stream)
      && (!query.trim() || haystack.includes(query.trim().toLowerCase()))
      && withinTimeWindow(event.time, timeWindow);
  });
  // Below the stacked-table breakpoint the header row is clipped and each cell
  // prints `attr(data-label)`. Without these the audit sequence degraded to
  // unlabelled strings per row.
  return <>
    <section className="card">
      <div className="section-heading"><div><p className="eyebrow">Immutable sequence</p><h2>Audit events</h2><p>Sequence-ordered and append-only. Stream, decision, and trace identifiers cite the records a reader can open when authorized.</p></div><StatusBadge label={`${visible.length} of ${events.length} shown`} tone="neutral" /></div>
      <div className="skills-catalog-toolbar" role="search">
        <label className="skills-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Search audit events</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search actor, event, stream, or decision" /></label>
        <div className="skills-attention-filter" role="group" aria-label="Filter by stream">{streams.map((value) => <button key={value} type="button" aria-pressed={stream === value} className={stream === value ? "active" : ""} onClick={() => setStream(value)}>{value === "ALL" ? "All streams" : value.replaceAll("_", " ")}</button>)}</div>
        <TimeWindowFilter value={timeWindow} onChange={setTimeWindow} label="Filter audit events by time" />
      </div>
    </section>
    {visible.length === 0
      ? <div className="card skills-empty-state"><Search size={20} /><strong>No audit event matches these filters.</strong></div>
      : <section className="card responsive-table"><table><caption>Immutable audit sequence</caption><thead><tr><th scope="col">Sequence</th><th scope="col">Time</th><th scope="col">Principal</th><th scope="col">Event</th><th scope="col">Stream</th><th scope="col">Decision</th><th scope="col">Safe payload hash</th></tr></thead><tbody>{visible.map((event) => <tr key={event.sequence}><td data-label="Sequence"><code>{event.sequence}</code></td><td data-label="Time">{Number.isNaN(new Date(event.time).getTime()) ? event.time : new Date(event.time).toLocaleString()}</td><td data-label="Principal">{event.principal}</td><td data-label="Event">{event.event}</td><td data-label="Stream">{event.stream_type ? <>{event.stream_type.replaceAll("_", " ")} · {(() => { const href = auditStreamHref(event.stream_type, event.stream_id); return href ? <a href={href}><code>{event.stream_id}</code></a> : <code>{event.stream_id}</code>; })()}</> : "—"}</td><td data-label="Decision">{event.decision ? <code>{event.decision}</code> : "—"}</td><td data-label="Safe payload hash"><code>{event.hash}</code></td></tr>)}</tbody></table></section>}
  </>;
}
