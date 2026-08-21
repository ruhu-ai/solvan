/** The Agents tab: the registered catalog, the one seat that can mutate
 *  production, and each agent's durable run ledger.
 */
import { useState } from "react";
import { ChevronLeft, Search, Workflow, Wrench } from "lucide-react";
import type { ConsoleSnapshot, StatusTone } from "./types";
import { LabelValue, MonoChip, StatusBadge } from "./components";
import { TimeWindowFilter, formatRecordedAt, withinTimeWindow } from "./fleetFormat";
import type { TimeWindow } from "./fleetFormat";

export function AgentCatalog({ agents, seats, runs }: { agents: ConsoleSnapshot["fleet"]["agents"]; seats: ConsoleSnapshot["fleet"]["deterministic_services"]; runs: AgentRun[] }): React.JSX.Element {
  const deployed = agents.filter((agent) => agent.deployment === "DEPLOYED").length;
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const selected = agents.find((agent) => agent.key === selectedKey) ?? null;
  if (selected) {
    return <AgentDetail agent={selected} runs={runs.filter((run) => run.agent_key === selected.key)} onClose={() => setSelectedKey(null)} />;
  }
  // Framework, model, and manifest version are fleet-level facts in the
  // manifest's platform block — one sentence above the grid, not six
  // identical lines on six cards.
  const platform = agents.map((agent) => agent.manifest).find(Boolean);
  return <>
    {/* Deployment is uniform across the fleet, so it is stated once. Six cards
        each reading "Implemented · not deployed" is one fact rendered six
        times; a card carries a badge only where it departs from the fleet. */}
    <p className="fleet-note" role="status">{deployed === 0
      ? `${agents.length} agents registered with a bounded capability profile. None is deployed: a Registry binding and an Agent Identity are required before any can run.`
      : `${deployed} of ${agents.length} agents deployed.`}{platform && ` Declared on ${platform.framework ?? "an unrecorded framework"} against ${platform.model ?? "an unrecorded model"} · registry manifest ${platform.manifest_version}.`}</p>
    <div className="agent-grid">
      {agents.map((agent) => {
        const runCount = runs.filter((run) => run.agent_key === agent.key).length;
        return <article className="agent-card" key={agent.key}>
          <div className="agent-symbol" aria-hidden="true"><Workflow size={22} strokeWidth={1.75} /></div>
          <div>
            <div className="agent-title"><h2>{agent.name}</h2>{agent.deployment === "DEPLOYED" && <StatusBadge label="Deployed" tone="success" machine={agent.deployment} />}</div>
            <p>{agent.capabilities}</p>
            <dl>
              <LabelValue label="Role" value={agent.execution_role} />
              <LabelValue label="Tools it can reach" value={agent.tool_count === 0 ? "none" : agent.tool_count === agent.declared_tool_count ? String(agent.tool_count) : `${agent.tool_count} of ${agent.declared_tool_count} declared`} />
              {agent.manifest?.owner_department && <LabelValue label="Owner department" value={agent.manifest.owner_department} />}
              {agent.manifest && agent.manifest.discoverable_departments.length > 0 && <LabelValue label="Discoverable by" value={`${agent.manifest.discoverable_departments.join(", ")} · discovery only, never execution`} />}
              {agent.registered_at && <LabelValue label="Registered" value={formatRecordedAt(agent.registered_at)} />}
            </dl>
            {agent.manifest === null && <p className="inline-notice">Registered from a superseded manifest; its facts are withheld until re-registration.</p>}
            {agent.manifest_hash && <p className="agent-manifest"><MonoChip>{agent.manifest_hash.slice(0, 18)}…</MonoChip></p>}
            <div className="dialog-actions"><button className="secondary-button" type="button" onClick={() => setSelectedKey(agent.key)}>Run history{runCount > 0 ? ` · ${runCount}` : ""}</button></div>
          </div>
        </article>;
      })}
      {seats.map((seat) => <article className="agent-card" key={seat.key}>
        <div className="agent-symbol" aria-hidden="true"><Wrench size={22} strokeWidth={1.75} /></div>
        <div>
          <div className="agent-title"><h2>{seat.name}</h2><StatusBadge label="Not model-backed" tone="neutral" /></div>
          <p>{seat.capabilities}</p>
          <dl><LabelValue label="Role" value="Deterministic seat" /><LabelValue label="Allowed operations" value={seat.allowed_operations.join(", ")} /></dl>
        </div>
      </article>)}
    </div>
  </>;
}

type AgentRun = NonNullable<ConsoleSnapshot["fleet"]["agent_runs"]>[number];

/** CREATED/DISPATCHED/RUNNING are one operator question ("is it moving?"),
 *  and CANCELLED/STALE another ("was it fenced?"); the schema's eight states
 *  collapse to the four an operator filters by. */
const runStatusFilters = [
  ["ALL", "All"],
  ["ACTIVE", "Active"],
  ["SUCCEEDED", "Succeeded"],
  ["FAILED", "Failed"],
  ["FENCED", "Fenced"],
] as const;

function runMatchesStatus(run: AgentRun, filter: (typeof runStatusFilters)[number][0]): boolean {
  if (filter === "ALL") return true;
  if (filter === "ACTIVE") return run.status === "CREATED" || run.status === "DISPATCHED" || run.status === "RUNNING";
  if (filter === "SUCCEEDED") return run.status === "SUCCEEDED";
  if (filter === "FAILED") return run.status === "FAILED" || run.status === "TIMED_OUT";
  return run.status === "CANCELLED" || run.status === "STALE";
}

function runStatusTone(status: string): StatusTone {
  if (status === "SUCCEEDED") return "success";
  if (status === "FAILED" || status === "TIMED_OUT") return "danger";
  if (status === "CANCELLED" || status === "STALE") return "warning";
  return "info";
}

function runAnchorLabel(run: AgentRun): string {
  if (run.incident_id) return `Incident ${run.incident_id}`;
  if (run.case_id) return `Reliability case ${run.case_id}`;
  return `Workspace ${run.workspace_id ?? "unanchored"}`;
}

function runTiming(run: AgentRun): string {
  if (run.started_at && run.completed_at) {
    const seconds = Math.max(0, Math.round((new Date(run.completed_at).getTime() - new Date(run.started_at).getTime()) / 1000));
    return `${new Date(run.started_at).toLocaleString()} · ${seconds}s`;
  }
  if (run.started_at) return `Started ${new Date(run.started_at).toLocaleString()}`;
  return `Not started · deadline ${new Date(run.deadline).toLocaleString()}`;
}

function AgentDetail({ agent, runs, onClose }: { agent: ConsoleSnapshot["fleet"]["agents"][number]; runs: AgentRun[]; onClose: () => void }): React.JSX.Element {
  const [statusFilter, setStatusFilter] = useState<(typeof runStatusFilters)[number][0]>("ALL");
  const [query, setQuery] = useState("");
  const [timeWindow, setTimeWindow] = useState<TimeWindow>("ALL");
  const visible = runs.filter((run) => {
    const haystack = `${run.incident_id ?? ""} ${run.case_id ?? ""} ${run.workspace_id ?? ""} ${run.step} ${run.revision} ${run.error_class ?? ""}`.toLowerCase();
    return runMatchesStatus(run, statusFilter)
      && (!query.trim() || haystack.includes(query.trim().toLowerCase()))
      && withinTimeWindow(run.started_at ?? run.deadline, timeWindow);
  });
  const groups: Array<{ anchor: string; items: AgentRun[] }> = [];
  for (const run of visible) {
    const anchor = runAnchorLabel(run);
    const group = groups.find((candidate) => candidate.anchor === anchor);
    if (group) group.items.push(run);
    else groups.push({ anchor, items: [run] });
  }
  return <section className="card skill-detail skill-detail-page" aria-labelledby="agent-detail-title">
    <button className="skill-detail-back" type="button" onClick={onClose}><ChevronLeft size={17} aria-hidden="true" /> Back to agents</button>
    <div className="section-heading"><div><p className="eyebrow">Agent detail · {agent.key}</p><h2 id="agent-detail-title">{agent.name}</h2><p>{agent.capabilities}</p></div></div>
    <dl className="skill-detail-facts">
      <LabelValue label="Role" value={agent.execution_role} />
      <LabelValue label="Region" value={agent.region} />
      <LabelValue label="Tools it can reach" value={agent.tool_count === 0 ? "none" : String(agent.tool_count)} />
      <LabelValue label="Registered" value={agent.registered_at ? formatRecordedAt(agent.registered_at) : "Not recorded"} />
      <LabelValue label="Registry manifest" value={agent.manifest_hash ?? "Not recorded"} />
      {agent.manifest?.owner_department && <LabelValue label="Owner department" value={agent.manifest.owner_department} />}
      {agent.manifest && agent.manifest.discoverable_departments.length > 0 && <LabelValue label="Discoverable by" value={agent.manifest.discoverable_departments.join(", ")} />}
      {agent.manifest?.framework && <LabelValue label="Framework / model" value={`${agent.manifest.framework} · ${agent.manifest.model ?? "unrecorded model"}`} />}
      {agent.manifest?.lifecycle && <LabelValue label="Lifecycle / approval" value={`${agent.manifest.lifecycle} · ${agent.manifest.approval_status ?? "unrecorded"}`} />}
      {agent.manifest?.permission_ceiling && <LabelValue label="Permission ceiling" value={agent.manifest.permission_ceiling} />}
      <LabelValue label="Evaluation" value="No durable evaluation receipt exists in this scope." />
    </dl>
    {agent.manifest === null && <p className="inline-notice">Registered from a superseded manifest; its declared facts are withheld until re-registration.</p>}
    <div className="section-heading"><div><p className="eyebrow">Durable run ledger</p><h3>Run history</h3><p>Every dispatch the coordinator recorded for this agent, grouped by the work it served. Full traces live in Agent Observability; this ledger cites the trace ID.</p></div></div>
    <div className="skills-catalog-toolbar" role="search">
      <label className="skills-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Search runs</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incident, case, step, or revision" /></label>
      <div className="skills-attention-filter" role="group" aria-label="Filter runs by status">{runStatusFilters.map(([value, label]) => <button key={value} type="button" aria-pressed={statusFilter === value} className={statusFilter === value ? "active" : ""} onClick={() => setStatusFilter(value)}>{label}</button>)}</div>
      <TimeWindowFilter value={timeWindow} onChange={setTimeWindow} label="Filter runs by time" />
    </div>
    {runs.length === 0
      ? <div className="skills-empty-state"><strong>No durable run is recorded for this agent in this scope.</strong><span>The coordinator writes a run for every dispatch; this agent has not been dispatched here.</span></div>
      : visible.length === 0
        ? <div className="skills-empty-state"><Search size={20} /><strong>No run matches these filters.</strong></div>
        : groups.map((group) => <section key={group.anchor} className="skills-group" aria-label={group.anchor}>
          <h3 className="skills-group-title">{group.anchor}</h3>
          <div className="memory-list">
            {group.items.map((run) => <article className="memory-card" key={run.id}>
              <div className="section-heading"><div><p className="eyebrow">{run.step} · attempt {run.attempt}</p><h4>{run.id}</h4></div><StatusBadge label={run.status} tone={runStatusTone(run.status)} /></div>
              <dl className="tool-facts">
                <LabelValue label="Revision" value={run.revision} />
                <LabelValue label="Timing" value={runTiming(run)} />
                <LabelValue label="Workflow version" value={String(run.workflow_version)} />
                {run.error_class && <LabelValue label="Error class" value={run.error_class} />}
                <LabelValue label="Trace" value={run.trace ?? "Not sampled"} />
              </dl>
            </article>)}
          </div>
        </section>)}
  </section>;
}
