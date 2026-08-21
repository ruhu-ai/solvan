/** The governed Tool catalog tab: what the fleet may reach, and the proof it
 *  needs before it may reach it.
 */
import { useState } from "react";
import { ChevronLeft, Wrench } from "lucide-react";
import type { ConsoleSnapshot, StatusTone } from "./types";
import { LabelValue, StatusBadge } from "./components";

type ToolRow = ConsoleSnapshot["fleet"]["tools"][number];
type ToolDefinitions = ConsoleSnapshot["fleet"]["tool_status_definitions"];

/** Tone follows what happened, not how bad it sounds.
 *
 *  `Not configured` is the state of a Tool nobody has connected yet, so it is
 *  neutral: it reports an unstarted setup step, not a fault. A warning tone
 *  there would render a fresh install as two dozen problems. `Unavailable` is
 *  reserved for a Tool that *was* probed and did not pass, which is a real
 *  finding and reads as one. */
function toolTone(availability: ToolRow["availability"]): StatusTone {
  if (availability === "Available") return "success";
  if (availability === "Disabled") return "danger";
  if (availability === "Unavailable" || availability === "Degraded") return "warning";
  return "neutral";
}

/** A value that reads the same on every row is a fleet fact, not a row fact. */
function sharedToolFact(tools: ToolRow[], read: (tool: ToolRow) => string): string | null {
  const first = tools[0];
  if (first === undefined) return null;
  const value = read(first);
  return tools.every((tool) => read(tool) === value) ? value : null;
}

/** The governed Tool catalog.
 *
 *  Every card used to carry fourteen labelled facts. Across the seeded
 *  catalog, ten of them — lifecycle, deployment, region, budget, timeout,
 *  connection, probe, identity, why, and next step — hold the same value on
 *  every card; `gateway` is the integration string printed a second time, and
 *  the registry URI restates the key already in the heading. A fact that never
 *  varies distinguishes nothing, so the fleet states it once, the same rule the
 *  Agents tab above already applies to deployment.
 *
 *  A row therefore keeps only what an operator chooses between — capability,
 *  permission class, and destination — the requesting agent becomes the group
 *  heading rather than a repeated field, and the full governance record moves
 *  into the detail, which is where specification 16 already puts it.
 */
export function ToolsView({ tools, definitions }: { tools: ToolRow[]; definitions: ToolDefinitions }): React.JSX.Element {
  const [selected, setSelected] = useState<ToolRow | null>(null);
  if (selected) return <ToolDetail item={selected} definitions={definitions} onClose={() => setSelected(null)} />;
  if (tools.length === 0) return <section className="card"><p className="empty-copy">No governed Tool revision is published in this scope.</p></section>;
  const selectable = tools.filter((tool) => tool.availability === "Available").length;
  // Why and next step are only fleet-level when one cause blocks the whole
  // catalog. The moment two tools are blocked differently they become row
  // facts again and are read in the detail.
  const blockedWhy = selectable === 0 ? sharedToolFact(tools, (tool) => tool.why) : null;
  const blockedStep = selectable === 0 ? sharedToolFact(tools, (tool) => tool.next_step) : null;
  const uniformAvailability = sharedToolFact(tools, (tool) => tool.availability);
  const groups: Array<{ title: string; items: ToolRow[] }> = [];
  for (const tool of tools) {
    const title = tool.agents.join(" · ") || "No declared requester";
    const group = groups.find((candidate) => candidate.title === title);
    if (group) group.items.push(tool);
    else groups.push({ title, items: [tool] });
  }
  return <>
    <section className="card tool-catalog-shell" aria-labelledby="tool-catalog-title">
      <div className="section-heading"><div><p className="eyebrow">Governed capability catalog</p><h2 id="tool-catalog-title">Tools</h2><p>{blockedWhy
        ? `${tools.length} approved revisions, none selectable here: ${blockedWhy.charAt(0).toLowerCase()}${blockedWhy.slice(1)}`
        : `${selectable} of ${tools.length} revisions are selectable in this scope.`} Discovery never grants use; open a tool for its governance record.</p></div><StatusBadge label="Read-only view" tone="neutral" /></div>
      {blockedStep && <div className="platform-next-step"><strong>Next safe step</strong><span>{blockedStep}</span></div>}
    </section>
    {groups.map((group) => <section className="tool-group" key={group.title} aria-label={group.title}>
      <h3 className="tool-group-title">{group.title}</h3>
      <div className="tool-catalog-grid">
        {group.items.map((tool) => <button className="card tool-card" type="button" key={`${tool.key}@${tool.version}`} onClick={() => setSelected(tool)}>
          <span className="tool-symbol" aria-hidden="true"><Wrench size={18} strokeWidth={1.75} /></span>
          <span className="tool-card-body"><h4>{tool.name}</h4><span className="tool-card-reach">{tool.permission_class} · {tool.integration}</span></span>
          {uniformAvailability === null && <StatusBadge label={tool.availability} tone={toolTone(tool.availability)} />}
        </button>)}
      </div>
    </section>)}
  </>;
}

/** One Tool revision's whole governance record.
 *
 *  Each status value is rendered beside the definition of the dimension it
 *  belongs to, so the vocabulary is learned where it is used instead of in a
 *  separate legend the reader has to hold in memory while scrolling a grid.
 */
function ToolDetail({ item, definitions, onClose }: { item: ToolRow; definitions: ToolDefinitions; onClose: () => void }): React.JSX.Element {
  const values: Record<string, string> = {
    lifecycle: item.lifecycle,
    availability: item.availability,
    evidence: `${item.evidence} · ${item.last_probe}`,
    deployment: item.deployment,
  };
  return <section className="card skill-detail skill-detail-page" aria-labelledby="tool-detail-title">
    <button className="skill-detail-back" type="button" onClick={onClose}><ChevronLeft size={17} aria-hidden="true" /> Back to tools</button>
    <div className="section-heading"><div><p className="eyebrow">{item.permission_class} · revision {item.version}</p><h2 id="tool-detail-title">{item.name}</h2><p>{item.why}</p></div><StatusBadge label={item.availability} tone={toolTone(item.availability)} /></div>
    <div className="platform-next-step"><strong>Next safe step</strong><span>{item.next_step}</span></div>
    <div className="tool-status-legend">{Object.entries(definitions).map(([label, meaning]) => <div key={label}><strong>{label}</strong><span className="tool-dimension-value">{values[label] ?? "Not projected"}</span><span>{meaning}</span></div>)}</div>
    <h3 className="tool-detail-section">Binding</h3>
    <dl className="skill-detail-facts">
      <LabelValue label="Requesting agent" value={item.agents.join(", ")} />
      <LabelValue label="Owner" value={item.owner} />
      <LabelValue label="Gateway destination" value={item.gateway} />
      {item.integration !== item.gateway && <LabelValue label="Integration" value={item.integration} />}
      <LabelValue label="Region" value={item.region} />
      <LabelValue label="Bound connection" value={item.connection} />
      <LabelValue label="Observed identity" value={item.identity} />
    </dl>
    <h3 className="tool-detail-section">Evidence and bounds</h3>
    <dl className="skill-detail-facts">
      <LabelValue label="Probe expiry" value={item.probe_expiry} />
      <LabelValue label="Last call" value={item.last_call} />
      <LabelValue label="Trace" value={item.trace} />
      <LabelValue label="Call budget" value={`${item.call_budget} calls`} />
      <LabelValue label="Timeout" value={`${item.timeout_ms / 1000}s`} />
      <LabelValue label="Payload ceiling" value={`${Math.round(item.max_payload_bytes / 1024).toLocaleString()} KiB`} />
      <LabelValue label="Model Armor" value={item.armor} />
    </dl>
    <p className="muted-copy">Registry <code>{item.registry}</code>. Registry discovery never grants invocation: dispatch revalidates agent, identity, Gateway route, connection, capability, region, and classification against the exact profile. Connection enrolment and credentials stay under Settings → Integrations.</p>
  </section>;
}
