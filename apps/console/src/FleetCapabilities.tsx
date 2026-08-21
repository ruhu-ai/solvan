/** The Capabilities & Policy matrix: which Agent may reach which destination,
 *  and the authority that decided it.
 *
 *  This was a flat list of twenty-three rows whose "Effective permission" was
 *  derived in the browser from a Tool's probe freshness, and whose "Winning
 *  provenance" column printed the destination host a second time. Fourteen of
 *  those rows said `Denied` about a capability no record had refused, including
 *  the one that reaches the production actuator.
 *
 *  Every value here now comes from `fleet.capabilities`, decided once by
 *  `solvan.application.capability_resolution` against the same authorities the
 *  run binder resolves. This file renders; it does not decide.
 */
import { useMemo, useState } from "react";
import { X } from "lucide-react";
import type { CapabilityDecision, CapabilityLayerOutcome, CapabilityVerdict, StatusTone } from "./types";
import { LabelValue, StatusBadge } from "./components";

const layerNames: Record<CapabilityLayerOutcome["layer"], string> = {
  PROFILE_MEMBERSHIP: "Profile membership",
  REQUESTER_DECLARATION: "Requester declaration",
  REVISION_LIFECYCLE: "Revision lifecycle",
  CLASSIFICATION_AND_REGION: "Classification and region",
  GATEWAY_ROUTE: "Gateway route",
  CONNECTION_BINDING: "Connection binding",
  CAPABILITY_PROBE: "Capability probe",
};

const verdictNames: Record<CapabilityVerdict, string> = {
  ALLOWED: "Allowed",
  DENIED: "Denied",
  NOT_REGISTERED: "Not registered",
  NOT_EVALUATED: "Not evaluated",
};

/** Tone follows the layer that refused, not the word it produced.
 *
 *  A capability refused because no connection is enrolled is an unstarted setup
 *  step; one refused by a retired revision or a missing Gateway route is a
 *  governance state. Painting both danger-red is the failure the Tools tab
 *  already corrected: it renders a fresh install as two dozen faults. The
 *  verdict word stays the vocabulary specification 06 defines, and the tone
 *  carries how much it should alarm.
 */
function capabilityTone(decision: { verdict: CapabilityVerdict; winning_layer: string }): StatusTone {
  if (decision.verdict === "ALLOWED") return "success";
  if (decision.verdict === "NOT_REGISTERED") return "neutral";
  if (decision.verdict === "NOT_EVALUATED") return "info";
  return decision.winning_layer === "CONNECTION_BINDING" ? "warning" : "danger";
}

function layerTone(state: CapabilityLayerOutcome["state"]): StatusTone {
  if (state === "SATISFIED") return "success";
  if (state === "REFUSED") return "danger";
  if (state === "NOT_APPLICABLE") return "neutral";
  return "info";
}

/** An Agent key cannot contain whitespace (`^[a-z0-9]+(-[a-z0-9]+)*$`), so the
 *  first space always separates it from a destination that may contain one. */
function cellKey(agentKey: string, destination: string): string {
  return `${agentKey} ${destination}`;
}

/** What a cell says when it holds more than one capability.
 *
 *  Reporting only the most permissive verdict would hide a refusal behind a
 *  grant, so a cell whose capabilities disagree says so and sends the reader to
 *  the detail rather than choosing a winner on their behalf.
 */
function cellVerdict(items: CapabilityDecision[]): { verdict: CapabilityVerdict; winning_layer: string; mixed: boolean } {
  const first = items[0];
  const uniform = items.every((item) => item.verdict === first.verdict);
  return { verdict: first.verdict, winning_layer: first.winning_layer, mixed: !uniform };
}

export function CapabilitiesView({ capabilities, region }: { capabilities: CapabilityDecision[]; region: string }): React.JSX.Element {
  const [selected, setSelected] = useState<{ agent: string; destination: string } | null>(null);
  const agents = useMemo(() => {
    const seen = new Map<string, string>();
    for (const item of capabilities) if (!seen.has(item.agent_key)) seen.set(item.agent_key, item.agent);
    return [...seen.entries()].sort((left, right) => left[1].localeCompare(right[1]));
  }, [capabilities]);
  const destinations = useMemo(
    () => [...new Set(capabilities.map((item) => item.destination))].sort((left, right) => left.localeCompare(right)),
    [capabilities],
  );
  const byCell = useMemo(() => {
    const index = new Map<string, CapabilityDecision[]>();
    for (const item of capabilities) {
      const key = cellKey(item.agent_key, item.destination);
      const existing = index.get(key);
      if (existing) existing.push(item);
      else index.set(key, [item]);
    }
    return index;
  }, [capabilities]);

  if (capabilities.length === 0) {
    return <section className="card"><p className="empty-copy">No governed capability binds an Agent to a destination in this scope.</p></section>;
  }

  const allowed = capabilities.filter((item) => item.verdict === "ALLOWED").length;
  const selectedItems = selected ? byCell.get(cellKey(selected.agent, selected.destination)) ?? [] : [];

  return <>
    <section className="card capability-intro" aria-labelledby="capability-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Capability and enforcement provenance</p>
          <h2 id="capability-title">Capabilities &amp; Policy</h2>
          <p>
            Every cell is decided by the same rule the coordinator applies when it binds a run, against
            profile membership rather than declared reach. Registry discovery never grants use. Scope: {region}.
          </p>
        </div>
        <StatusBadge
          label={allowed === 0 ? "Nothing allowed here" : `${allowed} allowed`}
          tone={allowed === 0 ? "neutral" : "success"}
          machine={`${capabilities.length} governed capabilities`}
        />
      </div>
      {allowed === 0 && <p className="inline-notice" role="status">
        No capability reads allowed in this scope. A capability is allowed only when every applicable
        authority is satisfied, and no bound platform preflight receipt registers a Gateway route here.
      </p>}
    </section>

    <section className="card responsive-table capability-matrix">
      <table>
        <caption>Which Agent may reach which destination, and the authority that decided it</caption>
        <thead>
          <tr>
            <th scope="col">Agent</th>
            {destinations.map((destination) => <th scope="col" key={destination}>{destination}</th>)}
          </tr>
        </thead>
        <tbody>
          {agents.map(([agentKey, agentName]) => <tr key={agentKey}>
            <th scope="row" data-label="Agent">{agentName}</th>
            {destinations.map((destination) => {
              const items = byCell.get(cellKey(agentKey, destination)) ?? [];
              if (items.length === 0) {
                return <td key={destination} data-label={destination} className="capability-cell empty">
                  <span className="sr-only">No catalog record binds {agentName} to {destination}.</span>
                  <span aria-hidden="true">—</span>
                </td>;
              }
              const cell = cellVerdict(items);
              const active = selected?.agent === agentKey && selected.destination === destination;
              return <td key={destination} data-label={destination} className="capability-cell">
                <button
                  type="button"
                  className={active ? "capability-chip active" : "capability-chip"}
                  aria-pressed={active}
                  onClick={() => setSelected(active ? null : { agent: agentKey, destination })}
                >
                  <StatusBadge
                    label={cell.mixed ? "Mixed" : verdictNames[cell.verdict]}
                    tone={cell.mixed ? "warning" : capabilityTone(cell)}
                    machine={`${cell.verdict}${cell.mixed ? " (mixed)" : ""} · ${cell.winning_layer}`}
                  />
                  {/* Discovery and permission stay visibly distinct: the cell
                      names the authority that decided, never the destination
                      it already sits under. */}
                  <span className="capability-layer">{cell.mixed ? `${items.length} capabilities differ` : layerNames[cell.winning_layer as CapabilityLayerOutcome["layer"]]}</span>
                </button>
              </td>;
            })}
          </tr>)}
        </tbody>
      </table>
    </section>

    {selected && <CapabilityProvenance
      items={selectedItems}
      onClose={() => setSelected(null)}
    />}
  </>;
}

/** What to cite for the authority that decided.
 *
 *  An unobserved authority has no record because nobody looked. A refusal by
 *  absence — no connection enrolled in this scope — was looked for and not
 *  found. Reporting the second as "not observed" contradicts the `refused`
 *  state shown beside it on the same panel.
 */
function decidingRecord(item: CapabilityDecision): string {
  if (item.winning_reference) return item.winning_reference;
  const winner = item.layers.find((layer) => layer.layer === item.winning_layer);
  return winner?.state === "NOT_EVALUATED"
    ? "No record; this authority has not been observed"
    : "No record to cite; this authority refused on the absence of one";
}

/** The effective value beside the chain that produced it (specification 06).
 *
 *  Each layer states what it said, the record that says so, and when it was
 *  observed. The layer that decided is marked; a layer nobody has observed says
 *  that rather than reading as a refusal.
 */
function CapabilityProvenance({ items, onClose }: { items: CapabilityDecision[]; onClose: () => void }): React.JSX.Element {
  const first = items[0];
  return <section className="card capability-provenance" aria-labelledby="capability-provenance-title">
    <div className="section-heading">
      <div>
        <p className="eyebrow">Resolution chain · {first.destination}</p>
        <h2 id="capability-provenance-title">{first.agent}</h2>
        <p>{items.length === 1 ? "One governed capability reaches this destination." : `${items.length} governed capabilities reach this destination.`}</p>
      </div>
      <button className="icon-button" type="button" aria-label="Close resolution chain" onClick={onClose}><X size={18} /></button>
    </div>
    {items.map((item) => <article className="capability-record" key={`${item.tool_key}@${item.version}`}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">{item.permission_class} · revision {item.version}</p>
          <h3>{item.tool}</h3>
        </div>
        <StatusBadge label={verdictNames[item.verdict]} tone={capabilityTone(item)} machine={`${item.verdict} · ${item.winning_layer}`} />
      </div>
      <dl className="skill-detail-facts">
        <LabelValue label="Decided by" value={layerNames[item.winning_layer]} />
        <LabelValue label="Deciding record" value={decidingRecord(item)} />
      </dl>
      <ol className="capability-layer-chain">
        {item.layers.map((layer) => <li key={layer.layer} className={layer.layer === item.winning_layer ? "winning" : ""}>
          <div className="capability-layer-head">
            <StatusBadge label={layer.state.replaceAll("_", " ").toLowerCase()} tone={layerTone(layer.state)} machine={layer.state} />
            <strong>{layerNames[layer.layer]}</strong>
            {layer.layer === item.winning_layer && <span className="capability-winner">decided this</span>}
          </div>
          <p>{layer.detail}</p>
          {layer.reference && <p className="capability-reference"><code>{layer.reference}</code>{layer.observed_at && <span> · observed {new Date(layer.observed_at).toLocaleString()}</span>}</p>}
        </li>)}
      </ol>
      <p className="muted-copy">
        Registry <code>{item.registry_resource}</code>. Registry discovery never grants invocation: dispatch
        revalidates Agent, identity, Gateway route, connection, capability, region, and classification against
        the exact profile, and a run adds checks this standing view does not answer.
      </p>
    </article>)}
  </section>;
}
