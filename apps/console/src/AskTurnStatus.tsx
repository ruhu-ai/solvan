/** What a turn is doing, and what it is spending doing it.
 *
 *  Kept apart from the rail because these two components answer a question the
 *  rest of the transcript does not: not "what was said" but "what is happening
 *  right now, and may I stop it". Specification 14 §19, §19.1.
 */
import type { AskResponse, PublicActivity } from "./conversation";
import type { TurnBudget } from "./AskSupport";

const ACTIVITY_LABELS: Record<string, string> = {
  READING_BOUND_PROJECTION: "Reading the incident timeline",
  INPUT_PROJECTION_ADVANCED: "Refreshing changed incident records",
};

/** The live row for a turn in flight.
 *
 *  One row, not three. The panel previously carried a hardcoded state line, a
 *  second hardcoded activity line, and a third from the event payload, any two
 *  of which could disagree. And the budget meter belongs to a turn in flight
 *  (§19): a finished answer that used one of twenty-five tool calls has
 *  nothing to report, so it reports nothing. A reached ceiling still speaks —
 *  through its own `budget_note` part, which is a statement, not a gauge.
 */
export function TurnWork({
  answer,
  activity,
  budget,
  onStop,
}: {
  answer: AskResponse;
  activity?: PublicActivity;
  budget: TurnBudget;
  onStop: () => void;
}): React.JSX.Element | null {
  if (answer.state !== "RUNNING" && answer.state !== "READY") return null;
  const label = answer.state === "READY"
    ? "Starting"
    : (activity ? (ACTIVITY_LABELS[activity.activity] ?? "Reading governed records") : "Reading governed records");
  const meter = budget.tool_calls > 0
    ? `${answer.tool_calls}/${budget.tool_calls} tools · ${answer.model_calls}/${budget.model_calls} models`
    : null;
  return (
    <div className="ask-turn-work" role="status">
      <p className="ask-activity">
        <span className="ask-activity-pulse" aria-hidden="true" />
        {label}
        <span className="ask-activity-actions">
          {meter && <span className="ask-usage">{meter}</span>}
          <button type="button" className="link-button" onClick={onStop}>Stop</button>
        </span>
      </p>
      {activity?.tool_identifier && (
        <details className="ask-tool-row">
          <summary>{activity.tool_identifier.replaceAll("_", " ")}</summary>
          <dl>
            <div><dt>Result class</dt><dd>{activity.result_class ?? "In progress"}</dd></div>
            {activity.timing_ms !== null && <div><dt>Timing</dt><dd>{activity.timing_ms} ms</dd></div>}
          </dl>
        </details>
      )}
    </div>
  );
}

/** Terminal state, only when it says something.
 *
 *  A completed answer needs no badge: it is on screen. What earns a line is a
 *  turn that queued, stopped, parked, or failed.
 */
export function TurnState({
  answer,
  onCancel,
}: {
  answer: AskResponse;
  onCancel: () => void;
}): React.JSX.Element | null {
  if (answer.state === "QUEUED") {
    return (
      <div className="ask-turn-state" role="status">
        <span>Queued{answer.queue_sequence ? ` · #${answer.queue_sequence}` : ""}</span>
        <button type="button" className="link-button" onClick={onCancel}>Cancel</button>
      </div>
    );
  }
  if (answer.state === "INTERRUPTED") {
    return <p className="ask-turn-state ask-turn-interrupted" role="status">Stopped before completion.</p>;
  }
  if (answer.state === "FAILED") {
    return <p className="ask-error" role="status">The answer attempt failed safely.</p>;
  }
  return null;
}
