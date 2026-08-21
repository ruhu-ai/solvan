/** Shared formatting and time-window filtering for the Fleet tabs.
 *
 *  The governance views filter client-side over the bounded recent window the
 *  snapshot carries, so "no match" under a narrow filter means nothing recent,
 *  not nothing ever.
 */

export function formatRecordedAt(value: string): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export type TimeWindow = "ALL" | "1H" | "24H" | "7D";

const timeWindowOptions = [["ALL", "Any time"], ["1H", "Last hour"], ["24H", "Last 24 hours"], ["7D", "Last 7 days"]] as const;

export function withinTimeWindow(iso: string | null, timeWindow: TimeWindow): boolean {
  if (timeWindow === "ALL") return true;
  if (!iso) return false;
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return false;
  const hours = timeWindow === "1H" ? 1 : timeWindow === "24H" ? 24 : 168;
  return Date.now() - at <= hours * 3_600_000;
}

export function TimeWindowFilter({ value, onChange, label }: { value: TimeWindow; onChange: (next: TimeWindow) => void; label: string }): React.JSX.Element {
  return <div className="skills-attention-filter" role="group" aria-label={label}>{timeWindowOptions.map(([option, text]) => <button key={option} type="button" aria-pressed={value === option} className={value === option ? "active" : ""} onClick={() => onChange(option)}>{text}</button>)}</div>;
}
