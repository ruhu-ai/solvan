/* The annotated incident timeseries.
 *
 *  Drawn only from the projection: the component computes geometry and nothing
 *  else. It never supplies, interpolates or rounds a value into existence, and
 *  it renders an empty state rather than an empty axis when no metric evidence
 *  has been accepted — a chart with no points is still a claim that a window
 *  was observed.
 *
 *  Series labels arrive from connector responses and are untrusted, so every
 *  one is placed as a text node. There is no markup path for provider strings.
 */
import { useId, useState } from "react";
import { MonoChip } from "./components";
import type { Incident } from "./types";

const PLOT = { left: 58, right: 706, top: 18, bottom: 196, width: 740, height: 232 };

type Point = { observed_at: string; value: number };

/** Round a ceiling to something a reader can hold: 1, 2 or 5 × a power of ten. */
function niceCeiling(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

function formatValue(value: number): string {
  if (value >= 1000) return value.toLocaleString(undefined, { maximumFractionDigits: 0 });
  if (value >= 10) return value.toFixed(0);
  return value.toFixed(2);
}

function clock(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? iso
    : `${String(parsed.getUTCHours()).padStart(2, "0")}:${String(parsed.getUTCMinutes()).padStart(2, "0")}Z`;
}

export function Timeseries({ incident }: { incident: Incident }): React.JSX.Element | null {
  const series = incident.series;
  const captionId = useId();
  const [active, setActive] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);

  if (series.points.length === 0) {
    return (
      <section className="chart-empty card">
        <p className="eyebrow">Signal over the incident</p>
        <p>
          No metric evidence has been accepted for this incident yet. Nothing is drawn rather
          than drawn from nothing.
        </p>
      </section>
    );
  }

  const points: Point[] = series.points;
  const times = points.map((point) => new Date(point.observed_at).getTime());
  const first = Math.min(...times);
  const last = Math.max(...times);
  const span = last - first || 1;
  const ceiling = niceCeiling(Math.max(...points.map((point) => point.value)) * 1.1);

  const x = (time: number) => PLOT.left + ((PLOT.right - PLOT.left) * (time - first)) / span;
  const y = (value: number) =>
    PLOT.bottom - (PLOT.bottom - PLOT.top) * Math.min(1, value / ceiling);

  const path = points
    .map((point, index) => `${index === 0 ? "M" : "L"}${x(times[index]).toFixed(1)},${y(point.value).toFixed(1)}`)
    .join(" ");
  const ticks = [0, ceiling / 3, (ceiling * 2) / 3, ceiling];
  const last_point = points[points.length - 1];

  const objectiveValue = Number.parseFloat(series.objective.replace(/[^0-9.]/g, ""));
  const hasObjective = Number.isFinite(objectiveValue) && objectiveValue > 0;

  const inRange = (iso: string) => {
    const time = new Date(iso).getTime();
    return Number.isFinite(time) && time >= first && time <= last;
  };

  return (
    <section className="chart-block">
      <figure>
        <svg
          className="plot"
          viewBox={`0 0 ${PLOT.width} ${PLOT.height}`}
          role="img"
          aria-labelledby={captionId}
        >
          {series.window_band && inRange(series.window_band.start) && (
            <rect
              className="window-band"
              x={x(new Date(series.window_band.start).getTime())}
              y={PLOT.top}
              width={Math.max(
                2,
                x(new Date(series.window_band.end).getTime()) -
                  x(new Date(series.window_band.start).getTime()),
              )}
              height={PLOT.bottom - PLOT.top}
            />
          )}

          {ticks.map((tick) => (
            <g key={tick}>
              <line className="grid-line" x1={PLOT.left} y1={y(tick)} x2={PLOT.right} y2={y(tick)} />
              <text className="axis-text" x={PLOT.left - 8} y={y(tick) + 3} textAnchor="end">
                {formatValue(tick)}
              </text>
            </g>
          ))}

          {hasObjective && objectiveValue <= ceiling && (
            <>
              <line
                className="threshold"
                x1={PLOT.left}
                y1={y(objectiveValue)}
                x2={PLOT.right}
                y2={y(objectiveValue)}
              />
              <text
                className="threshold-text"
                x={PLOT.right}
                y={y(objectiveValue) - 5}
                textAnchor="end"
              >
                {`objective ${series.objective}`}
              </text>
            </>
          )}

          {series.markers.filter((marker) => inRange(marker.at)).map((marker, index) => (
            <g key={`${marker.kind}-${marker.at}`}>
              <line
                className={marker.committed === "true" ? "marker" : "marker marker-proposed"}
                x1={x(new Date(marker.at).getTime())}
                y1={PLOT.top}
                x2={x(new Date(marker.at).getTime())}
                y2={PLOT.bottom}
              />
              <text
                className="marker-text"
                x={x(new Date(marker.at).getTime()) + 4}
                y={PLOT.top + 12 + (index % 2) * 14}
              >
                {marker.label}
              </text>
            </g>
          ))}

          <path className="series" d={path} />

          <circle className="end-dot" cx={x(last)} cy={y(last_point.value)} r={4.5} />
          <text className="end-label" x={PLOT.right} y={PLOT.bottom + 12} textAnchor="end">
            {formatValue(last_point.value)}
          </text>

          <text className="axis-text" x={PLOT.left} y={PLOT.height - 10}>
            {clock(points[0].observed_at)}
          </text>
          <text className="axis-text" x={PLOT.right} y={PLOT.height - 10} textAnchor="end">
            {clock(last_point.observed_at)}
          </text>

          {/* The hit target is the whole column, not the 2px line. Every point
              is focusable so a keyboard reaches exactly what a pointer does. */}
          {points.map((point, index) => (
            <rect
              key={point.observed_at}
              className="hit"
              x={x(times[index]) - (PLOT.right - PLOT.left) / (points.length * 2)}
              y={PLOT.top}
              width={Math.max(12, (PLOT.right - PLOT.left) / points.length)}
              height={PLOT.bottom - PLOT.top}
              tabIndex={0}
              role="button"
              aria-label={`${clock(point.observed_at)}, ${formatValue(point.value)}`}
              onMouseEnter={() => setActive(index)}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(index)}
              onBlur={() => setActive(null)}
            />
          ))}

          {active !== null && (
            <g className="crosshair" aria-hidden="true">
              <line x1={x(times[active])} y1={PLOT.top} x2={x(times[active])} y2={PLOT.bottom} />
              <circle cx={x(times[active])} cy={y(points[active].value)} r={4.5} />
            </g>
          )}
        </svg>

        <figcaption id={captionId}>
          {series.signal_kind || "signal"} · {points.length} bucket
          {points.length === 1 ? "" : "s"} · {clock(points[0].observed_at)}–
          {clock(last_point.observed_at)}
          {active !== null && (
            <>
              {" · "}
              <strong>
                {clock(points[active].observed_at)} {formatValue(points[active].value)}
              </strong>
            </>
          )}
        </figcaption>
      </figure>

      <div className="chart-sources">
        {series.evidence_refs.map((reference) => (
          <MonoChip key={reference}>{reference}</MonoChip>
        ))}
      </div>

      <button type="button" className="text-button" onClick={() => setShowTable(!showTable)}>
        {showTable ? "Hide" : "Show"} the {points.length} observations as a table
      </button>
      {showTable && (
        <div className="responsive-table">
          <table>
            <caption>
              Aligned buckets, oldest first. The chart is drawn from these and nothing else.
            </caption>
            <thead>
              <tr>
                <th>Bucket end</th>
                <th>Observed</th>
              </tr>
            </thead>
            <tbody>
              {points.map((point) => (
                <tr key={point.observed_at}>
                  <td data-label="Bucket end">{clock(point.observed_at)}</td>
                  <td data-label="Observed">{formatValue(point.value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}


/** The list-row variant: no axes, one threshold rule, an end-value label.
 *
 *  Specification 10 section 8 sizes it 120–640 x 40–56. It shares the full
 *  chart's rule that nothing is drawn from nothing: a row whose incident has no
 *  accepted metric evidence renders no sparkline rather than a flat line, which
 *  would read as a signal that was measured and did not move.
 */
export function Sparkline({ incident }: { incident: Incident }): React.JSX.Element | null {
  const points = incident.series.points;
  if (points.length < 2) return null;

  const width = 132;
  const height = 44;
  const pad = 5;
  const values = points.map((point) => point.value);
  const ceiling = niceCeiling(Math.max(...values) * 1.1);
  const x = (index: number) => pad + ((width - pad * 2) * index) / (points.length - 1);
  const y = (value: number) => height - pad - (height - pad * 2) * Math.min(1, value / ceiling);

  const objectiveValue = Number.parseFloat(incident.series.objective.replace(/[^0-9.]/g, ""));
  const hasObjective = Number.isFinite(objectiveValue) && objectiveValue > 0 && objectiveValue <= ceiling;
  const lastValue = values[values.length - 1];

  return (
    <svg
      className="sparkline"
      viewBox={`0 0 ${width + 46} ${height}`}
      width={width + 46}
      height={height}
      role="img"
      aria-label={`${incident.series.signal_kind || "signal"}, ${points.length} buckets, latest ${formatValue(lastValue)}`}
    >
      {hasObjective && (
        <line className="threshold" x1={pad} y1={y(objectiveValue)} x2={width - pad} y2={y(objectiveValue)} />
      )}
      <path
        className="series"
        d={points.map((point, index) => `${index === 0 ? "M" : "L"}${x(index).toFixed(1)},${y(point.value).toFixed(1)}`).join(" ")}
      />
      <circle className="end-dot" cx={x(points.length - 1)} cy={y(lastValue)} r={3.5} />
      <text className="end-label" x={width + 42} y={y(lastValue) + 4} textAnchor="end">
        {formatValue(lastValue)}
      </text>
    </svg>
  );
}


/** A stat tile's trend: twelve counts, no axes, no threshold, no labels.
 *
 *  It sits beside the figure and says which way it moved. It carries no value
 *  labels of its own — the figure above it is the number, and repeating it here
 *  would be two claims where the reader needs one.
 */
export function TrendLine({ points, label }: { points: number[]; label: string }): React.JSX.Element | null {
  if (points.length < 2) return null;
  const width = 104;
  const height = 28;
  const pad = 3;
  const ceiling = Math.max(1, ...points);
  const x = (index: number) => pad + ((width - pad * 2) * index) / (points.length - 1);
  const y = (value: number) => height - pad - (height - pad * 2) * (value / ceiling);
  return (
    <svg
      className="trendline"
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      role="img"
      aria-label={label}
    >
      <path
        className="series"
        d={points.map((value, index) => `${index === 0 ? "M" : "L"}${x(index).toFixed(1)},${y(value).toFixed(1)}`).join(" ")}
      />
      <circle className="end-dot" cx={x(points.length - 1)} cy={y(points[points.length - 1])} r={3} />
    </svg>
  );
}
