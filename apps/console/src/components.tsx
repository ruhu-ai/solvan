/* Shared console primitives. Every surface renders status through these so a
   tone can never be reinvented at a call site. */
import {
  Activity,
  Circle,
  CircleCheck,
  CircleDot,
  Info,
  ShieldX,
  Square,
  SquareCheck,
  SquareX,
  TriangleAlert,
} from "lucide-react";
import type { PlatformEvidence, PlatformHealth, StatusTone } from "./types";

/** The Solvan mark: a bounded recovery path resolving to a verified
 *  checkpoint. `currentColor`, so it takes the ink of whatever badge it sits
 *  in (`.brand-mark`, `.sign-in-mark`) rather than carrying its own fixed
 *  palette — those badges already flip foreground/background correctly
 *  across light and dark theme, and the mark should just follow. */
export function SolvanMark({ size = 20 }: { size?: number }): React.JSX.Element {
  // aria-hidden: every call site wraps the mark in a labelled or aria-hidden
  // badge, so a role/label here was either dead or a duplicate announcement.
  // A pixel default rather than a percentage: percentage sizing silently
  // fills whatever container it lands in, including an auto-sized one.
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth={9} strokeLinecap="round" strokeLinejoin="round">
        <path d="M49 13 H33.5 A9.5 9.5 0 0 0 33.5 32 H37 A9.5 9.5 0 0 1 37 51 H29" />
      </g>
      <circle cx={14.5} cy={51} r={5.5} fill="currentColor" />
    </svg>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: React.ReactNode }): React.JSX.Element {
  return <header className="page-header"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</header>;
}

/** A status badge. The tone is never the whole signal: the glyph and the label
 *  carry the meaning too, which is what makes the two exempt colour-vision
 *  pairs in specification 10 section 3.6 admissible. Do not render a status as
 *  colour alone.
 *
 *  `terminal` selects the square glyph specification 10 section 5 reserves for
 *  states that have stopped moving, so a settled state is a different SHAPE
 *  from one still in flight rather than only a different word.
 *
 *  `machine` is the exact machine state. Specification 6 asks for it on hover
 *  AND focus; `title` on a non-interactive span delivers hover only, and is
 *  unreliable on touch and inconsistently announced by assistive technology.
 *  It is now carried as a real text node the accessible name includes, with
 *  `title` kept for the pointer affordance it does serve. The visible label
 *  stays the human sentence — the machine state is never the primary label.
 */
export function StatusBadge({ label, tone = "neutral", machine, terminal = false }: { label: string; tone?: StatusTone; machine?: string; terminal?: boolean }): React.JSX.Element {
  const exact = machine && machine !== label ? machine : null;
  return (
    <span className={`status-badge status-${tone}`} title={machine ?? label}>
      <span aria-hidden="true">{statusIcon(tone, terminal)}</span>
      <span className="status-badge-label">{label}</span>
      {exact && <span className="sr-only">{` · machine state ${exact}`}</span>}
    </span>
  );
}

export function statusIcon(tone: StatusTone, terminal = false): React.JSX.Element {
  const common = { size: 13, strokeWidth: 1.75, "aria-hidden": true } as const;
  if (terminal) {
    if (tone === "success") return <SquareCheck {...common} />;
    if (tone === "danger") return <SquareX {...common} />;
    return <Square {...common} />;
  }
  if (tone === "success") return <CircleCheck {...common} />;
  if (tone === "danger") return <ShieldX {...common} />;
  if (tone === "warning") return <TriangleAlert {...common} />;
  if (tone === "agent") return <Activity {...common} />;
  if (tone === "provenance") return <CircleDot {...common} />;
  if (tone === "info") return <Info {...common} />;
  return <Circle {...common} />;
}

export function MonoChip({ children }: { children: React.ReactNode }): React.JSX.Element {
  return <code className="mono-chip">{children}</code>;
}

/** One labelled fact. The label is quiet; the value carries the weight. */
export function LabelValue({ label, value }: { label: string; value: React.ReactNode }): React.JSX.Element {
  return <div><span className="field-label">{label}</span><span className="field-value">{value}</span></div>;
}

export function platformHealthLabel(health: PlatformHealth): string {
  return { HEALTHY: "Healthy", DEGRADED: "Degraded", BLOCKED: "Blocked", UNKNOWN: "Unknown" }[health];
}

export function platformHealthTone(health: PlatformHealth): StatusTone {
  return ({ HEALTHY: "success", DEGRADED: "warning", BLOCKED: "danger", UNKNOWN: "neutral" } as Record<PlatformHealth, StatusTone>)[health];
}

export function platformEvidenceLabel(evidence: PlatformEvidence): string {
  return { LOCAL_VERIFIED: "Local checks passed", CLOUD_VERIFIED: "Cloud receipt verified", UNVERIFIED: "Not verified" }[evidence];
}

/** Where one step of a linear governance track stands.
 *
 *  Shared so a track can never be drawn by hand: `reached` is the number of
 *  completed steps and `failed` marks the step the record stopped in, so a
 *  cancelled or failed record can never render the same as a healthy one. */
export function phaseClass(index: number, progress: { reached: number; failed: boolean }, options?: { verifiedAt?: number }): string {
  if (index < progress.reached) return options?.verifiedAt === index ? "verified" : "done";
  if (index === progress.reached && progress.failed) return "failed";
  if (index === progress.reached) return "current";
  return "future";
}
