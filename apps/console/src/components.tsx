/* Shared console primitives. Every surface renders status through these so a
   tone can never be reinvented at a call site. */
import {
  Activity,
  Circle,
  CircleCheck,
  CircleDot,
  Info,
  ShieldX,
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

export function StatusBadge({ label, tone = "neutral", machine }: { label: string; tone?: StatusTone; machine?: string }): React.JSX.Element {
  return <span className={`status-badge status-${tone}`} title={machine ?? label}><span aria-hidden="true">{statusIcon(tone)}</span>{label}</span>;
}

export function statusIcon(tone: StatusTone): React.JSX.Element {
  const common = { size: 13, strokeWidth: 1.75, "aria-hidden": true } as const;
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
