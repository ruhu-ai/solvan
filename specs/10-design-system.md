# Solvan design system

Status: required approval-path subset; remaining system is target
Related: [UI/UX](06-ui-ux.md)

Research provenance: token architecture and enforcement adapted from the
ruhu-operator design system (same owner). Interaction and visual patterns were
studied across existing incident-response product surfaces and read-only
repository snapshots — pattern study only, with no assets, copy, or brand
elements reproduced.

## 1. Design character

Solvan should feel like a calm, evidence-led operations instrument: dense
enough for incident response, quiet enough that the exceptional state is the
loudest thing on screen, and precise about what is observed, proposed,
executed, and verified. It avoids sci-fi AI visuals, glowing gradients, robot
mascots, chat bubbles as the primary surface, and decorative confidence
gauges.

Two audiences see this console: an operator working an incident, and a judge
watching a compressed 1080p video. Every size and contrast decision below is
tested against both — nothing that must be read in the demo may depend on
subpixel detail or on color alone.

## 2. Token architecture — three layers

```
Layer 3  Component     --approval-panel-border
         Rare. Lives beside the component. References Layer 2, never Layer 1.

Layer 2  Semantic      --text-primary, --surface, --status-warning-fg, --type-h2
         The API components consume. Named by ROLE, never by appearance.

Layer 1  Primitive     --gray-950, --blue-600, --amber-50
         The only place a color value is written. Components never touch it.
```

Two files:

| File | Owns |
|---|---|
| `apps/console/src/styles/tokens.css` | Layers 1–2, type scale, space, radius, motion, layout |
| `apps/console/src/styles/app.css` | Components. Layer 2 references only. |

Primitives keep their **scale position** across themes: `--gray-0` is always
"the lightest surface," `--gray-950` always "primary ink." Values fork per
theme; the semantic layer does not — a new theme forks ~30 primitives, not
~80 semantic tokens.

Components use semantic tokens only. The approval-path token/contrast check is
required; repository-wide raw hex/rgb rejection is a target after MSR.

Anti-patterns:

| Bad | Why | Instead |
|---|---|---|
| `--paper`, `--ink` | appearance, not role; meaningless in dark | `--bg`, `--text-primary` |
| `#2563EB` in `app.css` | unthemeable, uncheckable | `var(--link)` |
| `--green-button` | couples role to hue | `--action-primary` |
| `--primary` | primary *what?* | `--text-primary`, `--action-primary` |

## 3. Color

### 3.1 Light primitives

Cool neutral ramp — the canvas reads as instrument, not paper. This replaces
an earlier warm "stone" ramp. The warm ground was chosen to look unlike the
blue-gray dashboards this console is judged beside, but differentiation bought
with temperature is paid for in legibility: a warm mid-grey needs an 18–20
point RGB spread to stay warm as it darkens, and at that spread it stops
reading as grey and starts reading as brown. The distinctiveness should come
from what the console *says* — held claims, authority status on every row —
not from the colour of its background.

**Temperature is a single decision, held in both themes.** Perceived
temperature is carried by absolute RGB spread, not by HSL saturation, which is
unreliable above 90% lightness. The ramp leans cool by 4–5 points at the
surfaces and up to 17 through the mid-tones, in one direction throughout. Two
rules follow, and both were violated by the warm ramp:

- **Light and dark carry the same temperature.** A console that is warm in
  light and cool in dark is two designs behind one toggle.
- **The mid-greys are where a ramp betrays itself.** Surfaces are pale enough
  to hide their bias and ink is dark enough to hide its own; `--gray-300`
  through `--gray-700` are where a viewer actually reads the temperature, so
  they carry it deliberately rather than drifting.

A fully neutral ramp is still not the alternative — an unbiased grey reads as
inherited rather than chosen.

| Token | Value | Role at this position |
|---|---|---|
| `--gray-0` | `#FFFFFF` | raised surfaces, cards |
| `--gray-25` | `#F5F6F7` | canvas |
| `--gray-50` | `#EEF0F2` | sunk/muted surface, mono chips |
| `--gray-100` | `#E8EAED` | default border |
| `--gray-200` | `#D8DCE1` | strong border |
| `--gray-300` | `#9AA1AA` | disabled text/icon |
| `--gray-500` | `#5B616B` | muted text |
| `--gray-700` | `#363940` | secondary text |
| `--gray-950` | `#17191C` | primary ink, primary action fill |
| `--blue-600` | `#2563EB` | link, focus ring, info |
| `--blue-700` | `#1D4ED8` | link hover, info text on tint |
| `--green-600` | `#137A4A` | verified/safe success |
| `--amber-600` | `#A15C00` | warning, approval wait |
| `--red-600` | `#B42318` | critical, denied, failed |
| `--violet-600` | `#6941C6` | agent/runtime activity |
| `--teal-600` | `#0F766E` | evidence provenance |

### 3.2 Dark primitives

Same positions, forked values. Dark is a first-class theme, not an inversion:
tints become deep tones, text hues lighten, and elevation is expressed by
surface lightness instead of shadow.

Because dark elevation is carried by lightness alone, the raised surface is
tuned rather than inherited. It sits a little above the canvas — enough for a
card to separate without a border doing the work, and no more.

**The ground is set by the tints, not by the card.** A status tint is a block
of colour on a card, and the two were within 1.00–1.05 of each other on the
first cool ramp: the agent tint was *exactly* the card's luminance, so those
blocks separated by hue alone and vanished for a red-green colourblind reader.
Automated contrast checks do not catch this, because they audit text against
its background and never a background against the surface beneath it. Lowering
the whole ground so the card sits at `#17191D` roughly doubles that separation
while improving every text pair. Where the two goals compete — a higher card
reads more raised, a lower card makes the tints legible — the tints win.

The six accent hues are unchanged from the warm ramp: swapping the ground moved
every accent contrast by less than 0.1, so re-tuning them would have been
change without a reason. The tints themselves remain a known limit — they could
separate further still, but `--red-600` is not light enough to sit on a lifted
danger tint at AA, so lifting them is a change to the status palette rather
than to the ground.

| Token | Value |
|---|---|
| `--gray-0` | `#17191D` (raised) |
| `--gray-25` | `#0B0C0E` (canvas) |
| `--gray-50` | `#101114` |
| `--gray-100` | `#262930` |
| `--gray-200` | `#363A42` |
| `--gray-300` | `#5E646C` |
| `--gray-500` | `#9AA1AB` |
| `--gray-700` | `#C4C8CE` |
| `--gray-950` | `#E6E8EB` |
| `--blue-600` | `#7AA5F5` |
| `--green-600` | `#4CC38A` |
| `--amber-600` | `#DFA640` |
| `--red-600` | `#E5695C` |
| `--violet-600` | `#A78BE8` |
| `--teal-600` | `#4FBDB0` |

### 3.3 Semantic roles

```
Surface   --bg --surface --surface-muted --surface-sunk --surface-overlay
Text      --text-primary --text-secondary --text-muted --text-disabled
          --text-on-action
Border    --border --border-strong
Action    --action-primary --action-primary-hover        (ink)
Link      --link --link-hover
Focus     --focus-ring                                    (blue, 3px, 2px offset)
Chart     --chart-1 --chart-marker --chart-threshold --chart-window
Status    --status-{success,warning,danger,info,agent,neutral}-{bg,border,fg,strong}
Evidence  --provenance-{bg,border,fg}
Elevation --shadow-overlay   (overlays/drawers only; borders define hierarchy)
```

### 3.4 The primary action is ink, not color

`--action-primary` resolves to `--gray-950`. A saturated accent doing four
jobs at once — primary button, link, focus, selection — makes every screen
read as urgent and leaves the status palette nothing to contrast against.
Split:

| Role | Token | Hue |
|---|---|---|
| Primary action (`Approve`, confirm), selected fill | `--action-primary` | ink |
| Text link, trace/evidence links | `--link` | blue |
| Focus ring (must differ from resting border) | `--focus-ring` | blue |
| Chart series | `--chart-1` | blue |
| Meaning: verified / waiting / denied / agent | `--status-*` | green / amber / red / violet |
| Evidence provenance chips | `--provenance-*` | teal |

Because primitives are position-stable, this inverts for free in dark mode: a
dark button with light text in light mode, a light button with dark text in
dark mode.

### 3.5 Status is a strict 4-tuple

Pick a status, take its four tokens — `bg`, `border`, `fg`, `strong` — no
exceptions. A pill needing a fifth variation is a different status.

Light-theme tuples:

| Status | bg | border | fg | strong |
|---|---|---|---|---|
| success | `#E9F5EE` | `#B7DFC6` | `#137A4A` | `#0E5C38` |
| warning | `#FBF3E4` | `#EDD8AC` | `#A15C00` | `#7A4600` |
| danger | `#FBEAE8` | `#F2C4BE` | `#B42318` | `#8A1A12` |
| info | `#EAF1FD` | `#C4D6F7` | `#1D4ED8` | `#1E40AF` |
| agent | `#F1EDFB` | `#D8CCF3` | `#6941C6` | `#4F2FA3` |
| neutral | `#F4F3F0` | `#D6D3CC` | `#57534A` | `#2E2B26` |
| provenance | `#E8F4F2` | `#B9DFDA` | `#0F766E` | `#0A544E` |

Dark-theme tuples are defined in `tokens.css` at the same positions
(deep-tone bg, one-step-lighter border, light fg/strong) and pass the same
contrast suite.

Assignments that must not drift:

- **Verified recovery is the only green.** A connector "succeeded" remains
  neutral/info until independent verification passes.
- Approval wait and `INCONCLUSIVE` are amber.
- Security denies and critical failures use red plus icon plus text.
- Agent/agent activity is violet — **activity, never judgment, and never a
  category**. Violet marks a agent executing *now*: an incident in
  `INVESTIGATING`, a case in `REPAIR_IN_PROGRESS`, a dispatched plan step, a
  running spinner. It is wrong on three things that look adjacent and are not:
  a **lifecycle position** (which phase a case has reached), a **judgment**
  (which hypothesis leads), and a **category** that is constant across a list
  (every agent card, every actuator of one posture). A colour applied to every
  row distinguishes nothing and has become decoration. The absence of activity
  — "no process running" — is neutral, never violet and never green.
  It is also wrong on a **deterministic actor**. Violet reads as "a model is
  working", so the coordinator, the policy engine, the Execution Agent's
  dispatch, the actuator, and a human take `info` or `neutral` even mid-flight.
  A timeline row therefore takes its tone from `actor_type`, not from the fact
  that a transition is in progress.
- **`--provenance-*` is deliberately not `--status-success-*`:** an evidence
  chip citing a verified-fresh source must not read as an approval or a
  verification verdict.

## 4. Typography

### 4.1 Fonts

```css
--font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
             "Helvetica Neue", Arial, sans-serif;
--font-mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas,
             "Liberation Mono", monospace;
```

**No web font in the release.** The console ships under a strict CSP with no
remote origins, and at these sizes a bundled face is indistinguishable from
the system stack on the demo recording. Bundling Inter later is a P3
enhancement gated on license inclusion; it must not change any token value.

Numerals in metrics, tables, and timelines use
`font-variant-numeric: tabular-nums`.

### 4.2 Scale — triplet steps

Each step is a **triplet** — size / line / weight — and components take all
three; a heading at body line-height breaks vertical rhythm as surely as a
wrong size. Sizes suit a dense operations tool that must also survive 1080p
video compression: body is 14, one 22px title per page, and nothing larger
except a glance metric.

| Token | Size/Line | Weight | Used for |
|---|---:|---:|---|
| `--type-h1` | 22/30 | 650 | page title — one per page |
| `--type-title` | 18/26 | 650 | finding/narrative headline, drawer title |
| `--type-h2` | 16/24 | 600 | card and section title |
| `--type-h3` | 14/20 | 600 | sub-section, table group |
| `--type-body` | 14/21 | 400 | default text, navigation |
| `--type-body-sm` | 13/19 | 400 | descriptions, secondary cell text |
| `--type-button` | 13/19 | 500 | buttons, tabs, actionable chips |
| `--type-small` | 12/17 | 400 | metadata, help text |
| `--type-micro` | 11/15 | 500 | timestamps, counts, axis labels |
| `--type-eyebrow` | 11/16 | 650 | uppercase labels, +0.06em tracking |
| `--type-mono` | 13/19 | 400 | IDs, digests, versions, resources |
| `--type-metric` | 26/32 | 650 | overview glance figures, tabular |
| `--type-metric-sm` | 18/24 | 650 | in-card figures, tabular |

Rules:

- weights are 400 / 500 / 600 / 650 / 700 only; system stacks synthesise
  anything else, so intermediate weights are never distinct;
- `clamp()` on a font size is banned — a viewport-scaled heading is a size
  nobody chose;
- never use all caps for sentences; machine states (`VERIFYING_MITIGATION`)
  render in `--type-mono` or `--type-eyebrow` with a human label adjacent and
  an accessible expansion;
- **uppercase marks a signpost, never content.** One eyebrow per section is a
  landmark the operator reads once and then navigates by. A label that repeats
  down a list or across a rail — phase names, per-row field labels, card
  headings — is content being compared, and uppercase strips the word-shape
  cues that make comparison fast. Those stay sentence case. If a screen shows
  more than a handful of uppercase strings, the device has stopped marking
  structure and started shouting.

## 5. Icons

One locally bundled outline set — **Lucide** (ISC license, recorded in
third-party notices). `--icon-size` 16 px, `--icon-size-sm` 13 px beside 13 px
text, stroke 1.75. Nothing exceeds 24 px. Icons carrying critical meaning have
text or accessible labels; decorative icons are `aria-hidden`.

Status icon vocabulary (paired with color, never replacing text):

- observed: eye/pulse;
- agent activity: workflow nodes — no anthropomorphic face;
- proposed: document/arrow;
- approval: shield/check;
- executing: rotating progress only when motion allowed;
- reconciled: linked check;
- verified: check-circle;
- blocked/denied: shield-x;
- inconclusive: circle-help;
- terminal states: square variant — a distinct shape from in-flight circles.

## 6. Inline semantic chips

Narrative surfaces (timeline, findings, hypotheses) refer to resources
constantly. Two chip primitives keep prose scannable:

### `MonoChip`

Inline identifier — service, version, revision, incident ID, digest suffix,
metric name. `--type-mono` on `--surface-sunk`, 1 px `--border`, radius 4,
padding 1 px 6 px. Never a link by itself; wrap in an anchor when it
navigates. Digests show first/last 6 characters with copy-full affordance.

```text
Rolled back  payments-api  ·  v2.8.1 → v2.8.0    digest a1b2c3…e4f5d6
```

### `SourceChip`

Evidence origin: source icon + name + freshness — `Cloud Logging · 13:22Z ·
fresh 4m`. Uses the `--provenance-*` tuple. Appears on every `EvidenceCard`
and inline wherever a narrative statement cites its source.

## 7. Narrative finding pattern

Committed findings render as **headline + evidence prose + annotated chart**
— the console's signature block, applied to Solvan's committed-facts model:

```text
┌─────────────────────────────────────────────────────────────┐
│ EVIDENCE SPECIALIST · 13:22:41Z                     [trace ↗]  │  eyebrow row
│                                                             │
│ payments-api: p95 latency breached 4m after deploy          │  --type-title
│                                                             │
│ Deploy `payments-api v2.8.1` completed at **13:18Z**.       │  --type-body
│ p95 rose from **210 ms** (7-day baseline) to **2.7 s**,     │  bold = measured
│ sustained 6m. DB connections at **94% of pool**.            │  values only
│                                                             │
│ [annotated timeseries: deploy marker · breach marker ·      │
│  threshold rule · observation window]                       │
│                                                             │
│ ⬡ Cloud Monitoring · fresh    ⬡ Cloud SQL metrics · fresh  │  SourceChips
└─────────────────────────────────────────────────────────────┘
```

Rules: the headline is a factual claim, not a summary of effort; **bold is
reserved for measured values** — numbers, versions, timestamps — never for
opinion emphasis; every value states its baseline and window; every block
carries its `SourceChip`s and a trace link.

## 8. Charts

Deterministic inline SVG with semantic labels. No chart runtime, no canvas,
no network.

- **Annotated timeseries** is the primary form: series in `--chart-1`; event
  markers (`deploy`, `action executed`, `verification start`) as labeled
  vertical rules in `--chart-marker` — dashed while proposed/uncommitted,
  solid only for committed events; thresholds as dashed rules in
  `--chart-threshold`; the verification observation window as a shaded band
  in `--chart-window`.
- Direct series labels at line end; a legend only above two series; series
  are distinguished by dash/marker as well as hue.
- Axis labels `--type-micro`; units in the axis title or first tick, never
  omitted; no truncated axis that exaggerates without an explicit break.
- Sparkline variant for feed/list rows: 120–640 × 40–56 px, no axes, one
  threshold rule, end-value label.
- Every chart has an equivalent table and one-sentence summary; chart render
  failure falls back to the table without losing data.

## 9. Spacing, radius, and elevation

Base unit: 4 px. Scale `1, 2, 3, 4, 5, 6, 8, 10, 12, 16` maps to 4–64 px.

- card padding: 16–20 px;
- page gutters: 24 px desktop, 16 px narrow;
- radius: `--radius-xs` 4 (chips), `--radius-sm` 6 (controls),
  `--radius-md` 8 (cards), `--radius-lg` 12 (dialogs/drawers),
  `--radius-pill` 999;
- shadows are subtle and reserved for overlays/raised drawers
  (`--shadow-overlay`); borders define ordinary hierarchy.

## 10. Density, target size, and layout

```
--control-min   36px  (mouse)  →  44px under (pointer: coarse) or ≤ 760px
--control-sm    28px  (mouse)  →  40px
--row-min       32px  (mouse)  →  44px
```

Target size is a property of the **pointer**, not the product. 36 px clears
the WCAG 2.2 AA 24×24 minimum at working density; the coarse-pointer rule
restores 44 px wherever a finger is the input. Approval-critical controls use
`--control-min` at every width and never take the small size. A label may be
12 px; the control around it never shrinks to match.

Layout tokens:

```
--sidebar-width   240px    left navigation
--rail-width      320px    contextual right drawer / attention rail
--measure         76ch     maximum readable narrative width
--content-max     1440px   incident detail max width
--timeline-rail   28px     fixed timeline gutter
```

- 12-column responsive grid for Overview;
- two-column evidence layout collapses to one below 900 px;
- rail becomes a drawer below 1180 px; tables become labeled card rows below
  760 px with status/units/provenance retained;
- approval panel uses a sticky summary only when all content remains keyboard
  and screen-reader reachable.

## 11. Motion

- `--motion-fast` 120 ms hover/focus, 180 ms drawers, 220 ms state
  transitions; one easing (`cubic-bezier(0.2, 0, 0, 1)`);
- no looping decorative animation;
- active work pulse at most once per 1.5 seconds;
- `prefers-reduced-motion` removes transforms/pulses and uses static status;
- state changes never rely on animation for comprehension.

## 12. Enforcement

`scripts/check-design-tokens` runs in CI before tests. Required for MSR on the
approval path (Overview, Incident detail, Approval routes); repository-wide is
target. It fails on:

1. a color literal (hex/`rgb()`/`hsl()`) outside `tokens.css`;
2. a bare `font-size` — must be `var(--type-*)`;
3. a `font-size` with no paired `line-height` in the same rule;
4. a bare `font-weight` outside the weight tokens;
5. a `var(--x)` that nothing defines;
6. an inline `style=` attribute or `<style>` block in component markup
   (computed SVG geometry attributes in charts are the one allowlisted case);
7. a `font:` shorthand other than `font: inherit`.

A system nobody can bypass by accident is the only kind that survives a
10-day agent-driven build — these checks catch drift the moment a coding
agent invents a value.

## 13. Status language and mapping

| Domain state | Visible label | Semantic style |
|---|---|---|
| `DETECTED` | Detected | danger |
| `TRIAGING` / `INVESTIGATING` | Investigating | agent |
| `DIAGNOSING` | Diagnosing | agent |
| `MITIGATION_PROPOSED` | Mitigation proposed | info |
| `AWAITING_APPROVAL` | Approval required | warning |
| `MITIGATING` | Executing mitigation | agent |
| `VERIFYING_MITIGATION` | Verifying recovery | info |
| `MITIGATED` | Service restored · repair open | success + open marker |
| `RESOLVED` | Resolved and verified | success |
| `ESCALATED` | Human ownership accepted | warning |
| `FALSE_POSITIVE` / `CANCELLED` | per label | neutral |
| `INCONCLUSIVE` | Verification inconclusive | warning |
| action `SUCCEEDED` (pre-verification) | Mutation reconciled | info — **not green** |
| security denial | Blocked by {control} | danger |

Investigation-step states use the same language discipline: `Planned`,
`Ready`, `Queued`, `Running`, `Succeeded`, `Failed`, `Stale`, and `Skipped`. A
`Queued` label maps to the persisted `DISPATCHED` state; there is no separate
`QUEUED` machine state. A
successful step means its typed result committed; it does not mean the
hypothesis or incident is resolved.

Do not show `MITIGATED` as identical to `RESOLVED`.

## 14. Core components

### Buttons

- primary ink (`--action-primary`): one main action per panel;
- danger: destructive/cancel/escalate only;
- secondary outline: alternatives — approval reject is a full secondary
  button, never a tertiary link;
- tertiary text: low-risk navigation only;
- loading retains label and width; disabled state explains why through
  adjacent text, not tooltip alone.

### Tables

- sticky header only in scroll container;
- sortable headers announce direction;
- units in header or each value; row height `--row-min`;
- row actions keyboard reachable;
- horizontal overflow retains first identity column;
- mobile converts to labeled rows.

### Timeline

- committed events use solid nodes on the `--timeline-rail`;
- active durable run uses animated ring unless reduced motion;
- proposed/uncommitted UI state never appears as a committed node;
- event grouping may compress repeated read calls but expands to exact
  records.

### Dialogs

- consequential confirmation and short focused tasks only;
- title states action and target;
- initial focus on explanatory content/least destructive control;
- escape closes only before request submission;
- after submit, show durable receipt/status rather than trapping the user.

Native browser `alert`, `confirm`, and `prompt` are never used. They cannot
show the bound digest/provenance contract, do not produce an adequate
accessible decision flow, and encourage non-durable result handling.

### Master-detail queues

- state counts and filters sit above the list and survive in the URL;
- selected detail does not discard scroll position or filters;
- list rows show identity, state, age, accountable owner, and next action;
- severity, risk, urgency, and freshness remain separate labelled fields;
- a side drawer is allowed only when its complete content is reachable at
  200% zoom and through a standalone URL or equivalent focus-safe detail
  route.

### Structured provenance and diffs

- compare semantic typed fields, not unbounded raw JSON blobs;
- label source layer, version, owner, effective time, and winning precedence;
- unchanged fields collapse behind an accessible disclosure;
- additions, removals, overrides, denies, and restricted values use icon,
  text, and color together;
- approval and policy diffs never permit inline editing.

### Trace disclosure

- group tool calls under durable plan step and registered agent run;
- summary rows show tool, state, duration, result class, and redacted size;
- expanded rows show schema-shaped redacted input/output summaries and hashes;
- raw credentials, unrestricted payloads, chain-of-thought, and unsafe
  evidence never enter the DOM;
- an authorized external-observability link is supplementary, not the only
  indication of run failure or fallback.

## 15. Empty, loading, and degraded states

Every data surface defines:

- initial loading skeleton with stable layout;
- empty because no records;
- empty because filters;
- unauthorized without revealing existence;
- stale snapshot with last updated time;
- subsystem degraded with impact and next retry;
- fatal error with correlation ID and safe retry/navigation.

## 16. Content and number formatting

- show `8.7%`, `210 ms`, `72 connections`, and explicit windows;
- relative time is paired with exact time on focus/hover;
- timestamps show timezone abbreviation and full offset in detail;
- digest displays first/last 6 characters with copy full value;
- versions are never localized;
- unknown data displays `Not available`, not zero or an em dash when the
  ambiguity matters.

## 17. Accessibility enforcement

Required for MSR: automated contrast/token check over every semantic fg/bg
pair in §3.5 (both themes; `fg` on `bg` ≥ 4.5:1, `strong` on `bg` ≥ 7:1), and
axe/keyboard checks on Overview, Incident detail, and Approval. The remaining
bullets are target until they have stored evidence.

- target: axe on every route/state fixture;
- keyboard acceptance for all critical flows;
- reduced-motion screenshot suite;
- screen-reader labels for badges, charts, timelines, icons, and live
  regions;
- 200% zoom and 320 CSS px reflow check;
- no hover-only information required for action.

## 18. Design acceptance

1. Operator can visually distinguish all action/verification phases — in
   grayscale.
2. Risk, environment, target, and approval expiry remain visible at narrow
   width.
3. Status meaning remains correct in grayscale and high contrast.
4. Verified-green appears nowhere except independent verification results.
5. Evidence provenance chips are visually distinct from success states.
6. Every chart's data is accessible without the chart.
7. No raw untrusted content can create style, link, image, or script
   behavior.
8. Light/dark themes meet AA contrast for text, controls, focus, and status.
9. Queue filters, selection, and expanded evidence survive
   navigation/reconnect.
10. Provenance/diff views identify the effective value and why it won without
    raw configuration editing.
11. Investigation and trace views remain useful with private reasoning
    omitted.
12. All body-size text used in the demo is legible in a 1080p video capture
    at default player size.
