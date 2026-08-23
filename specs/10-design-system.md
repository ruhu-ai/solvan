# Solvan design system

Status: required; token, contrast, type-scale and palette-separation checks are enforced by `tools/check_design_system.py` in `scripts/check`
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

Components use semantic tokens only. `tools/check_design_system.py` enforces
all of it in `scripts/check`: every `var()` resolves, colour literals appear
only in `tokens.css`, sizes and weights come from the scale, the semantic
contrast pairs hold in both themes, and the status hues stay separable. The
check exists because prose did not prevent six undefined tokens, eighteen raw
literals and a hundred and forty-nine hand-set sizes from accumulating.

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
| `--gray-150` | `#DFE0E1` | neutral status tint |
| `--gray-300` | `#9AA1AA` | disabled text/icon |
| `--gray-400` | `#929397` | strong border, control edge |
| `--gray-500` | `#5B616B` | muted text |
| `--gray-700` | `#363940` | secondary text |
| `--gray-950` | `#17191C` | primary ink, primary action fill |
| `--blue-200` | `#C4D6F7` | brand mark dot — not a status role |
| `--blue-300` | `#6593E3` | info border |
| `--blue-600` | `#2563EB` | link, focus ring |
| `--blue-700` | `#0550D1` | info text on tint |
| `--blue-800` | `#043B9B` | info `strong` |
| `--green-600` | `#176D42` | verified/safe success |
| `--amber-600` | `#7B3F0A` | warning, approval wait |
| `--red-600` | `#B42318` | critical, denied, failed |
| `--violet-600` | `#6D2E9E` | agent/runtime activity |

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
| `--gray-150` | `#2D3034` |
| `--gray-200` | `#63666A` |
| `--gray-300` | `#5E646C` |
| `--gray-500` | `#9AA1AB` |
| `--gray-700` | `#C4C8CE` |
| `--gray-950` | `#E6E8EB` |
| `--blue-600` | `#7AA5F5` |
| `--blue-700` | `#7BB8F4` |
| `--green-600` | `#4CC38A` |
| `--amber-600` | `#DFA640` |
| `--red-600` | `#F7695F` |
| `--violet-600` | `#C077F8` |

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

Light-theme tuples. Every tuple is derived, not chosen: the tint is the
foreground blended toward the surface until it clears **1.32:1** against the
card, the border until it clears **3.05:1**, and the `strong` step is the
foreground a quarter of the way to ink. The previous tints sat at 1.09–1.16
against the card, which meant a pill was identified almost entirely by its
text colour and flattened first under video compression.

| Status | bg | border | fg | strong |
|---|---|---|---|---|
| success | `#D4E4DC` | `#679F83` | `#176D42` | `#115131` |
| warning | `#E9DED6` | `#B08D6D` | `#7B3F0A` | `#5B2F07` |
| danger | `#F3DBD9` | `#D27C76` | `#B42318` | `#851A12` |
| info | `#D3E1F7` | `#6593E3` | `#0550D1` | `#043B9B` |
| agent | `#E7DCEF` | `#AA85C6` | `#6D2E9E` | `#512275` |
| neutral | `#DFE0E1` | `#929397` | `#363940` | `#17191C` |
| provenance | `#DFE0E1` | `#929397` | `#363940` | `#17191C` |

Dark-theme tuples are defined in `tokens.css` at the same positions and are
derived the same way against the `#17191D` raised surface.

**The border position is `-300`, not `-200`.** A status border must clear
3.05:1 against the card; a `-200` tint must not, and the two were the same
token. Raising the border therefore darkened the brand mark's dot, which
`tools/generate_brand_assets.py` draws from `--blue-200`. They are now separate
positions, and `--blue-200` exists solely for the brand.

`--border-strong` resolves to `--gray-400` at 3.07:1. It was `#D8DCE1` at
1.38:1, and it is the only boundary identifying `.secondary-button` and
`.icon-button`, whose fill equals the card — a non-text contrast failure on
real controls, not a stylistic preference.

### 3.6 Hue separation is checked, not judged

`tools/check_design_system.py` holds every pair of status foregrounds to an
OKLab ΔE floor — 15 under normal vision, 6 under simulated protanopia and
deuteranopia (Machado-Oliveira-Fernandes 2009, severity 1.0) — in both themes,
and requires each hue to clear an OKLCH chroma of 0.10 so it does not read
grey. The check runs in `scripts/check`.

Two pairs are permanently exempt, and the reasoning is recorded so it is not
relitigated:

- **danger against warning**, and **danger against success**. Both were
  searched exhaustively. No amber exists that clears ΔE 15 from this red while
  its foreground still clears 4.5:1 on a tint dark enough to separate from the
  card — a legible amber at that depth is a brown, and a dark brown sits beside
  a dark red in OKLab. The search is infeasible at every tint separation from
  1.10 to 1.32. Under deuteranopia red and green converge by construction; the
  only palettes that satisfy the floor turn success cyan and danger orange,
  which reads as a warning.

The exemption is admissible **only because colour is never the whole signal**:
every status renders through `StatusBadge`, which pairs the tuple with a glyph
and a written label. If a status is ever rendered as colour alone, the
exemption stops being valid and the floor applies.

**Provenance is no longer a hue.** Teal sat ΔE 6.0 from success in light and
6.2 in dark — a collision that survived the theme fork, against the rule below
that an evidence chip must never read as a verification verdict. Seven hued
classes was also one past the point where adjacent classes blur. A source chip
now takes the neutral tuple and is marked by **form**: square corners and a
3px leading rule, against the status pill. Shape survives both themes, video
compression, and every colour vision deficiency.

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
  verification verdict. This is now carried by form rather than hue — see 3.6.

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

Numerals use `font-variant-numeric: tabular-nums` **in columns that must
align vertically** — table rows, axis ticks, timeline stamps. A large
standalone figure does not: tabular gives every digit the width of a `0`, so a
value like `121` reads loose at metric size. Stat-tile and hero figures take
the font's proportional figures.

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
| `--type-mono-sm` | 12/18 | 400 | mono metadata: freshness, matrix cells, diff bodies |
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
- terminal states: square variant — a distinct shape from in-flight circles
  (`SquareCheck` / `SquareX`, both present in the bundled set).

Lucide is the set. It was re-evaluated against Phosphor and kept: the bundled
package carries 2,022 icons to Phosphor's 1,248 and covers this vocabulary
whole, the console has standardised on `strokeWidth={1.75}` across every call
site where Phosphor bakes stroke into a weight axis, and no finding in the
design audit traced to the icon set. Phosphor's weight axis would be the
reason to switch, and only if state is ever encoded by weight systematically;
the backup channel for the exempt CVD pairs in 3.6 is texture, not icon
weight.

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

Status: the annotated incident timeseries ships. `apps/console/src/Timeseries.tsx`
draws it from `series` on the incident projection, built by
`apps/api/incident_series.py` from `evidence_items.series_projection_json`.

**How the points get there.** The Cloud Monitoring request has always carried
`aggregation.alignmentPeriod=60s`, so the provider returns one bucket a minute;
`CloudMonitoringReader` keeps them beside the reduction (specification 13 §4.2)
instead of discarding their timestamps, the Evidence Broker projects them into
the shared `MetricSeries` shape, and acceptance stores a bounded copy in Cloud
SQL. The content itself stays in GCS behind the broker: the console reads Cloud
SQL and holds no customer-evidence read scope.

**The axis is composed, not widened.** `WindowArgs.checked_window()` caps an
evidence window at fifteen minutes because a provider task is bounded and
stateless. An incident-length axis is therefore several consecutive evidence
items concatenated, each separately authorized, classified, redacted and
hashed, so the provenance is N citable windows rather than one. Points are
never interpolated across a gap between items: a gap is a real gap in
observation, and a line through it asserts a measurement nobody took.

**Every annotation resolves to a durable record** — the incident's
`detected_at`, an execution receipt's `started_at`, the verification window,
the profile's comparator. A marker with no record is not drawn. There is no
deploy marker, because no deployment record exists in the schema; when one
exists the marker follows, and until then its absence is the honest state.

**The component computes geometry and nothing else.** It renders an empty state
rather than an empty axis, because a chart with no points still claims a window
was observed. Provider strings are placed as text nodes; there is no markup
path for them.

The sparkline variant below ships on the Overview's active-incident card,
drawn from the same projection and sharing the full chart's mark classes so the
two cannot drift. It is deliberately **not** in the incident queue: that table
already carries eight columns, the repository enforces that no cell overruns
its column at any supported width, and a ninth fixed-width column broke that
contract and cascaded into body overflow on unrelated screens. A dense table is
not a feed row.

**The stat tiles carry their delta and trend.** Nothing new is stored to
supply them: `apps/api/overview_history.py` reconstructs each figure at twelve
day boundaries from records that were already durable — an incident's
`detected_at` and its transitions, a Reliability Case's `created_at`. An
incident counts at a boundary if it had been detected by then and its state as
of then, the target of its last transition at or before that instant, is one
the tile counts. Seeding the walk from the incident's *current* state would
make every historical point report today's answer and the trend would be a flat
line at the present value, which reads as "nothing changed" rather than "we did
not look".

Where the reconstruction and the authoritative count cannot agree — a state
written without a transition, a transition recorded between two reads — the
count wins and the trend's last point is set to it, so a tile can never
contradict the list on the next screen.

**The delta is not coloured by direction.** More open incidents is worse and
more verified mitigations is better, so a single up-is-bad rule would be wrong
half the time, and whether a change is good is a judgement the records do not
carry. The tile states the change and its period and stops.

**The caption is derived, not written.** The line under a tile's figure reads
as part of it, so an operator takes it for a second measurement, and it used to
be a hand-written adjective — "durable", "exact", "stored" — which is the one
part of a tile that asserted something no record said. Each caption is now read
from the same rows the figure counted, at the same instant: the severity
composition of the open incidents, when the earliest scheduled wake-up is due,
how long the longest-waiting approval has waited, and when the most recent
mitigation passed verification. Durations are relative (`in 9h`, `2h`, `4d
ago`) rather than wall-clock, because a time with no date is ambiguous the
moment it is more than a day away and a tile row has no space for a date.

A caption is a claim, so it obeys the withholding rule the rest of the surface
does. "Oldest waiting" and "last verified" are claims about *every* counted
incident, and each is withheld — replaced by `wait time not recorded` or
`verification time not recorded` — unless every one of them carries the
transition that proves it, because the unrecorded one could be the oldest or
the most recent. The wait is measured from the entry into `AWAITING_APPROVAL`
and never from `detected_at`, and from the *last* such entry, since a denied
approval returns the incident to the gate and starts a new wait. Verification
is dated from the entry into `MITIGATED`, which is reachable only by
`VERIFICATION_PASSED`; for a resolved incident the later entry into `RESOLVED`
is the closure, not the verification. `overview_tiles` in
`apps/api/overview_history.py` is the only constructor of a tile row, and
`tile()` takes a `TileDetail` rather than a `str`, so there is no parameter
through which a written caption can reach a tile — including from the scripted
release fixture, which holds records and derives its captions through the same
functions.

**The axis draws a revision marker, not a deploy marker.** Cloud Run returns
`updateTime` on every service read and it was being discarded, so nothing
recorded when the observed revision arrived. It is captured now and projected
onto the axis under the name of what was actually observed — the service last
changed — rather than under "deploy", which would claim a deployment event
nobody recorded.

Deterministic inline SVG with semantic labels. No chart runtime, no canvas,
no network. The hover layer ships with the chart, not after it: a crosshair
snapping to the nearest x, one readout listing every series, the same detail on
keyboard focus as on pointer hover, and hit targets larger than the painted
mark. Series and category names arrive from connector responses and are
untrusted, so they are inserted as text nodes and never as markup.

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
- radius: `--radius-xs` 4 (chips, source tags), `--radius-sm` 6 (controls),
  `--radius-md` 8 (cards), `--radius-lg` 12 (dialogs/drawers),
  `--radius-pill` 999 (status badges);
- elevation tokens: `--shadow-raised` (active tab/segment),
  `--shadow-menu` (popover, floating pill), `--shadow-drawer` (side drawer),
  `--shadow-overlay` (dialog); one `--scrim` for every backdrop. Dark forks all
  five, because the light values are invisible over `#0B0C0E`;
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
