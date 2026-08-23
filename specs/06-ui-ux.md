# Solvan Console UI and UX specification

Status: required competition-release design
Related: [product](01-product-requirements.md), [data/API](04-data-event-api.md), [design system](10-design-system.md), [governed Tool Catalog](16-governed-tool-catalog.md)

The global Settings surface, operator menu, environment selector, preference
persistence, and runtime/governance disclosure are specified in
[the Console Settings specification](15-console-settings.md).

Research provenance: operator-facing interaction patterns were studied across
existing incident-response tooling. Nothing was copied — no assets, copy, or
brand elements — and no studied product is a runtime dependency. The adopted
patterns are the validated-vs-inferred finding split with resolvable evidence
citations, collapsible tool-step evidence rows, a bucketed and numeric
confidence display, todo-style investigation progress, non-guessing hedging
language, and feed-style source-attributed events with an attention rail. All
visual values live in the design system.

## 1. Product surface

The Solvan Console is an operational control surface for incidents, Reliability
Cases, fleet governance, and release evidence. It is not the source of authority
and does not expose unrestricted cloud consoles inside the app.

## 2. Experience goals

An operator must answer within ten seconds:

1. What is affected and how severe is it?
2. What has Solvan independently observed?
3. What has it done versus merely proposed?
4. Is human action required now?
5. What proves recovery or prevents closure?
6. Who/what currently owns the next step?

## 3. Information architecture

Competition navigation:

```text
Overview
Chat
Alerts
Incidents
Reliability Cases
Integrations
Agent Fleet
Release Evidence
Settings
```

`Alerts` is the triage surface of specification 21; `Integrations` is the
estate-connection surface of specification 13. Both ship, and both were absent
from this list.

Incident detail has five tabs:

```text
Timeline | Evidence | Actions | Verification | Permanent Repair
```

Hypotheses and Production Graph context live within Evidence. Approvals live
within Actions. **Chat** is the primary full-page conversation client: it opens
a reader-filtered scope thread from the canonical Liaison ledger and can only
read existing durable projections until the operator selects a narrower
addressable anchor. At incident scale, central Chat offers a reader-filtered,
paginated directory and turns an explicit selection into one visible incident
anchor; it does not put every incident into one conversation. The selected
anchor receives the same conversation controls as the incident-level **Ask the
ledger** rail. The conversational surface — central and per-entity prompt
boxes, threads, anticipated questions,
and the inline-approval rule — is specified separately in [the conversational
surface](14-conversational-surface.md) as a target contract; it adds no
requirement to this specification's competition release. Agent trace opens as a linked drawer/external Agent Observability
view from a timeline step. This keeps the judged UI implementable and coherent.

Fleet uses nine internal tabs without expanding primary navigation:

```text
Agents | Tools | Skills | Alert policies | Capabilities & Policy | Memory |
Security | Audit | Platform
```

The Integrations surface also includes a read-only **GitHub App integration**
panel. It shows the scoped repository binding, installation-token posture,
allowlisted operations, policy/classification, probe state, pull-request
status, exact patch digest, current head/check state, webhook processing, and
operation receipt references. It never displays token values and never offers
a merge or deploy button. A PR may be merged only by the coordinator release
seam after the independent review and check/head gates pass. Target governed
merge and deployment decisions render in the incident's Permanent Repair tab,
not in this credential/integration surface.

Target connection detail follows specification 13's derived health contract.
It shows the friendly instance name first and the exact connection ID,
provider, external project/account/workspace, environment, region, owner,
credential posture, observed capabilities, availability, last attempt, last
success, proof expiry, safe reason, and next step as secondary operational
detail. `Verify again` creates a bounded probe and is labelled as a check, not
as a repair or permission grant. Multiple instances are always separate rows;
the UI never marks one as an implicit provider default.

## 4. Application shell

### Desktop

- 240 px left navigation;
- top bar with environment selector, global autonomy state, security health, and
  operator menu;
- 1,280 px optimized content, fluid above 1,024 px;
- right contextual drawer for evidence/trace/policy details.

### Narrow screens

- navigation becomes a modal drawer;
- tables become labeled card rows without hiding status/units/provenance;
- approval controls remain full-width and digest details stay available;
- incident timeline remains chronological, never a horizontal-only chart.

## 5. Global status

Top bar states:

| State | Copy | Behavior |
|---|---|---|
| healthy | `Autonomy active · europe-west1` | normal |
| paused | `Autonomy paused by {actor}` | no new autonomous roots |
| degraded | `Agent Runtime degraded · work safely queued` | link to affected work |
| security block | `Security policy blocked an interaction` | link to security event |
| region mismatch | `Deployment policy invalid` | release-blocking banner |

Color is accompanied by icon and text. Critical banners cannot auto-dismiss.

## 6. Shared component contracts

### No status is asserted by the console

Every status label, tone and governance-track step is **derived from the
record**. A literal is prohibited wherever the value describes what the system
did: a verdict badge, a phase track, an operator queue and its counts, and any
"verified"/"passed"/"approved" prose. The console is not an authorization
boundary, but it is the operator's only view of one, so a hard-coded success is
the most damaging defect it can carry — it reports an outcome the system never
reached.

Two consequences bind implementations:

- An unrecognised state renders as *not yet reached*, never by inheriting the
  passing look through a fall-through default. `verificationPresentation` maps
  `VERIFIED`/`PASSED`, `FAILED` and `INCONCLUSIVE` explicitly and treats
  everything else as pending.
- A governance track marks the step a record **stopped in**. Terminal failures
  (`FAILED`, `REJECTED`, `EXPIRED`, `CANCELLED`, `BLOCKED`, `ROLLED_BACK`) stop
  the track and mark that step failed rather than ticking the remaining steps,
  so a dead action can never read like a healthy one. `phaseClass` is shared
  precisely so a track cannot be hand-drawn at a call site.

### `StateBadge`

Displays the human label, the exact machine state, an icon, and elapsed time.
The human label is the visible one; the machine state is secondary detail and
is never the primary label.

**The machine state is reachable without a pointer.** A `title` attribute
satisfies hover and nothing else: it is unreachable by keyboard, unavailable on
touch, and announced inconsistently by assistive technology. The state is
therefore carried as text within the badge's accessible name, and `title` is
kept only for the pointer affordance it does serve. This is the same rule the
reference library states for tooltips — a tooltip may carry short helper text,
never the only definition of a critical state.

Terminal and blocked states have distinct shapes/icons, not only colors:
terminal states take the square glyph of design system section 5, so a settled
state differs from one in flight by shape and not merely by wording.

### `ScopePill`

Always shows environment and region for production actions. It cannot be hidden
inside an overflow menu on approval surfaces.

### `EvidenceCard`

Fields:

- observation statement;
- `SourceChip` (design system §6): source icon, name, freshness — rendered in
  the provenance tuple, never the success tuple;
- time window;
- classification/redaction status;
- provenance link;
- supports/contradicts badges;
- Model Armor verdict when relevant.

Raw content is collapsed, size-bounded, safely escaped, and never interpreted as
HTML/Markdown/script.

**Citations must resolve.** A finding statement may cite only evidence IDs that
resolve to real stored records; a citation that resolves to nothing renders the
statement in the *inferred* group (below), never with a dangling reference.

### `SourceChip`

A citation is rendered from the incident's resolved evidence index, never as a
bare identifier. Every chip carries:

- a **kind** icon — metric, log, trace, config, code, receipt, synthetic probe —
  because a reader who cannot tell a chart from a config file cannot weigh the
  claim;
- a **human label** stating what the record shows;
- the **ref**, kept visible but subordinate: it is the address, not the meaning.

Activating a chip opens the contextual evidence drawer (§4) with the record's
source, observation window, freshness, classification, and stored content
reference. Raw content is never inlined; it is fetched only through an
authorized, redacted read.

A ref with no resolving record renders in a distinct **unresolved** style and
is not activatable. A truncated identifier styled as a confident chip is the
appearance of provenance without its function and is prohibited.

The Evidence tab additionally carries an **evidence ledger**: the count of
stored records the incident stands on, each typed and addressable. Validated
finding groups state how many of their citations resolved.

### `FindingBlock`

The narrative finding pattern from design system §7: eyebrow actor/time row,
`--type-title` factual headline, evidence prose in which **bold marks measured
values only**, an annotated timeseries where signals exist, and the block's
`SourceChip`s plus trace link. Findings are grouped under two explicit labels:

- **Validated** — every statement carries resolvable evidence citations;
- **Inferred — not validated** — agent inference without direct observation;
  visually subordinate, never bold-valued, excluded from `OperatorBrief`'s
  "last verified fact."

### `HypothesisCard`

Shows `PROPOSED`, `SUPPORTED`, `CONTRADICTED`, or `CONFIRMED`; confidence is
visually secondary to evidence status. A confirmed badge names the confirmation
rule.

Confidence displays on a dual scale: the visible label is bucketed
(`high / medium / low`) so narrative never implies false precision; the numeric
score appears as secondary mono text and in the data model for routing. The
bucket thresholds are configuration, not model output.

### `ActionCard`

Shows distinct phases:

```text
Proposed -> Awaiting approval -> Authorized -> Executing
-> Reconciling -> Succeeded -> Verifying -> Verified
```

`Succeeded` explicitly means target mutation reconciled, not service recovered.

Required fields: action, target, from/to, risk, blast radius, reversibility,
budget/cooldown, target reservation state, policy, approval state, receipt, and
verification link.

### `ApprovalPanel`

Displays exact digest suffix, target/environment, expected version/epoch,
evidence/policy versions, expiry countdown, rollback plan, uncertainty, and the
exact bound verification profile/version. Approval/reject are separate buttons; reject is not a
secondary tiny link. Approval requires a confirmation dialog that repeats the
exact target and change, not a text phrase challenge.

### `CodeChangeReviewPanel` — `target`, not implemented

The incident's Permanent Repair tab renders a Code Change Request as a
timeline, never as an agent-controlled "deploy" button:

```text
Patch validated → PR-creation approval → PR created → GitHub checks
→ mapped GitHub review + merge approval → protected merge → release candidate
→ deployment approval → canary → independent verification
```

The panel shows the exact diff itself (with a visible truncation boundary),
base and current head commits, changed paths, independent adjudication receipt,
GitHub PR and required-review/check/branch-protection projections, immutable
release candidate/provenance, target, rollout policy, predeploy health
snapshot, verifier profile, and expiry. It links to the canonical GitHub PR
for code review. A current, authorized reviewer may make a console
`PR_CREATION`, `MERGE`, `DEPLOYMENT`, or `ROLLBACK` decision only after an
explicit confirmation repeats that stage's exact material. The first two require
`CODE_CHANGE_APPROVER`; the latter two require `RELEASE_APPROVER`; all positive
decisions record the exact verified principal and current role at that stage.
One person may hold both roles and approve several stages. `MERGE` additionally
shows the verified Solvan-to-GitHub account binding and the specific GitHub
review that satisfies the frozen reviewer policy; a similarly named account or
another review cannot be substituted. `ROLLBACK` renders the frozen previous
release, observed current target state, failure receipt, and human recovery
route on rejection or ambiguity.

For a Workspace-authored patch, the same panel first renders a **Repair
proposal** section from durable records: frozen repository/base-tree and path
policy, exact `workspace.code-repair.v1` profile and selected skill hashes,
candidate-tree and exploratory receipt hashes, independent-adjudication status,
changed paths, uncertainty, and residual risks. Exploratory results are labelled
**experimental — not release evidence**. A missing/failed/stale selection,
profile, candidate, or adjudication has an explicit reason and never shows a
PR-creation control. The panel may link to safe bounded source/candidate views;
it never renders raw guidance bodies, source files, sandbox output, credentials,
or model reasoning by default.

The authenticated console's **Settings → Identity → GitHub** surface owns
personal account linking; the Integrations page's GitHub App panel remains an
administrator-only repository-installation surface and must never imply that
an administrator connected another person's identity. A current
`CODE_CHANGE_APPROVER` selects one active repository binding and clicks
**Connect GitHub identity**. Before leaving Solvan, the console explains that
GitHub will identify the account, that Solvan will retain the immutable account
identifier and proof rather than a personal token, and that this does not grant
the person or Solvan additional repository permissions. It opens only the
server-created authorization URL in the same browser flow; it never asks the
user to paste a token, username, email, code, client secret, or callback URL.

On return, the page shows a redacted account label, exact repository binding,
link creation/proof time, policy version, expiry/revalidation state, and a
**Disconnect** control. It never displays token values or a success state based
only on a login string. Pending, expired, refused, callback-mismatch,
authorization-denied, policy-changed, installation-changed, and revalidation
states are explicit and say that merge authority is unavailable until a fresh
link succeeds. Disconnect requires a confirmation that states it immediately
invalidates this account for Solvan merge decisions; it records a local
revocation rather than promising to revoke the user's GitHub authorization.
Only the linked user sees their identity-binding detail by default; authorized
administrators may see an opaque audit/status projection, never a token or
personal OAuth response.

The client never supplies a digest, head SHA, target, required-check state,
approval grant, operation ID, GitHub account, or rollback release. It requests
the panel by opaque locator and the server derives all decision material from
current durable records. Changed base/head/tree, checks, branch rules, reviewer
binding, candidate, target, policy, or expiry renders the decision stale and
removes the control. Pending external effects show `prepared`, `issued`, or
`reconciling` honestly; the UI never offers a retry that could issue a second
effect.

External Chat/Slack/email/Discord cards are status and deep-link surfaces only.
They never render a decision control. A verifier result is displayed as an
independent receipt and, on failure, a rollback proposal; it is not a green
agent assertion and it does not automatically roll back production.

### `AgentStep`

Shows role, registered version, status, duration, tool count, budget, fallback,
trace link, and result summary. It never displays hidden reasoning.

Expanding an `AgentStep` reveals its **tool rows**: one collapsible row per
registered tool call, with tool icon and name, the typed query summary in
`--type-mono` (truncated, expandable), status (running spinner is
motion-gated; completed is a neutral check — not verified-green), duration,
and a bounded, escaped result excerpt. Tool rows are the public activity
record — tool names, typed parameters, result classes — never prompt text or
chain-of-thought.

### `InvestigationMap`

Renders the accepted durable plan as an accessible dependency list/DAG. Every
step shows bounded purpose, required/optional state, dependencies, registered
agent/version, durable status, elapsed/queued time, tool/model budget consumed,
new evidence count, fallback, and trace link. Parallel branches align visually;
the equivalent ordered list is always available. Superseded plans remain
selectable and are never blended into the current version.

The component toggles between `Plan` (dependency view) and `Run timeline`
(time-aligned queued/running intervals). Both modes use the same durable data;
the detailed list is the accessible source representation.

A one-line progress header precedes the map — `3 completed · 1 running ·
2 pending` — with `[✓] / [~] / [ ]` markers on the ordered list so plan
progress is scannable without parsing the DAG.

### `OperatorBrief`

A structured, citation-bearing catch-up card with impact, last verified fact,
confirmed root cause or explicitly labelled leading hypothesis, action and
recovery state, required human attention, next step/owner, last committed event
sequence, and freshness. It is produced from durable projections, not a chat
transcript. Stale data, missing evidence, and unconfirmed diagnosis are stated
directly; the brief cannot override the underlying state.

The brief leads with the situation sentence itself — no "Summary" heading
above it. When a decision was informed by retrieved memories, the brief shows
a `Recalled` chip per memory ID (provenance tuple) linking to the memory
record, so memory influence is visible and auditable.

### `BaselineComparison`

Aligns five labeled intervals on the same time axis: healthy baseline, fault,
mutation, warmup, and post-action observation. It overlays the immutable
profile threshold and identifies the fresh synthetic probe. Baseline values are
comparison context only and the component never implies that the threshold was
derived or changed during the incident.

### `ProvenanceDiff`

Shows an effective policy or capability value beside the resolution chain that
produced it: local value, inherited values, Registry declaration, IAM/Gateway
enforcement, and frozen release-manifest reference. It highlights the winning
value and denied/mismatched layers using structured fields—not editable raw
JSON. Missing access displays `Restricted`, not a partial value.

### `MemoryCandidateCard`

Shows safe candidate summary, type, exact scope/purpose, source count and links,
confirmation and verification references, classification/residency, Armor and
redaction status, retention/expiry, review requirement, decision, actor, and
trace. The MSR surface is read-only; manual review controls are a target and
must use a dedicated typed review flow rather than a generic confirm dialog.

### `AuditEventRow`

Shows immutable sequence, time, principal, event/result, scope, decision/result
reference, correlation/trace link, and safe payload hash. Rows expand to
authorized structured metadata. Raw untrusted payloads do not appear inline.

### `VerificationPanel`

Shows profile owner/version, independently resolved binding, warmup/observation
window, each signal threshold and observed series/result, synthetic receipt,
guardrails, verdict, and missing/contradictory signals.

### `SecurityEventCard`

Shows control (`Model Armor`, `Gateway`, `IAM`, `scope`, `memory gate`), safe
summary, denied destination/action, affected trace, and whether work continued.
It never reveals the blocked secret/PII.

## 7. Overview screen

Primary cards:

- production health;
- open incidents;
- open Reliability Cases;
- awaiting approval;
- autonomous mitigations verified;
- policy/security blocks;
- MTTD and detection-to-recovery metric.

Below:

- active incident list ordered by severity then age;
- Reliability Cases requiring attention;
- fleet control health (Registry, Runtime, Memory, Identity, Gateway, Armor,
  Observability);
- durable work queue health: ready, running, sleeping, overdue, and fenced;
- recent verified outcomes.

An **attention rail** (right rail, `--rail-width`; drawer below 1180 px)
groups the operator's now-work as collapsible sections with counts:

```text
Needs approval        1   ← expanded by default when non-zero
Executing             2
Scheduled wake-ups    3
Recently verified     5   · last 24h
```

Rail rows are compact cards: one-line statement with `MonoChip` identifiers,
relative age, and state badge. Counts derive from the same durable projections
as the queues they link to — the rail is a projection, never a second source
of truth.

No invented aggregate “AI confidence” score appears.

## 8. Incidents list

Columns:

```text
ID | Severity | Service | State | Customer impact | Current owner | Age | Next action
```

**Customer impact is a column, not a detail-page fact.** A queue cannot be
triaged from severity and state alone: those say how loudly the system is
complaining, not what it cost anyone. The cell states the measured consequence
in one line ("18.4% of payment writes failed for 8m 10s").

Environment is deliberately *not* a column. It is constant across every row in
a scoped view, and a column that never varies spends width without informing.
It stays in the shell's scope indicator and in the incident header.

A row whose next durable step is blocked on a person is marked structurally —
a leading rule on the row plus emphasis on the next action — never by colour
alone, and the count of such rows appears on the filter control.

Filters: active/terminal, severity, service, environment, human attention,
autonomous action, security block. Every filter and the search box must
actually filter; a control that renders but does not act is prohibited. Filter
state persists in URL. Empty and permission-denied results are distinguished.

## 9. Incident detail

### Header

- incident ID/title, severity, state, affected services;
- environment/region;
- detected time and clocks;
- current owner/lease health;
- global action: `Escalate`, and authorized `Cancel` under overflow;
- linked Reliability Case.

Immediately below the header, `OperatorBrief` answers the six experience-goal
questions without requiring the operator to read the full timeline. Updating
the brief never changes incident state, action authority, or verification.

A compact **Related Alerts** panel follows the brief when reader-visible Alert
links exist. It identifies whether each Alert opened this Incident or attached
through deduplication, shows source freshness and current disposition, and
links to the Alert report. `Provider reports cleared` and `Recovery independently
verified` are separate fields and labels; one never implies the other. The
panel is produced by specification 21's reader-filtered projection, so hidden
Alerts contribute no count, cursor, time, title, or relationship signal.

The brief's impact is **structured, not a sentence**. It opens with the single
duration a person is asked for first — how long customers were affected, with
its start and end — and then one row per measured signal, each naming the
metric, the scope it happened to, and its citation. A single unattributed
percentage is not impact; it cannot be acted on and cannot be checked. Where a
signal establishes containment ("0 downstream services affected") that is a
finding and is shown, not omitted as an absence. A data-loss statement is made
only when an independent verification supports it; otherwise the line is absent
rather than reassuring.

Where no impact rows have been observed, the brief falls back to the one-line
summary. It never fabricates rows to fill the shape.

### Timeline

Chronological committed events rendered as a **source-attributed feed**: each
event card carries its origin identity (source icon + name — detection rule,
agent, connector, approver, scheduler) and timestamp in an eyebrow row, then
the event content. Material moments — a committed finding, a proposed action,
a verification verdict — render as full `FindingBlock`/`ActionCard`/
`VerificationPanel` summaries inline; routine events render as compact rows.
Each row shows actor, event, timestamp, state/version, and
evidence/action/trace links. Pending streaming animation may appear only for
an existing durable run; reconnect rebuilds from snapshot.

### Evidence

Four panels:

1. accepted investigation plan and parallel step progress;
2. observed signals and artifacts;
3. hypotheses with supporting/contradicting references;
4. relevant Production Graph slice and recent changes.

Poisoned evidence remains visible as a security-labeled record without showing
unsafe raw text by default.

### Actions

Action sequence, circuit-breaker budget, cooldown, reservations, approvals,
execution receipts, and exact before/after target state. Conflicting target
reservation shows the other incident ID only if operator is authorized for it.

### Action authority and mitigation experience — target

The action view makes the policy decision understandable without creating an
alternate control plane. It renders a durable, source-attributed activity trail
from proposal through authorization, execution receipt, reconciliation, and
independent verification. At the applicable point it also renders an exact
approval as pending/approved/rejected/expired/revoked, or an autonomous
authorization as eligible/denied. Failed, cancelled, and ambiguous outcomes are
shown as such. The UI derives these labels from canonical durable records; it
does not infer a state, collapse a failed action into a successful one, or offer
a browser-only state transition.

Every proposed or authorized action has a concise **Why this action?** card
with the registered action type, authority class (autonomous,
approval-bound, or disabled), policy version and provenance, risk and
reversibility, intended effect, exact target, expiry and preconditions,
reservation/idempotency reference, approval reference where required, and links
to receipts and the verification profile. Execution success, reconciliation,
and recovery verification remain visibly separate; `MITIGATED` is not rendered
as permanent closure when its Reliability Case remains open.

Where an effective action policy is scoped, the card and governance surface
show whether it came from the global, team, or service layer and identify the
winning immutable policy record. An absent, stale, or unauthorized projection
renders as unavailable and cannot be presented as a permissive default. Policy
editing remains in its typed, reviewed administration workflow rather than this
incident view.

Before an action is offered, the view exposes safe integration-health and
permission diagnostics: connection/actuator availability, required capability,
policy freshness, and the reason a proposal is blocked. It never exposes a
credential, raw provider response, or a control that asks Slack or another
external conversational channel to approve a production change.

### Verification

Live/past verification runs. Graphs have equivalent tables. Verdict remains
`INCONCLUSIVE` until complete. The “mark healthy” operator action does not exist;
operators may escalate/accept ownership, not forge verification.

The primary run view uses `BaselineComparison` and a signal table. It labels the
healthy baseline, injected/observed fault interval, exact action interval,
warmup, approved observation window, and fresh synthetic probe. Connector
reconciliation and model/coding tests are visually separated from the recovery
oracle.

### Permanent Repair

Reliability Case status, provider, repository commit snapshot, patch artifact,
test receipts, review/merge/canary/rollout/observation steps, next wake-up, and
blocked reason/recovery action.

**An exact patch review renders the change, not only its digest.** The digest
proves *which* change is meant; it gives a reviewer no way to judge it, so
approval is never offered over a hash and a storage URI alone. The panel shows
the parsed unified diff: per file, the path, added/removed counts, and every
line with its old and new line numbers and an add/remove marker that is not
colour alone.

The rendered diff is bounded (files, lines, and line length) and its bytes are
accepted only when their hash matches the durable ledger, so the diff read is
the diff the digest commits to. Three failure modes are stated rather than
hidden:

- content that exceeds the ceiling is labelled truncated, with the instruction
  to read the full artifact before approving — never silently sampled;
- content that cannot be parsed reports that no reviewable change was found;
- content that cannot be read and hash-verified says so and directs the
  reviewer to the source.

Diff text is carried verbatim and rendered as text. It is never interpreted as
markup, and never used to derive a control.

An optional target `WorkspaceCognitionPanel` makes the role boundary visible:

- `Lead investigator` and `Repair implementer` identify the same logical
  Incident Workspace while showing distinct task runs and artifact hashes;
- mechanism, contradictions, reproduction, patch, regression test, and clone
  pre-validation appear as linked but separately typed artifacts;
- provider eligibility, data classification, synthetic attestation, workspace
  generation, request status, Cloud Run revision/boot identity, checkpoint, and
  rehydration state are visible;
- the synthetic-attestation and provider-eligibility rows resolve to signed,
  immutable receipts; the UI never derives eligibility from fixture labels;
- `Proposed by workspace`, `Deterministic tests passed`, `Review approved`,
  `Deployed`, and `Production recovery verified` are separate states;
- the panel never offers approve, merge, deploy, mark-healthy, resolve, close,
  memory-promote, or Production-Graph-promote controls to the workspace actor;
- an independent critic, when present, is labeled with its separate identity
  and environment and is never presented as the production verifier.

## 10. Reliability Cases

List columns: case, service, state, originating/latest incident, age, repair
status, next action/time, owner. Detail uses a phase rail:

```text
Root cause -> Repair -> Review -> Canary -> Rollout -> Observation -> Closed
```

Recurrence displays the prior closed incident and new incident separately.

Below the phase rail, a continuity ledger groups actual checkpoints by calendar
day. It shows scheduled wake-up, claim/lease, execution or review receipt,
completion, next wake-up, overdue state, resume cause, and accountable owner.
Gaps display `No process running · next wake-up {time}` rather than an activity
spinner. Seeded proof is labeled as a replay of cited real receipts.

## 11. Fleet screen

### Agents

Registry-backed catalog cards show name/version, owner department, discoverable
departments, capabilities, region, framework/model, approval/lifecycle,
evaluation status, and identity suffix.

The primary names are `Incident Supervisor Agent`, `Evidence Agent`,
`Infrastructure Agent`, `Execution Agent`, `Verification Agent`, and
`Workspace Agent`. Stable keys such as `evidence-agent` appear only as
secondary technical metadata. Cards never use a vendor name such as `AWS
Agent` or `K8s Agent`; those capabilities appear as exact profiles on the
applicable institutional Agent.

Agent detail includes durable run history grouped by incident/case and plan
step. Filters cover agent, version, status, trigger, environment, and time. The
trace disclosure shows redacted typed input/output summaries, timing, tool
counts, budget, error class, and fallback; it links to Agent Observability for
the full authorized trace.

### Deterministic seats

Above the agent catalog, the Agents tab lists the seats that hold production
mutation capability. They are registered and identified exactly like an agent —
service account, region, image — but they are not model-backed, and the tab
states that plainly: every agent below can reason and none can change
production; these seats can change production and cannot reason.

A seat card names its allowed operations as literal enumerated tokens
(`PAYMENTS_POOL_RECYCLE`, `CLOUD_RUN_TRAFFIC_ROLLBACK`), not a prose
description, because the enumeration *is* the control. A seat never carries the
agent tone. When no actuator is registered the section is absent rather than
shown empty, so an unowned mutation destination is visible by its absence in
the capability matrix rather than concealed by a placeholder.

### Tools

The target read-only Tools tab implements specification 16 as a list and a
detail, and it never renders a fact on every row that holds the same value on
every row. The list groups revisions by requesting Agent and shows, per row,
the capability name, permission class, and destination — the facts an operator
chooses between. A row carries an availability badge only where it departs from
the fleet-wide state; when one cause blocks the whole catalog, that `Why` and
its `Next step` are stated once above the list rather than repeated per row.

A Tool that has never been probed in this scope reads `Not configured`, not
`Unavailable`. Both deny selection identically, but only the second is a fault,
and a catalog nobody has connected must not present itself as a catalog that is
broken. Specification 16 §10.1 holds the full vocabulary and its tones.

Opening a row shows the whole governance record for that exact revision: owner,
requesting Agent, Registry/Gateway/Identity provenance, Model Armor coverage,
region, bound connection, lifecycle, availability, evidence, deployment, last
probe and expiry, call budget, timeout, payload ceiling, last call, trace link,
`Why`, and `Next step`. Each status value is rendered beside the definition of
its dimension, so the vocabulary is learned where it is used and no separate
legend is required. Connection enrollment, credentials, and provider setup
remain under `Settings → Integrations`; Fleet links there but does not
duplicate setup.

### Skills

The target read-only **Skills** tab implements specifications 17 and 18. The
domain continues to call the records `GuidanceRevision` because a skill is
governed operational guidance, but the operator-facing catalog uses the plain
word “Skills” to match the interchange format and the user task.

The first viewport is a browse-first catalog, not an administrative form. It
provides Grid/List toggles, search, source and lifecycle filters, and a clearly
scoped `Add / import skill` action. Each card shows the skill name, revision,
source type and reference, owner/author, last synced or last edited timestamp,
lifecycle, availability, and evaluation state. Imported repository skills and
authored skills are visually distinguishable without implying that either is
approved or executable.

Selecting a card opens a detail panel with classification, region, allowed
Agents, revision digest, lineage/evidence summary, and the next safe step. The
panel links to the governed lifecycle workflow rather than exposing commands
inline by default. Import, quarantine diagnostics, license/scanner receipts,
compile metadata, independent evaluation, approval, refresh notices, and
export receipts remain available to an authorized operator from that workflow.

Skills detail does not render secrets, unsafe raw provider errors, unrestricted
commands, or content the current reader cannot access. Authoring, approval,
publishing, and retirement still require the immutable administrative workflow
specified in specification 17; the catalog never grants selection, dispatch,
mutation, or verification authority.

### Alert policies

The target **Alert policies** tab implements
[specification 21](21-alert-triage.md) §10.5: a read-only lifecycle view of
alert admission policy revisions — never an alert queue. Each revision states
lifecycle, availability, source-connection health, last match, last triage,
current capacity, suppression count, and evaluation/approval evidence, with a
clear `Why / Next step` for every non-admitting state. A scope with no policy
states that plainly and points at the calibrated templates; a reader without
the alert reader grant is told which grant is missing rather than shown a
generic failure. Scripted development data always carries its provenance
notice. Alert episodes themselves live under the primary `Alerts` route.

### Capabilities & Policy

Rows are agents; columns are registered destinations/tools. Cells show
`allowed`, `denied`, `not registered`, or `not evaluated`, with policy/IAM
references. Discovery and permission are visibly distinct. For MSR this is a
read-only rendering of the frozen release manifest and preflight receipt, not
live IAM introspection.

`not evaluated` is the fourth value because three could not state the truth. A
capability whose authority no record has observed — no bound preflight receipt
registers its Gateway route, no probe has run — has been refused by nobody.
Reporting it as `denied` asserts an enforcement decision that did not happen,
and on a capability reaching the actuator it understates production mutation
authority rather than overstating it. `not registered` stays distinct in the
other direction: that capability sits in no approved profile and was offered to
no one.

A cell's verdict comes from the same rule the coordinator applies when it binds
a run, over the ordered chain in [specification 16](16-governed-tool-catalog.md)
section 10. The UI never re-derives it, and a capability is `allowed` only when
every applicable authority is satisfied; one unobserved authority withholds the
grant. Where several capabilities share a cell and disagree, the cell says so
rather than reporting the most permissive of them.

Severity follows the layer that refused, not the word it produced. A capability
refused for want of an enrolled connection is an unstarted setup step; one
refused by a retired revision or an unrouted destination is a governance state.
Rendering both as faults presents a fresh installation as a page of problems,
which is the same error corrected in the Tool catalog's `Not configured`.

Selecting a cell opens `ProvenanceDiff`, including the effective value and each
source layer with the record supporting it and when it was observed, and marks
the layer that decided. The UI never offers raw policy JSON editing or implies
that a Registry discovery grant is execution authority.

### Memory

Read-only MSR queues: `Pending`, `Quarantined`, `Rejected`, `Promoted`, and
`Expired`. Filters cover purpose, classification, service, decision reason, and
time. Candidate detail uses `MemoryCandidateCard`; promoted content remains
bounded to caller scope. A poisoning denial links the candidate, security event,
policy decision, and trace without rendering the malicious raw instruction.

Manual candidate approval/rejection, semantic diff, bulk expiry, and purge are
post-MSR targets. They require separate roles, immutable decisions, stale-state
handling, and derived-memory impact preview.

### Security

Security events group by control and severity, with filters for incident,
agent, destination, environment, and time. The view shows whether the original
work safely continued, degraded, or escalated. It never reveals the blocked
secret, PII, or injection body.

### Audit

The MSR view is a read-only, sequence-ordered projection with filters for actor,
stream, event, result, agent, incident/case, and time. Export, saved searches,
and long-retention compliance reports are targets. Audit rows link to policy,
approval, receipt, verification, memory, security, and trace records when the
operator is authorized.

### Platform health

Shows region/project alignment, Registry/Gateway association, Memory scopes,
Armor template versions, trace ingestion time, and Preview feature status. The
view keeps three dimensions separate: lifecycle (`planned`, `implemented`,
`provisioned`, `deployed`), derived health (`healthy`, `degraded`, `blocked`,
`unknown`), and evidence scope (`local verified`, `cloud verified`,
`unverified`). It shows the last check and one safe next step for every
non-healthy or non-cloud-verified component. Health is derived from checks; the
console never offers a manual “mark healthy” action.

The page includes a short visible “How to read platform status” explanation.
Essential definitions are not tooltip-only. Tooltips may provide brief help for
technical terms, while longer remediation guidance belongs in an expandable
detail or linked runbook. Local checks must be labeled as local and must never
be presented as cloud deployment proof.

## 12. Release Evidence screen

Competition-only surface:

- six acceptance scenarios and current pass/fail/not-run;
- latest evidence receipt and environment/commit;
- recovery experiment receipt with baseline/fault/action/oracle phases and
  grader-isolation attestation;
- Google Cloud deployment proof;
- platform preflight;
- clean-start instructions link;
- demo readiness timer/checklist.

This screen never allows a model to mark a test passed.

In the GCP release, the API reads only the immutable evidence bucket and binds
the view to its configured full commit, project, region, deployment ID, and
bucket. It re-evaluates the canonical preflight document, validates every
content hash, and accepts only `LIVE_GCP` for S1 and `SCRIPTED_GCP` for S2–S6.
Malformed, local, cross-project, cross-deployment, wrong-mode, or out-of-bucket
receipts cannot promote the view. The console says
`BOUND_GCP_EVIDENCE_COMPLETE` only when this exact cloud set is complete; that
label deliberately does not claim the separate local or submission gates.
Pending controls use an open-circle state and never render as verified.

## 13. Interaction behavior

### Reconnect

Client fetches authoritative snapshot, then subscribes from last event sequence.
Duplicates are reducer-idempotent. A gap triggers snapshot refresh.

### Stale action

HTTP 409/412 preserves typed operator input, refreshes the action, explains the
changed version, and requires a new explicit decision.

### Long-running state

No indefinite spinner. Show durable status, last heartbeat, next check, and
safe navigation-away message. Browser closure does not cancel work.

An authorized operator may request cancellation of an active Agent attempt.
The UI distinguishes `Cancellation requested`, provider acknowledgement,
`Cancelled`, and `Cancellation unconfirmed`; closing a modal or browser tab is
never presented as cancellation. Resume creates and links a new durable
attempt after authority reconciliation. Context compaction is shown only as a
conversation-history boundary and never as evidence deletion or workflow
completion.

### Errors

User-facing copy includes what failed, whether work is safe, what Solvan will do
next, and available operator action. Correlation ID is copyable.

Native browser `alert`, `confirm`, and `prompt` are prohibited. Consequential
decisions use accessible typed dialogs; non-blocking results use inline status
or an announced toast that never contains the only copy of a receipt/error.

### Queue and master-detail behavior

Operational queues preserve filters in the URL, expose counts by meaningful
state, and open detail without losing list position. Counts never mix severity,
risk, and urgency. Bulk mutation is absent from the MSR. Empty, filtered-empty,
unauthorized, stale, and subsystem-degraded states remain distinct.

## 14. Content design

Use factual verbs:

- `proposed`, not `fixed`;
- `mutation reconciled`, not `recovered`;
- `verification passed`, not `looks good`;
- `blocked by Gateway`, not `AI refused`;
- `evidence supports`, not `root cause` until confirmed;
- `memory candidate rejected`, not `forgot` unless purge completed.

Hedging discipline for agent-produced text:

- an observed failure and an obstructed investigation are different sentences:
  `Found connection-pool exhaustion in payments-api logs` versus
  `Could not read Cloud SQL metrics — capacity evidence is incomplete`; the
  UI never lets the second read as the first;
- `could not verify` is stated outright; a gap is never papered over with a
  plausible guess;
- every quantitative claim names its window and baseline
  (`2.7 s p95, up from 210 ms 7-day baseline`);
- bold in narrative text marks measured values only.

## 15. Accessibility

MSR requires axe smoke on Overview, Incident detail, and Approval plus a
keyboard-complete approval/rejection flow, labelled controls, visible focus,
approved contrast tokens, and no color-only state. Full WCAG 2.2 AA coverage,
multiple screen-reader passes, every route/state, zoom, and motion matrices are
target after MSR.

- target WCAG 2.2 AA;
- visible focus for every interactive element;
- logical DOM order and landmark headings;
- 44×44 CSS px minimum critical action targets;
- charts include tables and summaries;
- live regions announce state changes without reading the entire timeline;
- no auto-focus steal when background events arrive;
- confirmation dialogs trap focus and return it to the invoking control;
- durations and timestamps have screen-reader-expanded labels;
- reduced motion and high-contrast modes are tested.

## 16. UI security

- escape all evidence and model output;
- no `dangerouslySetInnerHTML` for operational content;
- strict CSP; no remote scripts/fonts in release;
- sensitive raw evidence never enters list responses;
- authorization checked on every detail endpoint, not hidden only in UI;
- trace links open authorized Cloud Console routes without embedding tokens;
- browser storage contains no evidence payload, credentials, or approval secret.

## 17. UI acceptance criteria

1. Operator distinguishes proposed, executed, reconciled, and verified action.
2. Approval always shows target, environment, digest, version, risk, and expiry.
3. Agent failure/fallback and security denial are visible in the same incident.
4. Recurrence shows a new incident without rewriting the historical one.
5. Keyboard-only user completes rollback approval/rejection and inspects proof.
6. Every verification chart has an equivalent table.
7. Reload/reconnect reproduces exact committed timeline order without duplicates.
8. Mobile/narrow view retains all approval-critical fields.
9. Operator identifies parallel, blocked, failed, and superseded investigation
   branches without opening a model transcript.
10. Verification shows baseline, fault, action, warmup, observation, threshold,
    and fresh-probe evidence without implying dynamic threshold changes.
11. Fleet distinguishes discovery, effective policy provenance, and enforced
    permission, and exposes scoped memory/security/audit evidence.
12. Multi-day case continuity remains understandable when no process is running.
13. Operator brief identifies current impact, last verified fact, human need,
    and next owner with citations and an explicit freshness marker.
14. Validated and inferred findings are visually and semantically distinct, and
    no rendered citation resolves to a missing evidence record.
15. Memory-informed decisions display their `Recalled` memory IDs.
16. An obstructed investigation is never presented as an observed failure.
17. Every rendered citation states its kind and its claim, and opens the stored
    record; an unresolvable reference is styled as unresolved and is inert.
18. Impact is reported as a duration plus per-signal rows naming their scope,
    never as a single unattributed number.
19. An exact patch review renders the change itself; approval is never offered
    over a digest and a storage reference alone, and a diff shown under a
    ceiling says it was truncated.
20. Incident queue triage is possible from the list alone: customer impact is a
    column, rows blocked on a person are marked structurally, and every filter
    and search control actually filters.
21. Target: every non-ready connection shows a safe reason and next step;
    multiple provider instances remain distinct and no UI default implies
    routing authority.
22. Target: guidance discovery, approval, selection, step predicate status, and
    incident truth are distinct; an Agent narration cannot render a completed
    checklist step.
23. Target: cancellation request, provider acknowledgement, terminal
    cancellation, late-output fencing, and resumed attempt are not conflated.
24. Target: every §18 skills surface renders untrusted skill content as
    escaped plain text, and no import, approval, or export decision is
    offered without its exact digest and closed reason material.

## 18. Skills surfaces (target)

Status: target; this section renders the lifecycle defined in the
[Agent Skills interchange](18-agent-skills-interchange.md) and
[governed operational guidance](17-governed-operational-guidance.md)
specifications. Nothing here enters the release gate of §17 items 1–20.

The Skills tab presents one lineage-centric catalog with lifecycle badges
(`DRAFT`, `IN_REVIEW`, `APPROVED`, `DEPRECATED`, `RETIRED`), owning
department, and qualified selector. Seven surfaces, all subject to §16 UI
security:

1. **Import.** Start an import from a registered connection or upload;
   the attempt list shows every `skill_import_attempt` with its closed
   rejection reasons. There is no silent failure path.
2. **Quarantine detail.** Findings from the closed decision table, per-file
   dispositions, license evidence with location and digest, and upstream
   refresh notices. Skill content renders as escaped plain text only —
   never Markdown-rendered, never executable, exactly as evidence rows in
   §6.
3. **Compilation.** The authoring form for governed metadata, the typed
   step-graph editor with the advisory-checkpoint default, and the
   normalized license identifier proposal. Missing required material is
   shown as blocking, not deferred.
4. **Approval.** The reviewer sees the reviewable-material digest, the
   evaluation results bound to that digest, and a diff rendered from the
   canonical prompt-content manifests of the revision and its named
   predecessor (truncation labelled per §17 item 19); approval is offered
   only over that digest, mirroring action approval in §9. A fetch-content
   checkpoint is always labelled "fetched", never "consulted".
5. **Selection history.** Per-lineage analytics from the interchange
   specification §10.1: shortlist appearances, selection reasons, refusals,
   and step outcomes — counters and closed codes, never content. This is
   the description-tuning surface.
6. **Operator-explicit selection.** The conversational composer autocompletes
   eligible qualified selectors; ambiguity shows the closed disambiguation
   list; the untrusted note is visibly labelled as a note, not a command.
7. **Export.** The authorization flow names the destination binding and
   purpose, shows the redistribution check result, and lists export
   receipts.

Guidance state on an incident or case remains governed by §17 item 22:
discovery, approval, selection, predicate status, and incident truth stay
visually and semantically distinct.
