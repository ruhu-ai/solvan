# Solvan competition demo and submission specification

Status: required competition contract
Official sources reviewed: 2026-08-08
Rules: <https://allthingsagentichackathon.devpost.com/rules>

## 1. Category and thesis

Category: **Fortified Enterprise Fleet**.

One-line thesis:

> Solvan is a governed fleet of institutional agents that detects production
> degradation, executes bounded recovery, verifies the outcome independently,
> and maintains ownership through a multi-day permanent-repair case.

The judged vertical slice is the isolated payments fault-drill stack. It
is an acceptance workload enabled only in a dedicated dev/staging deployment,
not Solvan's product environment model. Ruhu is Solvan's
first target design-partner workload, but it is not shown as implemented or used
to replace any required payments proof unless its applicable adoption-phase
receipts independently pass before the release freeze.

## 2. Mandatory technology proof

| Rule/track requirement | Submission proof |
|---|---|
| Gemini 3.5+ | model resource in Runtime deployment, trace/model call, README |
| Google agent framework | Google ADK agent source and manifest |
| Google Cloud infrastructure | Agent Runtime, Cloud Run, Cloud SQL, Pub/Sub, Scheduler |
| Agent Registry | live catalog with versions/capabilities/departments |
| Agent Runtime | real bounded agent executions and resume |
| Memory Bank | exact-scope recall and gated promotion/denial |
| Agent Identity | distinct SPIFFE principals and IAM matrix |
| Agent Gateway | live allowed route plus denied bypass |
| Model Armor | injection verdict and continued safe investigation |
| Agent Observability | OTel trace DAG/topology and correlated domain timeline |
| weeks/asynchronous context | actual persisted multi-day case and live next-step resume |
| production-data safety | real synthetic GCP telemetry under classification/residency policy |

## 3. Submission checklist

Required before the deadline:

- Devpost project assigned to one category;
- working deployment/test build available through judging period;
- English project description;
- public or private source repository with the rule-required judge access;
- README with clean install/deploy/spin-up/test steps;
- architecture diagram;
- public YouTube or Vimeo video, ≤ 4:00, English or English subtitles;
- visible Google Cloud backend proof;
- disclosure of pre-existing code/assets and third-party/open-source licenses;
- all team members added and representative identified;
- final submitted commit/deployment/artifacts frozen.

Credit request deadline is August 28, 2026 at 12:00 PM PT while supplies last.
Submission deadline is August 31, 2026 at 5:00 PM PT / September 1 at 1:00 AM
WAT.

## 4. Four-minute video storyboard

Target runtime: **3:35–3:45**, leaving upload/player margin.

### 0:00–0:20 — Thesis and architecture

- one sentence on outcome ownership;
- architecture overlay: Cloud SQL durable case + Agent Runtime fleet + GEAP
  governance;
- show GCP project/region briefly.

### 0:20–0:45 — Institutional fleet

- Fleet screen with Registry agents, versions, department reuse;
- identity/permission matrix plus one effective-policy provenance disclosure;
- call out separate read, execute, and verify identities.

### 0:45–1:15 — Real incident begins

- healthy live payments traffic;
- inject/deploy v2.8.1;
- metrics degrade and incident opens automatically without prompt;
- show real Cloud SQL/timeline commit or GCP logs.

### 1:15–1:50 — Investigation survives attack/failure

- Evidence and Infrastructure agents run in parallel;
- durable investigation map shows both branches, budgets, and evidence delta;
- malicious log triggers Model Armor/security event;
- one Evidence attempt loops/crashes, budget stops it, fallback resumes;
- show correlated Agent Observability trace.

### 1:50–2:20 — Autonomous real action

- policy-authorized connection-pool recycle through the private actuator;
- target reservation acquired;
- action executes with no human click;
- actuator receipt shows the pool generation changed exactly once;
- baseline/fault/action overlay and fresh probe show incomplete recovery despite
  successful connector reconciliation;
- cooldown/circuit breaker prevents repeat.

### 2:20–2:55 — Human-bound high-risk action

- rollback card shows exact digest/version/risk;
- human approves;
- real rollback executes and reconciles;
- the same approved profile shows warmup, post-action metrics, and a fresh
  synthetic payment passing independently;
- incident becomes `MITIGATED`, not falsely permanently closed.

### 2:55–3:20 — Multi-day case and memory

- open the actual persisted Reliability Case continuity ledger with events,
  wake-ups, and no-process-running gaps across days;
- resume its next step live;
- show Memory Bank scoped recall plus the linked rejected candidate, security
  event, policy decision, and audit record;
- optional SDK-backed Antigravity Incident Workspace shows a cited mechanism,
  reproduction, minimal patch, and regression test from the public synthetic
  fixture if its separate preflight passed; otherwise show the ADK fallback;
- label it `Lead investigator · Repair implementer` while showing that review,
  deployment, production verification, and case closure remain separate.
- keep the optional workspace beat within 25 seconds: mechanism, patch,
  regression test, fresh Cloud Run revision/process rehydration with a new boot
  hash and unchanged durable hashes, and the governance-denial row; omit clones,
  bisection, critic, Service Workspace, and reliability-drill claims.

### 3:20–3:40 — Proof and close

- Release Evidence screen: six scenarios, zero unauthorized/duplicate/isolation;
- show the recovery experiment receipt and agent/oracle isolation attestation;
- show GCP trace/Registry/Gateway proof montage;
- close: “Mitigation is not completion. Solvan owns the outcome until the
  permanent repair is verified.”

## 5. Recording rules

- record the working project, not slides alone;
- keep terminal/console text legible at 1080p;
- redact project numbers, emails, and credentials where unnecessary;
- do not splice in a fake successful Preview result;
- label seeded historical evidence and distinguish it from the live resume;
- use captions and narration that explain state changes;
- never show raw malicious payload, secret-like fixtures, or chain-of-thought;
- verify public visibility and playback in a signed-out browser.

## 6. Live testing instructions

README must provide:

1. prerequisites and estimated cost;
2. exact tool versions and authentication roles;
3. Terraform/deployment commands;
4. seed-fault-drill command;
5. safe scenario command with expected duration/output;
6. console URL and test credentials if private;
7. cleanup command;
8. known Preview limitations and fallback behavior;
9. expected six-scenario evidence locations.

Judges may choose not to run the app; video/text/images must still show every
critical proof.

## 7. Stage One gate

Pass/fail self-review:

- project is complete and viable, not a speculative architecture;
- one category and relevant track proof;
- working source/deployment/video all agree;
- mandatory model/framework/cloud usage is load-bearing;
- links and access work signed out;
- no implementation claim rests only on documentation or mock UI.

## 8. Stage Two scoring plan

### Innovation and operational utility — 40%

Evidence:

- no-prompt incident ownership;
- real medium-risk autonomous mitigation;
- mitigation/permanent-repair split;
- independent verification and recurrence-safe Reliability Cases;
- clear measurable operator value: lower detection-to-recovery and follow-up
  completion without unbounded authority.

### Architectural discipline and tech stack — 30%

Evidence:

- GEAP capabilities used in their documented roles;
- Cloud SQL authoritative durability around seven-day Runtime limit;
- exact identities, default-deny Gateway, typed tools, Armor coverage honesty;
- target reservation, action budget, idempotency, approval TOCTOU defenses;
- memory promotion and data-sovereignty controls;
- Preview fallbacks and no Temporal duplication.

### Demo and production readiness — 30%

Evidence:

- real GCP service failure and action;
- live metrics and synthetic transaction;
- agent failure/security attack inside one coherent story;
- clean runbook, architecture, test evidence, accessible console;
- public reproducible repository and stable hosted build.

The rules accept a private repository when both named judging accounts receive
access. Solvan nevertheless targets a public GitHub repository because the
Stage Two documentation criterion explicitly rewards one; public status is a
scoring/delivery choice, not a Stage One eligibility claim.

## 9. Stage Three bonuses

Only after the Minimum Submittable Release gate:

- up to +0.2 for public build content that states it was created for the
  hackathon;
- up to +0.2 for qualifying social promotion using
  **#AllThingsAgenticHackathon**;
- +0.2 for each meaningfully integrated additional Google AI model, up to +0.6.

A bonus model must own a measurable task and evaluation. Do not risk the core
release for points. A Gemma-based first-stage log classifier is acceptable only
if it improves cost/latency and retains the Gemini 3.5 load-bearing path.

## 10. Submission freeze manifest

Record:

```text
Devpost submission ID and category
repository URL and commit
deployment project/region and image digests
agent/model/policy/template resource versions
release acceptance manifest URI/hash
architecture image hash
README hash
public video URL and duration
public content/social URLs if used
license/disclosure inventory
submission timestamp and representative
```

After deadline, do not change the judged deployment, repository branch, video,
or description unless rules/organizers explicitly permit it. Preserve the
frozen environment through the judging period.

## 11. Demo failure contingencies

| Failure | Recorded/live response |
|---|---|
| Antigravity unavailable/ineligible | show ADK fallback and that the required fast lane is unaffected |
| Memory Bank unavailable | show Cloud SQL truth; recall degraded, no safety loss |
| Runtime transient | queued durable step and prior completed trace |
| live rollback slow | show current durable phase and reconciler, not fake success |
| Cloud Console slow | console cached links plus pre-recorded immutable receipt |
| video upload issue | upload ≥24 hours early and verify backup public host allowed |

Contingency artifacts demonstrate a previously completed real run tied to the
same release; they do not substitute mocked screenshots.
