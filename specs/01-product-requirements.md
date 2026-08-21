# Solvan product requirements

Status: required competition-release contract
Audience: product, architecture, engineering, security, design, QA
Related: [architecture](02-system-architecture.md), [runtime](03-agent-model-runtime.md), [acceptance](08-test-evaluation-acceptance.md)

## 1. Product definition

Solvan is an autonomous production engineer. It consumes trusted alert events,
investigates live production evidence, diagnoses likely causes, executes only
policy-authorized bounded mitigations, verifies the observed result from fresh
telemetry, and owns a Reliability Case until permanent repair is verified or a
human/external owner explicitly accepts responsibility.

It is not a chat-first copilot, generic workflow builder, monitoring vendor,
unrestricted infrastructure agent, or substitute for incident command.

## 2. Product principles

1. **Incidents begin from events, not prompts.** Chat may explain or request work
   but does not define the production lifecycle.
2. **Outcome ownership over task completion.** A successful model response,
   tool response, deploy response, or test run is not service recovery.
3. **Mitigation is distinct from repair.** Restoring health does not erase the
   underlying defect.
4. **Authority is structural.** Identity, IAM, Gateway, typed tools, policy,
   approval, target reservation, and verification constrain every mutation.
5. **State is durable and typed.** Cloud SQL, not prompts or memory, records what
   happened and what must happen next.
6. **Evidence remains evidence.** Confidence does not convert a hypothesis into
   a confirmed root cause.
7. **Verification is independent.** The remediation planner cannot choose a
   weaker success criterion.
8. **Learning is gated.** Untrusted evidence cannot directly become durable
   cross-incident memory.
9. **Degradation is honest.** A Preview outage becomes a visible blocked state,
   never a fabricated success.
10. **The console shows control.** It displays decisions and evidence without
    exposing private chain-of-thought.

## 3. Users and stakeholders

| Persona | Primary need | Authority |
|---|---|---|
| on-call SRE | understand, approve, monitor, take over | incident actions within role |
| incident commander | coordinate and accept/escalate risk | high-risk approval and ownership transfer |
| platform engineer | publish agents/tools/policies and inspect fleet | Registry and platform configuration |
| service owner | own verification profiles and permanent repairs | service/case decisions |
| security/compliance | verify least privilege, residency, audit, retention | policy and audit review |
| competition judge | see real autonomous action and reproducible proof | read/test only |

## 4. Jobs to be done

### P0 — competition release

- detect a real induced payments degradation without a user prompt;
- correlate telemetry and deployment evidence through separate agents;
- execute a pre-authorized payments connection-pool recycle without human approval;
- prevent action flapping through budgets and cooldown;
- request exact approval for a high-risk rollback and reject stale approval;
- serialize conflicting actions against the same target;
- verify recovery from fresh metrics and a synthetic payment;
- persist and resume a multi-day Reliability Case;
- survive one agent loop/crash without losing or duplicating work;
- prevent poisoned evidence from granting authority or entering Memory Bank;
- show institutional agent discovery, identity, gateway policy, armor verdict,
  and end-to-end traces.

### P1 — post-competition

- add a provider-neutral Incident Workspace that acts as lead investigator and
  repair implementer while confirmation, review, deployment, verification,
  closure, and promotion remain independent typed authorities;
- integrate Ruhu as the first GCP design-partner workload through a phased,
  least-privilege adoption profile: observe-only first, approval-bound rollback
  second, and bounded autonomy only after Ruhu exposes typed operations;
- live GitHub App review/merge integration with a CI-published branch,
  coordinator-only release calls, signed webhook reconciliation, and exact
  patch/check/head gates; canary/rollout remains owned by the deployment system;
- dedicated agent-workload reliability scenario;
- additional service templates, verification profiles, and benchmark injectors;
- multi-organization hosted control plane and customer-managed keys;
- additional model and `WorkspaceAgent` providers.

### Roadmap

- AWS/Azure, generic Kubernetes, Datadog, broad database administration;
- autonomous schema changes, IAM changes, security-control changes;
- financial or business workflow automation unrelated to production reliability.

## 5. Canonical release scenario

### Preconditions

- `checkout-api`, `payments-api`, and PostgreSQL run in the Solvan staging GCP project;
- synthetic users produce normal payments traffic;
- `payments-api:v2.8.1` contains a real connection-management defect;
- agents, endpoints, tools, identities, policies, verification profiles, and
  Model Armor templates passed deployment preflight;
- one exact pool recycle is pre-authorized; rollback requires approval.

### Flow

1. Failure injection deploys `v2.8.1` and records onset.
2. The 25-second Solvan evaluator detects it, canonicalizes/deduplicates the
   event, and atomically creates `INC-2041`; Monitoring alert ingress is the
   secondary path.
3. Supervisor proposes Evidence and Infrastructure work; the coordinator
   validates the plan, creates durable runs, and dispatches both agents.
4. One agent intentionally violates a budget; its attempt is fenced and a new
   attempt resumes from durable references.
5. Model Armor detects a malicious instruction embedded in one log event; the
   content remains evidence but cannot become instruction or memory.
6. Typed evidence supports a deployment-regression hypothesis.
7. Solvan reserves the target and recycles the demo service connection pool
   through the private Action Actuator.
8. Independent verification finds only partial recovery; cooldown prevents a
   repeated pool recycle.
9. Solvan proposes rollback `v2.8.1 → v2.8.0` with exact digest and evidence.
10. The incident commander approves that immutable proposal.
11. Execution reacquires the target reservation, rechecks version/policy, rolls
    back, reconciles target state, and releases the reservation.
12. Verification resolves the service-owned profile and observes healthy
    metrics plus successful synthetic transactions.
13. Incident becomes `MITIGATED`; `REL-101` remains open.
14. A later scheduled event resumes `REL-101`, invokes a Workspace provider or
    records a visible block, and stores a durable next action.

### Required result

- no unauthorized or duplicate mutation;
- exact evidence and receipts for every transition;
- recovery criteria pass independently;
- prior incident remains immutable if recurrence later creates a new incident;
- the full path is visible through the console and correlated OTel traces.

## 6. Functional requirements

### Incident lifecycle

- **PR-001:** Alert delivery with the same source event ID is idempotent.
- **PR-002:** A qualifying alert creates exactly one incident without chat.
- **PR-003:** Every transition uses expected state and workflow version.
- **PR-004:** Terminal incident histories are immutable.
- **PR-005:** Recurrence creates a new incident with `recurrence_of` and reopens
  the Reliability Case; it does not rewrite the old incident.

### Investigation and diagnosis

- **PR-006:** Evidence agents receive typed read-only tools and bounded scope.
- **PR-007:** Evidence records preserve source, time range, query, hash,
  classification, residency, and retrieval actor.
- **PR-008:** Hypotheses cite evidence and remain suspected until a configured
  confirmation rule passes.
- **PR-009:** Conflicting or stale evidence is visible and cannot be silently
  discarded by a model.
- **PR-048:** Change history is first-class evidence. Admin Activity audit
  reads answer what changed, by whom, and when; grouped error signatures carry
  first-seen and last-seen observations. Service-account actors are reported
  exactly; human principals are pseudonymized stably so correlation survives
  without disclosing personal identity.

### Action safety

- **PR-010:** Only Execution Agent (`execution-agent`) can invoke the private Action Actuator; only
  the actuator holds production connector permissions.
- **PR-011:** Every mutation has a stable action ID and idempotency key.
- **PR-012:** Cross-incident mutations are serialized by target key and epoch.
- **PR-013:** Incident action budget, repeat limit, cooldown, and oscillation
  detector are deterministic and cannot be reset by an agent.
- **PR-014:** Medium-risk actions may execute only under an explicit standing
  policy; high-risk rollback requires exact approval.
- **PR-015:** Critical actions are infrastructure-denied even if a user asks or
  approves them.

### Approval

- **PR-016:** Approval binds action digest, target, environment, expected target
  version/epoch, application-derived expected-effect hash, evidence version,
  policy version, approver, and expiry.
- **PR-017:** Any material change invalidates approval.
- **PR-018:** Execution rechecks approval, policy, target, incident version, and
  reservation immediately before mutation; it then performs a side-effect-free
  connector dry run and deterministically refuses unless the predicted effect
  exactly matches the approval-bound expected-effect hash.

### Verification

- **PR-019:** Service/incident class maps to one exact approved verification
  profile in policy-owned Production Graph data.
- **PR-020:** Verification Agent resolves that mapping independently.
- **PR-021:** Missing, stale, contradictory, or insufficient signals yield
  `INCONCLUSIVE`, never success.
- **PR-022:** Connector success and Workspace Agent tests are not production
  recovery evidence.

### Durable continuation

- **PR-023:** Every next step is recoverable from Cloud SQL after process,
  Runtime execution, or deployment replacement.
- **PR-024:** Agent Runtime and Sessions can accelerate/resume work but cannot
  override authoritative state.
- **PR-025:** Scheduled wake-ups and external events use inbox/outbox semantics.
- **PR-026:** A Reliability Case may span more than one Runtime job and seven
  days without one long-lived process.
- **PR-049:** A failed agent dispatch defers its single declared fallback
  behind a durable `retry_not_before` backoff; reservation never dispatches
  earlier, including from a fresh coordinator after restart, so a transient
  fault cannot consume the final attempt in the same instant it failed.
- **PR-050:** An inbox or outbox event that exhausts its bounded claim budget
  without completing is quarantined durably and visibly and is never claimed
  again; one poison event cannot crash-loop a worker or hold a claim slot
  forever, and recovery requires an explicit superseding action.

### Memory

- **PR-027:** Memory scopes exactly include organization, project, environment,
  and purpose.
- **PR-028:** Only confirmed, verified, approved, provenance-bearing candidates
  pass the promotion gate.
- **PR-029:** Raw evidence, hypotheses, model summaries, and inconclusive results
  never write directly to Memory Bank.
- **PR-030:** Memory affects ranking/context only and cannot grant permission,
  approve, mutate, confirm root cause, or change state.

### Fleet governance

- **PR-031:** Every institutional agent and governed destination is registered.
- **PR-032:** Cross-department discovery exposes approved capabilities and
  metadata without granting execution permission.
- **PR-033:** Every agent has its own Agent Identity and least-privilege IAM.
- **PR-034:** Gateway-denied or bypassed traffic creates a security audit event.
- **PR-035:** Unsupported Model Armor payload classes still pass typed boundary,
  schema, secret, and authorization validation.

### Console

- **PR-036:** Timeline, Evidence, Actions, Verification, and Permanent Repair are
  the competition incident surfaces.
- **PR-037:** The UI differentiates proposed, approved, executing, reconciled,
  verified, blocked, and failed states.
- **PR-038:** The UI never labels an action complete merely because an agent or
  connector reported success.
- **PR-039:** Every critical status and action is keyboard accessible and never
  communicated by color alone.

### Operational explainability and outcome proof

- **PR-040:** The coordinator persists every accepted investigation plan and
  its typed step projection before agent dispatch. Replanning creates a new
  immutable plan version and marks the prior projection superseded.
- **PR-041:** The console exposes investigation branches, dependencies,
  required/optional status, assigned registered agent, durable state, budget
  use, evidence delta, fallback, and trace without exposing private
  chain-of-thought.
- **PR-042:** Verification evidence distinguishes the healthy baseline, fault
  window, mutation interval, warmup, post-action observation, and fresh
  synthetic probe. Incident-local baselines may provide comparison context but
  cannot weaken an approved verification profile.
- **PR-043:** Fleet governance shows the effective policy/capability value and
  its provenance chain—local, inherited, Registry, IAM, Gateway, or release
  manifest—separately from discovery and permission.
- **PR-044:** Authorized operators can inspect memory candidates, promotion or
  rejection decisions, security events, and audit events with exact scope,
  provenance, retention, and trace references; list APIs never return raw
  sensitive content.
- **PR-045:** Release fault experiments isolate agent principals from injected
  fault definitions, expected diagnoses, and oracle logic. Only a deterministic
  external oracle can pass recovery acceptance.
- **PR-046:** Reliability Case detail shows actual calendar-separated
  checkpoints, scheduled wake-ups, claims, overdue work, resume causes, and the
  next accountable owner without implying a continuously running process.
- **PR-047:** Incident detail begins with a bounded operator brief derived from
  committed records: impact, last verified fact, confirmed root cause or clearly
  labelled leading hypothesis, action/recovery state, required human attention,
  next step/owner, sequence, and freshness. Every claim links to evidence.

## 7. Non-functional requirements

### Reliability

- all mutation endpoints and event handlers are idempotent;
- zero duplicate mutations in all release scenarios;
- stale agents cannot commit after lease or target epoch changes;
- restart during every non-terminal state resumes or escalates visibly;
- no workflow remains `RUNNING` without a live lease beyond its recovery bound.

### Performance budgets

- alert accepted and incident ID returned: p95 ≤ 2 seconds;
- first investigation dispatch: p95 ≤ 5 seconds;
- console event visibility after durable commit: p95 ≤ 2 seconds;
- target reservation transaction: p95 ≤ 500 ms inside the demo region;
- one incident: ≤ 20 model calls, ≤ 50 tool calls, ≤ 30 minutes active compute;
- approval wait and observation windows do not consume active model budget.

### Security and privacy

- zero secrets in model prompts, traces, or browser payloads;
- zero cross-scope data reads in negative tests;
- all Runtime, Gateway, Registry, Memory, SQL, storage, logs, and model endpoints
  use the approved project/region topology;
- critical production permissions are absent from agent principals.

### Accessibility

- **required:** Overview, Incident detail, and Approval have axe smoke checks;
  approval/rejection is keyboard complete with focus, labels, contrast, and no
  color-only meaning;
- **target:** full WCAG 2.2 AA route/state, screen-reader, zoom, and motion matrix;
- dates, time zones, durations, units, percentages, versions, and environment
  are explicit;
- reduced-motion preference disables decorative animation.

## 8. Success measures

- Stage One submission completeness: 100%;
- six release scenarios pass with immutable receipts: 100%;
- unauthorized action rate: 0;
- duplicate mutation rate: 0;
- isolation violations: 0;
- verification false-positive rate in release fixtures: 0;
- root-cause hypothesis top-1 accuracy in implemented fixtures: ≥ 80%;
- operator can identify current owner, last verified fact, next action, and
  approval need in usability test: ≥ 90%;
- operator can identify which investigation branches are running, blocked, or
  exhausted and why recovery passed or remains inconclusive: ≥ 90%;
- four-minute demo completes with at least 20 seconds of contingency margin.

## 9. Deliberate exclusions

- private chain-of-thought storage or display;
- model-authored IAM, SQL, shell, Terraform, verification thresholds, or policy;
- credentials delivered to model context;
- indefinite autonomous retry or self-expanding tool access;
- native Agent Runtime revision traffic splitting while Gateway is attached;
- Temporal, OpenAI Agents runtime, or a second workflow state machine.
