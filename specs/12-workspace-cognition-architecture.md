# Solvan workspace cognition architecture

Status: target product contract with an optional competition experiment. It
does not expand the Minimum Submittable Release (MSR) in specification 08.
Related: [architecture](02-system-architecture.md),
[agents](03-agent-model-runtime.md),
[security](05-security-governance.md),
[Ruhu profile](11-ruhu-integration-profile.md), and
[Code Repair Workspace profile](23-code-repair-workspace-profile.md), and
[decisions](../docs/OPEN-DECISIONS.md)

## 1. Decision

Solvan adds a provider-neutral **workspace cognition plane** for deep work that
benefits from a filesystem, code execution, iterative investigation, and
artifact production. `WorkspaceAgent` is its only cognition/repair contract;
there is no legacy `WorkspaceAgent` compatibility surface. It does not replace
the fast incident-control path.

The release architecture is:

```text
SENSING       deterministic evaluators                          seconds
REFLEX        Supervisor + typed read-only agents              seconds/minutes
COGNITION     logical workspaces + bounded provider attempts    minutes/weeks
ACTUATION     deterministic, fenced, receipted actuator         bounded effects
ADJUDICATION  independent verification + promotion gates       deterministic
STATE         Cloud SQL authority + GCS artifacts + Memory Bank durable recall
GOVERNANCE    identity + Gateway + Armor + policy + audit       every boundary
```

Stage summary: **fast reflexes, deep cognition, deterministic hands,
independent eyes, durable memory.**

## 2. Design constants

1. **Latency independence.** The cognition plane never gates detection,
   mitigation, rollback, escalation, or verification.
2. **Epistemic independence.** Verification verdicts are computed from a bound
   profile. Verification shares no identity, session, provider process,
   conversation, or mutable artifact directory with a producer.
3. **Capability is not authority.** A capable workspace may propose and test
   broadly inside a bounded experiment, but it never receives production
   mutation authority.
4. **Injection containment.** Workspace inputs and outputs are untrusted. Reach
   is constrained by identity, typed tools, classification, scope, budgets,
   and network policy rather than by prompt instructions alone.
5. **Durable ownership.** The Reliability Case owns the obligation. Cloud SQL
   owns workflow truth. GCS owns immutable content-addressed artifacts. A
   provider process or container is never a system of record.
6. **Policy eligibility precedes provider preference.** Provider choice follows
   data classification, residency, terms, region, and preflight. A preferred
   provider cannot weaken those requirements.

The governing maxim is:

> Give intelligence maximum freedom inside a bounded, disposable experiment;
> grant production authority only through exact deterministic controls.

## 3. Two independent lanes

### 3.1 Fast control lane — required release path

Detection, Supervisor planning, Evidence Agent reads, Infrastructure Agent
reads, deterministic policy, Action Actuator execution, and Verification
Agent adjudication remain unchanged. This lane works when every workspace
provider is unavailable.

Evidence Agent and Infrastructure Agent remain distinct institutional agents.
Their sources have different sensitivity, injection exposure, query semantics,
and IAM ceilings. A future consolidation into a Telemetry Agent requires a
recorded evaluation showing equal or better quality and cost without broadening
the permission or prompt-injection blast radius.

### 3.2 Deep cognition lane — additive

Workspaces perform code forensics, evidence synthesis, reproduction, bisection,
patching, pre-validation, postmortem drafting, test-gap analysis, and guarded
learning proposals. Every output crosses an existing typed validation or
promotion boundary before it can affect authoritative state.

### 3.3 Recommended role allocation

The Incident Workspace is Solvan's **lead investigator and repair implementer**.
Those roles intentionally share one logical workspace and append-only artifact
history: the mechanism learned during investigation should inform the smallest
repair and its regression test without a lossy handoff. Provider sessions may
change, but both tasks reference the same workspace generation and provenance
graph.

| Responsibility | Accountable component | Workspace role |
|---|---|---|
| detect degradation and open incident | deterministic detector and coordinator | none |
| initial bounded triage and urgent mitigation proposal | Supervisor, Evidence Agent, Infrastructure Agent | optional synthesis; never gates fast lane |
| deep investigation and competing hypotheses | Incident Workspace | lead investigator |
| reproduce, bisect, patch, regression-test, pre-validate | same Incident Workspace | repair implementer |
| confirm root cause | deterministic confirmation rule or authorized reviewer | supplies evidence; cannot self-confirm |
| approve patch | authenticated human or independent review agent | cannot self-approve |
| merge, deploy, or execute production action | CI/CD, rollout controller, or Action Actuator | none |
| verify production recovery | independent Verification Agent | none |
| resolve incident or close Reliability Case | coordinator under state-machine guards | none |
| promote memory, rules, or Production Graph changes | governed promotion owner | drafts candidates only |

Investigation and implementation may share context; adjudication may not. A
high-risk policy may request an independent critic that receives only immutable
artifacts and source evidence in a different identity, environment, and
conversation. The critic is advisory unless a separately specified review
policy grants it a typed review role. It never replaces production verification.

## 4. A workspace is logical, not a sandbox

A **logical workspace** is a durable Solvan record and artifact graph. It may
dispatch a bounded attempt to the self-hosted Antigravity SDK service, ADK plus
regional Agent Runtime, or another qualified provider. Every provider returns a
proposal; exact reproduction and patch tests run through the separate
`europe-west1` Cloud Run Sandbox adjudication service.

```text
LogicalWorkspace
  identity: workspace_id, organization, scope, kind, generation
  ownership: service_id and/or reliability_case_id
  policy: data ceiling, residency, provider allowlist, budget
  state: lifecycle status, task cursor, manifest hash
  artifacts: immutable GCS URIs, hashes, provenance, classifications
  execution: immutable task runs, provider/revision, request/boot hashes, budget
```

No Cloud Run instance, SDK process, ADK session, or Runtime job is expected to
survive between workspace tasks. A wake operation therefore:

1. loads authoritative workspace state from Cloud SQL;
2. validates the last content-addressed checkpoint and provider eligibility;
3. resolves one eligible immutable provider revision and effective tool policy;
4. creates the durable workspace task run before any provider call;
5. materializes only the authorized manifest into the provider request;
6. executes one bounded task in a newly created SDK `Agent`/`Conversation` or
   one ADK Runtime attempt;
7. validates the typed result, citations, artifact descriptors, SDK/revision,
   request ID, provider boot hash, budget, and trace binding;
8. writes immutable artifacts and a checkpoint to GCS/Cloud SQL before
   terminally completing the run.

The SDK conversation is an in-task reasoning cache only. Rehydration means a
new provider process consumes the last authoritative checkpoint; it never means
resuming hidden conversation state. A deliberate new Cloud Run revision routes
the next request to a new process and produces a new boot-nonce hash. Unchanged input and artifact
manifest hashes across that boundary are the competition continuity proof.

## 5. Workspace kinds

### 5.1 Service Workspace — standing comprehension

One logical workspace per managed service. It wakes on repository changes,
incidents, or a bounded schedule to maintain versioned artifacts:

- architecture and dependency dossier;
- failure catalog with cited incident mechanisms and repairs;
- reproduction harness and known-good commands;
- watchpoint proposals for fragile code and configuration paths;
- advisory change reviews against the dossier.

Model-authored dossiers are untrusted recall, not approved Production Graph
facts. Each claim carries source references and a content hash.

### 5.2 Incident Workspace — case-scoped cognition

Created for a Reliability Case from an explicit snapshot of approved Service
Workspace artifacts; it is not a provider-native sandbox fork. It can perform:

1. code and version forensics;
2. bounded evidence synthesis;
3. hypothesis and contradiction tracking;
4. reproduction and version bisection in an experiment environment;
5. minimal repair and regression-test generation;
6. clone pre-validation;
7. PR, risk, mechanism, and residual-risk artifacts.

It ends when the case terminates. Its final manifest remains attached to the
case; no provider process or conversation is retained as case state.

The workspace may author both the mechanism narrative and patch because the
deterministic reproduction, test receipts, independent review, and production
verifier—not separation of authoring conversations—provide adjudication. Its
outputs remain `PROPOSED` until those external gates succeed.

### 5.3 Proactive reliability drills — `target`, not implemented

There is no third workspace kind. `workspaces.kind` enumerates exactly `SERVICE`
and `INCIDENT`; no value, unique index, or lifecycle is reserved for a drill
workspace, and adding one is a schema change with its own review. The opt-in
payments fault drill in specification 07 is operator-run tooling
(`scripts/run-fault-drill`), not a workspace.

The intended capability is an environment-scoped logical workspace that would
propose and run bounded fault drills against disposable experiments, maintain
fault injectors, replay historical reproductions, evaluate Solvan's own safety
controls, and propose detection, verification, runbook, or test improvements.
Promotion of any proposal would use the same ownership and approval gates as
human-authored changes.

Those drills would target cloned control planes and synthetic fixtures only.
Probing the live Solvan control plane is a separately authorized security-test
activity, never a drill task.

## 6. Provider eligibility

Provider selection is deterministic and recorded per task:

| Workload | Data ceiling | Required provider path | Antigravity eligibility |
|---|---|---|---|
| competition patch/reproduction | `PUBLIC`, `synthetic=true` | self-hosted Antigravity SDK on Cloud Run; regional ADK/Agent Runtime fallback | eligible only after SDK/container/security preflight |
| production repository/evidence | tenant policy | regional ADK/Agent Runtime provider | SDK provider unqualified for Solvan production |
| Ruhu production workload | Ruhu classification/residency profile | regional ADK/Agent Runtime path | SDK provider unqualified until a separate production review |
| disposable synthetic drill (`target`, §5.3) | `PUBLIC`, `synthetic=true` | any qualified provider | optional after isolation and cost preflight |

The official Antigravity SDK is Apache-2.0, Alpha, and executes its compiled
runtime in Solvan's container. `vertex=True` selects exact model
`gemini-3.1-pro-preview` through the Vertex `global` endpoint and ADC; it does
not invoke or inherit Managed Agents sandbox controls. This global inference
hop is an explicit exception to the otherwise `europe-west1` topology.
Solvan restricts this new provider to public synthetic competition artifacts
until a separate production qualification proves terms, residency, egress,
identity, reliability, tool isolation, and incident-response requirements. No
proprietary repository, customer data, regulated data, private telemetry,
credential, or production identifier enters the competition SDK path.

The provider adapter must not silently downgrade from a regional or
policy-eligible provider to Antigravity. If no eligible provider is available,
the task becomes `BLOCKED` or uses the explicitly configured safe fallback.

### 6.1 Synthetic attestation and provider decision

`synthetic=true` is never a caller or model boolean. The isolated fixture
attester identity signs the canonical artifact-manifest hash with a dedicated
Cloud KMS `EC_SIGN_P256_SHA256` asymmetric key after RFC 8785 JSON
canonicalization. Agents cannot impersonate the attester or sign with that key.
The attestation follows
[`synthetic-data-attestation.schema.json`](artifacts/synthetic-data-attestation.schema.json)
and is stored under the release evidence prefix.
`signed_payload_hash` is the SHA-256 of the RFC 8785 canonical object containing
all required fields through `kms_key_version` and excluding
`signed_payload_hash`, `signature_ref`, and `signature_hash`; the detached KMS
signature covers those canonical bytes.

Before any upload or mount, the deterministic policy service verifies the
signature, attester allowlist, release/deployment binding, expiry,
classification, manifest hash, terms revision, residency requirement, and
provider capability. It appends a `policy_decisions` row with
`policy_kind=PROVIDER_ELIGIBILITY` and a receipt conforming to
[`provider-eligibility-receipt.schema.json`](artifacts/provider-eligibility-receipt.schema.json).
A deny receipt is recorded before any provider call. A missing, invalid,
expired, mismatched, or agent-authored attestation is a deny.

## 7. Provider-neutral contract

`WorkspaceAgent` is the sole institutional cognition and repair role. The
former `WorkspaceAgent.repair()` abstraction, names, settings, manifests, and
deployment units are removed rather than wrapped or translated. Lifecycle and
provider execution are intentionally separate:

```python
class WorkspaceLifecycle(Protocol):
    async def open(self, spec: WorkspaceSpec) -> WorkspaceRef: ...
    async def checkpoint(self, ref: WorkspaceRef) -> WorkspaceCheckpoint: ...
    async def hibernate(self, ref: WorkspaceRef) -> WorkspaceCheckpoint: ...
    async def resume(
        self, checkpoint: WorkspaceCheckpoint
    ) -> WorkspaceRef: ...
    async def close(self, ref: WorkspaceRef) -> None: ...

class WorkspaceProvider(Protocol):
    async def execute(
        self, invocation: WorkspaceTaskInvocation
    ) -> WorkspaceTaskResult: ...
```

Task kinds are `MAINTAIN_DOSSIER`, `FORENSICS`, `SYNTHESIZE_EVIDENCE`,
`REPRODUCE`, `BISECT`, `REPAIR`, `PREVALIDATE`, `REHEARSE`, and `LEARN`.
`INVESTIGATE_LIVE` is reserved for a future provider and policy profile; it is
not an Antigravity task under current terms.

Each result includes the coordinator-generated run/request IDs, workspace
generation, input-manifest hash, provider and immutable Cloud Run/Runtime
revision, implementation SDK and version, SHA-256 provider boot-nonce hash,
task budget,
effective tool-policy hash, artifact descriptors, tool receipts, citations,
trace context, and terminal status. Provider session state alone cannot satisfy
any output contract.

### 7.1 Provider implementation boundary

```text
WorkspaceAgent
├── AntigravityWorkspaceProvider   flagship public-synthetic demonstration
│   ├── private Cloud Run          regional self-hosted service
│   ├── google-antigravity SDK     local loop, conversation, tools, hooks, policy
│   └── global Vertex model API    gemini-3.1-pro-preview + ADC
└── AdkWorkspaceProvider           production-safe regional/Ruhu path
    ├── Google ADK                 typed agent implementation
    └── regional Agent Runtime     proposal execution

Coordinator adjudication
└── Cloud Run Sandbox              europe-west1, fresh, no egress
```

The Antigravity SDK is the programming and agent-loop surface for the flagship
workspace; it is not simulated by a generic HTTP client. Solvan pins the
official PyPI-provenance-attested `google-antigravity==0.1.13` wheel by hash and
uses its `Agent`, bounded
`Conversation`, custom tool, capability, hook, and policy primitives inside a
private Cloud Run container. `LocalAgentConfig(vertex=True, project=...,
location="global")` selects exact `gemini-3.1-pro-preview` through ADC. It does not
deploy to or communicate with Managed Agents Agents/Interactions APIs.

The Solvan coordinator alone chooses the provider, owns the lifecycle state
machine, signs the exact input manifest, creates the run/request ID, persists
checkpoints, enforces budgets, and accepts a typed result. Each SDK service
process creates a cryptographically random boot nonce on startup and exposes
only its SHA-256 hash in
authenticated receipts. Provider-native conversation history ends with the
bounded request.

`AdkWorkspaceProvider` implements the same contract with Google ADK on regional
Agent Runtime. It is the required provider for
Ruhu and any production/private workload while the SDK provider remains
unqualified. Provider selection happens once per task after a durable
eligibility decision; there is no silent cross-provider failover or data-policy
downgrade.

The private provider accepts only authenticated coordinator requests whose
stored request ID, workspace generation, manifest hash, deadline, and tool
policy hash match. Model output cannot supply a request ID, provider revision,
boot hash, callback location, or routing field. Late or duplicate responses are
fenced by the durable run attempt and workflow version.

### 7.2 Remediation plans

A `REPAIR` task returned exactly one code patch. That shape decided in advance
that every incident is fixable by editing this repository, so an incident whose
remedy is a configuration change, a documented procedure, or a bounded
infrastructure operation had no representation and fell out of scope. Coverage
is not a property of how capable the model is; it is a property of how many
kinds of answer the contract can express.

A `REPAIR` task now returns a `RemediationPlan`: an ordered set of steps, each
declaring exactly one kind.

| Step kind | Artifact | Applied by |
|---|---|---|
| `PATCH` | unified diff, base commit, reproduction and test commands | governed code-change path after independent adjudication and review |
| `RUNBOOK` | ordered procedure citing evidence and expected observations | a human following it |
| `COMMAND_PLAN` | exact commands with preconditions and expected effects | a human running them |
| `ENUMERATED_ACTION_REQUEST` | one `ActionType` with its typed payload | the Action Actuator, after approval |

Every artifact is content-hashed and stored before the plan references it, so a
reviewer reads the bytes the digest commits to. No step kind carries authority.
A `PATCH` is not a merge, a `COMMAND_PLAN` is not an execution, and an
`ENUMERATED_ACTION_REQUEST` is a proposal that still requires the exact stored
action, human approval, target reservation, and actuator revalidation it always
did. The plan widens what a workspace can *say*, never what it can *do*.

A plan carrying no step, or a step whose declared kind does not match its
artifact, is rejected by the coordinator before persistence.

The `ENUMERATED_ACTION_REQUEST` lifecycle above is `target`. Nothing turns a
plan step into a stored action, so no such step reaches an approval, a
reservation, or the actuator. The safety property currently holds because the
path does not exist, not because it is enforced — which is a safe state to be
in and a misleading one to describe as a control. The step kind is accepted into
a plan, where it is inert text a reviewer reads, and the enumeration is bound to
`ActionType` so a step can never name an action the actuator has no branch for.

### 7.2.1 Governed code-change handoff — `target`, not implemented

A `PATCH` remains a proposed artifact until an independent adjudication sandbox
reproduces its declared result from the submitted bytes. Only the coordinator
may then create the immutable Code Change Request defined in specification 04
§5.1. The Workspace Agent has no GitHub App credential, PR, branch, merge,
deployment, approval, or release-verifier tool. Its exploratory receipts are
`EXPERIMENTAL`; its narrative that a patch works is not a test or release
receipt.

The Code Change Request binds one patch artifact to one approved repository
binding, base commit, allowed-path set, diff, adjudication receipt, required
checks, reviewer/branch policy, and expiry. The GitHub Provider independently
revalidates all of these before it can create or merge a pull request. GitHub
is the authoritative record for code review and branch protection. Solvan's
separate merge decision is an exact, expiring authorization to ask the Provider
to merge the still-identical PR; it does not assert that code review occurred.
The patch is first reduced to specification 04 §5.1's strict shared regular-file
transform and frozen result-tree hash. The workspace cannot introduce a
symlink, submodule, file-mode change, binary object, rename, copy, or another
Git object that the sandbox and Provider might interpret differently.

After protected merge, the separately identified Deployment Controller handles
the immutable release candidate and the Release Verifier decides whether a
bounded rollout had its intended effect. The full state machine and diagram are
in specification 07 §8.2. No PATCH step reaches the Action Actuator, and no
workspace result can confirm, merge, deploy, roll back, verify, resolve, or
close its own work.

### 7.3 Clarification — `target`, not implemented

A workspace may pause and ask exactly one bounded question, returning
`AWAITING_CLARIFICATION` with the question and the decision it blocks. The
coordinator persists it against the incident, schedules a durable wake-up, and
surfaces it through the conversational surface. An answer resumes the task from
its checkpoint with the answer as an immutable input.

None of that exists yet, and the terminal status is deliberately absent from
`WorkspaceTerminalStatus` until it does. `agent_runs.status` admits no parked
state, so a returned pause is recorded as a failed run: the task would die at
the exact moment it asked to wait. A workspace that cannot ask a question
reports insufficient evidence and says what it needed, which a person can act
on; a workspace whose question kills its own task is worse than one that cannot
ask. The status is added back together with the durable park, its wake-up, and
the resume attempt that carries the answer as an immutable input — not before.

The question is data. An answer grants no scope, tool, budget, or authority the
invocation did not already carry, and a workspace cannot ask for one — a
question requesting a permission, a credential, or a widened ceiling is refused
by the coordinator and recorded as a security event. Asking is not approving.

## 8. Tool and network contract

The self-hosted SDK inherits the Cloud Run service identity and network unless
Solvan constrains them; Managed Agents sandbox defaults do not apply. The
dedicated service account has only the exact global model-invocation and
tenant-safe telemetry permissions. It has no GCS, Secret Manager, Cloud SQL,
production, deployment, Runtime administration, Registry mutation, or
actuation permission. The coordinator materializes curated inputs and persists
outputs so provider tools never need cloud-storage credentials.

SDK built-in shell, unrestricted filesystem, network/search, MCP, triggers, and
general write capabilities remain disabled. The model sees only versioned custom
tools whose schemas and implementation enforce the workspace root, immutable
input paths, bounded candidate-output paths, exact request ID, byte/tool budget,
and no network. This is not a restriction on what a workspace may attempt; it is
a restriction on *where* the attempt runs. A built-in shell executes with the
provider service's own identity and egress, which is the ambient authority this
section exists to deny. A custom tool that dispatches the same command to the
no-egress adjudication service has no such authority, so §8.2 grants the
capability without granting the reach.

### 8.1 Approved guidance as workspace procedure — `target`, not implemented

The generic `agent_run`-anchored guidance-selection path remains blocked by its
ordering constraint: its frozen tool binding exists only after the run exists,
while full content cannot be fetched before a persisted selection. The Code
Repair Workspace profile resolves that specific case with the earlier
`repair_plan_guidance_selections` anchor defined in
[specification 23 §5](23-code-repair-workspace-profile.md#5-governed-skills-and-selection-lifecycle).
It is a target schema change, not a relaxation of the drift fence. The repair
plan selects and hash-binds approved skills before dispatch, and the run binds
that fixed set once. Other Workspace workloads remain blocked until they add an
equally explicit pre-run anchor.

The rest of this section is the contract all materialised workspace guidance
must satisfy; it is not a description of a running path.

A workspace receives the approved Operational Guidance revisions its invocation
selected, materialised into the workspace root as immutable input alongside the
evidence. Guidance is the institution's own procedure for an incident class, and
a workspace that cannot read it re-derives from first principles what the
organisation already decided.

Guidance is data and never authority, exactly as specification 17 defines it.
The materialised copy is the approved revision at its exact content hash, is
read-only, and cannot introduce a tool, widen a ceiling, or name a step the
invocation did not already permit. Text inside a pack is untrusted, as all
workspace content is. Only `APPROVED` revisions are materialised; a draft is
authorship, not procedure.

### 8.2 Sandboxed execution and iteration

A workspace that cannot run anything can only assert that a patch works. It
must be able to reproduce a failure, change code, run the result, read the
error, and try again — the loop that distinguishes a repair from a guess. That
loop is provider-neutral and belongs to the tool contract, not to any SDK.

The `ADJUDICATION` half below is implemented: the sandbox service derives the
run kind from the calling identity, so a workspace cannot obtain an adjudication
run. The `EXPLORATORY` half is `target`. No exploratory Workspace tool exists:
the current provider exposes only its synthetic-provider artifact tools, so
there are no exploratory receipts, `EXPERIMENTAL` trust classification, or
exploratory budget accounting. Its implementation requires the approved private
route to the assigned regional adjudication service defined by specification 23;
the current provider egress policy does not provide that route.

Specification 23 §3.3 defines the target-only
`workspace.code-repair.run-in-sandbox@1` custom tool. It is not implemented.
When implemented, it will dispatch a bounded catalog command to a fresh nested
no-egress sandbox and return a bounded exploratory receipt. It carries no
credential, resolves no network destination, and binds the workspace root,
exact request ID, and command budget. The provider service gains no capability
it did not already have; the command runs where there is nothing to reach.

The target contract has exactly two sandbox run kinds, whose distinction is
enforced by the adjudication service rather than declared by a caller:

- `EXPLORATORY` — requested by the workspace during its loop. Output is visible
  to the model and recorded as a tool receipt. It is `EXPERIMENTAL` trust class
  and is never evidence that a patch works.
- `ADJUDICATION` — requested by the coordinator after the workspace terminates,
  against the submitted diff and declared test command, in a fresh sandbox the
  workspace never observed. Only this produces the `patch_artifacts` test
  outcome.

A workspace cannot request an `ADJUDICATION` run, cannot observe one, and cannot
supply its result. The producer never adjudicates its own output, so an
unbounded exploratory loop remains safe: whatever the workspace convinced itself
of, the accepted outcome is the one a service it never touched reproduced from
the submitted bytes alone.

When implemented, exploratory runs will be bounded by wall-clock, count, and
aggregate output bytes from the task budget. Budget exhaustion will terminate
the loop and return `INSUFFICIENT_EVIDENCE` rather than an unproven claim.

Cloud Run ingress is internal and IAM-authenticated. All egress routes through
the approved VPC path with default-deny firewall/DNS policy and only the
Google API host set actually resolved by the pinned SDK for the configured
Vertex `global` location; preflight records that set and rejects any other
location or undeclared destination. The provider image
contains no `gcloud` credentials or application secrets. Preflight negatively
tests internet, metadata-token use through model-visible tools, GCS, Secret
Manager, production endpoints, and cross-workspace paths.

Workspace agents never receive raw GCP credentials or general-purpose cloud
administration tools. Experiment mutation uses a typed Experiment Controller
or MCP surface behind Solvan policy:

- exact clone ID and project/namespace;
- allowlisted operations and parameter bounds;
- synthetic-data attestation;
- no route or identity path to production;
- hard TTL, concurrency, spend, and resource quotas;
- idempotency key and immutable receipt for every effect;
- emergency cleanup independent of the workspace task/process.

“Maximum freedom” means filesystem and application-level experimentation
inside this bounded substrate. It does not mean unrestricted IAM, arbitrary
internet egress, cross-project discovery, or bypass of budgets.

The Experiment Controller remains target-only and cannot be used until a later
contract defines its request/receipt schemas, clone-template attestation,
isolation probes, cleanup state machine, and cost/TTL enforcement. The
competition demonstration makes no clone, bisection, or clone-prevalidation
implementation claim.

## 9. Evidence and authority

Workspace artifacts may support diagnosis and repair review, but their trust
class is explicit:

- `EXPERIMENTAL`: produced in a synthetic clone;
- `PROPOSED`: model-authored narrative, code, rule, or memory candidate;
- `OBSERVED`: read through an approved evidence broker from an authoritative
  source by an eligible provider;
- `VERIFIED`: assigned only by the independent verification subsystem.

An experiment may demonstrate a causal mechanism, but it cannot prove
production recovery. Production recovery still requires the exact Verification
Agent, bound profile, fresh production observation, and deterministic
comparators. A workspace cannot approve, merge, deploy, execute a production
action, resolve an incident, close a case, promote memory, or write approved
Production Graph state.

## 10. Competition integration

The competition MSR retains the exact six required registered agents and
existing fast-lane contracts. If the optional Antigravity demonstration is
enabled, its provider is a seventh Registry entry marked `ALPHA_SDK`,
`EXPERIMENT_ONLY`, `PUBLIC`, and
`synthetic_attestation_required=true`, with no
production permissions. Antigravity uses the isolated payments fixture
repository and synthetic evidence bundle only.

The optional demonstration has a real, non-MSR two-table seam:
`workspaces` stores logical identity, case ownership, generation, provider
eligibility, artifact prefix, and manifest; `workspace_checkpoints` stores
immutable checkpoint and process-rehydration events with SDK, Cloud Run
revision, provider boot/request hashes, exact provider receipt reference/hash,
SDK-distribution hash, provider image digest, and content hashes. Input and
checkpoint objects conform to
[`workspace-artifact-manifest.schema.json`](artifacts/workspace-artifact-manifest.schema.json).
Specification 04 and `schema.sql` are authoritative. The tables are deployed
with the canonical schema but remain dormant when the demo flag is disabled;
their behavior does not block MSR promotion or add a seventh required agent.

The optional demonstration may show:

1. a logical workspace record and input manifest;
2. an SDK-backed Cloud Run task producing a cited mechanism, patch, and test;
3. a checkpoint rehydrated after a deliberate provider restart, with a new
   provider boot hash and unchanged content hashes;
   the qualification receipt independently recomputes unchanged SDK-
   distribution and provider-image digests as well;
4. deterministic sandbox test receipts;
5. the real `WorkspaceCognitionPanel` governance matrix showing review,
   deployment, and verification denied to the workspace.

It is successful only when platform preflight, terms/data checks, authenticated
SDK task receipts, artifact hashes, and rehydration proof pass. Otherwise the UI labels
the provider unavailable and the required ADK/Agent Engine path remains honest.
Antigravity is not load-bearing for S1–S6 or promotion.

Rehydration qualification is restart-safe: once the new lineage event commits,
the checkpoint's content-bound provider receipt is sufficient to retry only the
qualification-evidence write. The coordinator does not call the provider or
replace the revision again on that reconciliation path.
The retry loads a hash-bound provider receipt whose SDK-distribution and image
digests must equal both the parent checkpoint and exact Terraform topology.

## 11. Security threats and required controls

| Threat | Required control and negative test |
|---|---|
| checkpoint/dossier poisoning | immutable generations, provenance, Armor scan, typed parsing, no automatic promotion |
| stale rehydration | compare workflow version, case state, policy version, manifest hash, and generation before dispatch |
| forged/late provider response | coordinator-generated stored request ID, workflow/run-attempt fence, authenticated private service identity, revision/boot/trace binding |
| cross-case artifact access | coordinator materializes only the signed manifest; provider has no GCS permission; negative cross-workspace path test |
| ADC/model-token abuse | no shell/network tools, model-only service-account permission, default-deny egress, metadata and Google-API negative probes |
| tool-policy widening | versioned custom-tool catalog and policy hash fixed before dispatch; SDK result cannot add tools |
| clone escape | separate project/namespace, deny production routes/IAM, isolation probe before and after task |
| clone/production confusion | immutable environment discriminator on every tool request and evidence receipt |
| cost or loop runaway | per-task and monthly budgets, TTL, concurrency quota, controller-side kill switch |
| Alpha SDK or region-policy mismatch | deterministic provider-eligibility decision and deny receipt before dispatch |
| producer self-verification | distinct identity, environment, inputs, and bound deterministic verifier |
| artifact rollback/substitution | content addressing, signed manifest generations, monotonic current pointer |

## 12. Economics and lifecycle

- Service Workspace maintenance is event-driven, not continuously running.
- Incident Workspaces wake only on case events and hibernate after each task.
- Fault drills, once §5.3 exists, are scheduled, isolated, and budget-capped.
- Artifacts follow tenant retention and legal-hold policy independently of
  provider process lifetime.
- Provider processes are disposable; scale-to-zero or revision replacement is
  normal and no keepalive is scheduled for conversation continuity.
- Each workspace reports model, execution, storage, experiment, and egress
  cost by service and case.

### 12.1 Critic policy

The competition release uses mandatory authenticated human patch review and
does not claim an implemented critic. Post-MSR, an independent critic is
required when deterministic repair policy assigns `HIGH` or `CRITICAL` risk,
or when every causal-confirmation input was produced inside the authoring
workspace. Risk is computed from approved path/resource classes and blast
radius, never selected by the workspace. The critic receives immutable
artifacts in a separate identity, environment, and conversation; its advisory
receipt is required before human review but never replaces that review or the
Verification Agent.

## 13. Adoption order

1. Preserve the required fast lane and exact six-agent release fleet.
2. Add the logical-workspace state and artifact contracts.
3. Implement the provider-neutral lifecycle and regional ADK/Agent Runtime
   provider under the sole `WorkspaceAgent` contract, with common regional
   Cloud Run Sandbox adjudication.
4. Implement `AntigravityWorkspaceProvider` as a private regional Cloud Run
   service with the pinned official SDK and exact global Vertex model calls for
   `PUBLIC`, independently attested synthetic inputs; prove checkpoint
   rehydration after provider restart in the competition fixture.
5. Add typed experiment-controller receipts and synthetic clones.
6. Add Service Workspaces and warm-start artifact snapshots.
7. Add proactive reliability drills and guarded learn-plane proposals.
8. Enable production evidence only for providers and locations that pass the
   tenant's then-current terms, classification, residency, and security policy.

## 14. Acceptance criteria

1. The fast lane completes or escalates when every workspace provider is down.
2. Loss of every provider process is recoverable from Cloud SQL and GCS alone.
3. A provider cannot read outside the coordinator-materialized manifest or
   mutate production.
4. Antigravity is denied any input not both `PUBLIC` and independently attested
   `synthetic=true` under current terms.
5. No experiment receipt can satisfy production recovery verification.
6. Verification rejects any producer-shared identity, process, or mutable
   artifact context.
7. A task cannot widen its versioned custom-tool policy through prompt, SDK
   output, or request fields.
8. Clone TTL, cost, scope, and isolation enforcement are controller-side.
9. Every artifact resolves to immutable bytes, provenance, classification, and
   the exact input-manifest generation.
10. The competition release remains promotable without Antigravity.
11. A provider response with an unknown request ID, unexpected Cloud Run
    revision/SDK version, reused boot hash after forced restart, stale workflow
    version, or mismatched manifest/tool-policy hash fails closed.
12. The optional provider appears in Registry only when its demo path is enabled
    and remains distinct from the six required release agents.
13. Dependency and import inspection proves the flagship provider uses the
    pinned official `google-antigravity` SDK; a REST-only substitute fails the
    demo release gate.
14. SDK configuration, hooks, policies, and model output cannot widen the
    coordinator-issued custom-tool set, egress policy, data manifest, or
    capability ceiling.
15. The SDK service account has no GCS, secret, SQL, deployment, Registry
    mutation, or production permission; negative IAM and egress probes pass.
16. A workspace cannot request, observe, or supply an `ADJUDICATION` sandbox
    run; the accepted patch outcome is reproduced from the submitted bytes by a
    sandbox the producer never touched.
17. An `EXPLORATORY` run is `EXPERIMENTAL` trust class and never satisfies a
    patch-works claim, however many times it succeeded.
18. Exhausting the exploratory budget terminates the loop and returns
    `INSUFFICIENT_EVIDENCE` rather than an unproven claim.
19. A `RemediationPlan` with no step, or a step whose declared kind does not
    match its artifact, is rejected before persistence.
20. No `RemediationPlan` step kind carries authority: a `PATCH` is not a merge,
    a `COMMAND_PLAN` is not an execution, and an `ENUMERATED_ACTION_REQUEST`
    still requires the stored action, human approval, target reservation, and
    actuator revalidation.
21. Only `APPROVED` guidance revisions are materialised into a workspace, at
    their exact content hash and read-only; a pack cannot introduce a tool,
    widen a ceiling, or name a step the invocation did not permit.
22. A clarification answer grants no scope, tool, budget, or authority; a
    question requesting a permission, credential, or widened ceiling is refused
    and recorded as a security event.
16. A fresh provider boot after deliberate restart produces the same checkpoint,
    artifact, SDK-distribution, and provider-image hashes without any
    conversation or process-state dependency.

## 15. Explicit non-decisions

- This specification does not merge Evidence and Infrastructure Agents.
- It does not use Managed Agents in the Antigravity SDK provider path.
- It does not treat an SDK conversation or Cloud Run instance as durable state.
- It does not authorize arbitrary cloud mutation inside experiments.
- It adds the two-table workspace/checkpoint seam required for the optional
  demonstration, but does not add it to the competition MSR release gate.
- It does not claim Agent Gateway governs the private SDK endpoint; Cloud Run
  IAM, VPC/egress policy, application validation, SDK policy, and OTel are its
  explicitly tested controls.
- It does not merge Evidence and Infrastructure Agents. Evaluation and any
  consolidation decision are explicitly parked until after the competition.
