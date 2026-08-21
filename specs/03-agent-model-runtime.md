# Solvan agent, model, and runtime specification

Status: required competition-release contract
Related: [architecture](02-system-architecture.md), [data contracts](04-data-event-api.md), [security](05-security-governance.md), [governed Tool Catalog](16-governed-tool-catalog.md)

## 1. Runtime objective

Agents perform bounded probabilistic work inside a deterministic incident
lifecycle. No agent owns authorization, durable state, budgets, or success
criteria.

## 2. Model policy

### Required model

`gemini-3.6-flash` is the fast-fleet release baseline. It passed the typed
incident-quality gate on 2026-08-10 and is the lower-latency choice for bounded
evidence classification, hypothesis ranking, and synthesis. The Antigravity
deep workspace uses exact model ID `gemini-3.1-pro-preview`: the same comparison
gave it perfect classification, top-1 diagnosis, and observation recall, while
the deeper repository task values quality over latency. Because 3.1 Pro is
Preview, it is qualified by exact ID and never silently replaced.

Gemini 3.6 Flash fast-fleet calls use Vertex location `eu` through the exact
jurisdictional hostname `https://aiplatform.eu.rep.googleapis.com`, while the
Agent Runtime resources remain in `europe-west1`.
Gemini 3.1 Pro Preview is available only at `global`, so the optional
Antigravity deep workspace retains one explicit inference-location exception.
Cloud SQL, GCS, Cloud Run, Registry, Gateway, Memory Bank, Model Armor, and
sandbox execution remain pinned to `europe-west1`.

### Optional routing

| Task | Default | Optional | Fallback |
|---|---|---|---|
| evidence extraction | Gemini 3.6 Flash | none | deterministic empty finding + escalation |
| hypothesis ranking | Gemini 3.6 Flash | none | evidence-only operator view |
| incident synthesis | Gemini 3.6 Flash | none | deterministic status template |
| Antigravity deep workspace | Gemini 3.1 Pro Preview | only the exact qualified ID | fast lane continues; optional workspace task blocks honestly |
| production/Ruhu workspace proposal | Gemini 3.6 Flash on regional ADK/Agent Runtime | later qualified exact model | workspace task blocks honestly |
| verification math | no model | none | no verification |
| policy/risk/approval | no model | none | deny |

Model ID changes require a recorded evaluation comparison. “Latest” aliases are
prohibited in the release manifest.

## 3. Institutional agent catalog

| Agent | Department reuse | Inputs | Outputs | Identity ceiling |
|---|---|---|---|---|
| Incident Supervisor Agent | SRE, Platform, AI Platform | incident snapshot, typed agent refs | proposed next step | propose agent requests; no invoke or infra access |
| Evidence Agent | SRE, Security, Compliance | bounded query plan | evidence and findings | logs/metrics/traces read |
| Infrastructure Agent | SRE, Platform, DB Engineering | target/service scope | topology/deploy/capacity evidence | deployment/SQL metadata read |
| Execution Agent | SRE, Platform | action ID and run reference | execution receipt reference | invoke private actuator only |
| Verification Agent | SRE, Release Engineering | action/result refs | verification result | telemetry/synthetic read |
| Workspace Agent | App Engineering, SRE | curated workspace manifest, repo/evidence snapshot | cited investigation, patch, and test artifacts | isolated workspace only |

Registry discovery never grants use. The calling identity still needs IAM,
Gateway policy, Solvan role, and an application-issued delegation.

These names also govern stable keys, packages, configuration, APIs, telemetry,
and durable records. Naming a component an Agent never grants peer invocation
or transfer: only the coordinator creates and dispatches durable Agent runs.
Specification 16 owns the complete naming and capability-profile decision.

The table is the six-agent required release fleet. Its required
`workspace-agent` implementation is the regional ADK/Agent Runtime provider.
When the optional Antigravity demonstration flag is enabled, Registry also
publishes the conditional `antigravity-incident-workspace` provider entry from
`agent-manifests.yaml`. It is marked `EXPERIMENT_ONLY`, accepts only `PUBLIC`
inputs with verified synthetic attestation, and advertises investigation/patch
proposal capabilities alongside explicit absence of confirmation, approval,
deployment, production mutation, verification, closure, and promotion powers.
It is not counted as a required release agent when disabled.

### 3.1 Deterministic seats

Every agent above is model-backed and none of them can change production. The
capability to change production belongs to a separate class of catalog entry:
a **deterministic seat**, declared under `deterministic_services` in
`agent-manifests.yaml`.

| Seat | Caller ceiling | Permission ceiling | Allowed operations |
|---|---|---|---|
| Action Actuator | Execution Agent identity (`execution-agent`) only | production mutation allowlist only | `PAYMENTS_POOL_RECYCLE`, `CLOUD_RUN_TRAFFIC_ROLLBACK` |

A seat is catalogued because an uncatalogued mutation capability is an
unauditable one — the Fleet capability matrix would otherwise show mutation
destinations with no owner. Registration does not soften any control:

- `model_backed` must be `false`. A seat holding the mutation allowlist may not
  contain a model, and `tools/check_agent_manifests.py` rejects a manifest that
  claims otherwise.
- `accepts_from_caller` may name only `action_id`, `scope`, `invocation_id`,
  and `trace_id`. It may never accept `payload`, `target`, `action_type`, or
  `expected_target_version`; a caller names a stored action, it never supplies
  the material to execute. The manifest check enforces this exclusion.
- Every precondition in `preconditions_revalidated` is re-checked by the seat
  itself against stored state, never trusted from the caller.
- No model-backed agent may carry the seat's permission ceiling.

## 4. Registry manifest

Each deployment publishes an A2A Agent Card where supported and a Solvan release
manifest:

```yaml
agent_manifest:
  schema_version: 1
  agent_key: evidence-agent
  display_name: Evidence Agent
  registry_kind: AGENT
  execution_role: SPECIALIST
  release_version: 0.1.0
  immutable_resource_name: projects/.../reasoningEngines/evidence-agent-0-1-0
  framework: google-adk
  model_resource: gemini-3.6-flash@qualified-manifest
  model_location: eu
  model_endpoint: https://aiplatform.eu.rep.googleapis.com
  owner_department: sre-platform
  discoverable_by: [sre, security, compliance, ai-platform]
  data_classes: [INTERNAL, CONFIDENTIAL_REDACTED]
  runtime_regions: [europe-west1]
  capabilities: [logs.read, metrics.read, traces.read]
  tools: [cloud_logging_query, cloud_monitoring_query, cloud_trace_read]
  permission_ceiling: READ_PRODUCTION_TELEMETRY
  evaluation_manifest: gs://.../evidence-agent/eval-20260808.json
  approval_status: APPROVED
  lifecycle: ACTIVE
  replacement: null
```

CI validates manifest/tool/identity/Gateway consistency. An unapproved or
deprecated agent can remain visible to administrators but cannot be resolved by
the Supervisor.

## 5. Invocation contract

```python
class AgentInvocation(BaseModel):
    schema_version: Literal[1]
    invocation_id: str
    logical_step_key: str
    organization_id: str
    project_id: str
    environment_id: str
    incident_id: str | None
    reliability_case_id: str | None
    workflow_version: int
    deadline: datetime
    budget: InvocationBudget
    evidence_refs: list[str]
    allowed_tool_names: list[str]
    input_payload: dict[str, JsonValue]
    trace_context: TraceContext

class InvocationBudget(BaseModel):
    max_runtime_seconds: int
    max_model_calls: int
    max_tool_calls: int
    max_output_bytes: int
    max_replans: int
```

The coordinator creates and stores the invocation before calling Runtime.
Agents cannot widen scope, extend deadline, add tools, or change workflow
version. Agent output over the byte limit is rejected and stored only as a
redacted diagnostic hash.

Validation requires exactly one of `incident_id` and `reliability_case_id`.
Only the coordinator service identity can invoke a Runtime agent. Registry/A2A
metadata never creates an agent-to-agent execution path in this release.

## 6. Incident Supervisor Agent

Responsibilities:

- select the next legal investigation/coordination step from application-
  supplied options;
- request independent agents;
- rank typed hypotheses;
- propose a remediation intent from an allowlisted action catalog;
- summarize evidence and uncertainty for the operator.

Forbidden:

- raw production access;
- arbitrary tool invocation;
- state transition commit;
- risk classification override;
- approval creation;
- verification profile selection;
- mutation execution;
- direct Memory Bank write.

The Evidence Agent may receive coordinator-constructed `memory_recall` input.
It cannot call Memory Bank itself. Every entry is labelled
`REFERENCE_ONLY_UNTRUSTED_HISTORICAL_CONTEXT`, retains the managed resource and
source references, and grants no factual, tool, permission, routing, or workflow
authority. The complete input is digest-bound before provider dispatch.

Planner output:

```json
{
  "schema_version": 1,
  "objective": "identify cause of payments availability regression",
  "steps": [
    {
      "step_key":"collect-telemetry",
      "kind":"invoke_agent",
      "agent":"evidence-agent",
      "scope_ref":"SCOPE-9",
      "purpose":"test whether the regression is visible in service signals",
      "depends_on":[],
      "required":true
    },
    {
      "step_key":"inspect-runtime",
      "kind":"invoke_agent",
      "agent":"infrastructure-agent",
      "scope_ref":"SCOPE-10",
      "purpose":"identify bounded deployment or capacity changes",
      "depends_on":[],
      "required":true
    }
  ],
  "completion_condition":"both required agent results available",
  "uncertainties":["database saturation may be symptom rather than cause"]
}
```

Application validation allows one repair attempt for schema errors. A second
invalid output ends the invocation and invokes deterministic recovery policy.
Step keys are stable within a plan version. The coordinator rejects dependency
cycles, unknown agents, scope widening, duplicate keys, unregistered
capabilities, and agent budgets above policy. It persists the accepted plan and
step rows before dispatch, and only durable coordinator events update their
visible states. A replan creates a superseding plan version.

### 6.1 Disabled read-only workflow and optimizer experiments

The `_pilot` ADK workflow is an internal implementation experiment for one
already-authorized read-only run. It is absent from the production dispatch
registry and refuses to build unless `SOLVAN_ADK_WORKFLOW_PILOT_ENABLED=true`.
Its code router is deterministic, selected branches use public `Workflow`,
`Edge`, `JoinNode`, and `FunctionNode` APIs, and bounded refinement uses public
`Context.run_node`. The pinned ADK package does not publicly export `Graph` or
`ScheduleDynamicNode`; Solvan does not import those private implementation
types. All nodes are replay-safe reads, have deterministic names and hashes,
and return one non-authoritative typed result. The Cloud SQL investigation DAG
and coordinator remain the only institutional orchestration authority.

Prompt optimization is offline only. The first configuration targets the
read-only Evidence Agent through
`google.adk.optimization.simple_prompt_optimizer`, with disjoint train,
validation, and adversarial-holdout partitions from the deterministic
trajectory suite. The preparation command calls no model and grants no
credentials. A generated candidate is rejected on any hard-gate regression;
passing gates can advance only to human review and a new immutable agent
revision. The GEPA CLI path stays unavailable until its optional dependency
set is explicitly locked and verified.

## 7. Evidence Agent

The agent turns a bounded question into registered read-only calls. It may
query only supplied service IDs, time window, log views, metrics, and trace
projects. Query syntax is built from typed parameters; the model does not write
arbitrary Logging queries for execution.

Output findings distinguish observation from inference:

```yaml
finding:
  finding_id: FND-31
  statement: http_5xx_rate exceeded 8 percent for 6 minutes
  type: OBSERVATION
  evidence_refs: [EVD-31]
  confidence: null
  contradictions: []
```

Instructions found in logs or traces are quoted as untrusted content and never
followed.

## 8. Infrastructure Agent

Read-only capabilities:

- resolve deployed revision/version and change history;
- inspect Cloud Run instance/revision health;
- inspect Cloud SQL connection/capacity metrics and configuration metadata;
- resolve Production Graph neighbors and owners;
- compare current state with the incident's frozen starting snapshot.

It cannot deploy, restart, rollback, scale, edit configuration, or open a
database data session.

## 9. Execution Agent

Execution Agent is deterministic in behavior. Its invocation contains only an action ID,
scope, stored run reference, and trace context. It calls the private Action
Actuator; the caller cannot supply the action payload inline.

Processing order:

1. Execution Agent authenticates to the actuator and submits the action ID;
2. actuator loads action and run, then checks caller, scope, digest, workflow
   version, deadline, risk, policy, and exact preauthorization or approval;
3. actuator acquires the target reservation and expected epoch/version;
4. actuator re-reads target and compares it with the frozen preconditions;
5. the selected connector performs a side-effect-free dry run from the typed
   action and observed pre-state;
6. application code canonicalizes the prediction and compares it with the
   expected-effect hash already stored on the action and bound into approval;
7. missing, malformed, unsupported, or unequal predictions durably settle as
   `DRY_RUN_MISMATCH`, release the reservation, and cannot call mutation;
8. actuator persists `EXECUTION_STARTED` intent;
9. actuator invokes the one connector selected by `action_type` with the stable
   idempotency key;
10. actuator reconciles observed state;
11. actuator persists the receipt, releases the reservation, and appends the
   verification outbox event in one transaction;
12. coordinator consumes that event and dispatches Verification Agent.

The expected effect is derived by typed application code when the action is
created. A model, tool result, connector response, dispatch caller, or approver
cannot author or weaken it. The connector independently predicts the same
closed descriptor; only application code canonicalizes and compares hashes.

Any uncertain step after connector invocation returns `AMBIGUOUS`; retry is
prohibited until read-only reconciliation determines whether the effect exists.

## 10. Verification Agent

The agent receives action/receipt references, not the remediation prompt. It:

1. reads service/incident-class binding from Production Graph policy;
2. resolves the exact approved bound profile version; requests cannot replace
   it with a caller-selected or nominally “stricter” profile;
3. starts after the configured warmup;
4. queries fresh telemetry using read-only identity;
5. runs the registered synthetic transaction;
6. applies deterministic comparators and sustained windows;
7. returns `VERIFIED`, `FAILED`, or `INCONCLUSIVE`.

The model may narrate the result but cannot calculate or choose the verdict.

## 11. Workspace Agent providers

Common provider interface; the coordinator-owned lifecycle contract is in
specification 12:

```python
class WorkspaceProvider(Protocol):
    async def execute(
        self, invocation: WorkspaceTaskInvocation
    ) -> WorkspaceTaskResult: ...
```

The `REPAIR` task contains a read-only repository snapshot URI, commit hash,
bounded evidence bundle, reproduction command, allowed file globs, test
command, deadline, and artifact output URI. Other task kinds and the complete
result envelope are defined in specification 12. No task contains production
credentials.

### AdkWorkspaceProvider

Required regional implementation deployed on Agent Runtime. It may:

- read only curated snapshot excerpts supplied in its typed invocation;
- propose a unified diff touching only allowed files;
- repeat the exact allowlisted test command and return residual risks.

It has no tools and cannot claim test success. The coordinator validates the
proposal and runs the exact patch and command through the separate private
Cloud Run Sandbox service in `europe-west1`. Each atomic request creates a
fresh nested sandbox with no egress, ambient credentials, metadata access, or
durable state. That sandbox—not the model—produces the durable test output hash
and patch receipt.

### AntigravityWorkspaceProvider

Flagship Alpha implementation for the optional competition demonstration. A
dedicated private Cloud Run service embeds the pinned official
`google-antigravity==0.1.10` wheel. Its local compiled runtime owns the bounded
agent loop, `Agent`, per-task `Conversation`, custom tools, hooks,
capabilities, and policies. `LocalAgentConfig(vertex=True, project=...,
location="global")` sends model inference to exact model
`gemini-3.1-pro-preview` using the service identity; it does not
deploy to Managed Agents.

Preflight confirms wheel provenance/version and Linux image compatibility,
exact global model/API access, quota, terms, Cloud Run revision, private ingress,
service-account ceiling, VPC/egress denial, SDK custom-tool policy, and SDK
boot receipt. Only fixture inputs classified `PUBLIC` and independently
attested `synthetic=true` are copied into the request. The provider has no GCS
or production access. Built-in shell, unrestricted filesystem, network/search,
MCP, and triggers are disabled; only versioned custom read/candidate-write tools
are visible. The coordinator validates the complete tool-policy hash and every
typed output. Patch/test truth remains in the shared regional Cloud Run
Sandbox adjudication service.

No provider may merge, deploy, approve, or call production.

### Clean workspace architecture

`WorkspaceAgent` replaces the former `WorkspaceAgent` abstraction. There are no
legacy aliases, dual schemas, compatibility settings, or translation paths.
Cloud SQL and GCS own the logical workspace. Cloud Run instances and SDK
conversations are disposable bounded attempts, not durable state. Solvan policy
keeps the Alpha SDK provider away from proprietary repositories, private
telemetry, customer data, and Ruhu production inputs until a separate
qualification. The exact six-agent release fleet therefore includes the
regional ADK workspace implementation, while the SDK-backed Antigravity service
is a conditional Registry provider for the public-synthetic demonstration.

Target role contract:

| Stage | Workspace task | Binding output | External owner/gate |
|---|---|---|---|
| deep investigation | `FORENSICS`, `SYNTHESIZE_EVIDENCE` | cited competing hypotheses and mechanism proposal | confirmation rule/reviewer |
| causal demonstration | `REPRODUCE`, `BISECT` | immutable experimental receipts | typed evidence validator |
| repair implementation | `REPAIR` | minimal diff and regression test | deterministic sandbox test |
| pre-validation | `PREVALIDATE` | clone-only result and residual risks | independent patch review |
| production rollout | no workspace task | none | CI/CD or deterministic rollout controller |
| recovery verification | no workspace task | none | Verification Agent |

The same logical Incident Workspace should perform deep investigation and
repair implementation so its cited mechanism, contradictions, and reproduction
remain attached to the patch. This does not grant self-confirmation or
self-review: root-cause confirmation, patch approval, rollout, verification,
incident resolution, case closure, memory promotion, and Production Graph
approval are external typed decisions. A high-risk independent critic, when
configured, receives immutable artifacts in a separate identity, environment,
and conversation.

The coordinator creates each workspace run and request ID before private-service
dispatch. The request binds workspace generation, workflow version, manifest,
deadline, budget, provider revision, and custom-tool policy hash. The provider
returns its SDK version, Cloud Run revision, SHA-256 process boot-nonce hash, request
ID, trace context, and typed result. Unknown, duplicate, stale, or mismatched
responses fail closed. A model, browser, artifact, or tool can never supply a
routing identifier, callback, provider revision, or boot identity.

## 12. ADK session and state policy

- one session per incident/case agent relationship, not one global session;
- session IDs are application-generated and linked in Cloud SQL;
- session state may cache non-authoritative intermediate context;
- state required after session deletion is stored in typed Cloud SQL records;
- sibling agents receive only explicitly delegated evidence refs, not each
  other's full conversation;
- prompts are rebuilt from current authoritative state on every durable step.

The target Liaison surface has the stricter, reader-sensitive contract in
[14 §12.1](14-conversational-surface.md): Cloud SQL `liaison_*` rows are the
canonical conversation ledger, and a named Conversation Context Compiler
creates one immutable, reference-only working-context manifest for each
principal and attempt. The runner uses a fresh disposable ADK Session seeded
from that compiled view. It never resumes a Session across principals,
membership/policy epochs, or turn attempts, and it never asks provider state to
decide visibility, reference resolution, freshness, or factual truth.

Agent Platform Sessions (`VertexAiSessionService`) are not the Liaison's
canonical store. Their conditional IAM boundary is `userId`, and session
listing requires an unconditional role; those boundaries do not express
Solvan's per-thread/per-part access envelopes. A later managed-Session adapter
is therefore an optional service-owned cache/projection only: its key and TTL
follow 14 §12.1, end users receive no direct Session access, deletion is safe,
and every retry or resume is reconstructible from Cloud SQL. ADK event
compaction and context caching are likewise optional optimizations and cannot
replace Solvan compaction, retention, purge lineage, or authorization.

For the Liaison, the pinned ADK `App`/runner processing boundary should host
only deterministic context injection and response validation whose inputs are
the already-compiled manifest. Application services run identity, access,
epoch, source-version, budget, and claim gates before/after that boundary. A
custom processor cannot broaden the manifest or introduce raw Session history.

## 13. Prompt assembly

Fixed order:

1. immutable agent role and prohibitions;
2. typed scope, deadline, and tool catalog;
3. authoritative incident/case snapshot;
4. approved Production Graph facts;
5. selected evidence excerpts after Armor/redaction;
6. retrieved memories wrapped as untrusted historical hints;
7. required output schema.

Prompt composer records template version, input reference hashes, memory IDs,
Model Armor verdict IDs, token estimate, and model resource. Tool output never
enters the instruction layer.

### 6.1 Durable dispatch acknowledgement

The exact `agent_runs` request is committed in `CREATED` before the provider
call. Provider return is classified as one of four boundaries:

1. pre-call refusal, where application code proves no provider call began;
2. complete acknowledgement, where operation, input, and output references are
   atomically stored and the row becomes `DISPATCHED`;
3. partial acknowledgement, where every returned non-null receipt field is
   stored while the row remains `CREATED`; or
4. unknown acceptance, where process death or transport loss leaves no
   authoritative provider receipt.

The Runtime adapter raises a typed incomplete-receipt error carrying the exact
returned fields; callers persist those fields before applying their existing
role-specific failure policy. A local deadline and a missing deterministic GCS
object do not prove provider absence. A deadline-expired `CREATED` row is
resolved only by a fenced coordinator sweep and receives a closed safe error
class such as `DISPATCH_RECEIPT_INCOMPLETE` or
`DISPATCH_ACCEPTANCE_UNKNOWN`. Late output can be retained for diagnosis but
cannot advance a terminal or superseded run.

## 14. Budgets and loop detection

Default invocation ceilings:

| Agent | Runtime | Model calls | Tool calls | Replans |
|---|---:|---:|---:|---:|
| Supervisor | 300 s | 6 | 0 | 1 |
| Evidence | 300 s | 4 | 10 | 1 |
| Infrastructure | 300 s | 4 | 8 | 1 |
| Verification | 1,200 s active | 1 narration | 20 reads | 0 |
| Workspace | 3,600 s | 12 | 20 bounded workspace/sandbox calls | 1 |

Repeated normalized tool name + argument digest, alternating tool signatures,
no-progress evidence sets, or budget exhaustion ends the invocation. The
coordinator—not the agent—decides retry, fallback, block, or escalation.
Every broker request consumes the immutable request budget, including an
idempotent cache hit. The first provider read remains one `tool_calls` row;
`request_count` records repeated requests so cached loops cannot evade the
ceiling. A failed step may return to `READY` only when its accepted plan names a
`fallback_ref`, and only attempt 1 may do so. Attempt 2 is terminal. The
failure records a durable `retry_not_before` backoff on the step; reservation
never dispatches the fallback earlier, so a transient Runtime fault cannot burn
the final attempt in the same instant, and the deferral survives coordinator
restarts. The coordinator sweeps due deferred steps on every tick. Fresh,
bounded evidence already committed for the incident is included in the
fallback's hashed Runtime input; it does not grant new tools or scope.

Loop enforcement is deterministic and outside the model:

1. Each requested call is fingerprinted from the exact Tool revision,
   connection ID, normalized schema-valid arguments, immutable input evidence,
   and connection/profile epochs before execution.
2. A repeated fingerprint returns the prior bounded receipt when reuse remains
   valid; it creates no second evidence item but increments `request_count` and
   consumes the immutable call budget.
3. After each iteration the coordinator computes a progress fingerprint from
   newly committed evidence IDs/hashes, resolved plan-step predicates, and
   typed result state. Free text, token shingles, and private reasoning are not
   progress signals.
4. Two consecutive iterations with no new progress require the one permitted
   re-plan when available. A second no-progress interval after re-planning, or
   no remaining re-plan budget, terminates the attempt as `exhausted` and
   escalates or uses the accepted fallback.
5. Alternating A-B-A request signatures, result paraphrasing, cache hits, and
   unsupported calls cannot reset the counter.

Every stop records safe reason codes, budget counters, progress fingerprints,
and trace references in Agent Observability. It records no chain-of-thought.

### 14.1 Operator interruption, resume, and context compaction

Cancellation is a durable request, not process signaling as workflow state.
The API atomically marks the active run `CANCEL_REQUESTED`; the Runtime adapter
attempts provider cancellation and records `CANCELLED`, `CANCEL_UNCONFIRMED`,
or the already-terminal result. A response arriving after the cancellation
fence may be retained for diagnosis but cannot commit evidence or advance the
workflow.

Resume always creates a new fenced attempt from current Cloud SQL state. It
reuses the same accepted plan, exact Tool profile, connection IDs, and
effective-set hash only when their policy, identity, capability, region, and
epoch bindings remain valid. Otherwise the coordinator reconciles and creates
a new plan/attempt; it never silently widens the prior run.

Session compaction may summarize model conversation for token efficiency, but
it cannot replace or rewrite plans, evidence, findings, approvals, receipts,
verification results, audit events, or workflow state. Prompts after resume
are rebuilt from authoritative records and resolvable citations. The console
labels cancellation, provider acknowledgement, resume attempt, and any
reconciliation separately.

## 15. Failure and retry classes

| Class | Examples | Automatic retry |
|---|---|---|
| transient | 429, temporary Runtime outage | yes, bounded backoff |
| invalid_output | schema mismatch, unknown tool | one repair, then no |
| policy_denied | IAM/Gateway/Armor/application deny | no |
| stale | workflow version/target changed | recompute new step, not retry effect |
| ambiguous_effect | timeout after mutation request | reconcile only |
| exhausted | loop/budget/deadline | fallback once or escalate |
| dispatch_acceptance_unknown | lost Runtime acknowledgement | Supervisor bounded replan; Execution/Verification escalate |
| dependency_unavailable | Antigravity/Memory unavailable | use specified degradation |

## 16. Agent acceptance criteria

1. Registry lists every release agent and exact capability metadata.
2. Each agent presents a distinct SPIFFE principal in traces and IAM tests.
3. Evidence/Infrastructure/Verification cannot invoke mutation endpoints.
4. Execution Agent requests the real pool recycle and rollback only by stored
   action ID; the actuator alone loads payloads and calls connectors.
5. A malicious agent result cannot introduce a tool or state transition.
6. A looped agent is stopped within budget and stale output cannot commit.
7. Memory Bank outage does not stop deterministic investigation or safety.
8. Antigravity outage or policy ineligibility uses the regional ADK provider or creates
   an honest blocked case.
9. The Antigravity provider imports the pinned official SDK and records its
   version, Cloud Run revision, request ID, and boot hash in deployment and task
   receipts.
10. No prompt or trace includes raw credentials or private chain-of-thought.
11. Managed Agents resources, environment IDs, and Interactions API receipts
    are absent from the SDK provider proof.
12. Duplicate-call replay consumes budget, creates no duplicate evidence, and
    cannot evade the deterministic no-progress breaker.
13. Cancellation fences late output; resume creates a new attempt from current
    authority and never treats provider/session state as durable workflow state.
