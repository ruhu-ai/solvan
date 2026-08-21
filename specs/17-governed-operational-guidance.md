# Solvan governed operational guidance and trigger policies

Status: target product contract; excluded from the Minimum Submittable Release
gate. Nothing in this document proves that guidance authoring, a Skills tab,
or a trigger adapter is implemented.

Related: [agent/runtime](03-agent-model-runtime.md),
[data/API](04-data-event-api.md), [security](05-security-governance.md),
[UI/UX](06-ui-ux.md), [evaluation](08-test-evaluation-acceptance.md),
[tenant integration](13-tenant-integration.md),
[governed Tool Catalog](16-governed-tool-catalog.md), and
[Agent Skills interchange](18-agent-skills-interchange.md).

Concept sources are read-only snapshots of open-source incident-investigation
projects, each pinned to an exact commit in a privately retained manifest. They
are research inputs, not runtime dependencies or security proofs.

## 1. Purpose

Operational knowledge should be reusable across departments without turning a
Markdown file into authority. Solvan therefore catalogs versioned runbooks,
skills, checklists, and diagnostic procedures as **Operational Guidance** in
Agent Registry. Approved guidance may help an Agent decide what evidence to
request and in what order. It cannot grant the request, establish a fact,
authorize an action, or decide recovery.

Trigger policies provide the complementary asynchronous behavior: a verified
deployment, alert, schedule, recurrence deadline, or verification deadline can
create durable coordinator work after a bounded delay. Triggering never invokes
an Agent directly and never replaces the Incident or Reliability Case state
machines.

## 2. Release boundary

This entire specification is target. The competition release may show an
ordinary linked release runbook as documentation, but it does not claim an
Agent Registry guidance catalog, authoring workflow, automated guidance
selection, or target trigger policy. Existing detector, verification, and case
wake-up behavior remains governed by specifications 02–09.

No requirement, test, or release gate in another specification may make this
document required without an explicit status change and traceability update.

## 3. Decisions

1. **Guidance is data, not instruction authority.** Approved content is placed
   in a labelled data envelope below the immutable Agent role and prohibitions.
2. **Discovery is not authorization.** Agent Registry may advertise guidance
   across departments; use still requires scope, classification, region,
   purpose, Agent, Tool-profile, and policy eligibility.
3. **Selection is two-phase and lazy.** A bounded metadata shortlist may enter
   prompt context. Full content is fetched only after an exact revision is
   selected, validated, and persisted for the run.
4. **Steps do not execute commands.** A step may request an ordinary READ,
   COMPUTE, or PROPOSE Tool already present in the frozen profile. It cannot
   add a Tool or contain a model-facing mutation capability.
5. **Completion is computed.** The application evaluates registered predicates
   against committed evidence and receipts. An Agent does not mark a step
   complete by saying it completed it.
6. **Triggers enqueue; the coordinator dispatches.** Trigger adapters write one
   deduplicated firing and coordinator inbox event. They have no Runtime,
   mutation, approval, or verification authority.
7. **Cloud SQL is authoritative.** Registry metadata, model context, Runtime
   sessions, CRD status, scheduler memory, and provider cursors are not the
   durable guidance or trigger ledger.

## 4. Operational Guidance catalog

### 4.1 Immutable revision

```python
class GuidanceRevision(BaseModel):
    schema_version: Literal[1]
    guidance_key: str
    version: str
    display_name: str
    description: str
    owner_department: str
    discoverable_departments: tuple[str, ...]
    guidance_kind: Literal["RUNBOOK", "SKILL", "CHECKLIST", "DIAGNOSTIC_PROCEDURE"]
    applicable_service_kinds: tuple[str, ...]
    applicable_incident_classes: tuple[str, ...]
    symptom_tags: tuple[str, ...]
    purpose: str
    classification: str
    eligible_regions: tuple[str, ...]
    allowed_agent_keys: tuple[str, ...]
    required_profile_revisions: tuple[str, ...]
    steps: tuple[GuidanceStepRevision, ...]
    content_ref: str
    content_hash: str
    source_kind: Literal["SOLVAN_AUTHORED", "CUSTOMER_AUTHORED", "IMPORTED"]
    source_ref: str
    evaluation_ref: str | None
    approval_ref: str | None
    supersedes: str | None
    lifecycle: Literal["DRAFT", "IN_REVIEW", "APPROVED", "DEPRECATED", "RETIRED"]
```

The content reference resolves only inside the authorized guidance service.
Registry listings expose safe metadata and the Solvan revision resource, not
the underlying object URL or unrestricted body.

### 4.2 Step contract

```python
class GuidanceStepRevision(BaseModel):
    step_key: str
    ordinal: int
    title: str
    objective: str
    step_kind: Literal["OBSERVE", "COMPUTE", "PROPOSE", "CHECKPOINT"]
    allowed_tool_revisions: tuple[str, ...]
    prerequisite_step_keys: tuple[str, ...]
    completion_predicate_key: str
    completion_predicate_version: str
    required_evidence_kinds: tuple[str, ...]
    maximum_tool_requests: int
    on_blocked: Literal["CONTINUE", "STOP_INCONCLUSIVE", "ESCALATE"]
```

Rules:

- ordinals are unique and prerequisites form a directed acyclic graph;
- a step's Tools must be a subset of every required profile revision;
- `MUTATE`, arbitrary shell, generic HTTP, generic SQL, unrestricted
  filesystem, secret, IAM, and deployment-administration Tools are invalid;
- objectives cannot contain credentials, customer data examples, hidden
  instructions, factual outcomes, approval language, or verification verdicts;
- a proposed action remains an ordinary typed proposal subject to all action
  policy and approval gates;
- predicates are code-implemented, enumerated, versioned, and tested. A missing
  or unknown predicate prevents approval.

## 5. Authoring, review, and lifecycle

Authoring creates a new draft revision; approved revisions are immutable.
Updating content, metadata, steps, predicates, profiles, classification, or
regions creates a successor. Historical runs keep resolving the old revision.

The ingestion pipeline performs, in order:

1. verified author and tenant-scope authorization;
2. size, encoding, structure, and closed-enum validation;
3. secret, credential, PII, classification, and residency checks;
4. Model Armor screening where the exact operation is supported;
5. Tool/profile existence and subset validation;
6. DAG and predicate validation;
7. adversarial evaluation under specification 08;
8. independent human approval of the exact content digest and evaluation;
9. Registry publication and Gateway/read-policy binding.

`GUIDANCE_AUTHOR` may draft and submit. `GUIDANCE_APPROVER` may approve,
deprecate, or retire in an authorized department/scope and cannot approve a
revision they authored. Importers have no approval authority. Approval binds
the exact content, metadata, step graph, predicate versions, evaluation, and
profile revisions. Empty discoverability, Agent, Tool-profile, classification,
or region eligibility denies use.

`GUIDANCE_EXPORTER` is a separate, purpose-bound role. It may export only an
already approved (or explicitly acknowledged deprecated) revision to a
registered destination after the export bytes pass the configured license,
secret/PII, Model Armor, and disclosure checks. It cannot author, evaluate,
approve, or alter a revision.

Imported guidance records source license and attribution. Import does not
preserve upstream trust or approval; it enters as `DRAFT` and passes the same
pipeline as authored content. The accepted interchange format, its bounds, and
its compilation mapping are defined in
[Agent Skills interchange](18-agent-skills-interchange.md).

## 6. Selection, fetch, and execution

The coordinator constructs candidates only from `APPROVED` revisions after
filtering tenant, project, environment, purpose, service/incident class,
classification, region, allowed Agent, exact profile, and lifecycle. The
shortlist contains only key/version, display name, description, applicability,
owner, and evaluation status.

An Agent may rank that shortlist or return `NO_GUIDANCE_MATCH`. The coordinator
accepts at most one primary and two supporting revisions, revalidates their
eligibility, and persists the exact keys, versions, hashes, profile hash,
connection epochs, and selection reason before fetching full content. A model
cannot supply an unknown key or version.

Fetched content is scanned again, bounded, labelled as untrusted operational
guidance, and placed below authoritative state in prompt assembly. A fetch
failure leaves the existing plan intact and records `GUIDANCE_UNAVAILABLE`; it
does not broaden the Tool set or fall back to an unapproved revision.

Each step produces an application-owned status:

```text
PENDING | RUNNING | SATISFIED | NOT_SATISFIED |
BLOCKED | SKIPPED_POLICY | NOT_APPLICABLE | ERROR
```

`SATISFIED`, `NOT_SATISFIED`, and `NOT_APPLICABLE` require the registered
predicate result and cited records. `BLOCKED`, `SKIPPED_POLICY`, and `ERROR`
require a closed reason code. Agent narration may explain a stored status but
cannot create or relabel it. Guidance execution ends inside the ordinary Agent
run budget and no-progress rules in specification 03.

### 6.1 Code Repair pre-run selection — `target`, not implemented

The `workspace.code-repair.v1` profile is the one exception to the generic
`agent_run` selection anchor: its repair plan is the required pre-run anchor.
The exact selection-set schema, mandatory `reliability.code-repair` skill,
conditional `reliability.ci-failure-triage` skill, candidate filters, hash
binding, fetch/scan ordering, and retry rules are normative in specification
23 §5. The exception does not weaken any guidance invariant: the selection is
persisted and all content hashes are bound before the agent request exists;
only then can content be fetched and the run created. A missing, stale,
ineligible, or unscannable required skill refuses dispatch rather than falling
back to an unskilled repair run.

## 7. Trigger policy revisions

### 7.1 Contract

```python
class TriggerPolicyRevision(BaseModel):
    schema_version: Literal[1]
    policy_key: str
    version: str
    owner_department: str
    trigger_kind: Literal[
        "DEPLOYMENT_ROLLOUT", "ALERT_OPENED", "ERROR_SIGNATURE",
        "SCHEDULE", "RECURRENCE_DUE", "VERIFICATION_DUE"
    ]
    source_connection_id: str
    target_selector_ref: str
    incident_class: str
    severity: Literal["SEV1", "SEV2", "SEV3", "SEV4"]
    deduplication_dimension: str
    action_budget: int
    repeated_action_limit: int
    guidance_revision: str | None
    investigation_profile_ref: str
    delay_ms: int
    cooldown_ms: int
    maximum_pending_per_target: int
    supersession: Literal["KEEP_ALL", "LATEST_WAITING_PER_TARGET"]
    region: str
    classification_ceiling: str
    lifecycle: Literal["DRAFT", "APPROVED"]
    approval_ref: str | None
    evaluation_ref: str | None
```

Trigger policy selectors are typed, stored, and human-authored. They cannot be
free-form model expressions, shell, SQL, arbitrary URLs, or unreviewed query
languages. Delay and cooldown bounds are policy-owned. A trigger may narrow the
resulting investigation but cannot select a mutation or weaker verification.

The incident class, severity, deduplication dimension, and action ceilings are
also exact human-approved policy material. They are required because the
coordinator cannot safely invent incident identity or budgets when a firing
becomes due; source payloads and models cannot supply or override them.

### 7.2 Current-head activation

Approval makes a revision eligible for activation; it does not make every
approved revision eligible for matching. One append-only
`trigger_policy_activation` ledger and one application-owned
`trigger_policy_current_heads` projection select at most one current revision
for each `(organization_id, project_id, environment_id, policy_key)`.

An activation records the scope triple, policy key, strictly increasing
`head_epoch`, expected prior head epoch, exact approved revision/version/hash,
its evaluation and approval references, connection epoch, cell ID, placement
epoch, actor, reason, and timestamp. The advancement transaction compares the
expected prior head and all exact approved material, appends the activation, and
updates the projection atomically. A retry with the same idempotency key and
request hash returns the original result; a differing retry refuses.

The target schema enforces this as one relational authority tuple—not a set of
same-scope references. The activation has composite foreign keys to the exact
revision `(key, version, policy_hash, evaluation_ref, approval_ref,
source_connection_epoch, supersession)`, a successful evaluation of that same
revision/hash, and an approving decision over that same evaluation. The
current-head projection references the exact activation tuple including key,
version, hash, head epoch, activation kind, connection epoch, placement epoch,
and supersession. An activation actor must hold the unexpired department-bound
`TRIGGER_POLICY_ACTIVATOR` role. Cross-policy, cross-revision, failed-evaluation,
rejected-approval, or field-spliced tuples fail before becoming a head.

Only the projected current head whose immutable revision lifecycle is
`APPROVED` is a matching candidate. `DISABLED` is availability in the head
projection, never a mutable revision lifecycle. Deactivating or retiring a head
appends an explicit deactivation that
either names one exact already-approved successor or leaves no current head; it
never revives a predecessor by query order, version, timestamp, or retry. A
firing freezes its head epoch, revision, hash, and activation ID. Every claim,
dispatch, result acceptance, and successor revalidates the current head; stale
work remains history and cannot start new work.

### 7.3 Lifecycle retirement

An approved revision is never updated to `RETIRED`. The append-only
`trigger_policy_lifecycle_decisions` ledger and its fenced
`trigger_policy_current_lifecycles` projection own availability after approval.
The first lifecycle authority is an explicit `MARK_ELIGIBLE` decision committed
by the Lifecycle Service after the exact approval becomes valid; it has epoch
1 and expected-prior epoch 0. Approval alone and a projection row with no
decision cannot manufacture eligibility. Each later decision records scope,
policy key/version/material hash, strictly
increasing lifecycle epoch, expected prior lifecycle epoch, operation
`RETIRE`, verified actor/role, idempotency key/request hash, reason, and time.
Only the deterministic **Trigger Policy Lifecycle Service** may apply the typed
retirement command after authorizing `trigger_policy_lifecycle_manager`; the
revision author and approver cannot retire it. Alone, a retirement of a current
head atomically appends only its deactivation and leaves no current head. It
cannot name or select a replacement. A replacement requires a separately
authorized, immutable Activation Service replacement intent under
`trigger_policy_activator`; the compound transaction consumes that exact intent
and the lifecycle decision once, with matching scope, expected lifecycle/head
epochs, current activation ID, successor revision/material/evaluation/approval,
connection/placement epochs, and compound request hash. Only the Activation
Service appends the successor head activation. A missing, stale, mismatched, or
replayed intent refuses the entire compound transition.
Historical firings retain their revision/hash; the current lifecycle projection
refuses new activation, matching, or work for a retired revision.

The lifecycle projection composite-references the exact immutable decision,
including operation and epoch. A replacement intent freezes the retiring
revision/hash and activation/head epoch, the successor's exact approved tuple,
and the lifecycle epoch it will consume. Consumption binds one exact `RETIRE`
decision through a composite foreign key and a partial unique index permits
that lifecycle decision to be consumed once globally in its scope. Both the
Lifecycle Service actor and Activation Service actor are checked against their
distinct current department-bound roles; neither role implies the other.

### 7.4 Durable firing and supersession

Verified source events are canonicalized and deduplicated before policy
matching. A match considers only current heads and commits one `trigger_firing`
and one scheduled wake-up in the same Cloud SQL transaction. The firing freezes
policy head epoch/activation ID/revision/hash/activation kind, source event,
connection epoch, placement epoch, exact eligible lifecycle decision/epoch,
supersession mode, target selector result, due time, scope, region, and
classification. Composite foreign keys bind the firing to the exact immutable
activation and `MARK_ELIGIBLE` lifecycle decision; current projections are
also compared transactionally at insertion and claim time.

For `LATEST_WAITING_PER_TARGET`, a newer matching source sequence atomically
marks older `WAITING` firings `SUPERSEDED` and becomes the only pending firing.
An older or equal non-duplicate sequence arriving after the current waiting
firing is committed as `SUPPRESSED` with reason `STALE_SOURCE_SEQUENCE`; it
never displaces the newer firing and never relies on a uniqueness violation as
its product decision.
It cannot supersede `CLAIMED` or `RUNNING`; those complete independently and
the newer event receives its own cooldown/suppression decision. Every
suppression or supersession is an immutable record, never silent deletion.

The concurrency backstop is a partial unique index over
`(scope, policy_key, policy_version, target_key)` for rows whose frozen
supersession is `LATEST_WAITING_PER_TARGET` and whose status is `WAITING`.
The serialized application command and its advisory transaction lock are the
primary arbiter: it locks the exact current policy-target authority row, appends
the supersession decision, transitions the predecessor, and inserts the
successor in one transaction. The unique index is a final corruption backstop,
not the product decision or normal concurrency control flow.

Cloud SQL owns the closed firing transition graph:

```text
WAITING -> CLAIMED -> ENQUEUED -> RUNNING -> COMPLETED
    |         |
    |         +-> BLOCKED
    +-> SUPERSEDED
```

Only `WAITING` and terminal `SUPPRESSED` are legal insertion roots; every other
state must be reached through the graph. `SUPPRESSED`, `SUPERSEDED`,
`BLOCKED`, and `COMPLETED` cannot transition again. Reclaiming an expired
`CLAIMED` row is the sole same-state lease update, and Cloud SQL permits it only
after the old lease expires at database time. Every `CLAIMED` firing must match
the exact active wakeup `{claim_owner, claim_token, claim_expires_at}` tuple in
the same transaction. Only `CLAIMED` may carry that complete tuple; enqueue
clears it atomically. `ENQUEUED`, `RUNNING`, and `COMPLETED` require the same
immutable coordinator inbox reference. Exactly the terminal set carries
`completed_at`, while refusal terminals require a closed reason code. A SQL
transition guard rejects illegal insertion roots, skips, regressions, partial
or stale lease material, missing inbox results, forged completion, and
outcome-field edits without a state transition.

At due time, a fenced scheduler claim revalidates current-head epoch and
lifecycle, source connection health/epoch, target eligibility, cooldown, region,
classification, and current workflow state. Success writes one coordinator inbox event. The
coordinator alone decides whether to open/deduplicate an incident and dispatch
an Agent through the normal durable plan path. Failure records a safe blocked
reason and retry policy; no model is called.

Cloud Scheduler, Pub/Sub, Eventarc, webhooks, or provider polling may deliver
source events, but none owns pending state. Process restart, duplicate delivery,
or delayed delivery cannot lose, duplicate, or reorder a committed firing.

## 8. Connection and identity binding

Guidance and trigger requests always name exact configured connection IDs.
Provider, environment, project, account, cluster, repository, and workspace
defaults are prohibited. Connection availability must be `READY` with fresh
capability proof under specification 13 before selection or firing.
Each Trigger Policy revision also binds one exact approved source-capability
Tool revision (`source_capability_tool_ref`), registered Agent
(`source_capability_agent_key`), exact verified identity
(`source_capability_identity_ref`), and closed capability class
(`source_capability_class`). At policy eligibility, one current `PASSED` receipt
proves only target-independent dependencies: the exact Tool/Agent/identity/
profile tuple, connection provider and epoch, declared capability shape,
Registry/network material, region, and classification ceiling. No target exists
at that stage, so eligibility never claims target-project coverage.

After a verified event resolves an exact target, event acceptance and every
duplicate replay prove the current approved Graph node, its external project,
the current environment authorization binding, and the exact connection
coverage row tied to that same fresh probe receipt. Due-time enqueue repeats
the complete target-bearing proof. A receipt or coverage row for another Tool,
Agent, identity, provider, capability class, target project, Registry resource,
network policy, region, or classification is ineligible. The source-capability
fields and identity reference are immutable policy material; the resolved
target snapshot hash—including its external project—is immutable firing
material. None is inferred from whichever probe happens to be fresh or from
caller/model input.

MCP-backed read Tools remain governed by specification 16. OAuth completion is
authentication material only: verified principal, authorization-code PKCE,
registered resource indicator, requested scope, tenant, connection ID/epoch,
expiry, catalog revision, profile, Gateway, and application policy must all
match. Guidance content never receives or chooses a token, scope, MCP server,
resource, or connection.

## 9. Target data model

The implementation phase adds, but does not yet merge into canonical
`schema.sql`:

```text
guidance_definitions
guidance_revisions
guidance_revision_agents
guidance_revision_profiles
guidance_steps
guidance_step_tools
guidance_ingestion_receipts
guidance_evaluations
guidance_approvals
operability_role_bindings
operability_audit_events
guidance_selections
guidance_step_runs
repair_plan_guidance_selection_sets
repair_plan_guidance_selections

trigger_policy_revisions
trigger_policy_evaluations
trigger_policy_approvals
trigger_policy_activations
trigger_policy_current_heads
trigger_policy_lifecycle_decisions
trigger_policy_current_lifecycles
trigger_policy_replacement_intents
trigger_firings
trigger_firing_wakeups
trigger_firing_suppressions
```

All tenant records carry the standard organization/project/environment scope
triple and RLS. Revision primary keys include version. Foreign keys bind exact
Agent, Tool, profile, connection, predicate, evaluation, approval, event,
incident/case, run, receipt, and supersession records. Historical references
use restrictive deletion; retention and legal hold follow specification 05.
`TRIGGER_POLICY_ACTIVATOR` and `TRIGGER_POLICY_LIFECYCLE_MANAGER` are distinct
verified role bindings. The target schema persists append-only activation,
deactivation, lifecycle, and one-use replacement-intent records with expected
epochs, idempotency/request hashes, exact material/approval/evaluation, and
connection/placement fence material; current-head and current-lifecycle tables
are fenced projections only.
Every projection row composite-references one exact immutable authority row;
the initial eligible lifecycle is also an immutable decision rather than an
unconstrained projection default.
User-authored bodies use the declared classification and are never copied into
audit rows, traces, or search indexes outside eligible scope/region.

Indexes support approved discovery by scope/applicability/lifecycle,
revision/hash resolution, selection by Agent/profile, step order and
prerequisites, due firing claims, target supersession, cooldown history, and
incident/case/run history. One partial unique index permits only one live
`WAITING` firing per `(scope, policy_revision, target_key)` when supersession is
`LATEST_WAITING_PER_TARGET`; a two-transaction acceptance test proves the
serialized decisions leave exactly one `WAITING` row whether the older or newer
source sequence acquires the policy-target lock first. The partial unique index
remains a corruption backstop, not normal control flow.

## 10. API contracts

Read APIs:

```text
GET /api/fleet/guidance
GET /api/fleet/guidance/{guidance_key}/revisions/{version}
GET /api/fleet/guidance/{guidance_key}/revisions/{version}/evaluations
GET /api/fleet/trigger-policies
GET /api/fleet/trigger-policies/{policy_key}/revisions/{version}
GET /api/fleet/trigger-firings
GET /api/incidents/{incident_id}/guidance-runs
```

Administrative commands are typed and version-fenced:

```text
POST /api/admin/guidance/drafts
POST /api/admin/guidance/{key}/revisions/{version}/submit
POST /api/admin/guidance/{key}/revisions/{version}/approve
POST /api/admin/guidance/{key}/revisions/{version}/deprecate
POST /api/admin/guidance/{key}/revisions/{version}/retire
POST /api/admin/trigger-policies/drafts
POST /api/admin/trigger-policies/{key}/revisions/{version}/evaluations
POST /api/admin/trigger-policies/{key}/revisions/{version}/approve
POST /api/admin/trigger-policies/{key}/revisions/{version}/mark-eligible
POST /api/admin/trigger-policies/{key}/heads/activate
POST /api/admin/trigger-policies/{key}/heads/deactivate
POST /api/admin/trigger-policies/{key}/heads/prepare-replacement
POST /api/admin/trigger-policies/{key}/revisions/{version}/retire
POST /api/admin/trigger-policies/{key}/revisions/{version}/retire-with-prepared-replacement
```

Every command requires verified identity, role, scope, current row version,
exact digest, idempotency key, and audit event. Request bodies never supply
principal or effective scope. Read APIs return reader-filtered metadata and
safe content only.

Only the deterministic **Trigger Policy Activation Service** may apply the two
head commands after authorizing the verified principal's
`trigger_policy_activator` role. The author of the candidate revision and its
approver may not activate it. The external `activate` body is exactly
`{schema_version, expected_digest, candidate_version,
expected_prior_head_epoch, expected_activation_id, placement_epoch}`. Verified
identity, scope, and idempotency key come from the authenticated request; the
service transaction resolves and locks evaluation, approval, connection epoch,
supersession, and reason code. Initial activation requires epoch zero and no
activation ID; every later activation requires both a positive prior epoch and
its exact activation ID. The external `deactivate` body is exactly
`{schema_version, expected_digest, current_version, expected_head_epoch,
expected_activation_id}` and can only remove the current head. Atomic
replacement exists only through the separately typed `prepare-replacement` and
`retire-with-prepared-replacement` protocol below. Every command appends an
immutable decision; none edits a revision. Stale head, activation, connection,
placement, material, evaluation, approval, role, self-activation, or changed
idempotent material refuses.

`retire` requires `{schema_version, idempotency_key, request_hash,
expected_lifecycle_epoch, revision_version, revision_material_hash, reason_code}`
and the verified `trigger_policy_lifecycle_manager` role. It appends the §7.3
lifecycle decision only; it never updates the revision. A retirement request for
a current head includes expected head epoch/activation ID and leaves no head.
`prepare-replacement` is an Activation Service command, independently
authorized by `trigger_policy_activator`, that records the exact successor and
all matching fence material as a one-use replacement intent but changes no head.
`retire-with-prepared-replacement` consumes that intent and the lifecycle
decision atomically; it requires both verified roles (which may not be the
author or approver), and is refused if either authorization is absent.
The prepared intent is never updated to mark consumption. The compound command
appends one immutable `trigger_policy_replacement_consumption` row, whose
one-to-one key makes the intent single-use, while current-head and current-
lifecycle tables remain explicitly rebuildable projections. The retiring and
successor revisions must advance the same `policy_key`; cross-key replacement
is a separate deactivate plus activate workflow, not one compound command.

Authorization precedes every idempotent replay. The verified principal and
required role set are part of each request hash, and replay rechecks the roles'
current, unexpired bindings. A different principal, a revoked role, or a role
whose department no longer matches receives no prior result.

## 11. Console contract

Agent Fleet adds the target `Skills` tab specified in specification 06. The
operator-facing name is Skills; the persisted and API-facing domain remains
Operational Guidance and `GuidanceRevision`.
Operators can distinguish:

- lifecycle: Draft, In review, Approved, Deprecated, Retired;
- availability in current scope: Available, Unavailable, Degraded, Disabled;
- evidence: Not evaluated, Evaluated, Evaluation stale;
- use: Selected, Running, Satisfied, Blocked, Skipped, Superseded.

Every non-healthy state shows `Why` and `Next step`. Guidance, trigger, and
connection health never share one overloaded badge. Color supplements label
and icon. Registry discovery, approval, availability, selection, step result,
and incident truth are visibly separate.

Incident Evidence shows the selected revision and step checklist. Each step
links to its predicate result, evidence, Tool receipts, blocked reason, and
trace. It never displays a green check based solely on Agent narration.
Trigger-policy detail shows selector summary, delay, cooldown, pending firing,
supersessions, last execution, connection health, and next due time.

## 12. Security and privacy

1. Guidance bodies, metadata, imports, provider errors, and trigger payloads
   are untrusted input.
2. Registry listing does not expose content beyond reader classification or
   authorize selection.
3. An empty access, Agent, profile, region, classification, or purpose set
   denies use.
4. Guidance cannot widen Tools, connections, budget, network, identity,
   classification, region, action, approval, or verification policy.
5. Secrets, credentials, PII, customer examples, raw provider errors, prompt
   injection bodies, and private reasoning are excluded from safe projections.
6. Content or metadata changes after approval require a successor revision and
   new evaluation/approval.
7. A compromised trigger source can enqueue only events that pass verified
   source identity, typed schema, selector, deduplication, delay, cooldown,
   connection, and application policy; it cannot dispatch or mutate.
8. Author, approver, trigger adapter, coordinator, Agent, actuator, and verifier
   identities remain distinct according to their responsibilities.
9. Model Armor is defense in depth. Unsupported operations and Armor outage
   remain protected by deterministic validation and may block/degrade according
   to policy; neither becomes default allow.
10. Search, embeddings, and Memory Bank cannot index guidance outside its
    classification, tenant, purpose, and region or promote guidance text into
    an authoritative fact.

## 13. Observability and audit

Safe OTel attributes include guidance key/version/hash suffix, step key,
selection outcome, predicate key/version, trigger policy/firing ID, source
event type, connection ID, lifecycle, status, reason code, budgets, latency,
and trace ID. Bodies, credentials, provider errors, raw Tool output, prompts,
responses, PII, and private reasoning are excluded.

The audit ledger records authoring, submission, evaluation, approval,
publication, selection, fetch, step verdict, deprecation/retirement, trigger
match, suppression, supersession, claim, enqueue, and refusal decisions with
safe references and digests. Agent Observability aids operations but is not the
approval or workflow ledger.

## 14. Invariants

| ID | Invariant |
|---|---|
| INV-OG-01 | Guidance discovery never grants content access, Tool use, dispatch, or action authority. |
| INV-OG-02 | Only an approved exact immutable revision may be selected for new work. |
| INV-OG-03 | Full guidance content is fetched lazily only after eligibility and selection persistence. |
| INV-OG-04 | Guidance Tools are a subset of the run's frozen approved profile and cannot change its effective-set hash. |
| INV-OG-05 | A model cannot establish step completion; registered predicates over committed records determine status. |
| INV-OG-06 | Guidance cannot assert root cause, approve, actuate, verify, resolve, close, or promote memory/graph state. |
| INV-OG-07 | Author and approver are distinct verified principals for one exact revision digest. |
| INV-OG-08 | Imported guidance has no inherited trust and must pass ingestion, evaluation, and approval. |
| INV-OG-09 | Trigger adapters enqueue one deduplicated firing and never invoke an Agent directly. |
| INV-OG-10 | Pending trigger state, delay, cooldown, suppression, and supersession are authoritative in Cloud SQL. |
| INV-OG-11 | A trigger firing revalidates the exact Tool/Agent/capability-class receipt and identity binding, connection epoch, authorized target external project and coverage, policy, target snapshot, region, classification, cooldown, and workflow state before enqueue. |
| INV-OG-12 | Explicit connection IDs are mandatory; implicit provider/environment routing is denied. |
| INV-OG-13 | MCP OAuth is principal-, connection-, resource-, scope-, epoch-, and expiry-bound and does not bypass catalog/profile authorization. |
| INV-OG-14 | Guidance and trigger telemetry/audit exclude bodies, secrets, PII, raw provider errors, prompts/responses, and private reasoning. |
| INV-OG-15 | This target contract creates no MSR obligation until explicitly promoted by documentation policy. |
| INV-OG-16 | Only one current activated policy head exists per scoped policy key; approval, version order, or retry cannot activate or revive a revision implicitly. |
| INV-OG-17 | Retirement is an append-only, role-gated lifecycle decision. It never edits approved policy material; it can only deactivate a current head unless a separately authorized, one-use Activation Service replacement intent is atomically consumed. |

## 15. Acceptance fixtures

1. Registry search discovers guidance but the reader lacks content scope;
   metadata is filtered and content is denied.
2. A model invents a plausible guidance key/version; selection rejects it.
3. Guidance is approved, then its body changes in object storage; hash mismatch
   blocks fetch and emits one security event.
4. Guidance names a Tool absent from the frozen profile; approval and runtime
   subset validation both fail.
5. Guidance text says to ignore policy and run shell/SQL; no such Tool exists,
   the injection is withheld/labelled, and the run degrades safely.
6. An Agent narrates “step completed” without predicate evidence; status does
   not advance.
7. A predicate is unknown or its version retired; the revision cannot be
   approved for new work.
8. The author attempts to approve their own exact revision; authorization
   refuses.
9. A remote/imported revision collides by name with an approved local revision;
   no override occurs and the import remains a distinct draft key/version.
10. Two connections could satisfy metadata and the request omits connection
    ID; selection fails instead of using a default.
11. A provider error contains credential and PII canaries; reason code and next
    step persist without either value.
12. MCP OAuth token is valid for the wrong resource, principal, tenant, scope,
    connection epoch, or expiry; Tool call is denied.
13. Duplicate source-event delivery creates one firing and one coordinator
    inbox event.
14. Three rollouts arrive during delay with `LATEST_WAITING_PER_TARGET`; two
    immutable supersessions remain and only the newest waiting firing runs.
15. A newer rollout arrives after the prior firing is `RUNNING`; it cannot
    supersede that run and receives a separate recorded cooldown decision.
16. Process death after trigger claim expires the lease; one new claimant
    resumes without duplicate enqueue.
17. Connection epoch, policy, target, or region changes while waiting; due-time
    revalidation blocks the stale firing.
18. Trigger content attempts to specify a model, Tool, mutation, approval, or
    verification profile; schema rejects it.
19. Guidance selection repeats Tools without progress; specification 03 stops
    the attempt within budget and creates no duplicate evidence.
20. Retired guidance remains readable for an authorized historical run but
    cannot enter a new run.
21. Audit/trace leak tests seed secrets, PII, provider errors, prompts, and raw
    bodies; safe telemetry contains none.
22. The MSR manifest and release checker run with no guidance/trigger resources
    and remain unchanged.
23. Exercise the typed activation commands: approve/activate v1, concurrently
    activate v2, retry both decisions, then deactivate v2 while
    firings race every boundary. Deny a caller without `trigger_policy_activator`,
    the author, a stale expected epoch/activation, and a changed retry hash. One
    head advancement wins per epoch; each firing freezes its head; no predecessor
    revives or creates a false policy-overlap conflict.
24. Retire a non-head and a current head through the typed lifecycle command;
    a lifecycle manager alone can leave no head but cannot choose a replacement.
    Supply an independently authorized one-use Activation Service replacement
    intent and commit both decisions once; reject stale/mismatched/replayed
    lifecycle/head/intent material, unauthorized or author/approver actors, and
    injected partial compound commits.
    Historical firings still resolve the original immutable material, while the
    current projection admits no new activation, match, or work for it.
25. Reuse one source event ID while changing each frozen event field in turn;
    every changed replay refuses, while an exact replay succeeds only while the
    exact source-capability receipt and connection authority remain current.
26. Replace each target-independent source-capability dimension in turn—Tool
    revision, Agent, receipt identity, provider, capability class, Registry
    resource, network-policy hash, region, and classification—with a fresh
    successful but nonmatching receipt; policy eligibility refuses. After an
    event resolves its target, replace the graph node's external project or
    its exact coverage row; event acceptance, replay, and due-time enqueue all
    refuse, and the old event snapshot hash cannot enqueue.
27. Revoke or expire evaluator/approver roles after a successful decision and
    retry its idempotency key; authorization is checked before returning the
    prior result. A same-key request with changed counts, receipt, reasons, or
    approval reason refuses.

## 16. Implementation sequence

1. Freeze this contract and add target DDL plus constraint oracles outside the
   canonical schema until implementation begins.
2. Add immutable guidance validators, content ingestion, safe projections,
   evaluation binding, and approval workflow.
3. Add Registry publication, deterministic candidate filtering, lazy fetch,
   profile intersection, and predicate-owned step runs.
4. Add the read-only Agent Fleet Skills tab and incident checklist.
5. Add trigger policy revisions, durable firings, wake-up reconciliation,
   supersession, cooldown, and read APIs.
6. Add one deployment-rollout trigger against a synthetic, non-production
   connection; qualify duplicates, restarts, staleness, and red herrings.
7. Add customer-authored guidance and other trigger kinds only after their
   classification, residency, identity, connection, and evaluation paths pass.

## 17. Non-goals

- executing arbitrary commands copied from a human runbook;
- one giant prompt containing every runbook or Tool schema;
- remote guidance overriding an approved revision by matching its name;
- a model selecting a provider, connection, permission, mutation, approval,
  verification profile, or trigger target;
- using a guidance checklist as evidence that work happened;
- using a trigger firing as evidence that an incident exists or is resolved;
- Kubernetes CRDs, scheduler memory, Agent sessions, or Registry metadata as
  authoritative pending-work state;
- automatic production remediation from an operational-guidance step;
- expanding the competition release gate.
