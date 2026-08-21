# Solvan governed Tool Catalog and capability profiles

Status: target product contract; excluded from the Minimum Submittable Release
gate except that the existing release fleet must use the naming and truthful
implemented-versus-deployed vocabulary in §3. Nothing in this document proves
that a target tool or channel is implemented.

Related: [architecture](02-system-architecture.md),
[agent/runtime](03-agent-model-runtime.md),
[data/API](04-data-event-api.md),
[security](05-security-governance.md),
[UI/UX](06-ui-ux.md),
[Ruhu profile](11-ruhu-integration-profile.md),
[tenant integration](13-tenant-integration.md),
[conversational surface](14-conversational-surface.md),
[governed operational guidance](17-governed-operational-guidance.md),
[Code Repair Workspace profile](23-code-repair-workspace-profile.md),
[production environment model](20-production-environment-model.md).

## 1. Purpose

Solvan must look and behave like a network of reusable institutional agents,
not a single incident bot and not a bag of cloud commands. Agent Registry is
the organizational discovery surface; Agent Runtime executes bounded attempts;
Cloud SQL owns durable multi-week work; Memory Bank supplies scoped,
non-authoritative recall; Agent Identity and Gateway enforce per-agent access;
Model Armor screens supported content paths; Agent Observability records
structured OTel traces without private chain-of-thought.

The Tool Catalog is the missing join between those platform capabilities. It
answers five questions deterministically:

1. What can the organization discover?
2. Which institutional agent is allowed to request it?
3. Which tenant connection makes it usable in this exact scope and region?
4. Which exact revision, schemas, policy, identity, and budget govern this run?
5. What evidence proves the call happened and remained inside its ceiling?

The catalog is not a marketplace and discovery is never authorization.

## 2. Release boundary

The competition release keeps its existing payments vertical slice and exact
tool set. No Ruhu, vendor, GKE, AWS, Slack, general MCP tool, catalog table,
capability-profile object, probe API, or Tools tab in this document enters the
Minimum Submittable Release gate. Section 3 only changes public names and adds
descriptive manifest metadata; it adds no runtime dependency.

The existing release continues to demonstrate the architectural form already
required by specifications 02–09:

- every required institutional agent is visible in Agent Registry;
- every release tool and destination is registered before Gateway allows it;
- every Agent Runtime principal is distinct;
- accepted investigation steps freeze allowed tool names before dispatch, and
  workspace runs additionally bind an effective tool-set hash;
- tool calls appear in Agent Observability and the Solvan audit projection;
- Memory Bank cannot add a tool or permission;
- Model Armor is shown as defense in depth, never as authorization;
- an Agent failure and multi-day case resume do not change the frozen tool set.

Persisting an immutable named profile revision and effective-set hash for every
Agent run is target work in this document, not retroactive MSR work.

## 3. Names: one clean Agent vocabulary

### 3.1 Decision

Every model-backed Registry entry is called an **Agent** in product copy and in
machine contracts. This includes Agent Cards, accessibility labels, events,
packages, types, configuration, deployment resources, stable keys, and durable
database fields. Solvan does not maintain a second `worker` vocabulary or a
compatibility alias for it.

| Public/Registry display name | Stable `agent_key` | Execution role |
|---|---|---|
| Incident Supervisor Agent | `incident-supervisor` | supervisor |
| Evidence Agent | `evidence-agent` | specialist |
| Infrastructure Agent | `infrastructure-agent` | specialist |
| Execution Agent | `execution-agent` | specialist |
| Verification Agent | `verification-agent` | specialist |
| Workspace Agent | `workspace-agent` | workspace |
| Antigravity Incident Workspace Agent | `antigravity-incident-workspace` | optional workspace provider |

The Action Actuator remains a **deterministic service**, not an agent. It can
change production and cannot reason. Calling it an agent would obscure the
most important authority boundary in the system.

### 3.2 Manifest contract

Every agent manifest adds:

```yaml
display_name: Evidence Agent
registry_kind: AGENT
execution_role: SPECIALIST
```

`registry_kind` is `AGENT` for model-backed institutional actors and
`DETERMINISTIC_SERVICE` for seats such as the Action Actuator.
`execution_role` is one of `SUPERVISOR`, `SPECIALIST`, `WORKSPACE`, or
`WORKSPACE_PROVIDER`. It never grants dispatch authority. The coordinator
creates every durable run and performs every dispatch; peer transfer remains
disabled. Machine identifiers remain lowercase kebab-case and are never
inferred from display text.

## 4. Catalog object

One immutable Tool revision has this normative shape:

```python
class ToolRevision(BaseModel):
    schema_version: Literal[1]
    tool_key: str
    version: str
    display_name: str
    description: str
    use_cases: tuple[str, ...]
    anti_use_cases: tuple[str, ...]
    owner_department: str
    permission_class: Literal["READ", "COMPUTE", "PROPOSE", "MUTATE"]
    implementation_kind: Literal[
        "APPLICATION_SERVICE", "CONNECTOR", "DETERMINISTIC_SERVICE", "MCP"
    ]
    allowed_requester_keys: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    required_connection_providers: tuple[str, ...]
    input_schema_ref: str
    input_schema_hash: str
    output_schema_ref: str
    output_schema_hash: str
    evidence_kind: Literal[
        "LOGS", "METRICS", "TRACES", "EVENTS", "TOPOLOGY",
        "DEPLOYMENT_METADATA", "QUERY_STATS", "ARTIFACT", "NONE"
    ]
    output_semantics: tuple[str, ...]
    supported_retrieval_controls: tuple[str, ...]
    no_data_semantics: Literal["HEALTHY", "UNKNOWN", "NOT_APPLICABLE"]
    failure_taxonomy: tuple[str, ...]
    supported_data_classes: tuple[str, ...]
    runtime_regions: tuple[str, ...]
    gateway_destination: str
    registry_resource: str
    model_armor_coverage: Literal[
        "SUPPORTED_OPERATION", "NOT_SUPPORTED", "NOT_APPLICABLE"
    ]
    network_policy_hash: str
    timeout_ms: int
    max_input_bytes: int
    max_output_bytes: int
    default_call_budget: int
    idempotency: Literal["NOT_APPLICABLE", "NATIVE", "SOLVAN_RECONCILED"]
    lifecycle: Literal["DRAFT", "APPROVED", "DEPRECATED", "RETIRED"]
    approval_ref: str | None
    evaluation_ref: str | None
    supersedes: str | None
```

Rules:

- a revision is content-addressed and never edited after approval;
- `MUTATE` tools are allowed only for deterministic services and never appear
  in a model-facing profile;
- `PROPOSE` emits typed intent only and cannot call an external mutation API;
- empty allowed-agent, capability, connection, region, classification, or
  schema fields deny use;
- an `APPROVED` revision requires approval and evaluation references;
- production approval and evaluation references are exact Google Cloud Deploy
  release/rollout resource names plus provider UIDs. The evaluation rollout
  must have succeeded on the same frozen release before a distinct human may
  approve the publication target; an opaque, caller-authored URI or a mutable
  object name is not governance evidence;
- `use_cases`, `anti_use_cases`, output semantics, retrieval controls, and
  failure classes are bounded, versioned data used by validators and
  evaluations; they are never concatenated into a privileged instruction
  layer;
- every evidence-producing revision names one closed `evidence_kind`; `NONE`
  is allowed only for deterministic compute or proposal tools whose outputs
  cite their inputs;
- `no_data_semantics` is explicit because an empty result can mean healthy,
  unknown, or not applicable and a model may not choose among them;
- an unsupported retrieval control makes the call invalid rather than being
  dropped or approximated by the connector;
- a deprecated revision remains inspectable but cannot enter a new run;
- a Registry entry without a matching Solvan revision is discoverable only to
  administrators and unusable;
- every deterministic `MUTATE` connector declares one immutable
  dry-run/effect-comparison profile revision. The action factory owns the
  expected descriptor; the connector independently predicts it from typed
  material and observed pre-state; application code alone compares hashes;
- `payments_pool_recycle` binds `payments-pool-recycle.v1` and
  `cloud_run_rollback_revision` binds `cloud-run-traffic-replacement.v1`.
  Missing, unsupported, or changed profiles refuse before mutation and cannot
  fall back to payload equality or model judgment;
- registration, Agent Identity, Gateway policy, connection capability,
  classification, residency, network policy, application policy, and budget
  must all allow independently.

## 5. Capability profiles

A profile is an immutable named set of exact Tool revisions, not a wildcard or
category. Profiles permit progressive disclosure without moving authorization
into model routing.

```python
class ToolRevisionRefV1(BaseModel):
    tool_key: str
    version: str

class ComputeOnlyToolConnectionRequirementV1(BaseModel):
    tool: ToolRevisionRefV1
    binding_kind: Literal["COMPUTE_ONLY"]

class PolicySourceToolConnectionRequirementV1(BaseModel):
    tool: ToolRevisionRefV1
    binding_kind: Literal["POLICY_SOURCE_CONNECTION"]
    provider: Literal[
        "CLOUD_MONITORING", "CLOUD_LOGGING", "CLOUD_AUDIT", "CLOUD_TRACE",
        "ERROR_REPORTING", "CLOUD_RUN", "CLOUD_SQL"
    ]
    capability_key: Literal[
        "METRIC_READ", "LOG_SEARCH", "AUDIT_LOG_READ", "TRACE_READ",
        "ERROR_GROUP_READ", "RESOURCE_METADATA_READ"
    ]
    external_project_selector: Literal["TARGET_RESOURCE_PROJECT"]

class ToolProfileRevision(BaseModel):
    schema_version: Literal[2]
    canonicalization_version: Literal[1]
    profile_key: str
    version: str
    purpose: str
    allowed_agent_key: str
    tool_revisions: tuple[ToolRevisionRefV1, ...]
    maximum_total_calls: int
    maximum_parallel_calls: int
    maximum_read_window_ms: int
    maximum_aggregate_evidence_bytes: int
    tool_connection_requirements: tuple[
        ComputeOnlyToolConnectionRequirementV1
        | PolicySourceToolConnectionRequirementV1, ...
    ]
    data_classification_ceiling: str
    runtime_region: str
    profile_material_hash: str
    lifecycle: Literal["DRAFT", "APPROVED", "DEPRECATED", "RETIRED"]
    approval_ref: str | None
    evaluation_ref: str | None
```

Every `tool_revisions` entry and every requirement uses the same exact
`ToolRevisionRefV1` representation. There is exactly one ordered connection
requirement for each ordered Tool revision; their ordinal and Tool reference
must agree. The closed requirement union binds a named exact Tool revision
either to no connection (`COMPUTE_ONLY`) or to a closed
provider/capability/resource selector (`POLICY_SOURCE_CONNECTION`); it is never
an inferred provider mapping. Provider and capability form a closed pair, not
two freely combinable enums. Valid pairs are
`CLOUD_MONITORING/METRIC_READ`, `CLOUD_LOGGING/LOG_SEARCH`,
`CLOUD_AUDIT/AUDIT_LOG_READ`, `CLOUD_TRACE/TRACE_READ`,
`ERROR_REPORTING/ERROR_GROUP_READ`, and
`CLOUD_RUN|CLOUD_SQL/RESOURCE_METADATA_READ`. A new pair requires its Tool
revision, capability probe/coverage semantics, threat model, target DDL and
negative fixtures in the same change. Specification 22's Relay catalog cannot
make an otherwise absent pair selectable. The canonical profile material object is RFC 8785
JSON encoded as UTF-8 and prefixed `sha256:` after SHA-256. It has exactly these
fields: `schema_version`, `canonicalization_version`, `profile_key`, `version`, `purpose`,
`allowed_agent_key`, ordered `tool_revisions`, ordered
`tool_connection_requirements`, `maximum_total_calls`,
`maximum_parallel_calls`, `maximum_read_window_ms`,
`maximum_aggregate_evidence_bytes`,
`data_classification_ceiling`, and `runtime_region`. Its digest is
`profile_material_hash`. Evaluation and approval references are outside this
object: each decision stores and verifies that exact material hash, so no
approval or evaluation can change it or create a circular digest.

The `effective_tool_set_hash` is separately
`sha256:RFC8785(EffectiveToolSetV1)`. One shared typed canonicalizer used by the
coordinator binder, replay verifier, Runtime adapter, Gateway adapter, and
vector verifier owns the only valid preimage. `EffectiveToolSetV1` has exactly:
`schema_version`, `profile_material_hash`, ordered `accepted_tools` as
`ToolRevisionRefV1` objects, `agent_key`, `agent_revision`, the exact `scope`
triple, ordered `connection_bindings`, `runtime_region`,
`accepted_data_classification`, `classification_ceiling`,
`policy_head_activation_id`, `policy_head_epoch`,
`placement_epoch`, and `accepted_step_budget_hash`. Each binding contains
`binding_kind` and the exact nested `tool` reference. It is either
`COMPUTE_ONLY` with no connection fields, or
`POLICY_SOURCE_CONNECTION` with the exact symbolic provider/capability/selector
and `{connection_id,connection_epoch,capability_receipt_id,
capability_receipt_hash,external_project_id}`. The
`external_project_id` is the exact project resolved from the frozen Graph target
for that Tool call, not the profile's symbolic selector. Before freezing it,
the coordinator verifies its environment binding and the exact capability
receipt's `METRIC_READ` coverage. Runtime and Gateway compare this ID as part
of the accepted binding and refuse a changed, uncovered, or substituted target,
`runtime_region`, `accepted_data_classification`, `classification_ceiling`,
`policy_head_activation_id`,
`policy_head_epoch`, `placement_epoch`, and the accepted step/budget hash. A
non-trigger run retains the policy-head fields explicitly as `null` and `0`;
omitting either field is invalid. `accepted_step_budget_hash` is the digest of
the closed `StepBudgetV1` object: schema version, deadline, Tool-call,
output-byte, model-call, and replan ceilings. All arrays retain declared ordinal
order; no extra field, lexical sort,
or approval/evaluation reference is permitted. This is the only effective-set
preimage accepted by Runtime and Gateway. The target test registry must publish
one byte-level vector for each hash plus mutations for every field above. A
mutation vector names its base object and exact field path; the keyed companion
`mutation_values` entry supplies its replacement value;
`*_order: REVERSE` reverses that declared array. For the Alert Triage vector,
`connection_bindings.policy_source` is ordinal zero and
`connection_bindings.compute_only` is ordinal one. Mutation objects may be
invalid profiles; they demonstrate only closed preimage coverage and must still
be rejected by the typed validator.

`accepted_data_classification` is the exact classification of the accepted run
input, not an upper bound. It is persisted in the immutable run binding, hashed
inside `EffectiveToolSetV1`, and compared exactly on every bind replay. It must
be no broader than `classification_ceiling`; changing it, even to another value
below the ceiling, creates different material and is refused for the same run.

An empty `accepted_tools` selection is valid only when the approved profile has
zero members and the accepted step budget has both `max_model_calls=0` and
`max_tool_calls=0`. An empty subset never narrows a non-empty profile and never
authorizes a model call without an explicit model budget.

The coordinator resolves a profile only after it has:

1. loaded the accepted investigation step;
2. loaded observed, non-stale connection capabilities;
3. applied tenant, project, environment, purpose, classification, and region;
4. verified the agent revision and Identity;
5. resolved registered Gateway destinations;
6. intersected the profile with policy and the step budget;
7. resolved every policy-source binding's external project from the frozen Graph
   target and revalidated its environment and capability coverage; and
8. persisted the exact ordered set, resolved external projects, and
   `effective_tool_set_hash` in the `agent_run` transaction.

The Runtime request contains only that ordered set. The agent cannot search the
catalog, substitute a revision, enable an MCP server, widen a connection, or
ask another agent for a tool. A retry uses the same profile and hash or becomes
a new durable attempt after policy reconciliation.

Every connection ID names one configured instance such as
`ruhu-prod-europe-west1` or `github-ruhu-production`. There is no implicit
default project, account, region, cluster, namespace, repository, telemetry
tenant, or Slack workspace. A tool whose request omits its resolved
`connection_id`, or supplies an instance outside the frozen profile, is
rejected before Gateway invocation.

## 6. Initial profiles

### 6.1 Existing release profiles

| Profile | Agent | Exact tools | Status |
|---|---|---|---|
| `evidence.gcp-core.v1` | Evidence Agent | Cloud Logging, Monitoring, Trace, Audit Logs, Error Reporting reads | tools implemented; profile revision target |
| `infrastructure.gcp-core.v1` | Infrastructure Agent | Cloud Run, Cloud SQL metadata, Production Graph reads | tools implemented; profile revision target |
| `execution.authorized-action.v1` | Execution Agent | stored-action request only | entry point implemented; profile revision target |
| `verification.payments.v1` | Verification Agent | bound deterministic verifier request only | entry point implemented; profile revision target |
| `workspace.ruhu-snapshot.v1` | Workspace Agent | no network tools; curated input manifest only | boundary implemented; profile revision target |
| `workspace.antigravity-synthetic.v1` | Antigravity Incident Workspace Agent | artifact read and candidate write | boundary implemented and optional; profile revision target |

### 6.2 Ruhu/GCP investigation profile

These tools are target. Each receives bounded identifiers and stored evidence
references; none accepts arbitrary URLs, shell, SQL, log query language, or
unreviewed PromQL from a model.

| Tool | Class | Agent | Contract |
|---|---|---|---|
| `managed_prometheus_query` | READ | Evidence Agent | execute a registered query template over one service and bounded window |
| `metric_baseline_compare` | COMPUTE | Evidence Agent | compare named incident and baseline evidence series using pinned statistics |
| `metric_change_point_detect` | COMPUTE | Evidence Agent | return candidate change points with method/version and minimum sample rules |
| `metric_correlate` | COMPUTE | Evidence Agent | correlate two approved series; label correlation as non-causation |
| `log_pattern_summary` | COMPUTE | Evidence Agent | count registered signatures and bounded normalized clusters |
| `log_sample_bounded` | COMPUTE | Evidence Agent | stratified deterministic sample preserving time and rare signatures |
| `cloud_asset_inventory_search` | READ | Infrastructure Agent | resolve registered resource kinds into a Production Graph candidate |
| `cloud_run_revision_compare` | COMPUTE | Infrastructure Agent | compare two observed immutable revision projections |
| `github_commit_range_read` | READ | Infrastructure Agent | read metadata and changed paths between two exact SHAs |
| `github_pr_diff_read` | READ | Infrastructure Agent | read one bound PR diff with path and byte ceilings |
| `github_workflow_run_read` | READ | Infrastructure Agent | read one bound check/workflow run and bounded failure annotations |
| `cloud_build_history_read` | READ | Infrastructure Agent | read builds for one registered trigger and bounded deployment window |

Profiles:

- `evidence.ruhu-observability.v1` contains the first six tools;
- `infrastructure.ruhu-change.v1` contains the last five;
- both extend, rather than replace, the applicable GCP-core profile in one
  coordinator-resolved immutable set;
- every returned observation becomes an `evidence_item`; compute tools cite
  their input evidence and store method/version/parameters in provenance;
- no compute result confirms root cause or recovery by itself.

### 6.3 Alert Triage read/compute profile — target

`alert-triage-read-compute-v1@1` is the only Alert Triage profile revision. It
is an immutable `APPROVED` target profile for `evidence-agent`; it is not an
alias for, or an extension selected at runtime from,
`evidence.gcp-core.v1`. Its ordered exact Tool revisions are:

```text
cloud_monitoring_query@1
metric_baseline_compare@1
metric_change_point_detect@1
metric_correlate@1
```

The first is `READ`; the latter three are `COMPUTE`. The sole connection
requirement binds `cloud_monitoring_query@1` to the Alert Policy's exact Cloud
Monitoring source connection/epoch with the registered `METRIC_READ` capability
and coverage receipt for the target resource project. The three compute Tools
are explicit ordered `COMPUTE_ONLY` requirements and receive only accepted
stored metric evidence. No Logging, Trace, Audit Log, Error Reporting, arbitrary
provider, or substitute connection is part of this first profile. Each Tool revision allows only `evidence-agent`,
has no `PROPOSE` or `MUTATE` permission, and is subject to its own registered
schema, Gateway destination, timeout, byte limit, and evidence contract.
Missing capability, connection, region, classification, or Tool revision
refuses before dispatch.

The profile has `maximum_total_calls=12`, `maximum_parallel_calls=2`, a maximum
read window of 24 hours, and a maximum aggregate returned-evidence reference
budget of 1 MiB, `data_classification_ceiling=CONFIDENTIAL`, and
`runtime_region=POLICY_BOUND`. Its `profile_material_hash` and
`effective_tool_set_hash` use the exact §5 canonical objects. The normative
byte-level vectors are in
[alert-triage-profile-hash-vectors.yaml](artifacts/alert-triage-profile-hash-vectors.yaml).
The coordinator may narrow the ordered set only by an accepted policy step and
must persist the resulting ordered set and `effective_tool_set_hash`; it may not
add, substitute, or reorder a Tool.
Connection IDs are resolved from the policy/target before this hash is frozen;
no profile or Tool has a default connection, arbitrary HTTP destination,
channel, Memory Bank, approval, verification, A2A, or self-dispatch capability.

### 6.4 Conditional GKE profile

`infrastructure.gke-read.v1` may be approved only for a tenant connection that
probes an exact cluster, namespace, and workload selector. It may contain:

- list bounded pods;
- describe one pod;
- read bounded pod logs through the evidence broker;
- read pod/workload events;
- describe one deployment and rollout history;
- describe one service and endpoints;
- read bounded CPU/memory usage.

It never contains `kubectl exec`, arbitrary `kubectl`, secret/config-map body
reads, port forwarding, delete, rollout restart, scale, patch, or apply. A
restart or rollout is a separately enumerated actuator action with all ordinary
approval, reservation, dry-run, receipt, and verification controls.

### 6.4 Conditional AWS profiles

AWS support does not create an `AWS Agent`. A future adoption contract may add
`evidence.aws-read.v1` and `infrastructure.aws-read.v1` for bounded CloudWatch,
EC2, Lambda, RDS, ECS, and CodePipeline reads. Before approval it requires AWS
identity, residency, credential posture, Gateway route, classification mapping,
and hostile-control-plane tests. No AWS actuation is implied.

### 6.5 Code Repair Workspace profile — target

`workspace.code-repair.v1` is the sole model-facing repair profile. Its exact
ordered revisions are `workspace.code-repair.read-artifact@1`,
`workspace.code-repair.write-candidate-artifact@1`, and
`workspace.code-repair.run-in-sandbox@1`; it has no connection binding because
the Coordinator supplies a pinned artifact manifest and command catalog rather
than granting repository or cloud access. The complete schemas,
path/command/budget ceilings, candidate generation, guidance binding, and
acceptance gate are normative in [specification 23](23-code-repair-workspace-profile.md).
The profile is `READ`/`PROPOSE`/`COMPUTE` only. It contains no GitHub write,
review, merge, deployment, rollback, approval, verifier, shell, arbitrary HTTP,
SQL, cloud-admin, secret, or network capability.

The existing synthetic-provider helper names `read_workspace_artifact` and
`write_candidate_artifact` are not Tool Catalog keys and cannot be registered
under the production keys above. Before any synthetic provider becomes catalog
eligible, its distinct experimental revisions must be registered as
`workspace.synthetic.read-artifact@1` and
`workspace.synthetic.write-candidate-artifact@1`, with their path-shaped
synthetic-only schemas and provider eligibility. No global revision key may
share a name while accepting an incompatible input schema.

## 7. GitHub evidence and workspace boundary

The GitHub release provider remains a deterministic service. It owns GitHub App
credentials and coordinator-authenticated PR operations. Model-backed agents
never receive a token.

GitHub read tools resolve a stored repository binding, exact object identifiers,
and current connection epoch. The provider returns normalized bounded evidence
and a content hash. For deep repair, the coordinator uses those reads to build
a digest-pinned repository snapshot before dispatch. Workspace Agents remain
network-isolated and can change only candidate artifacts in the allowed path
set. Sandbox tests, review, merge, deployment, and production verification stay
separate.

## 8. Slack channel boundary

Slack may be implemented only through specification 14's Liaison channel contract.
The adapter:

- verifies Slack signatures, timestamp window, and event deduplication;
- resolves an active enrollment and connection epoch;
- derives principal and scope from the enrollment, never message fields;
- scans, classifies, redacts, and applies Model Armor where covered before
  durable persistence;
- submits `Ask` or an explicitly confirmed, read-only `Steer` through the same
  Liaison API as the console;
- renders only reader-filtered durable parts;
- posts through the deterministic Slack Liaison delivery service holding the
  Slack credential;
- deep-links every approval to the authenticated console.

No Agent holds a Slack token, posts directly, accepts in-channel approval, or
uses Slack identity as proof of Solvan authority. Slack delivery success is not
workflow success.

## 9. Data model

The target schema adds an immutable Solvan projection of catalog principals,
immutable `tool_definitions`, `tool_revisions`, requester bindings,
`tool_profile_revisions`, and `tool_profile_members`, plus append-only
`tool_probe_receipts`. These tables are not added to canonical `schema.sql`
until the implementation phase and do not change the release schema revision.

A catalog principal and a Tool definition are versioned revisions with a
current head, exactly as `tool_revisions` and `tool_profile_revisions` are.
Publication resolves material to a revision and moves a head: identical
material resolves to the revision that already holds it and moves nothing,
changed material appends the next version and advances the head epoch. A head
may be repointed at any published revision, including an earlier one, because
rolling a release back is a head move and the history it moves across stays
intact. A revision is never rewritten and a head is never deleted.

Keying these two by their business key alone made them immutable *singletons*
rather than immutable histories, so the only material either could hold was
the material of its first publication. Because a principal's `manifest_hash`
is derived from the agent manifest, the first release that edited a manifest
could not publish its catalog at all.

Required fields:

```text
catalog_principal_revisions:
  principal_key, version, display_name,
  registry_kind AGENT|DETERMINISTIC_SERVICE, model_backed,
  manifest_hash, published_at
  unique (principal_key, <material>)   -- one version per distinct material

catalog_principals:                    -- current head, and the foreign-key
  principal_key, version, head_epoch,  -- target every requester binding uses
  display_name, registry_kind, model_backed, manifest_hash, created_at
  foreign key (principal_key, version, <material>)
    references catalog_principal_revisions

tool_definition_revisions:
  tool_key, version, display_name, owner_department, published_at
  unique (tool_key, display_name, owner_department)

tool_definitions:
  tool_key, version, head_epoch, display_name, owner_department, created_at
  foreign key (tool_key, version, display_name, owner_department)
    references tool_definition_revisions

tool_revisions:
  tool_key, version, permission_class, implementation_kind,
  required_capabilities_json, required_connection_providers_json,
  input_schema_ref/hash,
  output_schema_ref/hash, supported_data_classes_json, runtime_regions_json,
  use_cases_json, anti_use_cases_json, evidence_kind,
  output_semantics_json, supported_retrieval_controls_json,
  no_data_semantics, failure_taxonomy_json,
  registry_resource, gateway_destination, model_armor_coverage,
  network_policy_hash, timeout_ms, max_input_bytes, max_output_bytes,
  default_call_budget, idempotency, lifecycle, approval_ref, evaluation_ref,
  supersedes, content_hash, created_at

tool_revision_requesters:
  tool_key, tool_version, requester_key

tool_profile_revisions:
  schema_version, profile_key, version, purpose, allowed_agent_key, maximum_total_calls,
  maximum_parallel_calls, maximum_read_window_ms,
  maximum_aggregate_evidence_bytes, data_classification_ceiling, runtime_region,
  canonicalization_version, lifecycle, profile_material_hash, approval_ref,
  evaluation_ref, created_at

tool_profile_members:
  profile_key, profile_version, ordinal, tool_key, tool_version

tool_profile_connection_requirements:
  profile_key, profile_version, ordinal, tool_key, tool_version, binding_kind,
  provider, capability_key, external_project_selector

agent_run_tool_bindings:
  scope, agent_run_id, profile_key, profile_version, profile_material_hash,
  accepted_tool_count, effective_tool_set_hash, runtime_region, identity_ref,
  bound_at

agent_run_accepted_tool_bindings:
  scope, agent_run_id, profile_key, profile_version, ordinal, tool_key,
  tool_version, binding_kind, provider, capability_key,
  external_project_selector, connection_id, connection_epoch,
  capability_receipt_id/hash, resolved_external_project_id

tool_probe_receipts:
  scope, connection_id, tool_key, tool_version, agent_key, identity_ref,
  registry_resource, gateway_policy_ref, network_policy_hash,
  outcome, reason_code, missing_grant, observed_at, expires_at,
  receipt_ref/hash, trace_id
```

Constraints:

- revision and profile primary keys include version;
- every definition/revision/member/supersession reference has a foreign key;
- requester bindings reference `catalog_principals`; a profile's
  `allowed_agent_key` must reference a model-backed `AGENT` principal;
- profile members reference exact immutable revisions and have one ordinal;
- each profile member has exactly one same-ordinal
  `tool_profile_connection_requirements` row. `COMPUTE_ONLY` rows have no
  provider/capability/selector; `POLICY_SOURCE_CONNECTION` rows carry every
  closed field from `PolicySourceToolConnectionRequirementV1`; any other
  combination refuses. The persisted rows reconstruct precisely the ordered
  `tool_revisions` and `tool_connection_requirements` fields of the canonical
  material object, without defaulting or inference;
- each run binding references the exact `(profile_key, version,
  profile_material_hash)` revision, freezes `accepted_tool_count`, and has
  exactly one `agent_run_accepted_tool_bindings` row per accepted profile
  member. The accepted set may be a policy-narrowed subset of the profile; each
  row retains the member's original ordinal, and sorting by that ordinal is the
  only canonical order. A zero-member accepted set is valid for either a
  zero-Tool profile or an explicitly policy-narrowed run whose model-call and
  Tool-call ceilings are both zero. Those rows are the durable effective-set
  preimage—not opaque JSON—and must be an ordered subset of exact profile
  requirements. `COMPUTE_ONLY` has no connection, epoch, receipt, or external
  project; `POLICY_SOURCE_CONNECTION` has every such field. A dispatch/run
  transition requires a non-null `agent_runs.effective_tool_set_hash` exactly
  equal to its run-binding hash and accepted-row cardinality exactly equal to
  the frozen `accepted_tool_count`. Dispatch reconstructs and hashes the exact
  ordered accepted rows and rejects a missing, extra, duplicate, reordered, or
  out-of-profile row. It never compares accepted cardinality to total profile
  membership or silently fills a rejected member;
- a `MUTATE` revision may bind only a non-model-backed
  `DETERMINISTIC_SERVICE`; a model-backed Agent is rejected by a deferrable
  constraint trigger and the application validator;
- approved tool and profile revisions require approval and evaluation references;
- a successful probe requires every bound reference and no `missing_grant`;
- a failed probe requires a reason and actionable `missing_grant` where the
  operator can remediate it;
- all scoped probe rows receive the standard scope triple and RLS policy;
- retention preserves audit and run meaning after a tool is retired.

Required indexes follow the declared read paths rather than relying on table
scans:

- tool revisions by `(tool_key, lifecycle, created_at desc)` and
  `(registry_resource, gateway_destination)`;
- requester bindings by `(requester_key, tool_key, tool_version)`;
- profiles by `(allowed_agent_key, lifecycle, created_at desc)`;
- profile members by `(tool_key, tool_version)` as well as their primary key;
- probes by `(scope, connection_id, tool_key, tool_version, agent_key,
  observed_at desc)` with an index supporting `expires_at` reconciliation;
- calls by `(agent_run_id, created_at)`, `(profile_key, profile_version,
  created_at desc)`, and `otel_span_id`;
- uniqueness for content hashes within a tool revision and profile revision,
  while historical versions remain resolvable.

`agent_runs` continues to store the exact profile key/version and effective
tool-set hash. `tool_calls` adds `tool_version`, `profile_key`,
`profile_version`, `gateway_decision_ref`, `identity_ref`,
`input_bytes`, `output_bytes`, `cache_status`, and `otel_span_id` during the
implementation migration. Raw arguments and unrestricted payloads are never
stored.

## 10. API and console

Read API:

```text
GET /api/fleet/tools
GET /api/fleet/tools/{tool_key}
GET /api/fleet/tools/{tool_key}/revisions/{version}
GET /api/fleet/tool-profiles
GET /api/fleet/tool-profiles/{profile_key}/revisions/{version}
GET /api/fleet/tool-probes
GET /api/fleet/capabilities
GET /api/fleet/agents/{agent_key}/effective-tools
```

The two capability routes return **decisions**, not catalog rows. A decision is
one `(Agent, Tool revision)` pair carrying a verdict, the layer that produced it,
and the complete ordered chain of authorities behind it: profile membership, the
requester declaration, revision lifecycle, classification and region, the
registered Gateway route, the connection binding, and the capability probe. Each
layer reports `SATISFIED`, `REFUSED`, `NOT_APPLICABLE`, or `NOT_EVALUATED`, with
the record that supports it.

The verdict vocabulary is `ALLOWED`, `DENIED`, `NOT_REGISTERED`, and
`NOT_EVALUATED`. The last two are not softenings of the first two. A capability
in no approved profile was offered to nobody and is `NOT_REGISTERED`; an
authority no record has observed is `NOT_EVALUATED`, and it never folds to
`ALLOWED`. Reporting either as `DENIED` asserts a refusal no record made, which
on a capability reaching the actuator understates production mutation authority
rather than overstating it.

`effective_tools` contains only the capabilities that resolve to `ALLOWED`. The
endpoint previously filtered the catalog by the revisions naming the Agent as an
allowed requester, which is the declared set rather than the reachable one — nine
against four for the Infrastructure Agent — so a name asserting effectiveness
returned more than dispatch would resolve. Withheld capabilities remain in the
response with the authority that withheld each, because omitting them answers
"what can this Agent reach" by silence.

The rule producing these decisions is the one the coordinator applies when it
binds a run. It is not restated by the reader, and a predicate added to run
binding without a corresponding layer is a release-gate failure rather than a
divergence discovered later on a screen.

Capability observation is a separate, authenticated command. The reader observes
and the control-plane API commits, because `api` is the only workload holding
INSERT on `tool_probe_receipts` and `connection_external_project_coverage`,
while the reader — the sole identity permitted to impersonate an enrolled
customer service account — holds no database identity:

```text
POST /internal/v1/tools:probe        (direct GCP reader; observes, writes nothing)
```

The command names one approved Tool revision, one requesting Agent, and one
enrolled connection. The API resolves the Tool's declared capability, registry
resource, Gateway destination, network policy hash, and region ceiling from the
immutable catalog; it resolves the Agent Identity only from the attested
deployment binding, which must name a real Agent Runtime `reasoningEngines`
resource; and it resolves the Gateway policy only from provisioned deployment
attestation. Any of these being absent or unparsable refuses the command.

That refusal is load-bearing rather than defensive. The console's freshness test
reads `outcome` and `expires_at` and does not re-verify the identity on the
receipt, so a receipt written with an invented identity would render the Tool
`Available` while run binding still refused it — the console asserting a
capability the coordinator denies. A Tool therefore cannot become `Available`
before its Agent is deployed and its Gateway route provisioned, and this is a
property of the design rather than a gap in it.

The **Agent Fleet** page adds a `Tools` tab after `Agents`. It is a list and a
detail, and the list never renders a fact that holds the same value on every
row: a value that never varies distinguishes nothing, so it belongs to the
fleet or to the detail, not to every card. The list shows:

- the capability name and its READ, COMPUTE, PROPOSE, or MUTATE class;
- the required integration;
- the requesting Agent, as the group heading rather than a per-row field;
- availability, as a badge on a row only where that row departs from the
  fleet-wide availability;
- the count of selectable revisions in this scope, stated once above the list;
- one plain-language reason and next step above the list when a single cause
  blocks the whole catalog. When rows are blocked for different reasons, the
  reason and next step are row facts and are read in the detail.

Tool detail shows, for one exact revision: owner, requesting Agents, permission
class, integration, bound connection, observed Identity, Registry resource,
Gateway destination, Model Armor coverage, region, lifecycle, availability,
evidence and last probe, deployment, probe expiry, call budget, timeout,
payload ceiling, last call status, trace link, reason, and next step. Each
status value is rendered beside the definition of its dimension, so the
vocabulary in §10.1 is learned where it is used and no separate legend card is
required. Detail additionally shows the schema hashes, profile membership,
resolution/provenance chain, recent redacted calls, evaluation, supersession,
and health history. It never renders credentials, raw prompts, raw tool output,
or chain-of-thought.

The Fleet surface is governance and inspection. Connection creation, secret
rotation, OAuth enrollment, and provider-specific setup remain under
`Settings → Integrations`. The tool detail may deep-link there with the exact
missing grant. Target v1 is read-only; enabling, disabling, approving, or
editing tools requires a separately specified role and immutable change
workflow.

### 10.1 Status vocabulary

The UI does not use unexplained labels such as `ADAPTED` or `PROMOTED` for tool
health.

| Dimension | Values | Meaning |
|---|---|---|
| lifecycle | Draft, Approved, Deprecated, Retired | whether this revision may enter new runs |
| availability | Available, Not configured, Unavailable, Degraded, Disabled | whether it can be selected in this exact scope now |
| evidence | Not probed, Probe passed, Probe failed, Probe stale | freshness of observed capability evidence |
| deployment | Implemented, Deployed, Release-qualified | code, cloud presence, and release proof remain distinct |

`Not configured` and `Unavailable` are separate values because they are separate
facts. A revision with no capability probe in this scope has never been
connected; a revision whose probe ran and did not pass, or has expired, has been
observed to fail. Both deny selection identically — the gate is one boolean over
lifecycle and probe freshness, and neither value weakens it — but only the
second is a fault. Rendering an unconnected catalog as `Unavailable` reports an
estate that has not been set up as an estate that is broken, and sends an
operator to diagnose 23 failures instead of taking one setup step.

`Not configured` therefore carries a neutral tone; `Unavailable` and `Degraded`
carry a warning tone; `Disabled` carries a danger tone.

Every non-healthy state includes `Why` and `Next step`. Color supplements text
and icon; it never carries meaning alone. Body text uses the normal foreground
token on page/card surfaces. Muted text is reserved for secondary metadata and
must pass the design-system contrast gate.

## 11. Security requirements

1. Registry discovery never grants invocation or tool use.
2. The Gateway option that permits unregistered tools is prohibited.
3. Empty or unparsable profiles deny; `*`, category wildcards, prefix grants,
   and model-authored tool names are invalid.
4. The coordinator persists the exact profile before Runtime dispatch.
5. Agent output cannot add a tool, connection, region, classification, call,
   deadline, or byte budget.
6. Tool inputs are generated from typed stored identifiers and schemas, never
   raw model URLs, SQL, shell, PromQL, log query language, or cloud resource
   names.
7. Connector and MCP responses are untrusted data. They pass size/type,
   classification, redaction, injection, and output-schema validation before
   prompt construction or persistence.
8. Model Armor is applied where the exact protocol operation is supported;
   outage or unsupported coverage does not bypass deterministic validation.
9. Credentials stay in deterministic connector, auth-manager, or
   customer-side boundaries and never enter prompts, tool arguments, traces,
   Cloud SQL, or evidence excerpts.
10. Capability probes are minimal reads, separately budgeted, expiry-bearing,
    and never accepted as incident evidence unless the incident requests and
    records an ordinary bounded read.
11. A stale probe makes the tool unavailable until re-probed; a cached success
    cannot survive identity, connection-epoch, policy, revision, or region
    change.
12. A tool call receipt reports call outcome, not factual truth, root cause,
    mutation effect, service recovery, or case closure.
13. Compute tools are deterministic, method-versioned, and cite their exact
    source evidence; correlation is never rendered as causation.
14. A model-backed Agent cannot receive `MUTATE`, generic shell, arbitrary
   HTTP, generic SQL, unrestricted filesystem, IAM, secret, or deployment
   administration tools.
15. Tool and profile requests always carry an exact configured connection
    instance; provider or environment defaults are prohibited.
16. MCP OAuth uses authorization-code flow with PKCE where supported, binds
    tokens to the verified human or service principal and exact connection,
    requests the protocol resource indicator for the registered MCP resource,
    and never treats OAuth completion as tool authorization. A token without
    the expected issuer, audience/resource, subject, scope, tenant, connection
    epoch, or expiry is refused.
17. Operational guidance is an immutable Registry object under specification
    17. Guidance can narrow or sequence use of the frozen tool set but cannot
    add a revision, connection, permission, call budget, or authority.

## 12. Observability

Every call emits an OTel span with safe attributes:

```text
solvan.tool.key
solvan.tool.version
solvan.tool.profile_key
solvan.tool.profile_version
solvan.agent.key
solvan.agent.revision
solvan.invocation.id
solvan.connection.id
solvan.gateway.decision
solvan.armor.coverage
solvan.tool.status
solvan.tool.request_bytes
solvan.tool.response_bytes
solvan.tool.cache_status
```

Scope identifiers are represented by safe internal references according to
the telemetry classification policy. Arguments, payloads, credentials, PII,
raw prompts/responses, and private reasoning are excluded. The Solvan audit
ledger records the tool-call decision and receipt reference; Agent
Observability provides end-to-end operational traces but is not audit or
workflow authority.

## 13. Invariants

| ID | Invariant |
|---|---|
| INV-GT-01 | Every model-backed Registry entry has an Agent display name and a stable machine key. |
| INV-GT-02 | Agent role names never grant dispatch authority; only the coordinator creates and dispatches durable Agent runs. |
| INV-GT-03 | Every usable tool resolves to one approved immutable revision. |
| INV-GT-04 | Every run persists an exact approved profile and effective set hash before dispatch. |
| INV-GT-05 | No wildcard, category, prefix, discovered-only, or model-authored tool grant is executable. |
| INV-GT-06 | An unregistered destination or tool is denied even if Gateway can be configured otherwise. |
| INV-GT-07 | Tool use requires matching agent, identity, Gateway, connection, capability, region, classification, network, and application policy. |
| INV-GT-08 | A stale or absent capability probe denies selection. |
| INV-GT-09 | A model-backed Agent never receives a `MUTATE` tool. |
| INV-GT-10 | Tool inputs contain only typed stored identifiers and bounded parameters. |
| INV-GT-11 | Tool results are untrusted until bounded validation, classification, redaction, and schema checks pass. |
| INV-GT-12 | Tool success cannot confirm root cause, action effect, recovery, resolution, or closure. |
| INV-GT-13 | Compute tools are deterministic, method-versioned, and provenance-bearing. |
| INV-GT-14 | GitHub credentials never enter a model or workspace process. |
| INV-GT-15 | Slack credentials and delivery authority never enter an Agent process. |
| INV-GT-16 | A GKE read profile contains no exec, secret body, port-forward, or mutation capability. |
| INV-GT-17 | AWS capability creates no new actuation authority. |
| INV-GT-18 | Memory recall and conversation cannot add, widen, or re-enable a tool. |
| INV-GT-19 | OTel tool spans exclude credentials, raw payloads, PII, prompts, responses, and private reasoning. |
| INV-GT-20 | Retired revisions remain resolvable for historical run and audit interpretation. |
| INV-GT-21 | Every call resolves one explicit configured connection instance; no runtime default supplies project, account, region, cluster, namespace, repository, or workspace. |
| INV-GT-22 | Tool metadata defines testable use, anti-use, evidence, retrieval, no-data, and failure semantics without becoming authorization. |
| INV-GT-23 | An MCP OAuth token is principal-, connection-, resource-, scope-, epoch-, and expiry-bound; OAuth success does not grant catalog or profile permission. |
| INV-GT-24 | Guidance cannot widen the exact approved profile or effective tool-set hash. |

## 14. Acceptance fixtures

The implementation phase must bind every invariant above and include at least:

1. Registry search finds a tool; invocation without profile is denied.
2. Gateway is configured to allow unregistered MCP; Solvan still denies it.
3. A model emits a plausible new tool name; schema validation refuses it.
4. A profile contains `*`; manifest validation refuses deployment.
5. Connection probe expired one second ago; coordinator refuses dispatch.
6. Connection epoch changes after plan acceptance; profile is reconciled and
   the stale attempt cannot call.
7. Wrong Agent Identity calls a registered tool; Gateway/application deny and
   emit one security event.
8. Tool response contains prompt injection; it is withheld or typed/redacted
   before prompt construction and investigation degrades safely.
9. Model Armor is unavailable; deterministic validation still blocks an
   invalid payload.
10. Compute correlation is high; UI labels it correlation and root cause stays
    unconfirmed.
11. Tool returns over byte ceiling; response is rejected and only a safe hash
    and error class persist.
12. Retry repeats identical normalized call; budget request count increments
    and no duplicate evidence item is created.
13. GitHub read targets an unbound repository or SHA; provider refuses.
14. Workspace asks for network or GitHub token; request schema has no such
    field and provider identity lacks it.
15. Slack event has valid signature but replayed event ID; no second Liaison
    turn or delivery occurs.
16. Slack text says “approve”; only a console deep link renders and no approval
    record is created.
17. GKE profile attempts `kubectl exec`; the catalog revision cannot be
    approved.
18. Tool is deprecated after a run starts; the historical run remains
    interpretable and a new run cannot select it.
19. Tool call span contains a canary secret/PII value; telemetry test fails.
20. Agent Runtime restarts; the durable run resumes with the same profile hash
    or creates a fenced new attempt after reconciliation.
21. Two provider instances are configured and a request omits
    `connection_id`; dispatch is refused instead of selecting either default.
22. A tool is called for a declared anti-use case or with an unsupported
    retrieval control; profile evaluation fails and the connector is not
    invoked.
23. An empty connector result is returned for each `no_data_semantics` value;
    the application produces the registered meaning and the model cannot
    relabel it.
24. MCP OAuth succeeds for the wrong resource indicator, principal, tenant,
    connection epoch, or scope; tool invocation is denied and no token detail
    enters logs, traces, prompts, or evidence.
25. A fetched guidance revision names a tool absent from the frozen profile;
    the step is blocked and the effective tool-set hash is unchanged.
26. A model-backed Agent profile contains a `MUTATE` tool; catalog/profile
    validation refuses the revision before any run can bind it.
27. An Agent or workspace process environment contains a GitHub credential
    canary; the isolation test fails and no provider request is dispatched.
28. An Agent process environment contains a Slack credential or delivery
    authority canary; the isolation test fails and no Liaison delivery occurs.

## 15. Sequencing

1. Freeze this contract and its supporting tool study; no runtime change.
2. Add manifest `display_name`, `registry_kind`, and `execution_role`; render
   Agent names using the canonical `*-agent` keys with no legacy aliases.
3. Add target DDL, repositories, catalog/profile validators, and read APIs.
4. Render the read-only Fleet `Tools` tab with definitions and remediation
   guidance.
5. Implement deterministic metric/log compute tools and Managed Prometheus for
   Ruhu; qualify with synthetic evidence.
6. Implement Asset Inventory, revision comparison, GitHub reads, and Cloud
   Build history; enrich the pinned workspace snapshot.
7. Complete specification 14 channel infrastructure and then the Slack adapter.
8. Add GKE and AWS profiles only with a named adoption contract and their own
   identity, residency, threat, and evaluation evidence.

## 16. Non-goals

- matching a competitor's numerical tool count;
- one Investigation Agent with every tool;
- direct agent-to-agent invocation or model-selected delegation;
- a vendor-specific Agent for every connector;
- generic infrastructure administration;
- console editing of raw policy, schemas, credentials, or tool JSON;
- automatic enablement after Registry or MCP discovery;
- treating Agent Observability traces as private reasoning-chain disclosure;
- expanding the competition release gate.
