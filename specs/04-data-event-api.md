# Solvan domain, data, event, tool, and API specification

Status: required competition-release contract
Related: [runtime](03-agent-model-runtime.md), [security](05-security-governance.md), [acceptance](08-test-evaluation-acceptance.md), [governed Tool Catalog](16-governed-tool-catalog.md), [SaaS scale and isolation](19-saas-scale-and-isolation.md), [production environment model](20-production-environment-model.md)

## 1. Contract rules

- externally visible schemas carry `schema_version`;
- identifiers are opaque ULID-backed strings with type prefixes;
- timestamps are RFC 3339 UTC; UI renders the operator's explicit timezone;
- percentages are decimal ratios in storage and APIs (`0.01`, not `1%`);
- durations are integer milliseconds or ISO 8601 where stated;
- unknown enum values fail control-path validation;
- immutable records are superseded, never updated in place;
- every request carries correlation, actor, organization, project, and
  environment scope.

The required release schema remains single-cell. Specification 19 is the
target authority for tenant placement, cell routing, admission, usage,
production event sequencing, and lifecycle records; none is added to
`schema.sql` by this cross-reference.

## 2. State models

The loadable files
[incident-transitions.yaml](artifacts/incident-transitions.yaml) and
[reliability-case-transitions.yaml](artifacts/reliability-case-transitions.yaml)
are the sole legal-transition source for application code, diagrams, and tests.
They enumerate events, guards, terminal absorption, cancellation, early-state
failure escalation, stale-progress escalation, `REPAIR_IN_PROGRESS -> BLOCKED`,
and rollback/re-entry paths.

`MITIGATED -> RESOLVED` is legal only when policy says no permanent repair is
required or the linked Reliability Case is `CLOSED_VERIFIED`. A recurrence
creates a new incident and `case_incidents` link in the same transaction as
`REOPENED`. A cancellation received while a connector request is in flight is
recorded as intent; reconciliation completes before a terminal transition.
Cancelling a case is rejected while a linked incident is in an active state
other than `MITIGATED`. Cancelling a case linked to a `MITIGATED` incident
atomically emits `CASE_TERMINATED_WITHOUT_REPAIR`, moving that incident to
`ESCALATED` so residual risk always has an owner.

The two-hour incident stale policy does not apply to `MITIGATED` while its
linked non-terminal case has a due wake-up. Reliability Cases instead require
`next_action_at` plus an active scheduled wake-up in operational states, or
`blocked_owner`, `next_review_at`, and an active wake-up in `BLOCKED`. Missing
or repeatedly failed wake-ups create visible recovery work and cannot leave a
case silently dormant.

## 3. Core tables

[schema.sql](artifacts/schema.sql) is the authoritative PostgreSQL 16 DDL.
[concurrency.sql](artifacts/concurrency.sql) is the normative lease, CAS,
reservation, outbox-claim, and reaper reference. The prose below is an index,
not a second schema source; CI applies the DDL from empty and compares generated
models/migrations against it.

All scoped tables include `organization_id`, `project_id`, and `environment_id`
unless explicitly global. Primary/unique keys include scope where necessary.

### `incidents`

```text
id, display_id, scope, workflow_version, evidence_version,
state_machine_version, state, severity,
recurrence_of, reliability_case_id, detected_at, updated_at,
detection_rule_id, detection_rule_version, production_graph_snapshot_id,
deduplication_key, action_attempt_count, action_budget,
repeated_action_limit, cooldown_until, last_action_signature,
suspected_root_cause_id, confirmed_root_cause_id, terminal_reason,
lease_owner, lease_token, lease_expires_at, audit_stream_id
```

Only a non-terminal incident is unique on `(scope, deduplication_key)` through a
partial index. A terminal incident therefore does not block recurrence.
`deduplication_key` is `{rule_id}:{service_id}:{deduplication_dimension}` and
never includes an event timestamp. Workflow update requires the expected
workflow version plus the current lease owner, token, and unexpired lease; it
increments exactly once.

### `reliability_cases`

```text
id, scope, workflow_version, evidence_version, state_machine_version, state,
originating_incident_id, next_action_kind, next_action_at, blocked_owner,
next_review_at, recovery_plan, terminal_reason, lease_owner, lease_token,
lease_expires_at, audit_stream_id, created_at, updated_at
```

### `case_incidents`

Append-only `(case_id, incident_id, relationship, linked_at)` where relationship
is `ORIGINATING` or `RECURRENCE`. A partial unique index permits exactly one
`ORIGINATING` row per case. In the case-creation transaction, that row must
match both `reliability_cases.originating_incident_id` and the incident's
`reliability_case_id`; contract tests reject projection drift.

### `state_transitions`

Append-only:

```text
id, entity_type, entity_id, from_state, to_state, from_workflow_version,
to_workflow_version, transition_key, actor_type, actor_id, policy_decision_id,
reason_code, rationale_summary, evidence_refs_json, occurred_at, trace_id
```

Unique: `(entity_type, entity_id, transition_key)`.

### `inbox_events`

```text
id, source, source_event_id, event_type, payload_ref, payload_hash,
received_at, attempts, processing_state, claimed_at, claim_owner, claim_token,
claim_expires_at, processed_at, result_ref, error_class
```

Unique: `(source, source_event_id)`.

Every claim consumes one unit of the bounded `attempts` budget. An event that
exhausts the budget without completing — a handler that crashes on it every
time — is quarantined durably to `FAILED` with
`error_class = 'POISON_EVENT_QUARANTINED'` before the next claim and is never
claimed again, so one poison event cannot crash-loop a coordinator or consume a
claim slot forever. Recovery is an explicit re-ingest under a new source event
ID; the quarantined row is preserved as the record of the failure.

### `outbox_events`

```text
id, aggregate_type, aggregate_id, aggregate_version, topic, event_type,
payload_json, idempotency_key, created_at, publish_attempts, claimed_at,
claim_owner, claim_token, claim_expires_at, published_at, quarantined_at
```

Unique: `idempotency_key`.

Every claim consumes one unit of the bounded `publish_attempts` budget. An
unpublishable row that exhausts the budget is parked with `quarantined_at` and
never claimed again; a row is either published or quarantined, never both. The
outbox publish budget is deliberately larger than the inbox claim budget so a
broker outage ends with delayed publication, not mass quarantine. Recovery is
an explicit superseding operator action.

### `scheduled_wakeups`

```text
id, case_id, logical_step_key, wake_at, reason, status, claimed_at,
claim_owner, claim_token, claim_expires_at, completed_at, outbox_event_id
```

Unique active `(case_id, logical_step_key)`.

### `agent_runs`

```text
id, exactly one of incident_id/reliability_case_id/workspace_id/target alert_episode_id,
investigation_step_id, logical_step_key, agent_key,
agent_resource, agent_revision,
session_id, invocation_id, runtime_operation_name, runtime_input_ref,
runtime_output_ref, workspace_id/generation/task_kind,
provider_request_id/hash, provider_boot_hash, provider_service_revision,
effective_tool_set_hash, effective_network_policy_hash,
workflow_version, attempt, status, deadline,
budget_json, input_ref, input_hash, output_ref, output_hash, error_class,
started_at, completed_at, trace_id, span_id
```

Unique `(logical_step_key, attempt)`; only one non-terminal attempt per logical
step. The required MSR `WorkspaceAgent` repair attempt remains Reliability-
Case-scoped and binds its immutable repair plan. When the optional logical-
workspace path is enabled, the run is workspace-scoped instead and all
workspace request, generation, tool, and network-policy fields become required.
The target Alert Triage migration adds `alert_episode_id` as a fourth anchor.
It replaces the named `agent_runs_one_anchor_ck` constraint with the same
exactly-one rule across all four anchors and adds a restrictive composite
foreign key to the immutable scoped Alert episode. This permits pre-Incident
read-only triage without creating a placeholder Incident or a second Agent-run
state machine; it is target-only until Alert Triage is promoted.

For institutional incident runs, nullable `runtime_operation_name`,
`runtime_input_ref`, and `runtime_output_ref` also represent a partial provider
receipt while status remains `CREATED`. Returned fields are immutable once
non-null. A deadline-expired `CREATED` run is compare-and-set to `DISPATCHED`
only when a recoverable provider operation/output receipt is adopted; otherwise
it is compare-and-set to `TIMED_OUT` with
`DISPATCH_RECEIPT_INCOMPLETE` or `DISPATCH_ACCEPTANCE_UNKNOWN`. `TIMED_OUT`
means Solvan refuses that attempt's future result; it does not assert that the
provider job is terminal. Execution and Verification attempts are single-shot;
the Supervisor alone may create attempt 2 within its existing immutable replan
budget.

### `workspaces` and `workspace_checkpoints` — optional demo seam

Status: target. The canonical schema includes these dormant tables so the
optional Antigravity demonstration can be genuine; their behavior does not
block the MSR gate when the provider flag is disabled.

```text
workspaces:
id, kind, service_id, reliability_case_id, generation, provider,
implementation_sdk/version, provider_revision, registry_agent_key,
provider_agent_resource, classification, synthetic,
provider_service_identity, implementation_sdk_distribution_hash,
provider_artifact_digest, effective_network_policy_hash,
synthetic_attestation_ref/hash, provider_eligibility_decision_id,
artifact_prefix, input_manifest_ref/hash, status,
created_by_principal, created_at, updated_at

workspace_checkpoints:
id, workspace_id, workspace_generation, sequence_no, event_kind,
parent_checkpoint_id, provider, implementation_sdk/version, provider_revision,
implementation_sdk_distribution_hash, provider_artifact_digest,
provider_request_hash, provider_receipt_ref/hash, provider_boot_hash,
provider_service_revision,
input_manifest_ref/hash, artifact_manifest_ref/hash, effective_tool_set_hash,
effective_network_policy_hash,
created_by_principal, created_at
```

`workspaces` is mutable only through generation-fenced coordinator transactions;
`workspace_checkpoints` is append-only. Before any provider call the coordinator
inserts an `agent_runs` row containing the exact request, SDK-distribution,
provider-image, tool-policy, network-policy, generation, and deadline hashes. A response is accepted only for that
run and records the service revision and process boot hash. `CHECKPOINT` records
the resulting terminal manifest; `REHYDRATION` references its parent and proves
the same input, artifact, SDK-distribution, provider-image, tool, and network-policy hashes after a provider
process restart with a different boot hash. GCS objects use:

```text
gs://{bucket}/workspaces/{organization_id}/{project_id}/{environment_id}/
  {workspace_id}/generations/{generation}/{sha256}/...
```

Both input and checkpoint manifests conform to
`workspace-artifact-manifest.schema.json`; `additionalProperties=false` rejects
uncontracted provider state. The SDK conversation is scoped to one Cloud Run
request and is discarded afterward. No Managed Agents environment ID,
interaction cursor, SDK conversation, or container filesystem is accepted as
durable state.

An Antigravity SDK Cloud Run workspace requires `classification='PUBLIC'`, `synthetic=true`,
a valid fixture-attester reference/hash, and an allowed
`PROVIDER_ELIGIBILITY` decision. Exactly one non-terminal Incident Workspace may
exist per Reliability Case. A checkpoint must match the current workspace
generation and provider identity, and sequence numbers are monotonic per
workspace. A rehydration insert fails unless its parent belongs to that exact
generation, SDK distribution and provider image digests match, all durable
content/policy hashes match, and both the process boot hash and Cloud
Run service revision change. Every checkpoint content-binds the exact provider
receipt. If qualification evidence persistence fails after a rehydration has
committed, a retry loads that receipt by its stored hash and reconciles evidence
without another provider call or revision replacement.

### `repair_plans` and `patch_artifacts`

Permanent repair inputs and sandbox outcomes are immutable, queryable records:

```text
repair_plans:
id, reliability_case_id, plan_version, repository_node_id,
repository_snapshot_uri/hash, base_commit_sha, reproduction_command,
allowed_file_globs_json, test_command, artifact_output_uri,
confirmed_root_cause_id, evidence_refs_json, provider, content_hash, status,
supersedes_id, created_at

patch_artifacts:
id, reliability_case_id, repair_plan_id/version, agent_run_id,
sandbox_resource, base_commit_sha, unified_diff_ref/hash, changed_paths_json,
cognition_ref/hash, mechanism, hypotheses_json, reproduction_command,
reproduction_exit_code, reproduction_output_ref/hash, test_command,
test_exit_code, test_output_ref/hash, residual_risks_json,
provider, status, created_at
```

Only one repair plan is `ACTIVE` per case. `AWAITING_REVIEW` requires a
`TESTS_PASSED` patch artifact bound to the exact active plan, commit,
WorkspaceAgent attempt, typed proposed-cognition artifact, deterministic
baseline reproduction, test command, and Agent Engine sandbox resource.
`TESTS_PASSED` requires the unpatched reproduction to fail and the patched
regression to pass. Runtime output alone is never a cognition, patch,
reproduction, or test receipt.

`patch_reviews` records one exact, authenticated decision per patch artifact:
the patch/test digest, reviewer principal, `APPROVE` or `CHANGES_REQUESTED`,
reason, idempotency request ID, decision time, and coordinator application time.
The API records review intent but cannot move the case; the coordinator applies
the decision under a Reliability Case lease and retires the exact wake-up.

One logical Incident Workspace may author the investigation mechanism,
competing hypotheses, reproduction, patch, and regression test. The durable
agent run and cognition artifact bind the workspace ID, generation,
input-manifest hash, confirmed fast-lane cause, and immutable source citations.
The patch reviewer cannot
share the authoring workspace identity, provider process, or conversation.
Production verification remains bound to `verification_runs` and cannot consume
a workspace's `PREVALIDATE` result as a success verdict.

The target Code Repair Workspace profile adds the immutable, pre-run
`repair_plan_guidance_selections`, command-catalog, candidate-generation, and
exploratory-sandbox-receipt records defined in specification 23 §§2–5. They are
not columns silently added to the current `repair_plans` row and are not part of
the release schema. One `repair_plan_guidance_selection_set` is created before
the corresponding `agent_run`, then binds that one run exactly once; its ordered
members reference the precise repair-plan version, guidance revision/content
hash, profile material hash, selection-set hash, and selection reason. Its
closed `PENDING_BIND`/`BOUND`/`SUPERSEDED` lifecycle and uniqueness are defined
in specification 23 §5. The command catalog and candidate generation bind their
exact plan/base tree/path policy/budget generation. All are immutable or
append-only projections with scope-keyed foreign keys; changing any input
requires a successor plan.

### `investigation_plans` and `investigation_steps`

Accepted Supervisor plans are immutable versions:

```text
investigation_plans:
id, incident_id, plan_version, objective, completion_condition,
uncertainties_json, content_hash, status, created_by_agent_run_id,
supersedes_id, created_at

investigation_steps:
id, plan_id, step_key, ordinal, kind, agent_key, agent_resource,
agent_revision, current_agent_run_id, allowed_tool_names_json, scope_ref, purpose,
required, depends_on_json, budget_json, status, result_ref,
evidence_delta_count, fallback_ref, retry_not_before, started_at, completed_at
```

A dispatch failure that returns a step to `READY` for its declared fallback
records `retry_not_before`; reservation never dispatches the step earlier. The
deferral is a durable column, not process state, so it holds across coordinator
restarts and across every claimant.

Only the coordinator updates step projection state. A plan is never edited;
replanning inserts a higher version and marks the prior plan `SUPERSEDED`.
`depends_on_json` must reference step keys in the same plan and pass DAG
validation before commit. These tables support operator explanation and restart
recovery; they do not store private model reasoning.

The resolved immutable agent resource and revision are frozen into each agent
step when the plan is accepted. `current_agent_run_id` makes the active attempt
queryable; older attempts remain in `agent_runs`. This prevents a mutable
Registry alias from changing the meaning of an already accepted plan.

## 4. Evidence and hypothesis tables

### `evidence_items`

```text
id, scope, incident_id, source_kind, source_resource, query_spec_json,
window_start, window_end, observed_at, ingested_at, content_ref, content_hash,
classification, residency, armor_verdict_id, redaction_manifest_ref,
provenance_json, freshness_expires_at, created_by_agent_run_id
```

Payloads live in a regional Cloud Storage evidence bucket. Database projections
contain bounded redacted excerpts only.

### `tool_calls`

```text
id, agent_run_id, invocation_id, tool_name, arguments_hash, status,
request_count, evidence_item_id, error_class, created_at, last_requested_at,
completed_at
```

One row represents one normalized provider call per run, tool, and argument
digest. `request_count` increments for every broker request, including a cache
hit, and is checked against the immutable run budget while the run row is
locked. This preserves provider-call idempotency without allowing a repeated
cached request to create an unbounded agent loop.

### `hypotheses`

```text
id, incident_id, statement, normalized_cause_key, revision, status,
supporting_evidence_refs, contradicting_evidence_refs, confidence_score,
confirmation_rule_id, confirmation_rule_version, confirmed_at, supersedes_id,
created_by_run_id
```

Status: `PROPOSED`, `SUPPORTED`, `CONTRADICTED`, `CONFIRMED`, `REJECTED`.
Only deterministic confirmation policy may set `CONFIRMED`. One immutable,
non-forking revision chain exists per incident and normalized cause key.

### `findings` and `finding_evidence`

Committed agent findings are immutable queryable projections rather than
opaque `agent_runs.output_ref` blobs:

```text
findings:
id, incident_id, agent_run_id, finding_key, revision,
kind OBSERVATION|INFERENCE, statement, confidence_score, content_hash,
supersedes_id, created_at

finding_evidence:
finding_id, evidence_id, relationship SUPPORTS|CONTRADICTS, cited_at
```

The join table uses foreign keys to both records, making a rendered citation
that resolves to no evidence row structurally impossible. Revisions form a
single immutable chain per incident and finding key.

## 4A. Production Graph tables

`production_graph_snapshots` is the approved, versioned graph authority.
`production_graph_nodes` stores typed service, deployment, database, queue,
repository, owner, SLO, synthetic-check, agent, tool, and verification-profile
facts. `production_graph_edges` stores the relationship vocabulary from
specification 02, including distinct `DEPENDS_ON_DECLARED` and
`DEPENDS_ON_OBSERVED` evidence classes rather than collapsing them into one
edge. A node whose authoritative classification is not yet known stores
`NULL`; every filtered retrieval treats that node as ineligible instead of
guessing a classification. Nodes and edges are immutable within a snapshot and
carry source provenance; an incident freezes the exact snapshot it used.

## 5. Action, approval, and reservation tables

### `actions`

```text
id, display_id, incident_id xor reliability_case_id, workflow_version,
evidence_version, action_type,
normalized_signature, target_key,
expected_target_version, expected_target_epoch, payload_json, payload_digest,
expected_effect_json, expected_effect_hash,
risk_class, reversible, rollback_plan_json,
verification_profile_id/version, policy_decision_id, proposer_principal,
standing_preauthorization_id/version,
requires_approval, status, idempotency_key, expires_at, created_at
```

Status: `PROPOSED`, `AWAITING_APPROVAL`, `AUTHORIZED`, `EXECUTING`,
`RECONCILING`, `SUCCEEDED`, `FAILED`, `AMBIGUOUS`, `INVALIDATED`, `CANCELLED`.

`DRY_RUN_MISMATCH` is an additional terminal no-mutation refusal state. The
expected-effect descriptor is derived only by the typed application action
factory and stored canonically with its `sha256:` hash before authorization.
`AuthorizedActionMaterial` recomputes the action-type-specific descriptor from
the typed payload, target key, and expected target version and refuses any row
whose descriptor or hash differs. The approval digest binds the hash.

The two initial closed descriptors are:

```text
payments-pool-recycle.v1:
  schema_version, profile, action_type, target_key, from_pool_generation,
  operation {admin_operation, drain_timeout_ms}

cloud-run-traffic-replacement.v1:
  schema_version, profile, action_type, target_key, from_revision,
  service_name, traffic [{revision, percent}]
```

Neither descriptor includes a model-authored expected effect. Adding or
changing a profile requires a specification, connector revision, schema
constraint, approval-digest regression test, and mismatch fixture.

### `policy_decisions`

Append-only input hashes, rule IDs/version, deterministic result, semantic-
governance advisory verdict if enabled, rationale code, and timestamp. Generic
`input_ref`, `receipt_ref`, and `receipt_hash` columns bind consequential policy
decisions to immutable objects.

`policy_kind=PROVIDER_ELIGIBILITY` is decided before provider upload or mount.
Its canonical input covers workspace/task/generation, classification,
synthetic-attestation reference/hash, artifact-manifest reference/hash,
required/provider location, provider and revision, implementation SDK version
and signed distribution hash, Cloud Run service identity and image digest,
hosting control/data planes, provider-policy revision, and complete tool/network
policy hashes. This prevents a Managed Agents REST call or generic model client
from satisfying an Antigravity SDK decision. The receipt uses
`provider-eligibility-receipt.schema.json`; both `ALLOW` and `DENY` are stored.

### `approvals`

```text
id, action_id, sequence_no, action_digest, target_key, expected_target_version,
expected_target_epoch, evidence_version, policy_version, approver_principal,
decision, reason, decided_at, expires_at, supersedes_id
```

Approval rows are immutable. Revocation creates a superseding decision. Each
action has one root and a non-forking successor chain; the actuator locks the
action and resolves the unique leaf before authorization.

### 5.1 Governed code-change records — `implemented`; production qualification pending

Code delivery is a different mutation domain from an operational action. It
does **not** reuse `actions`, `approvals`, `target_reservations`, or the Action
Actuator dispatch tables. Those records are intentionally typed around closed
operational action descriptors; allowing a patch, pull request, or deployment
to masquerade as one would bypass their meaning and make the actuator a general
release engine.

The delivery migrations add the following append-only authority spine to the
authoritative deployment sequence. A row or local schema load alone is not
evidence that the complete deployed lifecycle ran.
`created_by_principal` is the verified human principal that explicitly started
the code-change request, never the coordinator service identity, Workspace
identity, GitHub App, channel account, or model output.

The executable target DDL, named constraints, uniqueness rules, and
append-only triggers are normative in
[`code-change-release-schema.target.sql`](artifacts/code-change-release-schema.target.sql).
Forward migrations through
[`code-change-release-schema.target.v19.sql`](artifacts/code-change-release-schema.target.v19.sql)
add governed delivery profiles, reviewer identity, provider-qualified request
creation, exact Cloud Run target observation, independent signed health
baselines, stage-bound release verification, failure registration, and
independently verified rollback finalization, plus terminal post-issue rollout
ambiguity. Local schema and service tests are implementation evidence;
they are not a deployed production qualification receipt.
Its negative-oracle companion is
[`code-change-release-schema-contract-tests.sql`](artifacts/code-change-release-schema-contract-tests.sql).
The non-owner runtime database-role matrix is normative in
[`code-change-release-database-authority.md`](artifacts/code-change-release-database-authority.md).
Those files are checksum-bound migrations and contracts; they are not evidence
that a particular customer target was deployed or qualified.

```text
code_change_requests:
id, qualification_receipt_id, code_delivery_profile_id,
reliability_case_id, patch_artifact_id, patch_digest,
patch_transform_version, patch_transform_ref/hash, proposed_tree_hash,
repository_binding_id, repository_policy_hash, default_branch,
base_commit_sha, base_tree_hash, allowed_paths_hash,
adjudication_receipt_ref/hash, required_checks_policy_ref/hash,
required_check_definition_paths_hash, base_required_check_definitions_ref/hash,
reviewer_policy_ref/hash, pr_creation_policy_ref/hash, merge_policy_ref/hash,
deployment_policy_ref/hash, immutable_request_hash, expires_at,
created_by_principal, created_at

code_change_qualification_intents:
id, reliability_case_id, patch_artifact_id, candidate_generation_id,
code_delivery_profile_id, repository_binding_id,
adjudication_receipt_ref/hash, request_hash, requested_by_principal,
expires_at, created_at

code_change_qualification_receipts:
id, qualification_intent_id, outcome/reason_code, repository_binding_id,
code_delivery_profile_id/hash, default_branch, base_commit_sha,
base_tree_ref/hash, patch_transform_version/ref/hash, proposed_tree_hash,
base_required_check_definitions_ref/hash, attributes_evaluation_ref/hash,
provider_observation_ref/hash, provider_service_revision, observed_at

code_change_transitions:
id, code_change_request_id, sequence_no, from_state, to_state,
expected_sequence_no, input_hash, idempotency_key, actor_kind, actor_identity,
receipt_ref/hash, decision_id/digest, occurred_at

code_change_decisions:
id, code_change_request_id, stage, sequence_no, decision_digest,
principal, github_reviewer_binding_id, github_review_state_hash,
decision, reason, authorization_snapshot_hash, step_up_receipt_hash,
decision_request_id, authenticated_session_hash, authenticated_at,
authorization_snapshot_ref, step_up_receipt_ref, decided_at, expires_at,
supersedes_id

code_change_decision_challenges:
id, code_change_request_id, stage, principal, decision_digest,
material_ref/hash, authorization_snapshot_ref/hash,
authenticated_session_hash, authenticated_at, expires_at, status,
decision_id, created_at, consumed_at

code_delivery_profiles:
id, repository_binding_id, profile_version, maximum_request_lifetime_minutes,
allowed_paths_json/hash,
required_checks_policy_ref/hash, required_check_definition_paths_json/hash,
reviewer_policy_ref/hash, pr_creation_policy_ref/hash, merge_policy_ref/hash,
deployment_policy_ref/hash, profile_hash, approval_ref/hash, status,
activated_at, revoked_at, created_by_principal, created_at

github_reviewer_bindings:
id, repository_binding_id, solvan_principal, github_account_node_id,
github_login, binding_proof_ref/hash, reviewer_policy_hash,
status, expires_at, revoked_at

github_oauth_client_profiles:
id, provider_kind, github_app_client_id, client_secret_ref,
authorization_endpoint, token_endpoint, api_base_url, callback_uri,
protocol_version, token_expiration_required, configuration_hash, status,
activated_at, revoked_at

github_identity_link_transactions:
id, oauth_client_profile_id, repository_binding_id, solvan_principal,
solvan_session_binding_hash, state_hash, pkce_verifier_ciphertext,
pkce_key_version, requested_permission_hash, status, expires_at,
consumed_at, failure_code, created_at

github_reviewer_binding_events:
id, github_reviewer_binding_id, sequence_no, event_kind, actor_kind,
actor_identity, input_hash, receipt_ref/hash, occurred_at

code_change_operations:
id, code_change_request_id, transition_sequence_no, operation_kind,
material_hash, idempotency_key, provider_request_id, worker_lease_token,
status, request_ref/hash, response_ref/hash, error_class,
prepared_at, issued_at, reconciled_at, completed_at

release_candidates:
id, code_change_request_id, repository_binding_id, merged_commit_sha,
source_tree_hash, build_definition_ref/hash, builder_identity,
build_invocation_ref/hash, build_artifact_ref/hash, sbom_ref/hash,
provenance_predicate_type/version/hash, provenance_ref/hash,
release_signature_ref/hash, signer_identity, signer_key_version,
deployment_manifest_ref/hash, release_policy_hash,
candidate_envelope_ref/hash, issued_at, created_at

release_signer_keys:
id, signer_identity, key_version, public_verification_ref,
signer_policy_hash, status, activated_at, revoked_at, revoked_reason

release_verifier_keys:
id, verifier_identity, key_version, public_verification_ref,
verifier_policy_hash, status, activated_at, revoked_at, revoked_reason

release_target_profiles:
id, target_key, provider_kind, service_resource_name, external_project_id,
location, service_name, expected_target_epoch, runtime_service_account,
deployment_manifest_profile_ref/hash, rollout_policy_ref/hash,
canary_percentages, observation_windows_seconds, rollout_deadline_seconds,
maximum_concurrent_rollouts, verification_profile_id/version/ref/hash,
profile_hash, status, approved_by_principal, approved_at,
revoked_at, revoked_reason, verifier_identity, verifier_key_version, created_at

release_target_observations:
id, code_change_request_id, release_candidate_id, release_target_profile_id,
target_key, target_version/epoch, service_generation, service_etag_hash,
runtime_service_account, current_release_candidate_id, current_revision,
assignment_ref/hash, observation_ref/hash, observer identity/revision, observed_at

release_health_baselines:
id, code_change_request_id, release_candidate_id, release_target_profile_id,
target_observation_hash, verification_profile_hash, target_version,
target_assignment_hash, window_start/end, signal_results_hash,
baseline_ref/hash, verifier identity/key version, signature_ref/hash, observed_at

deployment_rollouts:
id, release_candidate_id, target_key, expected_target_version/epoch,
target_reservation_id, rollout_policy_hash, approval_digest,
predeploy_snapshot_ref/hash, predeploy_release_candidate_id,
predeploy_assignment_ref/hash, rollback_release_candidate_id,
rollback_assignment_ref/hash,
release_effect_template_id/version, release_effect_input_refs_hash,
intended_effect_hash, verification_profile_id/version/hash,
release_target_profile_id/hash, predeploy_assignment_hash,
rollback_assignment_hash, release_health_baseline_id/ref/hash, status, created_at

deployment_rollout_operations:
id, deployment_rollout_id, operation_kind, stage_ordinal, material_hash,
idempotency_key, provider_request_id, worker_lease_token, status,
request_ref/hash, response_ref/hash, error_class,
prepared_at, issued_at, reconciled_at, completed_at

release_verification_receipts:
id, deployment_rollout_id, verifier_identity, verification_profile_hash,
predeploy_snapshot_ref/hash, postdeploy_observation_ref/hash,
intended_effect_hash, result, signature_ref/hash, stage_ordinal,
observation_window_generation, window_start/end, observed_target_version,
observed_assignment_hash, verifier_key_version, receipt_envelope_ref/hash,
release_health_baseline_ref/hash, observed_at

release_rollback_verification_receipts:
id, deployment_rollout_id, expected_revision, observed_target_version,
observed_assignment_hash, result, verifier identity/key version,
receipt_envelope_ref/hash, signature_ref/hash, observed_at

release_target_reservations:
id, target_key, expected_target_version/epoch, reservation_material_hash,
status, lease_token, lease_expires_at, held_by_identity, created_at

private_command_dispatches:
id, scope, command_kind, subject_id, material_hash, idempotency_key,
payload_ref/hash, payload_schema_hash, admitted_caller_identity/audience_hash, deadline, status,
response_ref/hash, created_at, completed_at
```

`code_change_requests` and their material fields are immutable. The patch is
not an open-ended Git diff language. The Coordinator first records an immutable
qualification intent over an independently adjudicated candidate. The GitHub
Provider reloads that intent and the active delivery profile, observes the
complete current base tree and repository policy, and derives the canonical
`patch_transform_ref/hash`. A database trigger permits request creation only
when every repository-, transform-, check-, and policy field exactly equals
that qualified receipt and profile; a browser, channel, or model cannot supply
those authority fields. Adjudication and the GitHub Provider execute only the
canonical transform, never the raw diff.
`patch_transform_version` identifies its exact parser/serialization, and
`proposed_tree_hash` is the canonical result of applying it to the frozen
`base_tree_hash`. It admits only declared create, replace, and explicit-delete
operations on regular UTF-8 files under the frozen path allowlist. The importer
rejects symlinks, submodules, hard/special files, mode/ownership changes,
renames, copies, binary patches, path aliases, non-canonical encoding, and Git
object headers such as `old mode`, `new mode`, `new file mode`, `deleted file
mode`, `similarity index`, `rename`, `copy`, `Subproject commit`, and `GIT
binary patch`. The GitHub Provider must produce and re-read exactly that tree
hash; a passing sandbox test of bytes that yield another tree is not eligible
for a request.

The transform is byte-level and deterministic. Paths are NFC-normalised UTF-8
byte sequences, compared byte-wise and case-sensitively; any path containing
NUL, backslash, a leading/trailing slash, `.`/`..` component, or a case-folding
collision with another transformed or relevant base-tree path is refused.
Content is the literal blob byte sequence; no checkout, clean/smudge, EOL, or
working-tree-encoding filter may rewrite it. Adjudication materialises those
bytes directly with `core.autocrlf=false` and attributes disabled, and refuses
a repository whose `.gitattributes` applies `text`, `eol`, `filter`, or
`working-tree-encoding` to an allowed path.

Every resulting tree entry has one specified mode. A create is always regular
blob mode `100644` and is refused if its path already exists in the base tree.
A replacement preserves its base entry's mode only when that mode is `100644`
or `100755`; all other base modes fail `MODE_UNSUPPORTED`. A delete requires an
existing regular base entry. The transform never changes a mode. Thus sandbox
and Provider have neither an ambient umask nor a Git API default to choose.

State is a guarded projection of `code_change_transitions`; a worker cannot
skip a state by updating a status field. Each transition atomically compares
`expected_sequence_no`, assigns the next unique sequence number, and consumes
one `idempotency_key` bound to its input hash. A transition content-binds its
predecessor, repository binding, patch/tree/base lineage, required checks,
policy hashes, and all receipts it relies on. The full target state machine is
specified in specification 07 §8.2.

`code_change_decisions.stage` is closed to `PR_CREATION`, `MERGE`,
`DEPLOYMENT`, and `ROLLBACK`. Each stage has its own non-forking immutable
decision chain and its own digest. A root has sequence one; every later record
names the immediately preceding leaf, and a predecessor may have one successor.
Only a leaf that is `APPROVED` and unexpired is live authorization, so stale
material creates a successor decision rather than mutating the old approval.
`PR_CREATION` binds the exact request,
base/tree, generated branch name, and creation policy. A `MERGE` decision
binds the pull-request number, repository, base and head SHAs, tree/diff hash,
GitHub required-review and branch-protection state, required-check state,
base and current required-check-definition paths/content hashes, active
`github_reviewer_binding`, and expiry. The binding proves the Solvan
approver is the GitHub account whose review satisfies the applicable reviewer
policy; a matching email, login string, channel identity, or a different
reviewer's approval is insufficient. A `DEPLOYMENT` decision binds the release
candidate, exact target version/epoch, rollout policy, pre-deploy health
snapshot, and expiry. A `ROLLBACK` decision binds the failed rollout, fresh
observed target state, frozen prior release/assignment, verification-failure
receipt, rollback policy, and expiry. A changed head, base/tree, diff, check,
branch rule, required-check definition, reviewer binding, release artifact,
target, or policy invalidates the corresponding decision rather than being
silently rechecked under an old approval.

`code_delivery_profiles` is the sole governed source for the policy material
frozen into a new request. An administrator supplies typed policy operands,
not references or digests; the API writes immutable documents, computes their
hashes, and activates one version per repository. The browser, Workspace,
channel, model, and request creator cannot supply or override a policy ref,
hash, required-check definition path, reviewer rule, or deployment target.

The request creator may approve any positive `PR_CREATION`, `MERGE`,
`DEPLOYMENT`, or `ROLLBACK` stage, and one verified principal may approve more
than one stage for the same request. This is intentional: Solvan supports an
authorized single-operator production workflow. Every decision still requires
the live, environment-scoped role for its exact stage, a fresh authenticated
session and step-up confirmation, current material revalidation, immutable
principal attribution, expiry, and an idempotency key. No stage authority is
inferred from request creation, a GitHub account, an earlier decision, or a
role for another stage. The decision service locks the request and decision
chain in one `SERIALIZABLE` transaction before recording the result. GitHub's
review and branch-protection requirements remain independently enforced, but
they are not repurposed as a Solvan same-person prohibition. Reject decisions
remain attributable and never authorize an effect.

#### GitHub reviewer identity linking — `implemented`; production qualification pending

The GitHub App repository installation and a person's GitHub identity are
separate authorities. The existing App installation is the only credential that
the GitHub Provider may use to create, inspect, or merge a pull request. A
GitHub **user-to-server** OAuth ceremony proves which GitHub account is linked
to the already authenticated Solvan person. It never lends that user's token to
the Provider, Workspace, Coordinator, browser, channel adapter, or model. In
particular, a reviewer binding is identity evidence; it is not a personal
access token, a bypass of branch protection, or repository mutation authority.

`github_oauth_client_profiles` is the versioned deployment configuration for
that ceremony. It is closed to `GITHUB_APP_USER_TO_SERVER`; a general OAuth App,
device flow, implicit flow, personal access token, and a browser-supplied client
identifier are not eligible. Exactly one `ACTIVE` profile may serve a scope and
repository binding. Its callback URI is a pre-registered HTTPS URI for that
environment, never a caller-provided or wildcard return URI. `client_secret_ref`
is a pinned Secret Manager version readable only by the GitHub Identity Broker;
the raw client secret is never in Cloud SQL, a browser bundle, logs, traces,
events, a model context, or an API response. The GitHub App must have
user-to-server token expiry enabled. The profile's `configuration_hash` binds
the GitHub App client ID, issuer/API origins, callback URI, token-expiry
posture, and protocol version; changing one creates a new profile and makes
outstanding transactions unusable.

The GitHub Identity Broker is a small deterministic service (it may be a
separately isolated API process) with exactly the client-secret read and the
two GitHub OAuth/API egress destinations required below. It has no GitHub App
private key, installation token, repository mutation method, deployment
credential, Agent Runtime dispatch, model route, or external-channel ingress.
The GitHub Provider has the converse boundary: it holds the App installation
capability but cannot start, consume, refresh, or inspect a user OAuth flow.

The browser flow is closed and server-controlled:

1. From an authenticated Solvan console session, a person selects an active
   repository binding and requests **Connect GitHub identity**. The server
   derives the Solvan principal, scope, exact repository binding, current
   `CODE_CHANGE_APPROVER` role, and a fresh step-up session; none may be sent
   as a body, query, header, chat parameter, or return URL. A binding is not
   created merely because an administrator installed the GitHub App.
2. The Broker creates one `github_identity_link_transaction` with a
   cryptographically random, at-least-256-bit state value and PKCE verifier.
   Only their SHA-256 state digest and a KMS-envelope-encrypted verifier are
   durable. The transaction is bound to the exact Solvan session, principal,
   repository binding, active OAuth-client-profile hash, fixed callback URI,
   and a maximum ten-minute expiry. Its status is `PENDING`; it may become
   exactly one of `CONSUMED`, `EXPIRED`, or `REFUSED`. A host-only, `Secure`,
   `HttpOnly`, `SameSite=Lax`, path-scoped callback cookie carries only an
   opaque transaction handle plus an authenticated MAC. It contains no GitHub
   token, code, principal, redirect target, or authority.
3. The Broker redirects only to the profile's GitHub authorization endpoint
   with its fixed client ID, exact callback URI, opaque state, and
   `code_challenge_method=S256`. It uses the smallest GitHub App
   user-to-server permission set already required by the installed App and
   does not request a broad `repo`, `user`, organization, or email OAuth
   scope. A displayed GitHub login may be a non-authoritative account-picker
   hint only. Device authorization is disabled for this web console flow.
4. The callback accepts only `code`, `state`, and GitHub's documented refusal
   parameters. Before exchanging a code it performs constant-time state and
   callback-cookie verification, resolves the transaction, verifies the
   current Solvan browser session/principal equals the transaction binding,
   verifies expiry/profile/redirect URI, atomically consumes the transaction,
   and rejects every duplicate, missing-cookie, cross-session, cross-scope,
   cross-repository, or callback-error case. It never redirects to a URL from
   the request; success and refusal go only to fixed console routes.
5. Only after those checks, the Broker exchanges the one-time code server-side
   at the configured token endpoint using the pinned client-secret reference
   and the original PKCE verifier. It bounds response size and fields, refuses
   a missing/expired/non-bearer token or token response inconsistent with the
   selected profile's documented protocol, and immediately calls GitHub's
   authenticated current-user endpoint. It records
   GitHub's immutable account node ID as the identity proof. Numeric IDs may
   be retained only as provider reconciliation metadata; login, name, and
   email are display metadata and can never be an authorization key.
6. In the same serializable transaction, the Broker confirms the selected
   repository binding remains active and attached to the exact GitHub App
   installation, freezes the current reviewer-policy hash, writes an immutable
   binding proof digest/receipt, and emits `LINKED`. At most one `ACTIVE`
   binding exists for `(repository_binding_id, solvan_principal)` and at most
   one for `(repository_binding_id, github_account_node_id)`. Re-linking the
   same pair creates a new immutable binding and marks the prior one
   `REPLACED`; linking an account already active for another Solvan principal
   is refused rather than guessing shared ownership.
7. The access token, refresh token, authorization code, PKCE verifier, and
   GitHub token response are erased from process memory as soon as the current
   user response has been verified; the consumed transaction's encrypted PKCE
   verifier is deleted in that same commit. They are never stored, refreshed,
   exposed, handed to the GitHub Provider, or used to act as the user. Solvan retains
   only the immutable account proof, profile/policy hashes, and bounded
   non-secret receipt metadata. Disconnect is a local append-only revocation;
   it removes Solvan's ability to rely on the binding. The person may separately
   revoke the GitHub App authorization in GitHub because Solvan intentionally
   retains no user token with which to revoke it later.

`github_reviewer_bindings` is an immutable base record and
`github_reviewer_binding_events` is its ordered, append-only lifecycle. The
current `status`, `expires_at`, and `revoked_at` are a guarded projection of
the event chain, not fields a worker may edit in place. Status is closed to
`ACTIVE`, `REVALIDATION_REQUIRED`, `EXPIRED`, `REVOKED`, and `REPLACED`; only
`ACTIVE` can satisfy a merge. `LINKED`, `REVALIDATED`, `REVALIDATION_REQUIRED`,
`EXPIRED`, `REVOKED`, and `REPLACED` are the closed event kinds. Role removal or
expiry, repository-binding revocation/degradation, installation suspension or
removal, GitHub authorization/repository-access change, account mismatch,
policy change, explicit disconnect, or proof expiry writes a terminal or
revalidation-required event. A missed webhook is never permission: immediately
before merge, the Provider independently re-reads the active installation,
repository, frozen reviewer/branch policy, required review, and reviewer
account node ID. Any unavailable, changed, ambiguous, or non-`ACTIVE` binding
refuses the merge. Restoring a role, installation, or policy does not revive a
binding; the person completes a new OAuth link.

The public API is deliberately narrow: `POST /github/reviewer-links` starts a
transaction for an opaque repository-binding locator and returns only a
server-generated authorization URL; `GET /github/oauth/callback` is the fixed
browser callback; `GET /github/reviewer-links/me` returns the caller's
redacted binding projections; and `DELETE /github/reviewer-links/{id}` records
the caller's local disconnect after fresh step-up. The API accepts no GitHub
token, OAuth code, state, client secret, GitHub account identifier, reviewer
claim, policy hash, principal, scope, or arbitrary redirect URL from a caller.
Channel adapters expose no link endpoint and no OAuth callback. Every start,
callback outcome, binding event, disconnect, and merge-time revalidation emits
an audit record with correlation ID, principal/service identity, scope,
repository binding, outcome code, and non-secret evidence digest only.

`release_signer_keys` is the registered verification-key authority. Only
`ACTIVE` exact signer/key-version pairs may satisfy a candidate; revocation is
an append-only status transition with reason, never deletion. Deployment reads
current status again at effect time, so a key revoked after signing cannot
deploy a previously valid candidate.

`code_change_operations` and `deployment_rollout_operations` are the durable
external-effect fences. Their key is unique over the scoped request/rollout,
operation kind, stage ordinal where applicable, and material hash. Each writes
`PREPARED` with the exact idempotency key, lease, and request material before
the external call; the atomic `PREPARED → ISSUED` transition is the sole claim
to issue it. A restart after `ISSUED` is reconcile-only: it uses the named
provider's operation-specific authoritative query and either records its exact
receipt or ends `AMBIGUOUS`, never calls again. A second call is possible only
when the provider's separately qualified idempotency contract proves the same
key is safe to replay. `CREATE_BRANCH`, `CREATE_PR`, `MERGE_PR`, `CANARY_STEP`,
`PROMOTE`, and `ROLLBACK` are distinct operation kinds. Operation status is
closed to `PREPARED`, `ISSUED`, `RECONCILING`, `SUCCEEDED`, `REFUSED`,
`AMBIGUOUS`, `EXPIRED`, and `CANCELLED`; no terminal row becomes issuable.

GitHub has no general request-idempotency key for these operations, so its
reconciliation is closed by operation kind. `CREATE_BRANCH` reads the reserved
ref and succeeds only when it names the exact expected commit/tree; a definite
absence after a fresh authenticated GitHub read returns to `PREPARED`, while a
different existing ref is `REF_COLLISION`. `CREATE_PR` queries the reserved
head/base pair and an application-generated immutable operation marker in the
PR body; only that exact tuple succeeds, a definite absence returns to
`PREPARED`, and any other matching head/base is `AMBIGUOUS`. `MERGE_PR` reads
the PR's merged flag and exact merge commit/tree; an open, unmerged PR with the
unchanged approved head/base can return to `PREPARED`, while an unreachable or
contradictory state is `AMBIGUOUS`. GitHub's asynchronous merge UUID may be
stored as `provider_request_id` when that endpoint is selected, but is never
assumed for branch or PR creation.

`release_target_reservations` reserve the deployment target in their own
namespace; they cannot borrow an action reservation. One active reservation and
one active rollout may exist for an exact target at a time, and a rollout's
scoped reservation foreign key binds the target key/version/epoch it observed.
Before a rollout row is created, the controller records the observed current
release candidate and exact target assignment as `predeploy_*`; those immutable
records are also the only possible rollback candidate/assignment. Both candidate
references and both assignment references are required and must agree. An estate
without an independently qualified prior release follows a separate human
bootstrap procedure and cannot create or enter this automated canary path.
`release_verification_receipts` are
written only by the separately identified release verifier and are unique per
rollout attempt. Neither a workspace sandbox receipt nor a deployer result can
promote a rollout. A rejected, expired, unsafe, or ambiguous rollback remains
blocked and escalates to a human recovery procedure; it cannot silently choose
another release or retry an effect.

`intended_effect_hash` is not workspace, model, PR, or reviewer prose. At
`DEPLOYMENT` decision time the application instantiates a release-effect
descriptor from an enumerated, digest-pinned template registry using only the
approved target, release candidate, production-graph records, and declared
rollout policy. Its template id/version, eligible input-reference hash, and
canonical descriptor hash are persisted above. The verifier receives that
frozen descriptor and the selected verification profile; it cannot select a
different profile or redefine success.

### `target_epochs`

One row per target key: `target_key, epoch, last_observed_version, updated_at`.

### `target_reservations`

```text
id, target_key, reservation_epoch, expected_target_epoch, action_id,
owner_identity, lease_token, acquired_at, expires_at, released_at,
release_reason
```

A partial unique index allows one active reservation per target key.

### `execution_receipts`

Append-only:

```text
id, action_id, attempt, connector_request_id, idempotency_key,
before_state_ref, after_state_ref, observed_target_version,
started_at, connector_returned_at, reconciled_at, result,
error_class, actor_identity, trace_id
```

### `actuator_dispatches` and `actuator_effect_receipts`

`actuator_dispatches` is the single action-bound mutation-attempt projection.
It binds the actuator, target reservation, customer policy hash,
expected-effect hash, canonical request hash, worker lease owner/token, optional
connector request ID, and trace. `PREPARED` means the mutation operation has
not been claimed. The atomic transition to `MUTATION_ISSUED` is the one allowed
mutation-call claim; `MUTATION_ISSUED` and `RECONCILING` are reconcile-only
after restart. Terminal states are `EXECUTED`, `AMBIGUOUS`, `REFUSED`,
`DRY_RUN_MISMATCH`, and `EXPIRED`.

`actuator_effect_receipts` is unique on dispatch and stores the pre-state hash,
predicted-effect hash, comparison result, observed-pre-state-derived undo plan,
optional after-state, execution-receipt link, and customer-owned audit
acknowledgement. It extends rather than replaces `execution_receipts`; recovery
never creates an attempt ordinal greater than one for the same action.

The actuator has no optional pre-mutation-gate mode. Human-approved actions
must pass the exact approval and scope gate. Standing-authority actions must
also pass the current Production Graph gate and create the exact
`earned_action_reservations` proof inside a fresh `SERIALIZABLE` transaction.
That transaction re-derives the action-to-preauthorization, pinned graph,
competence, falsification high-water, placement, and latest connector-capacity
binding; a Python boolean or earlier read cannot satisfy it. The proof expires
with the authorized action, not an unrelated worker lease. An exact retry
reuses the immutable proof, while a later action may target the same resource
after the authoritative `target_reservations` fence is released.

Recovery from `PREPARED` reauthorizes the stored action and reruns these gates
before claiming the mutation. Recovery from `MUTATION_ISSUED` or
`RECONCILING` never reruns the mutation. The private HTTP request contains only
the schema version, stored invocation ID, and optional trace ID; the actuator
derives organization/project/environment from the database role's exact
`database_scope_bindings` row. Caller-supplied scope fields are forbidden.

### `standing_preauthorizations` and RBAC

Static competition roles are `OPERATOR`, `APPROVER`, and `ADMIN`, scoped by
organization/project/environment in `actor_role_bindings`. A versioned standing
preauthorization binds one service, incident class, exact action type, maximum
risk, payload constraints, one attempt, cooldown, validity window, and human
owner. The autonomous action must match every field; absence, expiry, revocation,
or mismatch requires approval or denial. The same principal may hold multiple
roles, but an action proposer cannot approve that action unless an explicit
demo policy exception is recorded; the release fixture uses separate people.

### Detection and confirmation policy

`detection_rules` stores the typed monitoring query, incident class, 20–30
second interval, comparator, calibrated threshold, sustained-window count,
severity, deduplication dimension, and action limits. `detection_evaluations`
stores one immutable query receipt and comparison per rule/window, allowing the
sustained-window decision to survive a detector restart. `confirmation_rules`
stores the deterministic evidence
requirements that alone may set a hypothesis to `CONFIRMED`. Both are immutable
versioned policy records once approved.

[release-policy.template.yaml](artifacts/release-policy.template.yaml) is the
single deploy-time shape for RBAC, standing authority, confirmation, and both
detection rules. Deployment replaces calibration/principal placeholders,
changes the template status, validates it, and seeds the corresponding DDL
rows; an unchanged template is rejected.

## 6. Verification tables

### `verification_profiles`

Immutable versioned profile:

```text
id, version, status, owner, warmup_ms, observation_ms,
required_signals_json, guardrails_json, inconclusive_policy,
content_hash, approved_by, approved_at
```

### `verification_profile_bindings`

`production_graph_snapshot_id, service_id, incident_class, profile_id, profile_version,
effective_at, superseded_at, policy_owner`.

### `verification_runs`

```text
id, purpose MITIGATION_ACTION|CASE_OBSERVATION,
incident_id xor reliability_case_id, optional action_id,
profile_id, profile_version, resolved_binding_ref,
window_start, window_end, signal_results_json, synthetic_receipt_ref,
verdict, rationale_codes, agent_run_id, completed_at
```

Verdict is application-calculated.
`MITIGATION_ACTION` requires an incident and action. `CASE_OBSERVATION` requires
a Reliability Case and may retain the triggering rollout action when one
exists; case ownership is never faked through an unrelated incident action.
Resolution requires exactly one live, approved binding for the incident's
Production Graph snapshot, service, and class. Required telemetry samples and
the isolated synthetic receipt must fall inside the observation window.
Missing, stale, contradictory, or insufficient input is `INCONCLUSIVE`; a
complete threshold or synthetic failure is `FAILED`. Connector return status is
not an input to this verdict.

## 7. Memory tables

### `memory_candidates`

```text
id, scope_json, purpose, candidate_type, fact_text, source_refs,
content_hash, source_hashes, confirmation_status, verification_ref,
classification, residency, redaction_manifest_ref, armor_verdict_ref,
provenance_json, policy_version, review_requirement, status,
created_by_principal, created_at, expires_at
```

Status: `PENDING`, `QUARANTINED`, `APPROVED`, `PROMOTING`, `REJECTED`,
`PROMOTED`, `EXPIRED`. `PROMOTING` is a recoverable reconciliation state:
Memory Bank create is not idempotent, so retries first retrieve the exact scope
and match the fact before creating anything missing. Unavailability never
blocks incident or Reliability Case transitions.

### `memory_promotions`

Append-only mapping candidate to Memory Bank resource/revision, exact scope,
promoter identity, decision, promoted content hash, retention, and timestamp.
Human-reviewed promotion records an exact live `ADMIN` role binding and rejects
self-approval. Source correction, supersession, expiry, or purge appends a
`PURGED` decision rather than editing the earlier `PROMOTED` row; provider
deletion is reconciled before the memory can be recalled again.
Recall accepts only the exact organization, project, environment, purpose,
classification, and region scope. Semantic candidates are not accepted from
the ADK `search_memory` projection: the direct platform response must retain
resource name, revision, and distance, and Cloud SQL must resolve each candidate
to one current promotion before it enters context. Every fact remains untrusted
historical context, never execution authority.

`agent_runs.input_context_json` is the durable, typed prompt-context projection.
For Evidence Agent runs it may include the revalidated `memory_recall` envelope.
Any change recalculates `input_hash` while the attempt is still `CREATED`; a
stale attempt cannot attach or replace context.

The target conversational surface does not reuse `agent_runs.input_context_json`
or make ADK Session events authoritative. Its exact per-reader/per-attempt
projection is `liaison_turn_input_manifests`, governed by
[14 §12.1](14-conversational-surface.md) and the closed
[`liaison-turn-input-manifest.schema.json`](artifacts/liaison-turn-input-manifest.schema.json).
The manifest is reference-only; user/transcript/tool/compaction/memory prose
remains in its governed source. Its row digest includes the policy and
membership epochs stored beside the JSON, and each retry appends a new turn
attempt/manifest rather than replacing an earlier one.

## 8. Tool contract

This section is the required competition-release subset. The target immutable
revision, capability-profile, probe, UI, and per-run tool-set resolution model
is governed by specification 16. Discovery never expands this release subset.

```python
class ToolSpec(BaseModel):
    name: str
    version: str
    permission_class: Literal["READ", "COMPUTE", "MUTATE"]
    allowed_agents: list[str]
    input_schema: dict
    output_schema: dict
    timeout_ms: int
    max_output_bytes: int
    idempotency: Literal["NOT_APPLICABLE", "NATIVE", "SOLVAN_RECONCILED"]
    registry_resource: str
    gateway_destination: str
```

Release tools:

| Name | Class | Agent |
|---|---|---|
| `cloud_logging_query` | READ | Evidence |
| `cloud_monitoring_query` | READ | Evidence, Verification |
| `cloud_trace_read` | READ | Evidence |
| `cloud_audit_log_query` | READ | Evidence |
| `error_reporting_query` | READ | Evidence |
| `cloud_run_revision_read` | READ | Infrastructure |
| `cloud_sql_capacity_read` | READ | Infrastructure, Verification |
| `synthetic_payment_run` | READ/COMPUTE | Verification |
| `payments_pool_recycle` | MUTATE | deterministic Action Actuator, requested by Execution Agent |
| `cloud_run_rollback_revision` | MUTATE | deterministic Action Actuator, requested by Execution Agent |
| `repository_snapshot_read` | READ | coordinator-curated Workspace Agent input |
| `sandbox_patch_and_test` | isolated MUTATE | deterministic Workspace Sandbox; never model-facing |

`synthetic_payment_run` performs an application write only within isolated demo
tenant/account rows using a stable idempotency key; it has no customer or
general database scope. Its `READ/COMPUTE` class describes agent authority, not
an assertion that the test transaction is physically read-only.

No generic shell, arbitrary HTTP, generic SQL, IAM, secret read, or filesystem
tool is registered.

## 9. Event contract

```json
{
  "schema_version": 1,
  "event_id": "EVT-01J...",
  "event_type": "incident.action.reconciled",
  "occurred_at": "2026-08-08T13:24:30Z",
  "organization_id": "org-acme",
  "project_id": "checkout-production",
  "environment_id": "prod-europe-west1",
  "aggregate_type": "incident",
  "aggregate_id": "INC-2041",
  "aggregate_version": 19,
  "correlation_id": "COR-01J...",
  "causation_id": "EVT-01J...",
  "payload": {"action_id":"ACT-...","receipt_id":"RCP-..."},
  "trace_id": "0af..."
}
```

Consumers deduplicate by `event_id`. Aggregate version cannot decrease. Events
contain references, not raw evidence or secrets.

## 10. HTTP API

Prefix: `/api/v1`. Browser requests use OIDC-authenticated sessions and CSRF
protection. Machine callbacks use workload identity and signed audience.

### Incidents

```text
GET  /incidents
GET  /incidents/{incident_id}
GET  /incidents/{incident_id}/timeline
GET  /incidents/{incident_id}/evidence
GET  /incidents/{incident_id}/actions
GET  /incidents/{incident_id}/investigation-plan
POST /api/incidents/{incident_id}/cancel
POST /api/incidents/{incident_id}/escalate
```

Mutation requests require `Idempotency-Key` and `If-Match: workflow_version`.

### Actions and approvals

```text
GET  /actions/{action_id}
POST /actions/{action_id}/approve
POST /actions/{action_id}/reject
POST /actions/{action_id}/revoke
```

UI approval never calls a connector synchronously. Execution is not exposed in
the browser API.

Approval request:

```json
{
  "schema_version": 1,
  "action_digest": "sha256:...",
  "expected_workflow_version": 18,
  "decision": "APPROVE",
  "reason": "Rollback is preferred to continued payment failures"
}
```

### Reliability Cases

```text
GET  /reliability-cases
GET  /reliability-cases/{case_id}
GET  /reliability-cases/{case_id}/history
POST /reliability-cases/{case_id}/resume
POST /reliability-cases/{case_id}/assign
POST /reliability-cases/{case_id}/cancel
```

### Fleet and governance projections

```text
GET /api/fleet/agents
GET /api/fleet/agents/{agent_key}
GET /api/fleet/tools
GET /api/fleet/policies
GET /api/fleet/policies/{policy_id}/effective
GET /api/fleet/memory-candidates
GET /api/fleet/memory-candidates/{candidate_id}
GET /api/fleet/security-events
GET /api/fleet/audit-events
GET /api/fleet/traces/{trace_id}/link
```

These are read projections over Registry/IAM/Gateway/Armor/OTel plus the release
manifest. The browser never receives credentials or unrestricted cloud APIs.
List responses contain bounded summaries and references, never raw evidence,
memory text above the caller's classification, or unrestricted tool payloads.
Audit export and manual memory-candidate review are post-MSR targets; the release
surface is read-only.

### Internal event/callback endpoints

```text
POST /internal/events/monitoring
POST /internal/events/runtime-result
POST /internal/actions/{action_id}/execute
POST /internal/reconcile/actions/{action_id}
POST /internal/wakeups/dispatch

# coordinator-only GitHub release seam
POST /internal/v1/github/repositories:probe
POST /internal/v1/github/pull-requests
POST /internal/v1/github/pull-requests/{pull_request_id}:sync
POST /internal/v1/github/pull-requests/{pull_request_id}:merge

# GitHub App ingress (HMAC, not browser/API bearer auth)
POST /internal/github/webhooks
```

Every callback verifies issuer, audience, replay window, source event ID, and
payload schema before durable acceptance.

GitHub is a release-provider integration, not an agent or generic repository
shell. A release-admin job registers a scoped `github_repositories` binding in
`PENDING` state using only Secret Manager version references. The provider's
coordinator-authenticated probe promotes it to `ACTIVE`; a failed probe makes
it `DEGRADED`. Webhooks accept only `X-Hub-Signature-256`, deduplicate the
GitHub delivery ID, and persist bounded pull-request/check projections.

The branch-commit mechanism below describes the current narrow GitHub seam
only: repository CI publishes the candidate `solvan/...` branch and Solvan
reads it before opening a pull request. It is not the governed code-change
profile and cannot satisfy specification 07 §8.2. That target profile instead
uses the strict shared transform and deterministic Provider-created branch
defined in specification 04 §5.1; it must not silently fall back to this
current mechanism.

In the current seam, Solvan does not push arbitrary files or execute `git` on
behalf of a model. Its CI publisher is forbidden from using the target-reserved
`solvan/ccr/` prefix. Before opening a pull request, the provider reads the
exact non-target `solvan/...` branch ref and requires its head SHA to equal the
typed patch command. Create, sync, and merge operations are idempotent and receipt-backed.
Merge requires an active allowlist, `TESTS_PASSED` patch artifact, exact
`APPROVE` patch review and digest, current head SHA, and all required checks
passing. No browser, agent, or GitHub webhook can invoke merge authority.

## 11. Error contract

```json
{
  "error": {
    "code": "TARGET_VERSION_CHANGED",
    "message": "The production target changed; review a new action proposal.",
    "correlation_id": "COR-01J...",
    "retryable": false,
    "details": {"action_id":"ACT-..."}
  }
}
```

Stable codes include `REVISION_CONFLICT`, `LEASE_LOST`, `TARGET_RESERVED`,
`TARGET_VERSION_CHANGED`, `APPROVAL_REQUIRED`, `APPROVAL_EXPIRED`,
`POLICY_DENIED`, `GATEWAY_DENIED`, `ARMOR_BLOCKED`, `BUDGET_EXHAUSTED`,
`AMBIGUOUS_EFFECT`, `VERIFICATION_INCONCLUSIVE`, `SCOPE_DENIED`, and
`REGION_DENIED`.

## 12. Retention and deletion

Default synthetic release policy:

| Data | Retention | Deletion behavior |
|---|---:|---|
| incident/case/audit metadata | 90 days | scheduled purge after submission need |
| redacted evidence payloads | 30 days | object delete + tombstone reference |
| raw synthetic telemetry | 7 days | native logging/monitoring retention |
| prompts/responses | disabled by default | none stored |
| trace spans | 30 days | Cloud Trace retention policy |
| Memory Bank items | 30 days | scoped purge and promotion tombstone |
| approvals/receipts | 90 days | immutable until retention expiry |

Enterprise deployments make policy configurable, but deletion must purge
derived memories and payloads while retaining only legally permitted audit
metadata.
