# Code Repair Workspace profile and skills

Status: production-target contract; implementation pending. This is the
production design and qualification bar, not a demo-only or competition-only
variant.

Related: [workspace cognition](12-workspace-cognition-architecture.md),
[data/API](04-data-event-api.md), [security](05-security-governance.md),
[code-change delivery](07-implementation-deployment.md), [acceptance](08-test-evaluation-acceptance.md),
[Tool Catalog](16-governed-tool-catalog.md), and
[operational guidance](17-governed-operational-guidance.md).

## 1. Purpose and authority split

This contract makes a Workspace Agent useful for a production repair without
making it a repository administrator, release engineer, or production actor.
It defines the complete proposal-side tool profile and skills for this path:

```text
curated evidence + pinned repository snapshot
  → investigate and edit a disposable candidate tree
  → bounded exploratory test runs
  → content-addressed Patch Proposal
  → independent adjudication
  → Code Change Coordinator / GitHub Provider / human decisions
  → Deployment Controller / independent Release Verifier
```

The Workspace Agent owns only the middle three proposal-side activities. The
Coordinator owns durable request creation and dispatch. The independent
adjudication service owns the accepted test result. The GitHub Provider owns
the GitHub App installation token and repository operations. A human owns every
positive decision. The Deployment Controller owns rollout and rollback. The
Release Verifier owns the signed effect result. No component can substitute its
own result for another component's authority.

The profile is therefore deliberately **not** a collection of GitHub write,
deployment, approval, or rollback tools. Those are private deterministic
service contracts in specifications 04 and 07, not model-facing capabilities.

## 2. Preconditions and immutable repair input

The Code Change Coordinator may reserve this profile only after it has created
one immutable repair-plan input containing all of the following:

- exact reliability case and incident anchors;
- reader-filtered, classified evidence references and hypothesis constraints;
- one active repository binding, repository node, frozen base commit and tree;
- a content-addressed repository snapshot containing only the approved path
  allowlist and explicit read manifest;
- one ordered `test_command_catalog` whose commands were registered with the
  repository binding and independently evaluated as safe for the no-egress
  sandbox;
- exact allowed create/replace/delete path policy, maximum candidate files and
  bytes, and prohibited file/object classes;
- profile revision, tool revisions, data-classification ceiling, task budget,
  provider eligibility, and workspace region/placement decision;
- selected guidance revisions and their hashes, if any, under §5.

The snapshot is a read-only artifact, not a Git checkout. It contains no
credential, `.git` directory, private key, unbounded history, symlink,
submodule, device, socket, FIFO, or special file. The Coordinator materializes
literal regular-file bytes from its manifest with checkout filters disabled.
Paths use the same NFC, bytewise, case-collision, and regular-file rules as
specification 04 §5.1. A new base, snapshot, path policy, profile, guidance
selection, classification, or placement creates a new repair plan/run. Every
new plan materialises and freezes its own command catalog; a retry never
silently adopts changed material.

Registered test-command **definitions** are immutable and safety-evaluated at
repository-binding scope:

```text
id, repository_binding_id, command_kind, argv_json,
working_directory, declared_inputs_json/hash, declared_outputs_json/hash,
timeout_ms, cpu_millis, memory_mib, output_byte_limit, network_mode,
catalog_hash, lifecycle
```

`command_kind` is closed to `REPRODUCTION` and `REGRESSION`. `argv_json` is a
non-empty array of literal arguments; shell parsing, `sh -c`, `bash -c`,
PowerShell command strings, environment-variable expansion, command
substitution, redirects, pipes, backgrounding, and caller-supplied arguments
are invalid. The selected working directory and declared inputs must be inside
the snapshot/candidate root. `network_mode` is exactly `NONE`. Each command is
identified by `(repository_binding_id, command_hash)`; it cannot be inherited
merely because its display text looks similar.

A `repair_plan_command_catalogs` row is a plan-local materialisation of one
registered definition. Its `base_tree_hash` records the exact base against
which its declared input selectors were resolved; it is not an independent
command-registration authority. A successor plan re-materialises the same
registered definition IDs against its own newly frozen base and writes a new
catalog hash. It refuses the command when its working directory or declared
input selectors no longer resolve inside that successor snapshot. It never
copies a prior plan-local row, rewrites its base hash, or accepts a command
that merely has matching display text or argv.

The target data model also adds:

```text
repair_plan_command_catalogs:
id, repair_plan_id/version, command_ordinal, command_definition_id/hash,
base_tree_hash, argv_json, working_directory, declared_inputs_hash,
resolved_inputs_json/hash,
timeout_ms, cpu_millis, memory_mib, output_byte_limit, network_mode, status

workspace_candidate_generations:
id, repair_plan_id/version, agent_run_id, parent_generation_id,
generation_ordinal, base_tree_hash, changed_paths_hash, candidate_tree_hash,
candidate_manifest_ref/hash, aggregate_bytes, file_count, input_hash,
created_at

exploratory_sandbox_receipts:
id, agent_run_id, candidate_generation_id, command_id/hash, sandbox_image_hash,
request_hash, exit_code, stdout_ref/hash, stderr_ref/hash, output_bytes,
trust_class, started_at, completed_at
```

The executable target tables, named database constraints, and append-only
triggers are normative in
[`code-change-release-schema.target.sql`](artifacts/code-change-release-schema.target.sql);
the private delivery envelope is normative in
[`code-change-release-private-api.md`](artifacts/code-change-release-private-api.md).
Neither artifact is a migration or evidence of an implemented Workspace path.

The catalog, generations, and receipts are scope-keyed immutable rows. A unique
`(agent_run_id, generation_ordinal)` and expected-parent-generation CAS prevent
concurrent candidate writers from silently forking one attempt. Sandbox receipt
identity is unique over `(agent_run_id, candidate_generation_id, command_hash,
request_hash)`; duplicate delivery returns the same receipt and a changed
request hash refuses. Only `trust_class=EXPERIMENTAL` is legal in this table.

## 3. `workspace.code-repair.v1` capability profile

The only model-facing profile for this workflow is
`workspace.code-repair.v1`. It is an immutable `ToolProfileRevision` under
specification 16. Its `allowed_agent_key` is exactly `workspace-agent`; the
Antigravity synthetic provider may use a separately evaluated synthetic-only
successor, never this production/private profile. It has no connection-bound
tool: the Coordinator has already materialized the exact snapshot and evidence.
There is no implicit repository, cloud project, branch, region, account,
network destination, or sandbox command.

| Tool revision | Class | Maximum per run | Purpose |
|---|---:|---:|---|
| `workspace.code-repair.read-artifact@1` | `READ` | 64 calls | Read one manifest-listed immutable input or same-run candidate artifact in bounded slices. |
| `workspace.code-repair.write-candidate-artifact@1` | `PROPOSE` | 32 calls | Create, replace, or delete one regular candidate file under the frozen allowlist. |
| `workspace.code-repair.run-in-sandbox@1` | `COMPUTE` | 8 calls | Run one Coordinator-selected catalog command against a declared candidate manifest in an isolated no-egress sandbox. |

The profile has `maximum_total_calls=104`, `maximum_parallel_calls=1`,
`maximum_read_window_ms=0`, `maximum_aggregate_evidence_bytes=1_048_576`, and
one `COMPUTE_ONLY` requirement for each ordered tool. It also has a task-owned
total sandbox wall-clock ceiling of 600 seconds and a maximum candidate tree
size of 1 MiB across at most 128 regular files. A call cannot override these
ceilings.
Every tool response is bounded and content-addressed; tool success is a receipt
only and never proof of root cause, patch correctness, GitHub eligibility,
review, merge, deployment, recovery, or closure.

The Coordinator persists the exact profile material hash, ordered effective
tool-set hash, repair-plan hash, selected-guidance-set hash, command-catalog
hash, and budget hash before dispatch. Runtime, tool adapter, Gateway, and
sandbox compare all of them. An empty subset, a tool from another profile, an
extra revision, or changed order refuses the run.

### 3.1 `workspace.code-repair.read-artifact@1`

Input is closed to:

```json
{
  "schema_version": 1,
  "artifact_handle": "opaque same-run manifest handle",
  "offset_bytes": 0,
  "limit_bytes": 65536
}
```

`artifact_handle` must resolve to an input listed in the frozen snapshot/evidence
manifest or to a candidate artifact created by the same run. It is never a path,
URL, repository name, Git object ID, GCS URI, connection ID, or another run's
handle. `offset_bytes` and `limit_bytes` select an in-range literal byte slice;
the service rejects unlisted, stale, cross-run, cross-case, binary-unsafe, or
oversized reads. The output carries the immutable artifact hash, total size,
slice offset/length, media type, and bounded UTF-8-safe content or a typed
binary refusal. It does not expose a credential, hidden repository content, or
filesystem metadata.

`max_input_bytes` is 256 bytes and `max_output_bytes` is 65,536 bytes. A slice
larger than that output ceiling is rejected rather than truncated without an
explicit next call. Read receipt budget is charged by returned bytes, not by a
model-provided size claim.

### 3.2 `workspace.code-repair.write-candidate-artifact@1`

Input is closed to:

```json
{
  "schema_version": 1,
  "operation": "CREATE | REPLACE | DELETE",
  "relative_path": "NFC relative POSIX path",
  "expected_prior_hash": "sha256:... | null",
  "content_utf8": "required for CREATE or REPLACE; absent for DELETE"
}
```

The adapter verifies the exact run, candidate generation, path allowlist,
regular-file rules, UTF-8/NFC/path constraints, per-file and aggregate byte
ceilings, and expected prior hash. `CREATE` requires absence, `REPLACE` requires
the named base-or-candidate hash, and `DELETE` requires an existing permitted
regular file. It refuses modes, ownership, links, binary content, renames,
copies, paths outside the allowlist, `.git` content, tool/configuration
manifests, any CI/workflow definition, IAM, deployment-manifest, credential,
or policy path regardless of path-policy content, and writes after budget or
generation expiry. It returns only a new opaque
candidate handle and hash. The candidate tree is disposable and cannot become a
repository branch or patch artifact by this call.

`max_input_bytes` is 65,536 bytes, including UTF-8 content, and the maximum
single file size is 65,280 bytes. `max_output_bytes` is 1,024 bytes. The
adapter atomically writes a new candidate generation and receipt or neither;
there is no mutable current-tree file that a later call can overwrite outside
the expected-prior-hash transition.

### 3.3 `workspace.code-repair.run-in-sandbox@1`

Input is closed to:

```json
{
  "schema_version": 1,
  "test_command_id": "one frozen catalog entry",
  "candidate_tree_hash": "sha256:..."
}
```

The adapter derives the sandbox kind from its authenticated caller. A Workspace
call is always `EXPLORATORY`; request fields cannot name `ADJUDICATION`, an
image, runtime, command, argument, environment variable, network destination,
mount, identity, region, or timeout. The sandbox reconstructs the exact base
snapshot plus candidate tree in a fresh disposable root, applies only the
registered literal `argv`, has no network, metadata service, cloud credential,
host mount, shared cache, or writable output except its bounded receipt, and
enforces the catalog and run CPU/memory/wall-clock/output ceilings. Its output
contains exit status, bounded normalized stdout/stderr, command-catalog hash,
base/candidate hashes, image digest, and receipt hash marked `EXPERIMENTAL`.

`max_input_bytes` is 256 bytes and `max_output_bytes` is 131,072 bytes, shared
equally between normalized stdout and stderr. A catalog entry may lower but
never raise the per-run 120-second wall-clock, 1 vCPU, and 1 GiB memory ceiling;
the profile's 600-second aggregate ceiling remains outside the command's
control.

Only the Coordinator may later request an `ADJUDICATION` sandbox run, with the
submitted canonical patch transform and declared command reloaded from durable
records. It uses a new root and different authenticated identity. The Workspace
cannot request, observe, modify, or supply that result. An exploratory success
can help the model decide what to propose; it cannot satisfy a patch artifact's
test outcome or any release condition.

### 3.4 Invocation, identity, and failure contract

The three tools are private Workspace-provider custom tools, not public API
routes. Before provider dispatch, the Coordinator persists an invocation record
whose request ID, Workspace generation, provider revision/boot proof,
repair-plan/profile/effective-set/guidance-set/command-catalog/budget hashes,
and deadline are all content-bound. The provider accepts only that exact
Coordinator-authenticated invocation. Each tool call carries the opaque
provider request ID and an incrementing call ordinal; the adapter derives the
run, scope, candidate generation, budget, and Workspace identity from durable
state, never from model tool arguments.

The adapters return only closed result codes:

```text
ARTIFACT_HANDLE_INVALID | ARTIFACT_SCOPE_DENIED | ARTIFACT_SLICE_INVALID |
CANDIDATE_PATH_DENIED | CANDIDATE_CONFLICT | CANDIDATE_BUDGET_EXHAUSTED |
COMMAND_NOT_CATALOGED | CANDIDATE_TREE_INVALID | SANDBOX_BUDGET_EXHAUSTED |
SANDBOX_UNAVAILABLE | REQUEST_STALE | PROFILE_MISMATCH |
GUIDANCE_SET_MISMATCH | POLICY_DENIED
```

An unavailable sandbox, expired lease, stale generation, malformed output, or
exhausted budget terminates the attempt with a bounded insufficiency/block
record; it never retries through another identity, changes a command or ceiling,
or converts an exploratory result into adjudication. Tool receipts and candidate
generation transitions use expected generation/ordinal CAS plus idempotency
keys. A restarted provider may reconcile a receipt by its durable request hash
but may not invoke the sandbox or create a candidate generation again unless
the matching idempotency contract proves the repeat is the same effect.

## 4. Patch Proposal and CI-failure input

On normal completion the Workspace returns one typed `RemediationPlan` with at
most one `PATCH` step. The step references the candidate-tree hash, frozen base
commit/tree, exact reproduction and regression command IDs, exploratory receipt
hashes, evidence citations, changed-path list, uncertainty, residual risks,
and a short mechanism hypothesis. It contains no GitHub branch, PR number,
reviewer, approval, release, deployment, rollback, or verification field.

The Coordinator derives the canonical patch transform from the candidate tree
and frozen base; it does not accept a raw model diff as authoritative. It then
performs the independent adjudication required by specifications 04 and 12.
Only a passing independent result may create a Code Change Request.

When GitHub CI later fails, the GitHub Provider first records a bounded,
normalized `CI_FAILURE_EVIDENCE` artifact: exact PR/head/base/tree/check-run
identifier, check conclusion, approved annotation excerpts, and GitHub receipt
hash. The Coordinator may create a **new** repair-plan successor whose inputs
include that artifact and whose base/head/tree are re-frozen. It never resumes
the prior workspace under a changed PR or exposes raw GitHub payloads. Failed
CI therefore creates a new proposal attempt, not a model-controlled retry or a
way to alter an approved merge decision.

## 5. Governed skills and selection lifecycle

Two first-party skills are required before this profile may be production
eligible. They are ordinary `GuidanceRevision` records with
`guidance_kind=SKILL`; they undergo the full import/compile/evaluate/independent
approval lifecycle of specifications 17 and 18. Their text is untrusted data
and can sequence or narrow an already frozen profile only.

| Skill key | Eligible agent/profile | Purpose | Explicit anti-use |
|---|---|---|---|
| `reliability.code-repair` | `workspace-agent` / `workspace.code-repair.v1` | Inspect cited evidence and snapshot; minimize a candidate change; run registered reproduction/regression commands; return an evidence-backed Patch Proposal or insufficient-evidence result. | No GitHub operation, approval, deployment, rollback, production check, secret request, arbitrary command, external network, tool/profile/budget selection, or claim of verified recovery. |
| `reliability.ci-failure-triage` | `workspace-agent` / `workspace.code-repair.v1`, only on a successor plan containing `CI_FAILURE_EVIDENCE` | Classify the bounded CI failure, compare it with the frozen patch/base/tree, and prepare a revised candidate or a bounded human question. | No rerun of CI, PR alteration, branch retargeting, check override, reviewer selection, merge, deployment, rollback, or use on a plan without the exact CI evidence. |

There is intentionally no Workspace “merge skill,” “deployment skill,” or
“rollback skill.” The console derives a release-decision brief from immutable
templates and records; the Deployment Controller derives rollout/rollback
material; and the Release Verifier computes health/effect receipts. These are
deterministic application functions, not skill content and not model work.

### 5.1 Required skill step graphs

`reliability.code-repair@1` has the following closed ordered graph. Each
predicate is an application-owned, versioned function over durable records;
none accepts model narration as an input.

| Ordinal | Step | Permitted tools | Completion predicate |
|---:|---|---|---|
| 1 | Establish bounded repair inputs | `workspace.code-repair.read-artifact` | `repair-input-manifest-valid@1`: exact plan/profile/snapshot/command/guidance hashes are bound. |
| 2 | Inspect cited mechanism and source | `workspace.code-repair.read-artifact` | `repair-evidence-cited@1`: all required evidence and source handles were read or a typed no-data result was recorded. |
| 3 | Reproduce with the registered baseline command | `workspace.code-repair.run-in-sandbox` | `exploratory-baseline-recorded@1`: an experimental receipt for the frozen reproduction command exists; it does not label the hypothesis true. |
| 4 | Build a minimal candidate | `workspace.code-repair.read-artifact`, `workspace.code-repair.write-candidate-artifact` | `candidate-generation-recorded@1`: one legal generation with changed-path and tree hashes exists. |
| 5 | Run the registered regression command | `workspace.code-repair.run-in-sandbox` | `exploratory-regression-recorded@1`: an experimental receipt is bound to that candidate/command; it does not label the patch passed. |
| 6 | Submit a Patch Proposal or insufficiency | none | `patch-proposal-complete@1` or `repair-insufficient-evidence@1`: all required hashes/citations/uncertainty fields validate. |

`reliability.ci-failure-triage@1` has a closed graph of: validate the bounded
`CI_FAILURE_EVIDENCE` artifact; inspect the frozen check/head/base/tree and
approved annotation excerpts; classify the failure using an enumerated taxonomy;
then either emit `repair-insufficient-evidence@1` or create a legal candidate
and experimental receipt under the successor plan. Its first predicate,
`ci-failure-evidence-valid@1`, rejects absent provider receipt, changed
repository/PR/head/base/tree/check identity, raw webhook payload, or an attempt
to use the skill outside a successor plan.

**Publication status: the CI skill is not published.** Its classification step
would be completable only by a durable classification record, and no such
record exists in the schema; a runtime evaluator can never honestly satisfy
`ci-failure-classified@1`. The release loader therefore excludes the pack and
its two predicates rather than approving steps that could only verdict ERROR.
The skill returns when a durable, schema-enforced classification record exists
for the evaluator to check. Neither skill has a predicate named
“root cause confirmed,” “tests passed,” “PR approved,” “merged,” “deployed,” or
“recovered.”

The existing `agent_run`-anchored selection ordering is superseded for this
profile only. The target data model adds one selection-set authority and its
immutable ordered members:

```text
repair_plan_guidance_selection_sets:
id, repair_plan_id/version, selection_set_hash, status, created_at,
superseded_at, superseded_reason, bound_agent_run_id, bound_at

repair_plan_guidance_selections:
id, selection_set_id, selection_ordinal, guidance_key, guidance_version,
guidance_content_hash, guidance_revision_hash, profile_material_hash,
selection_reason, selected_by_kind, selected_by_identity,
selected_at
```

The Coordinator creates this append-only selection set in the same serializable
transaction that reserves the repair plan but before creating `agent_run`.
Candidate filtering is deterministic across scope, incident class, purpose,
classification, placement region, exact agent, and exact profile. The base
`reliability.code-repair` skill is required; `reliability.ci-failure-triage` is
eligible only under the preceding CI-failure rule. A model may rank a server
shortlist but cannot name a new skill or version. `NO_GUIDANCE_MATCH` is not a
legal outcome for this profile: a shortlist without the required base skill
refuses dispatch. The set has exactly the required base skill and at most one
supporting CI skill.

The Coordinator persists the exact selected revisions and set hash, then fetches
and re-scans their content, materializes it read-only under `guidance/`, and
only then creates the immutable run request whose hash binds that set. A fetch,
scan, lifecycle, profile, role, connection, or policy failure refuses dispatch;
it does not drop guidance, substitute an older revision, or create an unskilled
run. `repair_plan_guidance_selection_sets.status` is closed to `PENDING_BIND`,
`BOUND`, and `SUPERSEDED`. Exactly one `PENDING_BIND` or `BOUND` set may exist
for a repair-plan version; members are unique by `(selection_set_id,
selection_ordinal)` and one member set has one exact hash. `bound_agent_run_id`
is null only in `PENDING_BIND`, non-null only in `BOUND`, and is written once in
the transaction creating the run.

A transient fetch or scanner outage leaves the same `PENDING_BIND` set
retryable with the same hashes. Any changed eligibility/material, explicit
abandonment, or failed dispatch that needs different material atomically marks
the set `SUPERSEDED` with a closed reason and creates a successor repair plan;
the old plan cannot receive another set. Guidance cannot alter the command
catalog, path policy, snapshot, selected tools, effective set, model budget,
sandbox limits, or authority.

## 6. Human and deterministic surfaces

The authenticated console is the only human-control surface. Chat within that
console may display the proposal, exploratory receipts, independent
adjudication, GitHub checks, and deterministic approval cards from durable
records. Slack, email, Discord, and MCP display status and safe deep links only.
Neither a Workspace skill nor chat text can create an approval, code-change
decision, GitHub identity link, PR, merge, deployment, rollback, or verifier
receipt.

The required deterministic service contracts are:

| Service | Receives | May do | Cannot do |
|---|---|---|---|
| Code Change Coordinator | accepted patch/adjudication records and human decision digests | create/advance the durable Code Change Request and invoke private services | hold a GitHub token, deploy SDK, or approve on a human's behalf |
| GitHub Provider | exact Coordinator command and active repository binding | create/sync/merge the exact governed PR and re-read GitHub state | accept model/browser/channel commands or user OAuth tokens |
| GitHub Identity Broker | authenticated console OAuth-link transaction | prove a person's immutable GitHub account identity | repository mutation, deployment, or model dispatch |
| Deployment Controller | immutable release candidate, reservation, policy, decision digest | bounded canary/promotion/approved rollback | GitHub operations, human approval, or self-verification |
| Release Verifier | frozen profile and fresh scoped observations | write the signed effect receipt | deploy, roll back, merge, approve, or promote itself |

## 7. Security invariants

1. `workspace.code-repair.v1` contains exactly the three listed tool revisions;
   no model-facing successor is selected by name, category, or discovery.
2. Repository and production evidence reach the Workspace only through its
   frozen artifact manifest. It has no repository/network/cloud credential.
3. Candidate writes are confined to the frozen path policy and candidate tree;
   they cannot mutate a checkout, Git object, CI definition, deployment input,
   or another workspace.
4. Exploratory command execution is a catalog ID over literal argv in a
   disposable no-egress sandbox. It is not arbitrary shell execution.
5. Exploratory receipts are always `EXPERIMENTAL`. Only a separate
   Coordinator-requested adjudication result can support a Code Change Request.
6. A skill is selected before the run request, content-hash-bound to it, and
   cannot be dropped or changed during a retry.
7. Skills, repository text, CI annotations, evidence, model output, and sandbox
   output are untrusted and cannot widen tools, paths, commands, budgets,
   classification, region, identity, approval, repository, or mutation scope.
8. A CI failure creates a new bounded plan with a new base/head/tree and never
   mutates an approved request or merges a changed head.
9. No Workspace outcome confirms root cause, test pass, review, merge,
   deployment, recovery, rollback, verification, incident resolution, or case
   closure.
10. Audit/OTel records hashes, closed outcome codes, safe identifiers, budgets,
    and trace/correlation IDs only; they exclude source files, candidate bytes,
    command output, guidance bodies, OAuth material, credentials, PII, prompts,
    responses, and private reasoning.

## 8. Acceptance and qualification

The implementation is not production eligible until every case in
[`code-repair-workspace-acceptance.yaml`](artifacts/code-repair-workspace-acceptance.yaml)
passes with deployed receipts from the Workspace Provider, Sandbox,
Coordinator, GitHub Provider where applicable, and the governed guidance
services. A unit test, model evaluation, or console screenshot alone is not
qualification evidence.

## 9. Implementation order

1. Add target DDL and strict validators for repair-plan guidance selections,
   command catalogs, candidate-artifact generations, and receipt envelopes.
2. Implement the three Tool Catalog revisions and the frozen profile/effective
   set binder; qualify all profile/path/budget denials.
3. Add the private Workspace-to-Sandbox route and exploratory-run accounting;
   retain identity-derived run-kind enforcement.
4. Implement the pre-run guidance-selection anchor and create/evaluate/approve
   the two first-party skills.
5. Implement canonical candidate-tree-to-patch transformation and independent
   adjudication handoff.
6. Add normalized CI-failure ingestion and successor-plan creation.
7. Pass every CRW acceptance case and then integrate its passing Patch Proposal
   into the separately qualified CCR release lifecycle.

## 10. Non-goals

- arbitrary shell, Python, Node, package-manager, or cloud CLI execution;
- generic Git client, branch, push, PR, review, merge, workflow, or webhook
  access in the Workspace;
- editing deployment manifests, IAM, credentials, policy, or release workflow
  files unless a separately approved future path policy and threat model allow
  one exact file class;
- agent approval, deployment, rollback, verification, closure, or promotion;
- automatic production rollback after an exploratory or verifier failure;
- using a skill, channel message, GitHub login, or sandbox success as authority.
