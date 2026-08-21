# Code-change and release private command contract

Status: implemented contract; deployed production qualification pending. This document is authoritative for the internal
commands between the Coordinator, Workspace tool adapters, GitHub Provider,
GitHub Identity Broker, Deployment Controller, and Release Verifier. It is not
a public HTTP API and no channel, browser, or model invokes these commands.

Related: [data/API](../04-data-event-api.md), [deployment](../07-implementation-deployment.md),
[Workspace profile](../23-code-repair-workspace-profile.md), and
[acceptance](code-change-release-acceptance.yaml).

## 1. Common envelope

Every private request and response is a versioned JSON object. Transport is an
internal Cloud Run URL protected by IAM audience and an allowlisted caller
workload identity. The receiver derives the caller from the verified identity
token. Tenant scope, authority, target, run kind, subject, material hash,
idempotency key, and deadline come only from the durable Coordinator-created
command record identified by `command_id`; none is accepted from request JSON.
`payload_schema_hash` must equal the receiver's closed, versioned schema hash
for the stored command kind; it is not a caller-selected compatibility marker.

```json
{
  "schema_version": 1,
  "command_id": "cmd_...",
  "payload": {}
}
```

`command_id` is globally unique and resolves one immutable row containing
`scope`, `command_kind`, `subject_id`, `material_hash`, `idempotency_key`,
`deadline`, admitted caller identity/audience, and immutable payload reference,
payload hash, and payload schema hash. The
Coordinator writes that row and its durable `PREPARED` operation before
delivery. A receiver loads it by `command_id`, verifies its own authenticated
identity/audience, and then loads the typed subject under the stored scope. A
duplicate exact command returns its original response; a changed command hash,
payload, audience, caller, scope, or deadline refuses before any external call.

Every response is either:

```json
{
  "schema_version": 1,
  "command_id": "cmd_...",
  "outcome": "ACCEPTED | REFUSED | AMBIGUOUS | RETRYABLE",
  "reason_code": "CLOSED_UPPER_SNAKE_CASE",
  "receipt_ref": "opaque immutable reference",
  "receipt_hash": "sha256:...",
  "observed_at": "RFC3339 UTC timestamp"
}
```

or a transport-level authentication failure that reveals no subject material.
`ACCEPTED` never means the requested real-world effect succeeded; the specific
command contract states the subsequent authoritative observation required.
`RETRYABLE` is legal only before an external effect is issued. After issue, a
worker reconciles or returns `AMBIGUOUS`; it never guesses that a command was
safe to repeat.

## 2. Command registry

| Command | Caller → receiver | Required durable material | Accepted result | Receiver cannot do |
|---|---|---|---|---|
| `WORKSPACE_TOOL_INVOKE` | Coordinator → Workspace tool adapter | run request, profile/effective-set, guidance-set, command catalog and budget hashes | one bounded tool receipt | select a tool, command, identity, region, or ceiling |
| `EXPLORATORY_SANDBOX_RUN` | Workspace adapter → Sandbox | exact invocation record, frozen command ID, candidate tree hash | `EXPERIMENTAL` receipt only | adjudicate, create a patch outcome, use network/credentials |
| `ADJUDICATE_PATCH` | Coordinator → Sandbox | canonical transform, base tree, exact registered command definitions | independent patch-test receipt | accept Workspace exploratory output as result |
| `QUALIFY_CODE_CHANGE` | Coordinator → GitHub Provider | immutable qualification intent, candidate generation, active delivery profile, adjudication receipt | provider-observed base tree, policy, attributes, check-definition, and canonical-transform receipt | accept repository, ref, path, policy, transform, or credential from the request |
| `CREATE_PR`, `SYNC_PR`, `MERGE_PR` | Coordinator → GitHub Provider | active CCR, exact decision digest where required, repository/policy/tree hashes | Provider GitHub receipt | accept browser/channel/model/user-token input |
| `START_GITHUB_LINK`, `CONSUME_GITHUB_CALLBACK`, `REVOKE_GITHUB_LINK` | Console API → Identity Broker | authenticated session/step-up and link transaction | binding lifecycle receipt | mutate a repository or use an installation token |
| `START_ROLLOUT`, `PREPARE_CANARY`, `PROMOTE_CANARY`, `FINALIZE_ROLLOUT` | Coordinator → Deployment Controller | exact deployment decision and target observation for start; rollout, reservation, candidate/provenance, signed prior-stage receipt, target and policy hashes for effects | rollout creation, stage operation, or terminal promotion receipt | merge code, approve, or verify itself |
| `REGISTER_VERIFICATION_FAILURE`, `ROLLBACK_RELEASE`, `FINALIZE_ROLLBACK` | Coordinator → Deployment Controller | signed failed/inconclusive release receipt; then exact rollback decision, frozen prior revision/assignment and current target; finally signed rollback-verification receipt | failure registration, rollback effect, or terminal rollback receipt | infer a prior release, approve, or verify itself |
| `OBSERVE_RELEASE_BASELINE`, `VERIFY_RELEASE_EFFECT`, `VERIFY_ROLLBACK_EFFECT` | Coordinator → Release Verifier | exact target observation and frozen profile for baseline; rollout baseline, intended-effect hash, stage and observation generation for effects; frozen prior revision for rollback | signed baseline, stage receipt, or rollback-verification receipt | deploy, roll back, merge, approve, or promote |

No command has a generic `operation`, `url`, `repository`, `shell`, `headers`,
`identity`, `role`, `region`, `network`, `timeout`, `policy`, `tool`, `scope`,
`subject`, or free-form payload field. Each receiver reloads the typed durable
subject under the command record's scope and reconstructs its provider request
from that row.

## 3. Exact command payloads

### 3.1 Workspace and sandbox

`WORKSPACE_TOOL_INVOKE.subject_id` is an `agent_run`. Its payload contains only
`tool_revision`, `call_ordinal`, and `tool_input`. `tool_input` is exactly the
closed input object defined for that revision in specification 23 §3; it is not
merged into the envelope and it cannot contain caller, scope, command, region,
identity, or budget fields. The adapter compares the stored invocation, profile,
effective tool-set, repair-plan, guidance-set, catalog, and budget hashes.

`EXPLORATORY_SANDBOX_RUN.subject_id` is the same `agent_run`; its payload is
exactly `{test_command_id, candidate_tree_hash}`. The Sandbox derives
`EXPLORATORY` from the Workspace adapter's service identity. It returns a
receipt with `trust_class=EXPERIMENTAL` and no `patch_artifact_id`.

`ADJUDICATE_PATCH.subject_id` is a Patch Proposal. Its payload is exactly
`{patch_transform_hash, base_tree_hash, command_definition_ids_hash}`. Only the
Coordinator identity is admitted, and the Sandbox derives `ADJUDICATION`.
The fresh root and receipt cannot share a workspace candidate directory,
provider request, or exploratory receipt ID.

### 3.2 GitHub Provider

`QUALIFY_CODE_CHANGE.subject_id` is one immutable qualification intent and its
payload is empty. The Provider reloads the exact candidate generation, active
delivery profile, repository binding, and independent adjudication receipt. It
then reads the current default-branch commit and complete recursive Git tree,
rejects unsupported object modes and path aliases, evaluates `.gitattributes`
for every changed path, snapshots the required-check definition paths, and
derives `solvan-regular-tree-transform/v1`. A qualified receipt is the only
source permitted to populate a Code Change Request's base/tree/transform/check
material. A refusal receipt carries no partial tree or policy material.

All Provider commands identify only a `code_change_request_id`; the Provider
reloads the immutable request and active repository binding. `CREATE_PR`
requires an unexpired `PR_CREATION` decision digest. It re-reads installation,
base/tree, allowed paths, required-check definition paths/content, policy, and
the canonical transform before creating the reserved branch. `SYNC_PR` is
read-only reconciliation. `MERGE_PR` requires an unexpired `MERGE` decision
digest, a current mapped reviewer binding, and current GitHub review/check/
branch-rule state over the frozen base/head/tree/diff. It has no payload that
can name a branch, SHA, reviewer, merge method, required check, or token.

### 3.3 GitHub Identity Broker

The console API starts and consumes the OAuth flow only through the fixed
endpoints in specification 04 §5.1. `START_GITHUB_LINK` receives an opaque
repository-binding locator; it derives principal, role, scope, session and
step-up server-side. `CONSUME_GITHUB_CALLBACK` receives only GitHub's callback
fields plus the host-only callback cookie. `REVOKE_GITHUB_LINK` receives an
opaque binding ID. The Broker returns redacted lifecycle projections and never
returns an OAuth code, state, token, verifier, client secret, account ID, or
authorization URL chosen by the caller.

### 3.4 Deployment and verification

`START_ROLLOUT.subject_id` is a `code_change_request`; its payload is empty.
The Controller revalidates the exact current deployment decision and target
observation, then alone creates the target reservation, rollout, and
`DEPLOYMENT_APPROVAL_PENDING → CANARY_DEPLOYING` transition. The Coordinator
has no write grant for those rows and cannot mint deployment authority by
constructing them itself.

`PREPARE_CANARY.subject_id` is a `deployment_rollout`; its payload contains no
target address or artifact. The Controller reloads candidate, provenance,
signature, target reservation, predeploy observation, exact `DEPLOYMENT`
decision and rollout policy. `PROMOTE_CANARY` additionally requires the prior
canary operation's receipt hash and a fresh target observation. `ROLLBACK_RELEASE`
requires the exact `ROLLBACK` decision and fresh observed target state. A
request with a stale reservation, signer, target epoch, decision, policy,
predeploy assignment, canary receipt, or deadline is refused.

`OBSERVE_RELEASE_BASELINE.subject_id` is the Code Change Request and contains
only the verification-profile and target-observation hashes. The Verifier
loads the active target and key, executes only its closed Monitoring signals,
and writes a signed baseline. Deployment approval is unavailable until that
baseline is present, fresh, and bound to the same target observation.

`VERIFY_RELEASE_EFFECT.subject_id` is the rollout and contains only the frozen
verification profile hash, predeploy snapshot hash, intended-effect hash, and
an observation-window generation. The Verifier independently obtains scoped
read-only observations and signs the result. A release effect is accepted only
when those values equal the rollout's persisted values.

`REGISTER_VERIFICATION_FAILURE` accepts only the newest cryptographically
verified `FAILED` or `INCONCLUSIVE` stage receipt. `ROLLBACK_RELEASE` is not
created until a fresh exact human rollback decision binds that receipt and the
frozen predeploy revision/assignment. After the Controller moves traffic, the
rollout remains `ROLLBACK_PENDING`; only `VERIFY_ROLLBACK_EFFECT` may create
the independent signed proof consumed by `FINALIZE_ROLLBACK`.

If a service restarts after a provider operation or verifier receipt is durable
but before private-command completion, it reloads that exact immutable
receipt, validates its hash and original observation time, and completes the
same command. It does not reissue the external mutation or create another
verification result.

## 4. Closed error classes and reconciliation

Each command maps provider errors into one of:

```text
AUTHENTICATION_DENIED | AUDIENCE_DENIED | SCOPE_DENIED | MATERIAL_MISMATCH |
DEADLINE_EXPIRED | IDEMPOTENCY_CONFLICT | POLICY_DENIED | DECISION_STALE |
RESERVATION_STALE | PRECONDITION_FAILED | REQUIRED_CHECK_DEFINITION_TOUCHED |
PROVIDER_UNAVAILABLE | PROVIDER_RATE_LIMITED | EXTERNAL_STATE_AMBIGUOUS |
EXTERNAL_STATE_CHANGED | RECEIPT_INVALID | INTERNAL_CONTRACT_VIOLATION
```

`PROVIDER_UNAVAILABLE` and `PROVIDER_RATE_LIMITED` may be retryable only while
the operation remains `PREPARED`. After issuing an external request, a worker
uses the operation-specific authoritative read documented in specification 04
§5.1. It records `SUCCEEDED`, `REFUSED`, or `AMBIGUOUS`; no client retry can
turn an ambiguous effect into a new external call.

## 5. Qualification

The implementation must provide generated request/response models from this
contract, strict unknown-field rejection, IAM/audience negative tests, durable
idempotency/reconciliation tests, and trace-safe redaction. `CCR-006`,
`CCR-007`, `CCR-013`, `CRW-003`, `CRW-004`, `CRW-009`, and `CRW-010` are the
minimum acceptance cases; passing them is not a production release receipt.
