# Solvant Relay protocol contract

Status: target implementation contract; excluded from the Minimum Submittable
Release gate. Cloud SQL state, not an HTTP connection or Relay process, is
authoritative.

## Transport and identity

The Relay calls the cell-local control-plane audience over TLS 1.2 or newer.
There is no control-plane call into the Relay. Production requests require a
short-lived Google-signed or Workload-Identity-Federation-signed OIDC token
whose signature, issuer, audience, subject, expiry, and registered principal
are verified. Scope, enrollment, connection, cell, region, or posture supplied
by headers or request bodies is diagnostic only and never authority.

Every request has `Content-Type: application/json`, rejects unknown fields,
and is limited to 64 KiB. Times are UTC RFC 3339 strings. Identifiers are
uppercase Crockford ULIDs with the prefixes in the target DDL. Digests are
lowercase `sha256:` values. Signed objects use RFC 8785 JSON with the
`signature` member absent, SHA-256, and ECDSA P-256 SHA-256. The `key_id` must
resolve to an active control-plane signing-key revision recorded before issue;
revocation or expiry denies an unstarted job. Signing keys overlap for no more
than the longest issued job lifetime so an already-started attempt can be
reconciled without authorizing new work.

## Readiness challenge and authenticated runtime policy proof

`POST /internal/v1/relay/readiness-challenges`

The Relay authenticates with its registered OIDC identity and submits only
`schema_version`, `process_boot_id`, `relay_version`, `image_digest`, and
`runtime_proof_key_id`. The server derives scope and enrollment from verified
claims, verifies that the named proof-key revision is current for the
enrollment epoch, and returns one server-random 256-bit nonce in a signed
`RelayReadinessChallengeV1`. The challenge binds its ID, nonce hash, enrollment
and placement epochs, principal-claims hash, expected audience, process boot,
registered image digest, policy/key/catalog/redaction digests, region,
classification ceiling, issue time, and an expiry no more than 60 seconds
later.

`POST /internal/v1/relay/readiness-proofs`

After verifying the customer-signed local policy bytes, the Relay signs an
RFC-8785 `RelayRuntimePolicyProofV1` with the registered runtime proof key. The
proof repeats every challenge binding, includes the exact policy signature
digest and `local_policy_verified=true`, and identifies the challenge and
proof-key revision. It also carries a fresh OIDC token; the proof is accepted
only when its principal, process boot, enrollment epoch, and audience equal the
challenge and current registration. A challenge has at most one proof, is
single-use, and expires closed. A byte-identical replay returns the committed
projection; a different proof or signature conflicts.

This is a replay-resistant assertion by the registered Relay workload that it
verified the exact local policy. It is **not** evidence that the running host is
uncompromised and does not prove by itself which image executes. Build/image
attestation, host-specific deployment qualification, customer-local policy,
least-privilege IAM, and evidence validation remain separate controls. A
readiness receipt binds the accepted proof and independently approved image
attestation; neither substitutes for the other.

## Poll

`POST /internal/v1/relay/poll`

```json
{
  "schema_version": 1,
  "relay_version": "1.0.0",
  "process_boot_id": "01J...",
  "image_digest": "sha256:...",
  "image_attestation_digest": "sha256:...",
  "local_policy_id": "rpol_...",
  "local_policy_digest": "sha256:...",
  "runtime_policy_proof_id": "rpf_...",
  "runtime_policy_proof_digest": "sha256:...",
  "connector_catalog_digest": "sha256:...",
  "relay_connection_epoch": 7,
  "enrollment_epoch": 3,
  "kill_switch_engaged": false,
  "declared_adapter_revisions": ["cloud-monitoring.v1"]
}
```

The server derives enrollment and scope from verified identity, then requires
the body values to equal the current registration. The proof must be the
unexpired, accepted runtime policy proof from the preceding challenge exchange.
It contains no policy body, endpoint, or credential reference. The server
verifies its challenge, proof signature, customer key state, the separate image
attestation, policy signature digest, placement and expiry before recording a
readiness receipt. A body assertion by itself never makes an enrollment ready.
The Relay may hold the poll for at most 45 seconds. Responses are:

- `204`: no eligible work;
- `200`: one `CollectionJobEnvelope`;
- `401 IDENTITY_INVALID`;
- `403 ENROLLMENT_SCOPE_DENIED`;
- `409 ENROLLMENT_STALE`, `POLICY_DIGEST_MISMATCH`,
  `CATALOG_DIGEST_MISMATCH`, or `KILL_SWITCH_ENGAGED`;
- `426 RELAY_VERSION_UNSUPPORTED`;
- `429 POLL_RATE_LIMITED`;
- `503 CELL_UNAVAILABLE`.

The response contains `job`, `job_digest`, `signing_key_id`, and
`signature_base64`. A job contains exactly the fields defined by specification
22 §7. It expires no later than 120 seconds after issue. One active claim per
enrollment is the v1 profile constant.

## Claim acknowledgement

`POST /internal/v1/relay/jobs/{collection_job_id}/claim`

The body contains `schema_version`, `job_digest`, a Relay-generated
`claim_request_nonce`, `process_boot_id`, and `accepted_at`. A poll response
contains no lease authority. The server performs a serializable compare-and-set
from `PENDING` to `CLAIMED`, generates the random `claim_token`, and persists it
with the request nonce. Success is `200` with the committed claim token and
lease expiry. Repetition of the same request nonce returns that projection;
another request nonce loses the claim.
`409 CLAIM_LOST`, `JOB_EXPIRED`, or `BINDING_CHANGED` authorizes no read.

This explicit acknowledgement prevents a poll response from being treated as
proof that local execution began.

## Upload grant

`POST /internal/v1/relay/jobs/{collection_job_id}/upload-grant`

The body contains `schema_version`, `job_digest`, `claim_token`, `attempt_id`,
`attempt_number`, `process_boot_id`, `attempt_outcome_hash`, `local_result_hash`, `content_hash`,
`manifest_hash`, `redaction_manifest_hash`, `resource_binding_hash`,
`classification`, `residency_region`, `content_type`, and `content_length`. The
server accepts it
only for the exact current job/attempt/lease and after revalidating placement,
enrollment, Relay/source connections, source binding, policy/catalog/image,
region, classification and stated bounds.

Success returns `upload_grant_id`, `upload_grant_digest`, one opaque HTTPS
`PUT` URL plus the exact object key, required
checksum/content-type headers, maximum byte length, CMEK identifier and expiry.
The URL is not persisted by either side and never enters a log, trace, model
context or receipt. It can create exactly one new object and cannot read, list,
overwrite, redirect, change metadata, or select a bucket/key/region. Exact
request replay may return the still-valid grant; changed bytes return
`409 IDEMPOTENCY_CONFLICT`. An expired grant requires a fresh binding check and
never authorizes a second object key.

The durable grant row binds the job, attempt, request digest, exact object key,
content/manifest/redaction/resource hashes, classification, residency,
content-type, byte length, object-generation precondition, CMEK digest and
expiry. The URL itself is never stored. A receipt references that exact grant,
and the control plane independently verifies the resulting object's generation
and metadata before acceptance. The customer may return the upload response's
generation/metadata digest when its signed-upload provider exposes them; these
are assertions only. The control plane always retrieves the exact object and
pins its independently observed generation and metadata digest, so an XML
signed upload with no such response headers remains reconcilable.

## Retryable attempt outcome

`POST /internal/v1/relay/jobs/{collection_job_id}/attempt-outcome`

A retryable failure is an **attempt** outcome, never a job receipt. The request
binds the exact job digest, claim token, attempt ID/number, process boot, input
hash, started/completed times, closed error class, safe counts, and
`local_result_present=false`. Only `UPSTREAM_UNAVAILABLE` and
`UPSTREAM_RATE_LIMITED` are retryable in catalog revision 1. The serializable
command records the attempt as `FAILED_RETRYABLE`, appends the exact
`EXECUTING -> RETRY_WAIT` transition, and either returns a fresh retry decision
or terminalizes the job as `REFUSED` when its attempt budget is exhausted. It
creates no `relay_receipt`, upload grant, object, evidence item, or Tool-call
success. Exact replay returns the committed outcome; changed fields conflict.

## Receipt

`POST /internal/v1/relay/jobs/{collection_job_id}/receipt`

```json
{
  "schema_version": 1,
  "job_digest": "sha256:...",
  "claim_token": "uuid",
  "attempt_id": "rat_...",
  "attempt_number": 1,
  "process_boot_id": "01J...",
  "input_hash": "sha256:...",
  "attempt_outcome_hash": "sha256:...",
  "local_result_hash": "sha256:...",
  "result": "SUCCEEDED",
  "error_class": null,
  "safe_measurements": {"items": 12, "pages": 1, "bytes": 8042, "calls": 1},
  "evidence": {
    "object_ref": "gs://tenant-cell/relay/sha256/...",
    "content_hash": "sha256:...",
    "manifest_hash": "sha256:...",
    "redaction_manifest_hash": "sha256:...",
    "resource_binding_hash": "sha256:...",
    "classification": "INTERNAL",
    "residency_region": "europe-west1",
    "upload_grant_id": "rug_...",
    "upload_grant_digest": "sha256:...",
    "object_generation": "1712345678901234",
    "object_metadata_hash": "sha256:..."
  },
  "started_at": "2026-08-13T10:00:00Z",
  "completed_at": "2026-08-13T10:00:02Z",
  "receipt_nonce": "01J..."
}
```

`result` is `SUCCEEDED`, `REFUSED`, `FAILED_FINAL`, or
`AMBIGUOUS`. `error_class` is required unless succeeded and must be one of:
`SIGNATURE_INVALID`, `JOB_EXPIRED`, `NONCE_REPLAYED`, `SCOPE_MISMATCH`,
`CONNECTION_EPOCH_MISMATCH`, `ENROLLMENT_EPOCH_MISMATCH`,
`POLICY_DIGEST_MISMATCH`, `CATALOG_DIGEST_MISMATCH`,
`ADAPTER_REVISION_MISMATCH`, `OPERATION_DENIED`, `PARAMETER_BOUND_EXCEEDED`,
`ENDPOINT_DENIED`, `IDENTITY_INVALID`, `KILL_SWITCH_ENGAGED`,
`UPSTREAM_DENIED`, `UPSTREAM_UNAVAILABLE`, `UPSTREAM_RATE_LIMITED`,
`OUTPUT_BOUND_EXCEEDED`, `REDACTION_FAILED`, `LOCAL_RESULT_MISSING`, or
`UPSTREAM_EFFECT_UNKNOWN`.

`attempt_outcome_hash` is always present and binds the canonical final-attempt
outcome, including its result/error class, safe counts and timestamps.
`local_result_hash` is required for `SUCCEEDED`; it is nullable for a final
failure or ambiguity because refusal may occur before any local result exists.
Its absence never substitutes an empty-content digest.

For a successful receipt, the control plane verifies every immutable binding,
the current placement and connection/enrollment epochs, object metadata and
hashes, classification and residency, then atomically commits the receipt,
one accepted result, one `evidence_item`, and the Tool-call link. Repetition of
the exact receipt returns `200`; a changed covered field returns
`409 IDEMPOTENCY_CONFLICT` and creates no evidence.

An unavailable object, a hash mismatch, a revoked grant, or a changed binding
is never accepted merely because the local read succeeded. The object is
quarantined or deleted under specification 22 retention rules.

Success is committed only through the target DDL's security-definer
`relay_commit_success_v1` command. Direct application-role writes to receipt,
acceptance, evidence, Tool-call, job-transition, job-state, grant-consumption,
or outbox rows are denied. Its deferred bundle oracle requires, in one
transaction: the exact successful receipt and consumed upload grant; one
evidence item with the exact content object and canonical Relay provenance;
one `RESULT_STORED -> ACCEPTED` transition and `ACCEPTED` job version; the exact
Tool call completed as `SUCCEEDED` with that evidence item; and one
`RELAY_EVIDENCE_ACCEPTED` outbox event whose aggregate/version and closed
payload equal the bundle. Any mismatch rolls back all of them.

## Reconciliation and cancellation

`GET /internal/v1/relay/jobs/{collection_job_id}` returns only the job's
identity-bound committed status and whether the Relay should upload a stored
result, safely retry, or stop. It never returns evidence content.

`POST /internal/v1/relay/jobs/{collection_job_id}/cancel-ack` carries only
`schema_version` and `process_boot_id`, and acknowledges an already durable,
identity-bound cancel request. Cancellation before claim is terminal. After
claim it cannot prove the upstream read did not happen; the job is reconciled
and any result is either accepted under the original authorization or safely
discarded. A customer acknowledgement never creates, broadens, or terminalizes
a cancellation request on its own.

The Relay keeps a bounded encrypted local attempt ledger until 24 hours after a
terminal control-plane acknowledgement, or seven days after the last attempt
when no acknowledgement arrives. It contains
job/attempt IDs, hashes, state, timestamps, and an encrypted result object or
customer-store reference—never credentials or raw policy. Full disks refuse
new claims. Deletion is suspended by a customer legal hold.

## Health and version projection

Poll updates safe health only after identity validation. The console projection
may show lifecycle, readiness, version, image/attestation/policy/catalog
digests, last successful poll/receipt, adapter status, refusal reason, upgrade
requirement, kill-switch state, and lag. It never returns policy contents,
credential references, raw provider errors, evidence bodies, or attestation
claims not independently verified.

## Administrative control-plane API

The console uses the ordinary verified session/OIDC boundary and never calls
the internal Relay routes. These target commands are scope-derived from claims,
require `INTEGRATION_ADMIN`, and use `Idempotency-Key` with immutable request
hashes:

```text
POST /settings/integrations/relays
POST /settings/integrations/relays/{enrollment_id}/source-bindings
POST /settings/integrations/relays/{enrollment_id}:disable
POST /settings/integrations/relays/{enrollment_id}:reenable
POST /settings/integrations/relays/{enrollment_id}:revoke
POST /settings/integrations/relays/{enrollment_id}:reattest
POST /settings/integrations/relays/{enrollment_id}:test-read
GET  /settings/integrations/relays
GET  /settings/integrations/relays/{enrollment_id}
GET  /settings/integrations/relays/{enrollment_id}/deployment-bundle
```

Registration accepts only display metadata, host/profile choice, existing
Relay and source connection IDs, registered principal/audience, region and
classification constraints, and safe digests/public-key references. It never
accepts a credential, endpoint, local policy body, policy relaxation, READY
state, job, provider query, or mutation capability. Re-attestation creates a
new immutable receipt; re-enable advances the epoch and returns to
`REGISTERED`. Test-read creates an ordinary coordinator-owned Agent run/Tool
call/job against a dedicated non-sensitive test operation and cannot bypass
the same source binding or acceptance pipeline.

Closed command errors are `IDENTITY_INVALID`, `ROLE_DENIED`, `SCOPE_DENIED`,
`PLACEMENT_STALE`, `CONNECTION_INELIGIBLE`, `SOURCE_BINDING_CONFLICT`,
`POLICY_KEY_INELIGIBLE`, `ATTESTATION_INELIGIBLE`, `REGION_DENIED`,
`CLASSIFICATION_DENIED`, `LIFECYCLE_CONFLICT`, `IDEMPOTENCY_CONFLICT`, and
`DEPENDENCY_UNAVAILABLE`. No error includes provider bodies or secret material.
