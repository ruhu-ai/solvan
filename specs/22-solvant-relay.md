# Solvant Relay — customer-resident, read-only evidence plane

Status: implementation in progress; excluded from the Minimum Submittable
Release gate. The forward-only target migrations, explicit database grants,
typed job material, job/outbox creation, source-binding resolution, OIDC-bound
claim, customer-local policy verification, runtime-proof challenge signing and
verification, proof-backed polling, signed upload grants, independently
verified receipt acceptance, retry/lease reconciliation, coordinator-owned
expired-claim recovery, and a no-listener customer Relay command are locally
verified. Administrator enrollment and qualified Cloud Monitoring, Managed
Prometheus, Cloud Logging, Cloud Trace, and Kubernetes metadata source-binding
registration, disable, revoke, and proof-backed re-attestation are also locally
verified, as are coordinator job authorship from an ordinary governed Tool
invocation and the bounded Liaison Steer bridge. Customer OIDC-bound,
short-lived deployment-profile assertion and administrator review/consumption
are locally verified; the profile stores only identifiers, public references,
and digests. The customer deployment qualification receipt binds its exact
qualified adapter set as well as deployment, egress, ledger, and kill-switch
evidence. This wording is not a
production or customer deployment receipt.

Related: [tenant integration](13-tenant-integration.md),
[security](05-security-governance.md),
[governed Tool Catalog](16-governed-tool-catalog.md),
[SaaS cells](19-saas-scale-and-isolation.md),
[Production Environment Model](20-production-environment-model.md),
[protocol](artifacts/relay-api.md),
[target DDL](artifacts/relay-schema.target.sql),
[local-policy schema](artifacts/relay-local-policy.schema.json),
[connector catalog](artifacts/relay-connectors.yaml),
[evidence schema](artifacts/relay-evidence-envelope.schema.json),
[redaction profile](artifacts/relay-redaction-profile.yaml),
[state machines](artifacts/relay-transitions.yaml),
[resource-binding hash vectors](artifacts/relay-resource-binding-hash-vectors.yaml), and
[target acceptance registry](artifacts/relay-acceptance.yaml).

## 1. Purpose and release boundary

Solvant Relay is a small customer-resident process that lets Solvan collect
bounded operational evidence without receiving the customer's provider
credentials or an inbound network path into the customer estate. The Relay is
deterministic. It has no model and cannot reason, plan, select an Agent, approve,
mutate, verify recovery, resolve an incident, promote memory, or modify the
Production Graph.

Relay v1 supports one closed `gcp-observe.v1` catalog: bounded Cloud Monitoring,
registered Managed Prometheus templates, approved Cloud Logging signatures,
incident-bound Cloud Trace reads, and namespace-bounded Kubernetes workload
metadata. Cloud Logging/Audit, Error Reporting, Cloud Run metadata, and Cloud
SQL metadata remain catalogued only until their governed Tool bindings are
implemented. Kubernetes inventory beyond a policy-declared namespace and kind,
DNS-derived dependencies, packet capture, continuous watches, arbitrary PromQL,
arbitrary logging filters, and vendor-specific query languages are excluded.

This entire specification is `target`. It does not change S1--S6, the
competition release, or the Minimum Submittable Release gate.

**REL-RELAY-01:** no Relay specification, artifact, fixture, UI, local receipt,
or target migration is a competition-release requirement or proof. Only an
explicit future product release policy may promote its status.

## 2. Structural decisions

1. **Separate product boundary.** `solvant-relay` is a separate executable,
   dependency graph, image, service account, deployment manifest, and release
   receipt from the Action Actuator. It may import shared cryptography,
   identity, policy, telemetry, and typed-envelope libraries. It cannot import
   mutation connectors, action material, approval code, target reservations,
   undo plans, or actuator routes.
2. **No compatibility mode.** The Relay transport uses connection kind
   `RELAY` and provider `SOLVAN_RELAY`; observed systems retain their real
   provider connection (for example `CLOUD_MONITORING`) with
   `CUSTOMER_SIDE_NONE` credentials and an exact Relay source binding.
   The legacy Relay provider value `SOLVAN_COLLECTOR` and any mode flag that
   turns the mutation binary into a reader are removed when this target
   migrates. They are not aliases or fallbacks. The independently governed
   Action Actuator may retain its existing connection kind until its own
   migration changes that contract; Relay never uses that kind.
3. **Outbound only.** The Relay initiates authenticated TLS requests. It exposes
   no application ingress, webhook, callback, command stream, MCP server, A2A
   endpoint, shell, or generic proxy.
4. **Cloud SQL authority.** Enrollment, work, claim, attempt, receipt,
   acceptance, cancellation, revocation, and operator state are durable Cloud
   SQL records. A long poll, process, local file, GCS object, Agent Runtime run,
   or Pub/Sub delivery is not workflow authority.
5. **Coordinator-only dispatch.** An ordinary Agent invocation and Tool call
   are persisted before the coordinator may create a `CollectionJob`. The Relay
   does not create an Agent run or invoke an Agent.
6. **Exactly one accepted projection.** One job can create at most one accepted
   receipt, evidence item, and Tool-call result. Relay v1 does not claim exactly
   one upstream read because its initial Google read APIs do not expose a
   qualifying idempotency key.
7. **Local policy can only narrow.** Customer-authored local policy cannot be
   written or relaxed by Solvan. Missing, invalid, empty, expired, or mismatched
   policy refuses reads and evidence egress.

## 3. Components and authority

| Component | Responsibility | Explicitly lacks |
|---|---|---|
| Coordinator | persist Agent run/Tool call; resolve connection, profile and graph binding; create job | endpoint, credential, arbitrary query, mutation authority |
| Relay control-plane service | verify Relay identity; lease jobs; accept receipts/evidence atomically | customer credential and local-policy write access |
| Solvant Relay | validate signed job and local policy; call one closed read adapter; redact and upload | model, peer dispatch, arbitrary network access, mutation code |
| Customer identity/policy systems | issue workload identity and mount signed local policy/credential reference | Solvan workflow authority |
| Evidence pipeline | rescan and validate the returned envelope before prompt eligibility | authority to broaden classification, region, or visibility |
| Evidence/Infrastructure Agent | request an already-profiled Tool and interpret accepted evidence | ability to address the Relay, connection, endpoint, or job directly |
| Action Actuator | perform separately authorized production mutations | any Relay enrollment, job, local read credential, or evidence acceptance role |

The only shared boundary between Relay and Actuator is audited library code.
They have distinct identities, audiences, images, registries, SQL repositories,
network policies, APIs, and CI architecture tests.

## 4. End-to-end flow

1. An administrator registers a credentialless `RELAY` transport connection,
   a Relay enrollment, the real read-source connection, and an exact source
   binding. A new transport begins `PENDING`: it cannot be declared `READY`
   by registration. Its first accepted identity-, image-, and policy-bound
   readiness receipt is the sole transition that records the transport's
   minimal successful `relay.readiness` probe and enables it.
2. The attestation verifier validates the exact Relay image; the control plane
   records the attestation, customer policy digest, connector catalog digest,
   identity binding, cell/placement epoch, region, and classification ceiling.
3. A successful identity-bound poll that matches every recorded value may move
   a `REGISTERED` enrollment to `READY`; self-reported values are never proof.
4. An institutional Agent requests a registered read Tool. The coordinator
   persists the exact Agent run, Tool call, resolved source connection/profile,
   Production Graph resource binding, and input hash. The coordinator then
   resolves the current Relay source binding; neither the Agent nor model
   chooses the transport.
5. In the same application command, the coordinator creates and signs one
   expiring `CollectionJob`, or records a closed refusal. It never delegates
   job authorship to a model.
6. The Relay polls, validates the job, durably acknowledges its claim, and
   revalidates every binding immediately before the local adapter call.
7. The adapter performs only the catalog operation against the exact endpoint
   in local policy. The provider response is untrusted.
8. The Relay projects and redacts locally, runs local secret/PII checks, stores
   only the encrypted redacted result in its bounded attempt ledger, and uploads
   through a job-bound write-only object grant.
9. The control plane validates identity, job/attempt/receipt binding, current
   epochs, object metadata/hashes, schema, bounds, classification, region,
   deterministic secret/PII results, and Model Armor treatment before it
   atomically accepts an evidence item and completes the Tool call.
10. Only the accepted reader-filtered evidence projection can enter an Agent
    context. Provider text remains untrusted data, never instructions.

## 5. Executable and dependency boundary

The source tree contains a dedicated `apps/solvant_relay/main.py` entry point.
Its build target
uses a Relay-only lock group and produces a separately named image. A static
architecture test fails if its transitive imports include:

- `solvan.connectors.mutation`;
- `ActionActuator`, `AuthorizedAction`, approvals, target reservations,
  expected effects, undo plans, or execution receipts;
- a shell/subprocess runner, dynamic code loading, package installer, Docker
  socket client, Kubernetes write client, generic database client, or generic
  HTTP-forwarding route; or
- an Agent SDK, model SDK, MCP/A2A server, or Agent Runtime client.

Runtime configuration cannot enable a forbidden dependency. Relay and Actuator
service accounts are mutually exclusive and neither can impersonate the other.
The Relay image has no mutation IAM permission even if deployed incorrectly.

## 6. Enrollment and image attestation

An enrollment is scoped to exactly one organization/project/environment,
Relay transport connection, placement epoch, principal subject/issuer, expected audience,
region, classification ceiling, local-policy digest, connector-catalog digest,
redaction revision, image digest, and enrollment epoch.

`RelayImageAttestationVerifier` accepts only an immutable Artifact Registry
digest with all of:

- KMS-verified SLSA provenance from the approved builder identity;
- the exact source commit and Relay build target;
- an immutable SBOM and vulnerability-scan receipt;
- an approved signing-key revision and unexpired attestation; and
- proof that the image architecture check contains no prohibited dependency.

Self-reported image data is compared for drift but never proves attestation.
Local-policy readiness additionally uses the nonce-bound challenge/proof
exchange in the protocol artifact. The registered Relay workload signs an
exact statement that it verified the customer signature over the registered
policy digest and key. The control plane verifies the fresh OIDC identity,
single-use challenge, runtime proof key, signature and every bound epoch before
recording an expiring readiness receipt; a poll body assertion alone cannot
make the enrollment `READY`. This is an authenticated runtime assertion, not a
claim that build attestation proves which process is live or that the customer
host is uncompromised. Image attestation and host qualification remain separate
prerequisites.
Revocation, key compromise, policy change, connector-catalog change, placement
move, connection epoch change, principal change, or classification/region
change advances the enrollment epoch and makes outstanding unstarted work
ineligible. An already-started read is reconciled; it is accepted only if the
original authority still permits storage and disclosure, otherwise its output
is safely discarded.

One enrollment may serve several explicitly registered read-source connections.
`relay_source_bindings` maps one source connection and epoch to one enrollment,
adapter revision, local-policy binding digest, capability receipt, region and
classification ceiling. The source connection retains its real provider and
`CUSTOMER_SIDE_NONE` posture. A binding is usable only while both source and
Relay connections, the enrollment, capability proof, policy and placement are
current. There is no default Relay and no model-selected fallback.

## 7. CollectionJob contract

A `CollectionJob` is an RFC-8785-canonical, SHA-256-addressed, ECDSA-P256-signed
application object containing exactly:

```text
schema_version, collection_job_id, organization/project/environment scope hash,
cell and placement epoch, enrollment ID/epoch, Relay connection ID/epoch,
source-binding ID, source connection ID/epoch,
agent_run_id, tool_call_id and arguments hash, incident_id,
Tool-profile key/version/material hash, Tool key/version/profile ordinal,
accepted capability-receipt ID/hash,
connector-catalog key/revision/digest,
adapter key/revision, operation enum, typed parameters and parameter hash,
Production Graph resource binding ID/hash,
optional evidence window, page/item/byte/call/attempt ceilings,
redaction revision, classification ceiling, residency region,
input hash, issued_at, expires_at, nonce, signing key ID
```

It contains no endpoint, credential, credential reference, arbitrary query
text, URL, HTTP method/header/body, SDK method, file path, shell command,
Kubernetes verb, provider project selected from free text, action, approval,
verification profile, or mutation operation. Job lifetime is at most 120
seconds. The signed digest covers every field except the detached signature.

The coordinator derives operation and parameter material from the exact Tool
revision, accepted run binding, source connection, Relay source binding, and
approved Production Graph binding. The source connection recorded in the job
must equal the accepted Tool binding. A model can request a semantic Tool and
bounded window; it cannot choose a source or Relay connection, resource,
endpoint, region, classification, ceiling, policy, adapter, or raw provider
query.

`resource_binding_hash` is SHA-256 over the UTF-8
`relay-resource-binding-v1` preimage. The preimage contains, in the exact order
below, each value encoded as `<UTF-8 byte length>:<value>` and separated by
`|`; SQL `NULL` is encoded as `-1:`:

```text
schema version (=1), organization, project, environment, cell, placement epoch,
snapshot ID, approved snapshot material hash, node ID, node key, node kind,
resource ref, external project ID, effective classification, region,
instrumentation state, observation ID, source key, source revision
```

The byte-vector artifact and database function use this same preimage. The
coordinator derives it from the immutable approved snapshot/node row; it is
persisted on the job and repeated in the evidence envelope, upload grant and
successful receipt. A supplied digest is never trusted and a mismatch refuses
before the provider call or evidence acceptance.

## 8. Protocol

The normative route, envelope, identity, signing, closed error, cancellation,
upload, and reconciliation contract is
[`relay-api.md`](artifacts/relay-api.md). Poll, claim, execute, upload, receipt,
and accept are separate states. A `200` poll response does not prove a read
started, and a successful local result does not prove it remains admissible.

The upload service mints an HTTPS write-only grant for exactly one cell-local,
tenant-prefixed GCS object key, content type, maximum length, checksum, CMEK,
and expiry of at most five minutes. It permits no read, list, overwrite,
redirect, region change, or second object. The grant is control-plane-derived
and never appears in model context or durable job material.

## 9. State and concurrency

[`relay-transitions.yaml`](artifacts/relay-transitions.yaml) is the loadable
source of truth for enrollment and collection-job transitions.

- A serializable claim transaction selects one eligible `PENDING` job and
  compare-and-sets it to `CLAIMED` with a random lease token.
- V1 permits one active claimed/executing/ambiguous job per enrollment.
- Every local attempt is created before calling the adapter.
- A Relay restart checks its encrypted local ledger and the control-plane job
  state before any retry.
- A stale lease token cannot upload, submit a receipt, or complete a job.
- Cancellation after claim means cancel-requested and reconciliation; it never
  asserts that the upstream read did not happen.
- Terminal replay returns the committed projection and invokes no adapter.

An adapter may declare exactly-once upstream behavior only after a target
acceptance fixture proves a provider-supported idempotency key. All v1 catalog
adapters declare `NOT_SUPPORTED`. Ambiguous attempts may be retried only for a
catalogued retryable error, after local-result reconciliation, within the
two-attempt ceiling. The console shows the ambiguity and total upstream calls.
`FAILED_RETRYABLE` is an attempt outcome and moves the job through
`RETRY_WAIT`; it is not a job receipt. One final job receipt is stored only for
Relay-authored `SUCCEEDED`, `FAILED_FINAL`, terminal `AMBIGUOUS`, or an explicit
Relay refusal after it claimed the job. A coordinator-authored pre-claim
refusal, or a post-attempt retry-budget exhaustion committed from an already
durable `FAILED_RETRYABLE` attempt outcome, terminalizes the job and Tool call
with its closed reason but creates no Relay-authored receipt.

## 10. Persistence and atomicity

[`relay-schema.target.sql`](artifacts/relay-schema.target.sql) is the target DDL
source of truth. Every tenant row carries the scope triple and participates in
the same RLS and Cell Data Access Broker rules as specifications 13 and 19.

The authoritative repositories provide one method for every table. Critical
transactions are:

1. **Create job:** validate the current placement, Relay and source connections,
   source binding/capability proof, Relay enrollment, Agent run, Tool call,
   accepted Tool profile binding, graph binding, quota and
   expiry; insert the signed job and outbox wake-up atomically.
2. **Claim job:** lock enrollment/job, revalidate lifecycle and all epochs,
   record claim token/lease, and return the already-committed claim on exact
   replay.
3. **Accept receipt:** the security-definer `relay_commit_success_v1` command is
   the sole successful write path. It validates current authority, the consumed
   upload grant and immutable bytes; inserts the final receipt, evidence item,
   acceptance, exact `RESULT_STORED -> ACCEPTED` transition and outbox event;
   updates the job/version and exact Tool call to `SUCCEEDED` with that evidence
   item; and passes the deferred bundle oracle atomically. Direct application-
   role writes to any member are revoked. A partial commit is impossible.
4. **Revoke enrollment:** advance epoch, record immutable transition, stop new
   claims, and mark outstanding work for reconciliation atomically.

Object upload precedes acceptance but does not create evidence authority. An
unreferenced or refused object is quarantined and deleted by the retention
reconciler.

## 11. Local policy

[`relay-local-policy.schema.json`](artifacts/relay-local-policy.schema.json) is
the closed customer-policy format. The customer signs it with a key whose
public-key digest is installed as a local Relay trust root and separately
registered with the control plane. The Relay validates canonical bytes,
signature, key state, validity interval, organization binding, connection and
enrollment epochs, image, audience, region, classification, catalog, and
redaction revision before every local call.

The policy signature covers the RFC-8785 canonical object with the `signature`
member omitted. The Relay sends only the policy ID/digest, signature digest,
key ID, validity and the nonce-bound runtime proof to the control plane; it
never sends the policy body. The server verifies these against the scoped
policy-key and runtime-proof-key revisions and persists an immutable readiness
receipt whose expiry cannot exceed the challenge, policy, keys, image
attestation or identity proof.

The policy is mounted read-only from a customer configuration/secret system.
Solvan can display its digest and expiry but cannot upload, edit, refresh, or
override it. Empty adapter/operation lists deny. An endpoint is exact HTTPS
scheme, DNS host, port, TLS server name and CA policy; wildcards, IP literals,
implicit ports, redirects, DNS rebinding to private/unapproved addresses, and
unregistered proxy destinations deny.

Credential references are local deployment data. They never enter a job,
receipt, object name, database row, trace, log, metric label, prompt, support
bundle, or control-plane projection.

## 12. Connector and evidence contracts

[`relay-connectors.yaml`](artifacts/relay-connectors.yaml) is the closed v1
operation catalog. Unknown adapter, revision, operation, parameter, enum value,
resource kind, or bound refuses before network access. The local policy can
remove operations or lower ceilings; it cannot add or widen them.

Every adapter/operation names one exact `tenant_connections.provider` and one
capability class. The governed Tool profile and accepted run binding must carry
that exact pair and a current coverage receipt for the Production Graph node's
external project. Metrics use `CLOUD_MONITORING/METRIC_READ`; Logging and Audit
use their distinct providers and capability classes; Trace, Error Reporting,
Cloud Run metadata and Cloud SQL metadata likewise use the exact closed
variants declared by specifications 13 and 16. An adapter whose pair is absent
from those contracts is catalogued but **not selectable** until the connected
schema/profile/coverage fixtures land. V1 implementation therefore qualifies
Cloud Monitoring first and adds each later adapter only in the same change as
its governed Tool binding and capability probe—catalog presence is not runtime
availability.

Returned bytes must conform to
[`relay-evidence-envelope.schema.json`](artifacts/relay-evidence-envelope.schema.json).
Unknown fields are not forwarded. The envelope uses OTel-compatible safe
attribute names and explicit record types rather than raw provider payloads.

Provider responses, including errors, are untrusted. The Relay applies
[`relay-redaction-profile.yaml`](artifacts/relay-redaction-profile.yaml) before
egress. It projects allowlisted fields, hashes sensitive identifiers with a
scope-local key, drops raw messages/stacks/payloads, and runs pinned local
secret/PII detectors. Missing, unavailable, ambiguous, or denying detectors
withhold the entire result. There is no partial best-effort forwarding.

The control plane revalidates schema, hashes, classification, region and bounds,
then applies the existing untrusted-evidence/Model Armor gate. Model Armor
unavailability never makes content prompt-eligible. Model Armor is defense in
depth, not the only control stopping secrets or PII from leaving the customer.

## 13. Data classification, storage, and deletion

Raw provider responses exist only in bounded process memory and are zeroed or
released after projection. The local attempt ledger stores only the encrypted,
already-redacted canonical envelope and hashes. Its encryption key stays in the
customer KMS/secret system. New work refuses when the ledger cannot durably
record an attempt or is full.

Accepted objects use the tenant's cell-local regional GCS bucket, tenant prefix,
CMEK, uniform bucket-level access, public-access prevention, object versioning,
and retention policy. Default evidence retention follows specification 5;
Relay receipt metadata is retained for the audit period. Legal hold prevents
deletion. Revocation does not silently erase evidence already admitted under a
valid prior purpose, but future visibility is re-evaluated against current
reader grants and retention policy.

The customer-local redacted attempt is deleted after terminal acknowledgement
plus 24 hours, or after seven days without acknowledgement. A customer legal
hold can extend it. Credentials, raw responses, and policy bodies are never
eligible for legal-hold export because they are never stored by the Relay.

## 14. SaaS cells and sovereignty

Identity resolves the organization; organization placement resolves the cell.
Neither the Relay body nor a model chooses scope or cell. Polling, upload grants,
objects, SQL, logs, traces, signing keys, and support processing must all be in
the intersection of the tenant's allowed region set and the current cell
manifest. There is no cross-region spillover.

This is the control-plane residency rule, not a same-region workload rule. A
qualified Relay may run beside an explicitly authorized customer workload in a
different region. Its signed policy names that workload region; the frozen
graph target, source-binding capability receipt, local policy, provider
attribution, and accepted evidence projection must agree on it. The redacted
projection is uploaded only to the tenant's cell-local evidence store. A
missing or mismatched workload region refuses the job before a provider call.

Every request binds placement and enrollment epochs. A move or revocation makes
new work ineligible immediately. `OSS_SINGLE_TENANT`, `SHARED_CELL`, and
`DEDICATED_CELL` retain identical Relay identity, scope, policy, quota, audit,
and evidence-acceptance controls. Shared cells use the Cell Data Access Broker;
the Relay service receives no direct shared-cell SQL credential.

## 15. Deployment profiles

The same immutable Relay image supports:

| Host | Shape | Production condition |
|---|---|---|
| Cloud Run worker pool | outbound worker; no HTTP service ingress | exact regional worker-pool, VPC and identity qualification receipt |
| GKE | Deployment with no Service/Ingress | Workload Identity, default-deny NetworkPolicy and exact egress |
| On-prem federated | supervised rootless container/service | WIF identity, signed policy, customer egress allowlist and local encrypted ledger |
| On-prem key file | supervised rootless container/service | explicit recorded risk acceptance and customer rotation runbook |
| Developer host | local harness | never production eligible |

All production profiles run as non-root with a read-only root filesystem,
dropped Linux capabilities, no privilege escalation, bounded CPU/memory/disk,
no host filesystem, Docker socket, package manager, interactive shell, or
Kubernetes service-account token outside Workload Identity. GKE mounts no
Service. Health is projected through authenticated outbound polls; local
liveness is consumed only by the customer scheduler/process supervisor.

The egress policy permits only the exact control-plane audience, exact provider
endpoints in signed local policy, customer identity/KMS endpoints required by
the host, and DNS/NTP resolvers recorded in the deployment manifest. Proxy and
custom-CA configuration is explicit, immutable, and unable to add a destination.

### 15.1 Installation and qualification experience — target

Solvan adopts the useful installation shape of a customer-resident integration
agent—enroll, generate a deployment bundle, deploy in the customer estate, and
verify health—but not a bearer-token-controlled generic proxy.

The supported GKE installation is a versioned OCI Helm chart identified by an
immutable chart digest, signed provenance, SBOM, and a declared image/chart/
protocol compatibility matrix. Its values schema rejects unknown fields.
Customer tooling must verify chart digest, provenance, SBOM, image digest, and
compatibility before it applies a rendered manifest. Cloud Run Job and on-prem
profiles are separately rendered, versioned manifests; none is a compatibility
mode of another host. Generated material contains only immutable image
references, enrollment/source-binding identifiers, public-key and policy
digests, audience, declared host profile, and references to customer-local
secret mounts. It never contains a provider credential value, private key, raw
policy body, unbounded endpoint, arbitrary query, mutation permission, or a
Solvan command to deploy into the customer estate.

The customer applies the generated material through their own delivery system.
The Relay authenticates using its registered workload OIDC identity and proves
the signed local policy through the readiness protocol; an ingest token is not
an authority substitute. A one-time enrollment artifact, if introduced for
installation convenience, may only locate one pre-registered enrollment, must
expire quickly, be audience- and host-bound, and cannot claim work, widen
policy, or authenticate provider access.

The customer deployment process submits an OIDC-bound installation assertion
to the control plane. Its scope is resolved from the credentialless Relay
transport, while issuer and subject are derived from verified claims; it cannot
provide a scope, a credential, a policy body, or a private key. The assertion
is valid for at most 24 hours and is checked against the active customer policy
key, region-matched Relay transport, and unexpired allowed image attestation.
It is then immutable and `PENDING_REVIEW`.

The console setup flow selects and reviews that stored profile instead of asking
an administrator to type security-critical identifiers or digests: a qualified
Relay transport, attested image, customer workload identity, signed policy,
eligible real-provider source connection, and accepted capability receipt.
Approval consumes one unexpired profile atomically into one `REGISTERED`
enrollment; a replay, changed profile, or missing profile refuses. The source
binding derives the profile's local binding digest and the real connection's
current epoch, region, classification, and capability receipt in the API
transaction. The console then renders the exact required IAM/RBAC, egress,
secret-mount, ledger, and kill-switch requirements; it does not edit customer
policy or credentials.
After deployment, the same view shows readiness, binding health, expiry,
disable/revoke controls, and qualification state. A customer-signed
qualification receipt is accepted only through the authenticated Relay control
route after the exact enrollment is `READY`. The control plane independently
verifies the registered ECDSA P-256 runtime-key signature over a canonical
receipt digest, the current enrollment epoch, the approved profile's egress
digest, an enabled customer kill switch, and the bounded receipt expiry; it is
not a browser upload.

## 16. Upgrade and degradation

Jobs bind protocol, image, Relay, adapter, catalog, policy and redaction
revisions. A rollout drains claims before replacing an instance. Two image
revisions may overlap only when both are attested and protocol-compatible; they
still compete through one server lease. An unsupported version receives `426`
and no job.

Control-plane, identity, policy, attestation, local ledger, scanner, DNS, TLS,
provider, storage, or receipt failure cannot open a weaker path. The Relay
backs off with jitter inside fixed poll-rate limits, records a safe reason, and
becomes `DEGRADED` or `STALE`. Direct cloud reads are not an automatic fallback:
they require a separately registered eligible connection and a new coordinator
binding.

## 17. Quotas and resource bounds

The immutable v1 maxima are: one active job per enrollment, two attempts per
job, 60 seconds local execution, 120 seconds job lifetime, five minutes upload
grant lifetime, 20 pages, 20 upstream calls, 1,000 records, and 1 MiB canonical
evidence. Local policy and tenant quotas may only lower them.

Admission occurs before a job is created and before a provider call. Capacity
exhaustion queues or refuses; it never selects another connection, Relay,
tenant, region, operation, model, or weaker policy. Poll rate, upstream rate,
bytes, calls, attempts, storage and evidence acceptance are separately metered
with content-free idempotency keys.

## 18. Audit and observability

OpenTelemetry spans cover job creation, poll authentication, claim, local
validation, adapter call, redaction, upload, receipt validation, evidence
acceptance, reconciliation and deletion. Safe attributes include hashed scope,
job/enrollment/connection IDs, revisions/digests, closed state/reason, bounded
counts, duration, retry number, cell/region, and trace ID.

Logs, traces and metrics never include policy bodies, credential references,
endpoints containing user data, typed parameters, evidence bodies, provider
errors, upload grants, identity tokens, signatures, or customer resource names.
No private chain-of-thought exists or is logged.

Target SLOs require separately stored qualification receipts for availability,
poll-to-claim latency, receipt acceptance, stale-enrollment detection, duplicate
projection rate, redaction-denial rate, and upgrade recovery. Numeric SLO values
are environment qualification inputs, not invented by this design contract.

## 19. Console and operator experience

Relay configuration belongs under **Settings → Integrations → Relays**, not the
Agent Fleet. The Fleet may show that an Agent profile depends on a Relay-backed
connection, but the Relay is not catalogued as an Agent.

The list and detail projections show:

- Relay transport connection, bound source connections, host, environment,
  region and classification ceiling;
- lifecycle (`REGISTERED`, `READY`, `DEGRADED`, `STALE`, `DISABLED`, `REVOKED`)
  with a plain-language definition and deterministic next step;
- Relay/image/attestation/policy/catalog/redaction revisions and expiries;
- identity status, last poll, last accepted receipt, current/ambiguous job,
  connector health, bounded usage and upgrade requirement;
- local kill-switch status reported by the Relay; and
- safe audit and deployment receipt links.

The UI supports secret-free registration, selection of the exact ready source
connection for each closed adapter, source binding, disable/revoke, lifecycle
inspection, and download of a customer deployment bundle. The bundle carries
only identifiers, signed digests, required customer controls, and the selected
release templates; it never carries a policy body, credential value, private
key, or remote deployment command. The UI cannot edit local policy, display or
accept credentials, force `READY`, widen a connector, clear ambiguity, replay a
provider read, or enable remediation. Qualification receipt intake remains
disabled until its signature is verifiable against a separately registered
customer signing identity. Status is derived from authoritative records and
never from optimistic client state.

## 20. Security and threat model

The design assumes the Solvan control plane, model input, external channels,
provider data and customer network can each be hostile independently.

- A hostile control plane is constrained by customer-signed policy, exact
  endpoint/operation bounds, Relay identity, local kill switch, lack of mutation
  code and IAM, and local redaction.
- A hostile provider payload cannot become instructions; closed projection,
  local detectors, control-plane validation and Model Armor all run before
  prompt eligibility.
- A stolen Relay identity cannot select another scope because the principal is
  registered to one enrollment and all work binds current epochs and audience.
- A forged source or route cannot redirect evidence: the source must equal the
  Agent run's accepted Tool binding and the Relay transport must equal the
  current coordinator-resolved source binding.
- A replayed job, nonce, claim, upload or receipt cannot create another accepted
  result.
- A compromised Relay is still high impact for its allowlisted reads. Customers
  must restrict provider IAM, endpoints, egress and host access; Solvan cannot
  prove the customer host itself uncompromised.

Support bundles contain only safe health/audit projections and exact digests.
They require a purpose-bound export grant and the tenant's regional support
policy.

## 21. Invariants

| ID | Invariant |
|---|---|
| INV-RELAY-01 | Relay is a separate build and identity with no mutation dependency, route, IAM capability, or runtime switch. |
| INV-RELAY-02 | Relay exposes no application ingress and initiates every network interaction. |
| INV-RELAY-03 | Verified identity and placement derive scope; request/model values cannot select it. |
| INV-RELAY-04 | Missing, invalid, empty, expired, unsigned, or mismatched local policy performs no read or evidence egress. |
| INV-RELAY-05 | Only a current independently attested image and exact policy/catalog/identity binding can be `READY`. |
| INV-RELAY-06 | The coordinator persists the Agent run and Tool call before creating one signed job. |
| INV-RELAY-07 | A job cannot represent a URL, credential, arbitrary query, shell, Kubernetes verb, generic protocol, or mutation. |
| INV-RELAY-08 | Every binding is revalidated after claim and immediately before local execution. |
| INV-RELAY-09 | A stale claim token, nonce, epoch, policy, catalog, image, placement, or identity authorizes no new read. |
| INV-RELAY-10 | One job creates at most one accepted receipt, evidence item and Tool-call projection. |
| INV-RELAY-11 | Upstream exactly-once is never claimed without a separately qualified adapter idempotency contract. |
| INV-RELAY-12 | Raw provider content and errors never leave the customer; failed or ambiguous redaction withholds the whole result. |
| INV-RELAY-13 | Accepted evidence is schema-, hash-, bound-, region-, classification- and policy-validated atomically. |
| INV-RELAY-14 | Evidence remains untrusted data and cannot become prompt context if the control-plane safety gate is unavailable or denies. |
| INV-RELAY-15 | Credentials and policy bodies never enter Solvan SQL, GCS, logs, traces, receipts, prompts, or support exports. |
| INV-RELAY-16 | A cancellation or crash after claim reconciles; it never assumes a read did not happen. |
| INV-RELAY-17 | Capacity exhaustion refuses or queues and cannot widen authority or route elsewhere. |
| INV-RELAY-18 | Customer-local and control-plane retention, legal hold and deletion are region- and classification-bound. |
| INV-RELAY-19 | Relay evidence cannot create or promote Production Graph authority. |
| INV-RELAY-20 | Console status and next steps derive from authoritative receipts and never grant readiness or remediation. |
| INV-RELAY-21 | Revocation advances an epoch, prevents new claims immediately, and reconciles outstanding attempts. |
| INV-RELAY-22 | OSS, shared and dedicated profiles retain identical identity, scope, policy and evidence-acceptance controls. |
| INV-RELAY-23 | A job's source is the accepted Agent-run Tool binding, while its Relay transport is coordinator-resolved from one current source binding; neither is model-selected. |
| INV-RELAY-24 | Central Chat can only park and confirm a typed bounded Steer; the coordinator alone creates the Agent run, Tool call and Relay job, and neither Liaison nor model receives a Relay address, binding, job API or transport selector. |
| INV-RELAY-25 | Retryable failure is an attempt outcome; at most one final receipt exists per job and a retry cannot be blocked by an earlier attempt outcome. |
| INV-RELAY-26 | Successful acceptance atomically binds the accepted job/version/transition, final receipt, consumed upload grant and object metadata, evidence/provenance, exact successful Tool call, and exact outbox event. |
| INV-RELAY-27 | Job, enrollment, source binding, grant, receipt and evidence agree on residency and a classification no higher than every applicable ceiling. |
| INV-RELAY-28 | The canonical Production Graph resource-binding digest is derived and verified before execution and repeated unchanged through grant, receipt and evidence. |
| INV-RELAY-29 | READY requires one unexpired single-use challenge and signed runtime policy proof bound to verified identity, process boot and current epochs; it never treats build attestation as live-process proof. |
| INV-RELAY-30 | A Relay operation is selectable only when its exact provider/capability pair exists in the governed Tool profile, accepted run binding and current coverage receipt. |

Every invariant maps to a named target case in
[`relay-acceptance.yaml`](artifacts/relay-acceptance.yaml). An unimplemented case
is `null`, not implicitly passing. Local evidence is never a customer deployment
receipt.

## 22. Qualification and implementation order

The implementation proceeds in this order:

1. remove the shared-binary/`SOLVAN_COLLECTOR` target design and land the
   separate Relay registry, schema migration and state repositories;
2. implement canonicalization, signing, attestation and local-policy validation;
3. implement poll/claim/reconcile/receipt services and the encrypted local
   attempt ledger with process-kill tests;
4. implement one `cloud-monitoring.v1` operation end to end, including local
   redaction, object upload and atomic evidence acceptance;
5. add remaining `gcp-observe.v1` adapters one at a time with negative fixtures;
6. implement GKE and on-prem deployment bundles, then qualify Cloud Run worker
   pools separately;
7. implement console enrollment/health/audit surfaces and accessibility tests;
8. execute the complete hostile-control-plane, cross-tenant, crash, load,
   region, retention and upgrade matrix; and
9. run `scripts/check`, record a local target receipt, then obtain a distinct
   customer-environment deployment/qualification receipt.

Implementation may begin only when the connected specification review has no
open blocker or high-severity finding, every artifact in the Related list
parses/loads, every invariant has a target test, and the active plan records
the exact reviewed commit. Completion requires every acceptance entry to name
an implementation, repository methods and authorization tests for every target
table/route, all process-kill cases passing, a real customer-side deployment
receipt conforming to `relay-qualification-receipt.schema.json`, and a green
canonical check.

## 23. Non-goals

- Relay is not an Agent, Satellite clone, service mesh, VPN, generic query
  proxy, log shipper, remote shell, or remote configuration manager.
- It does not replace direct connections; each path requires its own explicit
  registration and coordinator binding.
- It does not add remediation. The Action Actuator remains a different product
  boundary with independent procurement, identity, policy and deployment.
- It does not independently verify recovery; Relay evidence may be one input to
  the separately isolated Verification Agent only through its own exact profile.
- It does not discover or promote topology, ownership, criticality,
  authorization or verification bindings.
- It does not claim parity with Resolve Satellite's Kubernetes inventory,
  DNS-derived service maps, or continuous topology features.
