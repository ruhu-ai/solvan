# Solvan SaaS scale, tenant isolation, and cell architecture

Status: target product contract; excluded from the Minimum Submittable Release
gate. Nothing in this document proves multi-tenant production qualification,
capacity, availability, billing, disaster recovery, or a managed Solvan
service is implemented.

Related: [architecture](02-system-architecture.md),
[data/API](04-data-event-api.md), [security](05-security-governance.md),
[deployment](07-implementation-deployment.md),
[evaluation](08-test-evaluation-acceptance.md),
[tenant integration](13-tenant-integration.md),
[Solvant Relay](22-solvant-relay.md),
[conversational surface](14-conversational-surface.md),
[target DDL](artifacts/saas-scale-schema.target.sql),
[target test registry](artifacts/saas-scale-target-tests.yaml), and
[official source record](../docs/sources/saas-scale-and-isolation.md).

## 1. Purpose and release boundary

This specification defines the architecture by which one clean Solvan product
can operate in three forms:

1. a self-hosted open-source installation for one organization;
2. a shared regional SaaS cell for several organizations with compatible
   sovereignty and isolation requirements; or
3. a dedicated cell for one regulated or high-volume organization.

The forms share one domain model, authorization contract, agent fleet, event
contract, and operator experience. A deployment profile changes placement and
capacity, never truth, identity, scope, approval, mutation, or verification
semantics.

This specification is entirely `target`. It does not enlarge the competition
release, the S1--S6 release scenarios, or the Minimum Submittable Release gate.
The existing single-region competition topology remains valid without this
specification being implemented.

## 2. Design constants

1. **A tenant is an organization.** `organization_id` is the top-level
   isolation and commercial boundary. `project_id` and `environment_id` are
   subordinate operational scopes and never substitute for it.
2. **Placement precedes access.** Verified identity determines the
   organization; the organization determines one active cell. A caller cannot
   select either value through a header, body, query, channel field, model
   argument, or connector response.
3. **One writable home.** An organization has exactly one writable home cell
   at a placement epoch. Active-active workflow writes across cells are
   prohibited.
4. **Capacity never changes authority.** Exhaustion queues, throttles, or
   refuses. It never selects another tenant, region, model, tool, verification
   profile, identity, or weaker policy.
5. **Sovereignty fails closed.** A cell, provider endpoint, backup, log sink,
   or support export outside the tenant's allowed locations is ineligible.
   There is no cross-region spillover.
6. **Cloud SQL remains authoritative inside each cell.** Pub/Sub, caches,
   provider sessions, Memory Bank, Runtime jobs, and routing grants are
   accelerators or projections, not workflow authority.
7. **Noisy-neighbour resistance is an authorization property.** Tenant-level
   admission and reservations are applied before shared downstream capacity is
   consumed.
8. **Scale claims require receipts.** Instance counts, provider quotas, SLOs,
   recovery objectives, and tenant counts are unverified until an exact
   deployment passes the named qualification profile.
9. **Open source is not a weaker mode.** A static single-tenant placement
   adapter may remove managed routing infrastructure, but it cannot disable
   scope predicates, RLS, quotas, audit, region checks, or identity validation.
10. **Models do not schedule or place tenants.** Placement, admission,
    metering, fairness, lifecycle, and recovery are typed application services.

## 3. Cell model and deployment profiles

A **cell** is a bounded failure, quota, data, and deployment unit with an exact
`cell_id`, Google Cloud project set, region, Cloud SQL authority, KMS boundary,
Agent Platform resources, Cloud Run services, Pub/Sub topics, storage, and
observability sinks. A cell publishes a signed immutable deployment manifest.

| Profile | Organizations per cell | Physical boundary | Intended use |
|---|---:|---|---|
| `OSS_SINGLE_TENANT` | exactly 1 | operator-owned project and database | self-hosted production |
| `SHARED_CELL` | `2..max_organizations` from the immutable cell manifest | one regional cell; logical isolation and RLS | cost-efficient managed SaaS |
| `DEDICATED_CELL` | exactly 1 | tenant-specific project set and datastore | regulated or high-volume tenant |

A shared cell may contain only tenants whose residency, classification,
service launch-stage, encryption, support-access, and recovery policies are
compatible with that cell's immutable capability envelope. Tenant-specific
exceptions do not widen a shared cell. A tenant requiring a wider or different
boundary moves to a dedicated cell.

Compatibility has two independently approved immutable operands: a
`CellEligibilityProfile` and a `TenantEligibilityRequirement`. Placement binds
both hashes. The deterministic placement service requires the requested
classification and home region in both allow-lists; every provider launch
stage and recovery region exposed by the cell inside the tenant's allow-lists;
the encryption profile to match exactly; and cell support access to be no
wider than the tenant permits. A missing operand, empty intersection, or
mismatch refuses before the placement can become current. Neither a request
nor a model may author either operand.

The initial managed topology uses `europe-west1` cells and `eu` Gemini
processing for eligible fast-fleet requests. Additional regions are separate
cell templates and require the source, threat-model, registry, model, tool,
backup, and acceptance updates already required by the engineering guide.

### 3.1 Logical routing and governance plane

The routing/governance plane contains only:

- opaque organization identifier and verified identity binding reference;
- cell identifier, home region, isolation tier, placement epoch, and lifecycle;
- policy, encryption, data-classification, and allowed-processing-location
  digests;
- content-free capacity and health summaries; and
- immutable placement/lifecycle audit references.

It must not contain incident titles, evidence, transcripts, prompts, model
responses, connector payloads, customer credentials, repository contents,
memory text, or production topology. Those records remain cell-local.

The routing plane is logically central; `global` is not a location claim. Its
own storage and processing location are recorded in its signed deployment
manifest. Every placement transaction proves that the routing-plane storage,
compute, KMS, log, backup, and support-processing locations belong to the
intersection of the tenant's independently approved location sets. An empty
intersection refuses placement; a generic `global` or `eu` label is not accepted
as evidence of the underlying locations.

## 4. Identity-derived routing

The ingress service validates the external cryptographic identity and resolves
its organization binding from authoritative identity records. It then reads
the active placement and mints a short-lived `CellRoutingGrant` containing:

```json
{
  "schema_version": 1,
  "organization_id": "org_...",
  "project_id": "prj_...",
  "environment_id": "env_...",
  "cell_id": "cell_europe_west1_01",
  "placement_epoch": 7,
  "region": "europe-west1",
  "principal_hash": "sha256:...",
  "request_hash": "sha256:...",
  "audience": "https://cell-api.example",
  "issued_at": "timestamp",
  "expires_at": "timestamp <= issued_at + 60 seconds",
  "jti": "ULID",
  "grant_digest": "sha256:..."
}
```

The grant is signed by a routing-plane KMS key. A cell accepts it only when
signature, audience, request hash, principal hash, region, cell, placement
epoch, expiry, and local non-revocation state match. A grant establishes only
routing eligibility; the ordinary scope, RBAC, read, steer, approval, action,
and tool gates still run inside the cell.

Cells receive a content-free placement mirror. Revocation or epoch advance is
published immediately, but Pub/Sub delivery is not trusted: the 60-second
grant ceiling bounds stale use and sensitive operations re-read placement
under the authoritative routing service. Failure to resolve placement refuses;
it never falls back to a default cell.

Customer-resident Solvant Relays poll only the tenant's current cell-local
Relay audience and bind the same placement epoch in enrollment, job, object
grant and receipt. A placement move makes unstarted work ineligible and
reconciles a possibly executed read; it never redirects a Relay, evidence
object or receipt across regions or cells. Specification 22 governs the
separate read-only executable, the coordinator-resolved source-to-transport
binding, and evidence-acceptance boundary.

`OSS_SINGLE_TENANT` implements the same `PlacementProvider` contract from one
startup-bound organization and cell manifest. Startup fails unless exactly one
organization is configured. Request values cannot override it.

## 5. Data and cryptographic isolation

Every cell-local tenant record keeps the complete scope triple
`(organization_id, project_id, environment_id)`. Every repository method,
foreign key, unique key, index prefix, outbox record, object path, cache key,
trace correlation attribute, Memory Bank scope, and Agent Platform Session user
key includes or derives from that boundary.

Shared cells require:

- PostgreSQL RLS on every tenant **content or operational** table. Work
  registry, capacity reservation, scheduler-lane, dispatch, usage, and event
  rows all carry the complete `(organization_id, project_id, environment_id)`
  triple and use forced exact-scope RLS. Organization-wide lifecycle,
  placement, quota-policy, and billing-settlement rows are content-free
  control-plane state: they carry `organization_id`, are never read through a
  tenant role, and can authorize subordinate work only after a typed control
  service resolves it to an exact-scope operational row. Cell-wide catalog and
  capacity rows are likewise inaccessible to tenant roles;
- one authenticated **Cell Data Access Broker** as the only shared-cell holder
  of a tenant-table database credential. Application services call the broker
  over audience-bound workload identity and cannot open SQL connections or set
  database context directly;
- the broker validates the signed routing grant, exact request/principal/
  audience hashes, current placement and revocation mirror before starting a
  transaction. The organization, project, and environment it checks the grant
  against come from the caller's verified identity, never from the grant being
  checked and never from the request path: comparing a grant with its own
  fields is not a scope check, and would let a validly signed grant for another
  project in the same cell install that project's scope; In that same transaction it creates a private
  `routing_grant_session` bound to a random context ID, JTI digest, exact scope,
  database role, PostgreSQL backend PID and transaction ID, then installs the
  context ID with `SET LOCAL`. The RLS security-definer predicate accepts only
  that exact live binding. A JTI or context ID alone is not a credential;
- the ordinary tenant application role is permitted only while the exact
  current placement is `ACTIVE`. `SUSPENDING`, `SUSPENDED`, `MOVING`,
  `DELETING`, `DELETED`, and `FAILED` deny ordinary tenant access. Lifecycle,
  repair, movement, deletion, and reconciliation use separate enumerated
  least-privilege roles and functions rather than the tenant RLS grant;
- pooled connections are transaction-scoped. Commit, rollback, error, timeout,
  cancellation, or pool return resets all context; `SET` without `LOCAL` and a
  pool lacking reset-on-return/dirty-connection destruction fail preflight;
- separate workload roles and least-privilege grants;
- cell-local KMS and Secret Manager, with per-tenant CMEK where the tenant
  policy requires it;
- organization-prefixed object names plus IAM conditions; prefix naming alone
  is not isolation;
- tenant-qualified cache keys with deny-on-missing scope;
- tenant identity attributes on metrics, expressed only as bounded opaque IDs;
  and
- negative cross-tenant tests at repository, API, channel, memory, connector,
  object-store, and support-tool boundaries.

Dedicated cells use a separate tenant project/data plane in addition to these
application controls. Physical isolation is defense in depth and never permits
removing the scope triple.

`OSS_SINGLE_TENANT` and `DEDICATED_CELL` retain the strongest simple database
posture: a workload database role bound to the exact tenant and a server-derived
transaction scope. They do not synthesize routing grants. A `SHARED_CELL` uses
the broker and a bounded set of cell roles above; creating one pool and database
role per SaaS tenant is prohibited because it turns tenant count into connection
exhaustion. Broker roles can create but cannot list live session rows. No
application, support, analytics, or audit role can read them. Audit rows store
only a JTI hash, never the JTI or context ID, and are not consulted as live
authorization state. A terminal `DENIED`, `EXPIRED`, or `REVOKED` event disables
the live session regardless of whether it was written before or after an
acceptance event.

The target privilege manifest is closed: `PUBLIC` receives no schema, table,
sequence, or security-definer-function privilege; the access broker receives
only the broker entry point and tenant operations required by its API; the
lifecycle role receives only fenced control procedures; audit/support roles
receive redacted audit projections and never live grant state. Every deployment
materializes and tests those grants before the cell becomes `READY`.
Database roles are `NOINHERIT`, have no membership in another scale role, and
cannot `SET ROLE` across kinds. The loadable
`scale_database_privilege_manifest` is the only input to the deployment grant
materializer; an object or privilege absent from it is revoked.

No customer content is copied into a centralized analytics warehouse by
default. Product analytics consume content-free usage events. Any support
export is purpose-bound, tenant-approved, expiring, audited, and region-safe.

Every cell manifest binds an immutable `CellEligibilityProfile`. The profile
is a closed allow-list of data classifications, exact residency/recovery
regions, provider launch stages, encryption profile, and support-access
posture. Placement refuses when any requested classification, region,
encryption, provider stage, support path, or recovery location is absent. A
shared cell never widens this profile per tenant; an incompatible tenant routes
to a newly qualified dedicated cell or remains unplaced.

## 6. Admission, quotas, and fair dispatch

Work enters shared execution in this order:

1. verify identity and active placement;
2. evaluate tenant lifecycle and product entitlement;
3. validate region, classification, and purpose eligibility;
4. reserve the exact tenant quota and cell capacity units;
5. persist the authoritative request/turn/run and its reservation; and
6. allow a scheduler to dispatch the eligible durable record.

The closed initial resource vocabulary is:

```text
API_REQUEST
CONVERSATION_TURN
AGENT_RUN
MODEL_REQUEST
MODEL_INPUT_TOKEN
MODEL_OUTPUT_TOKEN
MEMORY_READ
MEMORY_WRITE
CONNECTOR_CALL
CHANNEL_DELIVERY
SSE_CONNECTION
SUBSCRIPTION
STORED_BYTE
```

Every active tenant quota policy contains, for each applicable resource, an
exact sustained limit, burst limit, window, maximum concurrent reservations,
and behavior on exhaustion. Absence, invalidity, expiry, or an unknown resource
refuses new consumption. Configuration may lower a limit but cannot set an
unbounded sentinel.

The first implementation uses a continuously refilled token bucket per
`(organization, policy version, resource)`:

- bucket capacity is `burst_limit` units;
- tokens refill at `sustained_limit / window_seconds` using integer nanounits
  and a persisted remainder, so rounding is deterministic;
- admission serializes on the quota-counter row with `SELECT ... FOR UPDATE`,
  refills from its persisted monotonic timestamp, verifies the active immutable
  binding, available tokens, `maximum_concurrent`, current placement epoch, and
  request hash, then inserts the reservation and decrements tokens in the same
  transaction;
- an identical idempotency key and request hash returns the original result. A
  changed hash returns `QUOTA_IDEMPOTENCY_CONFLICT` and changes nothing;
- settlement is exactly once by reservation token. Release returns concurrency
  capacity, not consumed rate tokens; expiry is reconciled against the exact
  authoritative work reference before releasing concurrency;
- revoking a policy refuses new reservations and fences every `HELD`
  reservation that has not started. Already-started work follows its declared
  reconciliation contract and cannot start another provider attempt.

Quota policy revisions and their activation/revocation bindings are immutable.
The newest binding epoch is the current projection; activation names one exact
approved revision, while revocation leaves no active policy and therefore
refuses new consumption.

Durable work uses `QUOTA_WAIT` when waiting is safe. Synchronous requests
receive `429 TENANT_QUOTA_EXCEEDED` or `503 CELL_CAPACITY_UNAVAILABLE` with a
bounded `Retry-After`; the distinction is visible and auditable. Security
revocation, lease reaping, action reconciliation, and deletion have a small
separate control reserve that tenant work cannot consume. The reserve cannot
start new investigations, model calls, or mutations.

### 6.1 Hierarchical fairness

The cell scheduler selects an organization first, then eligible work inside
that organization. It uses the immutable `CellSchedulerProfile` and bounded
deficit round robin (DRR) over active organizations:

1. at the start of a round, an active lane receives
   `min(max_deficit, deficit + base_quantum * weight)`. A lane is one
   `(organization, ordinary | control)` pair, and each holds its own deficit:
   one counter shared between the two lanes would let a poll of an empty
   control lane clear the credit a tenant accumulated waiting for ordinary
   service, and would pay for control work out of the tenant's ordinary
   purse — the opposite of a reserve tenant work cannot consume;
2. a lane whose queue is empty resets its own deficit to zero rather than
   banking unbounded credit, leaving that tenant's other lane untouched;
3. the scheduler may claim the lane's oldest eligible item whose immutable
   catalog cost does not exceed the deficit, then subtracts that cost;
4. a lane that cannot afford work is skipped until the next round; and
5. `maximum_wait_seconds` ages the oldest eligible item to the front of that
   tenant's class order, without changing tenant selection or bypassing gates.

Resource costs and workload classes are versioned cell data, never request or
model values. Within one thread, specification 14 FIFO remains exact. The
closed initial intra-tenant order is the control classes
`CONTROL_RECONCILIATION`, `SECURITY`, `RECONCILIATION`, and `DELETION`, followed
by `OPEN_SEVERE`, `OPEN_OTHER`, `INTERACTIVE_ASK`, and `BACKGROUND`; aging
applies within the tenant.
Each tenant lane allocates `tenant_sequence` while holding its lane row in the
same transaction that appends the queue item. The number is ordering metadata,
not a cursor; a rollback may leave no row and no consumer treats a gap as work.
It is allocated and unique within the complete `(organization_id, project_id,
environment_id)` scope. Scheduler lanes, queue uniqueness, and retry lookups
use that same scope; organization-wide ordering is neither promised nor
inferred from this value.

The cell profile defines `ordinary_dispatch_slots`, `control_reserve_slots`,
`base_quantum`, `max_deficit`, `maximum_wait_seconds`, and
`maximum_tenant_share_basis_points` (initial target default `2500`, or 25%).
The assured share for an active tenant is the smaller of its concurrent quota
and `max(1, floor(ordinary_dispatch_slots * weight / sum(active weights)))`.
No tenant may exceed both its assured share and the configured maximum share.
Unused ordinary slots may be marked `borrowed=true`; borrowing ends only between
attempts. Control-reserve slots admit only `SECURITY`, `RECONCILIATION`, or
`DELETION` work and structurally reject user, model, investigation, and mutation
starts. The shared-cell `max_organizations` and scheduler profile are part of
the same immutable capacity manifest.

Quota consumption and release are idempotent and fenced by reservation token,
placement epoch, work ID, and expiry. Reapers reconcile expired reservations
through a typed `(work_kind, work_id)` foreign-reference registry before
releasing them. A free-form URI is not accepted. The claimed-work and expired-
reservation indexes are part of the target DDL.

## 7. Provider quota broker

Agent Runtime, Sessions, Memory Bank, model inference, Registry, Gateway, and
other Google APIs apply quotas at specific project/region or model scopes.
Cloud Run autoscaling does not increase those quotas.

Each cell stores a periodically refreshed, signed `CapacityReceipt` containing
the exact deployment, project, region, API metric, observed limit, reserved
headroom, expiry, and source receipt. Dispatch reserves against both the tenant
policy and the cell receipt. An expired or missing receipt prevents new work
for that resource while already accepted work follows its bounded retry and
reconciliation contract.

Receipts are immutable observations. A separate append-only binding ledger
selects or revokes the one current receipt per `(cell, resource)`. Selection
requires a receipt whose cell deployment-manifest hash exactly matches the
current cell, whose region/project/resource match, and whose `expires_at` is in
the future at use time. Expiry is derived from time and cannot be represented by
a stale `status` string. Concurrent binding decisions serialize on the
`(cell, resource)` current projection and monotonically increase its epoch.
For model capacity, the receipt and binding additionally carry the exact model
resource, jurisdictional endpoint, and provider profile digest. The binding's
composite foreign key includes cell, receipt, resource, project, region,
deployment manifest, model, endpoint, and profile; a receipt for one resource
or data plane therefore cannot qualify another. Every accepted tenant
reservation records the exact binding epoch and receipt ID it consumed.

Shared Agent Platform endpoints require tenant-level enforcement before the
provider call. Dedicated cells may use tenant-specific endpoints/projects for
quota isolation but retain the same broker. Quota increases are operational
inputs and do not become capacity claims until a fresh receipt and load test
bind them.

Provider `429`, saturation, or outage cannot cause silent model substitution,
cross-project use, cross-region routing, or a fallback from a dedicated to a
shared endpoint. Work waits, degrades through its declared path, or refuses.

## 8. Cloud Run and Cloud SQL capacity envelope

Every Cloud Run service has explicit concurrency, minimum instances, maximum
instances, CPU, memory, timeout, and downstream resource budgets in the cell
manifest. Defaults are never treated as qualified values.

Application services use bounded connection pools. Opening one new database
connection per request is not production eligible. Pool configuration records
minimum, maximum, acquisition timeout, idle lifetime, maximum connection
lifetime, health check, IAM-token refresh behavior, and application name.
Maximum connection lifetime is shorter than the effective IAM database
authentication lifetime with a configured safety margin. A connection is
destroyed rather than returned when identity refresh, transaction cleanup, or
scope-context reset cannot be proved.

The deployment gate enforces:

```text
sum(service_max_instances
    * observed_instance_overshoot_factor
    * per_instance_pool_max)
+ job_connection_budget
+ migration_connection_budget
+ operator_emergency_reserve
<= qualified_database_connection_limit
```

`observed_instance_overshoot_factor` is greater than or equal to 1 because a
Cloud Run maximum can be exceeded briefly during spikes or deployments. The
database keeps an explicit operational reserve; Solvan never budgets 100% of
`max_connections` to application pools.

Every equation input is stored in the immutable cell capacity profile:
per-service maximum instances, explicit request concurrency, measured
overshoot numerator/denominator, per-instance pool maximum, rolling-deployment
overlap, job and migration budgets, pooler/admin connections, replica/failover
overlap where applicable, and operator emergency reserve. The overshoot factor
comes from a named load/deploy experiment bound to service revision, Cloud Run
settings, region, request mix, observation window, and expiry; absent or expired
measurement uses the profile's larger fail-closed ceiling, never `1` by default.
The qualified SQL limit is a current immutable capacity receipt. Preflight
evaluates the equation with integer ceiling arithmetic and refuses the deploy
when any term, binding, or receipt is absent or stale.

Services that hold long requests, such as SSE, use a database connection only
for bounded reads and never pin one for the lifetime of the client. Agent work
is queue-first and asynchronous. Scale-out pauses before exhausting Cloud SQL,
provider quota, connector quota, or customer-actuator budgets.

Read replicas may serve explicitly stale-tolerant projections only. Approval,
authorization, placement, quota reservation, workflow transition, action,
verification, and cursor high-water reads always use the authoritative writer.

## 9. Lossless event ordering and fan-out

The existing `scope_event_sequences` allocation is acceptable for the
competition and `OSS_SINGLE_TENANT` profile. It intentionally serializes
event-bearing commits inside one environment so catch-up cannot skip a late
commit.

A `SHARED_CELL` or high-throughput `DEDICATED_CELL` must use the production
sequencer before qualification:

1. the domain mutation and an unsequenced `cell_event_ingress` row commit in
   the same transaction;
2. a fenced sequencer transaction can see and claim only already-committed rows
   for one scope;
3. it assigns a batch of monotonically increasing scope positions in one short
   transaction, ordered by the row's immutable ingress creation time and event
   ID among the rows visible to that claim;
4. the sequenced event becomes eligible for projection and Pub/Sub wake-up;
5. a cursor advances only across sequenced rows it is authorized to see.

This removes the sequence-row lock from domain writers without using a raw
PostgreSQL sequence as a cursor. The assigned position means **sequencer
assignment order**, not PostgreSQL commit timestamp order. A transaction that
commits after a batch snapshot becomes visible to a later batch and receives a
larger position, so an already-issued cursor cannot skip it. Solvan does not
enable or depend on `track_commit_timestamp`, and the ingress timestamp must not
be named or interpreted as a commit timestamp. A raw sequence allocated by the
domain writer remains insufficient because its number can become visible out of
allocation order.

Sequencer claims are leased and epoch-fenced. Duplicate wake-ups are harmless;
an event receives one scope position. Backlog age is a saturation signal and
blocks a capacity claim when it exceeds the cell profile.

Claim, batch assignment, `next_scope_sequence` advancement, and event
terminalization occur in one transaction after locking the scope lease row and
comparing lease token, lease epoch, cell, and current placement epoch. A
malformed event increments a bounded attempt count; after the configured limit
it becomes `QUARANTINED` with a content-free error reference and blocks cursor
advancement for that scope until an authorized operator supersedes or repairs
it. Later events cannot silently sequence around a poison event. Decreasing a
scope's next sequence is prohibited.

Pub/Sub carries content-free wake-ups. SSE and channel services resume from the
authoritative SQL cursor, apply current reader filtering, and disconnect slow
clients at the bounded buffer ceiling defined by specification 14. They do not
poll continuously or use Pub/Sub delivery order as transcript authority.

A production cursor binds at least cell ID, placement epoch, scope sequence,
policy epoch, membership epoch where applicable, and cursor schema version.
Tenant movement invalidates old-cell cursors and starts with a verified
destination high-water receipt.

The target schema represents this contract in `scope_event_cursors`. Cursor
recovery is a security-definer operation that accepts only a current active
placement and a receipt-bound high-water mark no greater than the authoritative
sequenced feed. Advancement locks the exact cursor, requires the expected
sequence, rejects quarantined or unsequenced rows, and never accepts a
Pub/Sub-delivered sequence as proof. A current placement epoch invalidates
older cursor rows through the target trigger; policy and membership changes
are supplied as the bound epochs and therefore require the same explicit
recovery path when they change.

## 10. Conversation, Sessions, Memory Bank, and caches

The Conversation Context Compiler remains the correct scale boundary:
authoritative records are filtered first and a bounded reader-specific view is
compiled per attempt. More tenants must never result in a shared ADK Session,
Memory Bank scope, transcript cache, prefix cache, compaction, or provider
conversation.

Every cache identity includes cell, organization, project, environment,
principal/reader, purpose, classification, region, placement epoch, policy
epoch, relevant membership epoch, compiler/model/template/tool digests, and
source high-water marks. Missing fields deny a hit. Moving or deleting a
tenant invalidates its namespace.

Memory Bank remains non-authoritative and exact-scope. Capacity pressure may
skip optional recall, but never scope filtering, predicate validation, approval
checks, verification, or the operator-visible holding form.

## 11. Tenant lifecycle and movement

The closed lifecycle is:

```text
PROVISIONING -> ACTIVE -> SUSPENDING -> SUSPENDED
ACTIVE|SUSPENDED -> MOVING -> ACTIVE
ACTIVE|SUSPENDED -> DELETING -> DELETED
PROVISIONING|MOVING|DELETING -> FAILED
```

Every transition is expected-state and placement-epoch fenced. Provisioning is
idempotent and produces receipts for project/cell placement, schema revision,
identity bindings, KMS, storage, quota policy, connection policy, backup, and
negative isolation tests before `ACTIVE`.

The transition graph is loadable data and is enforced by one typed lifecycle
service using expected-state/epoch CAS. The target DDL also rejects backward
placement epochs, undeclared lifecycle edges, mutation of immutable placement
identity, and every transition out of `DELETED`. Lifecycle jobs are append-only
attempt records with a separate transition history; a completed job cannot be
returned to a running state by clearing fields.

Suspension denies new user/model/agent work but preserves reconciliation,
security, export, legal-hold, and deletion control paths. It never abandons an
unknown production mutation; action settlement follows specification 13.

Movement is active-passive:

1. validate destination eligibility and capacity;
2. quiesce new work and settle or fence every in-flight attempt;
3. record the source high-water and immutable export manifest;
4. restore into an empty destination and verify counts, hashes, scope, keys,
   schema, and referenced objects;
5. run cross-tenant and sovereignty negatives;
6. atomically advance placement epoch and route to the destination; and
7. retain or delete the source only under the tenant retention/legal-hold
   policy.

The movement record carries the quiesce receipt, source scope high-water,
source export manifest/hash, destination cell and proposed epoch, destination
counts/hash receipt, isolation/sovereignty test receipt, cutover decision and
cutover epoch. `expected_placement_epoch` references the exact source placement.
The cutover transaction verifies all of them, retires the old current placement,
creates the strictly higher destination placement, and appends the immutable
decision. No free-form completion URI substitutes for these typed fields.

Rollback is allowed only before routing cutover. A `MOVE` job cannot become
`COMPLETED` directly from `VERIFYING`; it must enter `CUTOVER_READY`, commit
the exact cutover, and only then complete. After cutover, recovery is a new
fenced movement; cells are never concurrent writers.

Deletion enumerates Cloud SQL rows, objects, managed Sessions, Memory Bank,
caches, channel payloads, search indexes, secrets, keys where permitted,
backups under their expiry policy, and customer-audit references. Legal hold
blocks destructive steps and records why. Completion produces a content-free
deletion proof; `DELETED` cannot return to `ACTIVE`.

## 12. Availability, backup, and disaster recovery

Each production cell declares:

- high-availability mode and failure domains;
- backup/PITR configuration, storage location, encryption key, retention, and
  restore-test cadence;
- per-service SLO, error-budget policy, and saturation thresholds;
- RPO and RTO for each data class;
- degradation behavior for SQL, Pub/Sub, Agent Platform, model, Memory Bank,
  channel, and connector outages; and
- operator ownership and an immutable recovery runbook revision.

Location policy is not one generic array. Each tenant has independently
versioned allow sets for `ROUTING_PLANE_PROCESSING`, `MODEL_PROCESSING`,
`PRIMARY_DATA`, `BACKUP`, `LOG_SINK`, `SUPPORT_PROCESSING`, `CUSTOMER_AUDIT`,
`CHANNEL_DESTINATION`, `EXPORT`, and `FAILOVER`. Every relevant operation names
one policy kind and resolved location; missing kind or location refuses. A cell
manifest records its routing-plane locations separately and placement verifies
them against the tenant policy intersection.

Initial production uses regional high availability and restore-tested backups
inside the tenant's allowed boundary. Cross-region replicas or backup copies
exist only when the tenant policy explicitly allows the destination.
Sovereignty-restricted tenants refuse cross-region automatic failover.

No SLO, RPO, or RTO appears in product copy until chaos/restore evidence from
the exact cell template meets it. Recovery never reconstructs authority from
Sessions, Memory Bank, Pub/Sub, traces, or model output.

## 13. Metering, cost, and commercial separation

Every admitted resource produces an immutable, idempotent, content-free
`UsageEvent` with organization, subordinate scope when needed, cell, resource,
units, source work ID, model/provider identifier where relevant, occurred time,
and hash. It contains no prompt, transcript, evidence, credential, repository
content, or customer topology.

Usage events support capacity, abuse detection, customer-visible consumption,
and deterministic invoice aggregation. They are not permission, workflow, or
provider-billing authority. Provider invoices are reconciled separately; a
discrepancy is visible and never repaired by rewriting usage history.

Content-free identifiers use closed kinds plus ULID/UUID or bounded digest
formats; arbitrary strings, URLs, prompts, titles, topology, or customer names
are prohibited. Aggregation is by `(organization, resource, UTC billing period,
unit scale)` with exact integer units. Pricing, currency, tax, and rounding live
in a separately approved commercial policy and never change usage history.
Provider reconciliation writes an immutable comparison receipt referencing both
the usage high-water and provider invoice; it does not mutate either source.

Budget alerts and hard ceilings are separate. An alert cannot authorize extra
usage; a hard ceiling follows the same durable admission path as any quota.
The console explains the limiting resource, current safe aggregate, reset or
expiry, owner, and remediation without exposing another tenant's activity.

## 14. Open-source portability

The open-source distribution exposes interfaces for placement, quota-policy
storage, capacity receipts, usage sinks, object storage, event wake-up, and
identity binding. The maintained reference implementation remains Google
Cloud-native; portability is not permission to replace deterministic controls
with model decisions or trusted headers.

`OSS_SINGLE_TENANT` may use:

- one statically bound cell manifest instead of a routing service;
- PostgreSQL instead of managed Cloud SQL;
- a local content-free wake-up adapter instead of Pub/Sub; and
- a no-op commercial usage sink that still retains bounded operational usage
  counters.

It may not disable scope columns, RLS in a production multi-user database,
identity verification, tenant quotas, audit, retention, classification, region
eligibility, or customer-side mutation controls. Running several organizations
under the single-tenant profile is a configuration error, not an unsupported
shortcut to shared SaaS.

An OSS production database may omit RLS only when one immutable startup
manifest binds exactly one organization, every database login belongs to that
organization's trusted operator boundary, there is no end-user/support/
analytics SQL access, and the startup negative proves that a second
organization cannot be configured. Otherwise it uses the exact-role RLS path.
The shared-cell broker-session policy is not loaded in OSS or dedicated mode;
profile-specific policy migrations have the same repository API and hostile
suite and no fake routing-grant records.

## 15. Schema, migration, and deployment discipline

The target records and constraints are executable in
`artifacts/saas-scale-schema.target.sql`; they are not part of release
`schema.sql`. Promotion requires an explicit status decision, migration,
repository implementation, RLS policy, and production qualification.

`tenant_placements` is a rebuildable current projection. Every placement and
lifecycle transition also appends the immutable decision/audit record required
by specifications 04 and 05; updating the projection never rewrites that
history.

Every insert and every `is_current` transition serializes on the organization.
Activating an existing row is refused when any higher placement epoch exists;
cutover activates only the highest verified epoch in the same transaction that
retires the prior current row. Merely clearing `is_current` and replaying an
older row can never roll placement backward.

Every cell manifest binds application revision, schema revision, target DDL
revision, region, identities, tools, models, quota profile, pool profile, and
capacity receipt. A request from another cell/schema epoch refuses.

There are no permanent compatibility aliases or dual domain contracts.
Zero-downtime database rollout may use a time-bounded expand/migrate/contract
mechanism for the immediately adjacent release, but the compatibility object
is inventoried, has an expiry and removal test, grants no new behavior, and is
removed before the migration is declared complete.

## 16. Threat model additions

| Threat | Required control |
|---|---|
| spoofed tenant/cell headers | verified identity binding plus signed routing grant; body/header values ignored |
| stale route after movement/revocation | placement epoch, local revocation mirror, short grant TTL, sensitive-operation recheck |
| noisy tenant exhausts shared provider quota | tenant reservation before cell/provider reservation; assured-share scheduler |
| Cloud Run scales past SQL capacity | explicit max/concurrency, observed overshoot factor, bounded pools, deployment inequality |
| cache or Session crosses readers/tenants | complete isolation key; missing field denies; provider state disposable |
| shared-cell operator exports tenant content | purpose-bound audited support grant; no centralized content analytics |
| quota retry double charges | idempotency key, request hash, reservation token, settlement/reaper reconciliation |
| failover violates sovereignty | eligible-location check; no automatic cross-region spillover |
| event cursor skips a late commit | post-commit fenced sequencer; cursor advances only over sequenced rows |
| tenant movement creates two writers | quiesce, verified high-water, one epoch cutover, no rollback after cutover |
| deletion leaves derived copies | enumerated purge graph, legal-hold gate, content-free deletion proof |
| dedicated deployment drifts from shared controls | same application invariants and negative suite in every profile |

## 17. Invariants

- **INV-SCALE-01** Organization and cell are derived from verified identity and
  active placement; request and model values cannot select them.
- **INV-SCALE-02** One organization has at most one active writable placement
  epoch, and a cell accepts only its own current epoch.
- **INV-SCALE-03** Missing placement, tenant/cell eligibility operand, quota
  policy, capacity receipt, region eligibility, or isolation key refuses; the
  two eligibility operands must be compatible and no default or unbounded
  value exists.
- **INV-SCALE-04** Every cell-local record and access path carries the complete
  scope triple; an empty access set denies.
- **INV-SCALE-05** Dedicated cells add physical isolation without removing
  application scope, RLS, identity, audit, quota, or any equivalent defense-
  in-depth control used by shared cells.
- **INV-SCALE-06** Tenant quota is reserved before shared cell/provider
  capacity, and retries cannot consume either twice.
- **INV-SCALE-07** Fair scheduling selects a tenant before its work; no tenant
  can exceed its concurrency/share ceiling through priority or retries.
- **INV-SCALE-08** Control-reserve capacity cannot run ordinary user, model,
  investigation, or mutation work.
- **INV-SCALE-09** Provider exhaustion cannot cause model, project, tenant,
  region, endpoint, or isolation-tier substitution.
- **INV-SCALE-10** Cloud Run's qualified maximum demand, including measured
  overshoot and operational reserve, does not exceed SQL or provider capacity.
- **INV-SCALE-11** Production services use bounded pools and never retain one
  SQL connection for an SSE/client lifetime.
- **INV-SCALE-12** A production cursor never advances past an unsequenced
  committed event and is invalid after placement-epoch change.
- **INV-SCALE-13** Pub/Sub, caches, Sessions, Memory Bank, replicas, and traces
  cannot create or change workflow authority.
- **INV-SCALE-14** Tenant movement has one writer, one exact cutover epoch, and
  a verified source/destination high-water.
- **INV-SCALE-15** Tenant deletion covers derived copies and cannot complete
  while a legal hold or unsettled mutation blocks it.
- **INV-SCALE-16** Tenant-facing access to usage and routing-plane records
  cannot reveal another tenant's identifiers, workload, capacity, or activity.
  Control-plane records contain only approved opaque tenant references,
  normalized counters, placement metadata, and content-free health summaries,
  and are visible only to authorized platform services and administrators.
- **INV-SCALE-17** Every production capacity, SLO, RPO, RTO, and scale claim is
  bound to an unexpired exact-deployment receipt.
- **INV-SCALE-18** `OSS_SINGLE_TENANT` accepts exactly one startup-bound
  organization and does not weaken any production authority invariant.
- **INV-SCALE-19** Model output may analyze, explain, simulate, or recommend
  placement, capacity, fairness, lifecycle, billing, and recovery decisions,
  but it cannot establish, authorize, commit, or adjudicate them. Typed
  deterministic services own those decisions and their state transitions.
- `INV-SCALE-20` is retired; its former MSR-boundary statement is a release-
  assurance rule rather than a runtime invariant and is superseded by
  `REL-SCALE-01`. This identifier must not be reused.
- **INV-SCALE-21** Shared-cell SQL authorization exists only through a broker-
  created transaction session bound to exact scope, database role, backend PID,
  transaction ID, request/principal/audience hashes, cell, and placement epoch;
  a JTI, hash, context ID, header, body, request, or model value is insufficient.
- **INV-SCALE-22** Grant terminalization is order-independent; live grant state
  and immutable audit history are separate, and no audit reader can obtain an
  authorization credential.
- **INV-SCALE-23** Placement epochs strictly increase, lifecycle transitions
  follow the closed graph, completed histories are immutable, and `DELETED` is
  terminal.
- **INV-SCALE-24** Quota admission is serialized and token/concurrency exact;
  DRR credit, tenant share, borrowing, control reserve, and maximum wait are
  finite immutable values rather than model/request choices.
- **INV-SCALE-25** Scope positions are fenced sequencer-assignment order over
  committed-visible rows. Poison events are visible and block a scope cursor;
  neither ingress timestamps nor raw sequences are represented as commit order.

### 17.1 Release assurance

- **REL-SCALE-01** Target SaaS artifacts do not change the competition MSR,
  and local, scripted, or load-test fixtures never constitute production
  qualification without an exact deployed-environment receipt.

## 18. Acceptance and qualification

The target implementation must provide at least these falsifying tests:

| ID | Proof |
|---|---|
| `SEC-SCALE-ROUTE-SPOOF-001` | header/body/model-supplied organization or cell cannot alter routing |
| `SEC-SCALE-STALE-EPOCH-001` | stale placement grant fails after move, suspension, or revocation |
| `SEC-SCALE-CROSS-TENANT-001` | repositories, objects, caches, Sessions, Memory, channels, support, and metrics deny cross-tenant reads |
| `IT-SCALE-QUOTA-IDEMPOTENCY-001` | concurrent/retried admission consumes one reservation and one usage settlement |
| `IT-SCALE-FAIRNESS-001` | a saturating tenant cannot starve another tenant's assured share |
| `IT-SCALE-CONTROL-RESERVE-001` | ordinary work cannot consume reconciliation/deletion reserve |
| `IT-SCALE-CAPACITY-FAIL-CLOSED-001` | expired capacity/quota receipts queue or refuse without cross-region/model fallback |
| `IT-SCALE-POOL-BUDGET-001` | maximum Cloud Run demand plus overshoot stays below the tested SQL connection envelope |
| `IT-SCALE-SEQUENCER-RACE-001` | late commits, duplicate claims, crash/restart, and batch races emit each event once without cursor skips |
| `IT-SCALE-SLOW-CONSUMER-001` | SSE overflow disconnects and resumes from SQL without pinning a connection or dropping terminal events |
| `IT-SCALE-FANOUT-CURSOR-001` | content-free wake-ups are idempotent, authoritative rows are read in sequence order, and cell/placement/policy/membership changes force cursor recovery |
| `IT-SCALE-MOVE-001` | movement quiesces, verifies, cuts over once, and never permits two writers |
| `SEC-SCALE-SOVEREIGNTY-001` | disallowed inference, backup, log, export, or failover location refuses |
| `IT-SCALE-DELETE-001` | deletion covers every derived store; legal hold and unsettled action block completion |
| `IT-SCALE-OSS-ONE-TENANT-001` | the static profile starts with exactly one organization and cannot be overridden by a request |
| `LOAD-SCALE-NOISY-NEIGHBOUR-001` | qualified steady/burst load maintains the published per-tenant latency and fairness envelope |
| `DR-SCALE-RESTORE-001` | an empty-cell restore meets the declared RPO/RTO and preserves hashes, scopes, epochs, and audit continuity |
| `SEC-SCALE-STOLEN-CONTEXT-001` | another tenant role, backend, transaction, JTI hash, or context ID cannot reuse a broker session |
| `SEC-SCALE-REVOKE-BEFORE-ACCEPT-001` | a terminal grant event prevents later acceptance regardless of event ordering |
| `SEC-SCALE-POOL-RESET-001` | commit, rollback, exception, cancellation, and pool return cannot retain tenant context |
| `IT-SCALE-EPOCH-MONOTONIC-001` | placement epoch cannot decrease and `DELETED` cannot return to an active state |
| `IT-SCALE-RESERVATION-RACE-001` | concurrent token/concurrency admission cannot oversubscribe a tenant limit |
| `IT-SCALE-CAPACITY-BINDING-001` | only one fresh exact-manifest receipt is current; expiry and revocation fail closed |
| `CT-SCALE-CELL-ELIGIBILITY-001` | classification, residency, launch-stage, encryption, support-access, or recovery incompatibility refuses placement before it becomes current |
| `IT-SCALE-SEQUENCER-POISON-001` | a poison event quarantines visibly and blocks the cursor until superseded or repaired |
| `CT-SCALE-PRIVILEGES-001` | PUBLIC/application/support/audit/lifecycle/broker privilege matrices match the closed manifest |
| `CT-SCALE-DEDICATED-CONTROL-PARITY-001` | dedicated and OSS profiles retain scope, RLS, identity, audit, quota, and equivalent defense-in-depth controls |
| `SEC-SCALE-CONTENT-FREE-001` | tenant-facing reads reveal no other tenant; authorized control-plane reads expose only approved opaque references, normalized counters, placement metadata, and content-free health summaries |
| `CT-SCALE-DETERMINISTIC-AUTHORITY-001` | model/request output may recommend but cannot establish, authorize, commit, or adjudicate placement, capacity, fairness, lifecycle, billing, or recovery decisions |
| `CT-SCALE-MSR-BOUNDARY-001` | target artifacts remain excluded from the competition release gate and local receipts never satisfy production evidence |

Three tenants are the minimum pairwise isolation/fairness fixture, not scale
qualification. Load qualification runs at the cell's declared
`max_organizations` and at its connection/provider saturation boundary, with
at least one saturating, one ordinary, and one security-negative tenant. It
runs the declared steady load, burst,
provider throttling, SQL failover/reconnect, slow SSE consumer, sequencer
restart, and cell-drain cases. The receipt records exact tenant count,
request mix, model/tool mix, duration, concurrency, data volume, cell manifest,
quotas, pool settings, percentiles, errors, fairness, and cost. Passing a smaller
profile does not qualify a larger one.

## 19. Implementation order

1. Implement target DDL repositories and the static one-tenant
   `PlacementProvider`; add route/spoof and profile-negative tests.
2. Implement the Cell Data Access Broker, exact privilege manifests, backend/
   transaction-bound RLS sessions, and cross-tenant/pool-reset negatives before
   enabling the `SHARED_CELL` profile.
3. Replace per-call production SQL connections with bounded pools and make the
   deployment capacity inequality a preflight gate.
4. Add durable tenant quota policies, reservations, usage settlement, and the
   hierarchical scheduler; preserve per-thread FIFO.
5. Add the committed-event sequencer and content-free fan-out; migrate shared
   profiles away from mutation-time scope-sequence locking.
6. Add tenant provisioning, suspension, movement, export, deletion, and
   content-free proofs.
7. Add shared and dedicated cell Terraform modules plus quota/capacity receipt
   collection.
8. Run the complete isolation, noisy-neighbour, saturation, restore, and
   sovereignty suite before enabling a second production tenant.

## 20. Definition of production-ready

Solvan may describe one exact cell template and capacity profile as
production-ready only when:

- every invariant in §17 has a named passing test;
- the target DDL is promoted through an explicit migration and RLS is active;
- the exact cell's identities, regions, endpoints, quotas, pool budgets,
  backups, encryption, and observability are receipt-bound;
- noisy-neighbour and saturation qualification passes at the published
  envelope;
- restore, movement, suspension, deletion, and legal-hold drills pass;
- all external platform launch stages and limits are rechecked;
- the support-access and incident-response runbooks have named owners; and
- product copy names the qualified profile rather than implying unlimited or
  global scale.

Implementation, unit tests, or a local multi-tenant fixture alone cannot meet
this definition.
