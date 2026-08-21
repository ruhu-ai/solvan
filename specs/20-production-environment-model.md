# Solvan production environment model — governed topology

Status: target product contract; implementation-ready at the local DDL/oracle
boundary; excluded from the Minimum Submittable Release gate. No customer
estate, cloud source, movement, purge, or authorization path is verified by
this document.

Related: [architecture](02-system-architecture.md),
[security](05-security-governance.md),
[evaluation](08-test-evaluation-acceptance.md),
[tool catalog](16-governed-tool-catalog.md),
[SaaS isolation](19-saas-scale-and-isolation.md),
[target DDL](artifacts/production-graph-schema.target.sql), and the
[official source record](../docs/sources/production-environment-model.md).

## 1. Purpose and boundary

The release graph is hand-seeded. This target defines how a real estate may be
reconciled without allowing provider discovery, a model, or an old placement to
become workflow authority.

> Discovery is untrusted evidence. Cloud SQL holds the approved, immutable,
> version-cited graph used by Solvan.

The target schema remains separate from `artifacts/schema.sql`. Until the
runtime, cloud qualification, movement, purge, and authorization fixtures pass,
product copy must say `target`, not `implemented` or `verified`.

## 2. Four source tiers

Solvan does not depend on an undocumented App Topology query API. It reconciles
documented sources independently and records completeness per tier.

| Tier | Source | Authority | Required for `COMPLETE` | May originate |
|---|---|---|---|---|
| 1 | App Hub API v1 | application catalog | yes | services/workloads and governed ownership, environment, criticality attributes |
| 1 | Cloud Asset Inventory `searchAllResources` | resource catalog | yes | resource existence, location, and holding project — no attribute, no edge |
| 2 | Cloud IAM policy | identity authority | yes | `ALLOWED_TO_CALL` only |
| 3 | Cloud Asset Inventory relationships | declared relationship evidence; paid entitlement required | yes | declared dependency/storage edges |
| 4 | App Topology or Trace adapter | observed hint; Preview adapters degrade safely | no | `DEPENDS_ON_OBSERVED` only |

Cloud Asset Inventory appears at two tiers because it answers two different
questions under two different entitlements. `searchAllResources` needs only
`roles/cloudasset.viewer` and establishes **what exists, where, and in which
project** — the minimum that makes a first snapshot possible for a customer who
has never configured App Hub. Relationship queries need Security Command Centre
Premium or Enterprise and establish **declared dependency**. Conflating them
would make the cheaper read appear to carry dependency authority it does not
have.

The search source therefore originates nodes and **no edges**, and sets no
governed attribute: ownership, environment, criticality, classification,
authorization boundary, and verification profile stay absent rather than being
inferred from a resource name or label. A snapshot built from it alone is
`INCOMPLETE` for dependency authority — truthfully edgeless rather than
silently complete.

A refused, unreachable, or API-disabled search is **not** an empty estate. Each
refuses distinctly, because recording a denial as "no resources found" would let
a snapshot assert that a customer runs nothing and let every completeness check
downstream agree with it. An estate larger than the paginated bound reports
`PARTIAL` rather than truncating, for the same reason: silent truncation reads
as a complete, smaller production system.

Cloud Asset Inventory without relationship entitlement can still establish
resource existence, but the snapshot is `INCOMPLETE` for dependency authority.
Tier 4 never establishes completeness, classification, permission, ownership,
or criticality. Its unavailability cannot erase a declared edge.

Each source policy is an immutable revision carrying its launch stage,
entitlement posture, allowed node/edge kinds, and policy hash. Every element
references the exact observation and policy revision that permitted its kind.
Registering a safe source policy is insufficient; the element insert enforces
it again.

## 3. Scope, placement, and sovereignty

Every operational record binds the complete scope plus `cell_id` and
`placement_epoch` through a composite foreign key. Reconciliation begins only
for the current `ACTIVE` placement. Region and classification are filtered
before an observation becomes an element.

The coordinator's connector registry is deployment-owned but not globally
scoped. `SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON` is a closed, versioned envelope
containing the exact organization, project, and environment triple plus the
named source configuration. The coordinator and API compare all three values
to the active verified deployment scope before accepting the registry. A
missing registry disables execution; malformed, extra-field, or cross-scope
configuration refuses. This envelope contains endpoint/resource mappings only,
never credentials. Shared SaaS cells require an equivalent scoped secret or
database binding per tenant placement; they cannot reuse one unscoped registry.

A placement transition fences the run. The destination requires a new run and
human-approved first snapshot; prior snapshots remain historical evidence and
cannot authorize there. Tenant deletion removes graph content through the
SaaS purge graph. `quality_purge_scope` runs before `graph_purge_scope`; both
lock and validate the same exact `DELETE` lifecycle job in `VERIFYING`, and the
graph function leaves only a content-free scoped count/digest receipt.

## 4. Reconciliation and completeness

A coordinator-owned, leased, single-flight run:

1. begins as `PENDING` with an authoritative `requested_at` and no
   `started_at`; the API freezes the current placement and source-policy set
   without calling a provider;
2. is claimed by the coordinator under one exact lease token, which sets
   `started_at`, after which cloud reads occur without holding a database lock;
3. invokes each frozen, scope-bound source once through a governed read profile;
4. exhausts documented pagination and records response digest, page count,
   element count, region, and outcome—never provider payload;
5. re-locks the exact run, lease token, placement, and placement epoch before
   accepting any result; a stale worker writes no observation or draft;
6. writes all observations, source-bound nodes and edges, tier summaries,
   findings, diff, finalized `DRAFT`, and terminal run state in one Cloud SQL
   transaction;
7. records one outcome for every exact source revision in the pinned set and a
   derived roll-up for each tier;
8. derives the snapshot content and governed-material hashes in Cloud SQL; and
9. computes a typed diff against the exact approved predecessor.

`COMPLETE` means every exact source revision marked `required_for_complete` in
the run's immutable source-policy set completed all pages. One complete source
cannot stand in for another source merely because both occupy the same tier.
`PARTIAL`, `NOT_ENTITLED`, `UNAVAILABLE`, refusal, a missing required-source
observation, or partial pagination makes the snapshot `INCOMPLETE`. Tier status
is a display and policy summary, never the completeness authority. Console
display bounds are not ingestion limits and are never used as completeness
evidence.

## 5. Governed material projection

The material hash includes nodes, edges, source authority, and every attribute
that can affect ownership, blast radius, authorization, or verification:

- owner/responsible team;
- declared environment and business criticality;
- data classification and region/residency;
- authorization boundary;
- verification profile;
- resource and node/edge kind;
- instrumentation state and completeness; and
- source key/policy revision.

A catalog is allowed to leave a resource's data classification unknown. Before
promotion into the authoritative release projection, SQL deterministically
applies the active environment's approved classification ceiling as the
resource's conservative handling label. Both the effective classification and
the provenance marker (`SOURCE` or `ENVIRONMENT_CEILING`) are included in the
reviewed material hash and projected attributes. This fallback may restrict
access more than necessary; it never lowers the authored ceiling or claims the
provider observed a classification.

Unknown changes are material. Labels or descriptions not used by any decision
may be excluded only by a new reviewed material-projection revision. The diff
stores derived counters for each governed category; callers do not assert a
`MATERIAL`/`IMMATERIAL` label.

Two catalog sources may name the same underlying resource. Reconciliation
requires identical node kind, resource identity, holding project, and region;
any disagreement refuses the draft. It also refuses two non-null, unequal
governed values. When the observations agree, one whole source-bound assertion
is selected deterministically by governed-field completeness, instrumentation
specificity, and source revision. Fields are never spliced across sources,
because that would create a synthesized assertion with no truthful observation
provenance. The other source remains an immutable corroborating observation.

## 6. Promotion

Only `graph_promote_snapshot` changes graph authority:

- the first snapshot requires a named human;
- a human approves the exact finalized content hash;
- automatic promotion requires the exact currently approved predecessor, zero
  governed changes, equal material hash, complete required tiers, and no prior
  rejection of the candidate content;
- promotion atomically retires the predecessor and approves the candidate;
- the same transaction materializes the candidate's exact snapshot, nodes, and
  edges into `solvan.production_graph_*`, which is the sole graph authority
  consumed and cited by incidents, evidence, verification, and action policy;
- a candidate approval and its authoritative projection cannot commit
  independently, and current-graph reads require the matching approved
  projection rather than trusting reconciliation history alone;
- an incomplete snapshot may be human-approved for assisted reasoning but is
  never autonomy-eligible; and
- models have no reconciliation or promotion tool.

Direct status updates and direct promotion-receipt inserts refuse. Promotion
decisions and citations are immutable history.

### 6.1 Console review boundary

The target console uses four authenticated routes, all scoped from the verified
deployment environment rather than from request fields:

- `GET /api/v1/production-graph/status` returns the current placement, exact
  active source-policy revisions, recent durable reconciliation runs, and
  candidate/approved snapshot summaries. It never returns provider payloads.
- `POST /api/v1/production-graph/reconciliations` accepts only
  `schema_version=1` and a request id equal to `Idempotency-Key`. The API
  resolves the active placement and newest non-retired source revisions from
  Cloud SQL, persists a `PENDING` run, and performs no provider call. A
  coordinator-owned worker later claims and executes it; the request or model
  cannot choose sources, scope, region, cell, or placement epoch.

- `GET /api/v1/production-graph/{snapshot_id}/review-material` returns the
  candidate's exact content/material hashes, predecessor identity, derived
  governed-change counters, source-tier outcomes, and typed findings. It does
  not return provider payloads or bypass the normal identity/read gate.
- `POST /api/v1/production-graph/{snapshot_id}:promote` accepts
  `schema_version=1`, `decision_id`, `mode=HUMAN_APPROVED`,
  `expected_content_hash`, and a typed `reason_ref`, with
  `Idempotency-Key` equal to `decision_id`. The application re-reads the
  candidate, checks the exact hash and review policy, then calls only
  `graph_promote_snapshot`.

The route returns `503 GRAPH_TARGET_SCHEMA_UNAVAILABLE` when the target schema
is not installed; it never substitutes a local fixture or an older approved
snapshot. `AUTO_PROMOTED` is not accepted on the human console route. The
coordinator's workload-identity adapter may call the same typed repository
with `AUTO_PROMOTED` only after the exact predecessor, zero governed-change,
complete-tier, and rejection checks in this section and the SQL function pass.

The console keeps the operator token only in component memory, never browser
storage, and clears it after each discovery, review, or promotion command. A
review command renders only the exact hash-bound projection above: content and
material digests, predecessor and diff digest, governed-change counters, tier
outcomes, findings, completeness, and post-promotion autonomy eligibility. The
approval control stays disabled until the operator re-enters a token and the
loaded projection is a finalized `DRAFT` with a content hash. The browser sends
that exact hash; it never creates a reason reference for an external record
that does not exist. Active `PENDING` and `RUNNING` reconciliations may be
polled, but each poll is a read and never repeats the enqueue command.

## 7. Staleness and action authorization

Staleness policies are immutable revisions with one current, monotonic binding
per scope. The authorization transaction computes age from the approved
snapshot's `reconciled_at`; stored age fields are not authority.

An autonomous reservation refuses unless the snapshot:

- belongs to the current active placement;
- is the one approved snapshot for the scope;
- is `autonomy_eligible` and `COMPLETE`; and
- is no older than the current autonomy ceiling.

Assisted investigation may use an older approved snapshot if its age is
rendered and within the assisted ceiling. Severity, urgency, capacity, retry,
or model output cannot widen either ceiling.

## 8. Findings and uncertainty

Findings are typed records, not factual claims:

| Finding | Meaning |
|---|---|
| `UNDECLARED_DEPENDENCY` | an observed edge lacks declared support |
| `UNOBSERVED_DECLARATION` | a declared edge had no observation in the stated window |
| `UNINSTRUMENTED_COMPONENT` | dependency absence is unknowable |
| `ORPHANED_RESOURCE` | a resource has no application ownership |
| `SOURCE_INCOMPLETE` | a required source was unavailable, unentitled, refused, or did not exhaust pagination |
| `CLASSIFICATION_CONFLICT` | source metadata conflicts with the ceiling |

A subject is exactly one node, one edge, or—for `SOURCE_INCOMPLETE` only—one
exact source-policy revision. Partial unique indexes prevent the
nullable-uniqueness hole. No finding satisfies a conversational claim predicate
without separately cited ledger evidence.

## 9. Citations

Every Agent run, hypothesis, authorization, verification, and conversational
turn that uses topology records an immutable citation to the exact scoped
snapshot and consumer attempt. A later attempt may cite a later snapshot; the
old citation is never overwritten.

Graph reads default to the current approved snapshot. Draft reads require an
explicit operator review route and cannot feed authorization.

The ordinary read returns the exact snapshot id and version, reconciliation
timestamp, database-derived current age, completeness, current
autonomy-eligibility verdict, assisted-use verdict, cell, placement epoch, and
staleness-policy binding epoch. Callers never accept a stored age or recompute
eligibility from an incomplete subset of those operands. A missing current
placement, approved snapshot, or current policy binding returns no graph rather
than a best-effort predecessor.

## 10. Threat model

| Threat | Control |
|---|---|
| trace grants permission | tier-4 edge allow-list plus element trigger |
| forged observation or snapshot reference | composite foreign keys |
| provider result silently partial | exhausted pagination and per-tier outcomes |
| ownership/criticality change auto-promotes | governed material hash and derived diff counter |
| first snapshot inherits nonexistent approval | human-first promotion rule |
| rejected content is replayed | content-hash rejection check |
| two current staleness policies | unique active binding |
| move reuses old topology | current placement fence and composite epoch identity |
| model mutates graph | no write tool; deterministic coordinator/application functions |
| catalog omits classification | environment ceiling is a conservative, hash-bound handling fallback with explicit provenance |
| nullable duplicate finding | separate node/edge partial unique indexes |

## 11. Invariants

- **INV-PG-01** Ingestion writes `DRAFT` only; promotion is function-only.
- **INV-PG-02** Every element is bound to an observation and immutable source
  policy that permits its exact kind; observed hints cannot carry authority.
- **INV-PG-03** At most one approved snapshot exists per scope and promotion
  supersedes it atomically.
- **INV-PG-04** The first snapshot is human-approved; automatic promotion uses
  the exact predecessor and zero governed change.
- **INV-PG-05** Completeness is derived per required tier from exhausted
  pagination; incomplete snapshots are never autonomy-eligible.
- **INV-PG-06** One current staleness policy governs authorization and age is
  computed from authoritative timestamps.
- **INV-PG-07** Every graph consumer attempt cites one immutable scoped
  snapshot; citations cannot dangle or move.
- **INV-PG-08** Observations keep metadata/digests only and are append-only.
- **INV-PG-09** Findings never become claims without an independent predicate.
- **INV-PG-10** Uninstrumented means unknown dependencies, never none.
- **INV-PG-11** Scope, cell, placement, region, and classification are fenced
  before element storage and again before prompt construction.
- **INV-PG-12** No model can reconcile, promote, select, or weaken a graph used
  for authorization.
- **INV-PG-13** This target does not enlarge the MSR.
- **INV-PG-14** Purge removes tenant graph content and emits only a content-free
  deletion receipt; it refuses unless quality evidence was removed first and
  the exact lifecycle job is in its verified purge phase.
- **INV-PG-15** A source registry is accepted only for its exact verified scope;
  malformed, extra-field, and cross-scope registries refuse before cloud I/O.
- **INV-PG-16** A worker performs each frozen provider read once and may publish
  the graph only after revalidating its exact lease and current placement; stale
  work publishes nothing.
- **INV-PG-17** One reconciliation transaction commits the complete draft and
  terminal run state or neither; no partial graph is operator-visible.

## 12. Acceptance fixtures

| ID | Required proof |
|---|---|
| `SEC-PG-OBSERVED-AUTHORITY-001` | a tier-4 observation cannot insert `ALLOWED_TO_CALL` |
| `SEC-PG-PROVENANCE-MISMATCH-001` | element source and observation must match |
| `IT-PG-PAGINATION-001` | a complete observation requires exhausted pagination |
| `IT-PG-FIRST-HUMAN-001` | first auto-promotion refuses with the named error |
| `IT-PG-MATERIAL-HASH-001` | ownership, criticality, environment, policy, region, source, instrumentation, or structure changes prevent auto-promotion |
| `IT-PG-PROMOTION-ONLY-001` | direct status/decision writes refuse |
| `IT-PG-STALE-AUTONOMY-001` | stale/current race is fenced in the action-reservation transaction |
| `IT-PG-CITATION-IMMUTABLE-001` | dangling and rewritten citations refuse |
| `IT-PG-NULL-FINDING-001` | nullable subjects cannot admit duplicates |
| `IT-PG-MOVE-001` | placement movement invalidates the old run/snapshot for authorization |
| `IT-PG-PURGE-001` | purge leaves only the content-free terminal receipt |
| `SEC-PG-SOURCE-SCOPE-001` | malformed, extra-field, and another-scope deployment registries refuse before provider dispatch |
| `IT-PG-WORKER-ONCE-001` | each exact frozen source is read once and the stored graph is built from those frozen typed results |
| `IT-PG-WORKER-STALE-001` | a lost lease or moved placement writes no observation, draft, or terminal state |
| `IT-PG-WORKER-ATOMIC-001` | a draft write failure rolls back observations, elements, findings, diff, finalize, and terminal settlement together |
| `IT-PG-EARNED-ACTION-ATOMIC-001` | standing action, preauthorization, pinned current graph, competence, falsification high-water, placement, and latest connector capacity are re-derived and reserved in one serializable transaction |
| `IT-PG-PREPARED-RECOVERY-GATE-001` | a `PREPARED` crash recovery reruns the current graph and earned-autonomy gates before the sole mutation claim |

Every SQL negative oracle must assert exact SQLSTATE, constraint/application
error, and message. A failure for a different reason proves nothing.

## 13. Implementation order

1. Target DDL/functions/oracles and source-policy revisions.
2. Tier 1–3 read adapters and draft reconciliation; tier 4 remains optional.
3. Typed diff repository and human review UI.
4. Atomic promotion and immutable citation repository.
5. Staleness check inside the earned-autonomy reservation transaction.
6. Movement, purge, and hostile cloud qualification.
7. Production enablement only after a status decision and real receipts.

## 14. Definition of done

This target becomes `implemented` only when the runtime follows the DDL
contract end to end and all §12 fixtures pass. It becomes `verified` only after
a real eligible estate proves tier pagination, authority, movement, purge, and
staleness behavior. Local SQL proof is neither status.
