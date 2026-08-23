# Production environment model source record

Status: researched design input; **corrected 2026-08-12 after adversarial review**
Retrieved: 2026-08-12
Authority: official Google Cloud documentation only

> **Correction notice.** An [adversarial review](../reviews/2026-08-12-production-environment-outcome-quality-earned-autonomy-review.md)
> found three defects in the first version of this record. They are corrected
> in place below and marked **CORRECTED**; the original readings are stated so
> the error is visible rather than quietly replaced.
>
> 1. The 100-service / 100-workload / 1,000-element figures are **display**
>    bounds on a topology graph, not discovery or API limits, and Google
>    documents no truncation signal at those bounds.
> 2. App Topology is **Preview** and exposes no documented public REST query
>    resource. This record originally reasoned from Google including
>    platform-generated graphs in App Topology *billing* to a conclusion that
>    Solvan could call the same surface. That does not follow.
> 3. Cloud Asset Inventory **relationship** types require a paid tier, which
>    this record did not state.
>
> The consequent design change — a four-tier source model in which App Topology
> is demoted to optional observed hints — is recorded in the
> [disposition](../reviews/2026-08-12-production-environment-outcome-quality-disposition.md).
> [Specification 20](../../specs/20-production-environment-model.md) now uses
> that four-tier model. This source record remains research input, not runtime
> or cloud verification.

This record supports [specification 20](../../specs/20-production-environment-model.md).
It records what Google's application-topology surfaces actually provide and the
design consequences Solvan draws from them. It is not evidence that any
discovery, reconciliation, approval, or staleness profile is implemented or
qualified. Limits, launch stages, and billing models must be rechecked by
deployment preflight.

## Why this record exists

Solvan already carries an approved, versioned Production Graph in the release
schema (`production_graph_snapshots`, `_nodes`, `_edges`). Nothing populates it
except `tools/seed_demo.py`. The question this record answers is whether Solvan
should build discovery, or consume it.

## App Hub

- [Application-centric Google Cloud](https://docs.cloud.google.com/app-hub/docs/application-centric-google-cloud)

Current official guidance:

- An application is "a logical grouping of components, such as services and
  workloads, that work together to provide business functionality."
- Applications carry governance metadata including "owners, environment, and
  business criticality."
- Management is centralised in a designated **management project** that
  "centralizes all application management tasks, metadata, and APIs" — the
  *application management boundary*.
- Resources are **registered** to an application; App Hub separately tracks a
  registration status, and some correlations appear only when a resource has
  the `discovered` status.

Solvan consequences:

- treat the App Hub application boundary as the natural unit that maps to a
  Solvan `environment_id`, not to a tenant;
- do not re-model criticality, ownership, or environment where App Hub already
  carries them; import them as attributes with provenance;
- registration status is itself evidence about how complete a view is, and must
  be recorded rather than flattened away.

## App Topology API

- [Query and correlate data — App Topology](https://docs.cloud.google.com/hub/docs/app-topology/index)

Current official guidance:

- "App Topology lets you query data about your resources and applications from
  multiple sources, and then view the correlated data as a topology graph."
- The correlated sources are the **App Hub API, Cloud Asset API, Developer
  Connect API, Cloud Monitoring API, Security Command Center API, and Cloud
  Trace API**.
- "Starting September 15, 2026, the App Topology API transitions to a
  usage-based billing model that includes a daily free data usage allotment."
  The new model applies to topology graphs generated within Cloud Hub, Gemini
  Enterprise Agent Platform, and Cloud Monitoring.

**CORRECTED — launch stage and callable surface.** App Topology is **Preview**.
Google documents an interactive query builder and an
`apptopology.applicationTopologies.generate` permission; no public REST
resource or method schema for a general programmatic query surface was found.
Regional availability for ingestion is likewise undocumented — the App Hub
locations page describes App Hub locations, not an App Topology ingestion
endpoint contract.

Solvan consequences, **as corrected**:

- ~~do not build a discovery crawler; the six sources are already correlated by
  a first-party API that the required competition platform also consumes~~. The
  premise does not hold. Google including platform-generated graphs in App
  Topology *billing* establishes that those products generate topology; it does
  not establish that Solvan may call the same surface. **Withdrawn.**
- App Topology is a **tier-4 optional adapter** contributing observed hints
  only. It may never originate an authority-bearing edge, a classification, or
  completeness evidence, and it requires a tested degradation path — which is
  what `AGENTS.md` already demands of any Preview feature and what the original
  reading failed to honour by making it the sole substrate;
- the substrate Solvan can actually build on is documented elsewhere:
  [App Hub API v1](https://docs.cloud.google.com/app-hub/docs/reference/rest)
  exposes `discoveredServices` and `discoveredWorkloads` with `get`, `list`, and
  `lookup`, plus applications, services, and workloads. Its launch stage must be
  pinned at deployment preflight; App Hub for app-enabled folders carries Pre-GA
  Offerings Terms;
- Solvan's contribution remains the governance layer — an approved,
  content-hashed, version-cited snapshot — which never depended on where
  discovery came from;
- billing is usage-based from 2026-09-15, so reconciliation cadence is a cost
  input in the cell manifest. Cost may lengthen a cadence and must never widen a
  staleness ceiling.

## Application topology limits

- [View topology with Application Monitoring](https://docs.cloud.google.com/monitoring/docs/application-topology)

Current official guidance:

- "the graph **displays** at most 100 discovered services and 100 discovered
  workloads" for each supported App Hub region.
- "The topology graph **displays** at most 1000 nodes or connections."

**CORRECTED — these are display bounds, not discovery bounds.** The first
version of this record read them as limits on what discovery returns and built
a `TRUNCATED` completeness signal on them. The page says *displays*, describes
a rendered graph, and documents no truncation marker emitted at those bounds. A
completeness model cannot be derived from a rendering limit.

What replaces it: completeness must come from paginated API responses whose
page tokens and result counts Solvan can reason about, per tier. A graph built
from tiers 1–2 alone is structurally incomplete on dependency edges, and an
environment without the tier-3 licence below can never be `COMPLETE` — which
the specification must state rather than let a deployment discover.
- Topology requires that trace data carry application labels, which are
  available only when you "instrument your app with OpenTelemetry", "send your
  trace data to the Telemetry API", and "register your application with App
  Hub".
- Certain resources — Firestore, Spanner, Cloud Storage, Google Cloud MCP
  servers — "only display connections when the corresponding service or
  workload has an App Hub registration status of `discovered`".

Solvan consequences:

- **a discovered graph is bounded and may be incomplete, and Solvan must know
  which.** Completeness is a first-class recorded property of every snapshot,
  not an assumption;
- a truncated or partially failed discovery may inform an investigation but may
  never authorise autonomous action;
- OpenTelemetry instrumentation is a precondition for edge discovery, so an
  un-instrumented service appears as an isolated node rather than as an absent
  dependency, and the difference must be visible to an operator.

## Cloud Asset Inventory

- [Cloud Asset Inventory overview](https://docs.cloud.google.com/asset-inventory/docs/overview)

- [Relationship types](https://docs.cloud.google.com/asset-inventory/docs/relationship-types)

Solvan already registers `cloud_asset_inventory_search` in the governed tool
catalog with the stated purpose "resolve registered resource kinds into a
Production Graph candidate", so resource existence is an existing, contracted
read.

**CORRECTED — declared dependency edges are licence-gated.** Asset Inventory
**relationship** types are supported in the export, list, search, and monitor
APIs, but require **Security Command Center Premium or Enterprise, or Gemini
Cloud Assist**. The first version of this record treated declared edges as
freely available. They are a commercial precondition, and an environment
without that entitlement cannot produce a complete declared dependency graph.

Solvan consequences: Asset Inventory establishes that a resource *exists* and
what kind it is, without a licence. Its relationship types add declared
dependency edges, with one. Neither establishes that one resource *may call*
another — that is IAM policy, which is the authority-bearing tier and carries
no such gate.

## Cloud Trace

- [Cloud Trace overview](https://docs.cloud.google.com/trace/docs/overview)

Solvan already registers `cloud_trace_read`. Trace-derived edges are
*observed* behaviour.

Solvan consequence, and the load-bearing one for specification 20: an observed
edge and a declared edge are different claims. A call seen in traces but absent
from infrastructure-as-code is a finding about the estate, not merely a line in
a graph — and an edge that exists only because it was observed must never be
promoted into an authorisation-bearing edge kind.

## What the documented surfaces do not provide

Recorded so specification 20 does not imply otherwise. **CORRECTED** phrasing:
the first version claimed Google "does not provide" these, which asserts
universal nonexistence. The checkable claim is narrower and is the one made
here — the surfaces reviewed on the retrieval date do not provide them.

- no approval workflow over a topology version;
- no immutable content hash of a topology snapshot that an investigation can
  cite months later;
- no staleness contract binding topology freshness to permitted automation;
- no separation between declared intent and observed behaviour;
- no tenant/classification/residency filter applied before retrieval — and for
  App Topology specifically this is worse than absent. Google documents that it
  can read application and discovered-resource metadata across descendant
  projects even when those projects sit outside the management project's VPC
  Service Controls perimeter. The first version of this record asserted that
  tenant, classification, and residency filters apply before retrieval; that is
  unsupported for this source and possibly contradicted, and must be proven at
  request level before App Topology is treated as a governed source. It is a
  further reason the source is demoted to tier 4.

These five are exactly the Solvan layer.
