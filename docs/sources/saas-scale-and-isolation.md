# SaaS scale and tenant-isolation source record

Status: researched design input
Retrieved: 2026-08-12
Authority: official Google Cloud documentation only

This record supports specification 19. It records current platform facts and
the design consequences Solvan draws from them. It is not evidence that any
capacity, tenancy, availability, or recovery profile has been implemented or
qualified. Quotas, limits, locations, and launch stages must be rechecked by
deployment preflight.

## Multi-tenant agentic architecture

- [Multi-tenant agentic AI system](https://docs.cloud.google.com/architecture/multi-tenant-agentic-ai-system)

Current official guidance:

- Google presents a hub-and-spoke architecture with a routing hub, a central
  governance/security hub, and isolated tenant projects.
- The strict-isolation example uses a dedicated Google Cloud project, PAB
  policy, VPC Service Controls, tenant-specific Agent Runtime, Model Armor,
  MCP servers, datastore, and model access for each tenant/business unit.
- Google distinguishes dedicated Agent Platform endpoints, which inherently
  isolate project quota, from shared endpoints, which reduce cost but require
  explicit tenant rate limiting/quota enforcement and add operational
  complexity.
- Cloud Run instrumentation must identify the tenant from verified identity
  context rather than an untrusted application value.

Solvan consequences:

- adopt cells rather than one unlimited deployment;
- keep the central routing plane content-free and tenant operational data in
  the assigned cell;
- offer shared and dedicated cells behind one application contract;
- perform tenant admission before consuming a shared Agent Platform quota;
- preserve per-tenant application scoping even inside a dedicated project; and
- use project/PAB/VPC-SC isolation as defense in depth for dedicated tenants,
  not as a replacement for Solvan authorization.

The Google document is a reference architecture, not a statement that every
SaaS tenant must receive a dedicated project. Solvan therefore supports a
shared-cell profile only for compatible policies and qualifies it separately.

## Gemini Enterprise Agent Platform quotas

- [Generative AI on Gemini Enterprise Agent Platform quotas and system limits](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/quotas)
- [Gemini Enterprise Agent Platform quotas and limits](https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/quotas)

On the retrieval date, documented default Agent Runtime quotas for one project
in one region include:

| Resource | Current documented default |
|---|---:|
| Runtime `Query`/`StreamQuery` | 90 requests/minute |
| Session writes | 100 requests/minute |
| Session reads | 10,000 requests/minute |
| Session event appends | 300 requests/minute |
| Memory writes | 100 requests/minute |
| Memory reads | 300 requests/minute |
| Runtime resources | 100 |
| concurrent bidirectional Runtime connections | 10 |

Google documents these quotas at project/region scope and provides quota
increase workflows. General platform quotas also state that project usage is
shared across applications in that project.

Solvan consequences:

- never infer downstream capacity from Cloud Run instance count;
- collect exact quota/capacity receipts for each cell project and region;
- reserve tenant and cell capacity before each provider call;
- use dedicated projects/endpoints when quota or regulatory isolation requires
  it; and
- treat quota increases as unverified until observed and load-qualified.

The numeric values above are source observations, not hard-coded Solvan
limits. The deployment manifest stores the current observed limits.

## Agent Runtime, Sessions, and Memory Bank

- [Agent Runtime](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/runtime)
- [Agent Platform Sessions](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/sessions)
- [Memory Bank](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank)
- [Memory Bank IAM Conditions](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/iam-conditions)

Google describes Runtime as managed production scaling and Sessions as a
conversation-context service. Memory Bank isolates collections by exact scope
and supports IAM conditions for supported exact-scope operations.

Solvan consequences remain deliberately stricter:

- Cloud SQL is the workflow and Liaison transcript authority;
- one reader/attempt receives one disposable Session projection;
- no Session, Memory scope, or cache is shared across tenants or authority
  epochs;
- application authorization and the complete scope triple are applied before
  any provider retrieval; and
- provider service scaling does not replace product admission or fairness.

## Cloud Run autoscaling and concurrency

- [Maximum concurrent requests for services](https://docs.cloud.google.com/run/docs/about-concurrency)
- [Set maximum instances for services](https://docs.cloud.google.com/run/docs/configuring/max-instances)
- [Cloud Run quotas](https://docs.cloud.google.com/run/quotas)

Current official guidance:

- Cloud Run automatically scales revisions and allows an explicit maximum
  concurrency per instance; the documented upper bound is 1,000.
- For a newly created service, the current documented default differs by
  deployment surface: Google Cloud CLI or Terraform uses `80 × vCPU`, while the
  console uses 80. A subsequently configured revision retains its explicit
  setting. Solvan therefore reads the deployed revision and never infers a
  qualified value from either default.
- Lower concurrency can improve scaling/latency for workloads that cannot use
  high parallelism; higher concurrency can reduce instance count and cost for
  efficient I/O-bound workloads.
- A maximum-instance setting can limit cost or protect a backing service such
  as a database, but Google warns that the configured maximum can be exceeded
  briefly during traffic spikes or deployment.
- Regional CPU and memory quotas still bound aggregate scaling.

Solvan consequences:

- record concurrency and instance bounds in the immutable cell manifest;
- calibrate them through load tests rather than accepting defaults;
- budget an observed overshoot factor in the SQL/provider capacity equation;
- keep long-lived SSE connections away from pinned database connections; and
- queue asynchronous agent work before downstream saturation.

## Cloud SQL connections, availability, and recovery

- [Manage database connections](https://docs.cloud.google.com/sql/docs/postgres/manage-connections)
- [Choose how to connect to Cloud SQL for PostgreSQL](https://cloud.google.com/sql/docs/postgres/connect-overview)
- [Cloud SQL for PostgreSQL high availability](https://docs.cloud.google.com/sql/docs/postgres/high-availability)
- [Backup and restore overview](https://docs.cloud.google.com/sql/docs/postgres/backup-recovery/backups)
- [Point-in-time recovery](https://docs.cloud.google.com/sql/docs/postgres/backup-recovery/pitr)

Google documents finite overall connection limits and application connection
pooling. Cloud SQL high availability and recovery facilities do not eliminate
the need to bound client pools or test restore behavior.
Google recommends IAM database authentication where applicable and documents
that Cloud SQL connectors handle automatic IAM-token refresh. Connection-pool
guidance also treats maximum connection lifetime as a bounded setting rather
than allowing pooled connections to live indefinitely.

Solvan consequences:

- production application code uses bounded pools rather than one connection
  per request;
- maximum Cloud Run demand is derived from the tested database connection
  envelope with operational and deployment reserves;
- only stale-tolerant projections may use replicas;
- backup location/encryption must satisfy tenant sovereignty; and
- RPO/RTO and restore claims require exact-cell drill receipts.

## Data residency and security boundaries

- [Agent Platform data residency](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/data-residency)
- [VPC Service Controls overview](https://docs.cloud.google.com/vpc-service-controls/docs/overview)
- [Principal access boundary policies](https://docs.cloud.google.com/iam/docs/principal-access-boundary-policies)

Storage region and model-processing location are separate controls. PAB and
VPC Service Controls can strengthen a dedicated tenant boundary, but neither
derives Solvan tenant identity or replaces row-, object-, API-, channel-, or
tool-level authorization.

Solvan consequence: capacity failure never causes a region or endpoint
spillover. Shared cells admit only compatible sovereignty policies; dedicated
cells add physical/project isolation where required.
