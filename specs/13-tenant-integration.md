# Solvan tenant integration — observe and actuate

Status: target product contract; excluded from the Minimum Submittable Release
gate. Two connector additions in §5.3 are MSR-relevant and marked `required`.
Related: [architecture](02-system-architecture.md),
[data/API](04-data-event-api.md),
[security](05-security-governance.md),
[Ruhu profile](11-ruhu-integration-profile.md),
[governed Tool Catalog](16-governed-tool-catalog.md),
[SaaS scale and isolation](19-saas-scale-and-isolation.md),
[Solvant Relay](22-solvant-relay.md),
[decisions](../docs/OPEN-DECISIONS.md),
[DDL](artifacts/schema.sql)

This specification generalizes the Ruhu adoption profile into the commercial
integration model: how Solvan reads a customer's production estate, and how it
changes it without ever holding standing write authority over it.

Specification 19 governs where that tenant runs and how shared capacity is
isolated. Direct, Relay, and remediation paths do not choose a cell,
relax a quota, or override a tenant's home region.

## 1. Decision

Solvan connects to customer production through two structurally separate
customer-side products, plus a direct read path for fastest onboarding.

| Posture | Deployment | Credentials Solvan holds | Capability |
|---|---|---|---|
| **1a · Direct** | none | federated read (GCP) or stored read keys (vendor) | detect, investigate, own cases, escalate |
| **1b · Relay** | separate `solvant-relay` image, read-only policy | none | same as 1a, with zero customer credentials leaving their estate |
| **2 · Remediate** | separate Action Actuator image, write policy | none | adds approval-bound, policy-bound production actions |

Relay and Actuator may share audited identity, cryptography, policy, and
telemetry libraries, but they are different executables, images, identities,
audiences, dependencies, registries, APIs, deployment bundles, and release
receipts. Enabling remediation is a separate customer decision and deployment;
a configuration switch cannot add mutation code or IAM to a Relay.

Solvan never holds a credential that can mutate a customer's production. The
control plane holds *authorization*; the customer-deployed actuator holds
*capability*. Separating those two is the load-bearing property of this
design.

### 1.1 Production onboarding order — target

The first usable customer path is **direct, read-only Google Cloud
observation**. It uses a customer-owned per-estate Google service account and
a narrowly scoped, cross-project impersonation grant to the exact Solvan
reader workload identity, an exact external-resource scope, a successful
capability probe, and an approved source binding. It does not require Solvant
Relay. This is the default for a customer estate that permits Solvan's regional
control plane to read its selected Google Cloud APIs.

Solvant Relay is the optional second path for a private, hybrid, or
credential-egress-constrained estate. It gives the customer the same bounded
read capability while retaining provider credentials and provider network
access inside their estate. Relay enrollment must never be presented as a
prerequisite for direct GCP observation, and direct observation must never be
an automatic fallback after a Relay refusal.

### 1.2 Control-plane residency and workload location

Solvan's control-plane residency and a customer's workload location are
different facts. A tenant's cell, Cloud SQL, GCS evidence objects, logs,
traces, signing keys, and support processing remain in the tenant's approved
control-plane region. A customer workload may be in another region only when
the frozen Production Graph node, current environment authorization, exact
connection capability receipt, and provider evidence all name that same
**workload region**. There is no region inference, wildcard, or fallback.

A direct connection can read an explicitly authorized `europe-west2` workload
from a tenant whose Solvan cell is in `europe-west1`; Relay is not required
merely because those regions differ. Relay remains the path for private network
access, customer-held credentials, on-premises sources, or a customer choice to
perform collection locally. The Relay's own location is separately qualified
and its accepted projection is stored only in the tenant's control-plane region.

`tenant_connections.residency_region` means control-plane data residency. It
does not authorize a provider request. `workload_region` is immutable scope
material and is part of every graph target, environment binding, capability
coverage record, frozen Tool binding, provider attribution, Relay policy, and
accepted evidence projection. Changing either invalidates prior proof and
requires a new fenced probe or qualification.

The production onboarding sequence is therefore:

1. an administrator creates an estate and environment scope, then selects
   direct read-only GCP observation or customer-resident Relay;
2. the console emits exact customer-run IAM, customer reader service-account,
   and delegation-condition instructions, without receiving a credential value
   or private key;
3. the customer registers or binds the resulting identity and source scope;
4. Solvan executes a minimal, fenced probe and records observed capability,
   coverage, expiry, and any missing grant;
5. for Cloud Monitoring, the customer separately creates the exact
   authenticated notification delivery and Solvan records its immutable source
   binding; and
6. only a fresh probe and source binding enable read-only alert triage. An
   operator, not a provider delivery, creates the first Incident.

A service-account key is not a production-pilot onboarding route for GCP.
`FEDERATED_SHORT_LIVED` is required for the direct GCP pilot and its required
authentication mode is `GCP_SERVICE_ACCOUNT_IMPERSONATION`. Workload Identity
Federation is the distinct path for external workloads, such as eligible
customer on-prem hosts; it is not a substitute for the Google-to-Google
delegation required here. A long-lived key may be considered only through a
separately reviewed vendor-connector posture and can never supply mutation
authority.

Connections expose observed capabilities; they do not create new agents.
Institutional Agents receive exact immutable capability profiles resolved by
the coordinator under specification 16. A GKE, AWS, Datadog, Prometheus, or
GitHub integration therefore changes the allowed tool set for an Evidence or
Infrastructure Agent without creating a vendor-specific authority silo.

## 2. Design constants

1. **Authorization ≠ capability.** A compromised control plane can request
   only what the customer's local policy already permits.
2. **Fail closed on absence.** Missing policy, unreachable identity provider,
   unparsable configuration, or unset required environment resolves to refuse,
   never to permit. No configuration value may silently downgrade a control.
3. **Identity comes from verified claims only.** Never from a request header,
   body field, or model output.
4. **Credential posture is data, not prose.** Every connection records whether
   its credential is federated-short-lived, stored-long-lived, or
   customer-side-none, and the console renders it.
5. **Effect is predicted before it is caused.** Every mutation is dry-run and
   compared against the declared expected effect before execution.
6. **Undo is observed, not declared.** The rollback plan is derived from the
   pre-state read at execution time, not from a plan authored earlier.

## 3. Identity and hosting

### 3.1 Customer-side workload identity

Each Relay or Actuator authenticates to Solvan with its own verified,
audience-bound workload OIDC token. Google-hosted workloads use Google-signed
identity; eligible on-prem workloads use the separately registered Workload
Identity Federation path. Solvan validates signature, issuer, audience, expiry
and subject/principal against the exact registered customer-side workload.
Relay and Actuator audiences and principals are never interchangeable.

There is no shared secret in either direction. Solvan proves authorization
with digest-bound, expiring action payloads; the actuator proves identity with
a Google-signed assertion. Neither side provisions or rotates a secret for the
other.

### 3.2 Supported hosts

| `host_kind` | Identity mechanism | Production eligible |
|---|---|---|
| `CLOUD_RUN_SERVICE` | native Workload Identity, no key material | yes — Actuator only |
| `CLOUD_RUN_WORKER_POOL` | native Workload Identity, no key material | yes — Relay after exact regional qualification |
| `GKE` | Workload Identity; required when targets sit behind a private control plane or private IP | yes |
| `ONPREM_FEDERATED` | Workload Identity Federation through the customer's own OIDC issuer | yes |
| `ONPREM_KEYFILE` | service-account key file | **only with a recorded risk acceptance** |
| `DEV_LOCAL` | any | **never** — development and contract tests only |

`ONPREM_KEYFILE` reintroduces a long-lived credential inside the customer
estate. It is supported because hybrid customers exist, and it requires
`risk_acceptance_ref` to be non-null. `DEV_LOCAL` is structurally barred from
production eligibility by database constraint, not by convention.

### 3.3 Read credentials and their posture

| Read path | Credential | Posture value |
|---|---|---|
| GCP APIs via customer service-account impersonation | short-lived, auto-rotated, no key exists | `FEDERATED_SHORT_LIVED` |
| Datadog · Grafana · New Relic · Prometheus API | long-lived key Solvan stores | `STORED_LONG_LIVED` |
| Reads performed by Solvant Relay | none — nothing leaves their estate | `CUSTOMER_SIDE_NONE` |

Vendor API integrations widen reach to non-GCP estates and are the reason
tier 1a can onboard an AWS or hybrid customer. They also make Solvan a holder
of long-lived customer secrets, which is precisely the property the write-side
architecture exists to avoid. Therefore, for every `STORED_LONG_LIVED`
connection:

- the key is stored only as a Secret Manager reference with per-tenant CMEK;
  the value never enters Cloud SQL, logs, traces, events, or model context;
- onboarding must verify the key is read-only scoped and reject it otherwise;
- the console displays the posture on the connection and in the fleet
  governance matrix — a weaker posture is visible, never silent;
- rotation reminders and revocation are first-class connection operations.

`CUSTOMER_SIDE_NONE` is the strongest posture and is available at tier 1b
without enabling any mutation.

### 3.4 Direct GCP identity binding — target

### 3.5 Local-connected development

Local development may exercise real read-only Google Cloud integrations without
deploying the Solvan application. This is an identity topology, not a second
connection type:

- the locally running control plane uses Application Default Credentials that
  attest one dedicated development service account in the Solvan-owned
  development project;
- the monitored Google Cloud project, workload region, providers and
  customer-owned reader service account are selected only through the normal
  Integrations API and console; the launcher and ambient `gcloud` project are
  not routing authority;
- the customer reader grants the Solvan development identity only
  `iam.serviceAccounts.getAccessToken`, and the reader itself holds only the
  selected read roles in the selected project;
- the credential-bearing Direct GCP Reader remains a separate process with no
  Cloud SQL authority. Locally it listens only on a worktree-scoped Unix
  socket. A per-start random bearer secret stored in a mode-0600 file
  authenticates the local API and detector to that socket; the production
  reader continues to require Google-signed, audience-bound workload identity;
- user or workforce ADC may only mint the configured short-lived Solvan
  development identity; it is never used directly as provider read authority.
  A different effective service account, a key file, or an unverified target
  is refused. The launcher displays the effective Solvan identity and control
  project before enabling the Integrations commands;
- local-connected mode is always `DEV_LOCAL` and `NO_PRODUCTION_AUTHORITY`.
  It cannot start or call an actuator, GitHub mutation provider, deployment
  controller or release verifier, and it cannot produce a staging or
  production qualification receipt.

The local reader boundary is not a permissive configuration branch in the
production binary. It has a distinct local entry point and transport. Removing
the Unix-socket path or its secret refuses the request; it never falls back to
ambient credentials or a network listener.

The Integrations console exposes a local-only monitored-resource step after a
`READY` Cloud Monitoring connection exists. An administrator binds one exact
connection epoch, signal kind, Cloud Run service or Cloud SQL instance,
comparator, threshold, sustained-window count, and severity. The API derives
the external project from the connection rather than accepting it again. The
resulting service and rule carry `local-development://` calibration and
decision references and therefore cannot qualify a deployed environment. A
separate authenticated loopback worker asks the detector to evaluate, then
applies only the resulting durable inbox claims with the production Incident
transition handler; it starts no Agent, publisher, actuator, or release path.

The connection form links directly to a same-origin, bookmarkable Google Cloud
setup guide. The guide explains where every field comes from, distinguishes a
Google project ID from its display name and numeric project number, distinguishes
workload location from Solvan control-data residency, and walks through the
customer reader, generated grant, registration, probe, and monitoring-rule
sequence. It never asks for or teaches creation of a service-account key. The
connection card renders the external GCP project, workload region, and
control-data region as three separately labelled facts; an unlabelled region is
prohibited because it lets an operator mistake residency for provider reach.

Credential posture describes secret residency; it does not identify the
authentication protocol. A direct GCP connection declares exactly one closed
authentication mode:

| Authentication mode | Eligible use |
|---|---|
| `GCP_SERVICE_ACCOUNT_IMPERSONATION` | Solvan Google Cloud workload reads one customer Google Cloud estate |
| `EXTERNAL_WORKLOAD_IDENTITY_FEDERATION` | customer-owned external workload authenticates to Google Cloud |
| `STORED_SECRET_REFERENCE` | separately approved non-GCP read connector |
| `CUSTOMER_SIDE_NONE` | provider read stays entirely in a qualified Relay |

A direct GCP connection requires `GCP_SERVICE_ACCOUNT_IMPERSONATION`, the
exact Solvan reader service-account principal, one customer-owned reader
service-account principal per estate, a digest-pinned exact delegation binding,
an external-resource scope, and a maximum access-token lifetime of 900 seconds.
The token target, service account, scope, and lifetime are resolved from the
immutable connection revision only. They are never selected from process
environment, a request, a model tool call, or an operator-supplied identifier.

The customer reader service account receives only the approved read roles for
the bound source and resource scope. The exact Solvan reader identity receives
only `roles/iam.serviceAccountTokenCreator` on that customer service account,
through an unconditional binding on that exact service-account resource. The
binding is not project-wide: attaching it to the customer reader is the scope.
It must not add a `resource.name` IAM Condition because Google IAM resources do
not expose that condition attribute and the binding would never grant token
minting. Solvan records a digest over the exact target resource, member, role,
and absent condition. Project-wide grants, group grants,
default service accounts, broad workforce pools, and an ability to mint a token
for another service account are refused. The customer configures delegation and
Data Access audit logs; Solvan stores only safe audit references and the
verified principal/delegation chain.

Changing the customer reader principal, delegator, condition digest, resource
scope, role/capability receipt, or token-lifetime ceiling advances the
connection epoch and makes every prior probe and source binding stale. No
connection is `READY` until the new fenced probe proves that exact binding.

## 4. Capability discovery

After a connection is registered, Solvan probes what it can actually do and
records the result. Capability is **observed**, never assumed from
configuration.

Every configured provider instance is a separate connection. Its immutable
identity includes `connection_id`, provider, tenant scope, environment,
external project/account/workspace, region, credential posture, owner, and
purpose. Display names such as `ruhu-prod-europe-west1` are operator labels,
not authorization keys. Solvan has no implicit default project, account,
region, cluster, namespace, repository, telemetry tenant, or collaboration
workspace.

The current connection availability is derived from the newest non-superseded
probe and configuration lifecycle, using this closed vocabulary:

| Availability | Meaning | Selectable for new work |
|---|---|---|
| `NOT_CONFIGURED` | required enrollment or credential reference is absent | no |
| `PROBING` | one fenced minimal probe is running | no |
| `READY` | every capability required by the selected profile has fresh proof | yes |
| `DEGRADED` | some observed capabilities are healthy but the selected profile is incomplete | no for the incomplete profile |
| `MISCONFIGURED` | configuration is present but invalid | no |
| `DENIED` | verified identity reached the provider but required permission or policy was refused | no |
| `UNREACHABLE` | the bounded probe could not reach or authenticate the provider conclusively | no |
| `STALE` | prior proof expired or its identity, epoch, policy, revision, or region binding changed | no |
| `DISABLED` | an authorized immutable configuration change disabled the connection | no |

Every non-`READY` result contains a stable `reason_code`, safe explanation,
exact missing grant or configuration field when disclosable, remediation kind,
documentation or setup reference, owner, last attempt, last success, expiry,
and a trace/receipt reference. Secret values and provider response bodies are
never stored in the explanation. `Verify again` creates a rate-limited,
idempotent probe request; it cannot mark a connection healthy and cannot alter
configuration or permissions.

The console renders that operation as an authenticated action on the existing
connection. A registration that committed before its first external probe was
completed remains visible as unproven and is recovered by probing that exact
connection ID and epoch; the operator never has to create a duplicate
connection or repeat configuration material. A duplicate registration is a
typed conflict, never an internal error and never an implicit overwrite.

The probe result renders as a capability matrix in the console: what Solvan
can read, what the customer-side actuator can change, and — for each thing it
cannot — the exact missing role, scope, policy entry, or next safe step. A
connection without a fresh successful proof for the exact requested capability
cannot back an incident. Probe calls are operational checks and never become
incident evidence unless the coordinator separately performs and records the
ordinary bounded evidence read.

### 4.1 External resource scope and hierarchy coverage — target

Status: target. §4 already states that a connection's immutable identity
includes its external project, account, or workspace. This section defines that
field, and nothing here is implemented until the schema delta in
[`connection-scope-schema.target.sql`](artifacts/connection-scope-schema.target.sql)
is promoted.

**Two things called "project".** Solvan's scope triple carries `project_id`, a
tenancy subdivision beneath an organization. A Google Cloud project is an
external resource. They are unrelated, and the external one is therefore always
named `gcp_resource_*` in data and prose. Conflating them would let a tenancy
boundary be set by a customer's cloud layout.

**A tenant reaches many Google Cloud projects.** One `organization_id` holds
many connections; one connection names exactly one **external resource scope**
at one hierarchy level:

```text
projects/PROJECT_ID | folders/FOLDER_ID | organizations/ORG_ID
```

**Coverage is a property of the capability, not of the connection.** This is
the load-bearing rule, and it follows from the provider rather than from
preference. Cloud Logging accepts a folder or organization as a read resource,
so one grant covers every child project including projects created later. Cloud
Monitoring does not: a project's metrics scope contains only that project
unless a **scoping project** is configured with monitored projects attached,
after which the time-series read returns data for the scoping project and every
project it monitors. Asset and resource-admin reads are project-scoped again.

A connection therefore declares one resource scope, and each capability
declares the highest hierarchy level it can actually use:

| Capability class | Highest usable level | Consequence |
|---|---|---|
| log search | organization or folder | one grant covers descendants, including future projects |
| metric read | scoping project + monitored projects | a **metrics scope is required**, not one connection per project |
| asset and inventory search | organization or folder | subject to preflight confirmation |
| resource admin read (Cloud Run, Cloud SQL) | project | one connection per project, or a scope that enumerates them |
| repository and build read | external to Google Cloud | governed by its own connection |

Solvan **requires the metrics scope** rather than accepting one connection per
project for metrics. One scoping project with an explicit monitored-project
list is auditable and rotates once; a dozen connections are a dozen credentials
to rotate and a dozen postures to drift. The grant plan (§3.3) emits the exact
commands that configure it.

**Observed coverage, never declared coverage.** §4's rule that capability is
observed by probe extends to reach: the probe records, per capability, which
resource containers it actually read and which it was refused. A connection
whose declared scope is a folder but whose metric capability observed one
project is `DEGRADED` for metrics and `READY` for logs — one connection, two
truthful answers. Coverage is never inferred from the declared scope. It names
both the external project and one exact workload region: a proof for
`payments-prod/europe-west1` never authorizes `payments-prod/europe-west2`.

**Superseded tenancy wording.** The former one-Solvan-project-per-Google-project
rule is superseded by §4.3. A discovered external project enters an environment
only through the current authored environment binding defined there; it is not
a Solvan tenancy row. A metrics scope spanning production and staging carries
no signal that separates them, so inference is prohibited: an unbound
discovered project is visible as an onboarding task and contributes no evidence,
backs no incident, and is never a target.

**What refuses.** A capability requested above its usable hierarchy level; a
metric read against a connection with no configured metrics scope; evidence
from a discovered project with no current environment binding; a resource scope
whose hierarchy level the connection's credential posture cannot prove; and any
attempt to derive tenancy, environment, classification, or residency from the
external hierarchy rather than from the authored binding.

**Preflight-bound assumptions.** The hierarchy levels above are read from
provider documentation, not from a Solvan deployment. Folder-level asset search
behaviour, probe semantics at folder scope, and the propagation delay for a
project created after a grant are marked `preflight-required` in the source
register and must be observed against a real folder before any of them is
described as `implemented`. A target contract written from documentation alone
is how specification 20's ingestion premise had to be withdrawn.

### 4.2 Observed resource attribution — target

Status: target. §4.1 defines the reach a connection may have. This section
defines how a read records the reach it *actually had*, so that a value can be
attributed to the project it came from.

**Attribution is observed, not derived.** A Cloud Monitoring time series carries
a monitored resource whose labels name the project, and a log entry carries the
same in `resource.labels` and in its `logName`. The provider states the origin
of every value it returns. Solvan therefore never derives a value's project from
the service record, the connection's declared scope, or configuration: it reads
the label the provider returned. Deriving it would make attribution mutable —
re-pointing a service would silently rewrite which project historical incidents
claim to be about — and mutable history is prohibited.

**A read pins its project and verifies the answer.** Every metric read names its
project in the filter and groups by `resource.label.project_id`, so the returned
series carry the label back. The read then asserts the returned project equals
the requested one.

**Alerting preserves both Monitoring project identities.** A Cloud Monitoring
alert source connection is bound to one metrics **scoping project** in its
configuration/capability receipt. The notification's
`incident.scoping_project_id` must equal that bound project. The distinct
`incident.resource.labels.project_id` is the monitored-resource external
project: it must match the Production Graph target, that project's current
environment binding, and the connection's observed `METRIC_READ` coverage.
Neither value is derived from the other; absent, mismatched, unbound, or
uncovered values refuse before evidence, triage, or incident work.

**Cross-project reduction refuses.** A cross-series reduction over series from
more than one project produces a number describing no real service. A read whose
response carries more than one distinct project is an error, never a sum: either
the filter is under-specified or the metrics scope widened after the rule was
authored, and both are conditions an operator must see. Refusing is the same
rule as §4.1's — reach is observed, and an unobserved widening is not silently
absorbed.

**Declared location comes from the frozen graph, never from mutable text.** The
project a value should have come from is read from the **graph node** the read
selected: `graph_nodes.external_project_id`, in the snapshot the incident pinned.
That node is immutable, snapshot-bound, and already carries region, data
classification, and source revision.

It is deliberately *not* read from `services.platform_resource`. That column is
unconstrained text, mutable in place, unversioned, holds one resource per
service, and is meaningless for `platform_kind = 'EXTERNAL'`. Parsing it to
decide which estate to query would make prose into routing authority, which is
the failure this section exists to prevent. No column is added to `incidents`
either: the incident pins a graph snapshot, and the snapshot holds the location.

**A read proceeds only on a four-way agreement.** Each is an independent source,
and any disagreement refuses:

1. the frozen graph node for the selected resource declares project X in
   workload region R;
2. the incident's environment currently authorizes project X in R;
3. the selected connection and epoch hold fresh capability proof covering X in R for
   the capability class being used;
4. the provider attributes every returned value to X in R.

The target capability vocabulary is closed. The exact provider/capability
pairs available to Relay are `CLOUD_MONITORING/METRIC_READ`,
`CLOUD_LOGGING/LOG_SEARCH`, `CLOUD_AUDIT/AUDIT_LOG_READ`,
`CLOUD_TRACE/TRACE_READ`, `ERROR_REPORTING/ERROR_GROUP_READ`, and
`CLOUD_RUN/RESOURCE_METADATA_READ` or `CLOUD_SQL/RESOURCE_METADATA_READ`.
A catalog entry alone does not make a pair usable: the connection-scope DDL,
governed Tool profile, accepted run binding, current coverage receipt, and
provider-specific attribution fixture must all represent the same pair. An
unknown or cross-paired value refuses; it never falls back to a broader read
class.

Three of the four can be wrong in ways the others catch. A stale graph, a
withdrawn environment binding, a connection whose reach narrowed, and a metrics
scope that silently widened are four different failures, and none of them is
detectable from inside the others.

**The rest is provenance.** Every other observed label — revision, location,
cluster, database, version — is recorded verbatim on the evidence item and is
never interpreted, only cited and displayed. It is stored under the provider's
own names because a citation must reproduce what the provider returned.

Attribution changes what an operator can *see and cite*, never what a principal
may *reach*: `environment_id` remains the sole authorization and blast-radius
boundary.

**Vocabulary.** Raw provider labels are provenance and are stored under their
provider names, because a citation must reproduce what the provider returned.
Where a label has an OpenTelemetry equivalent under §5.2, the derived evidence
attribute uses the OTel name — a Google Cloud project is `cloud.account.id` —
and the raw label is retained alongside it. The two never merge: one is what was
observed, the other is what it means.

**What refuses.** A metric response carrying a project other than the one
requested; a response carrying more than one project; a detection rule whose
query names no project; a read whose selected graph node declares a project the
environment does not currently authorize; and evidence whose observed project is
not the project its graph node declares.

### 4.3 Tenancy rule — supersedes the one-project-per-tenant rule

A Solvan project is a **customer estate**. An environment inside it is the
authorization and blast-radius boundary. A Google Cloud project is an **external
resource container** where some of that environment's services happen to run. It
is not a level of Solvan tenancy.

One environment therefore holds services across many Google Cloud projects, and
`projects.gcp_project_id` is removed at promotion of this section's delta. The
earlier rule — one Solvan project per Google Cloud project, with
`projects.gcp_project_id` authoritative — is **superseded**, and the reason is
what it does to an operator rather than what it costs to build. Under it a
customer with twelve Google Cloud projects becomes twelve Solvan projects:
twelve incident queues, twelve role lists, and a Solvan project named
`acme-payments-prod` containing an environment named `production`, saying the
same thing twice in two vocabularies. Blast radius is the unit people reason
about and approve against, and it is the environment.

Consequences that are not optional:

- **Project resolution is per requested resource, not per incident.** A
  reservation carrying one project for every tool call is too coarse: service
  metrics resolve from the deployment node, database evidence from the selected
  database node, build evidence from the build-trigger node. A dependency in
  another project is the ordinary case, not an exception. The incident's primary
  service is the investigation anchor, never the address for every read.
- **Environment authorization and connection coverage are separate facts.**
  "This external project belongs to this environment" is authored once and is
  authority. "This connection can read this external project for this
  capability" is observed per probe and is reach. §4.1 already makes coverage a
  property of the capability, so a logging connection and a monitoring
  connection covering one project is the normal case; a single table keyed by
  connection would make them compete for environment authority.
- **One current environment binding per external project per organization.**
  The same Google Cloud project in two blast-radius environments would require
  resource-level isolation that project-wide Logging and Monitoring APIs cannot
  provide.
- **Solvan's own hosting project is not a customer project.** The value that
  builds Solvan's Cloud SQL IAM principals and cell deployment identity is the
  *deployment* project. It is named separately, sourced from the deployment
  manifest, and never resolved through a customer service or graph node. The two
  coincide only in a single-project development deployment, and that coincidence
  is not a contract.

**No compatibility path.** `SOLVAN_CUSTOMER_PROJECT_ID`, read today only by the
connection probe, is replaced by the connection's own external resource scope
when the §4.1 delta promotes. It is removed, not deprecated. A read path never
falls back to a process-wide project: a fallback would let an unattributed read
keep working, and an unattributed read is what this section exists to prevent.

## 5. Observer contract

### 5.1 Connector interface

Every read connector implements one typed contract returning evidence items
with source, query specification, window, freshness, classification,
residency, and content hash. Connectors never write, never hold mutation
permissions, and never return unbounded payloads.

### 5.2 Evidence is typed in OpenTelemetry semantic conventions

Evidence attributes use OTel semantic conventions — `service.name`,
`deployment.environment`, `http.route`, `http.response.status_code`,
`db.system`, `k8s.deployment.name` — regardless of the source system.

This is the portability seam. Google Cloud APIs are where GCP-native data
lives, but the *vocabulary* must be vendor-neutral, or the evidence model
silently becomes Cloud-Monitoring-shaped and every later connector needs a
translation layer with its own defects. A Datadog, Prometheus, or AWS adapter
then maps into the same vocabulary rather than beside it.

### 5.3 GCP-native connectors

| Connector | Purpose | Status |
|---|---|---|
| `cloud_monitoring_query` | metrics, detection signals | implemented |
| `cloud_logging_query` | application and platform logs | implemented |
| `cloud_trace_read` | distributed traces | implemented |
| `cloud_run_read` · `cloud_sql_metadata_read` | deployment and capacity metadata | implemented |
| **`cloud_audit_log_query`** | **"what changed" — every mutating API call with actor, target, method, timestamp** | **required** |
| **`error_reporting_query`** | **grouped error signatures with first-seen/last-seen** | **required** |
| `asset_inventory_search` | resource inventory and relationships for Production Graph discovery | target |
| `managed_prometheus_query` | PromQL for Prometheus-instrumented workloads | target |

The two `required` connectors are MSR-relevant and justify their status:

**Cloud Audit Logs** are the authoritative answer to *what changed*, which is
the central question of deployment-correlation diagnosis. They are queried
through Cloud Logging but require their own log-name filter and typed
projection, not generic log search. They also surface changes no other
connector sees — IAM edits, manual console changes, quota adjustments.

**Error Reporting** provides grouped error signatures natively. The
confirmation rule `rollback-correlation-v1` requires
`injected_error_signature_absent_for_observation_window`; this connector
answers that directly instead of reimplementing signature clustering.

### 5.4 Vendor connectors

`datadog_query`, `prometheus_query`, `grafana_query`, `newrelic_query` — all
target status, all read-only, all `STORED_LONG_LIVED` posture, all mapped into
OTel semantic conventions at the adapter boundary.

### 5.5 Solvant Relay — target

The **Solvant Relay** is the separate deterministic, customer-deployed,
read-only evidence plane governed by [specification 22](22-solvant-relay.md).
It is not an Agent, Actuator posture, MCP server, generic proxy, control-plane
extension, or source of workflow authority. Its clean target machine contracts
are connection kind `RELAY` and provider `SOLVAN_RELAY`; the current
`COLLECTOR`/`SOLVAN_COLLECTOR` scaffold is removed rather than aliased when the
target migration is implemented.

It exists to make `CUSTOMER_SIDE_NONE` practical for private, hybrid, and
credential-sensitive estates: local credentials stay in the customer
environment while the Relay returns bounded, locally-redacted typed evidence
to Solvan. The `RELAY` connection represents the transport; every observed
system retains its real provider connection with `CUSTOMER_SIDE_NONE`, and an
exact source binding connects the two. This keeps the accepted Agent Tool
binding on the actual source while the coordinator, never the model, resolves
the transport. It does not add an institutional agent, a vendor-specific agent, or
a new authority silo. The coordinator alone resolves a profile and creates the
durable collection work; the Evidence and Infrastructure Agents may only
request the already-profiled Tool through their ordinary invocation.
Specification 22 and its linked protocol, policy, schema, connector, evidence,
transition, redaction, and acceptance artifacts are the smallest governing
contracts for every Relay implementation detail.

#### 5.5.1 Local policy and deployment

The Relay is a distinct executable and immutable image with no mutation
dependency or IAM. The customer supplies a signed, read-only local policy using
[`relay-local-policy.schema.json`](artifacts/relay-local-policy.schema.json).
It may only narrow the registered Relay/source connections and closed connector catalog.
Missing or mismatched policy, identity, image attestation, epoch, region,
classification, endpoint, operation, bound, scanner, or local kill switch
performs no read or evidence egress. Specification 22 §§5--6, 11 and 15 define
the executable, attestation, policy and deployment contracts completely.

#### 5.5.2 Collection protocol

The Relay uses the distinct outbound-only poll, claim, upload, receipt,
cancellation, and reconciliation protocol in
[`relay-api.md`](artifacts/relay-api.md). Work is created only after the
coordinator persists the ordinary Agent run and Tool call. The signed
`CollectionJob` cannot represent an endpoint, credential, arbitrary query,
shell, Kubernetes verb, generic protocol, action, approval or mutation.

[`relay-transitions.yaml`](artifacts/relay-transitions.yaml) and
[`relay-schema.target.sql`](artifacts/relay-schema.target.sql) define durable
claims, attempts, ambiguity, revocation and exactly one accepted evidence
projection. The initial adapters do not support a qualifying upstream
idempotency key, so Relay v1 does not claim exactly one provider read; it
provides lease-fenced bounded retries and explicit ambiguity instead.

#### 5.5.3 Evidence and discovery boundary

Relay emits only the locally projected and redacted envelope in
[`relay-evidence-envelope.schema.json`](artifacts/relay-evidence-envelope.schema.json)
under [`relay-redaction-profile.yaml`](artifacts/relay-redaction-profile.yaml).
Raw provider responses and errors never leave the customer. Control-plane
schema, secret/PII and Model Armor gates run again before prompt eligibility.

Relay may report an observed capability only through §4's immutable probe
model. It cannot set `READY`, widen a capability, refresh proof, overwrite an
epoch, or create/promote Production Graph material. Kubernetes inventory,
DNS-derived maps, packet capture and continuous topology remain excluded under
specification 22 §§1, 12 and 23.

#### 5.5.4 Relay acceptance criteria

The complete invariant and fixture matrix is
[`relay-acceptance.yaml`](artifacts/relay-acceptance.yaml). A `null`
implementation is an explicit gap. Production status additionally requires the
exact customer-deployed image, policy/catalog digests, identity, region and
host qualification to be bound in a deployment receipt; local tests or a
console screenshot are not that receipt.

## 6. Actuator contract

### 6.1 Network direction

The actuator makes **outbound** calls only. It exposes no ingress; on Cloud
Run it is deployed with ingress disabled. The customer opens no firewall and
grants Solvan no network path into their estate.

### 6.2 Poll protocol

```text
POST /internal/actuator/poll
  Authorization: Bearer <Google-signed OIDC ID token>
  body: schema_version, actuator_version, image_digest, policy_hash,
        declared_capabilities[], kill_switch_engaged

  → 204  no work
  → 200  one authorized dispatch: action payload, digest, expected effect,
         expected target version and epoch, approval reference, lease expiry
```

The server holds the request open up to 45 seconds so an approved action
executes within seconds rather than waiting for a poll interval. At most one
dispatch is outstanding per actuator, which bounds concurrency without
distributed coordination on the customer side.

```text
POST /internal/actuator/receipt
  body: dispatch_id, action_id, result, policy_hash,
        before_state_ref, predicted_effect_hash, after_state_ref,
        undo_plan_json, started_at, completed_at, error_class
```

Receipts are idempotent on `dispatch_id`. A resubmitted receipt returns the
stored result and changes nothing.

### 6.3 Execution sequence

For every dispatch, in order, in code:

1. verify the dispatch is bound to this actuator's verified principal and
   tenant scope;
2. verify the action type is present in the **customer-authored** allowlist
   and the target matches a customer-authored selector;
3. verify budget: attempts remaining in window, cooldown satisfied;
4. verify the kill switch is not engaged;
5. read current target state → `before_state`;
6. **dry-run** the operation → `predicted_effect`;
7. compare `predicted_effect` against the action's declared `expected_effect`;
   on mismatch, refuse and emit a receipt with `DRY_RUN_MISMATCH` — do not
   execute;
8. derive the undo plan from `before_state`;
9. verify reversibility if the policy requires it;
10. execute;
11. reconcile: read `after_state`;
12. emit the receipt to Solvan **and** to the customer's own Cloud Logging.

The action already contains an application-derived canonical expected-effect
descriptor and `sha256:` hash before standing authorization or approval. The
initial closed profiles are `payments-pool-recycle.v1` and
`cloud-run-traffic-replacement.v1`, with the exact fields defined in
`specs/04-data-event-api.md`. The connector independently constructs its
prediction from typed action material and `before_state`; application code
canonicalizes and compares it. Missing, malformed, unsupported, profile-drifted,
or unequal predictions all take the same no-mutation `DRY_RUN_MISMATCH` path.

Steps 6–8 adopt a pattern established by open-source Kubernetes action
runners, which dry-run before every mutation and derive the rollback command
from the dry-run output rather than from a declared plan. This
converts "the model was asked to confirm the effect" into "the effect was
computed and compared before anything changed."

One action-bound dispatch authorizes exactly one call to the connector's
mutation operation. This restates the standing-preauthorization `one attempt`
contract in `specs/04-data-event-api.md` and the structural
`maximum_attempts = 1`/unique-action dispatch constraints. Once step 10 may have
started, process recovery resumes at step 11 and performs reconciliation only;
it never invokes the mutation again. A second mutation requires a new action
ID, fresh policy/approval authority, target reservation, dry run, and dispatch.

The dispatch projection distinguishes `PREPARED` from `MUTATION_ISSUED` and
`RECONCILING`. A worker commits `PREPARED` with the exact reservation, customer
policy hash, expected-effect hash, request hash, dry-run evidence, observed
pre-state, and derived undo plan before it may claim the mutation operation.
The atomic `PREPARED` → `MUTATION_ISSUED` transition is the single mutation-call
claim. A crash before that transition permits a newly leased worker to
revalidate current authority and claim it; a crash after it permits only
reconciliation. The dispatch lease owner/token and target-reservation token are
reclaimed together, so two recovery workers cannot both issue or settle the
dispatch.

`actions.rollback_plan_json` is proposal and approval-scope material. Binding it
into the action digest freezes what the approver considered, but it is never an
executable undo instruction. The only executable undo plan is derived in step
8 from the observed `before_state` and recorded in
`actuator_effect_receipts.undo_plan_json` with
`undo_derived_from = 'OBSERVED_PRE_STATE'`.

### 6.4 Customer-authored policy

The allowlist, target selectors, budgets, reversibility requirement, and risk
gates live in a file the **customer** owns, loaded at actuator start. Its hash
is reported on every poll and recorded in every receipt. Solvan displays the
hash and raises an event when it changes.

If Solvan authors the policy and the customer never edits it, the actuator is
a proxy that adds latency and better logging. The security value of this
architecture is entirely contingent on who writes that file.

**Absence is refusal.** No policy file, unparsable policy, or empty allowlist
means every dispatch is refused. There is no default-allow.

### 6.5 Kill switch

A local control that causes the actuator to refuse all dispatches and report
`kill_switch_engaged` on poll. It is evaluated locally and therefore works
when Solvan is unreachable, compromised, or malicious.

### 6.6 Dual-written receipts

Every receipt is written to Solvan and to the customer's own logging sink with
the same content hash. Audit that exists only inside Solvan can be erased by a
compromised Solvan.

## 7. What this bounds — and what it does not

Stated plainly, because a published limit that is accurate is worth more than
a marketing claim that is not:

**Bounded.** A fully compromised Solvan control plane cannot obtain
credentials to the customer estate, cannot reach it over the network, cannot
execute an operation outside the customer's allowlist, cannot exceed the
customer's rate budget, cannot act while the kill switch is engaged, cannot
cause an effect that differs from the one predicted by dry-run, and cannot
erase the customer's copy of the audit trail.

**Not bounded.** A compromised control plane can request any well-formed
action *inside* the allowlist, at the permitted rate, until the customer
notices. The architecture converts arbitrary production access into bounded,
reversible, rate-limited, dual-audited operations. It does not eliminate harm.

Customers requiring the stronger property use **customer-held signing**: for
`HIGH` and `CRITICAL` risk classes, the approval must carry a signature from a
key in the customer's own KMS, applied by a human in the customer's tooling.
A compromised Solvan then has zero capability at those risk classes. This is
target status and is the recommended posture for regulated estates.

## 8. Invariants

| ID | Invariant | Bound test |
|---|---|---|
| INV-T-01 | Solvan stores no credential capable of mutating a customer estate | `SEC-TENANT-NO-WRITE-CRED-001` |
| INV-T-02 | Actuator identity derives only from verified OIDC claims; headers and body fields are ignored | `SEC-ACTUATOR-IDENTITY-001` |
| INV-T-03 | A dispatch is delivered only to the actuator whose verified principal owns its tenant scope | `SEC-ACTUATOR-CROSS-TENANT-001` |
| INV-T-04 | Absent, unparsable, or empty customer policy refuses every dispatch | `UT-ACTUATOR-FAIL-CLOSED-001` |
| INV-T-05 | No configuration value can downgrade identity verification to a permissive mode | `SEC-NO-PERMISSIVE-DOWNGRADE-001` |
| INV-T-06 | Every mutation is dry-run and effect-compared before execution | `IT-ACTUATOR-DRY-RUN-001`, `IT-ACTUATOR-EFFECT-COMPARE-001` |
| INV-T-07 | The approval-bound proposed rollback is never executable; the only executable undo plan is derived from observed pre-state at execution time | `UT-ACTUATOR-UNDO-FROM-STATE-001` |
| INV-T-08 | Receipts are idempotent on `dispatch_id` | `IT-ACTUATOR-RECEIPT-IDEMPOTENT-001` |
| INV-T-09 | `DEV_LOCAL` hosts are structurally barred from production eligibility | `CT-ACTUATOR-HOST-ELIGIBILITY-001` |
| INV-T-10 | `ONPREM_KEYFILE` requires a recorded risk acceptance | `CT-ACTUATOR-KEYFILE-RISK-001` |
| INV-T-11 | Credential posture is recorded per connection and rendered in the console | `E2E-UI-CONNECTION-POSTURE-001` |
| INV-T-12 | `STORED_LONG_LIVED` credentials are Secret Manager references; values never enter Cloud SQL, logs, traces, or model context | `SEC-VENDOR-KEY-CONTAINMENT-001` |
| INV-T-13 | The kill switch is evaluated locally and holds when Solvan is unreachable | `IT-ACTUATOR-KILLSWITCH-001` |
| INV-T-25 | Every local-policy refusal emits one content-free record carrying its enumerated reason code, so an in-binary control is observable to an operator and not only to its caller | `UT-ACTUATOR-REFUSAL-OBSERVABLE-001` |
| INV-T-14 | Receipts are dual-written to the customer sink | `IT-ACTUATOR-DUAL-AUDIT-001` |
| INV-T-15 | Capability is observed by probe; an unprobed connection cannot back an incident | `IT-CONNECTION-CAPABILITY-PROBE-001` |
| INV-T-16 | Every provider instance has one explicit connection ID and no request is routed through an implicit environment/provider default | `IT-CONNECTION-NO-DEFAULT-001` |
| INV-T-17 | Non-ready connection state is derived from an immutable probe/configuration receipt and includes a safe reason and next step | `IT-CONNECTION-HEALTH-DERIVATION-001` |
| INV-T-18 | Manual verification can create a bounded probe but cannot mark health, change configuration, or grant a capability | `SEC-CONNECTION-VERIFY-NO-AUTHORITY-001` |
| INV-T-19 | Stale capability proof is invalidated by connection epoch, identity, policy, revision, region, or expiry change | `IT-CONNECTION-PROBE-FRESHNESS-001` |
| INV-T-20 | One action-bound dispatch permits one mutation call; recovery after a possibly sent mutation is reconcile-only, and another mutation requires a new authorized action | `IT-ACTUATOR-ONE-MUTATION-ATTEMPT-001` |
| INV-T-21 | A durable `PREPARED` dispatch and effect receipt precede the mutation-call claim; lease-token CAS fences competing issuers and finalizers | `IT-ACTUATOR-DISPATCH-INTENT-001`, `IT-ACTUATOR-RECONCILE-ONLY-001` |
| INV-T-22 | Solvant Relay and the Action Actuator are separate executables, images, identities, audiences, registries and IAM boundaries; Relay contains no mutation dependency or compatibility mode | `CT-RELAY-SEPARATE-BINARY-001` |
| INV-T-23 | Control-plane residency never implies workload reach; every direct or Relay read has one exact graph, environment, capability, policy, and provider-attributed workload region | `IT-CONNECTION-WORKLOAD-REGION-001` |
| INV-T-24 | Local-connected development derives target projects only from current UI-created connection records and accepts only an attested Solvan development service account over a worktree-scoped authenticated Unix socket | `IT-LOCAL-GCP-IDENTITY-001`, `IT-LOCAL-GCP-NO-TARGET-DEFAULT-001` |
| INV-T-25 | GCP onboarding explains every required field without soliciting a customer secret, and labels external project, workload region, and control-data residency separately | `E2E-UI-GCP-CONNECTION-GUIDE-001` |

## 9. Hostile-control-plane test suite

The security claim in §7 is only credible if it is falsifiable. This suite
assumes Solvan is **malicious**, and every case must fail closed. Each fixture
corresponds to a failure observed in shipping open-source incident tooling,
recorded in the
[competitive landscape study](../docs/research/2026-08-08-competitive-landscape.md).

| Fixture | Attack |
|---|---|
| `forged-signer` | token signed by a non-Google key |
| `wrong-audience` | valid Google token, audience for a different service |
| `unregistered-principal` | valid token, principal never registered |
| `cross-tenant-dispatch` | tenant A's actuator requests tenant B's action |
| `header-asserted-tenant` | correct token, spoofed `x-tenant-id` header — headers must be ignored |
| `permissive-mode-env` | environment attempts to disable identity verification |
| `replayed-receipt` | receipt resubmitted for a completed dispatch |
| `restart-replays-mutation` | actuator restarts after mutation may have been sent and attempts a second mutation instead of reconcile-only recovery |
| `expired-approval` | approval valid at dispatch, expired at execution |
| `outside-allowlist` | well-formed action absent from customer policy |
| `outside-target-selector` | allowed action type, target outside customer selector |
| `dry-run-mismatch` | predicted effect differs from declared expected effect |
| `proposal-used-as-undo` | actuator attempts to execute approval-bound `rollback_plan_json` instead of deriving undo from observed pre-state |
| `budget-exceeded` | same action beyond the customer's rate window |
| `killswitch-engaged` | any dispatch while the local switch is set |
| `non-reversible` | irreversible variant where policy requires reversibility |
| `policy-hash-drift` | policy changed between dispatch and execution |
| `unattested-image` | actuator image digest not in the registered attestation |
| `dev-local-production` | `DEV_LOCAL` host attempts a production mutation |
| `empty-policy-default-allow` | policy file present but allowlist empty |
| `implicit-provider-default` | request omits connection ID while two eligible-looking provider instances exist |
| `forged-ready-state` | client submits `READY`; server ignores it and derives availability from receipts |
| `stale-probe-after-epoch-change` | prior success exists but credential or connection epoch changed |
| `probe-error-secret-leak` | provider error includes a credential canary; safe reason persists without it |
| `verify-again-permission-escalation` | probe requester attempts to change scope or grant while rechecking health |

## 10. Invariant deltas for `AGENTS.md`

Apply with this specification, not before:

> - Solvan never holds a credential capable of mutating a customer estate.
>   Production mutation capability exists only in a customer-deployed actuator
>   bound by customer-authored policy, a local kill switch, and a rate budget.
> - Every stored customer credential records its posture. Federated
>   short-lived credentials are preferred; stored long-lived keys are
>   read-only scoped, held as Secret Manager references under per-tenant CMEK,
>   and surfaced in the console.
> - Every production mutation is dry-run and effect-compared before execution,
>   and its undo plan is derived from observed pre-state rather than a
>   previously declared plan.
> - Identity is established from verified cryptographic claims only. No
>   configuration value may downgrade an identity, policy, or isolation
>   control to a permissive mode.

## 11. Schema

DDL is merged into [`artifacts/schema.sql`](artifacts/schema.sql) at schema
revision 62. The tenant and GitHub release-provider tables carry the three scope columns, so the
row-level security loop enables `scope_isolation` on them automatically — no
policy is authored by hand and none can be forgotten. Local state and Compose
project names are revision-scoped, so the prior revision-51 volume is
preserved rather than overwritten.

The multi-instance health expansion in §4 is target and requires a successor
schema revision before implementation. It adds immutable probe requests and
receipts plus a derived projection containing provider instance identity,
owner/purpose, availability, reason code, safe detail-template key,
remediation kind/reference, missing grant, attempted/succeeded/expiry times,
connection/identity/policy/revision/region epochs, receipt hash, and trace ID.
Availability is never a client-writable column of authority; repositories
derive it from current configuration lifecycle and the newest eligible receipt.
Indexes support connection list by scope/provider/environment, fresh capability
resolution by profile, expiry reconciliation, and health history. Raw provider
errors and credentials are not columns.

Solvant Relay uses the separate target DDL in
[`artifacts/relay-schema.target.sql`](artifacts/relay-schema.target.sql). It is
not part of revision 62 or the competition release schema. Its promotion must
also cleanly replace the scaffold registry values `COLLECTOR` and
`SOLVAN_COLLECTOR` with `RELAY` and `SOLVAN_RELAY`; no compatibility alias or
process-wide fallback is permitted.

## 12. Adoption order

1. `cloud_audit_log_query` and `error_reporting_query` connectors — MSR-relevant, improve S1 evidence quality, no new tables.
2. Merge the tenant DDL; multi-instance connection registry, posture recording,
   derived health, and capability probes.
3. Solvant Relay as the separate executable/image specified in specification
   22, with signed local policy, collection protocol, identity/attestation,
   redaction-before-egress, durable ambiguity handling and the complete target
   acceptance registry.
4. Write posture (tier 2): customer policy loader, dry-run and effect comparison, undo derivation, budgets, kill switch, dual-written receipts.
5. Hostile-control-plane suite in CI; publish the threat model including §7's stated limits.
6. Vendor connectors and Asset Inventory graph discovery.
7. Customer-held KMS signing for `HIGH`/`CRITICAL`.

## 13. Non-goals

- This specification does not expand the Minimum Submittable Release beyond
  the two connectors marked `required`.
- It does not grant any workspace, agent, or model direct actuator access;
  dispatch remains coordinator-owned and Execution-Agent-mediated.
- It does not give the actuator a generic shell, arbitrary HTTP, generic SQL,
  or cloud administration surface. Typed operations only.
- It does not replace independent verification. An actuator receipt reports a
  reconciled mutation, never a recovered service.
- It does not authorize non-GCP mutation paths; AWS and Azure actuation
  require their own identity, policy, and threat-model contracts.
