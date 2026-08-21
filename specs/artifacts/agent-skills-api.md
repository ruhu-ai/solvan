# Agent Skills interchange API contract

Status: target implementation contract; excluded from the Minimum Submittable
Release gate. Commands are asynchronous and return durable operation receipts.
Cloud SQL is authoritative; a provider job or object-store response cannot
authorize a lifecycle transition.

## Command envelopes

Import requests include `schema_version: 1`, a client-generated command ID,
`purpose`, requested `classification`, requested `region`, and `source_kind`
(`ARCHIVE`, `REPOSITORY`, or `FIRST_PARTY`). Refresh requests include the
expected lineage epoch and purpose. Compile, lifecycle, governance, and export
requests carry only the fields named by their route contracts; they do not
repeat import-only source or classification fields. Verified tenant scope,
principal, and `authorization_ref` are server-derived after
cryptographic identity verification. They are never accepted from an HTTP
body, query parameter, caller-selected header, connector payload, or model
argument. The server records an opaque authorization receipt reference bound
to the exact active role, purpose, audience or destination, scope,
classification, region, and expiry.
Archive payloads over the profile's 1 MiB compressed bound are refused before
persistence; expanded package bounds remain the deterministic §5.3 limits.
`REPOSITORY` requests instead carry an exact lowercase `pinned_commit_sha` and
an optional safe `subdirectory`; they never carry an archive. The registered
connector fetches the pinned subtree only after validating its tenant
allowlist. If no connector is configured, the closed code
`REGISTERED_CONNECTOR_REQUIRED` is returned.

Every response includes `operation_id`, `status` (`ACCEPTED`, `COMPLETED`, or
`REFUSED`), and, when refused, one closed `reason_code` plus an immutable
attempt reference. Repeating a command with the same idempotency hash returns
the original receipt; a changed covered field returns `IDEMPOTENCY_CONFLICT`.
Import and refresh hashes bind the logical command and security-policy/scanner
versions but exclude the opaque short-lived authorization receipt and the
idempotency key. The server records the actual receipt on each created attempt
and reauthorizes every retry before replay. Export instead binds the exact
authorization receipt, approved content digest, destination snapshot, license
policy, purpose, principal, and stale-content acknowledgment because those are
the exact materials authorizing the boundary crossing.

## Commands

| Command | Required role | Durable result |
|---|---|---|
| `POST /v1/skills/import` | `GUIDANCE_AUTHOR` | `skill_import_attempt` and, only when quarantined, `skill_import` |
| `POST /v1/skills/{import_id}/compile` | `GUIDANCE_AUTHOR` | one `DRAFT` `GuidanceRevision`, or a closed refusal |
| `POST /v1/skills/{guidance_key}/refresh` | `GUIDANCE_AUTHOR` or registered schedule | refresh-ledger outcome and at most one upstream-change notice |
| `POST /v1/skills/{guidance_key}/export` | `GUIDANCE_EXPORTER` | export attempt and, on success, `skill_export_receipt` |
| `GET /v1/skills/import-attempts/{id}` | read grant | immutable attempt/quarantine projection, scanner/license/file/retention records without content |
| `GET /v1/skills/{key}/lineage` | discovery grant | current-head, revision, evaluation, approval, refresh-notice, and export projection, content-free by default |
| `GET /v1/skills/autocomplete` | exact reader grant | approved current heads visible under the reader's department, purpose, classification, and region grants |
| `GET /v1/skills/governance` | `OPERABILITY_ADMIN` | content-free owner, license-policy, reader-grant, and export-destination projection |
| `POST /v1/skills/governance/owners` | `OPERABILITY_ADMIN` | immutable owner-department slug registration; conflicting reuse is refused |
| `POST /v1/skills/governance/licenses` | `OPERABILITY_ADMIN` | reviewed import and redistribution policy registration; changed reuse is refused |
| `POST /v1/skills/governance/readers` | `OPERABILITY_ADMIN` | explicit principal/department/purpose/region/classification reader grant |
| `POST /v1/skills/governance/destinations` | `OPERABILITY_ADMIN` | exact regional GCS export binding; unsupported destination kinds are not registerable |

The target console uses the existing governed guidance commands for the
post-compile lifecycle. These are not alternate skill authority; they reuse
the same role, digest, independent-evaluation, and current-head checks:

| `POST /admin/guidance/{key}/revisions/{version}/submit` | `GUIDANCE_AUTHOR` | moves the exact draft to `IN_REVIEW` |
| `POST /admin/guidance/{key}/revisions/{version}/evaluations` | independent evaluator | records a digest-bound evaluation receipt |
| `POST /admin/guidance/{key}/revisions/{version}/approve` | `GUIDANCE_APPROVER` | records independent approval and publishes only the current head |

The console keeps the one-time identity token in memory only and displays the
exact digest before each command. Export remains the `GUIDANCE_EXPORTER`-
bound skill route above.

Import accepts a bounded archive upload or a registered repository connection
plus a pinned ref/subdirectory. The target adapter supports the explicit
`github://owner/repository` and `gitlab://group/project` schemes; the provider,
installation/token broker, exact repository allowlist, and destination rows
are tenant configuration, not request data. Repository access is through the
registered connector only; arbitrary URLs, redirects, private-network
targets, and model-supplied connection IDs are refused. Compilation accepts only a
quarantined import and requires explicit author metadata, normalized license
identifier, classification, purpose, region, step graph, and supersession
choice. Export accepts only an approved revision (or deprecated with an
explicit stale acknowledgement) and a destination from the tenant allowlist.
The projection routes never return prompt bytes, source package bytes, operator
notes, scanner payloads, credentials, or hidden approval authority. They return
only typed hashes, references, closed decisions, and timestamps already
committed in Cloud SQL, after verified scope filtering.

## Authorization and closed errors

`GUIDANCE_AUTHOR` may import, compile, and request refresh only in the owning
department and scope. `GUIDANCE_APPROVER` remains independent as required by
specification 17. `GUIDANCE_EXPORTER` requires a separate purpose-bound grant
naming the destination. Import attempts, license evidence, operator notes, and
export receipts use record-specific access modes and tenant classification and
regional storage policy.

The API checks the active role binding in Cloud SQL before every mutating
command. It does not infer a role from the request, model output, or an
authorization reference. Export also checks the destination allowlist,
regional binding, and classification ceiling before generating bytes. Exact
serialized export bytes are rescanned; a missing, unavailable, or ambiguous
scanner result refuses the operation.

Refresh commands do not accept authoritative repository identity, pinned
commit, subtree, connection, or prior tree-hash material from the caller. The
server loads that immutable binding from the named lineage and accepts only an
expected lineage epoch plus an idempotency key. The registered connector then
observes metadata for that exact binding.

Evaluation commands name a server-registered immutable evaluation receipt.
The API retrieves it through the evaluation-receipt reader, verifies object
generation and hash, suite allowlisting, revision digest, corpus and case-set
digests, scorer and model/configuration pins, repetitions, thresholds, and
aggregated result. Caller-asserted pass counts or hashes are not approval
evidence. Approval atomically attaches the verified evaluation ID and its hash
to the exact reviewable-material digest.

An export commits a SQL `PREPARED` attempt and stable export ID before any
provider write. The deterministic archive embeds that stable ID, the GCS
write uses `ifGenerationMatch=0`, and a retry resumes the same attempt and
bytes. The server verifies that the registered bucket's actual location equals
the destination's `europe-west1` binding before writing. Only then may one
atomic Cloud SQL transaction attach the generation receipt, the exact
destination-binding snapshot, all byte-scanner receipts, the active tenant
license-policy version, and move the attempt to `EXPORTED`. A provider outage
leaves the attempt resumable as `PREPARED`; it never creates a second
destination object.

The initial implementation exposes stable codes for at least:
`IDEMPOTENCY_CONFLICT`, `SCOPE_DENIED`, `REGION_DENIED`,
`AUTHORIZATION_EXPIRED`, `ARCHIVE_INVALID`, `ARCHIVE_TYPE_UNSUPPORTED`,
`REGISTERED_CONNECTOR_REQUIRED`, `CLASSIFICATION_DENIED`,
`PACKAGE_STRUCTURE_INVALID`, `PACKAGE_BOUNDS_EXCEEDED`, `PATH_UNSAFE`,
`PATH_COLLISION`, `SPECIAL_FILE`, `ENCODING_INVALID`, `YAML_UNSAFE`,
`FRONTMATTER_INVALID`, `LICENSE_MISSING`, `LICENSE_POLICY_DENIED`,
`LICENSE_IDENTIFIER_MISMATCH`,
`MODEL_ARMOR_DENIED`, `DESTINATION_NOT_ALLOWLISTED`,
`DESTINATION_PROVIDER_UNAVAILABLE`, `DESTINATION_REGION_MISMATCH`,
`LICENSE_REDISTRIBUTION_DENIED`, `LIFECYCLE_REFUSED`,
`STALE_CONTENT_ACKNOWLEDGMENT_REQUIRED`,
`STALE_CONTENT_ACKNOWLEDGMENT_NOT_APPLICABLE`, `LINEAGE_CONFLICT`,
`REFRESH_LEASE_HELD`, `REFRESH_CADENCE_LIMIT`, and `REFRESH_RETRY_LIMIT`.
