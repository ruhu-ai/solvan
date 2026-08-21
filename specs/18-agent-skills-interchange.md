# Solvan Agent Skills interchange

Status: target product contract with an implemented, locally verified target
slice; excluded from the Minimum Submittable Release gate. Section 13 records
the implementation and qualification boundary. Local verification is not a
cloud release receipt.

Related: [agent/runtime](03-agent-model-runtime.md),
[data/API](04-data-event-api.md), [security](05-security-governance.md),
[UI/UX](06-ui-ux.md), [evaluation](08-test-evaluation-acceptance.md),
[conversational surface](14-conversational-surface.md),
[governed Tool Catalog](16-governed-tool-catalog.md), and
[governed operational guidance](17-governed-operational-guidance.md).

Concept sources: the open Agent Skills specification at
`https://agentskills.io/specification`, its authoring guide, and its client
implementation guide (retrieved 2026-08-11); publicly documented skills
behaviour in existing incident-response products; and read-only snapshots of
Google ADK, OpenAI Agents, and other agent runtimes, each recorded with its
commit or its unversioned-extract status. They are research inputs, not runtime
dependencies or security proofs.

## 1. Purpose

Specification 17 already defines Solvan's skills capability: versioned
Operational Guidance with `guidance_kind: SKILL`, two-phase lazy selection,
data-not-authority prompt placement, and code-computed step completion. What
specification 17 leaves open is the boundary: what an import reads, what an
export writes, and how untrusted packages are held before they become
governed records. Without that contract, `source_kind: IMPORTED` is
unimplementable and every customer procedure must be re-authored by hand.

This specification closes the gap with a **Solvan Agent Skills Import Profile
v1**: a documented profile of the open Agent Skills format (`SKILL.md` with
YAML frontmatter) used by Claude-family agents and a growing ecosystem. The division of authority is fixed: the profile is an
**interchange contract**; specification 17 remains the **runtime authority**.
A skill file never becomes instruction authority, tool authority, or factual
authority by conforming to a format.

Compatibility is claimed at exactly these levels, and no further:

1. **Package syntactic conformance** — §5 defines what a conforming package
   is under this profile.
2. **Importability** — a package, conforming or normalizable with explicit
   diagnostics, can enter quarantine (§6).
3. **Governance eligibility** — quarantined content plus human-supplied
   Solvan metadata can become a `DRAFT` `GuidanceRevision` (§7).
4. **Content portability** — approved guidance exports back to a conforming
   package (§9).
5. **Runtime behavior portability** — deliberately **not provided**. Solvan
   never executes skill scripts, honors `allowed-tools`, or reproduces
   another runtime's activation semantics.

## 2. Release boundary

This entire specification is target. Implemented target surfaces do not create
a competition-release obligation or claim. No requirement, test, or release
gate in another specification may make this document required without an
explicit status change and traceability update.

## 3. Decisions

1. **One interchange profile.** Guidance import and export use the Solvan
   Agent Skills Import Profile v1 (§5), a restriction of the open Agent
   Skills format. Solvan defines no private skill format and accepts no other
   import format. Profile restrictions beyond the open standard are labelled
   as such; conformance to the open standard alone does not guarantee
   importability, and Solvan never claims full-standard compatibility.
2. **The quarantined import is the central abstraction.** Every accepted
   package first becomes an immutable `skill_import` record set (§6):
   validated, canonicalized, and scanned, with license evidence recorded in
   a closed state, but carrying no governance eligibility. Every attempt — accepted or rejected — leaves an
   immutable `skill_import_attempt` audit record. A `GuidanceRevision` is
   created only when compilation can produce a fully valid governed record
   (§7). No partially valid revision is ever written.
3. **Import compiles; it never trusts.** Draft creation from quarantine
   requires a human `GUIDANCE_AUTHOR`; the result enters the full nine-stage
   ingestion pipeline of specification 17 §5. Format conformance is never
   approval, eligibility, or evidence.
4. **The executable subset is empty.** Bundled `scripts/` are never executed,
   installed, or exposed to a model or provider in any environment. The
   `allowed-tools` frontmatter field is recorded as source metadata and
   grants nothing; Tools come only from the frozen profile of the run, per
   specification 17 §4.2.
5. **Import pins; activation never fetches the origin.** Import captures the
   exact package bytes and digests at a named source. Activation resolves
   only the approved immutable revision. Solvan deliberately diverges from
   Resolve's fetch-latest-at-activation behavior: a moving origin cannot
   silently change approved guidance; upstream updates arrive as new
   quarantined imports and `DRAFT` successors.
6. **License evidence is preserved, never fabricated.** Quarantine records
   a closed license-evidence state — `PRESENT | MISSING |
   REJECTED_BY_POLICY` — and, when present, the evidence itself as an
   immutable artifact with location and digest. A package quarantines in any
   state; only compilation requires `PRESENT` (§7.2). A reviewed, normalized
   license identifier — not the evidence itself — is what enters
   `GuidanceRevision.source_license`. Third-party material without
   acceptable evidence cannot become a `DRAFT`, cannot be approved,
   activated, or exported. A placeholder such as "unlicensed" is never
   written.
7. **Frontmatter is prompt-injection-capable untrusted input.** `name` and
   `description` are attacker-writable text that reaches model context
   during discovery. They are screened in ingestion like body content, enter
   the bounded shortlist as labelled data, and can at most influence ranking
   of already-eligible revisions; they cannot add eligibility, tools, scope,
   or facts.
8. **Every compiled skill has a genuine typed step graph.** A foreign skill
   carries prose, not registered predicates. The reviewing author either
   supplies a full typed step graph (specification 17 §4.2) or accepts the
   registered advisory checkpoint step (§7.3). No step graph is ever derived
   by a model from imported prose, and no placeholder that fails the
   governed step contract exists.
9. **Identity is internal; selectors are external.** Durable identity is the
   internal `guidance_key`; the human-facing qualified selector is a
   distinct, parsed surface form (§7.1). Idempotency binds to the proposed
   governed revision's approval digest, never to the source bundle digest,
   which is provenance only (§7.5).
10. **First-party guidance is dogfooded through the same quarantine.**
    Solvan-authored packs in this repository import through §6 from the
    pinned repository source, compile as `SOLVAN_AUTHORED`, and still
    require independent guidance approval; merging code is not approving
    guidance (§11).
11. **Operator-explicit selection is a closed intent.** The
    `GUIDANCE_REFERENCE` intent is registered in specification 14 and wired
    through the deterministic selector (§10). Selection of an
    already-eligible revision may be deterministic; interpreting prose never
    is, and a failed explicit selection never falls back to model ranking
    silently.
12. **Native ADK skill machinery is prohibited as authority.** The pinned
    Google ADK ships `SkillToolset`, `RunSkillScriptTool`, and
    `adk_additional_tools` metadata that executes bundled scripts and
    dynamically exposes tools. Production Solvan must not rely on any of:
    `RunSkillScriptTool`; `adk_additional_tools`; remote skill registries as
    workflow authority; skill-driven tool or permission expansion; or
    provider session state as durable activation state. An ADK parser or
    data model may be reused behind Solvan's deterministic importer, but
    Cloud SQL and the specification 17 lifecycle remain authoritative.
13. **Outcome recommendations cannot compile skills.** An Alert or Incident
    outcome may cause a scoped, expiring, machine-proposed recommendation to
    review an import candidate. It cannot supply trusted content, license
    evidence, classification, a typed step graph, evaluation, or approval.
    Accepting it enters the ordinary quarantine/import flow; a human
    `GUIDANCE_AUTHOR` supplies the typed graph or accepts §7.3's registered
    advisory checkpoint, and an independent principal approves the result.

## 4. What skills may contain

Skills may contain approved procedures, investigation order, interpretation
guidance, gotchas, output templates, and static thresholds. Skills cannot
assert current incident facts, outcomes, approvals, or verification verdicts;
specification 17 §4.2 content rules apply to imported and first-party content
alike. A threshold in a skill is a procedure parameter, not evidence about
any live system.

### 4.1 Deliberately excluded capabilities

The following are excluded by design, not omission. Each requires its own
specification revision and threat-model update before any implementation:

- **Script execution and dynamic tools** (§3 decisions 4, 12).
- **Parameterized skills.** Other runtimes pass slash-command text through as
  skill input. Solvan carries it only as an untrusted operator note (§10);
  no skill defines parameters, and no text reaches a run as a typed argument.
- **Multi-level composition.** Activation is single-level (§5.4); a skill
  cannot require, include, or activate another skill.
- **Cross-tenant sharing or a marketplace.** Interchange crosses the tenant
  boundary only through §6 import and §9 export.
- **Model-derived step graphs.** Steps come from authors or the registered
  advisory checkpoint (§7.3), never from a model reading prose.
- **Runtime behavior portability** (§1 level 5).

## 5. Solvan Agent Skills Import Profile v1

The profile restates the open Agent Skills format and marks each restriction
Solvan adds. Import validates deterministically against the closed decision
table in §5.5. Nothing is silently accepted or silently repaired.

### 5.1 Directory layout

```text
skill-name/
├── SKILL.md          # required: frontmatter + Markdown instructions
├── scripts/          # optional in the format; stored inert, never executed
├── references/       # optional: additional Markdown loaded on demand
├── assets/           # optional: templates and static resources; stored inert
└── ...
```

### 5.2 Frontmatter fields

| Field | Required | Contract |
|---|---|---|
| `name` | yes | 1–64 characters; lowercase `a-z`, `0-9`, and hyphens; no leading, trailing, or consecutive hyphens. |
| `description` | yes | 1–1024 characters, non-empty. The governed model caps descriptions at 1000 characters; 1001–1024 is a normalization finding and compilation requires an author-edited description of at most 1000 characters (Solvan restriction). |
| `license` | no | Recorded as license evidence (§3 decision 6). |
| `compatibility` | no | 1–500 characters; recorded as source metadata only. |
| `metadata` | no | String-to-string map; recorded as source metadata. |
| `allowed-tools` | no | Recorded as source metadata; grants nothing. |

Frontmatter must be one single-document YAML mapping parsed in safe mode
(§6.2).

### 5.3 Body and bundle bounds (profile restrictions)

- `SKILL.md` body: Markdown, at most 500 lines and 64 KiB.
- Each file under `references/`: Markdown, at most 64 KiB.
- Any other file: at most 256 KiB.
- Whole package: at most 64 entries and 1 MiB uncompressed; archives at most
  1 MiB compressed with a compression ratio of at most 100:1; no nested
  archives; text files UTF-8.

### 5.4 Progressive disclosure mapping

1. **Metadata** (`name`, `description`) → the bounded selection shortlist.
2. **Instructions** (`SKILL.md` body) → the fetched full content of the
   selected revision, labelled untrusted, below authoritative state.
3. **Resources** (`references/*.md`) → additional content refs of the same
   revision, fetched only when the body cites them, inside the same
   envelope, budget, and labelling. Never fetched from the origin.

Activation is single-level: an activated skill cannot activate, reference
into activation, or otherwise transitively load another skill. Composition
happens only through specification 17 selection (one primary, at most two
supporting revisions).

### 5.5 Closed decision table

Root discovery precedes the table: an upload must be a supported archive
type — Zip, POSIX tar, or gzip-compressed POSIX tar; anything else rejects
`ARCHIVE_TYPE_UNSUPPORTED` — whose expansion yields exactly one skill root
directory containing exactly one `SKILL.md`; a missing `SKILL.md`, multiple
candidate roots, or multiple `SKILL.md` candidates reject
`PACKAGE_STRUCTURE_INVALID`. "Nested archive" in §5.3 means archive-typed
**members**; the outer compression wrapper of a `.tar.gz` is not a nested
archive.

Evaluation is then deterministic: §6.2 hardening phases run in their stated
order, then table rows apply in table order per file. Every matching
condition's reason code **among the phases that ran** is recorded,
deduplicated, and sorted — a structural rejection ends the attempt without
parsing or scanning the unsafe bytes to enumerate later-phase codes. The
**validation outcome** is decided by dominance
`REJECT > STRIP > NORMALIZE > ACCEPT` and is recorded on the
`skill_validation_receipt`; the attempt's decision maps from it —
`REJECT → REJECTED`, everything else `→ QUARANTINED`. `STRIP` rows never
apply to `SKILL.md`.

| Condition | Outcome | Reason code |
|---|---|---|
| Conforming package | ACCEPT | — |
| Directory/name mismatch | NORMALIZE (directory renamed to `name`) | `NAME_DIRECTORY_MISMATCH` |
| Unknown frontmatter field | NORMALIZE (recorded, retained as source metadata) | `UNKNOWN_FRONTMATTER_FIELD` |
| Malformed optional frontmatter field (e.g. `metadata` not a string map, `allowed-tools` a YAML list) | NORMALIZE (raw value recorded verbatim as source metadata; grants nothing) | `FRONTMATTER_FIELD_MALFORMED` |
| `description` 1001–1024 characters | NORMALIZE (author edit required at compilation) | `DESCRIPTION_OVER_GOVERNED_LENGTH` |
| Reference link deeper than one level | NORMALIZE (recorded) | `REFERENCE_DEPTH_EXCEEDED` |
| External HTTP/file/data link in Markdown | NORMALIZE (recorded; never fetched) | `EXTERNAL_LINK_PRESENT` |
| Non-Markdown file in `references/` | STRIP | `REFERENCE_NOT_MARKDOWN` |
| Non-`SKILL.md` file over its size bound, package within bounds | STRIP | `FILE_OVER_SIZE` |
| `scripts/`, `assets/`, other extra entries | ACCEPT as `INERT_STORED` | — |
| Unsupported or undiscoverable package structure | REJECT | `PACKAGE_STRUCTURE_INVALID` / `ARCHIVE_TYPE_UNSUPPORTED` |
| Missing or invalid `name`/`description` | REJECT | `FRONTMATTER_INVALID` |
| `SKILL.md` over the §5.3 body bounds | REJECT | `BODY_BOUNDS_EXCEEDED` |
| Frontmatter not a single safe YAML mapping; duplicate keys; custom tags; alias/anchor flood | REJECT | `YAML_UNSAFE` |
| Package over entry/size/ratio bound; nested archive | REJECT | `PACKAGE_BOUNDS_EXCEEDED` |
| Path traversal, absolute path, Windows path, NUL byte | REJECT | `PATH_UNSAFE` |
| Symlink, hardlink, special file | REJECT | `SPECIAL_FILE` |
| Duplicate, case-folded, or NFC-collided paths | REJECT | `PATH_COLLISION` |
| Non-UTF-8 text file | REJECT | `ENCODING_INVALID` |
| Secret or credential finding | REJECT | `SECRET_OR_CREDENTIAL` |
| PII finding | REJECT | `PII_DETECTED` |
| Model Armor finding where supported | REJECT | `ARMOR_FINDING` |
| Model Armor unavailable or ambiguous | REJECT | `MODEL_ARMOR_UNAVAILABLE` |
| License absent | QUARANTINE governance state `MISSING`; compilation refused | `LICENSE_MISSING` |
| Recognized license denied by the active tenant policy | QUARANTINE governance state `REJECTED_BY_POLICY`; compilation refused | `LICENSE_POLICY_DENIED` |

## 6. Quarantined import

### 6.1 Accepted sources

Packages enter from exactly three source types:

- a **registered repository connection** (existing tenant connection record;
  named repository, subdirectory, and full commit SHA);
- an **uploaded archive** submitted by an authenticated principal;
- the **first-party repository source**: this repository at a pinned release
  commit, for packs under `guidance/` (§11).

There is no arbitrary-URL fetching. Repository fetches use the pinned
connection identity, resolve the exact commit, follow no cross-origin
redirects, and are SSRF-restricted to the connection's registered host.

### 6.2 Package hardening

Ingestion runs in three ordered phases, and no phase's decision is recorded
until the attempt completes:

1. **Structural**, before any content parsing: archive type and root
   discovery; size, entry-count, and compression-ratio limits; path,
   special-file, and collision rules (after case folding and NFC
   normalization).
2. **Parse**, on structurally safe bytes only: MIME detection for every
   file; UTF-8 validation; safe single-document YAML with duplicate-key
   rejection, no custom tags, and bounded aliases and anchors.
3. **Scan**, on parsed content: secret/credential/PII detection, Model
   Armor where supported, link and reference analysis.

Import is atomic: an accepted package is fully recorded or the attempt is
recorded as rejected with no partial `skill_import`. Idempotency binds to an
immutable `import_request_hash` covering scope; source identity and
`source_bundle_hash`; purpose; requested classification and residency;
profile and canonicalization versions; scanner and policy versions; and the
verified importer principal. It deliberately excludes the idempotency key and
the opaque, short-lived authorization receipt reference. Each attempt records
the actual server-minted authorization reference, and every retry is
reauthorized before lookup, so credential renewal neither creates duplicate
imports nor bypasses current authorization. A retry with the same
`import_request_hash` returns the existing attempt outcome; concurrent
identical requests serialize to one outcome. A request differing in any
covered element — including a policy or scanner revision — is a new attempt,
which is also the explicit reprocessing path for packages rejected under an
older policy.

The authorization reference in that hash is never caller-provided. The API
mints or resolves it from the verified principal's active scope-bound role and
binds it to the exact purpose, classification, region, source audience, and
expiry before constructing the import command.

The Dify skill-package service and the OpenAI Agents sandbox skills loader
in the pinned snapshots are reference patterns for archive hardening and
path containment; they are not dependencies.

### 6.3 Records

Every attempt writes one immutable `skill_import_attempt`:

- organization, project, and environment scope; purpose; requested
  classification and residency;
- source type and identity (connection or principal; repository,
  subdirectory, and commit SHA where applicable);
- `source_bundle_hash` where obtainable, and the `import_request_hash`
  (§6.2);
- decision `QUARANTINED | REJECTED` with the closed reason codes;
- importer principal, authorization reference, and created-at.

A rejected attempt preserves no expanded package content.

A quarantined attempt additionally writes:

- `skill_import`: the attempt reference; `source_skill_name` (the package's
  own `name`, preserved verbatim and stored separately from any Solvan
  key); `source_bundle_hash` and `normalized_package_hash` (§8); for
  repository sources, the chosen **upstream ref** (branch or tag), resolved
  commit SHA, and the provider's **subtree tree hash** for the imported
  subdirectory — the §6.5 comparison basis, bound to a lineage at
  compilation; an immutable source-package blob reference and a canonical
  prompt-content manifest reference, both stored in the tenant's CMEK-bound
  bucket in the record's region; the closed license-evidence state (§3
  decision 6) with normalized identifier, artifact reference, location, and
  digest when `PRESENT` or `REJECTED_BY_POLICY`;
  scanner names and versions; and the profile version applied.
- `skill_import_file`: per file — path, size, media type, content hash,
  immutable object reference, and disposition
  `PROMPT_ELIGIBLE | INERT_STORED | STRIPPED`.
- `skill_validation_receipt`: every §5.5 finding with its closed reason
  code.

Quarantine confers no eligibility: a `skill_import` is invisible to
selection, prompt assembly, Registry discovery, and export.

### 6.4 File dispositions

`SKILL.md` and `references/*.md` that pass §5 bounds are `PROMPT_ELIGIBLE`.
`scripts/`, `assets/`, and any other entry are `INERT_STORED`. `STRIP`
outcomes from §5.5 are `STRIPPED` with their finding.

### 6.5 Upstream refresh

For lineages whose import came from a registered repository connection, a
**refresh check** compares the origin against the lineage's last imported
state, using the same pinned connection identity and SSRF restrictions as
import:

- the caller supplies only the lineage key, expected lineage epoch, and
  idempotency key. The application loads the repository connection, upstream
  ref, pinned imported commit, subdirectory, and recorded subtree hash from
  the immutable lineage binding; none of that authority is accepted from the
  request body, a connector response, or model output;

- the comparison basis is the imported **subtree tree hash** recorded on
  the `skill_import` (§6.3): the check resolves the recorded upstream ref
  (branch or tag; "current" is never an implicit default) to a commit and
  reads the provider's tree hash for the imported subdirectory — provider
  metadata only. No file content is fetched, retained, or shown; a commit
  SHA alone is never compared against a content digest;
- checks are initiated by a `GUIDANCE_AUTHOR` in the owning department or
  by a tenant-configured schedule, and run against a durable, token-fenced
  **refresh ledger** in Cloud SQL recording each check's lease, outcome,
  last-checked-at, and failure count — the cadence survives process
  restarts and concurrent workers serialize on the lease;
- cadence is bounded by the ledger: at most one check per lineage per hour
  and at most three failed-check retries per lineage per day. Because a
  failed check ends in an error response, ledger accounting cannot share the
  request's transaction: the claim commits before the origin is contacted and
  the outcome commits after it, so a failure that propagates to the caller
  still increments the count that bounds the next retry. A refused check —
  lease held, cadence not elapsed, or lineage epoch conflict — records its own
  attempt row with the refusal reason rather than passing unrecorded;
- an observed subtree tree hash differing from the imported one writes one
  immutable upstream-change notice keyed by
  `(lineage, upstream_ref, observed_commit, observed_tree_hash)`; an
  already-recorded key writes nothing, so a changed-but-unimported origin
  produces exactly one notice per distinct observed state, not one per
  check.

A refresh check fetches nothing into prompts, creates no import, and
changes no revision. Acting on a notice is always an explicit new §6 import
attempt.

### 6.6 Retention, deletion, and residency

Every source package, manifest, imported file, validation receipt, and export
receipt has a scoped `skill_retention_controls` record. The record binds the
object to its storage region, retention deadline, deletion state, and optional
legal-hold reference. A deletion worker may mark an object eligible only after
the deadline, with no legal hold, and from the same regional control plane;
the worker then writes a verified deletion receipt before the row becomes
`DELETED`. A hold or region mismatch refuses deletion. Object storage uses
the tenant's regional CMEK-backed bucket, and a process restart or duplicate
job cannot turn a pending or held record into deletion.

Claim-time eligibility does not authorize the delete. Settlement re-reads the
control row under its lock, re-evaluates hold, region, and deadline against
that locked state, and only then calls the provider, so a hold attached
between claim and settlement refuses while the object still exists; a refusal
releases the claim rather than consuming it, and a superseded claim settles
nothing. The provider delete, the receipt, and the transition to `DELETED`
commit together, and the row keeps the claim that authorized it. Deleting an
object the provider reports as already absent is a successful settlement, so a
worker that crashes between the provider call and the commit converges on
retry instead of stranding an object with no receipt.

The retention deadline is not chosen by an import request, a model, or an
environment variable. Each scope has one operator-managed
`skill_retention_policies` row containing the approved storage region and a
retention duration in days (`1..3650`). Import and export transactions lock
that row and register every object they create with
`retention_until = created_at + retention_days`; a missing policy, a region
mismatch, or an object without a provider generation refuses the transaction.
License evidence is registered as `LICENSE_EVIDENCE`, and each scanner or
validation receipt is materialized as an immutable object before its SQL row
is committed. Registration is idempotent on the scoped object key. The
deletion worker claims only registered rows and settles them with a
generation-fenced provider receipt, so an unregistered object is never
silently treated as retained or deleted.

## 7. Compilation into governed guidance

A `GUIDANCE_AUTHOR` compiles a quarantined import into a `DRAFT`
`GuidanceRevision` by supplying everything the governed model requires and
the package cannot provide. The application validates the complete record
before writing; if any required field is missing the draft is not created.

| `GuidanceRevision` field | Source |
|---|---|
| `guidance_key` | internal key chosen by the author (§7.1); never the raw `source_skill_name` |
| `version`, `purpose`, `classification`, `owner_department`, `author_principal` | supplied by the author |
| `display_name` | author-editable default derived from `source_skill_name` |
| `description` | package `description`, author-editable, screened; an author edit to ≤ 1000 characters is mandatory when the import recorded `DESCRIPTION_OVER_GOVERNED_LENGTH` |
| `guidance_kind` | `SKILL`, deterministically |
| `discoverable_departments`, `applicable_service_kinds`, `applicable_incident_classes`, `symptom_tags`, `eligible_regions`, `allowed_agent_keys`, `required_profile_revisions` | supplied by the author; all non-empty per the governed model |
| `steps` | author-typed graph or the advisory checkpoint step (§7.3); non-empty per the governed model |
| `content_ref`, `content_hash` | the canonical prompt-content manifest; `guidance_content_hash` (§8) |
| `source_kind` | `IMPORTED` (or `SOLVAN_AUTHORED` for the first-party source, §11) |
| `source_ref` | the `skill_import` record reference |
| `source_license` | the reviewed normalized license identifier (§7.2); requires evidence state `PRESENT` |
| `lifecycle` | `DRAFT` |

The draft then follows specification 17 §5 unchanged: evaluation,
independent approval of the exact digest, publication. Importers have no
approval authority.

### 7.1 Keys, selectors, and slash grammar

Internal identity uses the existing `guidance_key` grammar
(`^[a-z0-9]+([._-][a-z0-9]+)*$`; no slashes):

```text
guidance_key       = <owner-slug> "." <skill-name>
owner-slug         = registered stable owner_department_slug
                     (lowercase alphanumerics and single hyphens)
```

The `owner_department_slug` is a registered, immutable identifier; identity
is never derived from the human-readable department name. The human-facing
**qualified selector** is a distinct surface form, parsed and mapped to the
internal key:

```text
selector           = <owner-slug> "/" <skill-name> | <skill-name>
command            = "/" selector [ SP note ]
```

A bare `<skill-name>` resolves only when exactly one eligible lineage
matches within the caller's grant scope; otherwise the closed disambiguation
refusal lists the qualified selectors. The grant scope is the union of the
caller's grants, not any one of them: eligible lineages are collected across
every grant and counted as distinct lineages before resolution, so a name that
one grant resolves and another finds ambiguous refuses. The same lineage
reached through several grants is one match, not an ambiguity. A qualified
selector is held to the same rule — matching more than one lineage refuses
rather than preferring the most recently approved. `note` is carried as an
untrusted operator note (§10).

### 7.2 License evidence and normalization

Two representations, never conflated:

- the **immutable license evidence artifact** in quarantine (§6.3): the
  frontmatter value, bundled license file, or repository declaration, with
  location and digest;
- the **reviewed normalized license identifier** (an SPDX expression or a
  registered internal identifier, ≤ 160 characters) that the compiling
  `GUIDANCE_AUTHOR` proposes from the evidence and the independent
  `GUIDANCE_APPROVER` binds at approval.

Acceptability is a governance determination against the registered tenant
license policy; repository metadata alone proves neither licensing rights nor
export permission. Compilation must match the author-supplied normalized
identifier byte-for-byte to the identifier persisted with the evidence; it
cannot substitute a different allowed identifier. An evidence state of
`MISSING` or `REJECTED_BY_POLICY` blocks
draft creation, approval, activation, and export; the quarantined record
itself is unaffected and may be reassessed under §6.2's reprocessing path.

### 7.3 The advisory checkpoint step

For skills consulted as prose rather than tracked procedures, the compiled
step graph is exactly one registered step. Every governed step field is
pinned; nothing is left for an implementer to invent:

```text
step_key:                     fetch-content
ordinal:                      1
title:                        Fetch guidance content
objective:                    Fetch this exact revision's content into the
                              labelled untrusted guidance envelope for this
                              run.
step_kind:                    CHECKPOINT
allowed_tool_revisions:       ()
prerequisite_step_keys:       ()
completion_predicate_key:     guidance-content-fetched
completion_predicate_version: 1
required_evidence_kinds:      (GUIDANCE_FETCH_RECEIPT,)
maximum_tool_requests:        0
on_blocked:                   CONTINUE
```

`guidance-content-fetched@1` asserts exactly what its evidence proves:
satisfied when the run's persisted selection record and bounded-fetch
receipt reference this exact revision's content digest. It deliberately
does **not** claim the content was consulted, understood, or followed —
no receipt can prove a model's internal use, and every rendered label for
this step says "fetched", never "consulted". Authors replace the checkpoint
with a genuine typed graph when procedure-grade tracking is wanted.

The `guidance-content-fetched@1` predicate and `GUIDANCE_FETCH_RECEIPT`
evidence kind are registered. Coordinator fetch records produce the exact
digest-bound receipt, and approval of a revision naming any unregistered
predicate or evidence kind fails closed.

### 7.4 Evaluation material

Specification 17's pipeline stage 7 (adversarial evaluation under
specification 08) is concretized for skills. Evaluation material lives on
the **evaluation record**, not on the draft: the implemented model
correctly forbids a non-approved revision from carrying `evaluation_ref`,
so the record references the draft, results bind to the draft's
**reviewable-material digest** (the governed digest computed excluding
evaluation and approval fields), and `evaluation_ref` attaches to the
revision at the approval transition. The approval binds the pair
(reviewable-material digest, evaluation receipt hash); this avoids the
circularity of a digest that changes when results are attached. Aligning
the implemented approval digest to exclude `evaluation_ref` is a declared
target dependency (§13).

Three case families:

- **Activation cases**: prompts and alert descriptions that should and
  should not shortlist this revision, evaluated against the fixed corpus of
  the tenant's approved guidance; description tuning is measured, not
  guessed.
- **Output-conformance cases**: where the skill defines an output template,
  graded checks that a run following the content produces the template's
  structure.
- **Injection-resistance cases**: the skill's own content embedded with
  adversarial instructions must not alter tool sets, step statuses, claims,
  or transitions in the evaluation harness.

Model execution is not deterministic, and this contract does not pretend
otherwise. What is deterministic is the **aggregation**: each case run
persists a per-run receipt (pinned model and configuration, grader
material, inputs, and graded result), and the evaluation verdict is a
deterministic aggregation over those stored receipts under recorded
thresholds. The evaluation receipt records the corpus digest, case-set
digest, scorer name and version, model/configuration pins, repetition
count, and pass thresholds. Model-graded results **contribute to** the
approval evidence a human `GUIDANCE_APPROVER` weighs; they never
independently establish it. Any content change invalidates prior results
and requires re-evaluation before approval. The upstream `skills-ref` and
agentskills.io evaluation guidance are calibration references for case
design, not graders.

Evaluation receipt material is retrieved and verified by a registered,
fail-closed application adapter. An evaluator request may name a receipt but
may not assert its pass counts, digest, suite, model, thresholds, or verdict.
The adapter verifies immutable object generation and bytes, the registered
suite version, and every binding above before the evaluation record is
committed. Approval selects that verified record and attaches
`evaluation_ref` atomically; an unavailable, ambiguous, or mismatched receipt
refuses the transition.

### 7.5 Collisions, idempotency, and retirement

Within one owner department, a `guidance_key` names one permanent lineage:

- compilation idempotency binds to scope + `skill_import` reference +
  requested revision reference + the full proposed approval digest
  (specification 17's reviewable-material digest). Identical proposals
  return the existing draft; a differing proposal for the same revision
  reference conflicts explicitly.
- the same `skill_import` may legitimately compile into materially distinct
  revisions (different eligibility, classification, steps, predicates,
  profiles, version, or purpose); `source_bundle_hash` is provenance, never
  revision identity, and revision content is deliberately not unique per
  key — a metadata-only successor reuses its predecessor's content hash.
- the lineage is a chain, not a bag: every revision after the first names
  its exact predecessor in `supersedes`, whether the change came from a new
  import digest or from metadata alone; nothing is silently merged and
  there is no branching. The chain is schema-enforced — at most one
  successor per predecessor and exactly one root per key — so two
  concurrent proposals naming the same predecessor conflict at insert; the
  loser re-proposes against the new chain tip. The application owns a
  single **current head** per key, defined as the furthest revision along
  the `supersedes` chain whose lifecycle is `APPROVED`, advanced by
  compare-and-set at the approval transition. Deprecating the head leaves
  the key **headless** — a bare or qualified selector then returns the
  closed refusal rather than silently resurrecting an older approved
  predecessor — until a successor is approved.
- the approval surface's diff renders from the canonical prompt-content
  manifests of the revision and its named predecessor, and a diff shown
  under a ceiling says it was truncated (specification 06 §17).
- retired keys remain permanently owned by their lineage definition; a
  retired key is never recycled for another department or display identity.

Cross-department discovery always displays the owning department, so a
typosquatted name in another department cannot impersonate an existing
lineage.

## 8. Digests and canonicalization

Four digests with distinct meanings; none is interchangeable:

- `source_bundle_hash` — the exact accepted source: the archive bytes as
  uploaded, or the canonical manifest of the fetched repository subtree.
- `normalized_package_hash` — the canonical manifest of the full quarantined
  package after §5.5 normalization, all dispositions included.
- `guidance_content_hash` — the canonical manifest of the normalized
  prompt-visible content only: the `SKILL.md` **body** (transport
  frontmatter excluded) plus sorted `references/` path/content pairs. This
  is `GuidanceRevision.content_hash`. Excluding transport frontmatter is
  what makes export round-trips digest-stable (§9).
- `export_bundle_hash` — the generated export package bytes.

The canonicalization contract is the target artifact
`specs/artifacts/skill-canonicalization.md`, versioned as
`skill-canonicalization/1`. It defines: relative POSIX paths sorted bytewise; NFC
name normalization; LF newlines; no BOM; canonical-JSON manifest encoding
with explicit length framing; **domain separation** so each of the four
digest kinds is computed under a distinct domain prefix and identical bytes
in different roles never collide; the `sha256:<64 hex>` representation
required by `GuidanceRevision`; exclusion of file modes and empty
directories; the **deterministic export container** (archive type, fixed
timestamps, fixed permissions, entry ordering, and compression parameters)
without which `export_bundle_hash` is not reproducible; and test vectors
with expected digests for each of the four digest kinds. Records store the
canonicalization version they were computed under.

## 9. Export

Export is an authorized, receipted operation, not a download:

- is gated on lifecycle: only `lifecycle = APPROVED` revisions export
  without qualification; a `DEPRECATED` revision exports only with an
  explicit stale-content acknowledgment recorded in the receipt; `DRAFT`,
  `IN_REVIEW`, and `RETIRED` fail closed with a closed reason code;
- requires the `GUIDANCE_EXPORTER` role and a purpose-bound authorization
  naming a destination from the tenant's registered destination allowlist;
- requires classification permitting the boundary crossing and a license
  redistribution/derivative-work check against the recorded evidence;
- rescans the exact exported bytes for secrets and PII. The bundle is a
  compressed archive, so the rescan reads back the produced bytes and scans
  each entry's decoded text — including the regenerated frontmatter, which no
  earlier gate has seen in its exported form. Scanning the archive's
  compressed bytes as one blob satisfies nothing: the deterministic scanners
  cannot match plaintext through DEFLATE and a content scanner cannot decode
  it. The recorded license-policy and byte-rescan results are the verdicts
  those gates actually returned, never a constant;
- is idempotent on an **export request hash** covering scope, revision
  reference, destination binding, purpose, authorization reference, and
  disclosure-policy version. The same hash returns the existing receipt; a
  reused idempotency intent with any differing covered element is a
  conflict, never a second export or a silently returned wrong one;
- records every attempt: a denied export writes an immutable export-attempt
  audit record with its closed denial reason; a completed export writes one
  immutable `skill_export_receipt` carrying the export request hash,
  revision reference and its lifecycle at export, the `DEPRECATED`
  stale-content acknowledgment when applicable, purpose,
  `export_bundle_hash`, `guidance_content_hash`, license-policy check
  result, byte-rescan result, disclosure-policy version, exporter
  principal, authorization reference, destination binding, and created-at —
  and records the destination's receipt where the destination supports
  one.

The exported package is conforming under §5:

- frontmatter: `name` from the key's skill-name part, `description`,
  `license` from the normalized identifier, and provenance under `metadata`
  keys `solvan-content-digest` (always) and `solvan-export-id` (an opaque
  receipt reference). Revision and owner identity appear only when the
  tenant's export policy permits identity disclosure; the raw
  `owner_department` never appears.
- body and `references/` from the exact approved content;
- no scripts, no inert artifacts, no credentials, and no approval or
  evaluation claims — Solvan approval authority does not travel.

Export is lossy by design; `export_bundle_hash` never equals
`source_bundle_hash`. Re-import of an export follows §6 like any other
package, and because `guidance_content_hash` excludes transport frontmatter,
its `guidance_content_hash` equals the exported revision's.

## 10. Operator-explicit selection

Specification 14 registers one closed intent whose deterministic behavior is
defined here:

| Intent | Example | Authority route | Behavior |
|---|---|---|---|
| `GUIDANCE_REFERENCE` | `/triage-payments-latency`, `/payments-sre/triage-payments-latency check spikes since 14:00` | `ASK` (specification 14's closed route vocabulary) | resolve one APPROVED, scope-eligible revision via the §7.1 selector grammar and record an operator-selected guidance candidate for the anchored case or incident |

Rules:

- autocomplete lists only revisions the caller's grant scope can discover;
- the `note` text is carried as an untrusted operator note attached to the
  selection record; it is not parsed into parameters, steps, or facts, and
  it **never enters any model context** — it is operator-to-operator
  annotation, readable only on the selection record under the record's
  access mode;
- selection records `selection_reason = OPERATOR_INVOKED` and then follows
  specification 17 §6 unchanged: coordinator revalidation, persisted exact
  keys and hashes, bounded fetch, untrusted labelling;
- an ineligible or ambiguous reference returns a closed refusal template
  (with qualified selectors on ambiguity) and never falls back to
  model-ranked selection silently; the template itself is part of the
  specification 14 registry addition (§13);
- precedence: the one primary revision's instructions take precedence over
  supporting revisions. A **conflict is a computed fact, not a model
  assertion**: it exists only when the application matches author-declared
  incompatibility declarations or an enumerated code rule such as
  colliding output templates. Declarations live in a typed, author-owned
  incompatibility relation keyed to the declaring revision and covered by
  its reviewable-material digest (§13) — never in package metadata, model
  output, or prose. Model narration reporting tension between skills is
  recorded as model-reported uncertainty, never as a conflict record.
  Because a conflict is computed against the invocations already recorded in
  the thread, two concurrent invocations would each observe a thread with no
  conflicting row and both record; invocation recording therefore serializes
  per thread, so the second observes the first's pending invocation.
  Declarations bind to every guidance kind, not only skills;
- selection never widens a Tool set, never marks steps, and any proposed
  action that results remains subject to every action, approval, and
  verification gate.

Shortlist integrity: per-owner-department candidate quotas bound bulk
imports, and equal-applicability ties break deterministically (approval
recency, then key order).

### 10.1 Selection analytics

The feedback loop that keeps descriptions honest is measured, content-free,
and scope-filtered:

- per revision: shortlist appearances, selections by reason (model-ranked
  versus `OPERATOR_INVOKED`), `NO_GUIDANCE_MATCH` outcomes where the
  revision was shortlisted, disambiguation and refusal counts, and the
  application-computed step statuses of runs that selected it;
- analytics rows carry revision references and closed codes only — never
  skill content, operator notes, or incident narrative;
- the console surfaces these counters on the lineage (specification 06 §18)
  so authors tune `description` text from observed activation, mirroring the
  agentskills.io description-optimization loop with recorded data instead of
  guesswork;
- analytics are a projection, not authority: nothing reads them for
  eligibility, ranking weight changes require a new approved revision, and
  retention follows the tenant's telemetry policy.

## 11. First-party guidance packs

Solvan-authored packs live at `guidance/<owner-slug>/<skill-name>/SKILL.md`
in this repository — the owner-slug segment prevents the cross-department
collisions a flat layout would recreate — and follow the agentskills.io
authoring guide: descriptions state what and when with trigger keywords; one
coherent procedure per skill; gotchas and output templates inline; detailed
reference material split into `references/`; defaults over menus;
specificity matched to fragility.

First-party publication is an ordinary §6 import from the first-party
repository source (§6.1) at a pinned release commit. It creates a
`skill_import_attempt` and `skill_import` like any other source.

Repository location alone does **not** establish authorship:
`source_kind = SOLVAN_AUTHORED` additionally requires a per-pack
provenance attestation — an authorship statement plus a per-file
third-party-notice review — recorded at compilation by the
`GUIDANCE_AUTHOR` and covered by the reviewable-material digest. Only then
is the repository license recorded as the license evidence with
third-party license policy set aside; a pack containing attested
third-party material compiles as `IMPORTED` under the full third-party
license rules instead. First-party packs are **built-in product
guidance**: part of the application, versioned with the release, and not
client-manageable content. At deployment, the release identity publishes
each pack through the standard specification 17 lifecycle machinery —
no separate write path — using three distinct release principals:
`product:solvan` as author, `release:merge-gate` as evaluator, and
`release:manager` as approver. The pinned release commit's merge-gate run
is the evaluation receipt and the release approval is the approval
record; every ordinary digest, role-binding, ingestion-receipt,
predicate, and separation check still executes. Built-in guidance cannot
be deprecated, retired, or removed by tenant principals — only
`release:`-prefixed principals may transition it, so a built-in revision
is superseded or retired exclusively by a subsequent application release.

Publication runs in the catalog-publication release job, in the same
transaction and immediately after principals, tools, and profiles, because a
pack revision binds registered Agents and approved profiles that do not exist
when the migration job runs. The loader refuses to run without an identifiable
release commit: an explicit argument, then `SOLVAN_RELEASE_COMMIT`, then
`git rev-parse`, and a value that is not a full commit SHA is a typed refusal
rather than a placeholder, because that commit is both idempotency material
and the evaluation's receipt reference. It also refuses an absent `guidance/`
directory, an unknown owner family, a family whose Agents or profiles are not
published, a frontmatter name that differs from its directory, duplicate
guidance keys, a missing or invalid `PROVENANCE.yaml`, and a lineage whose
versions are not release-authored — never a silent skip. The sha256 of each
pack's `PROVENANCE.yaml` is bound into the evaluation's pinned configuration
as `provenance_attestation`.

Convergence is by digest, and supersession is the only way a pack changes.
Publication recomputes each pack's revision and compares it to the lineage
head: an equal digest is an exact no-op, so re-running the loader at the same
commit converges rather than republishing. A differing digest supersedes —
`release:manager` deprecates the approved head and publishes the next integer
version, linked by `supersedes`, through the full
draft→ingest→submit→evaluate→approve chain in one transaction. Because a
revision digest pins its release commit, each release commit republishes every
pack. No approval, evaluation, ingestion receipt, selection, or audit event is
ever deleted or rewritten to converge a lineage; a stale never-approved draft
is left as immutable history and superseded past. Decision request IDs are
commit- and version-qualified as
`builtin:{commit12}:{key}@{version}:{stage}`, so replaying a release is
idempotent per revision while a new release remains a distinct decision.
Imported and customer-authored content keeps the full quarantine,
evaluation, and independent-approval path unchanged.

Validation uses an internally maintained, pinned profile validator run by
`scripts/check` once packs exist; an invalid pack fails the merge gate. The
upstream `skills-ref` tool describes itself as demonstrative and serves only
as a compatibility oracle in evaluation, never as a production dependency or
security control.

## 12. Threat model deltas

| Threat | Position |
|---|---|
| Frontmatter/description prompt injection | Attacker-writable text screened at ingestion, labelled untrusted in shortlists and prompts, below authoritative state; cannot mint tools, facts, approvals, or transitions (§3 decision 7). |
| Body/reference prompt injection | Unchanged from specification 17: data envelope below authoritative state. |
| Script or binary smuggling | `scripts/`/`assets/` are `INERT_STORED`; nothing executes, installs, or prompt-loads them; ADK script/tool machinery is prohibited (§3 decisions 4, 12). |
| Dynamic tool expansion via metadata | `allowed-tools` and `adk_additional_tools` grant nothing; Tools come only from the frozen profile. |
| Archive attacks (bombs, traversal, links, collisions) | §5.5/§6.2 hardening; rejection classes abort atomically with an audited attempt. |
| Name collision, typosquatting, key recycling | Qualified keys on registered owner slugs, deterministic collision handling, permanent lineage ownership of retired keys, owner display (§7.1, §7.5). |
| Moving-origin substitution | Pinned commit and `source_bundle_hash`; activation never contacts the origin; a digest change is a new quarantined import. A partial provider listing would hash a subset and report `UNCHANGED` over changed files, so tree observation follows the provider's pagination to a bounded page count and refuses on a missing, inconsistent, or exceeded bound rather than observing part of a tree. Metadata reads refuse redirects on every path, not only content fetches. |
| License spoofing or laundering | Evidence artifact with digest; human-determined normalized identifier bound at approval; no evidence → no draft, approval, activation, or export (§7.2). |
| Export exfiltration | Export role, purpose-bound authorization, destination allowlist, byte rescan, receipts, policy-controlled identity disclosure (§9). |
| Shortlist flooding | Bounded shortlist, per-owner quotas, deterministic tie-breaking (§10). |
| Stale approval reuse | Approval binds the full approval digest; a differing proposal or new import digest requires new evaluation and approval (§7.5). |
| Tenant or region leakage via import/export | Scope, classification, and residency are recorded on the attempt and enforced at quarantine scanning, draft, approval, and export gates; blobs live in CMEK-bound regional storage (§6.3, §9). |

## 13. Implementation and qualification status

The target product path is **implemented** and **verified locally**. The
logical record names in §§6–10 map to the plural physical tables in
`operability-schema.target.v3.sql`. The following are checked in and exercised
by the acceptance registry in §14:

1. canonical import/profile validation, domain-separated digests, immutable
   object receipts, Cloud SQL attempts and quarantine persistence;
2. fail-closed secret, PII, license-policy, and Model Armor adapters with
   version-bound idempotency and immutable receipts;
3. registered owner slugs, license policies, reader grants, export
   destinations, and server-derived role authorization;
4. compilation into typed `DRAFT` guidance, exact license-evidence binding,
   first-party provenance, evaluation receipt verification, independent
   approval, incompatibility declarations, and current-head compare-and-set;
5. `guidance-content-fetched@1`, `GUIDANCE_FETCH_RECEIPT`, coordinator-owned
   selection and revalidation, inert operator notes, and content-free
   analytics;
6. registered GitHub/GitLab pinned-source adapters, metadata-only refresh,
   durable token fencing, cadence/retry enforcement, and change notices;
7. deterministic export with `PREPARED` recovery, exact destination snapshot,
   byte rescanning, license redistribution policy, stale-content
   acknowledgment, GCS generation receipts, and immutable export receipts;
8. regional retention policies, legal holds, generation-fenced deletion, the
   first-party pack validator, authenticated API seams, and the Agent Fleet
   Skills console with lifecycle and governance views.

The target is not **release-qualified** until deployment produces external
receipts for all configured environments. Those remaining qualification
dependencies are operational, not missing application behavior:

- a tenant regional Skills bucket with CMEK posture and immutable-generation
  qualification;
- deployed OIDC/IAM role bindings and positive/negative authenticated route
  receipts;
- a configured regional Model Armor endpoint and scanner receipt;
- tenant-registered GitHub/GitLab token brokerage, repository allowlists, and
  export destinations where those optional integrations are enabled; and
- deployed scheduling and restart evidence for the bounded retention sweep.

D-033 fixes the profile bounds and shortlist quota. A later change requires a
new profile version rather than changing those constants in place.

## 14. Acceptance criteria

Target tests mapped in `specs/artifacts/skills-acceptance-registry.yaml` and
executed by the canonical check; they remain excluded from the required
competition-release map until this specification's release status changes:

1. `CT-SKILL-PROFILE-001` — every §5.5 row produces exactly its declared
   outcome and reason code; no condition falls through to an undeclared
   outcome; a package matching several rows records every code and resolves
   by the declared dominance order; an oversized `SKILL.md` rejects rather
   than strips; root-discovery failures reject with their structural codes.
2. `CT-SKILL-ATTEMPT-001` — a rejected package writes one
   `skill_import_attempt` with closed reasons and no partial `skill_import`
   or expanded content; an accepted package writes the full §6.3 record set
   with scope, classification, residency, blob and manifest references, and
   CMEK/region binding; the recorded validation outcome maps to the attempt
   decision exactly as §5.5 declares (`REJECT → REJECTED`, else
   `QUARANTINED`).
3. `CT-SKILL-DIGEST-001` — the four §8 digests match the canonicalization
   contract's test vectors, record their canonicalization version, and use
   the `sha256:` representation.
4. `CT-SKILL-COMPILE-001` — draft creation fails closed when any governed
   field, step graph, license identifier, or evidence is missing, and
   succeeds only as a fully valid `DRAFT` with `guidance_kind = SKILL`
   referencing the import record.
5. `CT-SKILL-STEP-001` — the §7.3 step block constructs a valid
   `GuidanceStepRevision` field-for-field, including the forbidden-phrase
   screen on its objective; `guidance-content-fetched@1` is satisfied only
   by the persisted selection record and bounded-fetch receipt of the exact
   revision's content digest, and every rendered label says "fetched";
   approval of a revision naming an unregistered predicate or evidence kind
   fails closed.
6. `CT-SKILL-KEY-001` — internal keys reject slashes; the §7.1 selector
   grammar maps qualified and bare selectors correctly; a bare-name
   ambiguity returns the closed disambiguation refusal.
7. `CT-SKILL-IDEMPOTENT-001` — identical concurrent compilation proposals
   yield one draft; the same `skill_import` compiles into two materially
   distinct successor revisions with distinct approval digests and the
   later one naming its predecessor; a metadata-only successor persists
   with its predecessor's content hash; a retried import with the same
   `import_request_hash` returns the existing attempt, while a request
   differing only in purpose, classification, or scanner/policy version is a
   new attempt; renewal of only the server-minted authorization receipt is the
   same logical attempt and still requires fresh authorization.
8. `SEC-SKILL-NOEXEC-001` — a package carrying scripts, `allowed-tools`,
   `adk_additional_tools` metadata, and an injected instruction body yields
   a revision whose activation exposes no script, grants no tool, and places
   all content below authoritative state.
9. `SEC-SKILL-ARCHIVE-001` — archive-bomb, traversal, symlink, nested-
   archive, case-fold/NFC collision, and NUL-byte packages reject atomically
   with closed reason codes and audited attempts.
10. `SEC-SKILL-YAML-001` — multi-document, duplicate-key, custom-tag, and
    alias-flood frontmatter rejects; safe-mode parsing is verified.
11. `SEC-SKILL-PIN-001` — after import, mutating the origin does not change
    activated content; the digest mismatch surfaces only as a new
    quarantined import candidate.
12. `SEC-SKILL-LICENSE-001` — a package without license evidence
    quarantines with state `MISSING` and no evidence-artifact fields, but
    cannot produce a draft, approval, activation, or export; the normalized
    identifier is bound at approval and reproduced on export; evidence and
    identifier are stored separately; a disallowed identifier quarantines as
    `REJECTED_BY_POLICY`, and compilation cannot substitute a different
    allowed identifier.
13. `SEC-SKILL-SCOPE-001` — cross-tenant and cross-region packages and
    exports are denied at quarantine scanning, draft, approval, and export
    gates.
14. `SEC-SKILL-EXPORT-001` — export without the exporter role, a
    purpose-bound authorization, or an allowlisted destination is denied
    with an export-attempt audit record; the byte rescan blocks planted
    secrets; a repeated request with the same export request hash returns
    the existing receipt, and reuse with a different destination or
    revision conflicts rather than exporting; receipts carry every §9
    field; identity disclosure follows export policy.
15. `IT-SKILL-INVOKE-001` — the registered `GUIDANCE_REFERENCE` behavior
    resolves an eligible revision deterministically, records
    `OPERATOR_INVOKED` and the untrusted note, refuses ineligible or
    ambiguous references with the closed template, and never falls back to
    model ranking silently.
16. `IT-SKILL-PRECEDENCE-001` — a conflict record exists only from
    author-declared incompatibility metadata or the enumerated code rule;
    model-narrated tension is recorded as model-reported uncertainty and
    creates no conflict record; transitive activation attempts are inert.
17. `CT-SKILL-EXPORT-RT-001` — a frontmatter-rewriting export re-imports to
    an equal `guidance_content_hash`; the re-import's `source_bundle_hash`
    differs from the original import's; domain separation guarantees no
    digest kind ever equals another digest kind over the same bytes.
18. `CT-SKILL-FIRSTPARTY-001` — a first-party pack imports through the
    §6 quarantine from the pinned repository source and compiles as
    `SOLVAN_AUTHORED` only with the recorded provenance attestation;
    without it, or with attested third-party material, compilation is
    `IMPORTED` under third-party license rules; the draft remains
    ineligible until independent guidance approval; every in-repo pack
    passes the pinned §5 validator in `scripts/check`.
19. `CT-SKILL-REFRESH-001` — a refresh check compares the recorded imported
    subtree tree hash against the origin's observed tree hash via provider
    metadata only, fetching no file content; a changed origin writes one
    notice per distinct observed state, an unchanged origin writes nothing,
    and repeated checks of the same state write nothing more; the ledger
    enforces the cadence and retry budget across a simulated process
    restart and a concurrent worker.
20. `CT-SKILL-EVAL-001` — a revision cannot be approved without an
    evaluation record bound to its reviewable-material digest; a content
    change invalidates prior results; `evaluation_ref` attaches only at the
    approval transition; grading reproduces exactly given the receipt's
    corpus digest, case-set digest, scorer version, repetitions, and
    thresholds.
21. `CT-SKILL-ANALYTICS-001` — selection analytics record only revision
    references and closed codes, never content or notes; counters match a
    scripted selection sequence; analytics influence no eligibility or
    ranking.
22. `SEC-SKILL-EXCLUSION-001` — a package or note attempting parameterized
    input, transitive activation, or cross-tenant sharing exercises only the
    §4.1 exclusions: the note stays an inert string that never enters model
    context, nested activation is refused, and no cross-tenant path exists.
23. `SEC-SKILL-LIFECYCLE-001` — export of `DRAFT`, `IN_REVIEW`, and
    `RETIRED` revisions fails closed with a closed reason code even under a
    valid role, authorization, license, and classification; `DEPRECATED`
    exports only with the stale-content acknowledgment recorded in the
    receipt; an imported revision is representable through `APPROVED`,
    `DEPRECATED`, and `RETIRED`, while only eligible lifecycle states can be
    selected or exported.
24. `CT-SKILL-LINEAGE-001` — two concurrent proposals naming the same
    predecessor yield exactly one successor and one explicit conflict; the
    chain never branches; the current head advances only at the approval
    compare-and-set; deprecating the head makes bare and qualified
    selectors return the closed refusal until a successor is approved, and
    no older approved predecessor silently resurrects.
