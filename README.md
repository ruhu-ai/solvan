# Solvan

Solvan is an autonomous production engineer that detects degradation, gathers
evidence, performs bounded policy-authorized mitigation, coordinates permanent
repair, independently verifies recovery, and remains responsible through a
multi-day Reliability Case.

Solvan is designed and operated as a production GCP control plane. Its normal
environments are `dev`, `staging`, and `production`; the customer estate,
approved connections, and governed Production Graph decide what it can observe
or act upon. The payments fault drill is an isolated acceptance workload,
not a product environment or a dependency of a customer deployment.

The competition release targets the **Fortified Enterprise Fleet** category of
the All Things Agentic Hackathon. It uses Gemini 3.6 Flash for the fast fleet,
Gemini 3.1 Pro Preview for the optional public-synthetic deep workspace, Google
ADK, the official
Antigravity SDK in a private regional Cloud Run service, Agent Runtime, Agent
Platform Sessions, Memory Bank, Agent Registry, Agent Identity, Agent Gateway,
Model Armor, Agent Observability, and Google Cloud infrastructure. Managed
Agents is a separate evaluated surface and is not part of Solvan's SDK path.

## Specification pack

The specifications are normative design contracts. The long-form
[`solvan v0.3.md`](solvan%20v0.3.md) remains the product vision and competition
thesis.

1. [Product requirements](specs/01-product-requirements.md)
2. [System architecture and GEAP integration](specs/02-system-architecture.md)
3. [Agent, model, and runtime contracts](specs/03-agent-model-runtime.md)
4. [Domain, data, event, tool, and API contracts](specs/04-data-event-api.md)
5. [Security, governance, privacy, and sovereignty](specs/05-security-governance.md)
6. [Console UI and UX](specs/06-ui-ux.md)
7. [Implementation and deployment](specs/07-implementation-deployment.md)
8. [Test, evaluation, and release acceptance](specs/08-test-evaluation-acceptance.md)
9. [Competition demo and submission](specs/09-competition-demo-submission.md)
10. [Design system](specs/10-design-system.md)
11. [Ruhu on GCP integration profile](specs/11-ruhu-integration-profile.md)
12. [Workspace cognition architecture](specs/12-workspace-cognition-architecture.md)
13. [Tenant integration — observe and actuate](specs/13-tenant-integration.md)
14. [Conversational surface — one ledger, three verbs](specs/14-conversational-surface.md)
15. [Console Settings](specs/15-console-settings.md)
16. [Governed Tool Catalog and capability profiles](specs/16-governed-tool-catalog.md)
17. [Governed operational guidance and trigger policies](specs/17-governed-operational-guidance.md)
18. [Agent Skills interchange](specs/18-agent-skills-interchange.md)
19. [SaaS scale, tenant isolation, and cell architecture](specs/19-saas-scale-and-isolation.md)
20. [Production environment model](specs/20-production-environment-model.md)
21. [Alert Triage](specs/21-alert-triage.md)
22. [Solvant Relay — customer-resident read-only evidence plane](specs/22-solvant-relay.md)
23. [Code Repair Workspace profile and skills](specs/23-code-repair-workspace-profile.md)
24. [Governed GitHub conversation](specs/24-governed-github-conversation.md)

Executable specification artifacts (DDL, concurrency SQL, state-machine YAML,
release fixtures/policy, and PR-to-test traceability) live in
[`specs/artifacts/`](specs/artifacts/).

Supporting material:

- [Architecture map](ARCHITECTURE.md)
- [Enterprise architecture reference (print/PDF)](Solvan_Enterprise_Architecture.html)
- [Competition architecture reference — Solvan through the ADK-lab lens (print/PDF)](Solvan_Competition_Architecture.html)
- [Submission architecture image](docs/assets/architecture.svg)
- [Implementation plan](PLAN.md)
- [Documentation policy](docs/documentation-policy.md)
- [Gemini Enterprise Agent Platform source register](docs/sources/gemini-enterprise-agent-platform.md)
- [SaaS scale and tenant-isolation source record](docs/sources/saas-scale-and-isolation.md)
- [Production environment model source record](docs/sources/production-environment-model.md)
- [Curated design reference library and review checklists](docs/references/README.md)
- [Repository quality scorecard](docs/quality.md)
- [Technical-debt ledger](docs/tech-debt.md)
- [Competition release runbook](docs/release-runbook.md)
- [Third-party notices and disclosure](THIRD_PARTY_NOTICES.md)
- [Generated repository map](docs/generated/repository-map.md)

Third-party source snapshots used for architecture and evaluation research are
available through the project-local `.opensrc` link when the shared research
store is configured. They are not Solvan dependencies. License and archive
status must be checked in the pinned manifest before reusing any code.

## Implemented engineering surface

The repository has crossed from scaffold to a locally verified product
implementation. It includes the authoritative 61-table Cloud SQL schema,
version-fenced Incident and Reliability Case workflows, coordinator-only Agent
Runtime dispatch, the six Google ADK agents, bounded read tools, a private
stored-action actuator, autonomous payments-pool recycling, exact approval-bound
Cloud Run rollback, independent verification, governed Memory Bank promotion,
sandboxed permanent-repair generation, exact patch review, Terraform for the
single-region Google Cloud topology, and the operator console.

The optional public-synthetic flagship is also implemented end to end: a
hash-locked `google-antigravity==0.1.13` loop in a private regional Cloud Run
service, independent KMS-backed fixture attestation, pre-upload eligibility
allow/deny receipts, typed competing hypotheses, deterministic baseline
reproduction and patched regression, content-bound logical-workspace
checkpoints, SDK-distribution/provider-image provenance fencing, and retry-safe
rehydration across a deliberate provider revision replacement. This provider remains experiment-only and is never a production
authority or a silent fallback for private data.

The local harness exercises these contracts without production authority:

```bash
scripts/bootstrap
scripts/start
scripts/observe status
scripts/check
scripts/stop
```

To keep the control plane local while exercising real read-only Google Cloud
sources, authenticate Application Default Credentials once and start the
closed development identity path:

```bash
gcloud auth application-default login
scripts/start-cloud-dev
```

The launcher uses `solvan-probe@solvan-dev.iam.gserviceaccount.com` by
default. Precedence is most specific first: `--reader-service-account`, then
`SOLVAN_READER_SERVICE_ACCOUNT` from `.env`, then the built-in default derived
from the control project (`--control-project`, default `solvan-dev`). An
explicit `--control-project` with a `.env` reader pinned for a different
control project derives the reader from the flag's project and says so. It
has no target-project argument: select the monitored project, customer-owned
reader identity, providers, workload region, and exact Cloud Run or Cloud SQL
resource in **Integrations**. The local-only test panel can then run the real
connection probe, detector evaluation, durable inbox, and Incident transition.
It never starts a mutation service and its evidence is not a staging or
production receipt.

With the dedicated staging project configured, the non-MSR statistical
quality gate runs exactly three repetitions of every pinned case:

```bash
scripts/eval-model-quality --output .solvan/releases/<deployment-id>/model-quality.json
```

It scores observation precision/recall, observation-versus-inference accuracy,
hypothesis top-1/top-3, typed-schema first-pass/repair success, plan validity,
and required uncertainty disclosure. It is not reported as verified until the
receipt binds the submitted model, project, and location.

Each Git worktree derives distinct ports, Compose project, state, logs, traces,
screenshots, and evaluation receipts. `scripts/check` is the canonical merge
gate. `scripts/run-scenarios` emits content-addressed local S1–S6 contract
receipts, but deliberately marks them non-promotable. See [repository
quality](docs/quality.md) for the exact implemented-versus-verified boundary.
The final release is frozen with `scripts/freeze-submission`, which rejects a
dirty/mismatched commit, incomplete platform fleet, missing S1–S6 receipts,
overlong video, false attestations, or changed repository artifact hashes.

No local-connected run is a Solvan GCP deployment receipt. Agent
Runtime resources, Agent Identities, Registry entries, Gateway/Model Armor
enforcement, Cloud SQL bootstrap, OTel export, and S1–S6 must all be collected
from the dedicated `europe-west1` staging project and one exact release commit
before the Minimum Submittable Release can pass. Local fixtures never count as
that proof.

Solvan’s cloud model has three normal environment classes: `dev` for mutable
engineering, `staging` for reviewed release qualification, and `production`
for declared customer estates. The reusable Terraform stack and isolated
configuration examples live in
[`infra/terraform/environments/gcp`](infra/terraform/environments/gcp/README.md).
Dev evidence is never promotable. The competition scenario is enabled only by
an explicit `fault_drill_enabled` deployment setting in an isolated dev or
staging project; it is forbidden in `production`.

## Competition release boundary

The judged release is intentionally one payments-stack vertical slice:

- live GCP services exercised by synthetic users and failure injection;
- autonomous incident creation with no chat prompt;
- parallel evidence and infrastructure investigation;
- one real Level 4 payments connection-pool recycle executed without human approval;
- one high-risk rollback that requires exact approval;
- independent policy-owned recovery verification;
- durable cross-session Reliability Case continuation;
- one agent failure and recovery;
- prompt/tool injection and memory-poisoning denial;
- Agent Registry discovery, individual Agent Identities, Gateway enforcement,
  Model Armor verdicts, and OpenTelemetry traces shown as evidence.

The broader agent-reliability workload, extra providers, additional clouds and
the remainder of the benchmark catalogue are roadmap. Ruhu is the first
design-partner workload for the post-release product; its phased, least-privilege
integration is specified separately and is not a substitute for the judged
payments vertical slice.

## Decision precedence

1. Binding competition rules govern submission eligibility.
2. Security, authority, privacy, and data-sovereignty contracts cannot be
   weakened by another document.
3. Data, state-machine, tool, event, and API contracts govern interoperability.
4. Agent/model/runtime contracts govern probabilistic execution.
5. UI and implementation documents govern their respective surfaces.
6. The product requirements govern scope and priority.

When a specification and implementation disagree, record an implementation gap
or documentation drift; do not silently redefine the requirement.

## Licence

Solvan is licensed under the [Apache License 2.0](LICENSE). You may run,
modify, and redistribute it, including commercially, subject to that licence's
attribution and notice terms; it carries an explicit patent grant.

Two limits are properties of the design rather than the licence, and neither is
waived by it. Production mutation capability is confined to a single actuator
that enforces its own kill switch and hourly ceiling before it constructs any
mutation connector, refusing when either is absent or unparsable. And local
harness output is never a release receipt — `scripts/check` proves this
worktree, not a deployment.

**Customer-side deployment of that actuator is a target, not a current
property.** The competition topology deploys it in Solvan's own project under a
Solvan service account (`infra/terraform/environments/gcp/cloud_run.tf`), so
today the controls above bound the blast radius rather than removing Solvan
from the trust boundary. Specification 13 governs the customer-deployed target.
