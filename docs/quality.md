# Solvan repository quality

Status: active engineering scorecard
Owner: Solvan engineering
Review cadence: update after a material harness or architecture change

This scorecard reports repository evidence, not product capability. A harness
check cannot prove that the GCP release or autonomous recovery path exists.

| Area | Current status | Evidence | Next graduation condition |
|---|---|---|---|
| repository navigation | verified locally | `scripts/check` at working-tree baseline `fba2365` | repeat in CI |
| reproducible dependencies | verified in a fresh detached worktree | exact Python/Node manifests and locks | repeat from public remote in CI |
| isolated local runtime | verified locally | two simultaneous worktrees with distinct IDs, ports, Compose projects and state | repeat as a scheduled/CI harness test |
| architecture enforcement | verified locally | machine rules, actionable failures and negative structural tests; twelve dated size exceptions recorded in `config/architecture-exceptions.yaml`, including five governed code-delivery exceptions expiring 2026-09-05, renewed once from 2026-08-20 with their removal conditions unmet | complete the named deployed qualification runs, split every expiring boundary, and repeat in CI |
| documentation integrity | verified locally | link, status, YAML, requirement and generated-map checks | repeat in CI |
| executable domain/data contracts | verified locally | 61-table clean PostgreSQL 16 load, negative constraint oracles, schema↔transition state equality, immutable version-fenced transition unit tests | execute the same migration and concurrency suites in CI and GCP staging |
| deterministic action and verification policy | verified locally | approval material, anti-flapping, exact profile binding, fail-closed verdict tests | connect to actuator and live telemetry |
| PostgreSQL application concurrency | verified locally | 36 clean-database integration contracts cover duplicate ingress, recurrence, 25 simultaneous incident opens without loss/duplication, coordinator atomicity, cached-call budget enforcement, one-shot agent fallback, fresh-process Runtime recovery, plan supersession fencing, wakeups, reservations, approval, action/verification, repair review, workspace lineage/reconciliation with SDK/image provenance fencing, RLS, and Memory promotion | execute restart cases against deployment replacement in GCP |
| action actuator safety | verified locally | stored-action reservation, exact approval/RBAC/evidence recheck, standing authority, target precondition, typed payments connector, mandatory reconciliation | deploy behind Cloud Run IAM and capture S1/S2/S4 receipts |
| browser feedback | verified for critical local journeys | 40 Playwright cases run across two device projects (79 executed) cover incident, exact approval, investigation, verification, patch review, continuity, fleet governance, release honesty, and automated serious/critical axe checks | repeat against the deployed live projection and complete manual keyboard/screen-reader smoke |
| deterministic agent safety | verified for pre-model boundary | 10/10 cases and content-free receipt | retain as required CI suite |
| live Gemini behavior | implemented, not verified | Vertex/ADC safety runner in `scripts/eval-agent --mode live`; pinned five-case quality dataset and exact three-repetition scorer in `scripts/eval-model-quality`, including the documented precision/recall, classification, hypothesis, schema-repair, and uncertainty gates | both live receipts pass for the exact release model/project/location without a safety-critical regression |
| workspace cognition providers | implemented and verified locally; cloud qualification pending | clean provider-neutral lifecycle; regional ADK adapter; official hash-locked Antigravity SDK private Cloud Run service; public-synthetic attestation and negative eligibility decision; typed competing-hypothesis artifact; deterministic baseline reproduction and patched regression; SDK-distribution/provider-image-fenced requests, results, checkpoints, and rehydration receipts; fresh-revision retry-safe qualification; Terraform, API, console, harness, PostgreSQL, IAM/egress preflight tests | run the conditional live provider, Registry, revision-rehydration, IAM, egress, Model Armor, and UI probes in staging |
| local observability | verified for local HTTP shell | queryable metrics and content-free NDJSON logs/traces per worktree | export the same semantic contracts through the production OTel path |
| local scenario evidence | verified, non-promotable | deterministic S2–S6 local contract receipts; S1 explicitly `NOT_RUN`; summary is always `release_eligible: false` | bind all receipts to one deployed commit/project/deployment and durable GCS evidence |
| cloud release | deployed, not verified | deployment `staging-20260823-04` completed all 19 phases on 2026-08-23 against commit `942e463d` (public `ruhu-ai/solvan` main): managed build `c65ee49a` approved and provenance-verified, Binary Authorization enforced, platform Terraform applied including alerting, six Agent Runtime engines created, gateway policies bound, private DB migration executed, catalog approved and published. Receipt status `DEPLOYED_UNVERIFIED_SCHEDULERS_PAUSED` -- deployment evidence is not a preflight or release pass | staging preflight and S1–S6 receipts pass |

Quality status uses the vocabulary in `docs/documentation-policy.md`. Do not
turn an `implemented` row into `verified` without recording the exact command,
commit, environment, and result.

## What the coverage figure now measures

`scripts/check` measures `src/solvan` **and** `apps` and enforces a ratchet of
64%, the true figure across both trees. It previously measured `solvan` alone
and reported 85% against a threshold of 85%, which left roughly 42% of the
runtime — the API, coordinator, actuator and liaison services — unmeasured and
made the number a property of the omissions rather than of the tests. The
ratchet rises as coverage improves and is never lowered to admit a change.
The canonical check erases coverage once, appends each disposable-PostgreSQL
contract shard, then appends the unit/harness suite before enforcing the
ratchet. This makes the figure describe every Python test the gate actually
ran, rather than only its last pytest process. `src/solvan/persistence` remains
omitted from the percentage because its correctness is judged by the separate
clean-schema, transition, concurrency, and negative-oracle contract receipts.

`scripts/check-contracts` now refuses a suite that skipped or executed nothing.
Every integration file is `skipif`-gated on `SOLVAN_TEST_DATABASE_URL`, so a
renamed variable, an unreachable container or a collection error previously
yielded "N skipped" and exit 0 — a green gate that proved no contract at all.
