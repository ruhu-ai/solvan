# Gemini Enterprise Agent Platform source register

Status: researched design input
Retrieved: 2026-08-21
Authority: official Google Cloud, Google ADK, and Google Antigravity sources only

Terraform provider check: the official Registry API reported
`hashicorp/google==7.45.0` published 2026-08-18. The initial 7.34.0 pin did not
contain the newly documented Agent Registry and Agent Gateway resource types;
the deploy root therefore pins 7.45.0 and validates its live provider schema.

This register records volatile platform facts that materially constrain Solvan.
Deployment preflight must recheck launch stage, region, API version, quotas, and
known limitations immediately before submission.

## Google-native release governance

- [Cloud Deploy overview](https://docs.cloud.google.com/deploy/docs/overview)
- [Cloud Deploy custom targets](https://docs.cloud.google.com/deploy/docs/custom-targets)
- [Cloud Deploy approvals](https://docs.cloud.google.com/deploy/docs/promote-release)
- [Cloud Deploy service accounts](https://docs.cloud.google.com/deploy/docs/cloud-deploy-service-account)
- [Binary Authorization attestations](https://docs.cloud.google.com/binary-authorization/docs/attestations)
- [Binary Authorization for Cloud Run](https://docs.cloud.google.com/binary-authorization/docs/run/enabling-binauthz-cloud-run)
- [Cloud Build provenance](https://docs.cloud.google.com/build/docs/securing-builds/generate-validate-build-provenance)
- [Cloud Storage Bucket Lock](https://docs.cloud.google.com/storage/docs/bucket-lock)

Verified facts and decisions:

- Cloud Deploy custom targets support arbitrary outputs while retaining ordered
  promotion, approvals, rollbacks, Google resource state, and Audit Logs.
- A target with `requireApproval=true` admits approval only from a principal
  holding `roles/clouddeploy.approver`; Solvan scopes that role to the catalog
  publication target and uses only individual human principals.
- Cloud Deploy recommends a dedicated execution service account with
  `roles/clouddeploy.jobRunner` rather than the broad default Compute identity.
- Binary Authorization for Cloud Run verifies attestations on service and job
  images. The Google `built-by-cloud-build` attestor proves the image came from
  Cloud Build; it does not approve catalog data or replace Cloud Deploy.
- Bucket Lock makes a retention policy irreversible. Solvan enables it only on
  the dedicated release-evidence bucket and never on mutable application data.

Multi-tenant cell placement, current Agent Platform quota observations, Cloud
Run concurrency/maximum-instance behavior, and Cloud SQL connection/recovery
guidance are maintained in the separate
[SaaS scale and tenant-isolation source record](saas-scale-and-isolation.md).
Specification 19 consumes that record without turning current default quotas
into hard-coded product limits.

## Platform overview

- [Agent Platform overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/overview)
- [Agents and platform architecture](https://docs.cloud.google.com/gemini-enterprise-agent-platform/agents)
- [Release notes](https://docs.cloud.google.com/gemini-enterprise-agent-platform/release-notes)

Design consequences:

- ADK is the code-first framework and has full Agent Runtime integration.
- Scale, Govern, and Optimize capabilities are platform services, not substitutes
  for Solvan's incident domain model.
- Release notes are the source for launch-stage gates. On the retrieval date,
  Agent Registry, Agent Gateway, Agent Observability, and Model Armor on Gateway
  are GA. The Agent Identity API is Preview; Runtime agents still receive the
  documented SPIFFE-formatted identity, so deployment preflight must distinguish
  that identity capability from Preview identity-management API operations.

## Agent Runtime and Sessions

- [Agent Runtime](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/runtime)
- [Deploy an agent](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/deploy-an-agent)
- [Use a custom agent and long-running query jobs](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/use-a-custom-agent)
- [Runtime contract](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/runtime-contract)
- [Agent Platform Sessions](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/sessions)
- [Manage Sessions with ADK](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/sessions/manage-with-adk)
- [Agent Platform Python Sessions client](https://docs.cloud.google.com/python/docs/reference/agentplatform/latest/vertexai._genai.sessions.Sessions)
- [Session IAM Conditions](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/sessions/iam-conditions)
- [ADK quickstart on Agent Runtime](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/runtime/quickstart-adk)

Verified facts and decisions:

- Agent Runtime deployment currently supports Python.
- Object deployment's `extra_packages` accepts local source directories and
  preserves the supplied path in its uploaded dependency archive. Solvan
  changes into the repository `src` directory and supplies relative `solvan/`
  so Runtime extracts an importable top-level package rather than a host path.
- ADK has full platform integration; use ADK rather than adding Temporal.
- Long-running query jobs can run for up to seven days. Solvan Reliability Cases
  can exceed that, so each job is one bounded case-step attempt.
- Google describes Sessions as the definitive source for conversation context
  and long-term memory generation and distinguishes Session, Event, State, and
  Memory. Solvan deliberately narrows that claim: Cloud SQL remains
  authoritative for incidents, cases, approvals, mutations, leases, schedules,
  outbox delivery, **and the Liaison transcript/access ledger**. A Liaison ADK
  Session is a disposable provider projection because Solvan's per-part,
  per-reader visibility cannot be delegated to the managed Session boundary.
- `VertexAiSessionService` persists ADK events/state and defaults to a 365-day
  TTL when neither TTL nor expiry is set. The current official Python Sessions
  `create` surface accepts the Agent Engine name, `user_id`, and optional
  configuration but no caller-supplied session id; Solvan therefore treats the
  returned session identifier as provider-generated and stores its own
  reader/attempt/epoch binding in Cloud SQL. Solvan must set an explicit shorter
  TTL bounded by transcript retention if a target managed-Session adapter is
  enabled; deletion must remain recoverable from Cloud SQL.
- Session IAM Conditions can restrict session/event access only by the
  arbitrary Session `userId`. `ListSessions` does not support IAM Conditions
  and requires an unconditional role. Therefore target Liaison end users never
  receive direct managed-Session access or listing; the service derives an
  opaque reader key and performs every Solvan authorization itself.
- Custom containers must satisfy the Runtime HTTP contract on port 8080. The
  competition release uses the supported ADK deployment path unless a custom
  container becomes necessary.
- The current long-running-query documentation and 1.165.1 package expose
  `agentplatform.Client.agent_engines.run_query_job` with a qualified
  `reasoningEngines` name, JSON query, and regional GCS output URI. Solvan pins
  `google-adk==2.7.1` and `google-cloud-aiplatform==1.165.1`, persists the run
  before this call, and stores the returned job/input/output references. It
  polls with `check_query_job(retrieve_result=True)` and commits only a strict
  structured result associated with that stored operation.
- The ADK long-running input file is not the agent message itself. Its JSON has
  an `input` object matching `QueryReasoningEngineRequest`; for `AdkApp` that
  object supplies `user_id` and `message`. Solvan serializes the strict
  `AgentInvocation` as the message and rejects query-job results unless the
  final Runtime output/event contains one object accepted by the agent's
  Pydantic output schema.
- The Runtime service agent for long-running query files is
  `service-{PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com`, not
  the general Vertex AI service agent. It receives object-creator and
  object-viewer roles on the regional Runtime bucket; it does not receive
  delete permission.
- Agent Runtime creation validates an attached Agent Gateway through the general
  Vertex AI service agent,
  `service-{PROJECT_NUMBER}@gcp-sa-aiplatform.iam.gserviceaccount.com`. The
  current IAM catalog assigns `networkservices.agentGateways.get` and
  `networkservices.agentGateways.use` to that service agent role. Solvan also
  binds those exact two permissions directly through a narrow project role so
  gateway validation does not depend on propagation of a changing predefined
  role; this is control-plane authority, not an Agent's runtime authority.
- `cancel_query_job` is the documented cancellation path. Deadline handling
  must both fence late output in Cloud SQL and request provider cancellation;
  a prompt-level deadline alone is not enforcement.

### ADK context-engineering guidance

- [Architecting efficient context-aware multi-agent framework for production](https://developers.googleblog.com/architecting-efficient-context-aware-multi-agent-framework-for-production/)

Verified patterns and Solvan consequences:

- Google frames working context as an ephemeral compiled view over richer
  Session, memory, and artifact sources. It recommends separating storage from
  presentation, named ordered processors, and minimum scope by default. Solvan
  adopts those mechanics in the target Conversation Context Compiler while
  retaining Cloud SQL—not the ADK Session—as the Liaison's authoritative
  structured source.
- ADK's contents processor performs selection, transformation, and injection.
  Solvan runs reader/access/source filtering before that boundary; an ADK
  processor may inject only the already-compiled, digest-pinned view and cannot
  broaden it with ambient Session history.
- Google documents context compaction/filtering, stable-prefix context caching,
  versioned artifacts loaded on demand, and reactive/proactive memory recall.
  In Solvan these are performance/relevance patterns only: compactions and
  memories remain untrusted context, artifacts stay references until an
  enumerated read, cache keys bind every reader/epoch/model/isolation input,
  and no optimization can affect authorization, factual predicates, retention,
  or purge.
- Google warns against passing complete ancestral history between agents and
  supports explicitly scoped handoffs. Solvan's coordinator-only dispatch
  remains stricter: agents never invoke one another, and every durable run gets
  an independently persisted typed input projection.

## Memory Bank

- [Memory Bank overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank)
- [Generate memories](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/generate-memories)
- [Fetch memories](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/fetch-memories)
- [IAM Conditions for memory scopes](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/iam-conditions)
- [Supported agent locations](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/agent-locations)

Verified facts and decisions:

- Retrieval requires an exact immutable scope match. Solvan uses organization,
  project, environment, and purpose keys in every scope.
- IAM Conditions can restrict access by the memory scope attribute.
- Google recommends positive Memory Bank scope conditions because missing or
  unsupported scope attributes otherwise risk overly broad negative matches.
  Multi-scope `ListMemories` and `PurgeMemories` do not support IAM Conditions;
  Solvan gives application identities only exact-scope operational paths and
  keeps broad administration outside the agent/Liaison identity.
- Memory generation and consolidation use models. Google's documentation warns
  that sensitive-data exclusion is not infallible; Solvan redacts and gates
  candidates before generation and treats all returned memories as untrusted.
- Regional Runtime, Sessions, Memory Bank, and Gateway are supported in
  `europe-west1`. Multi-region/global Sessions and Memory Bank have different
  launch-stage and CMEK constraints, so the competition deployment is regional.

## Agent Registry

- [Agent Registry](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/agent-registry)
- [Register agents](https://docs.cloud.google.com/agent-registry/register-agents)

Verified facts and decisions:

- Registry is the central catalog for agents, MCP servers, tools, and endpoints.
- Agent Runtime deployments register automatically; A2A metadata can expose
  capabilities for discovery.
- Solvan-specific approval, owner, data class, evaluation state, lifecycle, and
  department visibility are enforced through metadata, IAM, CI policy, and the
  release manifest. The spec does not assume every lifecycle concept is a
  native Registry state.
- Every Gateway destination is registered before it can be allowed.
- The catalog covers up to 5,000 registered resources per Registry. Solvan
  treats that as catalog scale, not permission to expose every resource to one
  run or prompt.

## Agent Identity and Gateway

- [Agent Identity overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/agent-identity-overview)
- [Agent Gateway overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview)
- [Set up Agent Gateway](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/set-up-agent-gateway)
- [Configure IAM agent policies](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/configure-iam-policies)
- [Gateway connectivity troubleshooting](https://docs.cloud.google.com/gemini-enterprise-agent-platform/troubleshooting/troubleshoot-agent-gateway)

Verified facts and decisions:

- Each deployed Runtime agent receives a unique SPIFFE-formatted principal.
- Runtime IAM members use the returned `principal://agents.global.{org-N or
  project-N}.system.id.goog/resources/aiplatform/projects/{number}/locations/
  {region}/reasoningEngines/{id}` value. Terraform never invents this value;
  the Runtime deploy receipt supplies it before actuator invocation is granted.
- IAM grants attach to that principal; shared broad service-account authority is
  prohibited for Agents.
- Gateway is regional and default-deny for egress. Runtime, Gateway, and its
  associated Registry must be in the same project and region.
- Gateway can be configured to permit calls to unregistered tools. Solvan
  prohibits that option: an unregistered tool or endpoint is denied again by
  application policy even if a cloud administrator weakens Gateway policy.
- Agent-to-Anywhere egress and Client-to-Agent ingress have different control
  capabilities. Solvan documents and tests them separately.
- Every allowed request must satisfy registration, gateway policy, identity/IAM,
  network, content inspection, and Solvan application policy.
- Google's IAP and Model Armor Agent Gateway examples attach each AuthzPolicy
  to one exact Agent Gateway resource. Solvan therefore uses separate IAP
  policies for ingress and egress while sharing the fail-closed IAP extension.
- The Runtime Gateway guide and troubleshooting page warn that SDK startup and
  telemetry may resolve regional, mTLS, or REP Agent Platform hosts and may call
  Resource Manager to translate project numbers. The release therefore
  registers and grants IAP egress on the exact documented
  `europe-west1-aiplatform`, `europe-west1-aiplatform.mtls`,
  `aiplatform.europe-west1.rep`, `aiplatform.eu.rep`, Resource Manager,
  Resource Manager mTLS, Logging, Telemetry, and Telemetry mTLS hosts. The IAP
  policy writer consumes each provider-returned `registry_resource` from the
  exact Terraform output because Agent Registry assigns the durable endpoint
  ID; it never reconstructs that ID from the requested service name. Preflight
  checks every binding; no wildcard hostname or registry-wide fleet principal
  is used.

## Model Armor and semantic governance

- [Configure Model Armor on Gateway](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/configure-model-armor)
- [Semantic governance policy overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview)

Verified facts and decisions:

- Model Armor can block or redact prompt injection, jailbreaks, sensitive-data
  leakage, and harmful content for supported ingress/egress payloads.
- Coverage is protocol-operation specific. Current MCP coverage includes
  `tools/call` and `prompts/get` requests/responses, but not every MCP message.
- Semantic governance is Preview, probabilistic, and does not support VPC-SC.
  It may be demonstrated in dry-run or defense-in-depth mode but cannot grant
  authority or replace deterministic policy, IAM, reservations, or approvals.

## Agent Observability

- [Observability overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/optimize/observability/overview)
- [View agent traces](https://docs.cloud.google.com/gemini-enterprise-agent-platform/optimize/observability/traces)
- [Instrument ADK with OpenTelemetry](https://docs.cloud.google.com/stackdriver/docs/instrumentation/ai-agent-adk)

Verified facts and decisions:

- Platform topology, dashboards, and traces require OpenTelemetry-formatted
  telemetry in Google Cloud Observability.
- ADK 1.17+ has built-in OTel integration; the implementation lockfile may use a
  newer compatible release but must not fall below that requirement.
- Prompts/responses are stored separately from trace spans. Solvan disables raw
  message content in span attributes and uses structured event fields.
- Trace UI is an operational debugging surface, not the audit authority and not
  a requirement to expose private chain-of-thought.

## Runtime revisions limitation

- [Manage revisions and traffic](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/manage-revisions-and-traffic)

At retrieval, revision traffic splitting is Preview and cannot be combined with
Agent Gateway on the same Runtime agent configuration. Solvan uses explicitly
versioned immutable agent resources and application-controlled cutover while
Gateway remains attached. The implementation must not claim both native Runtime
traffic splitting and Gateway enforcement on that path.

## Antigravity SDK and Managed Agents are separate surfaces

- [Antigravity SDK repository](https://github.com/google-antigravity/antigravity-sdk-python)
- [Antigravity SDK package](https://pypi.org/project/google-antigravity/)
- [Choosing an Antigravity surface](https://cloud.google.com/blog/topics/developers-practitioners/choosing-your-surface-antigravity-20-antigravity-cli-antigravity-ide-or-antigravity-sdk)
- [Managed Agents API overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/managed-agents)
- [Create and manage agents](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/managed-agents/create-manage)
- [Interact with managed agents](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/managed-agents/interact-with-agents)
- [Sandbox environment](https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/managed-agents/sandbox-environment)

Verified 2026-08-21 facts and decisions:

- Google publishes the Apache-2.0 `google-antigravity` Python SDK for custom
  agents. The SDK exposes high-level `Agent`, stateful `Conversation`, custom
  tools/MCP, capability configuration, hooks, policies, and triggers. The
  package contains a platform-specific compiled runtime and must be installed
  from the official hash-pinned wheel rather than reconstructed from a source
  checkout. PyPI reports `0.1.13`, uploaded 2026-08-20, Development Status
  Alpha, with trusted-publishing provenance attestations and Linux
  x86-64/ARM64 wheels. The release-approved manylinux x86-64 wheel digest is
  `sha256:f398664b362280037f8ed6df5cd61b996f3d02be1151ff665c6d09c87cc6a992`.
- `google-antigravity==0.1.13` requires `protobuf>=7.35`, while
  `google-cloud-aiplatform==1.165.1` requires `protobuf<7`. Solvan therefore
  maintains a separate lock and `Dockerfile.antigravity`; the provider image
  verifies the installed distribution and rejects ADK/Agent Platform packages
  in its closure.
- In 0.1.13, `CapabilitiesConfig.agent_behavior` defaults to autonomous and is
  now set explicitly; `BudgetConfig` receives the coordinator's invocation
  model/tool-call ceilings; `RunCommandConfig` disables daemons while the
  `RUN_COMMAND` built-in remains absent; lifecycle and pre-tool decision hooks
  validate tool names and argument shapes. Retries remain zero, the only
  enabled built-in is `finish`, custom tools remain deny-all plus two exact
  allows, and `WorkspaceModelProposal` remains the structured output schema.
- The current package instructions configure Gemini Enterprise Agent Platform
  with `LocalAgentConfig(vertex=True, project=..., location=...)` and ADC. This
  selects Vertex/Agent Platform for model calls; the SDK agent loop and compiled
  runtime still execute in the caller's process. The SDK README documents no
  Managed Agents deployment, `environment_id`, or Interactions API bridge.
- Solvan therefore self-hosts the pinned SDK in a private regional Cloud Run
  service. The dependency freezes at `0.1.13` for the competition release;
  upgrades require explicit API/behavior evaluation, a new lockfile, wheel
  provenance, container compatibility, and regression receipts.

## Current framework and deployment-tool releases

Official PyPI/GitHub/Registry metadata rechecked on 2026-08-21 records:

- `google-adk==2.7.1`, published 2026-08-17; 2.7.1 restores the OpenTelemetry
  1.42.1 ceiling and validates Session initialization events.
- `google-cloud-aiplatform==1.165.1`, published 2026-08-19; 1.165.0 added
  public Sessions update methods and fixed Agent Engine SSE handling, while
  1.165.1 fixes default bucket-name truncation.
- `google-genai==2.19.0`, published 2026-08-19; the Enterprise client remains
  `genai.Client(enterprise=True, project=..., location=...)` for Solvan's
  evaluated surface.
- `google-auth==2.56.3`, published 2026-08-06 and still current.
- `hashicorp/google==7.45.0`, published 2026-08-18. Its changes do not alter a
  Solvan-declared schema semantically; the Cloud Run computed-field fixes in
  7.44.0 reduce irrelevant drift.
- Terraform CLI `1.15.9` and Google Cloud CLI `581.0.0` are the current official
  releases observed by their official release channels. Local upgrades are
  tooling prerequisites, never deployment evidence.
- Managed Agents is a distinct `google.genai`/REST surface. Its current create
  contract supports only `base_agent=antigravity-preview-05-2026` in `global`;
  the official documentation does not describe uploading or executing a custom
  `google-antigravity` SDK agent. Solvan does not combine the surfaces or use
  Managed Agents in the flagship path.
- Managed Agents API is Preview, intended for testing/evaluation, and its terms
  prohibit proprietary, sensitive, or confidential data and commercial/
  production use. These terms govern Managed Agents, not the self-hosted SDK
  service; they are retained here only to prevent future conflation.
- Only the `global` location and the `antigravity-preview-05-2026` base agent
  are currently supported for Managed Agents. The self-hosted SDK can configure
  Vertex location independently; Solvan binds its optional Gemini 3.1 Pro
  Preview SDK path to `global` and proves that exact endpoint in preflight.
- The sandbox starts without ambient credentials or network access. Explicit
  domain allowlists, downscoped GCS/Skill Registry access, and remote MCP
  servers can be configured. Wildcard egress is prohibited by Solvan policy.
- Stored background interactions return an `interaction.id` and
  `environment_id`. `previous_interaction_id` continues interaction history;
  reusing `environment_id` preserves sandbox files, packages, and code context.
  Per-interaction tool/MCP configuration replaces the configured tool set for
  that turn. These are Managed Agents facts and are not SDK service contracts.
- A Managed Agents sandbox environment expires after seven days without
  interaction, with the TTL renewed on a new interaction. This is not a Solvan
  flagship lifecycle constraint.
- Multiple agents join the same sandbox when an interaction supplies the same
  `env_id`. Any future Managed Agents experiment must treat those identifiers
  as confidential coordinator-owned material, but the self-hosted SDK provider
  creates or accepts no `env_id`.
- The competition uses the self-hosted SDK provider as lead deep investigator
  and repair implementer for the isolated synthetic payments fixture: cited
  mechanism, reproduction, patch, and test. `PUBLIC` plus independently
  attested `synthetic=true` is a Solvan Alpha-provider release restriction, not
  an inherited Managed Agents rule. Humans and deterministic tests review
  critical output. The provider never receives confirmation, approval,
  deployment, production mutation, verification, closure, or promotion
  authority, and `AdkWorkspaceProvider` remains the required regional release
  fallback.

## Gemini model selection

- [Gemini 3.6 Flash model card](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-6-flash)
- [Gemini 3.1 Pro model card](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-1-pro)

Verified 2026-08-10 facts and decisions:

- Exact model ID `gemini-3.6-flash` is GA, has a one-million-token context
  window, supports structured output, tools, and code execution, and is
  positioned for multi-step orchestration and token-efficient agent work.
- Exact model ID `gemini-3.1-pro-preview` is Public Preview, has a
  one-million-token context window, and is positioned as Google's advanced
  reasoning model for software engineering and agentic work across repositories.
- Gemini 3.6 Flash lists `global`, `us`, and `eu` model endpoints and ML
  processing in `us` or `eu`; Solvan selects exact `eu` for the fast fleet.
  Gemini 3.1 Pro Preview lists only `global`, so the optional Antigravity deep
  workspace retains a documented inference-location exception.
- The documented EU jurisdictional hostname is
  `https://aiplatform.eu.rep.googleapis.com`. The locked
  `google-genai==2.19.0` Enterprise client resolves `location="eu"` to that
  hostname. A request sent to the global `aiplatform.googleapis.com` hostname
  with `/locations/eu/` in its path does not prove EU routing and is not an
  acceptable release probe; the negative control must use the same Enterprise
  client or endpoint-selection mechanism as production.
- A same-suite evaluation is required before model routing changes. On
  2026-08-10, 3.6 Flash at `eu` and 3.1 Pro Preview at `global` both passed the
  Solvan typed quality thresholds; Flash averaged 5.01 seconds per case and Pro
  8.95 seconds, while Pro retained a modest classification/recall advantage.
  This selects Flash for the fast fleet and Pro for the optional deep workspace
  without granting either model workflow authority.

## Agent Engine Code Execution — recorded but not used

- [Code Execution overview](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/code-execution/overview)
- [Code Execution quickstart](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/code-execution/quickstart)
- [Code Execution troubleshooting](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/troubleshooting/code-execution)

Verified 2026-08-10 facts and decisions:

- Agent Engine Code Execution is Preview and supported only in `us-central1`.
- It runs untrusted code in a managed isolated sandbox with a limited file
  system and no network access. Requests and responses may contain at most
  100 MB of files, execution times out after 300 seconds, and configurable
  sandbox state can persist for at most 14 days.
- The official Python SDK surface is
  `agentplatform.Client.agent_engines.sandboxes`; it can create, execute in,
  inspect, list, and delete a sandbox without deploying the caller as an Agent
  Engine agent.
- Solvan does not use this surface because its only supported region conflicts
  with the `europe-west1` execution policy. Merely configuring it with another
  location would fail at runtime.

## Cloud Run Sandboxes

- [Code execution in Cloud Run](https://docs.cloud.google.com/run/docs/code-execution)
- [Configure sandboxes for services](https://docs.cloud.google.com/run/docs/configuring/services/sandboxes)

Verified 2026-08-10 facts and decisions:

- Cloud Run Sandboxes is Preview and is enabled per service with
  `--sandbox-launcher` or container YAML field `sandboxLauncher: true`.
- The host container receives `/usr/local/gcp/bin/sandbox`. `sandbox do`
  creates a fresh ephemeral sandbox, executes one command, and deletes it.
- Sandboxes do not inherit the parent environment, secrets, or metadata access;
  they are isolated from one another. Outbound traffic is denied by default
  unless the caller explicitly supplies `--allow-egress`.
- A bind mount can expose an exact host directory to the sandbox for input and
  output. Solvan binds only one per-request temporary directory and never
  enables egress.
- The service runs in `europe-west1` with a dedicated no-project-role identity.
  The coordinator supplies exact bytes and a fixed runner; a hash-bound receipt
  returns only the ordered named outputs. Preview failure blocks the workspace
  path and never falls back to host-process shell execution.

## Data residency

- [Data residency](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/data-residency)
- [Supported capabilities by endpoint](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/supported-capabilities)
- [Model deployments and endpoints](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/locations)

Verified facts and decisions:

- Storage location and ML-processing location are separate questions.
- A global endpoint does not provide regional processing guarantees.
- The release uses `europe-west1` for platform resources and the `eu`
  multi-region for Gemini 3.6 Flash ML processing. Gemini 3.1 Pro Preview still
  requires `global`; only the optional public-synthetic Antigravity deep
  workspace is not region-pinned. Customer-facing language must distinguish
  those paths and never claim its Pro processing occurs only in the EU.
- Release evidence binds three distinct values for the fast fleet: exact model
  `gemini-3.6-flash`, location `eu`, and endpoint
  `https://aiplatform.eu.rep.googleapis.com`. The regional Agent Runtime REP
  hostname and the EU model-inference REP hostname are separate destinations.
- The hackathon dataset is synthetic, but the same scope/classification/residency
  policy is exercised and audited as if it were an enterprise workload.

## Cloud Run mutation feasibility

- [Cloud Run rollouts, rollbacks, and traffic migration](https://cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration)
- [Authenticate service-to-service Cloud Run requests](https://cloud.google.com/run/docs/authenticating/service-to-service)

Verified facts and decisions:

- Cloud Run supports migration of traffic to a pinned known-good revision; this
  is the release rollback connector and must use exact revision preconditions.
- The documented Cloud Run control surface does not provide a selected-instance
  restart operation. Solvan therefore never claims one. The autonomous action is
  the demo application's IAM-authenticated private connection-pool recycle.
- The Execution Agent (`execution-agent`) calls only the private actuator; the actuator uses an ID
  token with the target service as audience for its private admin request.

## Detection timing

- [Cloud Monitoring alerting behavior](https://docs.cloud.google.com/monitoring/alerts/concepts-indepth)
- [Cloud Monitoring AlertPolicy API](https://docs.cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.alertPolicies)

Verified facts and decisions:

- Metric visibility, alignment windows, retest windows, and notification
  delivery make alert-to-webhook latency unsuitable for a guaranteed 30-second
  video beat.
- Solvan's 25-second typed evaluator is the primary release detector. A real
  Monitoring alert policy/webhook remains enabled as the institutional
  secondary route, and both use the same canonical inbox contract.

## Cloud Run Job execution overrides

- [Execute Cloud Run jobs](https://docs.cloud.google.com/run/docs/execute-jobs)
- [Cloud Run IAM roles](https://docs.cloud.google.com/run/docs/reference/iam/roles)

Verified 2026-08-08 facts and decisions:

- `roles/run.invoker` permits an ordinary job execution but does not grant
  `run.jobs.runWithOverrides`.
- Solvan's preflight and scenario runners bind the exact commit, deployment ID,
  and immutable GCS object name through per-execution environment overrides.
  Those exact job resources therefore grant approved release operators
  `roles/run.jobsExecutorWithOverrides`; migration and calibrated seed jobs use
  ordinary `roles/run.invoker` because they accept no execution overrides.
- The broader Developer/Admin roles are unnecessary and are not granted.
