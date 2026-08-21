# 15. Solvan Console Settings specification

Status: required production implementation target
Related: [product](01-product-requirements.md),
[data/API](04-data-event-api.md), [security](05-security-governance.md),
[UI/UX](06-ui-ux.md), [acceptance](08-test-evaluation-acceptance.md),
[design system](10-design-system.md), [tenant integration](13-tenant-integration.md)

Research provenance: implementation patterns were studied in the pinned
read-only snapshots of existing operations tooling. Solvan adopts explicit
preference persistence, URL-addressable settings, role-aware read-only states,
effective model provenance, and named environment-profile clarity. Solvan does not
adopt raw configuration editors, browser-native alerts, secret entry in a
general settings page, or unrestricted runtime model switching.

## 1. Purpose

Settings is the console's trustworthy explanation of:

1. who the current operator is;
2. which tenant, project, and environment the console is showing;
3. which personal presentation preferences are active;
4. which AI runtime and governed release configuration is effective;
5. what authority, security, and retention boundaries apply; and
6. which exact external connections are usable and how an unavailable one can
   be repaired; and
7. which settings the current operator may change.

Settings is not a generic cloud console, an unrestricted manifest editor, or
an alternate path around release review. A value that affects agent authority,
production mutation, model execution, data retention, identity, or audit must
be displayed with its source and changed only through its owning reviewed
workflow.

## 2. Product principles

- **Effective state, not aspirational configuration.** Read-only values come
  from the active projection or a release-bound receipt, never UI literals.
- **Personal preference is not production policy.** Theme, density, motion,
  and timezone may be changed by an operator without creating production
  authority.
- **Visibility is not mutability.** The active model must be visible, but an
  ordinary operator cannot replace it from Settings.
- **Managed identity is honest.** Identity-provider-owned fields are labelled
  `Managed by Google` and are not rendered as editable controls.
- **No secrets.** Settings responses and UI never contain API keys, OAuth
  tokens, service-account material, passwords, or secret payloads.
- **Permission is enforced twice.** Capability flags shape the UI; the server
  independently authorizes every write.
- **Configuration has provenance.** Runtime and governance values state the
  manifest, policy, deployment, or identity source that produced them.
- **Local development remains unmistakable.** Fixture values grant no authority
  and keep the existing non-production disclosure.

## 3. Scope

### 3.1 Required for the production Settings release

- appearance and accessibility preferences;
- operator identity, role, organization, team, and session summary;
- authorized environment summary and top-bar selector contract;
- effective AI runtime disclosure;
- safety and governance disclosure;
- application build and diagnostic information;
- permission-aware navigation, read-only states, loading, failure, and stale
  states;
- local preference persistence and optional authenticated server sync;
- desktop, narrow-screen, keyboard, screen-reader, and contrast support;
- API, contract, integration, and end-to-end tests.

### 3.2 Deferred until its owning service exists

- user-uploaded avatars;
- editable display names for identity-provider-managed accounts;
- personal incident and approval notifications;
- team delivery routing;
- organization membership administration;
- SSO configuration;
- retention-policy editing;
- model experimentation;
- support-bundle download.

Deferred items may appear only as unavailable explanatory rows when that helps
the user understand ownership. They must not appear as dead controls.

### 3.3 Explicit non-goals

- raw YAML, JSON, Terraform, or policy editing;
- arbitrary environment IDs typed by the user;
- model/provider/API-key controls for ordinary operators;
- credential display or copy actions;
- bypassing Integrations, Agent Fleet, Release Evidence, or reviewed admin
  workflows;
- storing the Google identity token used for exact approvals;
- deriving identity, scope, or permissions from unverified browser-supplied
  profile fields.

## 4. Information architecture

Settings uses URL-addressable sections. The target routes are:

```text
/settings/personal
/settings/profile
/settings/environment
/settings/integrations
/settings/runtime
/settings/governance
/settings/about
```

If the current shell cannot yet provide path routing, the first implementation
may use `?section=` while preserving refresh, back/forward, and deep-link
behavior. Invalid sections fall back to `personal` and do not render a blank
page.

Desktop uses a compact secondary navigation and one primary content column.
Narrow screens use a labelled section selector above the content. The page
must not render a grid of unrelated, equal-weight cards.

The `Ruhu design partner` record is not a global setting. It belongs in the
Ruhu connection detail under Integrations. Deployment placeholders belong in
Release Evidence and must link to the unresolved evidence record.

## 5. Application-shell contracts

### 5.1 Environment control

The top bar renders the selected environment from the settings projection. If
the operator has one authorized scope, the control is a labelled, non-editable
summary. If multiple authorized scopes are returned, it becomes a selector.

Selecting an environment:

1. accepts only an opaque scope key returned by the server;
2. clears selected incident/case state from the previous scope;
3. aborts in-flight scoped reads;
4. refetches snapshot, settings, operator capabilities, and counts;
5. displays a bounded loading state;
6. restores the prior environment if the switch fails; and
7. never treats a client-selected scope as authorization.

### 5.2 Operator menu

The avatar button opens a keyboard-accessible menu containing:

- avatar or initials;
- display name and verified principal;
- effective environment roles;
- organization/team when present;
- `Profile and session` link;
- `Settings` link; and
- sign-out only when an authenticated session and sign-out operation exist.

The button must not show invented initials. Local development uses a neutral
`LD` avatar and `Local development reader`. A missing production identity renders
`Sign in required`, not a fabricated user.

The menu closes on Escape, outside activation, navigation, and focus loss. It
returns focus to the trigger and uses normal menu/popover semantics.

## 6. Personal preferences

### 6.1 Preference model

```typescript
type ThemeMode = "SYSTEM" | "LIGHT" | "DARK";
type DensityMode = "COMFORTABLE" | "COMPACT";
type MotionMode = "SYSTEM" | "REDUCED" | "FULL";
type TimezoneMode = "BROWSER" | "UTC" | "NAMED";

type UserPreferences = {
  theme: ThemeMode;
  density: DensityMode;
  motion: MotionMode;
  timezone_mode: TimezoneMode;
  timezone?: string;
};
```

The required first release implements all fields. The UI offers Browser
timezone, UTC, and a compact standard timezone list in one labelled selector.
The list intentionally avoids exposing the full IANA catalog because that
creates an unwieldy menu for a console preference. A user is never required to
type an IANA identifier. `NAMED` timezone values use canonical IANA identifiers
behind human-readable labels and are validated by the browser runtime.

### 6.2 Theme behavior

- Default is `SYSTEM`.
- `LIGHT` and `DARK` override the operating system.
- `SYSTEM` responds live to operating-system changes.
- The resolved theme is applied before React mounts to prevent a flash of the
  wrong theme.
- The root element carries `data-theme="light|dark"` and
  `data-theme-preference="system|light|dark"`.
- `<meta name="color-scheme">` supports both light and dark; the root CSS
  `color-scheme` matches the resolved theme.
- The choice is stored locally immediately. When an authenticated preference
  service is available, it is synchronized without blocking first paint.
- A server value wins only when it is newer than the local preference version;
  conflicts are visible and do not silently overwrite a newer local choice.

### 6.3 Motion, density, and timezone

- `SYSTEM` motion follows `prefers-reduced-motion`.
- `REDUCED` removes non-essential transitions and animated progress.
- `FULL` may enable normal transitions but cannot override browser/OS forced
  accessibility modes.
- Density changes spacing and row height, not information visibility.
- Timezone controls human timestamps. Stored event timestamps remain UTC and
  machine timestamps remain available in detail views.
- Preference changes auto-save and show `Saved`, `Saving`, or a recoverable
  error next to the affected group. There is no page-wide Save button.

## 7. Profile and session

### 7.1 Operator context

```typescript
type OperatorContext = {
  state: "LOCAL_DEVELOPMENT" | "AUTHENTICATED" | "AUTHENTICATION_REQUIRED";
  principal: string | null;
  display_name: string;
  email: string | null;
  avatar_url: string | null;
  initials: string;
  identity_provider: "LOCAL" | "GOOGLE" | null;
  managed_by: "SOLVAN" | "GOOGLE" | null;
  organization: { id: string; name: string } | null;
  team: { id: string; name: string } | null;
  roles: Array<"VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN">;
  session_expires_at: string | null;
};
```

The server derives principal and roles from verified identity and current
environment-scoped bindings. Request body, query string, unverified headers,
local storage, avatar metadata, and display-name fields are never authority.

### 7.2 Avatar and profile editing

- Prefer an approved identity-provider photo URL.
- If absent or rejected by content policy/CSP, use deterministic initials.
- Remote avatar URLs are proxied or restricted to approved origins and never
  receive Solvan credentials or referrer data.
- The first release does not upload avatars.
- Google-managed name, email, and avatar are read-only and labelled as such.
- A future Solvan-owned profile may allow display-name/avatar editing only
  after a dedicated profile store, malware-safe media path, deletion behavior,
  and audit/privacy contract exist.

## 8. Environment

```typescript
type EnvironmentSettings = {
  scope_key: string;
  name: string;
  environment_id: string;
  project_id: string;
  region: string;
  classification: "LOCAL" | "DEVELOPMENT" | "STAGING" | "PRODUCTION";
  data_status: string;
  authority: string;
  generated_at: string;
  available_scopes: Array<{
    scope_key: string;
    name: string;
    project_id: string;
    region: string;
    classification: string;
  }>;
};
```

All fields are read-only in Settings. Environment creation, deletion, project
binding, region changes, and authority changes are deployment operations.

Opaque IDs may be copied only when the operator can already view the scope.
The friendly name is primary; machine identifiers are subordinate mono text.

### 8.1 Integrations — target

`Settings → Integrations` owns connection enrollment and operational health;
Agent Fleet owns governance of the Tools and profiles those connections make
available. The two surfaces deep-link to one another without duplicating or
contradicting state.

Each provider instance is a separate row with friendly name, exact connection
ID, provider, external project/account/workspace, environment, region, owner,
purpose, credential posture, observed capabilities, availability, last probe,
last success, proof expiry, safe reason, and next step. There is no “default”
provider row. Filters cover provider, environment, region, owner, posture, and
availability.

The availability vocabulary is the closed specification 13 set:
`Not configured`, `Probing`, `Ready`, `Degraded`, `Misconfigured`, `Denied`,
`Unreachable`, `Stale`, and `Disabled`. The human label is primary and the
machine value is secondary. Every state other than Ready includes a visible
reason and one safe next step; definitions are available in-page and are not
tooltip-only.

`Verify again` is the only target v1 operation on the health panel. It creates
a bounded, idempotent probe request and shows queued/running/result state. It
cannot edit configuration, rotate a secret, grant a role, enable a Tool, or
mark the connection healthy. Enrollment, OAuth, secret rotation, disable, and
revocation require separately authorized, versioned workflows with immutable
audit; until those workflows are implemented, the page deep-links to approved
setup documentation and never renders dead controls.

### 8.1 Conversation channels

`Settings → Channels` is the production onboarding surface for an operator's
Slack, Discord, and email identities. It is not a credential editor and it
does not merge provider installation authority with principal binding.

Each provider card renders one closed state from `NOT_CONFIGURED`,
`AVAILABLE`, `CONNECTING`, `CONNECTED`, `NEEDS_ATTENTION`, or `DISABLED`, plus
the authoritative source, last verified time, safe reason, and one next step.
Slack and Discord expose `Connect` only when a bound deployment-health receipt
is current; clicking it creates an identity-agnostic one-time command and shows
the provider-native completion instruction. Email asks for a normal email
address, submits it to the server, and says that a verification message was
sent; production never displays the code. All three poll the durable enrollment
state until it is consumed, expires, is cancelled, or fails.

The surface provides retry after a terminal enrollment, cancel while pending,
refresh, and disconnect for an active binding. Disconnect requires explicit
confirmation and shows that queued delivery and subscriptions will be fenced.
No control asks for a platform identifier, Google identity token, OAuth code,
bot token, client secret, signing secret, or Secret Manager reference.
Provider-install controls, where authorized, deep-link to a separate
administrator workflow and never simulate readiness in this operator surface.

Solvant Relay is a nested `Settings → Integrations → Relays` target surface,
not an Agent Fleet entry. It uses specification 22 §19's closed lifecycle,
health, attestation, policy/catalog digest, connector, ambiguity, kill-switch,
source-binding, upgrade and deployment-receipt projection. The detail view
distinguishes the Relay transport from every real provider source connection.
The setup wizard selects only a `READY`, `CUSTOMER_SIDE_NONE` real-provider
connection whose exact provider/capability pair matches the closed adapter. It
selects—not free-text accepts—the qualified transport, customer workload
identity, attested image, signed policy, capability receipt, and source
binding; their hashes and identifiers are displayed as read-only provenance.
It then generates a download-only host-specific deployment bundle: strict Helm
values for GKE, a rendered Cloud Run Job manifest, or a rootless on-prem bundle,
with exact IAM/RBAC, egress, ledger, and kill-switch requirements. The bundle
is deliberately not a policy editor, credential carrier, or remote deployment
command: the customer adds local mounts, signing material, egress controls, and
their kill switch in their own delivery system. A qualification receipt remains
a customer-signed, independently verified record rather than a browser upload.

The direct-GCP onboarding view precedes Relay choice. It guides an
administrator through a customer reader service account, the exact Solvan
delegator identity and cross-project impersonation condition, the external
resource and metrics scopes, capability probe, and Cloud Monitoring source
binding. It displays condition and audit provenance as read-only records; it
does not offer browser-side service-account selection or key entry. It shows a
distinct read-only-pilot status until a deployed receipt proves real alert
delivery and manual incident escalation. It never implies that Relay
installation is required for a direct GCP customer.
The console cannot edit customer-
local policy, reveal a credential/reference, force readiness, clear an
ambiguous read, replay provider access, or turn a Relay into an Actuator.

## 9. AI runtime

```typescript
type EffectiveRuntimeSettings = {
  provider: string;
  model_resource: string;
  model_display_name: string;
  model_revision: string | null;
  region: string;
  framework: string;
  framework_version: string;
  runtime_sdk: string;
  runtime_sdk_version: string;
  agent_manifest_version: string;
  release_commit: string;
  deployment_id: string | null;
  source: "BOUND_RELEASE" | "MANIFEST_TARGET" | "LOCAL_FIXTURE";
  evidence_status: string;
  fallback_status: "NONE" | "ACTIVE" | "UNAVAILABLE";
};
```

The page shows the effective value and source. `MANIFEST_TARGET` is explicitly
labelled as intended configuration and must not be described as deployed.
`BOUND_RELEASE` requires a hash-validated deployment receipt. Local fixture
values are labelled non-authoritative.

Ordinary operators cannot change provider, model, model revision, framework,
SDK, region, fallback, prompt, tool registry, or agent policy here. An admin
with runtime-management capability receives a link to the reviewed release
workflow, not an inline selector.

## 10. Safety and governance

```typescript
type GovernanceSettings = {
  autonomy_state: string;
  autonomy_reason: string;
  autonomy_next_step: string;
  mutation_authority: string;
  policy_version: string;
  approval_mode: string;
  gateway_status: string;
  model_armor_status: string;
  identity_status: string;
  retention_summary: string;
  configuration_source: string;
  last_verified_at: string | null;
};
```

The UI uses human labels with machine states available in secondary text. Each
degraded, blocked, unresolved, or stale value links to Agent Fleet, Release
Evidence, Integrations, or the corresponding audit record.

Settings does not offer autonomy, mutation authority, gateway, Armor, IAM,
approval, policy, or retention toggles. Future admin workflows must use typed,
versioned requests, explicit confirmation, server authorization, optimistic
concurrency, and immutable audit events.

The governance surface includes an **Earned autonomy** panel. It renders the
machine state, a plain-language refusal reason, and one safe next step. Local
development and any environment without a current, independently derived
competence receipt must render `UNAVAILABLE`; the console must never infer
`ACTIVE` from a manifest, standing preauthorization, model output, or a local
fixture.

### 10.1 Action-policy explanation — target

`/settings/governance` also provides a read-only action-policy explanation. For
each visible registered action class it shows whether the effective policy is
autonomous, exact-approval-bound, or disabled; its risk/reversibility category;
the effective scope; policy version; provenance; validity; and the safe next
step when it cannot run. When policy inheritance is supported, the page shows
the global, team, and service layers and identifies the immutable record that
won. It does not imply that an absent layer is permissive.

This is an explanation and diagnostic surface, not a generic policy editor.
Creating or changing a team/service override remains a typed, versioned,
reviewed administrative request with explicit confirmation, server-side
authorization, optimistic concurrency, and an immutable audit event. The page
links an action-policy row to the governing workflow and relevant integration
health, but never displays credentials or grants a production approval.

## 11. About and diagnostics

Required fields:

- console version;
- API version;
- build commit;
- deployment ID when bound;
- settings schema version;
- snapshot schema version;
- settings projection generation time;
- API status;
- documentation, privacy, and third-party notice links.

Diagnostic fields never expose environment variables, tokens, connection
strings, secret names that disclose customer data, raw headers, prompts,
evidence payloads, or unrestricted stack traces.

## 12. Capabilities and authorization

```typescript
type SettingsCapabilities = {
  edit_preferences: boolean;
  switch_environment: boolean;
  sign_out: boolean;
  manage_members: boolean;
  manage_security: boolean;
  manage_runtime: boolean;
  view_audit: boolean;
  export_diagnostics: boolean;
};
```

Capabilities are calculated server-side for the selected environment. A hidden
or disabled control is not authorization. Every write endpoint repeats the
identity, scope, role, payload, version, and policy checks.

Unavailable controls follow these rules:

- omit actions the user can never perform;
- disable temporary unavailability with an explanation and recovery action;
- render managed fields as values, not disabled text inputs;
- never display a clickable control with no handler.

## 13. API contracts

### 13.1 Read endpoints

```text
GET /api/console/me
GET /api/console/settings
GET /api/console/environments
```

`/me` returns operator context and current environment capabilities.
`/settings` returns one versioned `SettingsProjection`:

```typescript
type SettingsProjection = {
  schema_version: 1;
  generated_at: string;
  data_status: string;
  preference_version: number;
  operator: OperatorContext;
  preferences: UserPreferences;
  environment: EnvironmentSettings;
  runtime: EffectiveRuntimeSettings;
  governance: GovernanceSettings;
  about: Record<string, string | null>;
  capabilities: SettingsCapabilities;
};
```

`/environments` may be folded into `/settings.environment.available_scopes` in
the first release. The server filters it to scopes the verified principal may
view.

### 13.2 Preference write

```text
PATCH /api/console/preferences
If-Match: "preference-version"
```

The body contains only allowlisted `UserPreferences` fields. Unknown fields,
invalid enum values, invalid timezones, stale versions, and attempts to write
operational configuration fail closed with typed errors.

Responses:

- `200` returns normalized preferences and the new version;
- `400` invalid preference;
- `401` identity required for server synchronization;
- `403` preference writes prohibited;
- `409` stale preference version;
- `422` valid JSON but invalid field value;
- `503` preference store unavailable; local preference remains active.

Local development uses a non-authoritative in-browser preference store and does
not pretend a server write was durable.

### 13.3 Caching

- `/me` and `/settings` are private/no-store when identity-specific.
- Non-sensitive immutable about/build metadata may use a short private cache.
- Environment switching changes the cache key by opaque authorized scope key.
- Responses include schema version and generated time.
- A stale projection is labelled and never silently presented as current.

## 14. Preference persistence and startup

Local storage key: `solvan.console.preferences.v1`.

The stored object contains only preferences, local version, and update time.
It contains no principal, email, role, scope authority, token, environment
permission, or runtime configuration.

Before the main stylesheet paints, a small bootstrap reads and validates the
theme enum, resolves system theme, and applies root attributes. Invalid or
unparseable storage is ignored and replaced with defaults after startup.

Authenticated server synchronization is eventually consistent:

1. apply valid local preferences before paint;
2. fetch server preferences after identity resolution;
3. compare versions/update times;
4. apply the newer valid record;
5. PATCH only when the operator is authenticated and synchronization is
   allowed; and
6. keep the last valid local preference if the server is unavailable.

## 15. Loading, error, empty, and stale states

- Shell-level theme remains available if the Settings API fails.
- The console snapshot carries the same versioned Settings projection used by
  the dedicated endpoint so a rolling frontend/API deployment cannot collapse
  the page. If the dedicated endpoint fails, the UI preserves that projection,
  labels it as not refreshed, and offers retry.
- When an older API supplies no embedded Settings projection, the client may
  derive a visibly degraded fallback only from fields already present in the
  snapshot. It must label unavailable model, identity, policy, and build fields
  rather than infer them.
- Each section has a bounded skeleton or progress label; it does not blank the
  entire console.
- A read failure states which information is unavailable and preserves last
  known data with a visible stale label when safe.
- A preference save failure leaves the selected local preference active and
  explains that it is not synchronized.
- Missing runtime evidence displays `Not verified`, not `Unknown model` when a
  manifest target is known.
- Missing identity displays authentication state; it never invents a profile.
- Empty role, environment, or capability collections receive explanatory copy
  and no dead actions.

## 16. Accessibility and responsive behavior

- All controls have visible labels and programmatic names.
- Theme, density, and motion use radio-group or segmented-control semantics.
- Current section uses `aria-current="page"`.
- Save status uses a polite live region; errors use an alert.
- Operator menu follows keyboard menu/popover behavior and restores focus.
- Focus is visible in both themes and all density modes.
- Status never relies on color alone.
- Text and controls meet WCAG 2.2 AA in light and dark themes.
- At 320 px width there is no page-level horizontal overflow.
- Settings rows stack labels, descriptions, values, and controls without
  clipping machine identifiers.
- At 200% zoom the section navigation and operator menu remain operable.

## 17. Privacy, security, and audit requirements

- Content Security Policy restricts avatar and external documentation origins.
- Avatar requests do not carry authorization headers or sensitive referrers.
- Preference telemetry records only the preference category changed, never the
  previous/new value when it could reveal accessibility or locale attributes.
- Viewing Settings is not an audit event.
- Administrative configuration changes are audited with actor, scope,
  before/after hashes, policy version, request ID, and outcome.
- Preference records are user-scoped and cannot be read by another user except
  through a documented support/admin privacy workflow.
- Deleting an account deletes Solvan-owned preferences according to retention
  policy; local browser preferences can be reset from the Personal section.

## 18. Acceptance criteria

### SET-01 Data truth

Settings and the top bar render environment name/region/authority from the API;
changing fixture values changes the UI without a frontend edit.

### SET-02 Theme

System, Light, and Dark work, persist across reload, apply before first paint,
respond to system changes in System mode, and pass automated contrast checks.

### SET-03 Accessibility preferences

Density, motion, and timezone apply consistently, persist, and preserve all
information and keyboard operations.

### SET-04 Operator menu

The menu displays truthful local/authenticated states, roles and scope; opens
and closes by keyboard; restores focus; and exposes no dead action.

### SET-05 Profile ownership

Google-managed identity fields are read-only and labelled. Missing/rejected
avatar images fall back to deterministic initials.

### SET-06 Runtime transparency

The effective model, provider, framework, SDK, region, manifest, release, and
evidence status are visible. Intended and deployed values are not conflated.

### SET-07 Governance transparency

Authority, approvals, Gateway, Armor, identity, retention, policy source, and
verification status are visible and link to their owning surfaces.

### SET-08 Authorization

Capabilities are environment-scoped; direct write attempts without the
required verified identity fail even when the request fabricates UI fields.

### SET-09 Secret absence

Contract and browser tests assert that settings responses, rendered fields,
DOM attributes, local storage, logs, and diagnostics contain no token, secret,
password, credential, private key, or connection string values.

### SET-10 Environment switching

Only server-returned scopes can be selected. Switching invalidates old scoped
state, refetches all projections, and safely restores the prior scope on
failure.

### SET-11 Failure behavior

API, identity, preference-store, avatar, and stale-version failures have
specific recoverable states; preferences never create operational authority.

### SET-12 Responsive and assistive technology

Settings passes axe checks and keyboard flows at desktop and 320/390 px widths,
200% zoom, both themes, and reduced-motion mode without horizontal overflow.

### SET-13 Ruhu ownership

No Ruhu tenant/integration state is hardcoded in global Settings. The linked
integration and release surfaces own those records.

### SET-14 Regression boundary

The existing incident, approval, fleet, integration, and release-evidence
critical paths pass unchanged in every theme.

### SET-15 Connection health — target

Multiple provider instances remain distinct; availability is derived from
server receipts; every non-ready state has a safe reason and next step; a probe
cannot edit configuration or grant capability; and no secret-bearing provider
error reaches the API, DOM, logs, trace, or assistive-technology text.

## 19. Required automated tests

### Unit

- preference parsing/defaulting/version comparison;
- theme resolution and system-change behavior;
- initials and avatar fallback;
- runtime source labels;
- settings capability projection;
- timezone validation.
- connection availability/reason-template derivation and secret redaction
  when the target Integrations section is implemented.

### API/contract

- local and authenticated `/me` projections;
- local and bound-release `/settings` projections;
- preference allowlist and optimistic concurrency;
- cross-scope and fabricated-principal denial;
- no-secret response scan;
- schema compatibility.
- multi-instance connection projection, bounded probe creation, fabricated
  Ready-state refusal, and cross-scope denial when target Integrations lands.

### End-to-end

- all required SET-01 through SET-14 criteria; SET-15 when the target
  Integrations section is implemented;
- operator menu keyboard flow;
- reload persistence/no wrong-theme flash;
- system theme change;
- deep-linked sections and back/forward;
- local read-only disclosure;
- mobile navigation and no overflow;
- axe in Light and Dark.

## 20. Implementation sequence

1. Add versioned settings, operator, preference, runtime, governance, about,
   and capability contracts.
2. Produce local fixture and cloud settings projections without secrets.
3. Add `/api/console/me` and `/api/console/settings`; add preference PATCH only
   when a durable authenticated preference store exists.
4. Implement pre-paint theme bootstrap and a single preference controller.
5. Replace top-bar literals and implement the operator menu.
6. Implement URL-addressable Settings sections and move Ruhu ownership.
7. Add unit, API, end-to-end, accessibility, responsive, and security tests.
8. Treat SET-01 through SET-14 as the completion gate.
