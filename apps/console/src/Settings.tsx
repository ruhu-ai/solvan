import { useEffect, useState } from "react";
import {
  Accessibility,
  Bot,
  Cable,
  CircleUserRound,
  Info,
  MonitorCog,
  Palette,
  ShieldCheck,
  Users,
} from "lucide-react";
import { LabelValue, PageHeader, StatusBadge } from "./components";
import { ChannelSettings } from "./ChannelSettings";
import { OperatorAccess } from "./OperatorAccess";
import {
  formatPreferenceTimestamp,
  readPreferences,
  subscribePreferences,
  writePreferences,
} from "./preferences";
import type {
  DensityMode,
  MotionMode,
  SettingsProjection,
  ThemeMode,
  UserPreferences,
} from "./types";

type SettingsSection = "personal" | "profile" | "access" | "environment" | "runtime" | "channels" | "governance" | "about";

const sections: Array<{
  id: SettingsSection;
  label: string;
  description: string;
  icon: typeof Palette;
}> = [
  { id: "personal", label: "Personal", description: "Appearance and accessibility", icon: Palette },
  { id: "profile", label: "Profile and session", description: "Identity and roles", icon: CircleUserRound },
  { id: "access", label: "Operator access", description: "Who reaches this environment", icon: Users },
  { id: "environment", label: "Environment", description: "Current operational scope", icon: MonitorCog },
  { id: "runtime", label: "AI runtime", description: "Effective model and platform", icon: Bot },
  { id: "channels", label: "Channels", description: "Slack, Discord, and email", icon: Cable },
  { id: "governance", label: "Safety and governance", description: "Authority and controls", icon: ShieldCheck },
  { id: "about", label: "About", description: "Build and diagnostics", icon: Info },
];

const browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
const standardTimezones: Array<{ value: string; label: string }> = [
  { value: "America/New_York", label: "Eastern Time (New York)" },
  { value: "America/Chicago", label: "Central Time (Chicago)" },
  { value: "America/Denver", label: "Mountain Time (Denver)" },
  { value: "America/Los_Angeles", label: "Pacific Time (Los Angeles)" },
  { value: "America/Toronto", label: "Eastern Canada (Toronto)" },
  { value: "America/Sao_Paulo", label: "Brazil Time (Sao Paulo)" },
  { value: "Europe/London", label: "UK Time (London)" },
  { value: "Europe/Paris", label: "Central Europe (Paris)" },
  { value: "Europe/Helsinki", label: "Eastern Europe (Helsinki)" },
  { value: "Africa/Lagos", label: "West Africa Time (Lagos)" },
  { value: "Africa/Johannesburg", label: "South Africa Time (Johannesburg)" },
  { value: "Africa/Nairobi", label: "East Africa Time (Nairobi)" },
  { value: "Asia/Dubai", label: "Gulf Time (Dubai)" },
  { value: "Asia/Kolkata", label: "India Time (Kolkata)" },
  { value: "Asia/Singapore", label: "Singapore Time" },
  { value: "Asia/Tokyo", label: "Japan Time (Tokyo)" },
  { value: "Australia/Sydney", label: "Australian Eastern Time (Sydney)" },
  { value: "Pacific/Auckland", label: "New Zealand Time (Auckland)" },
];

function sectionFromLocation(): SettingsSection {
  const value = new URLSearchParams(window.location.search).get("section");
  return sections.some((section) => section.id === value) ? value as SettingsSection : "personal";
}

function statusTone(value: string): "success" | "warning" | "danger" | "neutral" | "info" {
  const normalized = value.toUpperCase();
  if (normalized.includes("HEALTHY") || normalized.includes("COMPLETE") || normalized === "ACTIVE" || normalized === "AVAILABLE" || normalized === "CONSUMED") return "success";
  if (normalized.includes("BLOCK") || normalized.includes("DENIED") || normalized.includes("REQUIRED") || normalized.includes("UNAVAILABLE") || normalized.includes("NOT_REPORTED") || normalized === "NOT_CONFIGURED" || normalized === "NEEDS_ATTENTION") return "warning";
  if (normalized.includes("FAIL") || normalized.includes("ERROR")) return "danger";
  if (normalized.includes("LOCAL") || normalized.includes("FIXTURE")) return "info";
  return "neutral";
}

function PreferenceChoice<T extends string>({
  label,
  value,
  choices,
  onChange,
}: {
  label: string;
  value: T;
  choices: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
}): React.JSX.Element {
  return <div className="settings-segmented" role="radiogroup" aria-label={label}>{choices.map((choice) => (
    <button
      key={choice.value}
      type="button"
      role="radio"
      aria-checked={value === choice.value}
      className={value === choice.value ? "active" : ""}
      onClick={() => onChange(choice.value)}
    >{choice.label}</button>
  ))}</div>;
}

function SettingsRow({ title, description, children }: {
  title: string;
  description: string;
  children: React.ReactNode;
}): React.JSX.Element {
  return <div className="settings-row"><div><strong>{title}</strong><p>{description}</p></div><div className="settings-control">{children}</div></div>;
}

function DetailCard({ title, description, children }: {
  title: string;
  description?: string;
  children: React.ReactNode;
}): React.JSX.Element {
  return <section className="card settings-detail-card"><div className="section-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div></div>{children}</section>;
}

function Avatar({ name, initials, url }: { name: string; initials: string; url: string | null }): React.JSX.Element {
  const [failed, setFailed] = useState(false);
  return <span className="profile-avatar" aria-hidden="true">{url && !failed
    ? <img src={url} alt="" referrerPolicy="no-referrer" onError={() => setFailed(true)} />
    : initials || name.slice(0, 2).toUpperCase()}</span>;
}

function PersonalSettings({ preferences }: { preferences: UserPreferences }): React.JSX.Element {
  const [saveStatus, setSaveStatus] = useState("Preferences are stored only on this device.");
  const [saveFailed, setSaveFailed] = useState(false);

  function update(next: Partial<UserPreferences>): void {
    const result = writePreferences({ ...preferences, ...next });
    setSaveFailed(!result.persisted);
    setSaveStatus(result.persisted ? "Saved on this device" : "Applied for this tab; browser storage is unavailable.");
  }

  function updateTimezone(value: string): void {
    if (value === "BROWSER") update({ timezone_mode: "BROWSER", timezone: null });
    else if (value === "UTC") update({ timezone_mode: "UTC", timezone: null });
    else update({ timezone_mode: "NAMED", timezone: value });
  }

  const timezoneValue = preferences.timezone_mode === "NAMED" && preferences.timezone
    ? preferences.timezone
    : preferences.timezone_mode;

  return <div className="settings-section-stack">
    <DetailCard title="Appearance" description="Personal choices never change production policy or agent authority.">
      <SettingsRow title="Theme" description="Follow this device or choose a fixed console appearance.">
        <PreferenceChoice<ThemeMode> label="Theme" value={preferences.theme} choices={[
          { value: "SYSTEM", label: "System" }, { value: "LIGHT", label: "Light" }, { value: "DARK", label: "Dark" },
        ]} onChange={(theme) => update({ theme })} />
      </SettingsRow>
      <SettingsRow title="Density" description="Compact reduces spacing without hiding status or provenance.">
        <PreferenceChoice<DensityMode> label="Density" value={preferences.density} choices={[
          { value: "COMFORTABLE", label: "Comfortable" }, { value: "COMPACT", label: "Compact" },
        ]} onChange={(density) => update({ density })} />
      </SettingsRow>
      <SettingsRow title="Reset preferences" description="Restore System theme, comfortable density, system motion, and browser timezone.">
        <button className="secondary-button" type="button" onClick={() => update({ theme: "SYSTEM", density: "COMFORTABLE", motion: "SYSTEM", timezone_mode: "BROWSER", timezone: null })}>Reset to defaults</button>
      </SettingsRow>
    </DetailCard>
    <DetailCard title="Accessibility" description="Critical states always include text, icon, and shape.">
      <SettingsRow title="Motion" description="System follows your operating-system reduced-motion preference.">
        <PreferenceChoice<MotionMode> label="Motion" value={preferences.motion} choices={[
          { value: "SYSTEM", label: "System" }, { value: "REDUCED", label: "Reduced" }, { value: "FULL", label: "Full" },
        ]} onChange={(motion) => update({ motion })} />
      </SettingsRow>
      <SettingsRow title="Timezone" description="Events remain stored in UTC; this changes human-readable timestamps only.">
        <div className="timezone-control">
          <select aria-label="Display timezone" value={timezoneValue} onChange={(event) => updateTimezone(event.target.value)}>
            <option value="BROWSER">Browser timezone — {browserTimezone.replaceAll("_", " ")}</option>
            <option value="UTC">UTC</option>
            {preferences.timezone_mode === "NAMED" && preferences.timezone && !standardTimezones.some((zone) => zone.value === preferences.timezone) && <option value={preferences.timezone}>{preferences.timezone.replaceAll("_", " ")}</option>}
            {standardTimezones.map((zone) => <option key={zone.value} value={zone.value}>{zone.label}</option>)}
          </select>
        </div>
      </SettingsRow>
    </DetailCard>
    <p className={saveFailed ? "preference-status preference-status-error" : "preference-status"} role={saveFailed ? "alert" : "status"} aria-live="polite"><Accessibility size={15} aria-hidden="true" />{saveStatus}</p>
  </div>;
}

function ProfileSettings({ projection, preferences }: { projection: SettingsProjection; preferences: UserPreferences }): React.JSX.Element {
  const operator = projection.operator;
  return <div className="settings-section-stack">
    <DetailCard title="Profile" description={operator.managed_by === "GOOGLE" ? "Identity fields are managed by Google." : "This identity exists only in local development."}>
      <div className="profile-summary"><Avatar name={operator.display_name} initials={operator.initials} url={operator.avatar_url} /><div><h3>{operator.display_name}</h3><p>{operator.email ?? operator.principal ?? "No verified principal"}</p></div><StatusBadge label={operator.state.replaceAll("_", " ")} tone={operator.state === "AUTHENTICATED" ? "success" : "info"} /></div>
      <dl className="settings-facts">
        <LabelValue label="Identity provider" value={operator.identity_provider ?? "Not established"} />
        <LabelValue label="Managed by" value={operator.managed_by ?? "Not established"} />
        <LabelValue label="Organization" value={operator.organization?.name ?? "Not assigned"} />
        <LabelValue label="Team" value={operator.team?.name ?? "Not assigned"} />
      </dl>
    </DetailCard>
    <DetailCard title="Session and access" description="Roles are recalculated for the selected environment.">
      <dl className="settings-facts">
        <LabelValue label="Effective roles" value={operator.roles.join(", ") || "None"} />
        <LabelValue label="Session expires" value={operator.session_expires_at ? formatPreferenceTimestamp(operator.session_expires_at, preferences) : "No browser session"} />
        <LabelValue label="Environment access" value={projection.environment.name} />
        <LabelValue label="Profile editing" value={operator.managed_by === "GOOGLE" ? "Managed by Google" : "Unavailable in local development"} />
      </dl>
    </DetailCard>
  </div>;
}

function EnvironmentSettings({ projection, preferences }: { projection: SettingsProjection; preferences: UserPreferences }): React.JSX.Element {
  const environment = projection.environment;
  return <div className="settings-section-stack">
    <DetailCard title="Current operational scope" description="Environment authority is deployment-managed and read-only here.">
      <div className="settings-card-status"><StatusBadge label={environment.classification} tone={environment.classification === "LOCAL" ? "info" : environment.classification === "UNKNOWN" ? "warning" : "neutral"} /><StatusBadge label={environment.authority} tone={statusTone(environment.authority)} /></div>
      <dl className="settings-facts">
        <LabelValue label="Name" value={environment.name} />
        <LabelValue label="Project" value={environment.project_id} />
        <LabelValue label="Environment ID" value={environment.environment_id} />
        <LabelValue label="Region" value={environment.region} />
        <LabelValue label="Data status" value={environment.data_status} />
        <LabelValue label="Projection generated" value={formatPreferenceTimestamp(environment.generated_at, preferences)} />
      </dl>
    </DetailCard>
    <DetailCard title="Authorized environments" description="The server—not the browser—decides which scopes may be selected.">
      <div className="authorized-scope-list">{environment.available_scopes.map((scope) => <div key={scope.scope_key}><div><strong>{scope.name}</strong><span>{scope.project_id} · {scope.region}</span></div><StatusBadge label={scope.classification} tone={scope.scope_key === environment.scope_key ? "success" : "neutral"} /></div>)}</div>
    </DetailCard>
  </div>;
}

function RuntimeSettings({ projection, navigate }: { projection: SettingsProjection; navigate: (route: "Agent Fleet" | "Release Evidence") => void }): React.JSX.Element {
  const runtime = projection.runtime;
  return <div className="settings-section-stack">
    <DetailCard title="Effective model" description="Visible for transparency. Changes require a reviewed release, not a Settings toggle.">
      <div className="settings-card-status"><StatusBadge label={runtime.source.replaceAll("_", " ")} tone={runtime.source === "BOUND_RELEASE" ? "success" : runtime.source === "UNAVAILABLE" ? "warning" : "info"} /><StatusBadge label={runtime.evidence_status} tone={statusTone(runtime.evidence_status)} /></div>
      <dl className="settings-facts">
        <LabelValue label="Provider" value={runtime.provider} />
        <LabelValue label="Model" value={runtime.model_display_name} />
        <LabelValue label="Model resource" value={runtime.model_resource} />
        <LabelValue label="Revision" value={runtime.model_revision ?? "Provider-managed alias"} />
        <LabelValue label="Model endpoint" value={runtime.model_location} />
        <LabelValue label="Runtime region" value={runtime.region} />
        <LabelValue label="Fallback" value={runtime.fallback_status} />
      </dl>
    </DetailCard>
    <DetailCard title="Runtime provenance" description="The source distinguishes a manifest target from a bound deployment.">
      <dl className="settings-facts">
        <LabelValue label="Framework" value={`${runtime.framework} ${runtime.framework_version}`} />
        <LabelValue label="Runtime SDK" value={`${runtime.runtime_sdk} ${runtime.runtime_sdk_version}`} />
        <LabelValue label="Agent manifest" value={runtime.agent_manifest_version} />
        <LabelValue label="Release commit" value={runtime.release_commit} />
        <LabelValue label="Deployment" value={runtime.deployment_id ?? "No bound deployment receipt"} />
        <LabelValue label="Configuration source" value={runtime.source.replaceAll("_", " ")} />
      </dl>
      <div className="settings-actions"><button className="secondary-button" onClick={() => navigate("Agent Fleet")}>Open Agent Fleet</button><button className="secondary-button" onClick={() => navigate("Release Evidence")}>Open release evidence</button></div>
    </DetailCard>
  </div>;
}

function GovernanceSettings({ projection, preferences, navigate }: { projection: SettingsProjection; preferences: UserPreferences; navigate: (route: "Agent Fleet" | "Release Evidence") => void }): React.JSX.Element {
  const governance = projection.governance;
  return <div className="settings-section-stack">
    <DetailCard title="Authority boundary" description="These values are read-only summaries of enforced policy.">
      <div className="settings-card-status"><StatusBadge label={governance.autonomy_state} tone={statusTone(governance.autonomy_state)} /><StatusBadge label={governance.mutation_authority} tone={statusTone(governance.mutation_authority)} /></div>
      <dl className="settings-facts">
        <LabelValue label="Policy version" value={governance.policy_version} />
        <LabelValue label="Approval mode" value={governance.approval_mode} />
        <LabelValue label="Configuration source" value={governance.configuration_source} />
        <LabelValue label="Last verified" value={governance.last_verified_at ? formatPreferenceTimestamp(governance.last_verified_at, preferences) : "Not verified"} />
      </dl>
    </DetailCard>
    <DetailCard title="Earned autonomy" description="Autonomous mutation is enabled only after typed evidence, an independent evaluation, and a fresh authorization-time recheck.">
      <div className="settings-card-status"><StatusBadge label={governance.autonomy_state} tone={statusTone(governance.autonomy_state)} /></div>
      <div className="settings-refusal" role="status">
        <strong>Why this is not enabled</strong>
        <p>{governance.autonomy_reason}</p>
        <strong>Safe next step</strong>
        <p>{governance.autonomy_next_step}</p>
      </div>
    </DetailCard>
    <DetailCard title="Security controls" description="A blocked control remains visible and links to its owning evidence surface.">
      <div className="governance-control-list">
        <div><span>Agent Gateway</span><StatusBadge label={governance.gateway_status} tone={statusTone(governance.gateway_status)} /></div>
        <div><span>Model Armor</span><StatusBadge label={governance.model_armor_status} tone={statusTone(governance.model_armor_status)} /></div>
        <div><span>Agent Identity</span><StatusBadge label={governance.identity_status} tone={statusTone(governance.identity_status)} /></div>
        <div><span>Retention</span><strong>{governance.retention_summary}</strong></div>
      </div>
      <div className="settings-actions"><button className="secondary-button" onClick={() => navigate("Agent Fleet")}>Inspect platform controls</button><button className="secondary-button" onClick={() => navigate("Release Evidence")}>Inspect release proof</button></div>
    </DetailCard>
  </div>;
}

function AboutSettings({ projection, preferences }: { projection: SettingsProjection; preferences: UserPreferences }): React.JSX.Element {
  const about = projection.about;
  const links = [
    ["Documentation", about.documentation_url], ["Privacy", about.privacy_url], ["Third-party notices", about.notices_url],
  ].filter((item): item is [string, string] => Boolean(item[1]));
  return <div className="settings-section-stack">
    <DetailCard title="Build information" description="Useful identifiers only; diagnostics never expose credentials or raw environment variables.">
      <dl className="settings-facts">
        <LabelValue label="Console version" value={about.console_version} />
        <LabelValue label="API version" value={about.api_version} />
        <LabelValue label="Build commit" value={about.build_commit} />
        <LabelValue label="Deployment ID" value={about.deployment_id ?? "Not bound"} />
        <LabelValue label="Settings schema" value={about.settings_schema_version} />
        <LabelValue label="Snapshot schema" value={about.snapshot_schema_version} />
        <LabelValue label="API status" value={about.api_status} />
        <LabelValue label="Projection generated" value={formatPreferenceTimestamp(about.projection_generated_at, preferences)} />
      </dl>
    </DetailCard>
    {links.length > 0 && <DetailCard title="Resources"><div className="settings-link-list">{links.map(([label, url]) => <a key={label} href={url} target="_blank" rel="noreferrer">{label} →</a>)}</div></DetailCard>}
  </div>;
}

export function Settings({
  projection,
  error,
  retry,
  navigate,
  apiUrl,
}: {
  projection: SettingsProjection | null;
  error: string | null;
  retry: () => void;
  navigate: (route: "Agent Fleet" | "Release Evidence") => void;
  apiUrl: string;
}): React.JSX.Element {
  const [section, setSection] = useState<SettingsSection>(() => sectionFromLocation());
  const [preferences, setPreferences] = useState<UserPreferences>(() => readPreferences());

  useEffect(() => {
    const changed = () => setSection(sectionFromLocation());
    window.addEventListener("popstate", changed);
    return () => window.removeEventListener("popstate", changed);
  }, []);

  useEffect(() => subscribePreferences(setPreferences), []);

  function selectSection(next: SettingsSection): void {
    if (next === section) return;
    const url = new URL(window.location.href);
    url.searchParams.set("section", next);
    window.history.pushState({}, "", url);
    setSection(next);
  }

  const active = sections.find((item) => item.id === section) ?? sections[0];
  return <>
    <PageHeader eyebrow="Console settings" title="Settings" description="Personal preferences are editable. Environment, runtime, and safety values are provenance-backed and read-only." />
    <div className="settings-mobile-section"><label htmlFor="settings-section">Settings section</label><select id="settings-section" value={section} onChange={(event) => selectSection(event.target.value as SettingsSection)}>{sections.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></div>
    <div className="settings-layout">
      <nav className="settings-nav" aria-label="Settings sections">{sections.map((item) => { const Icon = item.icon; return <button key={item.id} aria-current={section === item.id ? "page" : undefined} className={section === item.id ? "active" : ""} onClick={() => selectSection(item.id)}><Icon size={17} strokeWidth={1.75} aria-hidden="true" /><span><strong>{item.label}</strong><small>{item.description}</small></span></button>; })}</nav>
      <div className="settings-content" aria-labelledby="settings-section-title">
        <div className="settings-content-heading"><p className="eyebrow">{active.label}</p><h2 id="settings-section-title">{active.description}</h2></div>
        {error && projection && <section className="settings-degraded" role="status"><div><strong>Some settings details could not be refreshed</strong><span>Showing safe values from the current console snapshot. Personal preferences continue to work.</span></div><button className="secondary-button" onClick={retry}>Retry settings</button></section>}
        {section === "personal" ? <PersonalSettings preferences={preferences} /> : error && !projection ? <section className="card settings-error" role="alert"><h2>Settings details unavailable</h2><p>The console could not load a safe settings projection.</p><code>{error}</code><button className="secondary-button" onClick={retry}>Try again</button></section> : !projection ? <section className="card settings-loading" aria-busy="true"><span className="spinner" /><p>Loading effective settings…</p></section> : section === "profile" ? <ProfileSettings projection={projection} preferences={preferences} /> : section === "access" ? <OperatorAccess apiUrl={apiUrl} /> : section === "environment" ? <EnvironmentSettings projection={projection} preferences={preferences} /> : section === "runtime" ? <RuntimeSettings projection={projection} navigate={navigate} /> : section === "channels" ? <ChannelSettings projection={projection} preferences={preferences} apiUrl={apiUrl} /> : section === "governance" ? <GovernanceSettings projection={projection} preferences={preferences} navigate={navigate} /> : <AboutSettings projection={projection} preferences={preferences} />}
      </div>
    </div>
  </>;
}
