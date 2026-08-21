import { useEffect, useState } from "react";
import type { ConsoleSnapshot } from "./types";
import { MonoChip, StatusBadge } from "./components";
import { challengeHeaders, digest, requestStepUp } from "./session";
import type { StepUpStart } from "./session";
import { StepUpDialog } from "./StepUpDialog";

/* The three setups that presuppose a binding already exists: which delivery
   profile a repository uses, which human reviewer an approving account must
   match, and which repair commands are approved for it. Separate from the
   connect flow because that flow creates a binding and these configure one, and
   because each grants authority over an already-connected repository rather
   than deciding whether to connect at all. */

type RepairCommand = {
  id: string;
  repository_binding_id: string;
  command_kind: string;
  argv: string[];
  working_directory: string;
  declared_inputs: string[];
  lifecycle: string;
  command_hash: string;
};

type GitHubReviewerLink = {
  id: string;
  repository_binding_id: string;
  github_login: string;
  status: string;
  expires_at: string;
  owner: string;
  name: string;
};
type CodeDeliveryProfile = {
  id: string;
  repository_binding_id: string;
  profile_version: number;
  allowed_paths_json: string[];
  reviewer_policy_hash: string;
  profile_hash: string;
  status: string;
};

export function CodeDeliveryProfileSetup({ apiUrl, repositories }: {
  apiUrl: string;
  repositories: ConsoleSnapshot["integration"]["github"]["repositories"];
}): React.JSX.Element {
  const [token, setToken] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [allowedPaths, setAllowedPaths] = useState("src/**/*.py\ntests/**/*.py");
  const [checks, setChecks] = useState("unit\nsecurity");
  const [definitions, setDefinitions] = useState(".github/workflows/ci.yml");
  const [target, setTarget] = useState("");
  const [profiles, setProfiles] = useState<CodeDeliveryProfile[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const lines = (value: string): string[] => value.split("\n").map((item) => item.trim()).filter(Boolean);
  async function load(): Promise<void> {
    if (!token.trim()) { setNotice("Enter a verified administrator identity token."); return; }
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/code-delivery-profiles`, { headers: { "X-Solvan-Approval-Token": token.trim() } });
      const value = (await response.json().catch(() => null)) as CodeDeliveryProfile[] | { detail?: string } | null;
      if (!response.ok || !Array.isArray(value)) throw new Error(!Array.isArray(value) && value?.detail ? value.detail : "Delivery profiles are unavailable.");
      setProfiles(value);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Delivery profiles are unavailable."); }
    finally { setBusy(false); }
  }
  async function register(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/code-delivery-profiles`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim() },
        body: JSON.stringify({ repository_binding_id: repositoryId, allowed_paths: lines(allowedPaths), required_checks: lines(checks), required_check_definition_paths: lines(definitions), minimum_approvals: 1, require_code_owner_review: true, merge_method: "squash", deployment_target_profile: target.trim(), maximum_request_lifetime_minutes: 120 }),
      });
      const value = (await response.json().catch(() => null)) as { profile_id?: string; detail?: string } | null;
      if (!response.ok || !value?.profile_id) throw new Error(value?.detail ?? "Delivery profile was refused.");
      setNotice(`Activated delivery profile ${value.profile_id}.`); await load();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Delivery profile was refused."); }
    finally { setBusy(false); }
  }
  return <details className="card connection-card" aria-label="Configure code delivery policy">
    <summary><strong>Configure code delivery policy</strong><span className="cell-detail">Freeze allowed repair paths, required checks, reviewer rules, and deployment target</span></summary>
    <p className="section-note">The browser supplies typed policy choices only. Solvan writes immutable policy documents and computes every reference and digest used by a Code Change Request.</p>
    <form className="connect-form" onSubmit={(event) => void register(event)}>
      <label className="field-label">Administrator identity token<input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer …" autoComplete="off" /></label>
      <label className="field-label">Repository<select required value={repositoryId} onChange={(event) => setRepositoryId(event.target.value)}><option value="">Choose an active repository</option>{repositories.filter((item) => item.status === "ACTIVE").map((item) => <option key={item.id} value={item.id}>{item.owner}/{item.name}</option>)}</select></label>
      <div className="form-grid"><label className="field-label">Allowed repair paths<textarea value={allowedPaths} onChange={(event) => setAllowedPaths(event.target.value)} /></label><label className="field-label">Required GitHub checks<textarea value={checks} onChange={(event) => setChecks(event.target.value)} /></label><label className="field-label">Check definition paths<textarea value={definitions} onChange={(event) => setDefinitions(event.target.value)} /></label></div>
      <label className="field-label">Deployment target profile<input required value={target} onChange={(event) => setTarget(event.target.value)} placeholder="cloud-run/payments-production@1" /></label>
      <div className="settings-actions"><button className="primary-button" type="submit" disabled={busy || !token.trim() || !repositoryId || !target.trim()}>{busy ? "Recording…" : "Activate immutable profile"}</button><button className="secondary-button" type="button" disabled={busy || !token.trim()} onClick={() => void load()}>Refresh</button></div>
    </form>
    {profiles.map((profile) => <p className="posture-row" key={profile.id}><span><MonoChip>{profile.id}</MonoChip> · v{profile.profile_version} · {profile.allowed_paths_json.join(", ")}</span><StatusBadge label={profile.status} tone={profile.status === "ACTIVE" ? "success" : "neutral"} /></p>)}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </details>;
}

export function GitHubReviewerIdentitySetup({ apiUrl, repositories }: {
  apiUrl: string;
  repositories: ConsoleSnapshot["integration"]["github"]["repositories"];
}): React.JSX.Element {
  const [token, setToken] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [links, setLinks] = useState<GitHubReviewerLink[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const activeRepositories = repositories.filter((item) => item.status === "ACTIVE");

  async function load(): Promise<void> {
    if (!token.trim()) { setNotice("Use a fresh verified Solvan sign-in first."); return; }
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/github/reviewer-links/me`, {
        headers: { "X-Solvan-Approval-Token": token.trim() },
        credentials: "same-origin",
      });
      const value = (await response.json().catch(() => null)) as GitHubReviewerLink[] | { detail?: string } | null;
      if (!response.ok || !Array.isArray(value)) throw new Error(!Array.isArray(value) && value?.detail ? value.detail : "GitHub reviewer links are unavailable.");
      setLinks(value);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "GitHub reviewer links are unavailable."); }
    finally { setBusy(false); }
  }

  async function connect(): Promise<void> {
    if (!token.trim() || !repositoryId) { setNotice("Choose a repository and use a fresh verified Solvan sign-in."); return; }
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/github/reviewer-links`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim() },
        credentials: "same-origin",
        body: JSON.stringify({ repository_binding_id: repositoryId }),
      });
      const value = (await response.json().catch(() => null)) as { authorization_url?: string; detail?: string } | null;
      if (!response.ok || !value?.authorization_url) throw new Error(value?.detail ?? "GitHub identity linking was refused.");
      window.location.assign(value.authorization_url);
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : "GitHub identity linking was refused.");
      setBusy(false);
    }
  }

  async function disconnect(bindingId: string): Promise<void> {
    if (!token.trim()) { setNotice("Use a fresh verified Solvan sign-in first."); return; }
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/github/reviewer-links/${encodeURIComponent(bindingId)}`, {
        method: "DELETE",
        headers: { "X-Solvan-Approval-Token": token.trim() },
        credentials: "same-origin",
      });
      if (!response.ok) {
        const value = (await response.json().catch(() => null)) as { detail?: string } | null;
        throw new Error(value?.detail ?? "GitHub identity disconnect was refused.");
      }
      await load();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "GitHub identity disconnect was refused."); }
    finally { setBusy(false); }
  }

  return <details className="card connection-card" aria-label="Connect GitHub reviewer identity">
    <summary><strong>Connect your GitHub reviewer identity</strong><span className="cell-detail">Prove which GitHub account supplied a repository review; no personal token is retained</span></summary>
    <p className="section-note">This opens GitHub's own sign-in page and links its immutable account ID to your verified Solvan identity for one repository. Solvan discards the one-time user token after reading your account; the GitHub App remains the only repository credential.</p>
    <label className="field-label">Fresh Solvan identity token<input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer …" autoComplete="off" /></label>
    <label className="field-label">Repository<select value={repositoryId} onChange={(event) => setRepositoryId(event.target.value)}><option value="">Choose an active repository binding</option>{activeRepositories.map((repository) => <option key={repository.id} value={repository.id}>{repository.owner}/{repository.name}</option>)}</select></label>
    <div className="settings-actions"><button type="button" className="primary-button" disabled={busy || !token.trim() || !repositoryId} onClick={() => void connect()}>{busy ? "Working…" : "Continue to GitHub"}</button><button type="button" className="secondary-button" disabled={busy || !token.trim()} onClick={() => void load()}>Refresh linked accounts</button></div>
    {links.map((link) => <div className="posture-row" key={link.id}><span><strong>@{link.github_login}</strong> · {link.owner}/{link.name} · <StatusBadge label={link.status} tone={link.status === "ACTIVE" ? "success" : "warning"} /></span>{link.status === "ACTIVE" && <button type="button" className="secondary-button" disabled={busy} onClick={() => void disconnect(link.id)}>Disconnect</button>}</div>)}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </details>;
}

export function RepairCommandSetup({ apiUrl, repositories }: {
  apiUrl: string;
  repositories: ConsoleSnapshot["integration"]["github"]["repositories"];
}): React.JSX.Element {
  const [token, setToken] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [kind, setKind] = useState("REPRODUCTION");
  const [argv, setArgv] = useState("python\n-m\npytest\n-q");
  const [workingDirectory, setWorkingDirectory] = useState(".");
  const [inputs, setInputs] = useState("src/**/*.py\ntests/**/*.py");
  const [commands, setCommands] = useState<RepairCommand[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function lines(value: string): string[] {
    return value.split("\n").map((item) => item.trim()).filter(Boolean);
  }

  async function refresh(): Promise<void> {
    if (!token.trim()) { setNotice("Enter a verified administrator identity token first."); return; }
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/repair-commands`, { headers: { "X-Solvan-Approval-Token": token.trim() } });
      if (!response.ok) throw new Error(`Repair command list refused (${response.status}).`);
      setCommands((await response.json()) as RepairCommand[]);
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Repair command list failed."); }
    finally { setBusy(false); }
  }

  async function register(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault(); setBusy(true); setNotice(null);
    try {
      if (!token.trim() || !repositoryId) throw new Error("Choose an active repository and provide administrator identity.");
      const response = await fetch(`${apiUrl}/api/v1/repair-commands`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim() },
        body: JSON.stringify({
          schema_version: 1,
          repository_binding_id: repositoryId,
          command_kind: kind,
          argv: lines(argv),
          working_directory: workingDirectory,
          declared_inputs: lines(inputs),
          declared_outputs: [],
          timeout_ms: 60000,
          cpu_millis: 1000,
          memory_mib: 512,
          output_byte_limit: 65536,
          network_mode: "NONE",
        }),
      });
      if (!response.ok) throw new Error(`Repair command registration refused (${response.status}).`);
      const value = (await response.json()) as { definition_id: string };
      setNotice(`Registered ${value.definition_id}. It becomes usable only when an approved production-graph policy selects it.`);
      await refresh();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : "Repair command registration failed."); }
    finally { setBusy(false); }
  }

  async function revoke(command: RepairCommand): Promise<void> {
    const reason = window.prompt("Why is this approved repair command being revoked?");
    if (!reason || reason.trim().length < 8) { setNotice("A revocation reason of at least eight characters is required."); return; }
    setBusy(true); setNotice(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/repair-commands/${encodeURIComponent(command.id)}:revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Solvan-Approval-Token": token.trim() },
        body: JSON.stringify({ reason: reason.trim() }),
      });
      if (!response.ok) throw new Error(`Repair command revocation refused (${response.status}).`);
      setNotice(`Revoked ${command.id}. New repair plans cannot select it.`);
      await refresh();
    } catch (reasonValue) { setNotice(reasonValue instanceof Error ? reasonValue.message : "Repair command revocation failed."); }
    finally { setBusy(false); }
  }

  const activeRepositories = repositories.filter((item) => item.status === "ACTIVE");
  return <details className="integration-setup">
    <summary>Configure bounded repair commands</summary>
    <p className="section-note">Register literal argument arrays for an active repository. Solvan does not accept a shell command, environment variables, network access, or a repository credential here.</p>
    <label className="field-label">Administrator identity token<input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer …" autoComplete="off" /></label>
    <div className="settings-actions"><button type="button" className="secondary-button" disabled={busy} onClick={() => void refresh()}>{busy ? "Working…" : "Load registered commands"}</button></div>
    <form className="stacked-form" onSubmit={(event) => void register(event)}>
      <label className="field-label">Repository<select value={repositoryId} onChange={(event) => setRepositoryId(event.target.value)} required><option value="">Choose an active binding</option>{activeRepositories.map((item) => <option key={item.id} value={item.id}>{item.owner}/{item.name}</option>)}</select></label>
      <label className="field-label">Command purpose<select value={kind} onChange={(event) => setKind(event.target.value)}><option value="REPRODUCTION">Reproduce the defect</option><option value="REGRESSION">Run regression checks</option></select></label>
      <label className="field-label">Arguments · one literal argument per line<textarea rows={5} value={argv} onChange={(event) => setArgv(event.target.value)} /></label>
      <label className="field-label">Working directory<input value={workingDirectory} onChange={(event) => setWorkingDirectory(event.target.value)} /></label>
      <label className="field-label">Declared input selectors · one per line<textarea rows={4} value={inputs} onChange={(event) => setInputs(event.target.value)} /></label>
      <button className="primary-button" type="submit" disabled={busy || activeRepositories.length === 0}>Register approved command</button>
    </form>
    {commands && <div className="responsive-table"><table><caption className="visually-hidden">Registered repair commands</caption><thead><tr><th>Purpose</th><th>Literal argv</th><th>Inputs</th><th>Status</th><th>Control</th></tr></thead><tbody>{commands.map((item) => <tr key={item.id}><td data-label="Purpose">{item.command_kind}<span className="cell-detail">{item.id}</span></td><td data-label="Literal argv"><MonoChip>{item.argv.join(" · ")}</MonoChip><span className="cell-detail">cwd {item.working_directory}</span></td><td data-label="Inputs">{item.declared_inputs.join(", ")}</td><td data-label="Status"><StatusBadge label={item.lifecycle} tone={item.lifecycle === "APPROVED" ? "success" : "neutral"} /></td><td data-label="Control">{item.lifecycle === "APPROVED" && <button type="button" className="secondary-button" disabled={busy} onClick={() => void revoke(item)}>Revoke</button>}</td></tr>)}</tbody></table></div>}
    {commands?.length === 0 && <p className="inline-notice">No repair command is registered for this scope.</p>}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
  </details>;
}
