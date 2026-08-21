import { useEffect, useState } from "react";
import type { ConsoleSnapshot } from "./types";
import { MonoChip, StatusBadge } from "./components";
import { challengeHeaders, digest, requestStepUp } from "./session";
import type { StepUpStart } from "./session";
import { StepUpDialog } from "./StepUpDialog";

/* The GitHub authority surface: connecting the App, widening one repository,
   and the three per-repository setups that depend on a binding already
   existing. Its own module because Integrations.tsx holds an exception granted
   for the Relay setup wizard sharing that surface, and this is not that — it is
   a separate authority with its own refusal vocabulary, its own step-up
   material, and no shared state with the rest of the page beyond the API URL
   and the repository list it is handed. */

type GitHubAppPosture = {
  app_slug: string;
  app_url: string;
  install_url: string;
  api_base_url: string;
  release_enabled: boolean;
  investigate_only_operations: string[];
  write_operations: string[];
};

type GitHubInstallation = {
  installation_id: number;
  account_login: string;
  account_type: string;
  target_type: string;
  repository_selection: string;
  html_url: string;
  suspended: boolean;
};

type GitHubDiscoveredRepository = {
  owner: string;
  name: string;
  default_branch: string;
  private: boolean;
  archived: boolean;
  html_url: string;
};

type GitHubConnectAllResult = {
  installation_id: number;
  account_login: string;
  bound: number;
  already_bound: number;
  skipped: number;
};

type GitHubBindingResult = {
  repository_id: string;
  installation_id: number;
  owner: string;
  name: string;
  default_branch: string;
  classification: string;
  policy_hash: string;
  allowed_operations: string[];
  investigate_only: boolean;
  status: string;
};

// The API answers with a closed reason code and no external text, so the
// sentence an operator reads is written here rather than assembled from a
// GitHub response body. An unrecognized code is reported as itself: inventing
// a friendlier sentence for a refusal this console does not understand would
// be worse than showing the code.
const githubRefusalCopy: Record<string, string> = {
  GITHUB_APP_NOT_CONFIGURED: "This deployment has no GitHub App configured. An operator must provision the App slug, App ID secret, private key secret, and webhook secret reference before anything can be connected here.",
  GITHUB_APP_UNREACHABLE: "Solvan could not read GitHub as the App. The App credentials in Secret Manager, or GitHub itself, are unavailable — nothing was recorded.",
  GITHUB_INSTALLATION_NOT_FOUND: "GitHub does not list that installation for this App. Install the App on the account you want, then discover installations again.",
  GITHUB_INSTALLATION_SUSPENDED: "That installation is suspended on GitHub. Unsuspend it there before binding a repository.",
  GITHUB_REPOSITORY_NOT_REACHABLE: "That installation cannot reach the repository, so a binding to it would name something Solvan cannot open. Grant the App access on GitHub, then discover repositories again.",
  GITHUB_REPOSITORY_ARCHIVED: "The repository is archived, so it cannot be granted authority to open, close, or merge pull requests. It can still be bound investigate-only.",
  GITHUB_RELEASE_POSTURE_DISABLED: "This deployment's release posture is off, so no binding may be granted pull-request authority. Record it investigate-only, or enable the release posture first.",
  GITHUB_OPERATIONS_INVALID: "Choose at least one operation, and do not repeat one.",
  GITHUB_BINDING_EXISTS: "A binding already exists for that repository in this scope. Bindings are immutable; supersede the existing one rather than re-recording it.",
  GITHUB_BINDING_REFUSED: "The binding contract refused these values. A RESTRICTED repository cannot receive merge authority.",
  GITHUB_ADMINISTRATOR_REQUIRED: "A verified administrator identity is required to connect GitHub.",
};

type GitHubAuthorityChoice = { key: string; label: string; detail: string; operations: string[]; writes: boolean };

// Taking part in a thread is granted separately from code authority, because
// they are different powers over the same repository: a binding that may
// comment cannot open a branch, and one that may merge has no voice in a
// thread. Folding conversation into the code ladder would grant it silently to
// anyone who wanted merge (specification 24 §1).
const githubConversationOperations = ["CREATE_ISSUE", "POST_ISSUE_COMMENT", "SUBMIT_PULL_REQUEST_REVIEW"];

// Investigate-only is first and selected by default, and it is the only choice
// that is a read boundary rather than a grant. The others state what they add
// in the same sentence that names them, so the operator is never granting
// merge authority as a side effect of picking a familiar-sounding option.
const githubAuthorityChoices: GitHubAuthorityChoice[] = [
  { key: "INVESTIGATE_ONLY", label: "Investigate only", detail: "Solvan reads pull-request state to reconcile what already exists. It cannot open, close, or merge anything.", operations: ["SYNC_PULL_REQUEST"], writes: false },
  { key: "PROPOSE", label: "Propose pull requests", detail: "Adds opening a draft pull request on a branch CI already published, and closing one Solvan opened. Merging stays out.", operations: ["CREATE_PULL_REQUEST", "SYNC_PULL_REQUEST", "CLOSE_PULL_REQUEST"], writes: true },
  { key: "PROPOSE_AND_MERGE", label: "Propose and merge pull requests", detail: "Adds merge authority. Every merge still passes approval, verification, and the release provider; this only decides whether it is permitted at all.", operations: ["CREATE_PULL_REQUEST", "SYNC_PULL_REQUEST", "MERGE_PULL_REQUEST", "CLOSE_PULL_REQUEST"], writes: true },
];


/** A failed onboarding read, carrying enough to tell the situations apart. */
class GitHubReadError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message);
  }
}

/** Connect the GitHub App in one step, and widen a binding only when asked.
 *
 *  The shape follows the stakes. Connecting so Solvan can investigate grants
 *  exactly `SYNC_PULL_REQUEST`, which changes nothing on GitHub, so there is
 *  nothing to decide per repository and this form asks nothing: install the
 *  App, press connect, done. Authorship, merge, and a voice in a thread are
 *  per-repository judgements an App installation cannot express, so they are
 *  asked for one repository at a time, behind a re-authentication bound to the
 *  exact authority being granted.
 *
 *  There is no identity token field. Every call here carries the signed-in
 *  session and, for the two that grant something, a single-use challenge.
 */
export function GitHubConnectFlow({ apiUrl, repositories, onChanged }: {
  apiUrl: string;
  repositories: ConsoleSnapshot["integration"]["github"]["repositories"];
  onChanged: () => void;
}): React.JSX.Element {
  const [posture, setPosture] = useState<GitHubAppPosture | null>(null);
  const [installations, setInstallations] = useState<GitHubInstallation[] | null>(null);
  const [connected, setConnected] = useState<GitHubConnectAllResult | null>(null);
  const [widening, setWidening] = useState<string | null>(null);
  const [authority, setAuthority] = useState("INVESTIGATE_ONLY");
  const [conversation, setConversation] = useState(false);
  const [classification, setClassification] = useState("INTERNAL");
  const [stepUpRequest, setStepUpRequest] = useState<StepUpStart | null>(null);
  const [pending, setPending] = useState<((challenge: string) => Promise<void>) | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [blocked, setBlocked] = useState<"UNCONFIGURED" | "NO_OPERATOR" | null>(null);
  // Set by the redirect the API lands the operator on after GitHub. Read once
  // and cleared from the URL, so a reload does not re-announce a stale result.
  const [landed] = useState(() => {
    const query = new URLSearchParams(window.location.search);
    const outcome = query.get("github_install");
    if (!outcome) return null;
    const result = {
      outcome,
      account: query.get("account") ?? "",
      bound: query.get("bound") ?? "0",
      alreadyBound: query.get("already_bound") ?? "0",
      reason: query.get("reason") ?? "",
    };
    const url = new URL(window.location.href);
    ["github_install", "account", "bound", "already_bound", "reason"].forEach((key) => url.searchParams.delete(key));
    window.history.replaceState({}, "", url);
    return result;
  });
  const [busy, setBusy] = useState(false);

  const selectedChoice = githubAuthorityChoices.find((choice) => choice.key === authority) ?? githubAuthorityChoices[0];
  const target = repositories.find((item) => item.id === widening) ?? null;
  const operations = conversation
    ? [...selectedChoice.operations, ...githubConversationOperations]
    : selectedChoice.operations;

  function refusal(code: string | undefined, status: number): Error {
    if (code && githubRefusalCopy[code]) return new Error(githubRefusalCopy[code]);
    return new Error(code ? `GitHub onboarding refused: ${code}` : `GitHub onboarding refused (${status}).`);
  }

  async function read<T>(path: string): Promise<T> {
    const response = await fetch(`${apiUrl}${path}`, { credentials: "include" });
    const value = (await response.json().catch(() => null)) as { detail?: string } | null;
    if (!response.ok) throw new GitHubReadError(refusal(value?.detail, response.status).message, response.status, value?.detail);
    return value as T;
  }

  // Discovery runs on its own: it grants nothing, and pressing a button to see
  // what is already installed was work the operator should never have had.
  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const app = await read<GitHubAppPosture>("/api/v1/github/app");
        if (!live) return;
        setPosture(app);
        const found = await read<GitHubInstallation[]>("/api/v1/github/installations");
        if (live) setInstallations(found);
      } catch (reason) {
        if (!live) return;
        // A deployment with no App and an operator with no session are
        // different situations with different next steps, and neither is a
        // GitHub failure. Reporting the raw refusal for all three told an
        // operator nothing about which one they were in.
        const status = reason instanceof GitHubReadError ? reason.status : 0;
        const code = reason instanceof GitHubReadError ? reason.code : undefined;
        if (code === "GITHUB_APP_NOT_CONFIGURED" || status === 404) setBlocked("UNCONFIGURED");
        else if (status === 401 || status === 403 || status === 503) setBlocked("NO_OPERATOR");
        else setNotice(reason instanceof Error ? reason.message : "GitHub discovery failed.");
      }
    })();
    return () => { live = false; };
  }, [apiUrl]);

  /** Re-authenticate for this exact grant, then come back and perform it. */
  async function stepUp(material: string, perform: (challenge: string) => Promise<void>): Promise<void> {
    setBusy(true); setNotice(null);
    try {
      const started = await requestStepUp(apiUrl, "github.bind", await digest(material));
      setPending(() => perform);
      setStepUpRequest(started);
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : "This grant could not be prepared.");
    } finally { setBusy(false); }
  }

  async function post<T>(path: string, challenge: string, body: unknown): Promise<T> {
    const response = await fetch(`${apiUrl}${path}`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID(), ...challengeHeaders(challenge) },
      body: JSON.stringify(body),
    });
    const value = (await response.json().catch(() => null)) as { detail?: string } | null;
    if (!response.ok) throw refusal(value?.detail, response.status);
    return value as T;
  }

  /** Begin an install: re-authenticate, then hand the operator to GitHub.
   *
   *  This is the flow for an account that has not installed the App yet.
   *  GitHub redirects back to the API, which binds everything the new
   *  installation reaches and lands the operator here with the result, so
   *  connecting is one continuous action rather than "go do something on
   *  GitHub and come back knowing to press a button".
   */
  function beginInstall(): void {
    const material = `github-install:v1:${bulkClassification}:SYNC_PULL_REQUEST`;
    void stepUp(material, async (challenge) => {
      const started = await post<{ install_url: string }>(
        "/api/v1/github/installations:begin", challenge,
        { schema_version: 1, classification: bulkClassification },
      );
      window.location.assign(started.install_url);
    });
  }

  function connectAll(installation: GitHubInstallation): void {
    // Must match apps/api/github_binding_material.connect_all_material byte
    // for byte; a drift here refuses every connect with "the material changed".
    const material = `github-connect-all:v1:${installation.installation_id}:${classification}:SYNC_PULL_REQUEST`;
    void stepUp(material, async (challenge) => {
      const result = await post<GitHubConnectAllResult>(
        `/api/v1/github/installations/${installation.installation_id}:connect-all`,
        challenge,
        { schema_version: 1, installation_id: installation.installation_id, classification },
      );
      setConnected(result);
      onChanged();
    });
  }

  function applyAuthority(): void {
    if (!target) return;
    const sorted = [...operations].sort();
    // Must match apps/api/github_binding_material.regrant_material.
    const material = `github-regrant:v1:${target.id}:${classification}:${sorted.join(",")}`;
    void stepUp(material, async (challenge) => {
      await post(`/api/v1/github/repositories/${target.id}/authority`, challenge, {
        schema_version: 1, allowed_operations: sorted, classification,
      });
      setWidening(null);
      onChanged();
    });
  }

  const bulkClassification = classification === "RESTRICTED" ? "CONFIDENTIAL" : classification;
  return <details className="card connection-card" aria-label="Connect the GitHub App" open>
    <summary><strong>Connect repositories</strong><span className="cell-detail">Install the App on GitHub, then connect everything it reaches</span></summary>
    <p className="section-note">Connecting grants investigate-only authority: Solvan reads pull-request state to reconcile what already exists and cannot open, close, merge, or comment on anything. Opening pull requests, merging, or replying in a thread is granted per repository below, because an App installation grants reach and cannot express any of those. The App private key and webhook secret stay in Secret Manager; nothing here asks for a credential.</p>

    {landed && <p className="inline-notice" role="status">
      {landed.outcome === "CONNECTED"
        ? `Connected ${landed.bound} repositor${landed.bound === "1" ? "y" : "ies"} from ${landed.account}${landed.alreadyBound !== "0" ? `; ${landed.alreadyBound} were already bound and were left as they are` : ""}. Each stays PENDING until the release provider observes it.`
        : `That install link could not be completed (${landed.reason}). Start again from this page.`}
    </p>}

    {/* Always rendered, disabled when it cannot be used.
        Two earlier shapes were both wrong. Showing it only when nothing was
        installed meant an operator adding a second account could not reach the
        flow at all. Hiding it until the App loaded meant the feature looked
        absent when it was merely unavailable — and "this product cannot do
        that" and "I am not signed in yet" are things an operator has to be
        able to tell apart without reading the source. */}
    <div className="settings-actions">
      <button
        className="primary-button"
        type="button"
        disabled={busy || !posture}
        onClick={() => beginInstall()}
      >
        {busy ? "Working…" : installations?.length ? "Install on another account" : "Install on GitHub"}
      </button>
      {!posture && <span className="cell-detail">
        {blocked === "UNCONFIGURED"
          ? "Unavailable until this deployment has a GitHub App configured."
          : "Unavailable until you are signed in as an administrator."}
      </span>}
    </div>

    {blocked === "UNCONFIGURED" && <p className="inline-notice" role="status">
      This deployment has no GitHub App configured, so there is nothing to connect to yet. An administrator provisions the App slug and the Secret Manager references for its identifier, private key, and webhook secret; until then this panel has nothing to show and no repository can be bound.
    </p>}
    {blocked === "NO_OPERATOR" && <p className="inline-notice" role="status">
      Connecting a repository needs a signed-in administrator. This view is running without one — sign in as an operator holding ADMIN in this scope, then reload.
    </p>}

    {posture && installations !== null && installations.length === 0 && <p className="inline-notice" role="status">
      The App is not installed on any account yet. Press <strong>Install on GitHub</strong> above: you will re-authenticate, choose which repositories to grant on GitHub&rsquo;s own screen, and land back here with them connected.
    </p>}

    {installations !== null && installations.length > 0 && <>
      <label className="field-label">Classification for newly connected repositories<select value={bulkClassification} onChange={(event) => setClassification(event.target.value)}>{["PUBLIC", "INTERNAL", "CONFIDENTIAL"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
      <table>
        <caption>Installations GitHub reports for this App</caption>
        <thead><tr><th scope="col">Account</th><th scope="col">Reaches</th><th scope="col">Connect</th></tr></thead>
        <tbody>
          {installations.map((installation) => <tr key={installation.installation_id}>
            <th scope="row"><MonoChip>{installation.account_login}</MonoChip><span className="cell-detail">{installation.target_type.toLowerCase()}</span></th>
            <td className="cell-detail">{installation.repository_selection === "all" ? "every repository on the account" : "selected repositories"}{installation.suspended ? " · suspended" : ""}</td>
            <td><button className="primary-button" type="button" disabled={busy || installation.suspended} onClick={() => connectAll(installation)}>{busy ? "Working…" : "Connect all, investigate only"}</button></td>
          </tr>)}
        </tbody>
      </table>
    </>}

    {connected && <p className="inline-notice" role="status">
      Connected {connected.bound} repositor{connected.bound === 1 ? "y" : "ies"} from {connected.account_login} as investigate-only{connected.already_bound > 0 ? `; ${connected.already_bound} were already bound and were left exactly as they are` : ""}{connected.skipped > 0 ? `; ${connected.skipped} could not be bound` : ""}. Each stays PENDING until the release provider probes GitHub itself.
    </p>}

    {repositories.length > 0 && <>
      <h4>What each connected repository may do</h4>
      <table>
        <thead><tr><th scope="col">Repository</th><th scope="col">Authority</th><th scope="col">State</th><th scope="col">Change</th></tr></thead>
        <tbody>
          {repositories.map((repository) => {
            const writes = repository.allowed_operations_json.some((operation) => operation !== "SYNC_PULL_REQUEST");
            return <tr key={repository.id}>
              <th scope="row"><MonoChip>{repository.owner}/{repository.name}</MonoChip></th>
              <td className="cell-detail">{writes ? repository.allowed_operations_json.join(" · ") : "Investigate only · cannot open pull requests or reply in a thread"}</td>
              <td><StatusBadge label={repository.status.toLowerCase()} tone={repository.status === "ACTIVE" ? "success" : repository.status === "REVOKED" ? "danger" : "warning"} machine={repository.status} /></td>
              <td><button className="secondary-button" type="button" disabled={busy} onClick={() => { setWidening(repository.id); setClassification(repository.classification); setAuthority("INVESTIGATE_ONLY"); setConversation(false); }}>Change what it may do</button></td>
            </tr>;
          })}
        </tbody>
      </table>
    </>}

    {target && <div className="card connection-card" aria-label="Change what one repository may do">
      <h4>{target.owner}/{target.name}</h4>
      <p className="section-note">You are stating the complete authority this repository should carry afterwards, not adding to it. Re-authentication is bound to exactly this set, so a change made after you leave this page cannot reuse it. The binding returns to PENDING and is re-probed, because the probe on record confirmed the authority it had before.</p>
      <div className="form-grid">
        <label className="field-label">Classification<select value={classification} onChange={(event) => { setClassification(event.target.value); if (event.target.value === "RESTRICTED" && authority === "PROPOSE_AND_MERGE") setAuthority("INVESTIGATE_ONLY"); }}>{["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
      </div>
      <fieldset className="operation-choice">
        <legend>Pull-request authority</legend>
        {githubAuthorityChoices.map((choice) => {
          const unavailable = (choice.writes && posture !== null && !posture.release_enabled) || (choice.key === "PROPOSE_AND_MERGE" && classification === "RESTRICTED");
          return <label key={choice.key} className="choice-option">
            <input type="radio" name="github-authority" value={choice.key} checked={authority === choice.key} disabled={unavailable} onChange={() => setAuthority(choice.key)} />
            <span><strong>{choice.label}</strong><span className="cell-detail">{choice.detail}</span>{unavailable && <span className="cell-detail">Unavailable: {choice.key === "PROPOSE_AND_MERGE" && classification === "RESTRICTED" ? "a RESTRICTED repository cannot receive merge authority" : "this deployment's release posture is off"}.</span>}</span>
          </label>;
        })}
      </fieldset>
      <fieldset className="operation-choice">
        <legend>Conversation</legend>
        <label className="choice-option">
          <input type="checkbox" checked={conversation} onChange={(event) => setConversation(event.target.checked)} />
          <span><strong>Answer mentions and reply in threads</strong><span className="cell-detail">Adds opening an issue, commenting on a thread, and submitting a pull-request review. Every reply is rendered from Solvan&rsquo;s pinned template registry and published only after an approver reads the exact words. Solvan cannot submit an approving review at all &mdash; an approval it authored would satisfy its own merge precondition.</span></span>
        </label>
      </fieldset>
      <p className="inline-notice" role="status">Records <MonoChip>{[...operations].sort().join(" · ")}</MonoChip>.</p>
      <div className="settings-actions">
        <button className="primary-button" type="button" disabled={busy} onClick={() => applyAuthority()}>{busy ? "Working…" : "Re-authenticate and apply"}</button>
        <button className="secondary-button" type="button" onClick={() => setWidening(null)}>Cancel</button>
      </div>
    </div>}

    {notice && <p className="inline-notice" role="status">{notice}</p>}
    {stepUpRequest && pending && <StepUpDialog
      apiUrl={apiUrl}
      request={stepUpRequest}
      onVerified={async (challenge) => {
        setStepUpRequest(null);
        setBusy(true);
        try { await pending(challenge); } catch (reason) {
          setNotice(reason instanceof Error ? reason.message : "The grant was not recorded.");
        } finally { setPending(null); setBusy(false); }
      }}
      onCancel={() => { setStepUpRequest(null); setPending(null); }}
    />}
  </details>;
}

