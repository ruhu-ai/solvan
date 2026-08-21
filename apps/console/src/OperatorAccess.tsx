/** Who reaches this environment, and who may be offered it (specification 05 §4.2).
 *
 *  Onboarding is invitation-based. Until this page existed the invitation table
 *  had exactly one writer — the local bootstrap script — so admitting a
 *  colleague to a deployment meant writing SQL against Cloud SQL by hand.
 *
 *  Inviting somebody is `role.grant`, and this is the first surface to spend a
 *  real action challenge: the grant is frozen, the operator proves recent
 *  mailbox possession, and what returns authorizes the exact grant shown rather than
 *  whatever this page holds afterwards.
 */
import { useCallback, useEffect, useState } from "react";
import { Loader2, ShieldCheck, Trash2, UserPlus } from "lucide-react";
import { challengeHeaders, requestStepUp } from "./session";
import type { StepUpStart } from "./session";
import { StepUpDialog } from "./StepUpDialog";

type Member = {
  actor_id: string;
  email: string | null;
  status: string;
  roles: string[];
  last_seen_at: string | null;
};

type Invitation = {
  id: string;
  email: string;
  role: string;
  created_at: string;
  expires_at: string;
};

type Roster = {
  admitted_domains: string[];
  members: Member[];
  invitations: Invitation[];
  notice: string;
};

const ROLES = ["OPERATOR", "APPROVER", "ADMIN"] as const;
type Role = (typeof ROLES)[number];

/** What the challenge authorizes, byte for byte as the API rebuilds it.
 *
 *  A mismatch is not a bug to paper over: it means the grant being submitted is
 *  not the grant whose presence proof was requested, and the API refuses it.
 */
function invitationMaterial(email: string, role: string): string {
  return `invitation:v1:${email.trim().toLowerCase()}:${role}`;
}

async function materialDigest(material: string): Promise<string> {
  const bytes = new TextEncoder().encode(material);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

type PendingIntent = { email: string; role: Role; kind: "invite" | "revoke"; id?: string };

export function OperatorAccess({ apiUrl }: { apiUrl: string }): React.JSX.Element {
  const [roster, setRoster] = useState<Roster | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("OPERATOR");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<PendingIntent | null>(null);
  const [stepUpRequest, setStepUpRequest] = useState<StepUpStart | null>(null);
  const [version, setVersion] = useState(0);

  const reload = useCallback(() => setVersion((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiUrl}/api/admin/operators`, { credentials: "include", signal: controller.signal })
      .then(async (response) => {
        if (response.status === 403) throw new Error("Administering access to this environment requires ADMIN.");
        if (!response.ok) throw new Error(`The roster could not be read (${response.status}).`);
        setRoster(await response.json() as Roster);
        setError(null);
      })
      .catch((cause: unknown) => {
        if (cause instanceof DOMException && cause.name === "AbortError") return;
        setError(cause instanceof Error ? cause.message : "The roster could not be read.");
      });
    return () => controller.abort();
  }, [apiUrl, version]);

  async function completeStepUp(challenge: string): Promise<void> {
    if (!pending) throw new Error("The action being verified is no longer available.");
    const response = pending.kind === "invite"
      ? await fetch(`${apiUrl}/api/admin/operators/invitations`, {
          method: "POST",
          credentials: "include",
          headers: { "content-type": "application/json", ...challengeHeaders(challenge) },
          body: JSON.stringify({ schema_version: 1, email: pending.email, role: pending.role }),
        })
      : await fetch(`${apiUrl}/api/admin/operators/invitations/${pending.id}`, {
          method: "DELETE",
          credentials: "include",
          headers: challengeHeaders(challenge),
        });
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { detail?: string } | null;
      throw new Error(body?.detail ?? `That did not complete (${response.status}).`);
    }
    setNotice(pending.kind === "invite"
      ? `${pending.email} is invited as ${pending.role}. They hold it once they sign in with Google at that address.`
      : "The invitation was withdrawn.");
    setEmail("");
    setPending(null);
    setStepUpRequest(null);
    reload();
  }

  async function stepUp(intent: PendingIntent): Promise<void> {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const started = await requestStepUp(
        apiUrl,
        "role.grant",
        await materialDigest(invitationMaterial(intent.email, intent.role)),
      );
      setPending(intent);
      setStepUpRequest(started);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "This action could not be prepared.");
    } finally {
      setBusy(false);
    }
  }

  if (error && !roster) {
    return <section className="card settings-error" role="alert">
      <h2>Access roster unavailable</h2>
      <p>{error}</p>
      <button className="secondary-button" onClick={reload}>Try again</button>
    </section>;
  }
  if (!roster) {
    return <section className="card settings-loading" aria-busy="true"><span className="spinner" /><p>Loading who has access…</p></section>;
  }

  const domain = email.includes("@") ? email.trim().toLowerCase().split("@")[1] : "";
  const domainAdmitted = domain === "" || roster.admitted_domains.includes(domain);

  return <>
    {stepUpRequest && <StepUpDialog apiUrl={apiUrl} request={stepUpRequest}
      onCancel={() => { setStepUpRequest(null); setPending(null); }}
      onVerified={completeStepUp} />}
    {notice && <p className="inline-notice" role="status">{notice}</p>}
    {error && <p className="inline-notice" role="alert">{error}</p>}

    <section className="card">
      <h3><UserPlus size={17} strokeWidth={1.75} aria-hidden="true" /> Invite someone</h3>
      <p className="muted-copy">{roster.notice}</p>
      <form className="access-invite" onSubmit={(event) => { event.preventDefault(); void stepUp({ email: email.trim().toLowerCase(), role, kind: "invite" }); }}>
        <label htmlFor="invite-email">Work email</label>
        <input id="invite-email" type="email" value={email} required disabled={busy}
          placeholder={roster.admitted_domains.length > 0 ? `someone@${roster.admitted_domains[0]}` : "someone@example.com"}
          onChange={(event) => setEmail(event.target.value)} />
        <label htmlFor="invite-role">Role</label>
        <select id="invite-role" value={role} disabled={busy} onChange={(event) => setRole(event.target.value as Role)}>
          {ROLES.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
        <button className="primary-button" type="submit" disabled={busy || !email.trim() || !domainAdmitted}>
          {busy ? <Loader2 size={16} className="spin" aria-hidden="true" /> : <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
          <span>{busy ? "Working…" : "Verify and invite"}</span>
        </button>
      </form>
      {/* Said before the request rather than after it fails, because the person
          who meets that refusal otherwise is the invitee, for a mistake made here. */}
      {!domainAdmitted && <p className="inline-notice" role="alert">
        {domain} is not an admitted domain here. This environment admits {roster.admitted_domains.join(", ") || "no domain yet"}.
      </p>}
      <p className="muted-copy">
        Inviting somebody changes who can reach production records, so it verifies your
        recent presence for that one grant. The invitation is what admits them; a verified Google
        account at an admitted domain only makes them eligible.
      </p>
    </section>

    <section className="card">
      <h3>People with access</h3>
      {roster.members.length === 0 ? <p className="muted-copy">Nobody holds access in this environment yet.</p> : <table className="access-table">
        <thead><tr><th>Person</th><th>Roles</th><th>Status</th><th>Last seen</th></tr></thead>
        <tbody>
          {roster.members.map((member) => <tr key={member.actor_id}>
            <td>{member.email ?? <span className="muted-copy">{member.actor_id}</span>}</td>
            <td>{member.roles.join(", ")}</td>
            <td>{member.status}</td>
            <td>{member.last_seen_at ? new Date(member.last_seen_at).toLocaleDateString() : "never"}</td>
          </tr>)}
        </tbody>
      </table>}
    </section>

    <section className="card">
      <h3>Invitations outstanding</h3>
      {roster.invitations.length === 0 ? <p className="muted-copy">No invitation is waiting to be taken up.</p> : <table className="access-table">
        <thead><tr><th>Email</th><th>Role</th><th>Expires</th><th /></tr></thead>
        <tbody>
          {roster.invitations.map((invitation) => <tr key={invitation.id}>
            <td>{invitation.email}</td>
            <td>{invitation.role}</td>
            <td>{new Date(invitation.expires_at).toLocaleDateString()}</td>
            <td><button className="secondary-button" disabled={busy}
              onClick={() => void stepUp({ email: invitation.email, role: invitation.role as Role, kind: "revoke", id: invitation.id })}>
              <Trash2 size={15} strokeWidth={1.75} aria-hidden="true" /><span>Withdraw</span>
            </button></td>
          </tr>)}
        </tbody>
      </table>}
    </section>
  </>;
}
