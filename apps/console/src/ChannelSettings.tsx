import { useEffect, useState } from "react";
import { StatusBadge } from "./components";
import { formatPreferenceTimestamp } from "./preferences";
import type { SettingsProjection, UserPreferences } from "./types";

type ChannelBinding = {
  id: string;
  channel_kind: "EMAIL" | "SLACK" | "DISCORD" | "MCP";
  channel_identity: string;
  connection_epoch: number;
  classification_ceiling: string;
  status: string;
  enrolled_at: string;
  revoked_at: string | null;
};

type ChannelKind = "EMAIL" | "SLACK" | "DISCORD";

type ChannelProvider = {
  channel_kind: ChannelKind;
  status: "NOT_CONFIGURED" | "AVAILABLE" | "NEEDS_ATTENTION" | "DISABLED";
  safe_reason_code: string;
  next_step_code: string;
  checked_at: string | null;
  expires_at: string | null;
  receipt_ref: string | null;
  deployment_id: string | null;
  service_revision: string | null;
};

type ChannelEnrollment = {
  challenge_id: string;
  channel_kind: ChannelKind;
  status: "REQUESTED" | "DISPATCHED" | "CONSUMED" | "CANCELLED" | "EXPIRED" | "FAILED";
  instruction: string;
  expires_in_seconds: number;
};

const channelNames: Record<ChannelKind, string> = {
  SLACK: "Slack",
  DISCORD: "Discord",
  EMAIL: "Email",
};

function statusTone(value: string): "success" | "warning" | "danger" | "neutral" {
  const normalized = value.toUpperCase();
  if (normalized === "AVAILABLE" || normalized === "CONSUMED") return "success";
  if (normalized === "NOT_CONFIGURED" || normalized === "NEEDS_ATTENTION") return "warning";
  if (normalized === "FAILED" || normalized === "EXPIRED") return "danger";
  return "neutral";
}

function readableCode(value: string): string {
  return value.toLowerCase().replaceAll("_", " ");
}

function displayChannelIdentity(binding: ChannelBinding): string {
  if (binding.channel_kind === "EMAIL") return binding.channel_identity.replace(/^email:/, "");
  return "Verified provider identity";
}

function DetailCard({ title, description, children }: {
  title: string;
  description: string;
  children: React.ReactNode;
}): React.JSX.Element {
  return <section className="card settings-detail-card"><div className="section-heading"><div><h2>{title}</h2><p>{description}</p></div></div>{children}</section>;
}

export function ChannelSettings({ projection, preferences, apiUrl }: {
  projection: SettingsProjection;
  preferences: UserPreferences;
  apiUrl: string;
}): React.JSX.Element {
  const [bindings, setBindings] = useState<ChannelBinding[]>([]);
  const [providers, setProviders] = useState<ChannelProvider[]>([]);
  const [emailAddress, setEmailAddress] = useState("");
  const [token, setToken] = useState("");
  const [enrollment, setEnrollment] = useState<ChannelEnrollment | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const identityHeaders: Record<string, string> = token.trim() ? { "X-Solvan-Approval-Token": token.trim() } : {};

  async function refresh(): Promise<void> {
    try {
      const [bindingsResponse, providersResponse] = await Promise.all([
        fetch(`${apiUrl}/api/v1/channels/bindings`, { headers: identityHeaders }),
        fetch(`${apiUrl}/api/v1/channels/providers`, { headers: identityHeaders }),
      ]);
      if (!bindingsResponse.ok || !providersResponse.ok) throw new Error(`Channel status unavailable (${Math.max(bindingsResponse.status, providersResponse.status)})`);
      const bindingValue = await bindingsResponse.json() as { bindings: ChannelBinding[] };
      const providerValue = await providersResponse.json() as { providers: ChannelProvider[] };
      setBindings(bindingValue.bindings);
      setProviders(providerValue.providers);
      setMessage(null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Channel status unavailable");
    }
  }

  useEffect(() => { void refresh(); }, [token]);

  useEffect(() => {
    if (!enrollment || !["REQUESTED", "DISPATCHED"].includes(enrollment.status)) return undefined;
    const poll = window.setInterval(() => {
      void fetch(`${apiUrl}/api/v1/channels/enrollments/${enrollment.challenge_id}`, { headers: identityHeaders })
        .then(async (response) => {
          if (!response.ok) throw new Error(`Connection status unavailable (${response.status})`);
          return response.json() as Promise<ChannelEnrollment>;
        })
        .then((value) => {
          setEnrollment((current) => current ? { ...current, status: value.status } : current);
          if (value.status === "CONSUMED") {
            setMessage(`${channelNames[value.channel_kind]} is connected.`);
            void refresh();
          }
        })
        .catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Connection status unavailable"));
    }, 2_000);
    return () => window.clearInterval(poll);
  }, [enrollment?.challenge_id, enrollment?.status, token]);

  async function enrollChannel(channelKind: ChannelKind): Promise<void> {
    if (channelKind === "EMAIL" && !/^[^\s@]+@[^\s@]+$/.test(emailAddress.trim())) {
      setMessage("Enter the email address you want Solvan to verify.");
      return;
    }
    setPending(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/channels/enrollments`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID(), ...identityHeaders },
        body: JSON.stringify({ schema_version: 1, channel_kind: channelKind, ...(channelKind === "EMAIL" ? { email_address: emailAddress.trim() } : {}) }),
      });
      if (!response.ok) throw new Error(`Enrollment could not start (${response.status})`);
      setEnrollment(await response.json() as ChannelEnrollment);
      setMessage("Verification started. Solvan stores only a digest of the one-time proof.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Enrollment could not start");
    } finally {
      setPending(false);
    }
  }

  async function cancelEnrollment(): Promise<void> {
    if (!enrollment) return;
    setPending(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/channels/enrollments/${enrollment.challenge_id}`, {
        method: "DELETE",
        headers: { "Idempotency-Key": crypto.randomUUID(), ...identityHeaders },
      });
      if (!response.ok) throw new Error(`Enrollment could not be cancelled (${response.status})`);
      setEnrollment({ ...enrollment, status: "CANCELLED" });
      setMessage("The pending verification was cancelled.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Enrollment could not be cancelled");
    } finally {
      setPending(false);
    }
  }

  async function revoke(bindingId: string): Promise<void> {
    setPending(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/channels/bindings/${bindingId}`, {
        method: "DELETE",
        headers: { "Idempotency-Key": crypto.randomUUID(), ...identityHeaders },
      });
      if (!response.ok) throw new Error(`Channel could not be disconnected (${response.status})`);
      setMessage("Channel revoked. Queued deliveries and subscriptions were fenced.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Channel could not be disconnected");
    } finally {
      setPending(false);
    }
  }

  return <div className="settings-section-stack">
    {projection.operator.state === "AUTHENTICATED" && <DetailCard title="Confirm your Solvan identity" description="Production requests use a short-lived Google identity proof. It is kept only in this browser view and never stored by Solvan.">
      <div className="channel-authentication"><label>One-time Google identity token<input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer …" autoComplete="off" /></label></div>
    </DetailCard>}
    <DetailCard title="Conversation channels" description="Connect your own identity to an administrator-installed provider. Slack and Discord identity comes only from the provider's signed event; you never paste internal IDs or provider tokens here.">
      <div className="channel-provider-grid">{providers.map((provider) => {
        const connected = bindings.find((binding) => binding.channel_kind === provider.channel_kind && binding.status === "ACTIVE");
        const available = provider.status === "AVAILABLE";
        return <article className="channel-provider-card" key={provider.channel_kind}>
          <div className="channel-provider-heading"><div><strong>{channelNames[provider.channel_kind]}</strong><span>{provider.channel_kind === "EMAIL" ? "Signed relay verification" : "Signed provider event"}</span></div><StatusBadge label={connected ? "CONNECTED" : provider.status.replaceAll("_", " ")} tone={connected ? "success" : statusTone(provider.status)} /></div>
          {connected ? <div className="channel-connected-summary"><span>{displayChannelIdentity(connected)}</span><small>Connected {formatPreferenceTimestamp(connected.enrolled_at, preferences)} · epoch {connected.connection_epoch}</small><button className="secondary-button" disabled={pending} onClick={() => void revoke(connected.id)}>Disconnect</button></div> : <>
            {provider.channel_kind === "EMAIL" && <label className="channel-email-field">Email address<input type="email" value={emailAddress} onChange={(event) => setEmailAddress(event.target.value)} placeholder="you@company.com" autoComplete="email" /></label>}
            <button className="primary-button" type="button" disabled={pending || !available} onClick={() => void enrollChannel(provider.channel_kind)}>{pending ? "Working…" : `Connect ${channelNames[provider.channel_kind]}`}</button>
            {!available && <p className="channel-next-step">{readableCode(provider.next_step_code)}</p>}
          </>}
          <footer><span>{readableCode(provider.safe_reason_code)}</span>{provider.checked_at && <span>Checked {formatPreferenceTimestamp(provider.checked_at, preferences)}</span>}</footer>
        </article>;
      })}</div>
      {providers.length === 0 && <p className="muted channel-empty">Provider status is loading.</p>}
      {enrollment && <div className="channel-instruction" role="status"><div><strong>{channelNames[enrollment.channel_kind]} verification</strong><StatusBadge label={enrollment.status.replaceAll("_", " ")} tone={statusTone(enrollment.status)} /></div><code>{enrollment.instruction}</code><span>The proof expires after ten minutes and can be consumed only once by the authenticated provider path.</span>{["REQUESTED", "DISPATCHED"].includes(enrollment.status) && <button className="secondary-button" disabled={pending} onClick={() => void cancelEnrollment()}>Cancel verification</button>}</div>}
      <div className="settings-actions"><button className="secondary-button" type="button" onClick={() => void refresh()}>Refresh status</button></div>
      {message && <p className="preference-status channel-status-message" role="status">{message}</p>}
    </DetailCard>
    <DetailCard title="Connection guarantees" description="Provider health and personal identity are separate controls; both must pass before a channel can carry a conversation.">
      <div className="governance-control-list">
        <div><span>Provider installation</span><strong>Qualified by an expiring deployed-path receipt</strong></div>
        <div><span>Personal identity</span><strong>Derived from a signed event or private email reply</strong></div>
        <div><span>Disconnect</span><strong>Fences queued deliveries before revocation completes</strong></div>
      </div>
    </DetailCard>
  </div>;
}
