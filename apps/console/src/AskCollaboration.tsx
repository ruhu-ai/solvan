/** Owner-governed collaboration controls for one durable conversation. */
import { useCallback, useEffect, useState } from "react";
import { UserPlus, Users, X } from "lucide-react";

export type ThreadParticipant = { principal: string; role: "OWNER" | "PARTICIPANT" };
type AccessRequest = {
  request_id: string;
  requested_principal: string;
  requested_by_principal: string;
  expires_at: string;
};

export function useThreadCollaboration({
  apiUrl,
  threadId,
  identityHeaders,
}: {
  apiUrl: string;
  threadId: string | null;
  identityHeaders: () => Record<string, string>;
}): {
  participants: ThreadParticipant[];
  requests: AccessRequest[];
  refresh: () => Promise<void>;
} {
  const [participants, setParticipants] = useState<ThreadParticipant[]>([]);
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const refresh = useCallback(async (): Promise<void> => {
    if (!threadId) {
      setParticipants([]);
      setRequests([]);
      return;
    }
    const participantResponse = await fetch(`${apiUrl}/api/v1/threads/${threadId}/participants`, {
      headers: identityHeaders(),
    });
    if (participantResponse.ok) {
      const body = await participantResponse.json() as { participants: ThreadParticipant[] };
      setParticipants(body.participants);
    }
    const requestResponse = await fetch(`${apiUrl}/api/v1/threads/${threadId}/access-requests`, {
      headers: identityHeaders(),
    });
    if (requestResponse.ok) {
      const body = await requestResponse.json() as { requests: AccessRequest[] };
      setRequests(body.requests);
    } else {
      // Non-owners are allowed to collaborate; they simply cannot enumerate
      // pending invitations addressed to an owner.
      setRequests([]);
    }
  }, [apiUrl, identityHeaders, threadId]);
  useEffect(() => { void refresh(); }, [refresh]);
  return { participants, requests, refresh };
}

export function PeoplePanel({
  apiUrl,
  threadId,
  identityHeaders,
  participants,
  requests,
  onChanged,
  onClose,
}: {
  apiUrl: string;
  threadId: string;
  identityHeaders: () => Record<string, string>;
  participants: ThreadParticipant[];
  requests: AccessRequest[];
  onChanged: () => Promise<void>;
  onClose: () => void;
}): React.JSX.Element {
  const [principal, setPrincipal] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const write = async (path: string, method: "POST" | "DELETE", body: unknown): Promise<boolean> => {
    setSaving(true);
    setError(null);
    try {
      const response = await fetch(`${apiUrl}${path}`, {
        method,
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
          ...identityHeaders(),
        },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`The membership change was refused (${response.status})`);
      await onChanged();
      return true;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The membership change failed");
      return false;
    } finally {
      setSaving(false);
    }
  };
  const add = async (): Promise<void> => {
    const selected = principal.trim();
    if (!selected) return;
    if (await write(`/api/v1/threads/${threadId}/participants`, "POST", {
      schema_version: 1,
      principal: selected,
      role: "PARTICIPANT",
    })) setPrincipal("");
  };
  const decide = async (requestId: string, approve: boolean): Promise<void> => {
    await write(`/api/v1/threads/${threadId}/access-requests/${requestId}:decide`, "POST", {
      schema_version: 1,
      approve,
    });
  };
  return (
    <section className="ask-people-panel" aria-label="Conversation participants">
      <header><div><p className="eyebrow">Conversation access</p><h3>People</h3></div><button type="button" className="icon-button" onClick={onClose} aria-label="Close people panel"><X size={16} /></button></header>
      <ul>
        {participants.map((item) => (
          <li key={item.principal}>
            <span><strong>{item.principal}</strong><small>{item.role.toLowerCase()}</small></span>
            {item.role !== "OWNER" && <button type="button" className="link-button" disabled={saving} onClick={() => void write(`/api/v1/threads/${threadId}/participants`, "DELETE", { schema_version: 1, principal: item.principal, role: item.role })}>Remove</button>}
          </li>
        ))}
      </ul>
      <div className="ask-person-add">
        <label><span>Principal</span><input value={principal} onChange={(event) => setPrincipal(event.target.value)} placeholder="teammate@example.com" /></label>
        <button type="button" className="secondary-button" disabled={saving || !principal.trim()} onClick={() => void add()}><UserPlus size={14} /> Add</button>
      </div>
      {requests.length > 0 && <div className="ask-access-requests"><h4>Access requests</h4>{requests.map((item) => <article key={item.request_id}><span><strong>{item.requested_principal}</strong><small>Requested without sharing conversation content</small></span><div><button type="button" className="link-button" onClick={() => void decide(item.request_id, false)}>Deny</button><button type="button" className="secondary-button" onClick={() => void decide(item.request_id, true)}>Admit</button></div></article>)}</div>}
      {error && <p className="ask-error" role="status">{error}</p>}
    </section>
  );
}

export const MENTION_LISTBOX_ID = "ask-mention-listbox";
export const mentionOptionId = (index: number): string => `ask-mention-option-${index}`;

/** What the composer is offering to complete, if anything.
 *
 *  The token deliberately allows an `@` inside it: a half-typed address such
 *  as `@teammate@example.` is exactly when someone needs the invitation
 *  affordance, and the old pattern excluded `@` from the capture, so the
 *  "Request access for …" branch could never be reached at all.
 */
export type MentionOption =
  | { kind: "participant"; principal: string; role: string }
  | { kind: "request"; principal: string };

export function mentionOptions(
  text: string,
  participants: ThreadParticipant[],
): { query: string; options: MentionOption[] } | null {
  const query = text.match(/(?:^|\s)@([^\s]*)$/)?.[1] ?? null;
  if (query === null) return null;
  const normalized = query.toLowerCase();
  const matches = participants
    .filter((item) => item.principal.toLowerCase().includes(normalized))
    .slice(0, 6);
  const options: MentionOption[] = matches.map((item) => ({
    kind: "participant",
    principal: item.principal,
    role: item.role.toLowerCase(),
  }));
  const exact = participants.some((item) => item.principal.toLowerCase() === normalized);
  // Anyone who is not already a participant is an invitation, never a silent
  // grant: the request carries no title, quotation, or incident state (§19.2).
  if (query.length > 0 && !exact) options.push({ kind: "request", principal: query });
  return options.length > 0 ? { query, options } : null;
}

export function MentionSuggestions({
  options,
  active,
  onSelect,
  onRequest,
}: {
  options: MentionOption[];
  active: number;
  onSelect: (principal: string) => void;
  onRequest: (principal: string) => Promise<void>;
}): React.JSX.Element | null {
  if (options.length === 0) return null;
  return (
    <ul
      className="ask-mention-menu"
      id={MENTION_LISTBOX_ID}
      role="listbox"
      aria-label="Mention a conversation participant"
    >
      {options.map((item, index) => (
        <li
          key={`${item.kind}:${item.principal}`}
          id={mentionOptionId(index)}
          role="option"
          aria-selected={index === active}
          className={[
            index === active ? "active" : "",
            item.kind === "request" ? "ask-request-access" : "",
          ].filter(Boolean).join(" ")}
          // The composer keeps focus and owns the keyboard, so these are
          // pointer targets rather than buttons: a button inside an option is
          // not a thing a listbox may contain.
          onMouseDown={(event) => {
            event.preventDefault();
            if (item.kind === "participant") onSelect(item.principal);
            else void onRequest(item.principal);
          }}
        >
          {item.kind === "participant" ? (
            <><Users size={13} aria-hidden="true" /><span>{item.principal}</span><small>{item.role}</small></>
          ) : (
            <><UserPlus size={13} aria-hidden="true" /><span>Request access for {item.principal}</span></>
          )}
        </li>
      ))}
    </ul>
  );
}
