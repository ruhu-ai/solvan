import React, { useCallback, useEffect, useState } from "react";
import { MonoChip, StatusBadge } from "./components";
import type { StatusTone } from "./types";

/**
 * The GitHub conversation surface: who may address Solvan on a repository, and
 * what Solvan proposes to say back.
 *
 * The publication list deliberately renders the full body rather than a
 * summary or a digest. An operator approving a comment is approving the exact
 * words that will appear in a public thread under Solvan's identity, and a
 * review UI that shows a shortened version of what it publishes is a UI that
 * collects approvals for something nobody read. Specification 24 §5.
 */

type Participant = {
  id: string;
  login: string;
  account_node_id: string;
  admission: "ADMITTED" | "PARKED" | "DISMISSED";
  admitted_by_principal: string | null;
  admitted_at: string | null;
  first_seen_at: string;
};

type ConversationAction = {
  id: string;
  repository_id: string;
  thread_id: string | null;
  operation: string;
  review_event: string | null;
  title: string | null;
  body: string;
  body_hash: string;
  template_registry_digest: string;
  template_ids_json: string[];
  state: string;
  external_url: string | null;
  error_class: string | null;
  decided_by_principal: string | null;
  expires_at: string;
  created_at: string;
};

type PublicationView = {
  action_id: string;
  operation: string;
  review_event: string | null;
  title: string | null;
  body: string;
  body_hash: string;
  template_registry_digest: string;
  template_ids: string[];
  state: string;
  decision_digest: string;
  required_role: string;
  external_url: string | null;
  expires_at: string;
};

const operationLabel: Record<string, string> = {
  CREATE_ISSUE: "Open an issue",
  POST_ISSUE_COMMENT: "Comment on a thread",
  SUBMIT_PULL_REQUEST_REVIEW: "Submit a pull-request review",
};

const stateTone: Record<string, StatusTone> = {
  APPROVAL_PENDING: "warning",
  APPROVED: "success",
  PUBLISHED: "success",
  REJECTED: "neutral",
  REFUSED: "danger",
  EXPIRED: "neutral",
  DISPATCHED: "info",
};

const admissionTone: Record<Participant["admission"], StatusTone> = {
  ADMITTED: "success",
  PARKED: "warning",
  DISMISSED: "neutral",
};

export function GitHubConversationPanel({
  apiUrl,
  repositoryId,
}: {
  apiUrl: string;
  repositoryId: string | null;
}): React.JSX.Element {
  const [token, setToken] = useState("");
  const [participants, setParticipants] = useState<Participant[] | null>(null);
  const [actions, setActions] = useState<ConversationAction[] | null>(null);
  const [selected, setSelected] = useState<PublicationView | null>(null);
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const authorized = token.trim().length > 0;

  const read = useCallback(
    async function read<T>(path: string): Promise<T> {
      const response = await fetch(`${apiUrl}${path}`, {
        headers: { "X-Solvan-Approval-Token": token.trim() },
      });
      const value = (await response.json().catch(() => null)) as
        | (T & { detail?: string })
        | null;
      if (!response.ok || value === null) {
        throw new Error(value?.detail ?? `Request failed (HTTP ${response.status}).`);
      }
      return value;
    },
    [apiUrl, token],
  );

  const refresh = useCallback(async (): Promise<void> => {
    if (!authorized || !repositoryId) return;
    setBusy(true);
    setNotice(null);
    try {
      const [people, pending] = await Promise.all([
        read<{ participants: Participant[] }>(
          `/api/v1/github/conversation/repositories/${encodeURIComponent(repositoryId)}/participants`,
        ),
        read<{ actions: ConversationAction[] }>(
          `/api/v1/github/conversation/actions?repository_id=${encodeURIComponent(repositoryId)}`,
        ),
      ]);
      setParticipants(people.participants);
      setActions(pending.actions);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not load the conversation surface.");
    } finally {
      setBusy(false);
    }
  }, [authorized, read, repositoryId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function decideParticipant(
    login: string,
    admission: "ADMITTED" | "DISMISSED",
  ): Promise<void> {
    if (!repositoryId) return;
    setBusy(true);
    setNotice(null);
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/github/conversation/repositories/${encodeURIComponent(repositoryId)}/participants`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Solvan-Approval-Token": token.trim(),
          },
          body: JSON.stringify({ schema_version: 1, login, admission }),
        },
      );
      if (!response.ok) {
        const value = (await response.json().catch(() => null)) as { detail?: string } | null;
        throw new Error(value?.detail ?? `Request failed (HTTP ${response.status}).`);
      }
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The admission was not recorded.");
      setBusy(false);
    }
  }

  async function openAction(actionId: string): Promise<void> {
    setBusy(true);
    setNotice(null);
    try {
      setSelected(
        await read<PublicationView>(
          `/api/v1/github/conversation/actions/${encodeURIComponent(actionId)}`,
        ),
      );
      setReason("");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not read the publication.");
    } finally {
      setBusy(false);
    }
  }

  async function decidePublication(approved: boolean): Promise<void> {
    if (!selected) return;
    setBusy(true);
    setNotice(null);
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/github/conversation/actions/${encodeURIComponent(selected.action_id)}/decision`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Solvan-Approval-Token": token.trim(),
          },
          body: JSON.stringify({
            schema_version: 1,
            // The digest the server computed from the body shown above. It is
            // echoed rather than recomputed here so a browser cannot approve
            // words it rendered differently from what the server stored.
            decision_digest: selected.decision_digest,
            approved,
            reason: reason.trim(),
          }),
        },
      );
      if (!response.ok) {
        const value = (await response.json().catch(() => null)) as { detail?: string } | null;
        throw new Error(value?.detail ?? `Request failed (HTTP ${response.status}).`);
      }
      setSelected(null);
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The decision was not recorded.");
      setBusy(false);
    }
  }

  if (!repositoryId) {
    return (
      <section className="card" aria-labelledby="github-conversation-heading">
        <h3 id="github-conversation-heading">Repository conversation</h3>
        <p className="section-note">
          Bind a repository first. Solvan takes part in a repository&rsquo;s conversation only
          through a binding that grants it, and every reply still passes an approval here.
        </p>
      </section>
    );
  }

  const parked = (participants ?? []).filter((item) => item.admission === "PARKED");
  const pending = (actions ?? []).filter((item) => item.state === "APPROVAL_PENDING");
  const settled = (actions ?? []).filter((item) => item.state !== "APPROVAL_PENDING");

  return (
    <section className="card responsive-table" aria-labelledby="github-conversation-heading">
      <h3 id="github-conversation-heading">Repository conversation</h3>
      <p className="section-note">
        Solvan answers a mention or a trigger label only from a login you have admitted here, and
        publishes only sentences its pinned template registry rendered. Nothing on this page
        publishes anything by itself: approving a reply queues it for the provider, which re-reads
        the thread and refuses if it moved.
      </p>

      <label className="field-label">
        Approver identity token
        <input
          type="password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          placeholder="Bearer …"
          autoComplete="off"
        />
      </label>
      <div className="settings-actions">
        <button
          className="secondary-button"
          type="button"
          disabled={busy || !authorized}
          onClick={() => void refresh()}
        >
          {busy ? "Working…" : "Refresh"}
        </button>
      </div>

      {notice && (
        <p className="inline-notice" role="status">
          {notice}
        </p>
      )}

      <h4>Who may address Solvan</h4>
      {participants === null ? (
        <p className="section-note">Enter an approver token to load participants.</p>
      ) : participants.length === 0 ? (
        <p className="section-note">
          Nobody has addressed Solvan on this repository yet. Until a login is admitted here, a
          mention is recorded and left parked — it causes no action.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Login</th>
              <th scope="col">Standing</th>
              <th scope="col">Admitted by</th>
              <th scope="col">First seen</th>
              <th scope="col">Decide</th>
            </tr>
          </thead>
          <tbody>
            {participants.map((person) => (
              <tr key={person.id}>
                <th scope="row">
                  <MonoChip>{person.login}</MonoChip>
                </th>
                <td>
                  <StatusBadge
                    label={person.admission.toLowerCase()}
                    tone={admissionTone[person.admission]}
                    machine={person.admission}
                  />
                </td>
                <td className="cell-detail">{person.admitted_by_principal ?? "—"}</td>
                <td className="cell-detail">{person.first_seen_at}</td>
                <td>
                  <div className="settings-actions">
                    <button
                      className="secondary-button"
                      type="button"
                      disabled={busy || person.admission === "ADMITTED"}
                      onClick={() => void decideParticipant(person.login, "ADMITTED")}
                    >
                      Admit
                    </button>
                    <button
                      className="secondary-button"
                      type="button"
                      disabled={busy || person.admission === "DISMISSED"}
                      onClick={() => void decideParticipant(person.login, "DISMISSED")}
                    >
                      Dismiss
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {parked.length > 0 && (
        <p className="inline-notice" role="status">
          {parked.length} sender{parked.length === 1 ? "" : "s"} asked Solvan for something and
          {parked.length === 1 ? " has" : " have"} no standing on this repository. Nothing was done
          for them.
        </p>
      )}

      <h4>Replies awaiting your decision</h4>
      {pending.length === 0 ? (
        <p className="section-note">Nothing is waiting to be published.</p>
      ) : (
        <ul>
          {pending.map((action) => (
            <li key={action.id}>
              <button
                className="secondary-button"
                type="button"
                disabled={busy}
                onClick={() => void openAction(action.id)}
              >
                {operationLabel[action.operation] ?? action.operation}
                {action.review_event ? ` · ${action.review_event.toLowerCase()}` : ""}
              </button>
              <span className="cell-detail"> expires {action.expires_at}</span>
            </li>
          ))}
        </ul>
      )}

      {selected && (
        <div className="card connection-card" aria-label="Review a proposed publication">
          <h4>{operationLabel[selected.operation] ?? selected.operation}</h4>
          {selected.title && (
            <p>
              <strong>Title:</strong> {selected.title}
            </p>
          )}
          {selected.review_event && (
            <p className="section-note">
              This review is submitted as <strong>{selected.review_event.toLowerCase()}</strong>.
              Solvan cannot submit an approving review at all — an approval it authored would
              satisfy its own merge precondition.
            </p>
          )}
          <p className="section-note">
            These are the exact words that will be published, rendered from template
            {selected.template_ids.length === 1 ? " " : "s "}
            {selected.template_ids.join(", ")}.
          </p>
          <pre className="skill-content-source">{selected.body}</pre>
          <dl className="skill-detail-facts">
            <dt>Body digest</dt>
            <dd>
              <MonoChip>{selected.body_hash}</MonoChip>
            </dd>
            <dt>Template registry</dt>
            <dd>
              <MonoChip>{selected.template_registry_digest}</MonoChip>
            </dd>
            <dt>Required role</dt>
            <dd>{selected.required_role}</dd>
          </dl>
          <label className="field-label">
            Reason for your decision
            <textarea
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={3}
              placeholder="Why this may or may not be published"
            />
          </label>
          <div className="settings-actions">
            <button
              className="primary-button"
              type="button"
              disabled={busy || reason.trim().length < 8}
              onClick={() => void decidePublication(true)}
            >
              Approve publication
            </button>
            <button
              className="secondary-button"
              type="button"
              disabled={busy || reason.trim().length < 8}
              onClick={() => void decidePublication(false)}
            >
              Reject
            </button>
            <button className="secondary-button" type="button" onClick={() => setSelected(null)}>
              Close
            </button>
          </div>
        </div>
      )}

      {settled.length > 0 && (
        <>
          <h4>Recently decided</h4>
          <table>
            <thead>
              <tr>
                <th scope="col">Action</th>
                <th scope="col">State</th>
                <th scope="col">Decided by</th>
                <th scope="col">Published</th>
              </tr>
            </thead>
            <tbody>
              {settled.slice(0, 20).map((action) => (
                <tr key={action.id}>
                  <th scope="row">{operationLabel[action.operation] ?? action.operation}</th>
                  <td>
                    <StatusBadge
                      label={action.state.replace(/_/g, " ").toLowerCase()}
                      tone={stateTone[action.state] ?? "neutral"}
                      machine={action.state}
                    />
                  </td>
                  <td className="cell-detail">{action.decided_by_principal ?? "—"}</td>
                  <td className="cell-detail">
                    {action.external_url ? (
                      <a href={action.external_url} target="_blank" rel="noreferrer">
                        view
                      </a>
                    ) : (
                      (action.error_class ?? "—")
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
