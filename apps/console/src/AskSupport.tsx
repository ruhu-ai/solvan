/** Shared state types and small controls for the Ask rail. */
import { useEffect, useState } from "react";
import type { AskPart, AskResponse, TranscriptMessage } from "./conversation";

/** One question and the answer that replied to it. */
export type Exchange = {
  kind: "exchange";
  key: string;
  question: string;
  userMessageId: string | null;
  userAuthor: string;
  userCreatedAt: string;
  answer: AskResponse | null;
  answerAuthor: string | null;
  answerCreatedAt: string | null;
  error: string | null;
  attachments: TranscriptMessage["attachments"];
};

/** A durable Liaison message that replies to nothing.
 *
 *  A parked steer confirmation is created by the steer route as its own
 *  message with no `in_reply_to_message_id`, and a delta delivered into the
 *  thread has no question either. Keying the transcript purely off replies
 *  silently dropped both: the card existed in the ledger and never on screen.
 */
export type Notice = {
  kind: "notice";
  key: string;
  author: string;
  createdAt: string;
  answer: AskResponse;
};

export type ThreadItem = Exchange | Notice;

/** The ceilings a turn ran under. Supplied by the server, never guessed. */
export type TurnBudget = { model_calls: number; tool_calls: number; tokens: number };
export const UNKNOWN_BUDGET: TurnBudget = { model_calls: 0, tool_calls: 0, tokens: 0 };
export type SteerState = { requestId: string | null; status: string; error: string | null };
export type Subscription = { id: string; anchor_record_type: string | null; anchor_record_id: string | null; cadence: string; status: string };

/** The rail is resizable because the right width depends on the question. A
 *  yes/no about recovery wants a narrow companion; reading a causal chain beside
 *  the record wants half the screen. The bounds keep it useful at both ends:
 *  below the minimum the prose stops being readable, and above the maximum the
 *  record it is meant to sit beside is no longer visible, which defeats a
 *  non-modal rail. */
export const RAIL_MIN_WIDTH = 380;
export const RAIL_MAX_WIDTH = 880;
export const RAIL_DEFAULT_WIDTH = 520;
const RAIL_WIDTH_KEY = "solvan.console.ask-rail-width.v1";

export function clampRailWidth(value: number): number {
  const ceiling = Math.min(RAIL_MAX_WIDTH, Math.round(window.innerWidth * 0.9));
  return Math.max(RAIL_MIN_WIDTH, Math.min(ceiling, Math.round(value)));
}

export function readRailWidth(): number {
  try {
    const stored = Number(window.localStorage.getItem(RAIL_WIDTH_KEY));
    return Number.isFinite(stored) && stored > 0 ? clampRailWidth(stored) : RAIL_DEFAULT_WIDTH;
  } catch {
    // Storage blocked: a display preference must never break the surface.
    return RAIL_DEFAULT_WIDTH;
  }
}

/** Where the reader's catch-up cursor lives.
 *
 *  "Since you last looked" is only true if something records when they last
 *  looked. The server has always supported it — it returns an opaque cursor and
 *  replaying that cursor yields no deltas — but the client never stored one, so
 *  every open re-read the whole history under a label promising a diff.
 *
 *  Per-device, like the rail width: this is a reading position, not authority,
 *  and the server re-derives visibility from the grant on every request. */
function cursorKey(recordType: string, recordId: string): string {
  return `solvan.console.ask-cursor.v1.${recordType}:${recordId}`;
}

export function readCursor(recordType: string, recordId: string): string | null {
  try {
    return window.localStorage.getItem(cursorKey(recordType, recordId));
  } catch {
    return null;
  }
}

export function storeCursor(recordType: string, recordId: string, cursor: string): void {
  try {
    window.localStorage.setItem(cursorKey(recordType, recordId), cursor);
  } catch {
    /* storage blocked: the brief simply stays all-time for this device */
  }
}

export function storeRailWidth(width: number): void {
  try {
    window.localStorage.setItem(RAIL_WIDTH_KEY, String(width));
  } catch {
    /* per-device convenience only; nothing depends on it persisting */
  }
}

export function draftKey(recordType: string, recordId: string, threadId: string | null): string {
  return `solvan.console.ask-draft.v1.${threadId ?? `${recordType}:${recordId}`}`;
}

export function readDraft(recordType: string, recordId: string, threadId: string | null): string {
  try {
    return window.localStorage.getItem(draftKey(recordType, recordId, threadId)) ?? "";
  } catch {
    return "";
  }
}

export function storeDraft(recordType: string, recordId: string, threadId: string | null, value: string): void {
  try {
    const key = draftKey(recordType, recordId, threadId);
    if (value) window.localStorage.setItem(key, value);
    else window.localStorage.removeItem(key);
  } catch {
    /* A draft is device-local convenience and never workflow authority. */
  }
}

const EMPTY_DEFECTS = {
  suppressed: 0,
  held: 0,
  unresolved_citations: 0,
  unknown_templates: 0,
  provider_degraded: 0,
};

export function absoluteTime(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function relativeTime(value: string, now: number = Date.now()): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  const elapsed = Math.max(0, now - parsed.getTime());
  const seconds = Math.floor(elapsed / 1_000);
  if (seconds < 10) return "now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** A clock the transcript can actually read.
 *
 *  "1m ago" was computed once at render and then left there: a message could
 *  claim to be a minute old for an hour. Relative time is only honest if
 *  something re-renders it.
 */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

/** Whether this item should print a time, given the one before it.
 *
 *  A timestamp on every line is noise in a conversation whose turns arrive
 *  seconds apart. One per exchange, and only when the conversation actually
 *  paused, is the information; the rest is decoration.
 */
export const TIME_GROUPING_MS = 5 * 60 * 1_000;

export function startsNewTimeGroup(previous: string | null, current: string): boolean {
  if (previous === null) return true;
  const before = new Date(previous).getTime();
  const after = new Date(current).getTime();
  if (Number.isNaN(before) || Number.isNaN(after)) return true;
  return after - before >= TIME_GROUPING_MS;
}

function answerOf(
  threadId: string,
  message: TranscriptMessage,
  userMessageId: string,
  budget: TurnBudget,
  suggested: AskResponse["suggested"],
): AskResponse {
  return {
    thread_id: threadId,
    thread_anchor: "",
    state: message.turn_state,
    user_message_id: userMessageId,
    answer_message_id: message.id,
    attempt: message.attempt ?? 1,
    generation: message.generation ?? 1,
    queue_sequence: message.queue_sequence,
    model_calls: message.model_calls,
    tool_calls: message.tool_calls,
    tokens: message.tokens,
    budget,
    parts: message.parts,
    suggested,
    defects: EMPTY_DEFECTS,
  };
}

/** Project a durable transcript into what the rail renders.
 *
 *  Every message in the page appears exactly once, in stream order: a question
 *  with the answer that replied to it, or — for a Liaison message that replies
 *  to nothing, such as a parked steer confirmation — a standalone card.
 */
export function transcriptItems(
  threadId: string,
  messages: TranscriptMessage[],
  options: {
    readerPrincipal: string | null;
    budget: TurnBudget;
    suggestionsByMessage?: Record<string, AskResponse["suggested"]>;
  },
): ThreadItem[] {
  const { readerPrincipal, budget, suggestionsByMessage = {} } = options;
  const replies = new Map<string, TranscriptMessage>();
  for (const message of messages) {
    if (message.role !== "USER" && message.in_reply_to_message_id) {
      replies.set(message.in_reply_to_message_id, message);
    }
  }
  const consumed = new Set([...replies.values()].map((message) => message.id));
  const authorOf = (author: string | null): string =>
    author && author === readerPrincipal ? "You" : (author ?? "Solvan");

  const items: ThreadItem[] = [];
  for (const message of messages) {
    if (message.role === "USER") {
      const answer = replies.get(message.id);
      items.push({
        kind: "exchange",
        key: message.id,
        question: String(message.parts[0]?.payload.sentence ?? "Content withheld"),
        userMessageId: message.id,
        userAuthor: authorOf(message.author),
        userCreatedAt: message.created_at,
        error: null,
        attachments: message.attachments,
        answerAuthor: answer ? authorOf(answer.author) : null,
        answerCreatedAt: answer?.created_at ?? null,
        answer: answer
          ? answerOf(threadId, answer, message.id, budget, suggestionsByMessage[answer.id] ?? [])
          : null,
      });
      continue;
    }
    if (consumed.has(message.id)) continue;
    items.push({
      kind: "notice",
      key: message.id,
      author: authorOf(message.author),
      createdAt: message.created_at,
      answer: answerOf(
        threadId,
        message,
        message.in_reply_to_message_id ?? "",
        budget,
        suggestionsByMessage[message.id] ?? [],
      ),
    });
  }
  return items;
}

export function ClarificationControl({
  apiUrl,
  part,
  identityHeaders,
  onDecided,
}: {
  apiUrl: string;
  part: AskPart;
  identityHeaders: () => Record<string, string>;
  onDecided: () => Promise<void>;
}): React.JSX.Element | null {
  const [answer, setAnswer] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestId = part.payload.request_id;
  if (!requestId) return null;
  const isSteer = part.payload.kind === "STEER_CONFIRMATION";
  const submit = async (accept = true): Promise<void> => {
    if ((!isSteer && !answer.trim()) || saving) return;
    setSaving(true);
    setError(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/parked/${requestId}:answer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
          ...identityHeaders(),
        },
        body: JSON.stringify({
          schema_version: 1,
          accept,
          decided_payload: null,
          answer: isSteer ? null : answer.trim(),
        }),
      });
      if (!response.ok) throw new Error(`Clarification was refused (${response.status})`);
      await onDecided();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Clarification failed");
    } finally {
      setSaving(false);
    }
  };
  if (isSteer) {
    return (
      <div className="ask-steer-actions">
        <button type="button" className="secondary-button" disabled={saving} onClick={() => void submit(false)}>
          Reject
        </button>
        <button type="button" className="primary-button" disabled={saving} onClick={() => void submit(true)}>
          {saving ? "Submitting…" : "Confirm request"}
        </button>
        {error && <p className="ask-error">{error}</p>}
      </div>
    );
  }
  return (
    <div className="ask-clarification">
      <label>
        <span className="visually-hidden">Clarify which earlier point you mean</span>
        <input
          value={answer}
          onChange={(event) => setAnswer(event.target.value)}
          placeholder="For example: first point"
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void submit(true);
            }
          }}
        />
      </label>
      <button type="button" className="secondary-button" disabled={saving || !answer.trim()} onClick={() => void submit(true)}>
        {saving ? "Sending…" : "Continue"}
      </button>
      {error && <p className="ask-error">{error}</p>}
    </div>
  );
}
