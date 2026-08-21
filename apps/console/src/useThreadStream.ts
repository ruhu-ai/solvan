/** Subscribe to one thread's committed event stream.
 *
 *  The rail used to poll the finite replay endpoint every 900ms and re-fetch
 *  the whole transcript whenever anything came back. That is a lot of work to
 *  learn nothing, and it made the latency of an answer a property of the poll
 *  interval rather than of the answer.
 *
 *  `EventSource` cannot carry the identity header, and an identity token has
 *  no business in a query string, so the stream is read with `fetch` and a
 *  `ReadableStream` parser. Everything is cursor based: a dropped connection,
 *  a refused stream, or a proxy that buffers SSE all resume from the last
 *  acknowledged `stream_sequence`, and the finite replay endpoint remains the
 *  fallback so the surface degrades to what it did before rather than to
 *  nothing (spec 14 §19.2).
 */
import { useEffect, useRef } from "react";

export type ThreadEvent = {
  sequence: number;
  type: string;
  message_id: string | null;
  payload: Record<string, unknown>;
};

const POLL_INTERVAL_MS = 2_000;
const RECONNECT_DELAY_MS = 1_500;
const REPLAY_PAGE_LIMIT = 256;
/** Matches the server's per-consumer ceiling: drain, then resume from the cursor. */
const MAX_REPLAY_PAGES = 8;

function parseEventBlock(block: string): ThreadEvent | null {
  let type = "message";
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith(":")) continue;
    if (line.startsWith("event:")) type = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).trim());
  }
  if (data.length === 0) return null;
  try {
    const parsed = JSON.parse(data.join("\n")) as {
      sequence?: number;
      message_id?: string | null;
      payload?: Record<string, unknown>;
    };
    if (typeof parsed.sequence !== "number") return null;
    return {
      sequence: parsed.sequence,
      type,
      message_id: parsed.message_id ?? null,
      payload: parsed.payload ?? {},
    };
  } catch {
    return null;
  }
}

export function useThreadStream({
  apiUrl,
  threadId,
  identityHeaders,
  onEvents,
}: {
  apiUrl: string;
  threadId: string | null;
  identityHeaders: () => Record<string, string>;
  onEvents: (events: ThreadEvent[], lastSequence: number) => void | Promise<void>;
}): { cursor: React.RefObject<number> } {
  const cursor = useRef(0);
  // Held in a ref so a re-rendered callback never restarts the connection: the
  // stream's lifetime belongs to the thread, not to the parent's render.
  const sink = useRef(onEvents);
  sink.current = onEvents;
  const headers = useRef(identityHeaders);
  headers.current = identityHeaders;

  useEffect(() => {
    if (!threadId) return;
    cursor.current = 0;
    let stopped = false;
    const controller = new AbortController();

    const deliver = async (events: ThreadEvent[]): Promise<void> => {
      const fresh = events.filter((event) => event.sequence > cursor.current);
      if (fresh.length === 0) return;
      cursor.current = fresh[fresh.length - 1].sequence;
      await sink.current(fresh, cursor.current);
    };

    /** Finite, ordered catch-up. Always runs first, and again after any gap. */
    const replay = async (): Promise<boolean> => {
      for (let page = 0; page < MAX_REPLAY_PAGES && !stopped; page += 1) {
        const query = new URLSearchParams({
          after_sequence: String(cursor.current),
          limit: String(REPLAY_PAGE_LIMIT),
        });
        const response = await fetch(`${apiUrl}/api/v1/threads/${threadId}/events?${query}`, {
          headers: headers.current(),
          signal: controller.signal,
        });
        if (!response.ok) return false;
        const body = (await response.json()) as {
          events: ThreadEvent[];
          last_sequence: number;
          has_more: boolean;
        };
        await deliver(body.events);
        if (!body.has_more || body.events.length === 0) return true;
      }
      return true;
    };

    const stream = async (): Promise<void> => {
      const query = new URLSearchParams({
        thread_id: threadId,
        after_sequence: String(cursor.current),
      });
      const response = await fetch(`${apiUrl}/api/v1/liaison/events?${query}`, {
        headers: { accept: "text/event-stream", ...headers.current() },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) throw new Error(`stream refused (${response.status})`);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!stopped) {
        const { done, value } = await reader.read();
        if (done) return;
        buffer += decoder.decode(value, { stream: true });
        const blocks = buffer.split("\n\n");
        buffer = blocks.pop() ?? "";
        const events: ThreadEvent[] = [];
        for (const block of blocks) {
          if (block.startsWith("event: error")) {
            // The server fenced us for falling too far behind. Cursor state is
            // still valid, so replay fills the gap rather than clearing state.
            throw new Error("event buffer overflow");
          }
          const event = parseEventBlock(block);
          if (event) events.push(event);
        }
        await deliver(events);
      }
    };

    /** Fallback for a proxy or runtime that will not stream. */
    const poll = async (): Promise<void> => {
      while (!stopped) {
        await replay();
        await new Promise((resolve) => window.setTimeout(resolve, POLL_INTERVAL_MS));
      }
    };

    void (async () => {
      let streamable = true;
      while (!stopped) {
        try {
          await replay();
          if (!streamable) {
            await poll();
            return;
          }
          await stream();
        } catch (error) {
          if (stopped || controller.signal.aborted) return;
          // One failure is a dropped connection; a refusal means this
          // deployment cannot stream, and polling takes over for good.
          streamable = !(error instanceof Error && error.message.startsWith("stream refused"));
        }
        if (stopped) return;
        await new Promise((resolve) => window.setTimeout(resolve, RECONNECT_DELAY_MS));
      }
    })();

    return () => {
      stopped = true;
      controller.abort();
    };
  }, [apiUrl, threadId]);

  return { cursor };
}
