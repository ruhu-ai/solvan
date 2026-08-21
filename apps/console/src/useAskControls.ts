/** Focused controller hooks for the conversational rail's bounded actions. */
import { useCallback, useRef, useState } from "react";
import type {
  Dispatch,
  KeyboardEvent,
  PointerEvent,
  RefObject,
  SetStateAction,
} from "react";
import type { AskPart } from "./conversation";
import type { AskResponse } from "./conversation";
import {
  clampRailWidth,
  readRailWidth,
  storeRailWidth,
  type SteerState,
} from "./AskSupport";

type IdentityHeaders = () => Record<string, string>;

export function useExactTurnActions({
  apiUrl,
  identityHeaders,
  hydrateTranscript,
  onError,
}: {
  apiUrl: string;
  identityHeaders: IdentityHeaders;
  hydrateTranscript: (threadId: string) => Promise<void>;
  onError: (message: string | null) => void;
}): {
  cancelQueued: (answer: AskResponse) => Promise<void>;
  abortRunning: (answer: AskResponse) => Promise<void>;
} {
  const transition = useCallback(async (
    answer: AskResponse,
    operation: "cancel" | "abort",
  ): Promise<void> => {
    onError(null);
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/threads/${answer.thread_id}/turns/${answer.answer_message_id}:${operation}`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "Idempotency-Key": crypto.randomUUID(),
            ...identityHeaders(),
          },
          body: JSON.stringify({
            schema_version: 1,
            attempt: answer.attempt,
            generation: answer.generation,
          }),
        },
      );
      // The endpoints fence on the exact attempt and generation, so a refusal
      // is normal and meaningful: the turn moved on. Swallowing it made Stop
      // and Cancel look like controls that simply do nothing.
      if (!response.ok) {
        throw new Error(response.status === 409
          ? operation === "cancel"
            ? "That answer already started, so it can no longer be cancelled."
            : "That answer already finished."
          : `The request was refused (${response.status})`);
      }
      await hydrateTranscript(answer.thread_id);
    } catch (error) {
      onError(error instanceof Error ? error.message : "The request failed");
    }
  }, [apiUrl, hydrateTranscript, identityHeaders, onError]);
  return {
    cancelQueued: useCallback((answer: AskResponse) => transition(answer, "cancel"), [transition]),
    abortRunning: useCallback((answer: AskResponse) => transition(answer, "abort"), [transition]),
  };
}

export function useSteerActions({
  apiUrl,
  threadId,
  recordType,
  recordId,
  identityHeaders,
}: {
  apiUrl: string;
  threadId: string | null;
  recordType: string;
  recordId: string;
  identityHeaders: IdentityHeaders;
}): {
  steers: Record<string, SteerState>;
  draftSteer: (key: string, part: AskPart) => Promise<void>;
  decideSteer: (key: string, accept: boolean) => Promise<void>;
} {
  const [steers, setSteers] = useState<Record<string, SteerState>>({});
  const draftSteer = useCallback(async (key: string, part: AskPart): Promise<void> => {
    if (!threadId) return;
    setSteers((current) => ({
      ...current,
      [key]: { requestId: null, status: "DRAFTING", error: null },
    }));
    try {
      const response = await fetch(`${apiUrl}/api/v1/liaison/steer:draft`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
          ...identityHeaders(),
        },
        body: JSON.stringify({
          schema_version: 1,
          thread_id: threadId,
          purpose: part.payload.proposed_step ?? "Request one bounded evidence read.",
          anchor_record_type: recordType,
          anchor_record_id: recordId,
          tool_profile: part.payload.tool_profile ?? ["metrics.read"],
        }),
      });
      if (!response.ok) throw new Error(`Steer draft was refused (${response.status})`);
      const body = await response.json() as { parked_request_id: string };
      setSteers((current) => ({
        ...current,
        [key]: { requestId: body.parked_request_id, status: "PENDING", error: null },
      }));
    } catch (error) {
      setSteers((current) => ({
        ...current,
        [key]: {
          requestId: null,
          status: "FAILED",
          error: error instanceof Error ? error.message : "Steer draft failed",
        },
      }));
    }
  }, [apiUrl, identityHeaders, recordId, recordType, threadId]);

  const decideSteer = useCallback(async (key: string, accept: boolean): Promise<void> => {
    const current = steers[key];
    if (!current?.requestId) return;
    setSteers((states) => ({
      ...states,
      [key]: { ...current, status: "DECIDING", error: null },
    }));
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/liaison/parked/${current.requestId}:decide`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "Idempotency-Key": crypto.randomUUID(),
            ...identityHeaders(),
          },
          body: JSON.stringify({ schema_version: 1, accept, decided_payload: null }),
        },
      );
      if (!response.ok) throw new Error(`Steer decision was refused (${response.status})`);
      const body = await response.json() as { outcome: string };
      setSteers((states) => ({
        ...states,
        [key]: { ...current, status: body.outcome, error: null },
      }));
    } catch (error) {
      setSteers((states) => ({
        ...states,
        [key]: {
          ...current,
          status: "FAILED",
          error: error instanceof Error ? error.message : "Steer decision failed",
        },
      }));
    }
  }, [apiUrl, identityHeaders, steers]);
  return { steers, draftSteer, decideSteer };
}

export function useResizableRail(): {
  width: number;
  startDrag: (event: PointerEvent<HTMLDivElement>) => void;
  onDrag: (event: PointerEvent<HTMLDivElement>) => void;
  endDrag: (event: PointerEvent<HTMLDivElement>) => void;
  nudge: (event: KeyboardEvent<HTMLDivElement>) => void;
} {
  const [width, setWidth] = useState(readRailWidth);
  const dragging = useRef(false);
  const startDrag = useCallback((event: PointerEvent<HTMLDivElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    dragging.current = true;
  }, []);
  const onDrag = useCallback((event: PointerEvent<HTMLDivElement>) => {
    if (dragging.current) setWidth(clampRailWidth(window.innerWidth - event.clientX));
  }, []);
  const endDrag = useCallback((event: PointerEvent<HTMLDivElement>) => {
    if (!dragging.current) return;
    dragging.current = false;
    event.currentTarget.releasePointerCapture(event.pointerId);
    storeRailWidth(width);
  }, [width]);
  const nudge = useCallback((event: KeyboardEvent<HTMLDivElement>) => {
    const step = event.shiftKey ? 64 : 16;
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    setWidth((current) => {
      const next = clampRailWidth(current + (event.key === "ArrowLeft" ? step : -step));
      storeRailWidth(next);
      return next;
    });
  }, []);
  return { width, startDrag, onDrag, endDrag, nudge };
}

export function useCollaborationActions({
  apiUrl,
  threadId,
  identityHeaders,
  refresh,
  setQuestion,
  composerRef,
  onError,
}: {
  apiUrl: string;
  threadId: string | null;
  identityHeaders: IdentityHeaders;
  refresh: () => Promise<void>;
  setQuestion: Dispatch<SetStateAction<string>>;
  composerRef: RefObject<HTMLTextAreaElement | null>;
  onError: (message: string | null) => void;
}): {
  requestAccess: (principal: string) => Promise<void>;
  selectMention: (principal: string) => void;
} {
  const requestAccess = useCallback(async (principal: string): Promise<void> => {
    if (!threadId) return;
    onError(null);
    try {
      const response = await fetch(`${apiUrl}/api/v1/threads/${threadId}/access-requests`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
          ...identityHeaders(),
        },
        body: JSON.stringify({ schema_version: 1, principal, role: "PARTICIPANT" }),
      });
      if (!response.ok) throw new Error(`Access request was refused (${response.status})`);
      setQuestion((current) => current.replace(/@[^\s]*$/, ""));
      await refresh();
    } catch (error) {
      onError(error instanceof Error ? error.message : "The access request failed");
    }
  }, [apiUrl, identityHeaders, onError, refresh, setQuestion, threadId]);
  const selectMention = useCallback((principal: string): void => {
    // The partial token may itself contain an `@` — a half-typed address is
    // the common case — so the replacement matches to the last whitespace.
    setQuestion((current) => current.replace(/@[^\s]*$/, `@${principal} `));
    window.requestAnimationFrame(() => composerRef.current?.focus());
  }, [composerRef, setQuestion]);
  return { requestAccess, selectMention };
}
