/** Sending one question, and filing whatever came with it.
 *
 *  Held apart from the rail controller because this is the only path in the
 *  surface that writes: it appends a durable USER message, optimistically
 *  shows it, files scanned attachments beside it, and then re-reads the ledger
 *  rather than trusting what the browser assembled. Specification 14 §12, §19.1.
 */
import { useCallback } from "react";
import type { Dispatch, RefObject, SetStateAction } from "react";
import type { AskResponse, SuggestedQuestion } from "./conversation";
import type { ThreadItem, TurnBudget } from "./AskSupport";

export function useAskComposer({
  apiUrl,
  recordType,
  recordId,
  anchorKind,
  serviceKey,
  windowStart,
  windowEnd,
  threadId,
  setThreadId,
  identityHeaders,
  mentionsIn,
  hydrateTranscript,
  setItems,
  setSuggested,
  setBudget,
  setActionError,
  setAttachmentNotice,
  attachments,
  setAttachments,
  suggestionsByMessage,
  pending,
  setPending,
  composerRef,
  setQuestion,
}: {
  apiUrl: string;
  recordType: string;
  recordId: string;
  anchorKind: "RECORD" | "SERVICE_WINDOW" | "SCOPE";
  serviceKey?: string;
  windowStart?: string;
  windowEnd?: string;
  threadId: string | null;
  setThreadId: Dispatch<SetStateAction<string | null>>;
  identityHeaders: () => Record<string, string>;
  mentionsIn: (text: string) => string[];
  hydrateTranscript: (threadId: string) => Promise<void>;
  setItems: Dispatch<SetStateAction<ThreadItem[]>>;
  setSuggested: Dispatch<SetStateAction<SuggestedQuestion[]>>;
  setBudget: Dispatch<SetStateAction<TurnBudget>>;
  setActionError: (message: string | null) => void;
  setAttachmentNotice: Dispatch<SetStateAction<string | null>>;
  attachments: File[];
  setAttachments: Dispatch<SetStateAction<File[]>>;
  suggestionsByMessage: RefObject<Record<string, SuggestedQuestion[]>>;
  pending: boolean;
  setPending: Dispatch<SetStateAction<boolean>>;
  composerRef: RefObject<HTMLTextAreaElement | null>;
  setQuestion: Dispatch<SetStateAction<string>>;
}): (text: string) => Promise<void> {
  const fileAttachments = useCallback(async (
    answer: AskResponse,
    pendingAttachments: File[],
  ): Promise<void> => {
    const verdicts = await Promise.all(pendingAttachments.map(async (file) => {
      try {
        const form = new FormData();
        form.set("attachment", file);
        const upload = await fetch(
          `${apiUrl}/api/v1/threads/${answer.thread_id}/messages/${answer.user_message_id}/attachments`,
          {
            method: "POST",
            headers: { "Idempotency-Key": crypto.randomUUID(), ...identityHeaders() },
            body: form,
          },
        );
        if (!upload.ok) return "FAILED";
        const body = await upload.json() as { scan_status: string };
        return body.scan_status;
      } catch {
        return "FAILED";
      }
    }));
    const clean = verdicts.filter((item) => item === "CLEAN").length;
    const blocked = verdicts.filter((item) => item === "BLOCKED").length;
    const failed = verdicts.length - clean - blocked;
    // Says what actually happened to the object: scanned, then filed beside the
    // message. It was never input to the answer, and the wording no longer
    // lets the paperclip imply that it was.
    setAttachmentNotice([
      clean ? `${clean} attachment${clean === 1 ? "" : "s"} scanned and filed to the conversation` : "",
      blocked ? `${blocked} blocked and discarded` : "",
      failed ? `${failed} could not be stored` : "",
    ].filter(Boolean).join(" · "));
  }, [apiUrl, identityHeaders, setAttachmentNotice]);

  return useCallback(async (text: string): Promise<void> => {
    const trimmed = text.trim();
    if (!trimmed || pending) return;
    setPending(true);
    setActionError(null);
    setQuestion("");
    const pendingAttachments = attachments;
    setAttachments([]);
    setAttachmentNotice(null);
    const optimisticKey = crypto.randomUUID();
    setItems((current) => [
      ...current,
      {
        kind: "exchange",
        key: optimisticKey,
        question: trimmed,
        userMessageId: null,
        userAuthor: "You",
        userCreatedAt: new Date().toISOString(),
        answer: null,
        answerAuthor: null,
        answerCreatedAt: null,
        error: null,
        attachments: [],
      },
    ]);
    try {
      const response = await fetch(`${apiUrl}/api/v1/liaison:ask`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": optimisticKey,
          "Prefer": "respond-async",
          ...identityHeaders(),
        },
        body: JSON.stringify({
          schema_version: 1,
          question: trimmed,
          anchor_kind: anchorKind,
          ...(anchorKind === "RECORD" ? {
            anchor_record_type: recordType,
            anchor_record_id: recordId,
          } : anchorKind === "SERVICE_WINDOW" ? {
            anchor_service_key: serviceKey,
            anchor_window_start: windowStart,
            anchor_window_end: windowEnd,
          } : {}),
          thread_id: threadId,
          mentions: mentionsIn(trimmed),
        }),
      });
      if (!response.ok) throw new Error(`The conversation service returned ${response.status}`);
      const answer = (await response.json()) as AskResponse;
      setBudget(answer.budget);
      if (answer.suggested.length) {
        suggestionsByMessage.current[answer.answer_message_id] = answer.suggested;
        setSuggested(answer.suggested);
      }
      if (pendingAttachments.length > 0) await fileAttachments(answer, pendingAttachments);
      setThreadId(answer.thread_id);
      setItems((current) =>
        current.map((item) => item.kind === "exchange" && item.key === optimisticKey
          ? {
              ...item,
              key: answer.user_message_id,
              userMessageId: answer.user_message_id,
              answer,
              answerAuthor: "Solvan",
              answerCreatedAt: new Date().toISOString(),
            }
          : item),
      );
      // The ledger is the transcript's authority, and attachment rows commit
      // after the message response, so read it back rather than trusting
      // optimistic browser state.
      await hydrateTranscript(answer.thread_id).catch(() => undefined);
    } catch (error) {
      const message = error instanceof Error ? error.message : "The question could not be answered";
      setItems((current) =>
        current.map((item) => item.kind === "exchange" && item.key === optimisticKey
          ? { ...item, error: message }
          : item),
      );
    } finally {
      setPending(false);
      window.requestAnimationFrame(() => composerRef.current?.focus());
    }
  }, [
    apiUrl, attachments, composerRef, fileAttachments, hydrateTranscript, identityHeaders,
    anchorKind, mentionsIn, pending, recordId, recordType, serviceKey, windowStart, windowEnd,
    setActionError, setAttachmentNotice,
    setAttachments, setBudget, setItems, setPending, setQuestion, setSuggested, setThreadId,
    suggestionsByMessage, threadId,
  ]);
}
