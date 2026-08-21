/** The Ask panel renders typed, reader-filtered parts; it never parses prose
 * to discover authority or behavior. Specification 14 §4.2, §12, §19. */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AskRailView } from "./AskRailView";
import { useThreadCollaboration } from "./AskCollaboration";
import type {
  AskResponse,
  CatchUpBrief,
  GuidanceSuggestion,
  PublicActivity,
  SuggestedQuestion,
  ThreadSummary,
  TranscriptResponse,
} from "./conversation";
import {
  UNKNOWN_BUDGET,
  readCursor,
  readDraft,
  storeCursor,
  storeDraft,
  transcriptItems,
  type ThreadItem,
  type TurnBudget,
} from "./AskSupport";
import { useLiaisonSubscription } from "./useLiaisonSubscription";
import { useAskComposer } from "./useAskComposer";
import { useThreadStream, type ThreadEvent } from "./useThreadStream";
import {
  useCollaborationActions,
  useExactTurnActions,
  useResizableRail,
  useSteerActions,
} from "./useAskControls";

export function AskRail({
  recordType,
  recordId,
  anchorKind = "RECORD",
  serviceKey,
  windowStart,
  windowEnd,
  surface = "rail",
  title,
  showClose = true,
  initialThreadId = null,
  apiUrl,
  authority,
  renderApprovalPart,
  onClose,
}: {
  recordType: string;
  recordId: string;
  anchorKind?: "RECORD" | "SERVICE_WINDOW" | "SCOPE";
  serviceKey?: string;
  windowStart?: string;
  windowEnd?: string;
  surface?: "rail" | "page";
  title?: string;
  showClose?: boolean;
  initialThreadId?: string | null;
  apiUrl: string;
  authority: string;
  renderApprovalPart: (actionId: string) => React.ReactNode;
  onClose: () => void;
}): React.JSX.Element {
  const [question, setQuestion] = useState(() => readDraft(recordType, recordId, null));
  const [suggested, setSuggested] = useState<SuggestedQuestion[]>([]);
  const [guidanceSuggestions, setGuidanceSuggestions] = useState<GuidanceSuggestion[]>([]);
  const [items, setItems] = useState<ThreadItem[]>([]);
  const [pending, setPending] = useState(false);
  // The server owns the thread; the client only remembers which one it is, so
  // a reload can rejoin the same conversation rather than starting over.
  const [threadId, setThreadId] = useState<string | null>(initialThreadId);
  const [threads, setThreads] = useState<ThreadSummary[]>([]);
  const [brief, setBrief] = useState<CatchUpBrief | null>(null);
  const [identityToken, setIdentityToken] = useState("");
  const [readerPrincipal, setReaderPrincipal] = useState<string | null>(null);
  const [budget, setBudget] = useState<TurnBudget>(UNKNOWN_BUDGET);
  const [actionError, setActionError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const composerRef = useRef<HTMLTextAreaElement>(null);
  const attachmentInputRef = useRef<HTMLInputElement>(null);
  const [attachments, setAttachments] = useState<File[]>([]);
  const [attachmentNotice, setAttachmentNotice] = useState<string | null>(null);
  const readerNearBottom = useRef(true);
  const [newMessagesWaiting, setNewMessagesWaiting] = useState(false);
  const [activityByMessage, setActivityByMessage] = useState<Record<string, PublicActivity>>({});
  const closeRef = useRef<HTMLButtonElement>(null);
  const [allQuestions, setAllQuestions] = useState(false);
  // Follow-ups belong to the answer that offered them, but they arrive only on
  // the live response. Remembering them here keeps them attached to their
  // answer across a rehydration instead of vanishing on the next event.
  const suggestionsByMessage = useRef<Record<string, SuggestedQuestion[]>>({});

  useEffect(() => {
    // A companion, not a modal. Escape dismisses and focus lands on the close
    // control so a keyboard reader is not stranded, but focus is deliberately
    // not trapped and nothing is inert behind: the point of the rail is to read
    // the incident and ask about it at the same time.
    if (!showClose) return;
    closeRef.current?.focus();
    function onKey(event: KeyboardEvent): void {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose, showClose]);

  useEffect(() => {
    const controller = new AbortController();
    // A workspace or service-window conversation has its own answerable set.
    // Asking only for a record's questions is what left the Chat route with a
    // bare composer and nothing to suggest.
    const query = new URLSearchParams(
      anchorKind === "RECORD"
        ? { anchor_kind: "RECORD", record_type: recordType, record_id: recordId }
        : { anchor_kind: anchorKind },
    );
    fetch(`${apiUrl}/api/v1/liaison/questions?${query}`, { signal: controller.signal })
      .then(async (response) => (response.ok ? await response.json() : { questions: [] }))
      .then((body: { questions?: SuggestedQuestion[] }) => setSuggested(body.questions ?? []))
      .catch(() => setSuggested([]));
    return () => controller.abort();
  }, [anchorKind, apiUrl, recordType, recordId]);

  const identityHeaders = useCallback((): Record<string, string> => identityToken.trim()
    ? { "X-Solvan-Approval-Token": identityToken.trim() }
    : {}, [identityToken]);

  useEffect(() => {
    const match = /^\/([a-z0-9/-]*)$/i.exec(question.trim());
    if (!match) {
      setGuidanceSuggestions([]);
      return;
    }
    const controller = new AbortController();
    const query = new URLSearchParams({ query: match[1] ?? "" });
    fetch(`${apiUrl}/api/v1/skills/autocomplete?${query}`, {
      signal: controller.signal,
      headers: identityHeaders(),
    })
      .then(async (response) => response.ok
        ? await response.json() as { items?: GuidanceSuggestion[] }
        : { items: [] })
      .then((body) => setGuidanceSuggestions(body.items ?? []))
      .catch(() => setGuidanceSuggestions([]));
    return () => controller.abort();
  }, [apiUrl, identityHeaders, question]);
  const subscription = useLiaisonSubscription({
    apiUrl, recordType, recordId, identityHeaders, enabled: anchorKind === "RECORD",
  });
  const collaboration = useThreadCollaboration({ apiUrl, threadId, identityHeaders });
  const { width, startDrag, onDrag, endDrag, nudge } = useResizableRail();
  const { steers, draftSteer, decideSteer } = useSteerActions({
    apiUrl, threadId, recordType, recordId, identityHeaders,
  });
  const { requestAccess, selectMention } = useCollaborationActions({
    apiUrl,
    threadId,
    identityHeaders,
    refresh: collaboration.refresh,
    setQuestion,
    composerRef,
    onError: setActionError,
  });

  const hydrateTranscript = useCallback(async (selectedThreadId: string): Promise<void> => {
    const response = await fetch(
      `${apiUrl}/api/v1/threads/${selectedThreadId}/messages?limit=100`,
      { headers: identityHeaders() },
    );
    if (!response.ok) throw new Error(`Transcript service returned ${response.status}`);
    const body = (await response.json()) as TranscriptResponse;
    if (body.budget) setBudget(body.budget);
    setItems(transcriptItems(selectedThreadId, body.messages, {
      readerPrincipal,
      budget: body.budget ?? UNKNOWN_BUDGET,
      suggestionsByMessage: suggestionsByMessage.current,
    }));
  }, [apiUrl, identityHeaders, readerPrincipal]);

  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams({
      anchor_kind: anchorKind,
    });
    if (anchorKind === "RECORD") {
      query.set("record_type", recordType);
      query.set("record_id", recordId);
    } else if (anchorKind === "SERVICE_WINDOW" && serviceKey && windowStart && windowEnd) {
      query.set("service_key", serviceKey);
      query.set("window_start", windowStart);
      query.set("window_end", windowEnd);
    }
    fetch(`${apiUrl}/api/v1/threads?${query}`, {
      signal: controller.signal,
      headers: identityHeaders(),
    })
      .then(async (response) => (response.ok ? await response.json() as { threads: ThreadSummary[] } : { threads: [] }))
      .then(async ({ threads: found }) => {
        setThreads(found);
        const selected = initialThreadId ?? found[0]?.id ?? null;
        setThreadId((current) => current ?? selected);
        if (selected) {
          // Thread discovery is asynchronous. Never let a late hydration
          // response erase text the operator has already begun composing.
          setQuestion((current) => current || readDraft(recordType, recordId, selected));
          await hydrateTranscript(selected);
        }
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [anchorKind, apiUrl, hydrateTranscript, identityHeaders, initialThreadId, recordId, recordType, serviceKey, windowEnd, windowStart]);

  useEffect(() => {
    storeDraft(recordType, recordId, threadId, question);
  }, [question, recordId, recordType, threadId]);

  const acknowledge = useCallback(async (sequence: number): Promise<void> => {
    // A read cursor is a claim about a person, so it advances only when that
    // person could actually have seen the message. Advancing it on arrival
    // made "since you last looked" a lie for anyone reading further up.
    if (!threadId || !readerNearBottom.current) return;
    await fetch(`${apiUrl}/api/v1/threads/${threadId}/read-cursor`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "Idempotency-Key": crypto.randomUUID(),
        ...identityHeaders(),
      },
      body: JSON.stringify({ schema_version: 1, stream_sequence: sequence }),
    }).catch(() => undefined);
  }, [apiUrl, identityHeaders, threadId]);

  const applyEvents = useCallback(async (
    events: ThreadEvent[],
    lastSequence: number,
  ): Promise<void> => {
    let touchesTranscript = false;
    for (const event of events) {
      if (
        event.message_id
        && (event.type === "turn.started" || event.type === "turn.activity")
        && typeof event.payload.activity === "string"
      ) {
        setActivityByMessage((current) => ({
          ...current,
          [event.message_id as string]: {
            message_id: event.message_id as string,
            activity: event.payload.activity as string,
            tool_identifier: typeof event.payload.tool_identifier === "string" ? event.payload.tool_identifier : null,
            result_class: typeof event.payload.result_class === "string" ? event.payload.result_class : null,
            timing_ms: typeof event.payload.timing_ms === "number" ? event.payload.timing_ms : null,
          },
        }));
      }
      if (
        event.message_id
        && ["turn.completed", "turn.parked", "turn.interrupted", "turn.error"].includes(event.type)
      ) {
        setActivityByMessage((current) => {
          const next = { ...current };
          delete next[event.message_id as string];
          return next;
        });
      }
      // Only a committed part or a terminal turn changes what is on screen.
      // Activity events move the one live row and cost no transcript read.
      if (event.type.startsWith("message.") || event.type.startsWith("turn.")) {
        touchesTranscript = touchesTranscript || !event.type.startsWith("turn.activity");
      }
    }
    if (touchesTranscript && threadId) {
      await hydrateTranscript(threadId).catch(() => undefined);
      await acknowledge(lastSequence);
    }
  }, [acknowledge, hydrateTranscript, threadId]);

  useThreadStream({ apiUrl, threadId, identityHeaders, onEvents: applyEvents });

  useEffect(() => {
    if (anchorKind !== "RECORD") {
      setBrief(null);
      return;
    }
    const controller = new AbortController();
    const query = new URLSearchParams({ record_type: recordType, record_id: recordId });
    const since = readCursor(recordType, recordId);
    if (since) query.set("cursor", since);
    fetch(`${apiUrl}/api/v1/liaison/catchup?${query}`, { signal: controller.signal })
      .then(async (response) => (response.ok ? ((await response.json()) as CatchUpBrief & { principal?: string }) : null))
      .then((value) => {
        setBrief(value);
        // The server names the verified reader; the client never asserts it.
        // Knowing it is what lets your own messages read as "You" rather than
        // flipping to a raw principal the moment the transcript rehydrates.
        if (value?.principal) setReaderPrincipal(value.principal);
        // Advance only once the brief is on screen, so "last looked" means
        // looked. A policy change returns a fresh authorized start cursor;
        // storing it is what stops the next open replaying hidden history.
        if (value?.cursor) storeCursor(recordType, recordId, value.cursor);
      })
      .catch(() => setBrief(null));
    return () => controller.abort();
  }, [anchorKind, apiUrl, recordType, recordId]);

  const mentionsIn = useCallback((text: string): string[] => collaboration.participants
    .map((item) => item.principal)
    .filter((principal) => text.includes(`@${principal}`)), [collaboration.participants]);

  const ask = useAskComposer({
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
  });

  const { cancelQueued, abortRunning } = useExactTurnActions({
    apiUrl, identityHeaders, hydrateTranscript, onError: setActionError,
  });

  const runningAnswer = useMemo(() => items
    .map((item) => (item.kind === "exchange" ? item.answer : item.answer))
    .find((answer) => answer?.state === "RUNNING") ?? null, [items]);

  const stopAndSend = useCallback(async (): Promise<void> => {
    const replacement = question.trim();
    if (!runningAnswer || !replacement || pending) return;
    setPending(true);
    setActionError(null);
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/threads/${runningAnswer.thread_id}/turns/${runningAnswer.answer_message_id}:stop-and-send`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "Idempotency-Key": crypto.randomUUID(),
            ...identityHeaders(),
          },
          body: JSON.stringify({
            schema_version: 1,
            attempt: runningAnswer.attempt,
            generation: runningAnswer.generation,
            replacement,
          }),
        },
      );
      if (!response.ok) {
        // The exact-generation fence refuses when the visible turn has already
        // finished or been replaced. Say so: the reader still holds their text.
        throw new Error(response.status === 409
          ? "That answer already finished. Send the message normally."
          : `Stop and send was refused (${response.status})`);
      }
      setQuestion("");
      await hydrateTranscript(runningAnswer.thread_id);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Stop and send failed");
    } finally {
      setPending(false);
    }
  }, [apiUrl, hydrateTranscript, identityHeaders, pending, question, runningAnswer]);

  const startNewThread = useCallback((): void => {
    // A conversation is a durable record, not a scratchpad: nothing is cleared.
    // Asking with no thread id opens a second one on the same anchor, and the
    // first stays readable and citable exactly as it was.
    setThreadId(null);
    setItems([]);
    setActivityByMessage({});
    setActionError(null);
    suggestionsByMessage.current = {};
    window.requestAnimationFrame(() => composerRef.current?.focus());
  }, []);

  const selectThread = useCallback(async (selected: string): Promise<void> => {
    setThreadId(selected);
    setItems([]);
    setActivityByMessage({});
    setActionError(null);
    await hydrateTranscript(selected).catch(() => undefined);
  }, [hydrateTranscript]);

  const scrollToLatest = useCallback(() => {
    endRef.current?.scrollIntoView({ block: "end", behavior: "smooth" });
    readerNearBottom.current = true;
    setNewMessagesWaiting(false);
  }, []);

  useEffect(() => {
    if (readerNearBottom.current) {
      window.requestAnimationFrame(() => endRef.current?.scrollIntoView({ block: "end" }));
      setNewMessagesWaiting(false);
    } else {
      setNewMessagesWaiting(true);
    }
  }, [items]);

  const handleScroll = useCallback<React.UIEventHandler<HTMLDivElement>>((event) => {
    const node = event.currentTarget;
    const nearBottom = node.scrollHeight - node.scrollTop - node.clientHeight < 96;
    readerNearBottom.current = nearBottom;
    if (nearBottom) setNewMessagesWaiting(false);
  }, []);

  return (
    <AskRailView
      recordId={recordId}
      surface={surface}
      title={title ?? (anchorKind === "SCOPE" ? "Chat" : `About ${recordId}`)}
      eyebrow={anchorKind === "SCOPE" ? "Chat · current workspace · read-only" : "Ask the ledger · read-only"}
      composerLabel={anchorKind === "SCOPE" ? "Ask a question about this workspace" : anchorKind === "SERVICE_WINDOW" ? "Ask about this service window" : "Ask a question about this incident"}
      composerPlaceholder={anchorKind === "SCOPE" ? "Ask about your workspace…" : `Ask about ${recordId}…`}
      showClose={showClose}
      showSubscription={anchorKind === "RECORD"}
      apiUrl={apiUrl}
      authority={authority}
      onClose={onClose}
      width={width}
      startDrag={startDrag}
      onDrag={onDrag}
      endDrag={endDrag}
      nudge={nudge}
      subscriptionPending={subscription.pending}
      following={subscription.following}
      toggleSubscription={subscription.toggle}
      closeRef={closeRef}
      identityToken={identityToken}
      setIdentityToken={setIdentityToken}
      subscriptionError={subscription.error}
      actionError={actionError}
      dismissActionError={() => setActionError(null)}
      scrollRef={scrollRef}
      handleScroll={handleScroll}
      brief={brief}
      items={items}
      budget={budget}
      cancelQueued={cancelQueued}
      abortRunning={abortRunning}
      ask={ask}
      pending={pending}
      question={question}
      identityHeaders={identityHeaders}
      hydrateTranscript={hydrateTranscript}
      steers={steers}
      draftSteer={draftSteer}
      decideSteer={decideSteer}
      endRef={endRef}
      newMessagesWaiting={newMessagesWaiting}
      scrollToLatest={scrollToLatest}
      suggested={suggested}
      guidanceSuggestions={guidanceSuggestions}
      allQuestions={allQuestions}
      setAllQuestions={setAllQuestions}
      composerRef={composerRef}
      setQuestion={setQuestion}
      runningAnswer={runningAnswer}
      stopAndSend={stopAndSend}
      renderApprovalPart={renderApprovalPart}
      activityByMessage={activityByMessage}
      threadId={threadId}
      threads={threads}
      startNewThread={startNewThread}
      selectThread={selectThread}
      participants={collaboration.participants}
      accessRequests={collaboration.requests}
      refreshCollaboration={collaboration.refresh}
      requestAccess={requestAccess}
      selectMention={selectMention}
      attachments={attachments}
      setAttachments={setAttachments}
      attachmentInputRef={attachmentInputRef}
      attachmentNotice={attachmentNotice}
    />
  );
}
