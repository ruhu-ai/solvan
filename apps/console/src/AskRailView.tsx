/** Presentational shell for the durable Ask controller. */
import { useMemo, useState } from "react";
import { ArrowUp, Check, MessagesSquare, Paperclip, Square, Users, X } from "lucide-react";
import { Answer, CatchUp } from "./AskParts";
import { SolvanMark } from "./components";
import {
  MENTION_LISTBOX_ID,
  MentionSuggestions,
  PeoplePanel,
  mentionOptionId,
  mentionOptions,
} from "./AskCollaboration";
import type { AskRailViewProps } from "./AskRailView.types";
import {
  ClarificationControl,
  RAIL_MAX_WIDTH,
  RAIL_MIN_WIDTH,
  absoluteTime,
  relativeTime,
  startsNewTimeGroup,
  useNow,
} from "./AskSupport";
import { TurnState, TurnWork } from "./AskTurnStatus";

export function AskRailView({
  recordId, surface, title, eyebrow, composerLabel, composerPlaceholder, showClose, showSubscription,
  apiUrl, authority, onClose, width, startDrag, onDrag, endDrag, nudge,
  subscriptionPending, following, toggleSubscription, closeRef, identityToken,
  setIdentityToken, subscriptionError, actionError, dismissActionError, scrollRef,
  handleScroll, brief, items, budget,
  cancelQueued, abortRunning, ask, pending, question, identityHeaders,
  hydrateTranscript, steers, draftSteer, decideSteer, endRef, newMessagesWaiting,
  scrollToLatest, suggested, guidanceSuggestions, allQuestions, setAllQuestions, composerRef,
  setQuestion, runningAnswer, stopAndSend, renderApprovalPart, activityByMessage,
  threadId, threads, startNewThread, selectThread, participants, accessRequests,
  refreshCollaboration, requestAccess, selectMention,
  attachments, setAttachments, attachmentInputRef, attachmentNotice,
}: AskRailViewProps): React.JSX.Element {
  const activeSubscription = following;
  const [peopleOpen, setPeopleOpen] = useState(false);
  const [activeMention, setActiveMention] = useState(0);
  const [activeGuidance, setActiveGuidance] = useState(0);
  const now = useNow();
  const mentions = useMemo(() => mentionOptions(question, participants), [participants, question]);
  const mentionIndex = mentions ? Math.min(activeMention, mentions.options.length - 1) : 0;

  const onComposerKeyDown: React.KeyboardEventHandler<HTMLTextAreaElement> = (event) => {
    if (guidanceSuggestions.length > 0) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const step = event.key === "ArrowDown" ? 1 : -1;
        setActiveGuidance((current) =>
          (Math.min(current, guidanceSuggestions.length - 1) + step
            + guidanceSuggestions.length) % guidanceSuggestions.length);
        return;
      }
      if (event.key === "Enter" || event.key === "Tab") {
        event.preventDefault();
        setQuestion(`${guidanceSuggestions[Math.min(activeGuidance, guidanceSuggestions.length - 1)].selector} `);
        setActiveGuidance(0);
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        setQuestion("");
        setActiveGuidance(0);
        return;
      }
    }
    if (mentions && mentions.options.length > 0) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const step = event.key === "ArrowDown" ? 1 : -1;
        const count = mentions.options.length;
        setActiveMention((current) => (Math.min(current, count - 1) + step + count) % count);
        return;
      }
      if (event.key === "Enter" || event.key === "Tab") {
        // Completing a mention is what Enter means while the list is open.
        // Sending the half-typed address instead was the old behaviour.
        event.preventDefault();
        const selected = mentions.options[mentionIndex];
        if (selected.kind === "participant") selectMention(selected.principal);
        else void requestAccess(selected.principal);
        setActiveMention(0);
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        setQuestion((current) => `${current} `);
        return;
      }
    }
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      void ask(question);
    }
  };

  let previousTime: string | null = null;
  return (
    <aside
      className={surface === "page" ? "ask-rail ask-chat-page" : "ask-rail"}
      role="complementary"
      aria-labelledby="ask-panel-title"
      style={surface === "rail" ? { width: `${width}px` } : undefined}
    >
      {surface === "rail" && <div
          className="ask-rail-grip"
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize the ledger panel"
          aria-valuenow={width}
          aria-valuemin={RAIL_MIN_WIDTH}
          aria-valuemax={RAIL_MAX_WIDTH}
          tabIndex={0}
          onPointerDown={startDrag}
          onPointerMove={onDrag}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
          onKeyDown={nudge}
        />}
      <header className="ask-rail-head">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h2 id="ask-panel-title">{title}</h2>
        </div>
        <div className="ask-rail-head-actions">
          {/* Following is a small persistent control, not a block of its own.
              It sits beside close because both act on the rail, not on a turn. */}
          {showSubscription && <button
            type="button"
            className="ask-follow"
            disabled={subscriptionPending}
            aria-pressed={Boolean(activeSubscription)}
            onClick={() => void toggleSubscription()}
            >
            {subscriptionPending ? "Saving…" : activeSubscription ? "Following" : "Follow"}
          </button>}
          {/* A conversation is durable and citable, so nothing here clears it.
              Starting a second one on the same record leaves the first intact
              and readable — which is what "clear the context" actually wants. */}
          <button
            type="button"
            className="icon-button"
            disabled={!threadId}
            aria-label="Start a new conversation about this record"
            title="New conversation"
            onClick={startNewThread}
          >
            <MessagesSquare size={18} strokeWidth={1.75} />
          </button>
          <button type="button" className="icon-button" disabled={!threadId} aria-label="Manage conversation participants" aria-expanded={peopleOpen} onClick={() => setPeopleOpen((current) => !current)}>
            <Users size={18} strokeWidth={1.75} />
          </button>
          {showClose && <button ref={closeRef} className="icon-button" onClick={onClose} aria-label="Close the ledger panel">
            <X size={18} strokeWidth={1.75} />
          </button>}
        </div>
      </header>
      {threads.length > 1 && (
        <label className="ask-thread-picker">
          <span className="visually-hidden">Choose a conversation about this record</span>
          <select value={threadId ?? ""} onChange={(event) => void selectThread(event.target.value)}>
            {threadId === null && <option value="">New conversation</option>}
            {threads.map((item, index) => (
              <option key={item.id} value={item.id}>
                Conversation {threads.length - index} · {relativeTime(item.last_activity_at, now)}
              </option>
            ))}
          </select>
        </label>
      )}
      {peopleOpen && threadId && (
        <PeoplePanel
          apiUrl={apiUrl}
          threadId={threadId}
          identityHeaders={identityHeaders}
          participants={participants}
          requests={accessRequests}
          onChanged={refreshCollaboration}
          onClose={() => setPeopleOpen(false)}
        />
      )}
      <div className="ask-rail-controls">
        {authority === "GOOGLE_CLOUD_IAM" && (
          <label className="ask-identity-token">
            <span>One-time Google identity token</span>
            <input type="password" autoComplete="off" value={identityToken} onChange={(event) => setIdentityToken(event.target.value)} placeholder="Bearer …" />
            <small>Held only in this rail and sent over TLS for server-side identity verification.</small>
          </label>
        )}
      </div>
      {subscriptionError && <p className="ask-error" role="status">{subscriptionError}</p>}
      {actionError && (
        <p className="ask-error ask-action-error" role="alert">
          {actionError}
          <button type="button" className="link-button" onClick={dismissActionError}>Dismiss</button>
        </p>
      )}

      <div
        ref={scrollRef}
        className="ask-rail-scroll"
        onScroll={handleScroll}
      >
      {brief && <CatchUp brief={brief} />}

      <ol className="ask-thread">
        {items.map((item, index) => {
          // One time per exchange, and only when the conversation paused. A
          // timestamp beside every line is decoration; a timestamp after a
          // gap is information.
          const stamp = item.kind === "exchange" ? item.userCreatedAt : item.createdAt;
          const showTime = startsNewTimeGroup(previousTime, stamp);
          previousTime = stamp;
          if (item.kind === "notice") {
            return (
              <li key={item.key}>
                <article className="ask-message ask-message-liaison" aria-label={`Message from ${item.author}`}>
                  <div className="ask-message-meta">
                    <span className="ask-avatar ask-avatar-solvan" aria-hidden="true"><SolvanMark size={13} /></span>
                    <strong>{item.author}</strong>
                    {showTime && (
                      <time dateTime={item.createdAt} title={absoluteTime(item.createdAt)}>
                        {relativeTime(item.createdAt, now)}
                      </time>
                    )}
                  </div>
                  <Answer
                    answer={item.answer}
                    onAsk={(text) => void ask(text)}
                    pending={pending}
                    hideSuggestions
                    renderParkedControl={(part) => (
                      <ClarificationControl
                        apiUrl={apiUrl}
                        part={part}
                        identityHeaders={identityHeaders}
                        onDecided={() => hydrateTranscript(item.answer.thread_id)}
                      />
                    )}
                    renderApprovalControl={(part) => renderApprovalPart(part.payload.action_id ?? "")}
                  />
                </article>
              </li>
            );
          }
          return (
          <li key={item.key}>
            <article className="ask-message ask-message-user" aria-label={`Message from ${item.userAuthor}`}>
              <div className="ask-message-meta ask-message-meta-user">
                {/* Your own turn in a two-party conversation needs no byline:
                    the side of the panel it sits on already says who wrote it. */}
                {item.userAuthor !== "You" && (
                  <>
                    <span className="ask-avatar" aria-hidden="true">{item.userAuthor.slice(0, 1).toUpperCase()}</span>
                    <strong>{item.userAuthor}</strong>
                  </>
                )}
                {showTime && (
                  <time dateTime={item.userCreatedAt} title={absoluteTime(item.userCreatedAt)}>
                    {relativeTime(item.userCreatedAt, now)}
                  </time>
                )}
              </div>
              <p className="ask-question">{item.question}</p>
              {item.attachments.length > 0 && <div className="ask-message-attachments">{item.attachments.map((attachment) => <span key={attachment.attachment_id} className={attachment.scan_status === "CLEAN" ? "clean" : "blocked"}><Paperclip size={11} />{attachment.mime} · {attachment.scan_status === "CLEAN" ? "filed to the conversation" : "blocked"}</span>)}</div>}
              {/* Appended to the ledger, said once, as a mark rather than a
                  word: "Committed" beside a governed surface reads as an
                  approval, which a delivery mark must never imply (§19.1). */}
              <span
                className="ask-delivery"
                title={item.userMessageId ? "Appended to the conversation ledger" : "Appending to the conversation ledger"}
              >
                {item.userMessageId
                  ? <><Check size={12} aria-hidden="true" /><span className="visually-hidden">Appended to the conversation ledger</span></>
                  : "Sending…"}
              </span>
            </article>
            {item.answer && (
              <TurnWork
                answer={item.answer}
                activity={activityByMessage[item.answer.answer_message_id]}
                budget={budget}
                onStop={() => void abortRunning(item.answer!)}
              />
            )}
            {item.answer && <TurnState answer={item.answer} onCancel={() => void cancelQueued(item.answer!)} />}
            {item.answer && item.answer.parts.length > 0 && (
              <article className="ask-message ask-message-liaison" aria-label={`Message from ${item.answerAuthor ?? "Solvan"}`}>
                <div className="ask-message-meta">
                  <span className="ask-avatar ask-avatar-solvan" aria-hidden="true"><SolvanMark size={13} /></span>
                  <strong>{item.answerAuthor ?? "Solvan"}</strong>
                </div>
              <Answer answer={item.answer} onAsk={(text) => void ask(text)} pending={pending} hideSuggestions={Boolean(question.trim())} renderParkedControl={(part) => (
                <ClarificationControl
                  apiUrl={apiUrl}
                  part={part}
                  identityHeaders={identityHeaders}
                  onDecided={() => hydrateTranscript(item.answer!.thread_id)}
                />
              )} renderApprovalControl={(part) => renderApprovalPart(part.payload.action_id ?? "")} renderSteerControl={(part) => {
                // The server appends a durable liaison message when a steer
                // is drafted.  That can change the rendered list index before
                // the draft response arrives, so an index-based key loses the
                // pending state and makes the action look as if it did nothing.
                // The answer message id is stable across hydration; pair it
                // with the typed part sequence for an unambiguous client key.
                const key = `${item.answer!.answer_message_id}:${part.sequence}`;
                const state = steers[key];
                if (!state) return <button type="button" className="secondary-button" onClick={() => void draftSteer(key, part)}>Review bounded read</button>;
                if (state.status === "PENDING") return <div className="ask-steer-actions"><button type="button" className="secondary-button" onClick={() => void decideSteer(key, false)}>Reject</button><button type="button" className="primary-button" onClick={() => void decideSteer(key, true)}>Confirm request</button></div>;
                return <p className={state.error ? "ask-error" : "inline-notice"}>{state.error ?? state.status.replaceAll("_", " ").toLowerCase()}</p>;
              }} />
              </article>
            )}
            {item.error && <p className="ask-error">{item.error}</p>}
            {!item.answer && !item.error && <p className="ask-pending">Sending…</p>}
          </li>
          );
        })}
      </ol>
      {/* The scroll anchor lives outside the list: an `ol` may only parent `li`. */}
      <div ref={endRef} />

      {newMessagesWaiting && (
        <button type="button" className="ask-new-messages" onClick={scrollToLatest}>
          New messages
        </button>
      )}

      {/* Hydrated answers do not carry ephemeral suggestions, so keep the
          server-authorized tray available whenever the composer is empty. */}
      {suggested.length > 0 && !question.trim() && (
        <div className="ask-suggestions" aria-label="Suggested questions">
          {(allQuestions ? suggested : suggested.slice(0, 3)).map((item) => (
            <button key={item.id} className="ask-chip" disabled={pending} onClick={() => void ask(item.prompt)}>
              <span aria-hidden="true">↳</span> {item.prompt}
            </button>
          ))}
          {!allQuestions && suggested.length > 3 && (
            <button type="button" className="ask-chip ask-chip-more" onClick={() => setAllQuestions(true)}>
              {suggested.length - 3} more
            </button>
          )}
        </div>
      )}

      </div>

      <form
        className="ask-form"
        onSubmit={(event) => {
          event.preventDefault();
          void ask(question);
        }}
      >
        {mentions && (
          <MentionSuggestions
            options={mentions.options}
            active={mentionIndex}
            onSelect={selectMention}
            onRequest={requestAccess}
          />
        )}
        {guidanceSuggestions.length > 0 && (
          <div className="ask-skill-suggestions" role="listbox" aria-label="Approved Skills">
            {guidanceSuggestions.map((item, index) => (
              <button
                type="button"
                role="option"
                aria-selected={index === activeGuidance}
                className={index === activeGuidance ? "active" : ""}
                key={`${item.guidance_key}@${item.version}`}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => {
                  setQuestion(`${item.selector} `);
                  setActiveGuidance(0);
                  composerRef.current?.focus();
                }}
              >
                <strong>{item.selector}</strong>
                <span>{item.display_name} · {item.description}</span>
              </button>
            ))}
          </div>
        )}
        {attachments.length > 0 && <div className="ask-attachment-tray" aria-label="Attachments waiting to be scanned">{attachments.map((file, index) => <span key={`${file.name}:${file.size}:${index}`}><Paperclip size={12} />{file.name}<button type="button" aria-label={`Remove ${file.name}`} onClick={() => setAttachments((current) => current.filter((_, itemIndex) => itemIndex !== index))}><X size={12} /></button></span>)}</div>}
        {attachmentNotice && <p className="ask-attachment-notice" role="status">{attachmentNotice}</p>}
        {/* The send control sits inside the field, as a chat composer does.
            Its accessible name still says what it does; only the visible label
            is an arrow. */}
        <label className="ask-composer">
          <span className="visually-hidden">{composerLabel}</span>
          <textarea
            ref={composerRef}
            rows={1}
            value={question}
            placeholder={composerPlaceholder}
            aria-expanded={Boolean(mentions) || guidanceSuggestions.length > 0}
            aria-controls={mentions ? MENTION_LISTBOX_ID : undefined}
            aria-activedescendant={mentions ? mentionOptionId(mentionIndex) : undefined}
            onChange={(event) => { setQuestion(event.target.value); setActiveMention(0); }}
            onKeyDown={onComposerKeyDown}
          />
          <input
            ref={attachmentInputRef}
            className="visually-hidden"
            type="file"
            multiple
            accept="text/plain,text/csv,application/json,image/png,image/jpeg"
            onChange={(event) => {
              const selected = Array.from(event.target.files ?? []);
              setAttachments((current) => [...current, ...selected].slice(0, 6));
              event.target.value = "";
            }}
          />
          {/* Attachments are scanned and filed beside the message. They are
              evidence for people, not input to the answer, and the label says
              so rather than letting the paperclip imply the model read them. */}
          <button type="button" className="ask-attach" aria-label="Attach files: scanned and filed to the conversation, not read by the answer" onClick={() => attachmentInputRef.current?.click()}>
            <Paperclip size={16} aria-hidden="true" />
          </button>
          <button
            type="submit"
            className="ask-send"
            disabled={pending || !question.trim()}
            aria-label={pending ? "Sending question" : "Send question"}
          >
            <ArrowUp size={17} strokeWidth={2} aria-hidden="true" />
          </button>
        </label>
        {runningAnswer && question.trim() && (
          <button type="button" className="ask-stop-send" disabled={pending} onClick={() => void stopAndSend()}>
            <Square size={13} fill="currentColor" aria-hidden="true" />
            Stop and send
          </button>
        )}
      </form>
    </aside>
  );
}
