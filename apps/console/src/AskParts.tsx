/** How one typed part renders.
 *
 *  Kept apart from the rail because the two answer different questions. This
 *  file decides what a claim, a refusal, or a withheld part *looks* like; the
 *  rail decides how a conversation is held, sized, and transported. Nothing
 *  here parses prose — a part arrives typed, and its `kind` picks the shape.
 *
 *  Specification 14 §12, §19.
 */
import { useState } from "react";
import {
  EyeOff,
  History,
  Info,
  ShieldQuestion,
} from "lucide-react";
import { StatusBadge } from "./components";
import { SourceChip } from "./Incidents";
import type { AskPart, AskResponse, CatchUpBrief } from "./conversation";

/** What kind of record a citation points at, as a glyph.
 *
 *  The record *id* is not repeated per sentence: on an incident page, five
 *  claims citing INC-1042 five times says nothing the header did not. What does
 *  carry information is the kind of thing each statement stands on — a
 *  measurement reads differently from a verification run — so the type is
 *  inline and the exact ids are listed once beneath the answer.
 */
function CitationMarks({ part }: { part: AskPart }): React.JSX.Element | null {
  const citations = part.payload.citations ?? [];
  if (citations.length === 0) return null;
  return (
    <span className="ask-marks">
      {citations.map((citation) => (
        <SourceChip
          key={`${citation.record_type}-${citation.record_id}`}
          refId={citation.record_id}
          compact
        />
      ))}
    </span>
  );
}

/** What a held claim's heading says, by the kind of claim being held. */
const HELD_HEADINGS: Record<string, string> = {
  RECOVERY: "Not confirmed yet",
  DATA_LOSS: "Not established",
  DEPLOYMENT: "Not applied",
  CLOSURE: "Still open",
  ATTENTION: "Nothing pending",
  CONTAINMENT: "Not established",
};

/** One typed part. The `kind` decides the shape; the payload never decides it. */
export function PartView({
  part,
  steerControl,
  parkedControl,
  approvalControl,
}: {
  part: AskPart;
  steerControl?: React.ReactNode;
  parkedControl?: React.ReactNode;
  approvalControl?: React.ReactNode;
}): React.JSX.Element | null {
  const sentence = part.payload.sentence ?? "";

  if (part.kind === "text") {
    return <p className="ask-connective">{sentence}</p>;
  }

  if (part.kind === "claim") {
    // A sentence, not a card. Each one is still individually template-rendered
    // and predicate-verified; the border around it was never what made it true,
    // and five borders in a row read as five alerts rather than one answer.
    return (
      <p className="ask-claim">
        {sentence}
        <CitationMarks part={part} />
      </p>
    );
  }

  if (part.kind === "refusal") {
    // A held answer is a first-class answer: it says what is true and names
    // the record that would change it. The heading follows the claim's kind,
    // because "not confirmed yet" is the wrong thing to say about a case that
    // is simply not waiting on anybody.
    return (
      <div className="ask-refusal">
        <div className="ask-refusal-head">
          <ShieldQuestion size={15} strokeWidth={1.75} aria-hidden="true" />
          <span>{HELD_HEADINGS[part.payload.claim_kind ?? ""] ?? "Not confirmed yet"}</span>
        </div>
        <p>{sentence || part.payload.held_reason}</p>
        {part.payload.releasing_record && (
          <small>Releases when a {part.payload.releasing_record.replace(/_/g, " ")} says so.</small>
        )}
      </div>
    );
  }

  if (part.kind === "content_withheld") {
    const explanation = part.payload.reason
      ?? (part.payload.verdict === "MODEL_ARMOR_BLOCKED"
        ? "Model Armor blocked unsafe content before it could be shown or stored."
        : "Withheld from this reader by the current access policy.");
    return (
      <p className="ask-withheld">
        <EyeOff size={14} strokeWidth={1.75} aria-hidden="true" />
        {explanation}
      </p>
    );
  }

  if (part.kind === "steer_draft") {
    return (
      <div className="ask-steer">
        <p className="ask-steer-missing">{part.payload.missing}</p>
        <p className="ask-steer-step">{part.payload.proposed_step}</p>
        <StatusBadge label="Needs your confirmation" tone="warning" />
        {steerControl}
      </div>
    );
  }

  if (part.kind === "approval_ref") {
    return (
      <div className="ask-approval-ref">
        {approvalControl ?? (
          <p className="ask-withheld">The referenced action is not visible to this reader.</p>
        )}
      </div>
    );
  }

  if (part.kind === "guidance_ref") {
    return (
      <div className="ask-guidance-ref">
        <p className="eyebrow">Approved skill selected</p>
        <strong>{part.payload.guidance_key}</strong>
        <p>
          Revision {part.payload.guidance_version} is recorded for coordinator
          revalidation. This message did not start work or grant tools.
        </p>
        <code>{part.payload.invocation_request_id}</code>
      </div>
    );
  }

  if (part.kind === "interrupted") {
    return <p className="ask-turn-state ask-turn-interrupted">This answer was stopped.</p>;
  }

  if (part.kind === "budget_note") {
    return <p className="ask-budget">Stopped at the {part.payload.ceiling}.</p>;
  }

  if (part.kind === "parked_request") {
    const isSteer = part.payload.kind === "STEER_CONFIRMATION";
    return (
      <div className="ask-parked">
        <p>{isSteer ? "Review this bounded investigation request." : part.payload.prompt}</p>
        {isSteer && (
          <dl className="ask-parked-step">
            <div><dt>Purpose</dt><dd>{part.payload.purpose}</dd></div>
            <div><dt>Agent</dt><dd>{part.payload.agent}</dd></div>
            <div><dt>Read tools</dt><dd>{part.payload.tool_profile?.join(", ")}</dd></div>
            <div><dt>Budget</dt><dd>{part.payload.budget}</dd></div>
          </dl>
        )}
        {part.payload.candidates && part.payload.candidates.length > 0 && (
          <ol>
            {part.payload.candidates.map((candidate) => (
              <li key={`${candidate.message_id}:${candidate.sequence}`}>
                Point {candidate.number}
                {candidate.template_id ? ` · ${candidate.template_id.replaceAll("_", " ").toLowerCase()}` : ""}
              </li>
            ))}
          </ol>
        )}
        {parkedControl}
      </div>
    );
  }

  if (part.kind === "error") {
    return <p className="ask-error-part">{part.payload.error}</p>;
  }

  return null;
}

export function Answer({
  answer,
  onAsk,
  pending,
  hideSuggestions = false,
  renderSteerControl,
  renderParkedControl,
  renderApprovalControl,
}: {
  answer: AskResponse;
  onAsk: (prompt: string) => void;
  pending: boolean;
  hideSuggestions?: boolean;
  renderSteerControl?: (part: AskPart) => React.ReactNode;
  renderParkedControl?: (part: AskPart) => React.ReactNode;
  renderApprovalControl?: (part: AskPart) => React.ReactNode;
}): React.JSX.Element {
  const [showAllFollowups, setShowAllFollowups] = useState(false);
  const claims = answer.parts.filter((part) => part.kind === "claim").length;
  const suppressed = answer.defects.suppressed;
  const degraded = (answer.defects.provider_degraded ?? 0) > 0;
  return (
    <div className="ask-answer">
      {answer.parts.map((part) => (
        <PartView
          key={`${part.kind}-${part.sequence}`}
          part={part}
          steerControl={part.kind === "steer_draft" ? renderSteerControl?.(part) : undefined}
          parkedControl={part.kind === "parked_request" ? renderParkedControl?.(part) : undefined}
          approvalControl={part.kind === "approval_ref" ? renderApprovalControl?.(part) : undefined}
        />
      ))}
      {/* Composition defects are shown, not buried: a suppressed claim is a
          thing the model tried to say and could not support. An answer that
          asserted nothing has nothing to count, and a scorecard reading zero
          under a greeting is noise rather than provenance. */}
      {(claims > 0 || suppressed > 0 || degraded) && (
        <p className="ask-provenance">
          <Info size={13} strokeWidth={1.75} aria-hidden="true" />
          {claims} verified {claims === 1 ? "statement" : "statements"} from the ledger
          {suppressed > 0 &&
            ` · ${suppressed} unverifiable ${suppressed === 1 ? "statement" : "statements"} withheld`}
          {/* A degradation nobody can see is not a tested degradation path.
              The gates are unchanged either way; what changed is who chose
              which reads to make, and the reader is entitled to know. */}
          {degraded && " · answered without the model planner"}
        </p>
      )}
      {/* Follow-ups belong to the answer they extend, not to a tray at the foot
          of the panel: the question only makes sense beside what prompted it. */}
      {answer.suggested.length > 0 && !hideSuggestions && (
        <div className="ask-followups" aria-label="Follow-up questions">
          {(showAllFollowups ? answer.suggested : answer.suggested.slice(0, 3)).map((item) => (
            <button
              key={item.id}
              className="ask-chip"
              disabled={pending}
              onClick={() => onAsk(item.prompt)}
            >
              <span aria-hidden="true">↳</span> {item.prompt}
            </button>
          ))}
          {!showAllFollowups && answer.suggested.length > 3 && (
            <button type="button" className="ask-chip ask-chip-more" onClick={() => setShowAllFollowups(true)}>
              {answer.suggested.length - 3} more
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/** The catch-up brief. No model composed any of this — each line is a stored
 *  event rendered through its own phrase, carrying the authority of its source
 *  record so a proposal is never displayed as a verified fact (spec 14 §6). */
export function CatchUp({ brief }: { brief: CatchUpBrief }): React.JSX.Element | null {
  if (brief.deltas.length === 0) return null;
  return (
    <details className="ask-catchup">
      <summary className="ask-catchup-head">
        <History size={14} strokeWidth={1.75} aria-hidden="true" />
        <span>Since you last looked</span>
        <strong>{brief.deltas.length + brief.remaining}</strong>
      </summary>
      <div className="ask-catchup-body">
        <ol>
          {brief.deltas.map((delta) => (
            <li key={delta.sequence}>
              <span className={`ask-authority ask-authority-${delta.authority_status.toLowerCase()}`}>
                {delta.authority_status.replace(/_/g, " ").toLowerCase()}
              </span>
              <span className="ask-catchup-phrase">{delta.phrase}</span>
            </li>
          ))}
        </ol>
        {brief.remaining > 0 && <small>and {brief.remaining} further events</small>}
      </div>
    </details>
  );
}
