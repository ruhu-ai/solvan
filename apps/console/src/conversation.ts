/** Types for the conversational surface.
 *
 *  Held apart from `types.ts` because they describe a different subject: not
 *  the console's projection of the ledger, but the transcript of asking about
 *  it. Specification 14 §12 and §17.
 */

/** One typed part of a Liaison answer. The `kind` decides the shape; a client
 *  never parses prose to discover what it is looking at (spec 14 §12). */
export type AskPart = {
  kind: string;
  sequence: number;
  classification: string;
  access_mode: string;
  payload: {
    sentence?: string;
    template_id?: string;
    claim_kind?: string;
    polarity?: string;
    held_reason?: string;
    releasing_record?: string | null;
    citations?: Array<{ record_type: string; record_id: string }>;
    missing?: string;
    proposed_step?: string;
    tool_profile?: string[];
    requires_confirmation?: boolean;
    ceiling?: string;
    prompt?: string;
    kind?: "QUESTION" | "STEER_CONFIRMATION" | "SUBSCRIPTION_CONFIRMATION";
    request_id?: string;
    purpose?: string;
    agent?: string;
    budget?: string;
    anchor_record_type?: string;
    anchor_record_id?: string;
    dependencies?: string[];
    candidate_count?: number;
    candidates?: Array<{
      number: number;
      message_id: string;
      sequence: number;
      template_id?: string | null;
    }>;
    reason?: string;
    verdict?: string;
    error?: string;
    action_id?: string;
    invocation_request_id?: string;
    guidance_key?: string;
    guidance_version?: string;
    guidance_hash?: string;
    status?: string;
  };
};

export type SuggestedQuestion = { id: string; prompt: string };

export type GuidanceSuggestion = {
  selector: string;
  guidance_key: string;
  version: string;
  display_name: string;
  description: string;
};

/** One committed event since the reader's cursor. `authority_status` travels
 *  with it so a model-proposed hypothesis is never shown as verified fact. */
export type CatchUpDelta = {
  sequence: number;
  record: string;
  phrase: string;
  authority_status: string;
  reference: string | null;
};

export type CatchUpBrief = {
  anchor: string;
  cursor: string;
  policy_changed: boolean;
  remaining: number;
  deltas: CatchUpDelta[];
};

export type AskResponse = {
  thread_id: string;
  thread_anchor: string;
  state: string;
  user_message_id: string;
  answer_message_id: string;
  attempt: number;
  generation: number;
  queue_sequence: number | null;
  model_calls: number;
  tool_calls: number;
  tokens: number;
  budget: { model_calls: number; tool_calls: number; tokens: number };
  parts: AskPart[];
  suggested: SuggestedQuestion[];
  /** Counted, not buried: a suppressed claim is one the model could not support. */
  defects: {
    suppressed: number;
    held: number;
    unresolved_citations: number;
    unknown_templates: number;
    /** One when the model planner failed and the deterministic path answered. */
    provider_degraded?: number;
  };
};

export type TranscriptMessage = {
  id: string;
  role: "USER" | "LIAISON" | "DELTA";
  author: string | null;
  in_reply_to_message_id: string | null;
  turn_state: string;
  attempt: number | null;
  generation: number | null;
  queue_sequence: number | null;
  model_calls: number;
  tool_calls: number;
  tokens: number;
  attachments: Array<{
    attachment_id: string;
    scan_status: string;
    classification: string;
    mime: string;
    size_bytes: number;
  }>;
  created_at: string;
  parts: AskPart[];
};

export type TranscriptResponse = {
  thread_id: string;
  /** The ceilings the server applied. Never invented here (spec 14 §11.3). */
  budget?: { model_calls: number; tool_calls: number; tokens: number };
  messages: TranscriptMessage[];
  next_before_id: string | null;
};

export type ThreadSummary = {
  id: string;
  visibility: string;
  status: string;
  created_by: string;
  last_activity_at: string;
};

export type PublicActivity = {
  message_id: string;
  activity: string;
  tool_identifier: string | null;
  result_class: string | null;
  timing_ms: number | null;
};
