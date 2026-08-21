-- Solvan conversational surface: TARGET schema.
--
-- This file is deliberately NOT part of the authoritative release DDL. It is
-- loaded into a clean PostgreSQL 16 instance by `scripts/check-contracts`
-- so the contract cannot drift while it waits to be built, and it must never
-- be concatenated into `schema.sql` until the conversational surface enters a
-- release. Specification 14 §11.
--
-- The rules this file exists to enforce, rather than merely describe:
--   * anchors have exactly three shapes, and no orphaned field can survive;
--   * every part carries an access mode, and an empty record set denies;
--   * one execution lane per thread, with durable queued and parked turns;
--   * queued/parked turns hold no lease, so the reaper cannot mistake them for dead;
--   * a delivery is either a direct answer or a subscription interval;
--   * pull-only channels can never be a subscription destination.

BEGIN;

CREATE SCHEMA IF NOT EXISTS solvan_liaison;
SET search_path TO solvan_liaison, public;

-- Scope-local monotonic ordering. The catch-up cursor depends on a single
-- total order across entities whose own workflow versions overlap, so the
-- sequence is allocated in the same transaction as the authoritative mutation
-- and its outbox insert. Gaps are permitted and imply nothing: a rolled-back
-- transaction must leave no visible event and no derivable hidden count.
CREATE TABLE scope_event_sequences (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
  PRIMARY KEY (organization_id, project_id, environment_id)
);

-- Nodes of the addressable-record graph.
CREATE TABLE liaison_record_directory (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  record_type text NOT NULL CHECK (record_type IN
    ('incident','reliability_case','action','evidence_item','verification_run',
     'patch_artifact','workspace','tenant_connection')),
  record_id text NOT NULL,
  service_key text,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, record_type, record_id)
);

-- Committed events in scope order. The release outbox is not modified for a
-- target feature, so ordered events are mirrored here with their scope
-- sequence — the same relationship the record directory has to the projection.
-- `authority_status` travels with each event so a restated hypothesis can
-- never be delivered dressed as a verified fact (§6).
CREATE TABLE liaison_scope_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  scope_sequence bigint NOT NULL CHECK (scope_sequence > 0),
  record_type text NOT NULL,
  record_id text NOT NULL,
  event_key text NOT NULL,
  phrase text NOT NULL,
  authority_status text NOT NULL CHECK (authority_status IN
    ('OBSERVED','MODEL_PROPOSED','CONFIRMED','RECONCILED','VERIFIED')),
  reference text,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, scope_sequence),
  UNIQUE (organization_id, project_id, environment_id, record_type, record_id, event_key),
  FOREIGN KEY (organization_id, project_id, environment_id, record_type, record_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id)
);

CREATE INDEX liaison_scope_events_by_record ON liaison_scope_events
  (organization_id, project_id, environment_id, record_type, record_id, scope_sequence);

-- The domain is a graph, not a tree: evidence, findings, and patches have
-- several legitimate parents. Append-only.
CREATE TABLE liaison_record_edges (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  parent_type text NOT NULL,
  parent_id text NOT NULL,
  child_type text NOT NULL,
  child_id text NOT NULL,
  relation text NOT NULL CHECK (relation IN
    ('CONTAINS','EVIDENCES','MITIGATES','VERIFIES','REPAIRS')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
               parent_type, parent_id, child_type, child_id, relation),
  FOREIGN KEY (organization_id, project_id, environment_id, parent_type, parent_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id),
  FOREIGN KEY (organization_id, project_id, environment_id, child_type, child_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id)
);

CREATE TABLE liaison_threads (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^thr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  anchor_kind text NOT NULL CHECK (anchor_kind IN ('RECORD','SERVICE_WINDOW','SCOPE')),
  anchor_record_type text,
  anchor_record_id text,
  anchor_service_key text,
  anchor_window_start timestamptz,
  anchor_window_end timestamptz,
  visibility text NOT NULL CHECK (visibility IN ('PARTICIPANTS','SCOPE')),
  status text NOT NULL CHECK (status IN ('OPEN','ARCHIVED')),
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  last_activity_at timestamptz NOT NULL DEFAULT now(),
  next_stream_sequence bigint NOT NULL DEFAULT 1 CHECK (next_stream_sequence > 0),
  next_turn_queue_sequence bigint NOT NULL DEFAULT 1
    CHECK (next_turn_queue_sequence > 0),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               anchor_record_type, anchor_record_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id),
  -- One exhaustive disjunction. A SCOPE anchor is valid and no non-record
  -- anchor may retain a stray record or window field.
  CHECK (
    (anchor_kind = 'RECORD'
      AND anchor_record_type IS NOT NULL AND anchor_record_id IS NOT NULL
      AND anchor_service_key IS NULL
      AND anchor_window_start IS NULL AND anchor_window_end IS NULL)
    OR
    (anchor_kind = 'SERVICE_WINDOW'
      AND anchor_record_type IS NULL AND anchor_record_id IS NULL
      AND anchor_service_key IS NOT NULL
      AND anchor_window_start IS NOT NULL
      AND anchor_window_end > anchor_window_start)
    OR
    (anchor_kind = 'SCOPE'
      AND anchor_record_type IS NULL AND anchor_record_id IS NULL
      AND anchor_service_key IS NULL
      AND anchor_window_start IS NULL AND anchor_window_end IS NULL)
  ),
  CHECK ((status = 'ARCHIVED') = (archived_at IS NOT NULL))
);

-- Membership is append-only: removing and re-adding a participant writes a new
-- epoch rather than rewriting history, and a part scoped to an epoch keeps
-- meaning it.
CREATE TABLE liaison_thread_participants (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  thread_id text NOT NULL,
  principal text NOT NULL,
  membership_epoch bigint NOT NULL CHECK (membership_epoch > 0),
  role text NOT NULL CHECK (role IN ('OWNER','PARTICIPANT')),
  added_by_principal text NOT NULL,
  added_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id,
               thread_id, principal, membership_epoch),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id)
);

CREATE UNIQUE INDEX liaison_participant_active
  ON liaison_thread_participants
     (organization_id, project_id, environment_id, thread_id, principal)
  WHERE removed_at IS NULL;

-- A central-Chat record cannot be selected by free text, URL material, model
-- output, or a pasted identifier. The server first issues this short-lived
-- receipt from the reader-filtered directory, then consumes it exactly once
-- while opening the exact record thread. A replay returns the same thread.
CREATE TABLE liaison_record_selection_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rsl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  principal text NOT NULL,
  anchor_kind text NOT NULL CHECK (anchor_kind = 'RECORD'),
  record_type text NOT NULL,
  record_id text NOT NULL,
  record_revision text NOT NULL CHECK (record_revision ~ '^sha256:[0-9a-f]{64}$'),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  -- The receipt reserves the creator membership at epoch 1. Consumption
  -- verifies the newly opened owner row has exactly this epoch.
  membership_epoch bigint NOT NULL,
  reader_grant_digest text NOT NULL CHECK
    (reader_grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ISSUED','CONSUMED','EXPIRED','REFUSED')),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  thread_id text,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, receipt_digest),
  FOREIGN KEY (organization_id, project_id, environment_id, record_type, record_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id),
  CHECK (expires_at > issued_at),
  CONSTRAINT liaison_selection_membership_epoch_ck CHECK (membership_epoch = 1),
  CONSTRAINT liaison_selection_consumed_shape_ck CHECK
    ((status = 'CONSUMED') = (consumed_at IS NOT NULL AND thread_id IS NOT NULL)
     AND (status = 'CONSUMED' OR (consumed_at IS NULL AND thread_id IS NULL)))
);

CREATE INDEX liaison_record_selection_receipts_current
  ON liaison_record_selection_receipts
     (organization_id, project_id, environment_id, principal, expires_at)
  WHERE status = 'ISSUED';

-- Service selection is a distinct receipt because it binds a registry-derived
-- service entity set and an explicit closed time window, not one record row.
CREATE TABLE liaison_service_selection_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ssl_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  principal text NOT NULL,
  service_key text NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  entity_set_digest text NOT NULL CHECK (entity_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  membership_epoch bigint NOT NULL,
  reader_grant_digest text NOT NULL CHECK (reader_grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('ISSUED','CONSUMED','EXPIRED','REFUSED')),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  thread_id text,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,receipt_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,thread_id)
    REFERENCES liaison_threads (organization_id,project_id,environment_id,id),
  CONSTRAINT liaison_service_selection_window_order_ck
    CHECK (window_end > window_start),
  CONSTRAINT liaison_service_selection_window_width_ck
    CHECK (window_end - window_start <= interval '24 hours'),
  CONSTRAINT liaison_service_selection_retention_ck
    CHECK (window_start >= issued_at - interval '180 days'),
  CONSTRAINT liaison_service_selection_future_ck
    CHECK (window_end <= issued_at + interval '5 minutes'),
  CHECK (expires_at > issued_at),
  CONSTRAINT liaison_service_selection_membership_epoch_ck CHECK (membership_epoch = 1),
  CONSTRAINT liaison_service_selection_consumed_shape_ck CHECK
    ((status='CONSUMED') = (consumed_at IS NOT NULL AND thread_id IS NOT NULL)
     AND (status='CONSUMED' OR (consumed_at IS NULL AND thread_id IS NULL)))
);

CREATE INDEX liaison_service_selection_receipts_current
  ON liaison_service_selection_receipts
     (organization_id,project_id,environment_id,principal,expires_at)
  WHERE status='ISSUED';

CREATE TABLE liaison_access_requests (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^lar_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  thread_id text NOT NULL,
  requested_principal text NOT NULL,
  requested_by_principal text NOT NULL,
  status text NOT NULL CHECK (status IN
    ('PENDING','APPROVED','DENIED','EXPIRED','CANCELLED')),
  expires_at timestamptz NOT NULL,
  decided_by_principal text,
  decided_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id),
  CHECK ((status IN ('APPROVED','DENIED')) =
         (decided_by_principal IS NOT NULL AND decided_at IS NOT NULL)),
  CHECK (expires_at > created_at)
);

CREATE TABLE liaison_thread_read_cursors (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  thread_id text NOT NULL,
  principal text NOT NULL,
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  stream_sequence bigint NOT NULL DEFAULT 0 CHECK (stream_sequence >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, thread_id, principal),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id)
);

CREATE TABLE liaison_messages (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^lms_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  thread_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('USER','LIAISON','DELTA')),
  author_principal text,
  in_reply_to_message_id text,
  channel_binding_id text,
  supersedes_message_id text,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  redaction_verdict_ref text,
  content_hash text,
  turn_state text NOT NULL CHECK (turn_state IN
    ('QUEUED','READY','RUNNING','PARKED','COMPLETED','INTERRUPTED','FAILED')),
  purge_after timestamptz NOT NULL,
  deleted_at timestamptz,
  legal_hold_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  -- Transcript order is a database fact, not an inference from the id.
  -- `created_at` is transaction time, so every message a single turn writes
  -- shares it; and two ULIDs minted in the same millisecond need not sort in
  -- the order they were written. A cursor built on either can skip a message
  -- or repeat one. This ordinal is assigned at insert and never changes, so
  -- the paging order is total, stable, and gap-tolerant.
  stream_position bigserial NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, thread_id, stream_position),
  UNIQUE (organization_id, project_id, environment_id, id, thread_id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               in_reply_to_message_id, thread_id)
    REFERENCES liaison_messages
      (organization_id, project_id, environment_id, id, thread_id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               supersedes_message_id, thread_id)
    REFERENCES liaison_messages
      (organization_id, project_id, environment_id, id, thread_id),
  CHECK ((role = 'USER') = (author_principal IS NOT NULL)),
  -- Only a Liaison message can be mid-turn; a user message is complete when
  -- it is written.
  CHECK (role = 'LIAISON' OR turn_state = 'COMPLETED'),
  CHECK ((turn_state IN ('COMPLETED','INTERRUPTED','FAILED')) =
         (completed_at IS NOT NULL))
);

-- One live answer per user message. A correction supersedes rather than edits.
CREATE UNIQUE INDEX liaison_one_live_answer
  ON liaison_messages (organization_id, project_id, environment_id, in_reply_to_message_id)
  WHERE role = 'LIAISON' AND supersedes_message_id IS NULL;

-- Parts are rows, not a rewritten JSON array: streaming appends cannot race,
-- and a completed part is immutable.
CREATE TABLE liaison_message_parts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  message_id text NOT NULL,
  sequence integer NOT NULL CHECK (sequence >= 0),
  kind text NOT NULL CHECK (kind IN
    ('text','claim','tool','catchup_delta','steer_draft','approval_ref','guidance_ref',
     'refusal','budget_note','parked_request','compaction','content_withheld',
     'interrupted','error')),
  schema_version integer NOT NULL CHECK (schema_version > 0),
  status text NOT NULL CHECK (status IN ('STREAMING','COMPLETED')),
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  access_mode text NOT NULL CHECK (access_mode IN
    ('RECORD_SET','PARTICIPANTS_AT_EPOCH','AUTHOR_ONLY','SYSTEM_PUBLIC',
     'DERIVED_SOURCES')),
  author_principal text,
  membership_epoch bigint,
  payload_json jsonb NOT NULL,
  access_set_hash text,
  -- Provider attempt fencing is nullable for user/compaction rows.  Every
  -- provider-produced completed or streaming part binds both values.
  attempt integer CHECK (attempt > 0),
  generation bigint CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, message_id, sequence),
  UNIQUE (organization_id, project_id, environment_id, id, message_id),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id)
    REFERENCES liaison_messages (organization_id, project_id, environment_id, id),
  CHECK (access_mode <> 'AUTHOR_ONLY' OR author_principal IS NOT NULL),
  CHECK (access_mode <> 'PARTICIPANTS_AT_EPOCH' OR membership_epoch IS NOT NULL),
  CHECK (access_mode <> 'DERIVED_SOURCES' OR kind = 'compaction'),
  CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
  CHECK ((attempt IS NULL) = (generation IS NULL))
);

-- A streaming row may be completed or discarded by its exact owner. Once it
-- is completed, no update can rewrite transcript history; the typed retention
-- service may still delete expired bodies.
CREATE FUNCTION liaison_message_part_mutation_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.status = 'COMPLETED' THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='completed liaison message parts are immutable';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER liaison_message_part_immutable
  BEFORE UPDATE OR DELETE ON liaison_message_parts
  FOR EACH ROW EXECUTE FUNCTION liaison_message_part_mutation_guard();

-- The access envelope. A `RECORD_SET` part with no rows here is invisible to
-- everyone: absence denies rather than defaulting to public.
CREATE TABLE liaison_part_access (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  part_id text NOT NULL,
  record_type text NOT NULL,
  record_id text NOT NULL,
  relation text NOT NULL CHECK (relation IN ('CITES','READ','EVENT','SUBJECT','SOURCE')),
  PRIMARY KEY (organization_id, project_id, environment_id,
               part_id, record_type, record_id, relation),
  FOREIGN KEY (organization_id, project_id, environment_id, part_id)
    REFERENCES liaison_message_parts (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, record_type, record_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id)
);

CREATE TABLE liaison_part_audience_principals (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  part_id text NOT NULL,
  principal text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, part_id, principal),
  FOREIGN KEY (organization_id, project_id, environment_id, part_id)
    REFERENCES liaison_message_parts (organization_id, project_id, environment_id, id)
);

-- Replayable public protocol events. Payloads are bounded typed activity and
-- transcript references, never prompts, raw model/tool output, or reasoning.
CREATE TABLE liaison_stream_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  thread_id text NOT NULL,
  stream_sequence bigint NOT NULL CHECK (stream_sequence > 0),
  event_id text NOT NULL CHECK (event_id ~ '^lev_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  event_type text NOT NULL CHECK (event_type IN
    ('turn.started','turn.queued','turn.activity','message.part.completed','turn.parked',
     'turn.completed','turn.interrupted','turn.error',
     'thread.membership.changed','thread.status.changed')),
  schema_version integer NOT NULL CHECK (schema_version > 0),
  message_id text,
  part_id text,
  attempt integer CHECK (attempt > 0),
  generation bigint CHECK (generation > 0),
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  access_mode text NOT NULL CHECK (access_mode IN
    ('RECORD_SET','PARTICIPANTS_AT_EPOCH','AUTHOR_ONLY','SYSTEM_PUBLIC')),
  audience_principal text,
  membership_epoch bigint,
  payload_json jsonb,
  payload_hash text NOT NULL,
  payload_purged_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
               thread_id, stream_sequence),
  UNIQUE (organization_id, project_id, environment_id, event_id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id, thread_id)
    REFERENCES liaison_messages
      (organization_id, project_id, environment_id, id, thread_id),
  FOREIGN KEY (organization_id, project_id, environment_id, part_id, message_id)
    REFERENCES liaison_message_parts
      (organization_id, project_id, environment_id, id, message_id),
  CHECK (access_mode <> 'AUTHOR_ONLY' OR audience_principal IS NOT NULL),
  CHECK (access_mode <> 'PARTICIPANTS_AT_EPOCH' OR membership_epoch IS NOT NULL),
  CHECK (access_mode <> 'RECORD_SET' OR part_id IS NOT NULL),
  CHECK ((attempt IS NULL) = (generation IS NULL)),
  CHECK (event_type <> 'message.part.completed' OR
         (message_id IS NOT NULL AND part_id IS NOT NULL)),
  CHECK (event_type NOT LIKE 'turn.%' OR
         (message_id IS NOT NULL AND attempt IS NOT NULL AND generation IS NOT NULL)),
  CHECK (event_type NOT LIKE 'thread.%' OR
         (message_id IS NULL AND part_id IS NULL AND attempt IS NULL AND generation IS NULL)),
  CHECK ((payload_json IS NULL) = (payload_purged_at IS NOT NULL))
);

-- A compaction's record access envelope answers who may read it; this source
-- relation answers which transcript bodies it was derived from. Keeping the
-- two facts separate makes source purge enforceable without treating message
-- identifiers as record-directory authority.
CREATE TABLE liaison_compaction_sources (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  compaction_part_id text NOT NULL,
  source_message_id text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id,
               compaction_part_id, source_message_id),
  FOREIGN KEY (organization_id, project_id, environment_id, compaction_part_id)
    REFERENCES liaison_message_parts
      (organization_id, project_id, environment_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, project_id, environment_id, source_message_id)
    REFERENCES liaison_messages
      (organization_id, project_id, environment_id, id) ON DELETE CASCADE
);

-- Attachments are quarantined until scanned; nothing reaches a model before
-- its verdict is CLEAN.
CREATE TABLE liaison_attachments (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  message_id text NOT NULL,
  object_ref text NOT NULL,
  content_hash text NOT NULL,
  mime text NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes > 0),
  scan_status text NOT NULL CHECK (scan_status IN ('PENDING','CLEAN','BLOCKED')),
  classification text CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  purge_after timestamptz NOT NULL,
  deleted_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id)
    REFERENCES liaison_messages (organization_id, project_id, environment_id, id)
);

CREATE TABLE liaison_channel_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^chb_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  channel_kind text NOT NULL CHECK (channel_kind IN ('EMAIL','SLACK','DISCORD','MCP')),
  channel_identity text NOT NULL,
  principal text NOT NULL,
  identity_proof_ref text NOT NULL,
  enrolled_at timestamptz NOT NULL,
  credential_secret_ref text,
  connection_epoch bigint NOT NULL DEFAULT 1 CHECK (connection_epoch > 0),
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL')),
  status text NOT NULL CHECK (status IN
    ('ENROLLING','ACTIVE','REAUTH_REQUIRED','REVOKING','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, channel_kind, channel_identity),
  -- Composite target so a subscription's channel kind cannot drift from its
  -- binding's: the MCP exclusion below depends on the two agreeing.
  UNIQUE (organization_id, project_id, environment_id, id, channel_kind),
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE liaison_enrollment_challenges (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  principal text NOT NULL,
  channel_kind text NOT NULL CHECK (channel_kind IN ('EMAIL','SLACK','DISCORD','MCP')),
  -- Slack/Discord identity is derived only from the signed provider event.
  -- Email names its exact intended address before relay dispatch.
  channel_identity text,
  nonce_hash text NOT NULL,
  callback_mechanism text NOT NULL,
  console_authenticated_at timestamptz NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  status text NOT NULL DEFAULT 'REQUESTED' CHECK (status IN
    ('REQUESTED','DISPATCHED','CONSUMED','CANCELLED','EXPIRED','FAILED')),
  dispatch_receipt_ref text,
  safe_reason_code text,
  dispatched_at timestamptz,
  consumed_at timestamptz,
  cancelled_at timestamptz,
  audit_ref text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  CHECK (expires_at > issued_at),
  CONSTRAINT liaison_enrollment_email_identity_ck
    CHECK (channel_kind IN ('SLACK','DISCORD') OR channel_identity IS NOT NULL),
  CONSTRAINT liaison_enrollment_dispatch_time_ck
    CHECK (status NOT IN ('DISPATCHED','CONSUMED') OR dispatched_at IS NOT NULL),
  CHECK (status <> 'REQUESTED' OR dispatched_at IS NULL),
  CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
  CONSTRAINT liaison_enrollment_consumed_identity_ck
    CHECK (status <> 'CONSUMED' OR channel_identity IS NOT NULL),
  CHECK ((status = 'CANCELLED') = (cancelled_at IS NOT NULL)),
  CHECK (status NOT IN ('FAILED','EXPIRED') OR safe_reason_code IS NOT NULL)
);
CREATE INDEX liaison_enrollment_principal_status
  ON liaison_enrollment_challenges
     (organization_id, project_id, environment_id, principal, status, issued_at DESC);

-- Immutable provider-health receipts. Configuration is never promoted to
-- READY without a bounded deployed-path probe and its external receipt.
CREATE TABLE liaison_channel_provider_health_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  channel_kind text NOT NULL CHECK (channel_kind IN ('EMAIL','SLACK','DISCORD','MCP')),
  deployment_id text NOT NULL CHECK (deployment_id ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
  service_revision text NOT NULL CHECK (length(service_revision) BETWEEN 1 AND 128),
  status text NOT NULL CHECK (status IN
    ('AVAILABLE','NEEDS_ATTENTION','DISABLED')),
  safe_reason_code text NOT NULL CHECK (safe_reason_code ~ '^[A-Z][A-Z0-9_]{2,79}$'),
  next_step_code text NOT NULL CHECK (next_step_code ~ '^[A-Z][A-Z0-9_]{2,79}$'),
  checked_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  receipt_ref text NOT NULL CONSTRAINT liaison_provider_health_receipt_ref_ck
    CHECK (receipt_ref ~ '^gs://[^/]+/.+'),
  receipt_hash text NOT NULL CONSTRAINT liaison_provider_health_receipt_hash_ck
    CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  CONSTRAINT liaison_provider_health_time_ck CHECK (expires_at > checked_at),
  CONSTRAINT liaison_provider_health_validity_ck
    CHECK (expires_at <= checked_at + interval '24 hours')
);
CREATE INDEX liaison_channel_provider_health_current
  ON liaison_channel_provider_health_receipts
     (organization_id, project_id, environment_id, channel_kind, checked_at DESC);

CREATE TABLE liaison_parked_requests (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^prk_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  thread_id text NOT NULL,
  message_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN
    ('QUESTION','PERMISSION','STEER_CONFIRMATION','SUBSCRIPTION_CONFIRMATION')),
  payload_json jsonb NOT NULL,
  payload_hash text NOT NULL,
  decided_payload_json jsonb,
  decided_payload_hash text,
  answer_audience text NOT NULL DEFAULT 'INITIATOR'
    CHECK (answer_audience IN ('INITIATOR','NAMED')),
  named_answerer_principal text,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  initiated_by_principal text NOT NULL,
  expected_workflow_version bigint,
  expected_plan_version integer,
  binding_id text,
  binding_epoch bigint,
  status text NOT NULL CHECK (status IN
    ('PENDING','ANSWERED','REJECTED','EXPIRED','WITHDRAWN')),
  answer_json jsonb,
  answered_by_principal text,
  decision_idempotency_key text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  answered_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id)
    REFERENCES liaison_messages (organization_id, project_id, environment_id, id),
  CHECK ((status IN ('ANSWERED','REJECTED'))
         = (answered_by_principal IS NOT NULL AND answered_at IS NOT NULL)),
  CHECK (answer_audience <> 'NAMED' OR named_answerer_principal IS NOT NULL),
  CHECK ((binding_id IS NULL) = (binding_epoch IS NULL))
);

CREATE TABLE liaison_subscriptions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^sub_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  principal text NOT NULL,
  anchor_kind text NOT NULL CHECK (anchor_kind IN ('RECORD','SERVICE_WINDOW','SCOPE')),
  anchor_record_type text,
  anchor_record_id text,
  anchor_service_key text,
  anchor_window_start timestamptz,
  anchor_window_end timestamptz,
  channel_binding_id text,
  channel_kind text,
  external_conversation_id text,
  cadence text NOT NULL CHECK (cadence IN ('ON_EVENT','DAILY_DIGEST','ON_CLOSE')),
  consent_kind text NOT NULL CHECK (consent_kind IN ('PARKED_REQUEST','CONSOLE_ACTION')),
  consent_ref text NOT NULL,
  last_delivered_sequence bigint NOT NULL DEFAULT 0 CHECK (last_delivered_sequence >= 0),
  policy_epoch bigint NOT NULL DEFAULT 1 CHECK (policy_epoch > 0),
  next_delivery_at timestamptz,
  expires_at timestamptz,
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  status text NOT NULL CHECK (status IN ('ACTIVE','ENDED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               anchor_record_type, anchor_record_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id),
  FOREIGN KEY (organization_id, project_id, environment_id, channel_binding_id, channel_kind)
    REFERENCES liaison_channel_bindings
      (organization_id, project_id, environment_id, id, channel_kind),
  -- MCP is client-initiated, so there is no push path to it. The exclusion is
  -- a constraint rather than a convention.
  CHECK (channel_kind IS DISTINCT FROM 'MCP'),
  CHECK ((channel_binding_id IS NULL) = (external_conversation_id IS NULL)),
  -- A record anchor closes with its record; scope and service anchors never
  -- close by themselves, so they must carry an expiry.
  CHECK (anchor_kind = 'RECORD' OR expires_at IS NOT NULL),
  CHECK ((status = 'ENDED') = (ended_at IS NOT NULL)),
  CHECK (status = 'ACTIVE' OR
    (claim_owner IS NULL AND claim_token IS NULL AND claim_expires_at IS NULL)),
  CHECK ((claim_owner IS NULL AND claim_token IS NULL AND claim_expires_at IS NULL)
         OR (claim_owner IS NOT NULL AND claim_token IS NOT NULL
             AND claim_expires_at IS NOT NULL)),
  CHECK (
    (anchor_kind = 'RECORD'
      AND anchor_record_type IS NOT NULL AND anchor_record_id IS NOT NULL
      AND anchor_service_key IS NULL
      AND anchor_window_start IS NULL AND anchor_window_end IS NULL)
    OR
    (anchor_kind = 'SERVICE_WINDOW'
      AND anchor_record_type IS NULL AND anchor_record_id IS NULL
      AND anchor_service_key IS NOT NULL
      AND anchor_window_start IS NOT NULL
      AND anchor_window_end > anchor_window_start)
    OR
    (anchor_kind = 'SCOPE'
      AND anchor_record_type IS NULL AND anchor_record_id IS NULL
      AND anchor_service_key IS NULL
      AND anchor_window_start IS NULL AND anchor_window_end IS NULL)
  )
);

CREATE UNIQUE INDEX liaison_subscription_unique_active
  ON liaison_subscriptions
     (organization_id, project_id, environment_id, principal, anchor_kind,
      coalesce(anchor_record_type, ''), coalesce(anchor_record_id, ''),
      coalesce(anchor_service_key, ''), coalesce(channel_binding_id, ''))
  WHERE status = 'ACTIVE';

CREATE TABLE liaison_channel_threads (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  binding_id text NOT NULL,
  binding_epoch bigint NOT NULL CHECK (binding_epoch > 0),
  external_conversation_id text NOT NULL,
  thread_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','STOPPED','REVOKED')),
  enrolled_at timestamptz NOT NULL DEFAULT now(),
  stopped_at timestamptz,
  stop_reason text CHECK (stop_reason IN
    ('USER_STOPPED','BINDING_REVOKED','BINDING_SUPERSEDED','MEMBERSHIP_ENDED','THREAD_ARCHIVED')),
  PRIMARY KEY (organization_id, project_id, environment_id,
               binding_id, external_conversation_id),
  FOREIGN KEY (organization_id, project_id, environment_id, binding_id)
    REFERENCES liaison_channel_bindings (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id),
  CHECK ((status = 'ACTIVE') = (stopped_at IS NULL AND stop_reason IS NULL))
);

CREATE INDEX liaison_channel_threads_active
  ON liaison_channel_threads
     (organization_id, project_id, environment_id, binding_id, binding_epoch,
      external_conversation_id)
  WHERE status = 'ACTIVE';

ALTER TABLE liaison_subscriptions
  ADD FOREIGN KEY (organization_id, project_id, environment_id,
                   channel_binding_id, external_conversation_id)
  REFERENCES liaison_channel_threads
    (organization_id, project_id, environment_id,
     binding_id, external_conversation_id);

CREATE TABLE liaison_inbound_events (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  binding_id text NOT NULL,
  binding_epoch bigint NOT NULL,
  external_event_id text NOT NULL,
  payload_hash text NOT NULL,
  thread_id text,
  message_id text,
  status text NOT NULL DEFAULT 'RECEIVED' CHECK
    (status IN ('RECEIVED','PENDING','CLAIMED','COMPLETED','FAILED','FENCED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  claim_owner text,
  claim_token uuid,
  claim_expires_at timestamptz,
  next_attempt_at timestamptz,
  terminal_reason text,
  received_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, binding_id, external_event_id),
  FOREIGN KEY (organization_id, project_id, environment_id, binding_id)
    REFERENCES liaison_channel_bindings (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES liaison_threads (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id)
    REFERENCES liaison_messages (organization_id, project_id, environment_id, id),
  CHECK ((thread_id IS NULL) = (message_id IS NULL)),
  CHECK (status <> 'RECEIVED' OR message_id IS NULL),
  CHECK (status NOT IN ('PENDING','CLAIMED','COMPLETED','FAILED') OR message_id IS NOT NULL),
  CHECK (status <> 'CLAIMED' OR
    (claim_owner IS NOT NULL AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CHECK (status = 'CLAIMED' OR
    (claim_owner IS NULL AND claim_token IS NULL AND claim_expires_at IS NULL)),
  CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL))
);
CREATE INDEX liaison_inbound_due ON liaison_inbound_events
  (organization_id, project_id, environment_id, status, next_attempt_at, received_at);

-- Delivery is at-least-once and says so. A direct answer to a channel question
-- and a subscription interval are both deliveries; neither can masquerade as
-- the other.
CREATE TABLE liaison_deliveries (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  delivery_kind text NOT NULL CHECK (delivery_kind IN
    ('DIRECT_MESSAGE','SUBSCRIPTION_DELTA')),
  source_message_id text,
  subscription_id text,
  binding_id text NOT NULL,
  binding_epoch bigint NOT NULL,
  from_sequence bigint,
  to_sequence bigint,
  policy_epoch bigint NOT NULL,
  payload_ref text NOT NULL,
  payload_hash text NOT NULL,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  redaction_verdict_ref text NOT NULL,
  access_set_hash text NOT NULL,
  provider_idempotency_key text,
  provider_message_id text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  lease_owner text,
  lease_token uuid,
  lease_expires_at timestamptz,
  status text NOT NULL CHECK (status IN
    ('PENDING','SENDING','DELIVERED','FAILED','FENCED')),
  next_attempt_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  -- The receipt outlives the payload. Retention removes what was said off the
  -- channel while the record that it was said, to whom, and under which policy
  -- epoch stays. A reader can tell the difference, so a dangling payload_ref is
  -- never mistaken for a body that is still fetchable.
  payload_purged_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, binding_id)
    REFERENCES liaison_channel_bindings (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, source_message_id)
    REFERENCES liaison_messages (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, subscription_id)
    REFERENCES liaison_subscriptions (organization_id, project_id, environment_id, id),
  CHECK ((delivery_kind = 'DIRECT_MESSAGE') = (source_message_id IS NOT NULL)),
  CHECK ((delivery_kind = 'SUBSCRIPTION_DELTA')
         = (subscription_id IS NOT NULL
            AND from_sequence IS NOT NULL AND to_sequence IS NOT NULL)),
  CHECK ((status = 'DELIVERED') = (delivered_at IS NOT NULL)),
  CHECK (status <> 'SENDING' OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK (status = 'SENDING' OR
    (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL))
);

CREATE UNIQUE INDEX liaison_delivery_direct_once
  ON liaison_deliveries
     (organization_id, project_id, environment_id, source_message_id, binding_id)
  WHERE delivery_kind = 'DIRECT_MESSAGE';

CREATE UNIQUE INDEX liaison_delivery_interval_once
  ON liaison_deliveries
     (organization_id, project_id, environment_id, subscription_id,
      from_sequence, to_sequence)
  WHERE delivery_kind = 'SUBSCRIPTION_DELTA';

-- A scan advances past hidden events without inventing a visible delivery.
-- The receipt makes every cursor movement auditable; a visible scan binds the
-- exact delivery row created in the same transaction.
CREATE TABLE liaison_subscription_scans (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  subscription_id text NOT NULL,
  from_sequence bigint NOT NULL CHECK (from_sequence >= 0),
  to_sequence bigint NOT NULL CHECK (to_sequence >= from_sequence),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  visible_delta_count integer NOT NULL CHECK (visible_delta_count >= 0),
  delivery_id text,
  outcome text NOT NULL CHECK (outcome IN ('NO_VISIBLE_DELTA','DELIVERY_QUEUED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, subscription_id)
    REFERENCES liaison_subscriptions (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, delivery_id)
    REFERENCES liaison_deliveries (organization_id, project_id, environment_id, id),
  CHECK ((outcome = 'DELIVERY_QUEUED') = (delivery_id IS NOT NULL)),
  CHECK (outcome <> 'NO_VISIBLE_DELTA' OR visible_delta_count = 0),
  UNIQUE (organization_id, project_id, environment_id, subscription_id,
          from_sequence, to_sequence, policy_epoch)
);

-- Turn execution. QUEUED and PARKED turns hold no lease. A thread has at most
-- one RUNNING/READY execution lane, while parked human decisions and durable
-- queued follow-ups remain independently addressable.
CREATE TABLE liaison_turns (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  message_id text NOT NULL,
  thread_id text NOT NULL,
  request_hash text NOT NULL,
  conversation_intent text NOT NULL CHECK (conversation_intent IN
    ('SOCIAL','HELP','LEDGER_QUERY','FOLLOW_UP','STEER_DRAFT',
     'ACTION_REFERENCE','OUT_OF_SCOPE')),
  authority_route text NOT NULL CHECK (authority_route IN
    ('NONE','ASK','STEER','ACT_SURFACE_ONLY')),
  attempt integer NOT NULL CHECK (attempt > 0),
  generation bigint NOT NULL CHECK (generation > 0),
  queue_sequence bigint CHECK (queue_sequence > 0),
  queued_at timestamptz,
  lease_owner text,
  lease_token uuid,
  lease_expires_at timestamptz,
  heartbeat_at timestamptz,
  service_revision text,
  process_boot_id text,
  model_session_ref text,
  model_calls integer NOT NULL DEFAULT 0 CHECK (model_calls >= 0),
  tool_calls integer NOT NULL DEFAULT 0 CHECK (tool_calls >= 0),
  tokens bigint NOT NULL DEFAULT 0 CHECK (tokens >= 0),
  status text NOT NULL CHECK (status IN
    ('QUEUED','RUNNING','PARKED','READY','COMPLETED','INTERRUPTED','FAILED')),
  terminal_reason text CHECK (terminal_reason IN
    ('ANSWER_COMPLETED','PARKED_ANSWER_ACCEPTED',
     'USER_CANCELLED_BEFORE_START','USER_ABORTED','STOP_AND_SEND',
     'LEASE_EXPIRED','POLICY_REVOKED','PARKED_EXPIRED','PARKED_REJECTED',
     'TURN_ERROR','BUDGET_EXHAUSTED','MANIFEST_INVALID','PROVIDER_FAILURE',
     'INPUT_REFRESH_REQUIRED')),
  started_at timestamptz,
  ended_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, message_id, attempt),
  UNIQUE (organization_id,project_id,environment_id,message_id,attempt,generation),
  UNIQUE (organization_id, project_id, environment_id, thread_id, queue_sequence),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id, thread_id)
    REFERENCES liaison_messages
      (organization_id, project_id, environment_id, id, thread_id),
  CHECK ((conversation_intent IN ('SOCIAL','HELP','OUT_OF_SCOPE')) =
         (authority_route = 'NONE')),
  CHECK ((conversation_intent IN ('LEDGER_QUERY','FOLLOW_UP')) =
         (authority_route = 'ASK')),
  CHECK ((conversation_intent = 'STEER_DRAFT') =
         (authority_route = 'STEER')),
  CHECK ((conversation_intent = 'ACTION_REFERENCE') =
         (authority_route = 'ACT_SURFACE_ONLY')),
  CHECK ((queue_sequence IS NULL) = (queued_at IS NULL)),
  CHECK (status <> 'QUEUED' OR queue_sequence IS NOT NULL),
  CHECK ((status = 'RUNNING') =
         (lease_owner IS NOT NULL AND lease_token IS NOT NULL
          AND lease_expires_at IS NOT NULL)),
  CHECK (status = 'RUNNING' OR heartbeat_at IS NULL),
  CHECK (status NOT IN ('RUNNING','PARKED','COMPLETED','FAILED')
         OR started_at IS NOT NULL),
  CHECK ((status IN ('COMPLETED','INTERRUPTED','FAILED')) = (ended_at IS NOT NULL)),
  CHECK (
    (status = 'COMPLETED' AND terminal_reason IN
      ('ANSWER_COMPLETED','PARKED_ANSWER_ACCEPTED'))
    OR
    (status = 'INTERRUPTED' AND terminal_reason IN
      ('USER_CANCELLED_BEFORE_START','USER_ABORTED','STOP_AND_SEND','INPUT_REFRESH_REQUIRED',
       'LEASE_EXPIRED','POLICY_REVOKED','PARKED_EXPIRED','PARKED_REJECTED'))
    OR
    (status = 'FAILED' AND terminal_reason IN
      ('TURN_ERROR','BUDGET_EXHAUSTED','MANIFEST_INVALID','PROVIDER_FAILURE'))
    OR
    (status IN ('QUEUED','RUNNING','PARKED','READY') AND terminal_reason IS NULL)
  )
);

CREATE UNIQUE INDEX liaison_turn_one_nonterminal_attempt
  ON liaison_turns (organization_id, project_id, environment_id, message_id)
  WHERE status IN ('QUEUED','RUNNING','PARKED','READY');

CREATE UNIQUE INDEX liaison_turn_one_thread_lane
  ON liaison_turns (organization_id, project_id, environment_id, thread_id)
  WHERE status IN ('RUNNING','READY');

CREATE UNIQUE INDEX liaison_turn_one_provider_session
  ON liaison_turns
    (organization_id, project_id, environment_id, model_session_ref)
  WHERE model_session_ref IS NOT NULL;

CREATE INDEX liaison_turn_queue_claim
  ON liaison_turns
    (organization_id, project_id, environment_id, thread_id, queue_sequence)
  WHERE status = 'QUEUED';

ALTER TABLE liaison_message_parts
  ADD FOREIGN KEY (organization_id, project_id, environment_id,
                   message_id, attempt, generation)
    REFERENCES liaison_turns
      (organization_id, project_id, environment_id, message_id, attempt, generation);

-- Immutable, pre-dispatch input. The JSON contains references and version
-- digests only; the user-authored body remains in its governed message part.
-- The application validates the closed schema and digest before dispatch.
CREATE TABLE liaison_context_compiler_revisions (
  compiler_version text PRIMARY KEY,
  manifest_schema_version integer NOT NULL CHECK (manifest_schema_version = 2),
  compiler_digest text NOT NULL UNIQUE CHECK (compiler_digest ~ '^sha256:[0-9a-f]{64}$'),
  tokenizer_id text NOT NULL,
  tokenizer_digest text NOT NULL CHECK (tokenizer_digest ~ '^sha256:[0-9a-f]{64}$'),
  manifest_schema_uri text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (compiler_version, manifest_schema_version),
  UNIQUE (compiler_version,manifest_schema_version,compiler_digest,tokenizer_digest)
);

INSERT INTO liaison_context_compiler_revisions (
  compiler_version,manifest_schema_version,compiler_digest,tokenizer_id,
  tokenizer_digest,manifest_schema_uri)
VALUES (
  'liaison-context-v2',2,
  'sha256:5925664d93bf85988250484fcb9ee6b5cd2274b15266e002a6bdb7094b61fe82',
  'utf8-byte-upper-bound-v1',
  'sha256:42c5f1895b007e8036306b2154a6fb945744fb725844b771847d621ff6ca3b67',
  'https://solvan.dev/schemas/liaison-turn-input-manifest-v2.json'
);

-- Activation is append-only history, never a mutable flag on a revision.
-- The application selects only the highest epoch and accepts it only when its
-- decision is ACTIVATE. REVOKE carries no compiler and fails closed.
CREATE TABLE liaison_context_compiler_bindings (
  binding_key text NOT NULL DEFAULT 'TURN_INPUT_MANIFEST_V2'
    CHECK (binding_key = 'TURN_INPUT_MANIFEST_V2'),
  binding_epoch bigint NOT NULL CHECK (binding_epoch > 0),
  decision text NOT NULL CHECK (decision IN ('ACTIVATE','REVOKE')),
  compiler_version text,
  manifest_schema_version integer,
  decision_ref text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (binding_key,binding_epoch),
  UNIQUE (binding_epoch,compiler_version),
  FOREIGN KEY (compiler_version,manifest_schema_version)
    REFERENCES liaison_context_compiler_revisions
      (compiler_version,manifest_schema_version),
  CHECK ((decision = 'ACTIVATE') =
         (compiler_version IS NOT NULL AND manifest_schema_version IS NOT NULL))
);
INSERT INTO liaison_context_compiler_bindings
  (binding_epoch,decision,compiler_version,manifest_schema_version,decision_ref)
VALUES (1,'ACTIVATE','liaison-context-v2',2,'ref_liaison_context_v2');

CREATE TABLE liaison_turn_input_manifests (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  message_id text NOT NULL,
  attempt integer NOT NULL CHECK (attempt > 0),
  generation bigint NOT NULL CHECK (generation > 0),
  schema_version integer NOT NULL CHECK (schema_version = 2),
  manifest_json jsonb NOT NULL CHECK (jsonb_typeof(manifest_json) = 'object'),
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  reader_principal text NOT NULL,
  read_grant_id text NOT NULL,
  compiler_version text NOT NULL,
  compiler_binding_epoch bigint NOT NULL CHECK (compiler_binding_epoch > 0),
  compiler_digest text NOT NULL CHECK (compiler_digest ~ '^sha256:[0-9a-f]{64}$'),
  tokenizer_digest text NOT NULL CHECK (tokenizer_digest ~ '^sha256:[0-9a-f]{64}$'),
  model_resource text NOT NULL,
  template_registry_digest text NOT NULL CHECK (template_registry_digest ~ '^sha256:[0-9a-f]{64}$'),
  tool_registry_digest text NOT NULL CHECK (tool_registry_digest ~ '^sha256:[0-9a-f]{64}$'),
  read_grant_digest text NOT NULL CHECK (read_grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  stable_prefix_digest text NOT NULL CHECK (stable_prefix_digest ~ '^sha256:[0-9a-f]{64}$'),
  variable_suffix_digest text NOT NULL CHECK (variable_suffix_digest ~ '^sha256:[0-9a-f]{64}$'),
  context_digest text NOT NULL CHECK (context_digest ~ '^sha256:[0-9a-f]{64}$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  purpose text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL')),
  region text NOT NULL,
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  membership_epoch bigint NOT NULL CHECK (membership_epoch > 0),
  scope_sequence_high_water bigint NOT NULL CHECK (scope_sequence_high_water >= 0),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, message_id, attempt),
  FOREIGN KEY (organization_id,project_id,environment_id,message_id,attempt,generation)
    REFERENCES liaison_turns
      (organization_id,project_id,environment_id,message_id,attempt,generation)
      ON DELETE CASCADE,
  FOREIGN KEY (compiler_version,schema_version,compiler_digest,tokenizer_digest)
    REFERENCES liaison_context_compiler_revisions
      (compiler_version,manifest_schema_version,compiler_digest,tokenizer_digest),
  FOREIGN KEY (compiler_binding_epoch,compiler_version)
    REFERENCES liaison_context_compiler_bindings(binding_epoch,compiler_version),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES solvan_scale.tenant_placements
      (organization_id, placement_epoch, cell_id),
  CHECK (manifest_json ->> 'schema_version' = schema_version::text),
  CHECK (manifest_json #>> '{scope,organization_id}' = organization_id),
  CHECK (manifest_json #>> '{scope,project_id}' = project_id),
  CHECK (manifest_json #>> '{scope,environment_id}' = environment_id),
  CHECK (manifest_json ->> 'reader_principal' = reader_principal),
  CHECK (manifest_json ->> 'cell_id' = cell_id),
  CHECK ((manifest_json ->> 'placement_epoch')::bigint = placement_epoch),
  CHECK (manifest_json ->> 'purpose' = purpose),
  CHECK (manifest_json ->> 'classification_ceiling' = classification_ceiling),
  CHECK (manifest_json ->> 'region' = region),
  CHECK (manifest_json #>> '{working_context,compiler_version}' = compiler_version),
  CHECK ((manifest_json #>> '{working_context,compiler_binding_epoch}')::bigint =
         compiler_binding_epoch),
  CHECK (manifest_json #>> '{working_context,compiler_digest}' = compiler_digest),
  CHECK (manifest_json #>> '{working_context,tokenizer_digest}' = tokenizer_digest),
  CHECK (manifest_json #>> '{working_context,model_resource}' = model_resource),
  CHECK (manifest_json #>> '{working_context,template_registry_digest}' = template_registry_digest),
  CHECK (manifest_json #>> '{working_context,tool_registry_digest}' = tool_registry_digest),
  CHECK (manifest_json #>> '{working_context,read_grant_digest}' = read_grant_digest),
  CHECK (manifest_json #>> '{working_context,stable_prefix_digest}' = stable_prefix_digest),
  CHECK (manifest_json #>> '{working_context,variable_suffix_digest}' = variable_suffix_digest),
  CHECK (manifest_json #>> '{working_context,context_digest}' = context_digest),
  CHECK ((manifest_json ->> 'scope_sequence_high_water')::bigint = scope_sequence_high_water),
  CHECK ((manifest_json #>> '{working_context,expires_at}')::timestamptz = expires_at),
  CHECK (expires_at > created_at)
);

-- One immutable request identity is prepared in the same transaction that
-- claims the turn. The external provider call may begin only after a separate
-- CAS records DISPATCHED. The request stores no prompt body: the exact bytes
-- are reproducible from the immutable manifest and current-user source row,
-- and their digest is bound here without duplicating governed user content.
CREATE TABLE liaison_provider_requests (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^prq_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  message_id text NOT NULL,
  attempt integer NOT NULL CHECK (attempt > 0),
  generation bigint NOT NULL CHECK (generation > 0),
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_input_digest text NOT NULL
    CHECK (provider_input_digest ~ '^sha256:[0-9a-f]{64}$'),
  provider_input_bytes bigint NOT NULL CHECK (provider_input_bytes > 0),
  model_resource text NOT NULL,
  service_revision text NOT NULL,
  process_boot_id text NOT NULL,
  state text NOT NULL CHECK (state IN
    ('PREPARED','DISPATCHED','COMPLETED','FAILED','NOT_SENT','FENCED')),
  dispatch_count integer NOT NULL DEFAULT 0 CHECK (dispatch_count >= 0),
  prepared_at timestamptz NOT NULL DEFAULT now(),
  dispatched_at timestamptz,
  terminal_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,message_id,attempt,generation),
  FOREIGN KEY (organization_id,project_id,environment_id,message_id,attempt)
    REFERENCES liaison_turn_input_manifests
      (organization_id,project_id,environment_id,message_id,attempt)
      ON DELETE CASCADE,
  CHECK ((state IN ('DISPATCHED','COMPLETED','FAILED')) =
         (dispatched_at IS NOT NULL)),
  CHECK ((state = 'PREPARED' OR state IN ('NOT_SENT','FENCED')) OR dispatch_count > 0),
  CHECK (state <> 'PREPARED' OR dispatch_count = 0),
  CHECK ((state IN ('COMPLETED','FAILED','NOT_SENT','FENCED')) =
         (terminal_at IS NOT NULL)),
  CHECK (terminal_at IS NULL OR terminal_at >= prepared_at),
  CHECK (dispatched_at IS NULL OR dispatched_at >= prepared_at)
);

CREATE INDEX liaison_provider_requests_by_state
  ON liaison_provider_requests
    (organization_id,project_id,environment_id,state,prepared_at);

CREATE FUNCTION liaison_reject_manifest_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'liaison compiler history and turn input manifests are immutable'
    USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER liaison_turn_input_manifest_immutable
  BEFORE UPDATE ON liaison_turn_input_manifests
  FOR EACH ROW EXECUTE FUNCTION liaison_reject_manifest_update();

CREATE FUNCTION liaison_enforce_provider_request_transition() RETURNS trigger AS $$
BEGIN
  IF NEW.organization_id <> OLD.organization_id OR
     NEW.project_id <> OLD.project_id OR
     NEW.environment_id <> OLD.environment_id OR
     NEW.id <> OLD.id OR NEW.message_id <> OLD.message_id OR
     NEW.attempt <> OLD.attempt OR NEW.generation <> OLD.generation OR
     NEW.manifest_hash <> OLD.manifest_hash OR
     NEW.provider_input_digest <> OLD.provider_input_digest OR
     NEW.provider_input_bytes <> OLD.provider_input_bytes OR
     NEW.model_resource <> OLD.model_resource OR
     NEW.service_revision <> OLD.service_revision OR
     NEW.process_boot_id <> OLD.process_boot_id OR
     NEW.prepared_at <> OLD.prepared_at THEN
    RAISE EXCEPTION 'liaison provider request identity is immutable'
      USING ERRCODE='55000';
  END IF;
  IF NOT (
    (OLD.state='PREPARED' AND NEW.state IN ('DISPATCHED','NOT_SENT','FENCED')) OR
    (OLD.state='DISPATCHED' AND NEW.state IN ('DISPATCHED','COMPLETED','FAILED','FENCED'))
  ) THEN
    RAISE EXCEPTION 'illegal liaison provider request transition % -> %',
      OLD.state, NEW.state USING ERRCODE='23514';
  END IF;
  IF NEW.state='DISPATCHED' AND NEW.dispatch_count <> OLD.dispatch_count + 1 THEN
    RAISE EXCEPTION 'provider dispatch count must increase by one'
      USING ERRCODE='23514';
  ELSIF NEW.state <> 'DISPATCHED' AND NEW.dispatch_count <> OLD.dispatch_count THEN
    RAISE EXCEPTION 'provider dispatch count changes only at dispatch'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER liaison_provider_request_transition
  BEFORE UPDATE ON liaison_provider_requests
  FOR EACH ROW EXECUTE FUNCTION liaison_enforce_provider_request_transition();

CREATE TRIGGER liaison_provider_request_no_delete
  BEFORE DELETE ON liaison_provider_requests
  FOR EACH ROW EXECUTE FUNCTION liaison_reject_manifest_update();

CREATE TRIGGER liaison_context_compiler_revision_immutable
  BEFORE UPDATE OR DELETE ON liaison_context_compiler_revisions
  FOR EACH ROW EXECUTE FUNCTION liaison_reject_manifest_update();

CREATE TRIGGER liaison_context_compiler_binding_immutable
  BEFORE UPDATE OR DELETE ON liaison_context_compiler_bindings
  FOR EACH ROW EXECUTE FUNCTION liaison_reject_manifest_update();

CREATE FUNCTION liaison_enforce_compiler_binding_epoch() RETURNS trigger AS $$
DECLARE latest bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(197214,hashtext(NEW.binding_key));
  SELECT max(binding_epoch) INTO latest FROM liaison_context_compiler_bindings
   WHERE binding_key=NEW.binding_key;
  IF latest IS NOT NULL AND NEW.binding_epoch <= latest THEN
    RAISE EXCEPTION 'compiler binding epoch must increase' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER liaison_context_compiler_binding_epoch_monotonic
  BEFORE INSERT ON liaison_context_compiler_bindings
  FOR EACH ROW EXECUTE FUNCTION liaison_enforce_compiler_binding_epoch();

-- Cross-table invariants require deferred constraint triggers because message,
-- turn, and manifest rows are intentionally committed in one transaction.
CREATE FUNCTION liaison_assert_message_turn_alignment() RETURNS trigger AS $$
DECLARE
  checked_message_id text;
  checked_organization_id text;
  checked_project_id text;
  checked_environment_id text;
  message_state text;
  current_turn_state text;
BEGIN
  IF TG_TABLE_NAME = 'liaison_messages' THEN
    checked_message_id := NEW.id;
  ELSE
    checked_message_id := NEW.message_id;
  END IF;
  checked_organization_id := NEW.organization_id;
  checked_project_id := NEW.project_id;
  checked_environment_id := NEW.environment_id;

  SELECT turn_state INTO message_state
    FROM solvan_liaison.liaison_messages
   WHERE organization_id = checked_organization_id
     AND project_id = checked_project_id
     AND environment_id = checked_environment_id
     AND id = checked_message_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT status INTO current_turn_state
    FROM solvan_liaison.liaison_turns
   WHERE organization_id = checked_organization_id
     AND project_id = checked_project_id
     AND environment_id = checked_environment_id
     AND message_id = checked_message_id
   ORDER BY (status IN ('QUEUED','READY','RUNNING','PARKED')) DESC,
            attempt DESC
  LIMIT 1;
  IF NOT FOUND THEN
    -- Deterministic parked Steer drafts have a parked-request row but no
    -- model turn. Whenever a turn does exist, its state must agree exactly.
    RETURN NULL;
  END IF;

  IF message_state IS DISTINCT FROM current_turn_state THEN
    RAISE EXCEPTION 'liaison message state % disagrees with current turn state %',
      message_state, current_turn_state USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER liaison_turn_message_alignment_from_turn
  AFTER INSERT OR UPDATE ON liaison_turns
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_message_turn_alignment();

CREATE CONSTRAINT TRIGGER liaison_turn_message_alignment_from_message
  AFTER INSERT OR UPDATE ON liaison_messages
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_message_turn_alignment();

CREATE FUNCTION liaison_assert_turn_manifest() RETURNS trigger AS $$
DECLARE
  checked_organization_id text;
  checked_project_id text;
  checked_environment_id text;
  checked_message_id text;
  checked_attempt integer;
  checked_status text;
BEGIN
  IF TG_TABLE_NAME = 'liaison_turns' THEN
    checked_organization_id := NEW.organization_id;
    checked_project_id := NEW.project_id;
    checked_environment_id := NEW.environment_id;
    checked_message_id := NEW.message_id;
    checked_attempt := NEW.attempt;
    checked_status := NEW.status;
  ELSE
    checked_organization_id := OLD.organization_id;
    checked_project_id := OLD.project_id;
    checked_environment_id := OLD.environment_id;
    checked_message_id := OLD.message_id;
    checked_attempt := OLD.attempt;
    SELECT status INTO checked_status FROM solvan_liaison.liaison_turns
     WHERE organization_id = checked_organization_id
       AND project_id = checked_project_id
       AND environment_id = checked_environment_id
       AND message_id = checked_message_id
       AND attempt = checked_attempt;
    IF NOT FOUND THEN
      RETURN NULL;
    END IF;
  END IF;

  IF checked_status IN ('QUEUED','READY','RUNNING','PARKED') AND NOT EXISTS (
    SELECT 1 FROM solvan_liaison.liaison_turn_input_manifests manifest
     WHERE manifest.organization_id = checked_organization_id
       AND manifest.project_id = checked_project_id
       AND manifest.environment_id = checked_environment_id
       AND manifest.message_id = checked_message_id
       AND manifest.attempt = checked_attempt
  ) THEN
    RAISE EXCEPTION 'nonterminal liaison turn has no input manifest'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER liaison_turn_requires_manifest
  AFTER INSERT OR UPDATE ON liaison_turns
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_turn_manifest();

CREATE CONSTRAINT TRIGGER liaison_manifest_cannot_leave_dispatchable_turn
  AFTER DELETE OR UPDATE ON liaison_turn_input_manifests
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_turn_manifest();

CREATE TABLE liaison_grant_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  grant_kind text NOT NULL CHECK (grant_kind IN
    ('CONVERSATION_READ','PROJECTION_READ','STEER_SUBMISSION')),
  principal text NOT NULL,
  thread_id text,
  message_id text,
  attempt integer CHECK (attempt > 0),
  generation bigint CHECK (generation > 0),
  operation_id text,
  anchor_label text,
  entity_set_digest text CHECK (entity_set_digest IS NULL OR
    entity_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  parked_request_id text,
  purpose text,
  classification_ceiling text CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL')),
  membership_epoch bigint CHECK (membership_epoch > 0),
  audience text NOT NULL CHECK (audience IN ('PROJECTION_API','COORDINATOR_INBOX')),
  allowed_projection_methods text[] NOT NULL DEFAULT '{}'::text[] CHECK
    (allowed_projection_methods <@ ARRAY[
      'read_projection','get_record','get_evidence','get_action','get_verification',
      'get_case','get_patch','recall_conversation','list_directory','list_questions',
      'list_threads','read_transcript','read_events','catch_up','list_subscriptions',
      'list_channel_bindings','list_channel_provider_health','list_participants',
      'list_access_requests',
      'read_attachment','resolve_selection']::text[]),
  grant_digest text NOT NULL CHECK (grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  audit_ref text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id,
          id, principal, message_id, policy_epoch),
  CHECK (expires_at > issued_at),
  -- A turn read grant is reusable within its turn. A direct projection read
  -- is request-scoped and is recorded only after that read completes. A steer
  -- grant is spent once.
  CONSTRAINT liaison_conversation_read_grant_shape_ck CHECK
         ((grant_kind = 'CONVERSATION_READ') =
         (thread_id IS NOT NULL AND message_id IS NOT NULL AND attempt IS NOT NULL AND
          generation IS NOT NULL AND purpose IS NOT NULL AND
          classification_ceiling IS NOT NULL AND membership_epoch IS NOT NULL AND
          audience = 'PROJECTION_API' AND cardinality(allowed_projection_methods) > 0)),
  CONSTRAINT liaison_projection_read_grant_shape_ck CHECK
         (grant_kind <> 'PROJECTION_READ' OR
         (thread_id IS NULL AND message_id IS NULL AND attempt IS NULL AND
          generation IS NULL AND operation_id IS NOT NULL AND anchor_label IS NOT NULL AND
          entity_set_digest IS NOT NULL AND purpose IS NOT NULL AND
          classification_ceiling IS NOT NULL AND audience = 'PROJECTION_API' AND
          cardinality(allowed_projection_methods) = 1 AND consumed_at IS NOT NULL)),
  CONSTRAINT liaison_steer_grant_shape_ck CHECK
         (grant_kind IN ('CONVERSATION_READ','PROJECTION_READ') OR
         (parked_request_id IS NOT NULL AND audience = 'COORDINATOR_INBOX' AND
          cardinality(allowed_projection_methods) = 0)),
  FOREIGN KEY (organization_id,project_id,environment_id,message_id,attempt,generation)
    REFERENCES liaison_turns
      (organization_id,project_id,environment_id,message_id,attempt,generation)
      ON DELETE CASCADE
);
CREATE TRIGGER liaison_grant_receipt_immutable
  BEFORE UPDATE ON liaison_grant_receipts
  FOR EACH ROW EXECUTE FUNCTION liaison_reject_manifest_update();

CREATE INDEX liaison_projection_read_receipt_lookup
  ON liaison_grant_receipts
    (organization_id,project_id,environment_id,principal,issued_at DESC)
  WHERE grant_kind='PROJECTION_READ';

ALTER TABLE liaison_turn_input_manifests
  ADD FOREIGN KEY (organization_id,project_id,environment_id,
                   read_grant_id,reader_principal,message_id,policy_epoch)
    REFERENCES liaison_grant_receipts
      (organization_id, project_id, environment_id,
       id, principal, message_id, policy_epoch);

CREATE FUNCTION liaison_assert_manifest_grant_binding() RETURNS trigger AS $$
DECLARE grant_row liaison_grant_receipts%ROWTYPE;
BEGIN
  SELECT * INTO grant_row FROM liaison_grant_receipts
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=NEW.read_grant_id;
  IF NOT FOUND OR grant_row.grant_kind <> 'CONVERSATION_READ' OR
     grant_row.principal <> NEW.reader_principal OR
     grant_row.message_id <> NEW.message_id OR grant_row.attempt <> NEW.attempt OR
     grant_row.generation <> NEW.generation OR grant_row.purpose <> NEW.purpose OR
     grant_row.classification_ceiling <> NEW.classification_ceiling OR
     grant_row.membership_epoch <> NEW.membership_epoch OR
     grant_row.policy_epoch <> NEW.policy_epoch OR
     grant_row.audience <> 'PROJECTION_API' OR
     grant_row.grant_digest <> NEW.read_grant_digest OR
     NEW.expires_at > grant_row.expires_at THEN
    RAISE EXCEPTION 'manifest does not match exact turn read grant'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path=solvan_liaison,pg_temp;
CREATE TRIGGER liaison_manifest_exact_grant
  BEFORE INSERT ON liaison_turn_input_manifests
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_manifest_grant_binding();

CREATE TABLE liaison_manifest_sources (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  message_id text NOT NULL,
  attempt integer NOT NULL CHECK (attempt > 0),
  record_type text NOT NULL,
  record_id text NOT NULL,
  source_version text NOT NULL,
  source_digest text NOT NULL CHECK (source_digest ~ '^sha256:[0-9a-f]{64}$'),
  access_verdict_ref text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id,
               message_id, attempt, record_type, record_id),
  FOREIGN KEY (organization_id, project_id, environment_id, message_id, attempt)
    REFERENCES liaison_turn_input_manifests
      (organization_id, project_id, environment_id, message_id, attempt)
      ON DELETE CASCADE,
  FOREIGN KEY (organization_id, project_id, environment_id, record_type, record_id)
    REFERENCES liaison_record_directory
      (organization_id, project_id, environment_id, record_type, record_id)
);

CREATE INDEX liaison_manifest_sources_by_record
  ON liaison_manifest_sources
    (organization_id, project_id, environment_id, record_type, record_id,
     message_id, attempt);

CREATE FUNCTION liaison_assert_manifest_sources() RETURNS trigger AS $$
DECLARE
  checked_organization_id text;
  checked_project_id text;
  checked_environment_id text;
  checked_message_id text;
  checked_attempt integer;
  source_json jsonb;
BEGIN
  IF TG_OP = 'DELETE' THEN
    checked_organization_id := OLD.organization_id;
    checked_project_id := OLD.project_id;
    checked_environment_id := OLD.environment_id;
    checked_message_id := OLD.message_id;
    checked_attempt := OLD.attempt;
  ELSE
    checked_organization_id := NEW.organization_id;
    checked_project_id := NEW.project_id;
    checked_environment_id := NEW.environment_id;
    checked_message_id := NEW.message_id;
    checked_attempt := NEW.attempt;
  END IF;

  SELECT manifest_json -> 'source_versions' INTO source_json
    FROM solvan_liaison.liaison_turn_input_manifests
   WHERE organization_id = checked_organization_id
     AND project_id = checked_project_id
     AND environment_id = checked_environment_id
     AND message_id = checked_message_id
     AND attempt = checked_attempt;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  IF EXISTS (
    SELECT 1
      FROM jsonb_array_elements(COALESCE(source_json, '[]'::jsonb)) expected
     WHERE NOT EXISTS (
       SELECT 1 FROM solvan_liaison.liaison_manifest_sources actual
        WHERE actual.organization_id = checked_organization_id
          AND actual.project_id = checked_project_id
          AND actual.environment_id = checked_environment_id
          AND actual.message_id = checked_message_id
          AND actual.attempt = checked_attempt
          AND actual.record_type = expected ->> 'record_type'
          AND actual.record_id = expected ->> 'record_id'
          AND actual.source_version = expected ->> 'version'
          AND actual.source_digest = expected ->> 'digest'
     )
  ) OR EXISTS (
    SELECT 1 FROM solvan_liaison.liaison_manifest_sources actual
     WHERE actual.organization_id = checked_organization_id
       AND actual.project_id = checked_project_id
       AND actual.environment_id = checked_environment_id
       AND actual.message_id = checked_message_id
       AND actual.attempt = checked_attempt
       AND NOT EXISTS (
         SELECT 1
           FROM jsonb_array_elements(COALESCE(source_json, '[]'::jsonb)) expected
          WHERE actual.record_type = expected ->> 'record_type'
            AND actual.record_id = expected ->> 'record_id'
            AND actual.source_version = expected ->> 'version'
            AND actual.source_digest = expected ->> 'digest'
       )
  ) THEN
    RAISE EXCEPTION 'manifest source rows do not equal manifest source_versions'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER liaison_manifest_source_set_from_manifest
  AFTER INSERT ON liaison_turn_input_manifests
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_manifest_sources();

CREATE CONSTRAINT TRIGGER liaison_manifest_source_set_from_source
  AFTER INSERT OR UPDATE OR DELETE ON liaison_manifest_sources
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION liaison_assert_manifest_sources();

-- Idempotency with an explicit claim protocol: the row is claimed in the same
-- transaction the governed write begins, so a concurrent replay waits for the
-- winner rather than performing the work twice.
CREATE TABLE liaison_operation_ledger (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  idempotency_key text NOT NULL,
  operation text NOT NULL,
  request_hash text NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','COMPLETED','FAILED')),
  claim_token uuid NOT NULL,
  response_ref text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, operation, idempotency_key),
  CHECK ((status = 'COMPLETED') = (response_ref IS NOT NULL))
);

CREATE TABLE liaison_purge_jobs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL,
  message_id text NOT NULL,
  targets_json jsonb NOT NULL,
  target_kinds text[] NOT NULL CHECK (cardinality(target_kinds) > 0),
  legal_hold_ref text,
  deadline_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','HELD')),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  CHECK (deadline_at > created_at),
  CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
  CHECK ((status = 'HELD') = (legal_hold_ref IS NOT NULL)),
  CHECK (target_kinds <@ ARRAY[
    'COMPACTION','DELIVERY_PAYLOAD','ATTACHMENT','SEARCH_INDEX',
    'MANAGED_SESSION','CONTEXT_CACHE','MANIFEST','MEMORY_PROMOTION'
  ]::text[])
);

-- What a reader is allowed to see, reduced to one advancing number.
--
-- A catch-up cursor is only safe to honour while the authority it was minted
-- under still holds. Rather than hooking every place authority can change, the
-- epoch is derived: each turn digests the principal's live bindings, and the
-- epoch advances when that digest moves. A revoked reader therefore presents a
-- cursor from a superseded epoch, and is re-briefed under what they may see now
-- instead of resuming where they left off.
CREATE TABLE liaison_policy_epochs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  principal text NOT NULL,
  epoch bigint NOT NULL DEFAULT 1 CHECK (epoch > 0),
  authority_digest text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, principal)
);

CREATE TABLE liaison_budget_counters (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('THREAD','PRINCIPAL')),
  subject_id text NOT NULL,
  window_date date NOT NULL,
  model_calls integer NOT NULL DEFAULT 0 CHECK (model_calls >= 0),
  tool_calls integer NOT NULL DEFAULT 0 CHECK (tool_calls >= 0),
  tokens bigint NOT NULL DEFAULT 0 CHECK (tokens >= 0),
  PRIMARY KEY (organization_id, project_id, environment_id,
               subject_kind, subject_id, window_date)
);

-- Query paths the API promises (§11.2).
CREATE INDEX liaison_threads_by_record ON liaison_threads
  (organization_id, project_id, environment_id, status, anchor_kind,
   anchor_record_type, anchor_record_id, last_activity_at DESC, id);
CREATE INDEX liaison_threads_by_service ON liaison_threads
  (organization_id, project_id, environment_id, status, anchor_service_key,
   anchor_window_start, anchor_window_end, last_activity_at DESC, id);
CREATE INDEX liaison_access_requests_by_thread ON liaison_access_requests
  (organization_id, project_id, environment_id, thread_id, status, expires_at);
CREATE INDEX liaison_read_cursors_by_thread ON liaison_thread_read_cursors
  (organization_id, project_id, environment_id, thread_id, principal);
CREATE INDEX liaison_messages_by_thread ON liaison_messages
  (organization_id, project_id, environment_id, thread_id, stream_position DESC);
CREATE INDEX liaison_parts_by_message ON liaison_message_parts
  (organization_id, project_id, environment_id, message_id, sequence);
CREATE INDEX liaison_streaming_parts_by_attempt ON liaison_message_parts
  (organization_id, project_id, environment_id, message_id, attempt, generation,
   sequence)
  WHERE status = 'STREAMING';
CREATE INDEX liaison_stream_by_thread ON liaison_stream_events
  (organization_id, project_id, environment_id, thread_id, stream_sequence);
CREATE INDEX liaison_access_by_record ON liaison_part_access
  (organization_id, project_id, environment_id, record_type, record_id, part_id);
CREATE INDEX liaison_parked_expiry ON liaison_parked_requests
  (organization_id, project_id, environment_id, status, expires_at);
CREATE INDEX liaison_parked_by_thread ON liaison_parked_requests
  (organization_id, project_id, environment_id, thread_id, status);
CREATE INDEX liaison_subscriptions_due ON liaison_subscriptions
  (organization_id, project_id, environment_id, status, cadence, next_delivery_at);
CREATE INDEX liaison_bindings_by_principal ON liaison_channel_bindings
  (organization_id, project_id, environment_id, principal, status);
CREATE INDEX liaison_deliveries_due ON liaison_deliveries
  (organization_id, project_id, environment_id, status, next_attempt_at);

CREATE INDEX liaison_compaction_sources_by_source
  ON liaison_compaction_sources
    (organization_id, project_id, environment_id, source_message_id,
     compaction_part_id);

COMMIT;
