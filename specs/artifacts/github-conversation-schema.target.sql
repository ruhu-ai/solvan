-- Target migration: governed GitHub conversation (specification 24).
--
-- Three additions: who may address Solvan on a repository, what threads it has
-- observed, and what it has been asked to publish. No table here holds a token,
-- a private key, or a raw webhook body; a thread carries GitHub's untrusted
-- text only as bounded, length-clipped projections, and a published body is
-- stored beside the registry digest that rendered it.

BEGIN;
CREATE SCHEMA IF NOT EXISTS solvan_conversation;
SET search_path TO solvan_conversation, solvan, public;

-- Extend the operation vocabulary. The code-delivery kinds are unchanged;
-- CLOSE_PULL_REQUEST remains declared with no implementation.
ALTER TABLE solvan.github_operations DROP CONSTRAINT github_operations_operation_check;
ALTER TABLE solvan.github_operations ADD CONSTRAINT github_operations_operation_check
  CHECK (operation IN (
    'CREATE_PULL_REQUEST','SYNC_PULL_REQUEST','MERGE_PULL_REQUEST',
    'CLOSE_PULL_REQUEST','CREATE_ISSUE','POST_ISSUE_COMMENT',
    'SUBMIT_PULL_REQUEST_REVIEW'));

-- ---------------------------------------------------------------------------
-- Who may cause Solvan to act on a repository. Absence denies: a binding with
-- no rows here takes no action on any inbound event. Admission is per binding
-- because a GitHub login is global while the decision to let someone direct
-- Solvan's attention is not.
-- ---------------------------------------------------------------------------

CREATE TABLE github_conversation_participants (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ghm_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_id text NOT NULL,
  login text NOT NULL CHECK (login ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$'),
  account_node_id text NOT NULL CHECK (length(account_node_id) BETWEEN 1 AND 128),
  admission text NOT NULL CHECK (admission IN ('ADMITTED','PARKED','DISMISSED')),
  admitted_by_principal text,
  admitted_at timestamptz,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, repository_id, login),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_id)
    REFERENCES solvan.github_repositories(organization_id, project_id, environment_id, id),
  -- An admitted participant names the operator who admitted them and when.
  -- Admission by omission is exactly what this table exists to prevent.
  CHECK ((admission <> 'ADMITTED')
    OR (admitted_by_principal IS NOT NULL AND admitted_at IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- One observed issue or pull-request thread. Projected from verified webhooks
-- and authoritative reads; never authoritative for workflow state itself.
-- ---------------------------------------------------------------------------

CREATE TABLE github_conversation_threads (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ght_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_id text NOT NULL,
  thread_kind text NOT NULL CHECK (thread_kind IN ('ISSUE','PULL_REQUEST')),
  external_number integer NOT NULL CHECK (external_number > 0),
  html_url text NOT NULL CHECK (html_url ~ '^https://'),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('OPEN','CLOSED')),
  locked boolean NOT NULL DEFAULT false,
  head_commit_sha text CHECK (head_commit_sha IS NULL OR head_commit_sha ~ '^[0-9a-f]{40}$'),
  author_login text CHECK (author_login IS NULL OR
    author_login ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$'),
  trigger_kind text CHECK (trigger_kind IS NULL OR
    trigger_kind IN ('MENTION','LABEL','SYNCHRONIZE','NONE')),
  last_event_id text,
  observation_hash text NOT NULL CHECK (observation_hash ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, repository_id,
          thread_kind, external_number),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_id)
    REFERENCES solvan.github_repositories(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, last_event_id)
    REFERENCES solvan.github_webhook_events(organization_id, project_id, environment_id, id),
  -- Only a pull-request thread carries a head commit; an issue has no code.
  CHECK ((thread_kind = 'PULL_REQUEST') OR head_commit_sha IS NULL)
);

-- ---------------------------------------------------------------------------
-- One proposed publication. The body stored here is the rendered body — the
-- exact bytes that will be published — beside the registry digest that
-- produced it and the hash the approver decided against.
-- ---------------------------------------------------------------------------

CREATE TABLE github_conversation_actions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gha_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  repository_id text NOT NULL,
  thread_id text,
  operation text NOT NULL CHECK (operation IN
    ('CREATE_ISSUE','POST_ISSUE_COMMENT','SUBMIT_PULL_REQUEST_REVIEW')),
  review_event text CHECK (review_event IN ('COMMENT','REQUEST_CHANGES')),
  title text CHECK (title IS NULL OR length(title) BETWEEN 1 AND 256),
  body text NOT NULL CHECK (length(body) BETWEEN 1 AND 65536),
  body_hash text NOT NULL CHECK (body_hash ~ '^sha256:[0-9a-f]{64}$'),
  template_registry_digest text NOT NULL CHECK
    (template_registry_digest ~ '^sha256:[0-9a-f]{64}$'),
  template_ids_json jsonb NOT NULL,
  proposal_hash text NOT NULL CHECK (proposal_hash ~ '^sha256:[0-9a-f]{64}$'),
  agent_run_id text,
  expected_thread_state text CHECK (expected_thread_state IN ('OPEN','CLOSED')),
  expected_head_commit_sha text CHECK
    (expected_head_commit_sha IS NULL OR expected_head_commit_sha ~ '^[0-9a-f]{40}$'),
  state text NOT NULL CHECK (state IN
    ('APPROVAL_PENDING','APPROVED','REJECTED','DISPATCHED','PUBLISHED',
     'REFUSED','EXPIRED')),
  decision_digest text CHECK (decision_digest ~ '^sha256:[0-9a-f]{64}$'),
  decided_by_principal text,
  decided_at timestamptz,
  operation_id text,
  external_id bigint CHECK (external_id IS NULL OR external_id > 0),
  external_url text CHECK (external_url IS NULL OR external_url ~ '^https://'),
  error_class text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, proposal_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, repository_id)
    REFERENCES solvan.github_repositories(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, thread_id)
    REFERENCES solvan_conversation.github_conversation_threads(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, operation_id)
    REFERENCES solvan.github_operations(organization_id, project_id, environment_id, id),
  CHECK (jsonb_typeof(template_ids_json) = 'array'
    AND jsonb_array_length(template_ids_json) > 0),
  -- A review names its event and its reviewed head; APPROVE is not in the
  -- domain at all, so it cannot be written and later read back as authority.
  CHECK ((operation = 'SUBMIT_PULL_REQUEST_REVIEW') = (review_event IS NOT NULL)),
  CHECK ((operation <> 'SUBMIT_PULL_REQUEST_REVIEW')
    OR (expected_head_commit_sha IS NOT NULL AND thread_id IS NOT NULL)),
  -- A comment needs a thread to land in; a new issue does not have one yet and
  -- must instead carry the title it will be created with.
  CHECK ((operation <> 'POST_ISSUE_COMMENT') OR thread_id IS NOT NULL),
  CHECK ((operation <> 'CREATE_ISSUE') OR (title IS NOT NULL AND thread_id IS NULL)),
  -- A decided action names its decider, its digest, and when.
  CHECK ((state NOT IN ('APPROVED','REJECTED','DISPATCHED','PUBLISHED'))
    OR (decision_digest IS NOT NULL AND decided_by_principal IS NOT NULL
        AND decided_at IS NOT NULL)),
  -- A published action carries the external identity of what it published, so
  -- the operation reconciles exactly once and never republishes.
  CHECK ((state <> 'PUBLISHED')
    OR (external_id IS NOT NULL AND external_url IS NOT NULL
        AND operation_id IS NOT NULL)),
  CHECK ((state IN ('REFUSED','EXPIRED')) = (error_class IS NOT NULL))
);

CREATE INDEX github_conversation_actions_pending
  ON github_conversation_actions
    (organization_id, project_id, environment_id, repository_id, state, created_at DESC);

CREATE INDEX github_conversation_participants_parked
  ON github_conversation_participants
    (organization_id, project_id, environment_id, repository_id, admission, first_seen_at DESC);

COMMIT;
