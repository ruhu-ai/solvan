-- Target migration: production decision-session and idempotency closure.
-- Existing decision rows cannot be guessed into the stronger contract.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM code_change_decisions) THEN
    RAISE EXCEPTION 'legacy code change decisions cannot be migrated without session receipts';
  END IF;
END $$;

ALTER TABLE code_change_decisions
  ADD COLUMN decision_request_id text NOT NULL,
  ADD COLUMN authenticated_session_hash text NOT NULL
    CHECK (authenticated_session_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN authenticated_at timestamptz NOT NULL,
  ADD COLUMN authorization_snapshot_ref text NOT NULL CHECK (authorization_snapshot_ref ~ '^gs://'),
  ADD COLUMN step_up_receipt_ref text NOT NULL CHECK (step_up_receipt_ref ~ '^gs://'),
  ADD CONSTRAINT code_change_decision_request_uk
    UNIQUE (organization_id,project_id,environment_id,decision_request_id),
  ADD CONSTRAINT code_change_decision_fresh_authentication_ck
    CHECK (authenticated_at<=decided_at AND decided_at-authenticated_at<=interval '5 minutes'),
  ADD CONSTRAINT code_change_decision_bounded_lifetime_ck
    CHECK (expires_at<=decided_at+interval '10 minutes'),
  ADD CONSTRAINT code_change_decision_github_binding_shape_ck
    CHECK (
      (stage='MERGE' AND decision='APPROVED'
       AND github_reviewer_binding_id IS NOT NULL AND github_review_state_hash IS NOT NULL)
      OR NOT (stage='MERGE' AND decision='APPROVED')
    );

CREATE TABLE code_change_decision_challenges (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^dch_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  code_change_request_id text NOT NULL,
  stage text NOT NULL CHECK (stage IN ('PR_CREATION','MERGE','DEPLOYMENT','ROLLBACK')),
  principal text NOT NULL,
  decision_digest text NOT NULL CHECK (decision_digest ~ '^sha256:[0-9a-f]{64}$'),
  material_ref text NOT NULL CHECK (material_ref ~ '^gs://'),
  material_hash text NOT NULL CHECK (material_hash ~ '^sha256:[0-9a-f]{64}$'),
  authorization_snapshot_ref text NOT NULL CHECK (authorization_snapshot_ref ~ '^gs://'),
  authorization_snapshot_hash text NOT NULL
    CHECK (authorization_snapshot_hash ~ '^sha256:[0-9a-f]{64}$'),
  authenticated_session_hash text NOT NULL
    CHECK (authenticated_session_hash ~ '^sha256:[0-9a-f]{64}$'),
  authenticated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','CONSUMED','EXPIRED')),
  decision_id text,
  created_at timestamptz NOT NULL DEFAULT now(), consumed_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,code_change_request_id)
    REFERENCES code_change_requests(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,decision_id)
    REFERENCES code_change_decisions(organization_id,project_id,environment_id,id),
  CHECK (expires_at>created_at AND expires_at<=created_at+interval '10 minutes'),
  CHECK (
    (status='PENDING' AND decision_id IS NULL AND consumed_at IS NULL)
    OR (status='CONSUMED' AND decision_id IS NOT NULL AND consumed_at IS NOT NULL)
    OR (status='EXPIRED' AND decision_id IS NULL AND consumed_at IS NOT NULL)
  )
);
CREATE UNIQUE INDEX code_change_one_pending_decision_challenge
  ON code_change_decision_challenges
    (organization_id,project_id,environment_id,code_change_request_id,stage,principal)
  WHERE status='PENDING';

CREATE FUNCTION delivery_guard_decision_challenge() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'decision challenge cannot be deleted';
  END IF;
  IF TG_OP='UPDATE' AND (
      OLD.status<>'PENDING' OR NEW.status NOT IN ('CONSUMED','EXPIRED')
      OR to_jsonb(OLD)-'status'-'decision_id'-'consumed_at'
         IS DISTINCT FROM to_jsonb(NEW)-'status'-'decision_id'-'consumed_at') THEN
    RAISE EXCEPTION 'decision challenge material is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_decision_challenge_guard
BEFORE UPDATE OR DELETE ON code_change_decision_challenges
FOR EACH ROW EXECUTE FUNCTION delivery_guard_decision_challenge();
CREATE TRIGGER delivery_decision_challenge_no_truncate
BEFORE TRUNCATE ON code_change_decision_challenges
FOR EACH STATEMENT EXECUTE FUNCTION delivery_reject_history_mutation();

CREATE OR REPLACE FUNCTION delivery_guard_decision_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE predecessor code_change_decisions%ROWTYPE;
DECLARE request_state text;
DECLARE request_expires_at timestamptz;
DECLARE required_state text;
DECLARE required_role text;
BEGIN
  SELECT state,expires_at INTO request_state,request_expires_at
    FROM code_change_requests
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=NEW.code_change_request_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CODE_CHANGE_REQUEST_NOT_FOUND' USING ERRCODE='23982';
  END IF;
  required_state := CASE NEW.stage
    WHEN 'PR_CREATION' THEN 'PR_CREATION_APPROVAL_PENDING'
    WHEN 'MERGE' THEN 'MERGE_APPROVAL_PENDING'
    WHEN 'DEPLOYMENT' THEN 'DEPLOYMENT_APPROVAL_PENDING'
    WHEN 'ROLLBACK' THEN 'ROLLBACK_APPROVAL_PENDING' END;
  required_role := CASE WHEN NEW.stage IN ('PR_CREATION','MERGE')
    THEN 'CODE_CHANGE_APPROVER' ELSE 'RELEASE_APPROVER' END;
  IF request_state<>required_state OR request_expires_at<=now()
     OR NEW.expires_at>request_expires_at THEN
    RAISE EXCEPTION 'DECISION_STAGE_NOT_CURRENT' USING ERRCODE='23990';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM solvan.actor_role_bindings role_binding
     WHERE role_binding.organization_id=NEW.organization_id
       AND role_binding.project_id=NEW.project_id
       AND role_binding.environment_id=NEW.environment_id
       AND role_binding.principal=NEW.principal
       AND role_binding.role=required_role
       AND (role_binding.expires_at IS NULL OR role_binding.expires_at>NEW.decided_at)
  ) THEN
    RAISE EXCEPTION 'DECISION_STAGE_ROLE_REQUIRED' USING ERRCODE='23989';
  END IF;
  IF NEW.sequence_no=1 THEN
    IF EXISTS (SELECT 1 FROM code_change_decisions
      WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
        AND environment_id=NEW.environment_id
        AND code_change_request_id=NEW.code_change_request_id AND stage=NEW.stage) THEN
      RAISE EXCEPTION 'DECISION_ROOT_ALREADY_EXISTS' USING ERRCODE='23992';
    END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO predecessor FROM code_change_decisions
   WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
     AND environment_id=NEW.environment_id AND id=NEW.supersedes_id
   FOR UPDATE;
  IF NOT FOUND OR predecessor.code_change_request_id<>NEW.code_change_request_id
     OR predecessor.stage<>NEW.stage OR predecessor.sequence_no<>NEW.sequence_no-1 THEN
    RAISE EXCEPTION 'DECISION_PREDECESSOR_INVALID' USING ERRCODE='23993';
  END IF;
  IF EXISTS (SELECT 1 FROM code_change_decisions
      WHERE organization_id=NEW.organization_id AND project_id=NEW.project_id
        AND environment_id=NEW.environment_id AND supersedes_id=NEW.supersedes_id) THEN
    RAISE EXCEPTION 'DECISION_CHAIN_FORK' USING ERRCODE='23994';
  END IF;
  RETURN NEW;
END $$;

ALTER TABLE code_change_decision_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_change_decision_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY delivery_scope_isolation ON code_change_decision_challenges
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
REVOKE ALL ON code_change_decision_challenges FROM PUBLIC;

COMMIT;
