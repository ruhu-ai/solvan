-- Target migration: terminal rollout ambiguity and closed operator recovery.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

CREATE OR REPLACE FUNCTION delivery_transition_allowed(from_value text, to_value text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT (from_value,to_value) IN (
    ('PATCH_VALIDATED','PR_CREATION_APPROVAL_PENDING'),
    ('PR_CREATION_APPROVAL_PENDING','PR_REQUESTED'),
    ('PR_CREATION_APPROVAL_PENDING','EXPIRED'),
    ('PR_REQUESTED','PR_CREATED'), ('PR_REQUESTED','BLOCKED'),
    ('PR_CREATED','CI_PENDING'), ('CI_PENDING','CI_PASSED'),
    ('CI_PENDING','CI_FAILED'), ('CI_FAILED','BLOCKED'),
    ('CI_PASSED','GITHUB_REVIEW_PENDING'),
    ('GITHUB_REVIEW_PENDING','MERGE_APPROVAL_PENDING'),
    ('MERGE_APPROVAL_PENDING','MERGED'), ('MERGE_APPROVAL_PENDING','EXPIRED'),
    ('MERGED','RELEASE_CANDIDATE'),
    ('RELEASE_CANDIDATE','DEPLOYMENT_APPROVAL_PENDING'),
    ('DEPLOYMENT_APPROVAL_PENDING','CANARY_DEPLOYING'),
    ('DEPLOYMENT_APPROVAL_PENDING','EXPIRED'),
    ('CANARY_DEPLOYING','VERIFYING'), ('CANARY_DEPLOYING','BLOCKED'),
    ('VERIFYING','PROMOTED'), ('VERIFYING','VERIFICATION_FAILED'),
    ('VERIFYING','BLOCKED'),
    ('VERIFICATION_FAILED','ROLLBACK_APPROVAL_PENDING'),
    ('ROLLBACK_APPROVAL_PENDING','ROLLING_BACK'),
    ('ROLLBACK_APPROVAL_PENDING','ROLLBACK_REJECTED'),
    ('ROLLBACK_APPROVAL_PENDING','ROLLBACK_EXPIRED'),
    ('ROLLBACK_APPROVAL_PENDING','BLOCKED'),
    ('ROLLING_BACK','ROLLED_BACK'), ('ROLLING_BACK','ROLLBACK_AMBIGUOUS'),
    ('BLOCKED','ABANDONED'), ('EXPIRED','BLOCKED'),
    ('ROLLBACK_REJECTED','BLOCKED'), ('ROLLBACK_EXPIRED','BLOCKED'),
    ('ROLLBACK_AMBIGUOUS','BLOCKED')
  )
$$;

CREATE OR REPLACE FUNCTION delivery_guard_rollout_reservation() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE reservation_status text; reservation_expires timestamptz;
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'deployment rollout cannot be deleted' USING ERRCODE='23997';
  END IF;
  SELECT status,lease_expires_at INTO reservation_status,reservation_expires
  FROM release_target_reservations WHERE organization_id=NEW.organization_id
    AND project_id=NEW.project_id AND environment_id=NEW.environment_id
    AND id=NEW.target_reservation_id AND target_key=NEW.target_key FOR UPDATE;
  IF reservation_status IS NULL THEN
    RAISE EXCEPTION 'RELEASE_TARGET_RESERVATION_STALE' USING ERRCODE='23998';
  END IF;
  -- An already-issued effect must always be able to terminate as ambiguous,
  -- even when the reservation deadline elapsed while the provider was in flight.
  IF TG_OP='UPDATE' AND NEW.status='AMBIGUOUS' THEN
    RETURN NEW;
  END IF;
  IF reservation_status NOT IN ('HELD','RECONCILING') OR reservation_expires<=now() THEN
    RAISE EXCEPTION 'RELEASE_TARGET_RESERVATION_STALE' USING ERRCODE='23998';
  END IF;
  RETURN NEW;
END $$;

COMMIT;
