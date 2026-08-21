-- Target migration: exact failed-verification registration and rollback decision binding.

BEGIN;
SET search_path TO solvan_delivery, solvan, public;

ALTER TABLE private_command_dispatches
  DROP CONSTRAINT private_command_dispatches_command_kind_check,
  ADD CONSTRAINT private_command_dispatches_command_kind_check CHECK (
    command_kind IN ('WORKSPACE_TOOL_INVOKE','EXPLORATORY_SANDBOX_RUN','ADJUDICATE_PATCH',
      'QUALIFY_CODE_CHANGE','CREATE_PR','SYNC_PR','MERGE_PR','START_GITHUB_LINK',
      'CONSUME_GITHUB_CALLBACK','REVOKE_GITHUB_LINK','OBSERVE_RELEASE_TARGET',
      'OBSERVE_RELEASE_BASELINE','START_ROLLOUT','PREPARE_CANARY','PROMOTE_CANARY',
      'FINALIZE_ROLLOUT','REGISTER_VERIFICATION_FAILURE','ROLLBACK_RELEASE',
      'VERIFY_RELEASE_EFFECT'));

ALTER TABLE code_change_decisions
  ADD COLUMN deployment_rollout_id text,
  ADD COLUMN release_verification_receipt_hash text CHECK (
    release_verification_receipt_hash IS NULL
    OR release_verification_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT code_change_decision_rollout_fk
    FOREIGN KEY (organization_id,project_id,environment_id,deployment_rollout_id)
    REFERENCES deployment_rollouts(organization_id,project_id,environment_id,id),
  ADD CONSTRAINT code_change_decision_rollback_shape_ck CHECK (
    (stage='ROLLBACK' AND decision='APPROVED' AND deployment_rollout_id IS NOT NULL
     AND release_verification_receipt_hash IS NOT NULL)
    OR NOT (stage='ROLLBACK' AND decision='APPROVED'));

CREATE FUNCTION delivery_guard_rollback_decision_material() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.stage='ROLLBACK' AND NEW.decision='APPROVED' AND NOT EXISTS (
    SELECT 1
      FROM code_change_requests request
      JOIN release_candidates candidate
        ON candidate.organization_id=request.organization_id
       AND candidate.project_id=request.project_id
       AND candidate.environment_id=request.environment_id
       AND candidate.code_change_request_id=request.id
      JOIN deployment_rollouts rollout
        ON rollout.organization_id=request.organization_id
       AND rollout.project_id=request.project_id
       AND rollout.environment_id=request.environment_id
       AND rollout.id=NEW.deployment_rollout_id
       AND rollout.release_candidate_id=candidate.id
       AND rollout.status='VERIFICATION_FAILED'
      JOIN release_target_reservations reservation
        ON reservation.organization_id=rollout.organization_id
       AND reservation.project_id=rollout.project_id
       AND reservation.environment_id=rollout.environment_id
       AND reservation.id=rollout.target_reservation_id
       AND reservation.status IN ('HELD','RECONCILING')
       AND reservation.lease_expires_at>NEW.decided_at
      JOIN LATERAL (
        SELECT receipt.* FROM release_verification_receipts receipt
         WHERE receipt.organization_id=rollout.organization_id
           AND receipt.project_id=rollout.project_id
           AND receipt.environment_id=rollout.environment_id
           AND receipt.deployment_rollout_id=rollout.id
         ORDER BY receipt.stage_ordinal DESC,
                  receipt.observation_window_generation DESC LIMIT 1
      ) receipt ON receipt.result IN ('FAILED','INCONCLUSIVE')
               AND receipt.receipt_envelope_hash=NEW.release_verification_receipt_hash
               AND receipt.observed_at>NEW.decided_at-interval '10 minutes'
     WHERE request.organization_id=NEW.organization_id
       AND request.project_id=NEW.project_id
       AND request.environment_id=NEW.environment_id
       AND request.id=NEW.code_change_request_id
       AND request.state='ROLLBACK_APPROVAL_PENDING'
  ) THEN
    RAISE EXCEPTION 'ROLLBACK_DECISION_MATERIAL_INVALID' USING ERRCODE='23971';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_rollback_decision_material_fence
BEFORE INSERT ON code_change_decisions
FOR EACH ROW EXECUTE FUNCTION delivery_guard_rollback_decision_material();

COMMIT;
