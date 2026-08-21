-- Direct GCP pilot qualification issuance is singleton per live source epoch.
--
-- The qualification verifier serializes issuance as well, but the database
-- remains the final guard against a retry, a second verifier revision, or an
-- operational command bypassing that process from producing two current
-- receipts for the same qualified source binding.
BEGIN;
SET search_path TO solvan_alerts, solvan, public;

CREATE UNIQUE INDEX direct_gcp_pilot_one_current_receipt_per_source_epoch
  ON direct_gcp_pilot_qualification_receipts
    (organization_id,project_id,environment_id,source_binding_id,source_binding_epoch)
  WHERE superseded_at IS NULL;

COMMIT;
