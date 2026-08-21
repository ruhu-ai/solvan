BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
     WHERE schemaname='solvan_alerts'
       AND indexname='direct_gcp_pilot_one_current_receipt_per_source_epoch'
  ) THEN
    RAISE EXCEPTION 'direct GCP pilot qualification must have one current receipt per source epoch';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan_alerts' AND table_name='alert_policy_revisions'
       AND column_name='calibration_receipt_refs_json'
  ) THEN RAISE EXCEPTION 'phase-five policy provenance is missing'; END IF;
  IF to_regclass('solvan_alerts.alert_policy_simulation_receipts') IS NULL OR
     to_regclass('solvan_alerts.alert_policy_templates') IS NULL OR
     to_regclass('solvan_alerts.alert_policy_recommendations') IS NULL OR
     to_regclass('solvan_alerts.alert_policy_recommendation_decisions') IS NULL OR
     to_regclass('solvan_alerts.alert_recovery_verification_links') IS NULL THEN
    RAISE EXCEPTION 'phase-five Alert product tables are missing';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='solvan_alerts'
      AND indexname='alert_incident_links_incident_cursor_idx'
  ) THEN RAISE EXCEPTION 'related-Alert cursor index is missing'; END IF;
END $$;

ROLLBACK;
