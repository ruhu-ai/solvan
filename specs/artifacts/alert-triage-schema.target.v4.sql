-- Alert-scoped evidence anchor required by the phase-2 Evidence Agent runtime.

BEGIN;

ALTER TABLE solvan_alerts.alert_episodes
  ADD COLUMN evidence_version bigint NOT NULL DEFAULT 0 CHECK (evidence_version>=0);

ALTER TABLE solvan.evidence_items
  ALTER COLUMN incident_id DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS alert_episode_id text;
ALTER TABLE solvan.evidence_items
  DROP CONSTRAINT IF EXISTS evidence_items_alert_episode_fk,
  DROP CONSTRAINT IF EXISTS evidence_items_one_anchor_ck,
  ADD CONSTRAINT evidence_items_alert_episode_fk
    FOREIGN KEY (organization_id,project_id,environment_id,alert_episode_id)
    REFERENCES solvan_alerts.alert_episodes
      (organization_id,project_id,environment_id,id),
  ADD CONSTRAINT evidence_items_one_anchor_ck CHECK (
    (incident_id IS NOT NULL)::integer
    + (alert_episode_id IS NOT NULL)::integer = 1
  );

CREATE INDEX IF NOT EXISTS evidence_items_alert_episode_sequence_idx
  ON solvan.evidence_items
    (organization_id,project_id,environment_id,alert_episode_id,ingested_at,id)
  WHERE alert_episode_id IS NOT NULL;

COMMIT;
