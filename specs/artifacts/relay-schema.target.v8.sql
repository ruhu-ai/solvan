-- A customer qualification receipt names the exact closed adapters it proved.
-- No endpoint, policy body, credential, provider payload, or query is stored.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

ALTER TABLE relay_qualification_receipts
  ADD COLUMN qualified_adapter_keys jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
    jsonb_typeof(qualified_adapter_keys) = 'array'
    AND jsonb_array_length(qualified_adapter_keys) BETWEEN 1 AND 5
    AND qualified_adapter_keys <@ '["cloud-monitoring.v1","managed-prometheus.v1",
      "cloud-logging.v1","cloud-trace.v1","kubernetes-metadata.v1"]'::jsonb
  );
COMMIT;
