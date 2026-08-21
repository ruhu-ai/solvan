-- The shipped customer Relay has one qualified read surface: Cloud Monitoring.
-- Retired experimental adapters must not remain representable in durable
-- bindings or jobs merely because an earlier target schema catalogued them.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

ALTER TABLE relay_source_bindings
  ADD CONSTRAINT relay_source_bindings_cloud_monitoring_only
  CHECK (adapter_key='cloud-monitoring.v1');

ALTER TABLE collection_jobs
  ADD CONSTRAINT collection_jobs_cloud_monitoring_only
  CHECK (
    adapter_key='cloud-monitoring.v1'
    AND operation IN ('monitoring.time-series.read.v1','monitoring.metric-descriptors.read.v1')
  );

COMMIT;
