-- Four additional Relay adapters become representable only as exact provider
-- and capability pairs. This replaces the temporary Monitoring-only fence;
-- it does not permit a generic adapter or query surface.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

ALTER TABLE relay_source_bindings
  DROP CONSTRAINT relay_source_bindings_cloud_monitoring_only;
ALTER TABLE collection_jobs
  DROP CONSTRAINT collection_jobs_cloud_monitoring_only;

ALTER TABLE relay_source_bindings
  ADD CONSTRAINT relay_source_bindings_qualified_adapter_only CHECK (
    adapter_key IN ('cloud-monitoring.v1','managed-prometheus.v1',
                    'cloud-logging.v1','cloud-trace.v1','kubernetes-metadata.v1')
  );
ALTER TABLE collection_jobs
  ADD CONSTRAINT collection_jobs_qualified_adapter_operation_only CHECK (
    (adapter_key='cloud-monitoring.v1' AND operation IN
      ('monitoring.time-series.read.v1','monitoring.metric-descriptors.read.v1')) OR
    (adapter_key='managed-prometheus.v1' AND operation='prometheus.registered-range.read.v1') OR
    (adapter_key='cloud-logging.v1' AND operation='logging.entries.read.v1') OR
    (adapter_key='cloud-trace.v1' AND operation='trace.spans.read.v1') OR
    (adapter_key='kubernetes-metadata.v1' AND operation='kubernetes.metadata.list.v1')
  );
COMMIT;
