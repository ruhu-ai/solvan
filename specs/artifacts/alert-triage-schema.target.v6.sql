-- Direct GCP production-pilot identity, source qualification, and receipt
-- records. This migration intentionally refuses the retired WIF connection
-- shape: estates must be re-enrolled under service-account impersonation.

BEGIN;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan' AND table_name='tenant_connections'
       AND column_name IN ('wif_pool_resource','impersonated_principal')
  ) THEN
    RAISE EXCEPTION
      'legacy WIF tenant_connections columns are unsupported; rebuild/re-enroll the estate under direct GCP impersonation';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='solvan' AND table_name='tenant_connections'
       AND column_name='authentication_mode'
  ) THEN
    RAISE EXCEPTION
      'tenant_connections lacks authentication_mode; apply the current clean schema before target migrations';
  END IF;
END $$;

CREATE TABLE solvan_alerts.alert_source_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^asb_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  binding_epoch bigint NOT NULL DEFAULT 1 CHECK (binding_epoch > 0),
  source_identity_id text NOT NULL,
  status text NOT NULL CHECK (status IN
    ('PENDING_CONFIGURATION','QUALIFIED','DISABLED','REVOKED')),
  scoping_project_id text NOT NULL CHECK (scoping_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  topic_name text NOT NULL CHECK (topic_name ~ '^projects/[^/]+/topics/[^/]+$'),
  subscription_name text NOT NULL CHECK (subscription_name ~ '^projects/[^/]+/subscriptions/[^/]+$'),
  push_service_account text NOT NULL CHECK (push_service_account ~ '^serviceAccount:[^@ ]+@[^@ ]+$'),
  oidc_audience text NOT NULL CHECK (oidc_audience ~ '^https://'),
  payload_schema_version text NOT NULL CHECK (payload_schema_version='1.2'),
  configuration_digest text NOT NULL CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
  pubsub_token_minting_receipt_ref text NOT NULL,
  qualification_delivery_id text,
  qualified_at timestamptz,
  qualified_by_principal text,
  invalidated_reason text,
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,connection_id,connection_epoch),
  UNIQUE (organization_id,project_id,environment_id,id,binding_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,connection_id)
    REFERENCES solvan.tenant_connections(organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,source_identity_id)
    REFERENCES solvan_alerts.alert_provider_source_identities
      (organization_id,project_id,environment_id,id),
  CHECK ((status='QUALIFIED') = (qualification_delivery_id IS NOT NULL
    AND qualified_at IS NOT NULL AND qualified_by_principal IS NOT NULL)),
  CHECK (status NOT IN ('DISABLED','REVOKED') OR invalidated_reason IS NOT NULL)
);

CREATE TABLE solvan_alerts.alert_source_qualification_deliveries (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^aqd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  source_binding_id text NOT NULL,
  source_binding_epoch bigint NOT NULL CHECK (source_binding_epoch > 0),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  subscription_name text NOT NULL,
  pubsub_message_id text NOT NULL,
  authenticated_push_principal text NOT NULL,
  oidc_audience text NOT NULL,
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  configuration_digest text NOT NULL CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,source_binding_id,pubsub_message_id),
  FOREIGN KEY (organization_id,project_id,environment_id,source_binding_id,source_binding_epoch)
    REFERENCES solvan_alerts.alert_source_bindings
      (organization_id,project_id,environment_id,id,binding_epoch)
);

ALTER TABLE solvan_alerts.alert_source_bindings
  ADD CONSTRAINT alert_source_bindings_qualification_delivery_fk
  FOREIGN KEY (organization_id,project_id,environment_id,qualification_delivery_id)
  REFERENCES solvan_alerts.alert_source_qualification_deliveries
    (organization_id,project_id,environment_id,id);

CREATE TABLE solvan_alerts.direct_gcp_pilot_qualification_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^pgq_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  source_binding_id text NOT NULL,
  source_binding_epoch bigint NOT NULL CHECK (source_binding_epoch > 0),
  connection_id text NOT NULL,
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  verifier_principal text NOT NULL CHECK (verifier_principal ~ '^serviceAccount:[^@ ]+@[^@ ]+$'),
  verifier_revision text NOT NULL,
  kms_key_version text NOT NULL,
  signature_digest text NOT NULL CHECK (signature_digest ~ '^sha256:[0-9a-f]{64}$'),
  immutable_object_ref text NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
  superseded_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,receipt_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,source_binding_id,source_binding_epoch)
    REFERENCES solvan_alerts.alert_source_bindings
      (organization_id,project_id,environment_id,id,binding_epoch)
);

CREATE FUNCTION solvan_alerts.reject_direct_pilot_receipt_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
      (NEW.id <> OLD.id OR NEW.receipt_hash <> OLD.receipt_hash OR
       NEW.source_binding_id <> OLD.source_binding_id OR NEW.source_binding_epoch <> OLD.source_binding_epoch OR
       NEW.connection_id <> OLD.connection_id OR NEW.connection_epoch <> OLD.connection_epoch OR
       NEW.verifier_principal <> OLD.verifier_principal OR NEW.verifier_revision <> OLD.verifier_revision OR
       NEW.kms_key_version <> OLD.kms_key_version OR NEW.signature_digest <> OLD.signature_digest OR
       NEW.immutable_object_ref <> OLD.immutable_object_ref OR NEW.issued_at <> OLD.issued_at OR
       NEW.expires_at <> OLD.expires_at)) THEN
    RAISE EXCEPTION 'direct GCP pilot receipt history is immutable' USING ERRCODE='23971';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER direct_gcp_pilot_receipt_immutable
BEFORE UPDATE OR DELETE ON solvan_alerts.direct_gcp_pilot_qualification_receipts
FOR EACH ROW EXECUTE FUNCTION solvan_alerts.reject_direct_pilot_receipt_mutation();

ALTER TABLE solvan_alerts.alert_source_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE solvan_alerts.alert_source_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE solvan_alerts.alert_source_qualification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE solvan_alerts.alert_source_qualification_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE solvan_alerts.direct_gcp_pilot_qualification_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE solvan_alerts.direct_gcp_pilot_qualification_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY alert_source_bindings_scope_isolation ON solvan_alerts.alert_source_bindings
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
CREATE POLICY alert_source_qualification_scope_isolation ON solvan_alerts.alert_source_qualification_deliveries
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));
CREATE POLICY direct_gcp_pilot_receipt_scope_isolation ON solvan_alerts.direct_gcp_pilot_qualification_receipts
  USING (solvan.scope_permitted(current_user,organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user,organization_id,project_id,environment_id));

COMMIT;
