-- A deployment is qualified only by a fresh customer-signed receipt after the
-- same enrollment has completed its independent readiness proof.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

CREATE TABLE relay_qualification_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rqr_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  deployment_profile_id text NOT NULL,
  deployment_manifest_digest text NOT NULL CHECK (deployment_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  egress_manifest_digest text NOT NULL CHECK (egress_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  ledger_configuration_digest text NOT NULL CHECK (ledger_configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
  kill_switch_state text NOT NULL CHECK (kill_switch_state='ENABLED'),
  receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  signature_base64 text NOT NULL CHECK (length(signature_base64) BETWEEN 16 AND 16384),
  runtime_proof_key_id text NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch),
  UNIQUE (organization_id,project_id,environment_id,receipt_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch)
    REFERENCES relay_enrollments(organization_id,project_id,environment_id,id,enrollment_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,deployment_profile_id)
    REFERENCES relay_deployment_profiles(organization_id,project_id,environment_id,id),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '30 days')
);
ALTER TABLE relay_qualification_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_qualification_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY relay_qualification_receipt_scope_isolation ON relay_qualification_receipts
  USING (solvan.scope_permitted(current_user, organization_id,project_id,environment_id))
  WITH CHECK (solvan.scope_permitted(current_user, organization_id,project_id,environment_id));
COMMIT;
