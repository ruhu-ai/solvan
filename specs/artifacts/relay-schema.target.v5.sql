-- Customer Relay deployment profiles are immutable, reviewable installation
-- assertions.  They deliberately store only identifiers, digests, and public
-- references; neither a provider credential nor a policy body reaches Solvan.
BEGIN;
SET search_path TO solvan_relay, solvan, public;

CREATE TABLE relay_deployment_profiles (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rdp_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  relay_connection_id text NOT NULL,
  host_kind text NOT NULL CHECK (host_kind IN
    ('CLOUD_RUN_WORKER_POOL','GKE','ONPREM_FEDERATED','ONPREM_KEYFILE')),
  principal_subject text NOT NULL,
  principal_issuer text NOT NULL CHECK (principal_issuer ~ '^https://'),
  expected_audience text NOT NULL CHECK (expected_audience ~ '^https://'),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  image_attestation_id text NOT NULL,
  image_attestation_decision text NOT NULL DEFAULT 'ALLOW'
    CHECK (image_attestation_decision='ALLOW'),
  local_policy_digest text NOT NULL CHECK (local_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
  policy_key_id text NOT NULL,
  connector_catalog_digest text NOT NULL CHECK (connector_catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
  redaction_revision text NOT NULL,
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  relay_version text NOT NULL,
  runtime_proof_key_id text NOT NULL,
  runtime_proof_public_key_ref text NOT NULL CHECK (runtime_proof_public_key_ref ~ '^gs://[^/]+/.+'),
  runtime_proof_public_key_digest text NOT NULL CHECK (runtime_proof_public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  egress_manifest_digest text NOT NULL CHECK (egress_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  local_binding_digest text NOT NULL CHECK (local_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
  assertion_digest text NOT NULL CHECK (assertion_digest ~ '^sha256:[0-9a-f]{64}$'),
  asserted_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  review_state text NOT NULL CHECK (review_state IN ('PENDING_REVIEW','APPROVED','CONSUMED','EXPIRED','REJECTED')),
  reviewed_by_principal text,
  reviewed_at timestamptz,
  enrollment_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,assertion_digest),
  UNIQUE (organization_id,project_id,environment_id,enrollment_id),
  FOREIGN KEY (organization_id,project_id,environment_id,relay_connection_id)
    REFERENCES tenant_connections(organization_id,project_id,environment_id,id),
  FOREIGN KEY (image_attestation_id,image_digest,image_attestation_decision)
    REFERENCES relay_image_attestations(id,image_digest,decision),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key_id)
    REFERENCES relay_policy_key_revisions(organization_id,project_id,environment_id,key_id),
  CHECK (expires_at > asserted_at),
  CHECK ((review_state IN ('APPROVED','CONSUMED')) = (reviewed_by_principal IS NOT NULL AND reviewed_at IS NOT NULL)),
  CHECK ((review_state='CONSUMED') = (enrollment_id IS NOT NULL))
);

CREATE INDEX relay_deployment_profile_review_idx
  ON relay_deployment_profiles(organization_id,project_id,environment_id,review_state,expires_at);

ALTER TABLE relay_enrollments
  ADD COLUMN deployment_profile_id text;
ALTER TABLE relay_enrollments
  ADD CONSTRAINT relay_enrollments_deployment_profile_fk
  FOREIGN KEY (organization_id,project_id,environment_id,deployment_profile_id)
  REFERENCES relay_deployment_profiles(organization_id,project_id,environment_id,id);
CREATE UNIQUE INDEX relay_one_enrollment_per_deployment_profile
  ON relay_enrollments(organization_id,project_id,environment_id,deployment_profile_id)
  WHERE deployment_profile_id IS NOT NULL;

ALTER TABLE relay_deployment_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_deployment_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY relay_deployment_profile_scope_isolation ON relay_deployment_profiles
  USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))
  WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id));

COMMIT;
