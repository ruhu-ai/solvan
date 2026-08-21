-- Solvant Relay TARGET schema for specification 22.
-- This file is loadable only after specs/artifacts/schema.sql. It is not part
-- of the competition release DDL and proves no runtime implementation.

BEGIN;
CREATE SCHEMA solvan_relay;
SET search_path TO solvan_relay, solvan, public;

-- Specification 22 intentionally replaces only the old Relay scaffold alias
-- in the connected target schema. There is no Relay compatibility value: a
-- transport connection is exactly RELAY/SOLVAN_RELAY, while observed source
-- connections retain their real provider. COLLECTOR remains the independently
-- governed Action Actuator kind until its own migration changes that contract.
ALTER TABLE solvan.tenant_connections
  DROP CONSTRAINT tenant_connections_kind_check,
  DROP CONSTRAINT tenant_connections_provider_check;
ALTER TABLE solvan.tenant_connections
  ADD CONSTRAINT tenant_connections_kind_check CHECK
    (kind IN ('GCP_NATIVE','VENDOR_API','COLLECTOR','RELAY')),
  ADD CONSTRAINT tenant_connections_provider_check CHECK
    (provider IN
      ('CLOUD_MONITORING','CLOUD_LOGGING','CLOUD_TRACE','CLOUD_AUDIT',
       'ERROR_REPORTING','ASSET_INVENTORY','MANAGED_PROMETHEUS','CLOUD_RUN',
       'CLOUD_SQL','CLOUD_BUILD','GITHUB','PRODUCTION_GRAPH','SOLVAN_ACTUATOR',
       'SOLVAN_VERIFIER','WORKSPACE_SNAPSHOT','ANTIGRAVITY',
       'DATADOG','PROMETHEUS','GRAFANA','NEW_RELIC','KUBERNETES','SOLVAN_RELAY'));

CREATE TABLE relay_signing_key_revisions (
  key_id text PRIMARY KEY CHECK (length(key_id) BETWEEN 1 AND 255),
  kms_key_version_ref text NOT NULL,
  public_key_digest text NOT NULL CHECK (public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  algorithm text NOT NULL CHECK (algorithm = 'ECDSA_P256_SHA256'),
  region text NOT NULL CHECK (length(region) BETWEEN 2 AND 63),
  lifecycle text NOT NULL CHECK (lifecycle IN ('ACTIVE','VERIFY_ONLY','REVOKED','EXPIRED')),
  valid_from timestamptz NOT NULL,
  issue_until timestamptz NOT NULL,
  verify_until timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (issue_until >= valid_from),
  CHECK (verify_until >= issue_until),
  CHECK ((lifecycle = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE relay_transition_rules (
  machine text NOT NULL CHECK (machine IN ('relay_enrollment','collection_job')),
  from_state text NOT NULL,
  event text NOT NULL,
  to_state text NOT NULL,
  guard_key text NOT NULL,
  PRIMARY KEY (machine,from_state,event,to_state),
  CHECK (from_state <> to_state)
);
INSERT INTO relay_transition_rules(machine,from_state,event,to_state,guard_key) VALUES
 ('relay_enrollment','REGISTERED','ATTESTATION_ACCEPTED','READY','identity_image_policy_catalog_and_region_current'),
 ('relay_enrollment','REGISTERED','ADMIN_DISABLED','DISABLED','authorized_administrator'),
 ('relay_enrollment','READY','HEALTH_DEGRADED','DEGRADED','current_safe_health_receipt'),
 ('relay_enrollment','READY','POLICY_OR_EPOCH_CHANGED','STALE','authoritative_binding_changed'),
 ('relay_enrollment','READY','ADMIN_DISABLED','DISABLED','authorized_administrator'),
 ('relay_enrollment','DEGRADED','HEALTH_RESTORED','READY','fresh_attested_health_receipt'),
 ('relay_enrollment','DEGRADED','POLICY_OR_EPOCH_CHANGED','STALE','authoritative_binding_changed'),
 ('relay_enrollment','DEGRADED','ADMIN_DISABLED','DISABLED','authorized_administrator'),
 ('relay_enrollment','STALE','REATTESTED','READY','identity_image_policy_catalog_and_region_current'),
 ('relay_enrollment','STALE','ADMIN_DISABLED','DISABLED','authorized_administrator'),
 ('relay_enrollment','DISABLED','ADMIN_REENABLED','REGISTERED','authorized_administrator_and_epoch_advanced'),
 ('relay_enrollment','REGISTERED','REVOKED','REVOKED','authorized_administrator_or_identity_revoked'),
 ('relay_enrollment','READY','REVOKED','REVOKED','authorized_administrator_or_identity_revoked'),
 ('relay_enrollment','DEGRADED','REVOKED','REVOKED','authorized_administrator_or_identity_revoked'),
 ('relay_enrollment','STALE','REVOKED','REVOKED','authorized_administrator_or_identity_revoked'),
 ('relay_enrollment','DISABLED','REVOKED','REVOKED','authorized_administrator_or_identity_revoked'),
 ('collection_job','PENDING','CLAIM_ACCEPTED','CLAIMED','ready_enrollment_current_epochs_and_no_active_claim'),
 ('collection_job','PENDING','EXPIRED','EXPIRED','expiry_reached_before_claim'),
 ('collection_job','PENDING','CANCELLED','CANCELLED','coordinator_and_no_claim'),
 ('collection_job','CLAIMED','EXECUTION_STARTED','EXECUTING','claim_token_and_all_bindings_revalidated'),
 ('collection_job','CLAIMED','CLAIM_EXPIRED_UNSTARTED','PENDING','no_attempt_started_and_retry_budget_remaining'),
 ('collection_job','CLAIMED','CLAIM_EXPIRED_AMBIGUOUS','AMBIGUOUS','attempt_may_have_started'),
 ('collection_job','EXECUTING','LOCAL_RESULT_STORED','RESULT_STORED','local_result_hash_and_attempt_token_bound'),
 ('collection_job','EXECUTING','RETRYABLE_ATTEMPT_FAILED','RETRY_WAIT','closed_retryable_error_and_no_local_result'),
 ('collection_job','EXECUTING','EXECUTION_AMBIGUOUS','AMBIGUOUS','upstream_effect_unknown_or_process_lost'),
 ('collection_job','RESULT_STORED','RECEIPT_ACCEPTED','ACCEPTED','exact_receipt_bindings_and_evidence_projection_committed_atomically'),
 ('collection_job','RESULT_STORED','RECEIPT_REFUSED','REFUSED','closed_nonretryable_reason'),
 ('collection_job','AMBIGUOUS','LOCAL_RESULT_RECONCILED','RESULT_STORED','exact_local_attempt_result_found'),
 ('collection_job','AMBIGUOUS','SAFE_RETRY_AUTHORIZED','PENDING','adapter_retryable_and_budget_remaining_and_no_local_result'),
 ('collection_job','AMBIGUOUS','AMBIGUITY_EXHAUSTED','REFUSED','reconciliation_or_retry_budget_exhausted'),
 ('collection_job','RETRY_WAIT','SAFE_RETRY_AUTHORIZED','PENDING','retryable_error_and_budget_remaining'),
 ('collection_job','RETRY_WAIT','RETRY_BUDGET_EXHAUSTED','REFUSED','retry_budget_exhausted');

CREATE TABLE relay_image_attestations (
  id text PRIMARY KEY CHECK (id ~ '^ria_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  build_provenance_ref text NOT NULL,
  build_provenance_digest text NOT NULL CHECK (build_provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
  sbom_ref text NOT NULL,
  sbom_digest text NOT NULL CHECK (sbom_digest ~ '^sha256:[0-9a-f]{64}$'),
  vulnerability_scan_ref text NOT NULL,
  vulnerability_scan_digest text NOT NULL CHECK (vulnerability_scan_digest ~ '^sha256:[0-9a-f]{64}$'),
  signer_principal text NOT NULL,
  signing_key_id text NOT NULL REFERENCES relay_signing_key_revisions(key_id),
  decision text NOT NULL CHECK (decision IN ('ALLOW','DENY','REVOKED','EXPIRED')),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (id, image_digest, decision),
  CHECK (expires_at > issued_at),
  CHECK ((decision = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE relay_policy_key_revisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 255),
  public_key_ref text NOT NULL,
  public_key_digest text NOT NULL CHECK (public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  algorithm text NOT NULL CHECK (algorithm = 'ECDSA_P256_SHA256'),
  lifecycle text NOT NULL CHECK (lifecycle IN ('ACTIVE','VERIFY_ONLY','REVOKED','EXPIRED')),
  valid_from timestamptz NOT NULL,
  issue_until timestamptz NOT NULL,
  verify_until timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,key_id),
  UNIQUE (organization_id,project_id,environment_id,key_id,public_key_digest),
  CHECK (issue_until >= valid_from),
  CHECK (verify_until >= issue_until),
  CHECK ((lifecycle = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE relay_runtime_proof_key_revisions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 255),
  public_key_digest text NOT NULL CHECK (public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  algorithm text NOT NULL CHECK (algorithm='ECDSA_P256_SHA256'),
  lifecycle text NOT NULL CHECK (lifecycle IN ('ACTIVE','VERIFY_ONLY','REVOKED','EXPIRED')),
  valid_from timestamptz NOT NULL,
  issue_until timestamptz NOT NULL,
  verify_until timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,enrollment_id,
               enrollment_epoch,key_id),
  UNIQUE (organization_id,project_id,environment_id,enrollment_id,
          enrollment_epoch,key_id,public_key_digest),
  CHECK (issue_until >= valid_from AND verify_until >= issue_until),
  CHECK ((lifecycle='REVOKED')=(revoked_at IS NOT NULL))
);

CREATE TABLE relay_enrollments (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ren_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  relay_connection_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  cell_id text NOT NULL,
  host_kind text NOT NULL CHECK (host_kind IN
    ('CLOUD_RUN_WORKER_POOL','GKE','ONPREM_FEDERATED','ONPREM_KEYFILE','DEV_LOCAL')),
  production_eligible boolean NOT NULL,
  risk_acceptance_ref text,
  principal_subject text NOT NULL,
  principal_issuer text NOT NULL CHECK (principal_issuer ~ '^https://'),
  expected_audience text NOT NULL CHECK (expected_audience ~ '^https://'),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  image_attestation_id text NOT NULL REFERENCES relay_image_attestations(id),
  image_attestation_decision text NOT NULL DEFAULT 'ALLOW'
    CHECK (image_attestation_decision = 'ALLOW'),
  local_policy_digest text NOT NULL CHECK (local_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
  connector_catalog_digest text NOT NULL CHECK (connector_catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
  redaction_revision text NOT NULL,
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  relay_version text NOT NULL,
  lifecycle text NOT NULL CHECK (lifecycle IN
    ('REGISTERED','READY','DEGRADED','STALE','DISABLED','REVOKED')),
  workflow_version bigint NOT NULL DEFAULT 0 CHECK (workflow_version >= 0),
  safe_reason_code text,
  last_identity_verified_at timestamptz,
  last_poll_at timestamptz,
  last_receipt_at timestamptz,
  created_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, principal_issuer, principal_subject),
  UNIQUE (organization_id, project_id, environment_id, id, enrollment_epoch),
  UNIQUE (organization_id, project_id, environment_id, id, enrollment_epoch, cell_id, placement_epoch),
  FOREIGN KEY (organization_id, project_id, environment_id, relay_connection_id)
    REFERENCES tenant_connections(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES solvan_scale.tenant_placements(organization_id, placement_epoch, cell_id),
  FOREIGN KEY (image_attestation_id, image_digest, image_attestation_decision)
    REFERENCES relay_image_attestations(id, image_digest, decision),
  CHECK (production_eligible = (host_kind <> 'DEV_LOCAL')),
  CHECK ((host_kind <> 'ONPREM_KEYFILE') OR risk_acceptance_ref IS NOT NULL),
  CHECK (lifecycle <> 'READY' OR
    (production_eligible AND last_identity_verified_at IS NOT NULL AND safe_reason_code IS NULL)),
  CHECK (lifecycle = 'READY' OR safe_reason_code IS NOT NULL)
);
CREATE UNIQUE INDEX relay_one_ready_per_connection
  ON relay_enrollments(organization_id, project_id, environment_id, relay_connection_id)
  WHERE lifecycle = 'READY';
CREATE INDEX relay_health_projection_idx
  ON relay_enrollments(organization_id, project_id, environment_id, lifecycle, last_poll_at);

ALTER TABLE relay_runtime_proof_key_revisions
  ADD FOREIGN KEY (organization_id,project_id,environment_id,enrollment_id)
    REFERENCES relay_enrollments(organization_id,project_id,environment_id,id);

CREATE TABLE relay_readiness_challenges (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rch_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  cell_id text NOT NULL,
  principal_claims_hash text NOT NULL CHECK (principal_claims_hash ~ '^sha256:[0-9a-f]{64}$'),
  expected_audience text NOT NULL CHECK (expected_audience ~ '^https://'),
  process_boot_id text NOT NULL,
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  local_policy_digest text NOT NULL CHECK (local_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
  policy_key_id text NOT NULL,
  connector_catalog_digest text NOT NULL CHECK (connector_catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
  redaction_revision text NOT NULL,
  runtime_proof_key_id text NOT NULL,
  runtime_proof_key_digest text NOT NULL CHECK (runtime_proof_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  nonce_hash text NOT NULL CHECK (nonce_hash ~ '^sha256:[0-9a-f]{64}$'),
  challenge_digest text NOT NULL CHECK (challenge_digest ~ '^sha256:[0-9a-f]{64}$'),
  signing_key_id text NOT NULL REFERENCES relay_signing_key_revisions(key_id),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,nonce_hash),
  UNIQUE (organization_id,project_id,environment_id,id,challenge_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,enrollment_id,
               enrollment_epoch,runtime_proof_key_id,runtime_proof_key_digest)
    REFERENCES relay_runtime_proof_key_revisions
      (organization_id,project_id,environment_id,enrollment_id,
       enrollment_epoch,key_id,public_key_digest),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '60 seconds'),
  CHECK (consumed_at IS NULL OR consumed_at BETWEEN issued_at AND expires_at)
);

CREATE TABLE relay_runtime_policy_proofs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rpf_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  challenge_id text NOT NULL,
  challenge_digest text NOT NULL CHECK (challenge_digest ~ '^sha256:[0-9a-f]{64}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  principal_claims_hash text NOT NULL CHECK (principal_claims_hash ~ '^sha256:[0-9a-f]{64}$'),
  expected_audience text NOT NULL CHECK (expected_audience ~ '^https://'),
  process_boot_id text NOT NULL,
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  local_policy_digest text NOT NULL CHECK (local_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
  local_policy_signature_digest text NOT NULL CHECK (local_policy_signature_digest ~ '^sha256:[0-9a-f]{64}$'),
  policy_key_id text NOT NULL,
  connector_catalog_digest text NOT NULL CHECK (connector_catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
  redaction_revision text NOT NULL,
  runtime_proof_key_id text NOT NULL,
  runtime_proof_key_digest text NOT NULL CHECK (runtime_proof_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  local_policy_verified boolean NOT NULL CHECK (local_policy_verified),
  proof_digest text NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
  signature_base64 text NOT NULL,
  verified_by_principal text NOT NULL,
  verified_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,challenge_id),
  UNIQUE (organization_id,project_id,environment_id,id,proof_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,challenge_id,challenge_digest)
    REFERENCES relay_readiness_challenges
      (organization_id,project_id,environment_id,id,challenge_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,enrollment_id,
               enrollment_epoch,runtime_proof_key_id,runtime_proof_key_digest)
    REFERENCES relay_runtime_proof_key_revisions
      (organization_id,project_id,environment_id,enrollment_id,
       enrollment_epoch,key_id,public_key_digest),
  CHECK (expires_at > verified_at)
);

CREATE TABLE relay_readiness_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rrd_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  cell_id text NOT NULL,
  relay_connection_id text NOT NULL,
  runtime_policy_proof_id text NOT NULL,
  runtime_policy_proof_digest text NOT NULL CHECK (runtime_policy_proof_digest ~ '^sha256:[0-9a-f]{64}$'),
  principal_claims_hash text NOT NULL CHECK (principal_claims_hash ~ '^sha256:[0-9a-f]{64}$'),
  expected_audience text NOT NULL CHECK (expected_audience ~ '^https://'),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  image_attestation_id text NOT NULL,
  image_attestation_decision text NOT NULL CHECK (image_attestation_decision='ALLOW'),
  local_policy_id text NOT NULL CHECK (local_policy_id ~ '^rpol_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  local_policy_digest text NOT NULL CHECK (local_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
  local_policy_signature_digest text NOT NULL CHECK (local_policy_signature_digest ~ '^sha256:[0-9a-f]{64}$'),
  policy_key_id text NOT NULL,
  policy_key_digest text NOT NULL CHECK (policy_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  connector_catalog_digest text NOT NULL CHECK (connector_catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
  redaction_revision text NOT NULL,
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  relay_version text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ALLOW','DENY')),
  safe_reason_code text,
  verified_by_principal text NOT NULL,
  verification_evidence_ref text NOT NULL,
  verification_evidence_digest text NOT NULL CHECK (verification_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch,id),
  FOREIGN KEY (organization_id,project_id,environment_id,enrollment_id)
    REFERENCES relay_enrollments
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,policy_key_id,policy_key_digest)
    REFERENCES relay_policy_key_revisions
      (organization_id,project_id,environment_id,key_id,public_key_digest),
  FOREIGN KEY (image_attestation_id,image_digest,image_attestation_decision)
    REFERENCES relay_image_attestations(id,image_digest,decision),
  FOREIGN KEY (organization_id,project_id,environment_id,
               runtime_policy_proof_id,runtime_policy_proof_digest)
    REFERENCES relay_runtime_policy_proofs
      (organization_id,project_id,environment_id,id,proof_digest),
  CHECK (expires_at > observed_at),
  CHECK ((decision='ALLOW') = (safe_reason_code IS NULL))
);
CREATE INDEX relay_readiness_current_idx
  ON relay_readiness_receipts
    (organization_id,project_id,environment_id,enrollment_id,enrollment_epoch,expires_at DESC);

CREATE FUNCTION assert_runtime_policy_proof_challenge() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM relay_readiness_challenges c
     WHERE (c.organization_id,c.project_id,c.environment_id,c.id,c.challenge_digest)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.challenge_id,NEW.challenge_digest)
       AND (c.enrollment_id,c.enrollment_epoch,c.placement_epoch,
            c.principal_claims_hash,c.expected_audience,c.process_boot_id,
            c.image_digest,c.local_policy_digest,c.policy_key_id,
            c.connector_catalog_digest,c.redaction_revision,
            c.runtime_proof_key_id,c.runtime_proof_key_digest,c.region,
            c.classification_ceiling)=
           (NEW.enrollment_id,NEW.enrollment_epoch,NEW.placement_epoch,
            NEW.principal_claims_hash,NEW.expected_audience,NEW.process_boot_id,
            NEW.image_digest,NEW.local_policy_digest,NEW.policy_key_id,
            NEW.connector_catalog_digest,NEW.redaction_revision,
            NEW.runtime_proof_key_id,NEW.runtime_proof_key_digest,NEW.region,
            NEW.classification_ceiling)
       AND c.consumed_at=NEW.verified_at
       AND NEW.verified_at BETWEEN c.issued_at AND c.expires_at
       AND NEW.expires_at <= c.expires_at
  ) THEN RAISE EXCEPTION 'runtime policy proof does not match one consumed challenge'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER runtime_policy_proof_exact_challenge
  AFTER INSERT ON relay_runtime_policy_proofs DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_runtime_policy_proof_challenge();

CREATE TABLE relay_source_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rsb_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  source_connection_id text NOT NULL,
  source_connection_epoch bigint NOT NULL CHECK (source_connection_epoch > 0),
  adapter_key text NOT NULL,
  adapter_revision text NOT NULL,
  local_binding_digest text NOT NULL CHECK (local_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
  capability_receipt_id text NOT NULL,
  capability_receipt_hash text NOT NULL CHECK (capability_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  region text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  lifecycle text NOT NULL CHECK (lifecycle IN ('REGISTERED','READY','STALE','DISABLED','REVOKED')),
  safe_reason_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
          source_connection_id,source_connection_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,enrollment_id)
    REFERENCES relay_enrollments
      (organization_id,project_id,environment_id,id),
  FOREIGN KEY (organization_id,project_id,environment_id,source_connection_id)
    REFERENCES tenant_connections(organization_id,project_id,environment_id,id),
  CHECK (lifecycle <> 'READY' OR safe_reason_code IS NULL),
  CHECK (lifecycle = 'READY' OR safe_reason_code IS NOT NULL)
);
CREATE UNIQUE INDEX relay_one_ready_transport_per_source
  ON relay_source_bindings(organization_id,project_id,environment_id,source_connection_id)
  WHERE lifecycle='READY';
CREATE INDEX relay_source_binding_resolution_idx
  ON relay_source_bindings
    (organization_id,project_id,environment_id,source_connection_id,
     source_connection_epoch,lifecycle);

CREATE TABLE relay_enrollment_transitions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^ret_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  from_state text NOT NULL,
  event text NOT NULL,
  to_state text NOT NULL,
  workflow_version bigint NOT NULL CHECK (workflow_version > 0),
  machine text NOT NULL DEFAULT 'relay_enrollment' CHECK (machine='relay_enrollment'),
  reason_code text NOT NULL,
  principal text NOT NULL,
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, enrollment_id, workflow_version),
  FOREIGN KEY (organization_id, project_id, environment_id, enrollment_id)
    REFERENCES relay_enrollments
      (organization_id, project_id, environment_id, id),
  FOREIGN KEY (machine,from_state,event,to_state)
    REFERENCES relay_transition_rules(machine,from_state,event,to_state),
  CHECK (from_state <> to_state)
);
CREATE INDEX relay_transition_history_idx
  ON relay_enrollment_transitions
    (organization_id, project_id, environment_id, enrollment_id, occurred_at DESC);

CREATE TABLE collection_jobs (
  schema_version integer NOT NULL CHECK (schema_version=1),
  canonicalization_version integer NOT NULL CHECK (canonicalization_version=1),
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rcj_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  enrollment_id text NOT NULL,
  enrollment_epoch bigint NOT NULL CHECK (enrollment_epoch > 0),
  relay_connection_id text NOT NULL,
  relay_connection_epoch bigint NOT NULL CHECK (relay_connection_epoch > 0),
  source_binding_id text NOT NULL,
  source_connection_id text NOT NULL,
  source_connection_epoch bigint NOT NULL CHECK (source_connection_epoch > 0),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  cell_id text NOT NULL,
  agent_run_id text NOT NULL,
  tool_call_id text NOT NULL,
  tool_arguments_hash text NOT NULL CHECK (tool_arguments_hash ~ '^sha256:[0-9a-f]{64}$'),
  incident_id text NOT NULL,
  profile_key text NOT NULL,
  profile_version text NOT NULL,
  profile_material_hash text NOT NULL CHECK (profile_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  profile_ordinal integer NOT NULL CHECK (profile_ordinal > 0),
  tool_key text NOT NULL,
  tool_version text NOT NULL,
  capability_receipt_id text NOT NULL,
  capability_receipt_hash text NOT NULL CHECK (capability_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  connector_catalog_key text NOT NULL CHECK (connector_catalog_key='gcp-observe.v1'),
  connector_catalog_revision integer NOT NULL CHECK (connector_catalog_revision=1),
  connector_catalog_digest text NOT NULL CHECK (connector_catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
  adapter_key text NOT NULL,
  adapter_revision text NOT NULL,
  operation text NOT NULL,
  typed_parameters_json jsonb NOT NULL CHECK (jsonb_typeof(typed_parameters_json) = 'object'),
  parameters_hash text NOT NULL CHECK (parameters_hash ~ '^sha256:[0-9a-f]{64}$'),
  resource_binding_id text NOT NULL CHECK
    (resource_binding_id ~ '^pgn_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  graph_snapshot_id text NOT NULL CHECK
    (graph_snapshot_id ~ '^pgs_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  resource_binding_hash text NOT NULL CHECK (resource_binding_hash ~ '^sha256:[0-9a-f]{64}$'),
  window_start timestamptz,
  window_end timestamptz,
  maximum_pages integer NOT NULL CHECK (maximum_pages BETWEEN 1 AND 20),
  maximum_items integer NOT NULL CHECK (maximum_items BETWEEN 1 AND 1000),
  maximum_bytes integer NOT NULL CHECK (maximum_bytes BETWEEN 1 AND 1048576),
  maximum_calls integer NOT NULL CHECK (maximum_calls BETWEEN 1 AND 20),
  maximum_attempts integer NOT NULL CHECK (maximum_attempts BETWEEN 1 AND 2),
  redaction_revision text NOT NULL,
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  residency_region text NOT NULL,
  input_hash text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
  job_digest text NOT NULL CHECK (job_digest ~ '^sha256:[0-9a-f]{64}$'),
  job_nonce text NOT NULL,
  signing_key_id text NOT NULL REFERENCES relay_signing_key_revisions(key_id),
  signature_base64 text NOT NULL,
  job_wakeup_outbox_event_id text NOT NULL,
  state text NOT NULL CHECK (state IN
    ('PENDING','CLAIMED','EXECUTING','RETRY_WAIT','RESULT_STORED','AMBIGUOUS',
     'ACCEPTED','REFUSED','EXPIRED','CANCELLED')),
  workflow_version bigint NOT NULL DEFAULT 0 CHECK (workflow_version >= 0),
  refusal_reason text,
  claim_request_nonce text,
  claim_token uuid,
  lease_owner text,
  lease_expires_at timestamptz,
  cancel_requested_at timestamptz,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, tool_call_id),
  UNIQUE (organization_id, project_id, environment_id, id, job_digest),
  FOREIGN KEY (organization_id, project_id, environment_id, enrollment_id)
    REFERENCES relay_enrollments
      (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, relay_connection_id)
    REFERENCES tenant_connections(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, source_connection_id)
    REFERENCES tenant_connections(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id,project_id,environment_id,source_binding_id,
               enrollment_id,enrollment_epoch,source_connection_id,source_connection_epoch)
    REFERENCES relay_source_bindings
      (organization_id,project_id,environment_id,id,enrollment_id,enrollment_epoch,
       source_connection_id,source_connection_epoch),
  FOREIGN KEY (organization_id, project_id, environment_id, agent_run_id)
    REFERENCES agent_runs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, tool_call_id)
    REFERENCES tool_calls(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, job_wakeup_outbox_event_id)
    REFERENCES outbox_events(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, incident_id)
    REFERENCES incidents(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, cell_id,
               placement_epoch, graph_snapshot_id, resource_binding_id)
    REFERENCES solvan_graph.graph_nodes
      (organization_id, project_id, environment_id, cell_id, placement_epoch,
       snapshot_id, node_id),
  CHECK (window_end IS NULL OR window_start IS NOT NULL),
  CHECK (window_end IS NULL OR window_end >= window_start),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '120 seconds'),
  CHECK (state NOT IN ('CLAIMED','EXECUTING','RETRY_WAIT','RESULT_STORED','AMBIGUOUS') OR
    (claim_request_nonce IS NOT NULL AND claim_token IS NOT NULL AND
     lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK (state <> 'PENDING' OR
    (claim_request_nonce IS NULL AND claim_token IS NULL AND
     lease_owner IS NULL AND lease_expires_at IS NULL)),
  CHECK ((state IN ('ACCEPTED','REFUSED','EXPIRED','CANCELLED')) = (completed_at IS NOT NULL)),
  CHECK (state <> 'REFUSED' OR refusal_reason IS NOT NULL)
);
CREATE UNIQUE INDEX relay_one_active_job_per_enrollment
  ON collection_jobs(organization_id, project_id, environment_id, enrollment_id)
  WHERE state IN ('CLAIMED','EXECUTING','RETRY_WAIT','RESULT_STORED','AMBIGUOUS');
CREATE INDEX relay_pending_jobs_idx
  ON collection_jobs
    (organization_id, project_id, environment_id, enrollment_id, issued_at)
  WHERE state = 'PENDING';
CREATE INDEX relay_expiry_reconciliation_idx
  ON collection_jobs(expires_at, lease_expires_at)
  WHERE state IN ('PENDING','CLAIMED','EXECUTING','RETRY_WAIT','RESULT_STORED','AMBIGUOUS');

CREATE TABLE collection_job_transitions (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rjt_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  collection_job_id text NOT NULL,
  workflow_version bigint NOT NULL CHECK (workflow_version > 0),
  machine text NOT NULL DEFAULT 'collection_job' CHECK (machine='collection_job'),
  from_state text NOT NULL,
  event text NOT NULL,
  to_state text NOT NULL,
  reason_code text NOT NULL,
  claim_token uuid,
  principal text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,collection_job_id,workflow_version),
  FOREIGN KEY (organization_id,project_id,environment_id,collection_job_id)
    REFERENCES collection_jobs(organization_id,project_id,environment_id,id),
  FOREIGN KEY (machine,from_state,event,to_state)
    REFERENCES relay_transition_rules(machine,from_state,event,to_state),
  CHECK (from_state <> to_state)
);
CREATE INDEX relay_job_transition_history_idx
  ON collection_job_transitions
    (organization_id,project_id,environment_id,collection_job_id,workflow_version);

CREATE TABLE relay_attempts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rat_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  collection_job_id text NOT NULL,
  job_digest text NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 2),
  claim_token uuid NOT NULL,
  process_boot_id text NOT NULL,
  adapter_revision text NOT NULL,
  state text NOT NULL CHECK (state IN
    ('STARTED','FAILED_RETRYABLE','LOCAL_RESULT_STORED','UPLOADED',
     'ACKNOWLEDGED','AMBIGUOUS','REFUSED')),
  outcome_hash text CHECK (outcome_hash IS NULL OR outcome_hash ~ '^sha256:[0-9a-f]{64}$'),
  error_class text CHECK (error_class IS NULL OR error_class IN
    ('UPSTREAM_UNAVAILABLE','UPSTREAM_RATE_LIMITED')),
  local_result_hash text CHECK (local_result_hash IS NULL OR local_result_hash ~ '^sha256:[0-9a-f]{64}$'),
  started_at timestamptz NOT NULL,
  local_result_stored_at timestamptz,
  terminal_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, collection_job_id, attempt_number),
  UNIQUE (organization_id, project_id, environment_id, id, collection_job_id, job_digest),
  UNIQUE (organization_id, project_id, environment_id, id, collection_job_id,
          job_digest, outcome_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, collection_job_id, job_digest)
    REFERENCES collection_jobs
      (organization_id, project_id, environment_id, id, job_digest),
  CHECK (state NOT IN ('LOCAL_RESULT_STORED','UPLOADED','ACKNOWLEDGED') OR
    (local_result_hash IS NOT NULL AND outcome_hash IS NOT NULL)),
  CHECK (state <> 'STARTED' OR local_result_hash IS NULL),
  CHECK (state = 'STARTED' OR outcome_hash IS NOT NULL),
  CHECK (local_result_stored_at IS NULL OR local_result_stored_at >= started_at),
  CHECK ((state IN ('FAILED_RETRYABLE','ACKNOWLEDGED','REFUSED')) = (terminal_at IS NOT NULL)),
  CHECK ((state='FAILED_RETRYABLE') =
    (error_class IS NOT NULL AND outcome_hash IS NOT NULL AND local_result_hash IS NULL))
);

CREATE TABLE relay_upload_grants (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rug_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  collection_job_id text NOT NULL,
  job_digest text NOT NULL CHECK (job_digest ~ '^sha256:[0-9a-f]{64}$'),
  attempt_id text NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 2),
  claim_token uuid NOT NULL,
  request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  grant_digest text NOT NULL CHECK (grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  object_ref text NOT NULL CHECK (object_ref ~ '^gs://'),
  object_generation_match text NOT NULL,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  evidence_manifest_hash text NOT NULL CHECK (evidence_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  redaction_manifest_hash text NOT NULL CHECK (redaction_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  resource_binding_hash text NOT NULL CHECK (resource_binding_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  residency_region text NOT NULL,
  content_type text NOT NULL,
  content_length integer NOT NULL CHECK (content_length BETWEEN 1 AND 1048576),
  cmek_digest text NOT NULL CHECK (cmek_digest ~ '^sha256:[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  object_generation text,
  object_metadata_hash text CHECK (object_metadata_hash IS NULL OR object_metadata_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id,project_id,environment_id,id),
  UNIQUE (organization_id,project_id,environment_id,id,grant_digest),
  UNIQUE (organization_id,project_id,environment_id,collection_job_id,object_ref),
  UNIQUE (organization_id,project_id,environment_id,request_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,collection_job_id,job_digest)
    REFERENCES collection_jobs
      (organization_id,project_id,environment_id,id,job_digest),
  FOREIGN KEY (organization_id,project_id,environment_id,attempt_id,
               collection_job_id,job_digest)
    REFERENCES relay_attempts
      (organization_id,project_id,environment_id,id,collection_job_id,job_digest),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
  CHECK ((consumed_at IS NULL) =
    (object_generation IS NULL AND object_metadata_hash IS NULL))
);

CREATE TABLE relay_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^rrc_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  collection_job_id text NOT NULL,
  job_digest text NOT NULL,
  attempt_id text NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 2),
  claim_token uuid NOT NULL,
  process_boot_id text NOT NULL,
  receipt_nonce text NOT NULL,
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  result text NOT NULL CHECK (result IN
    ('SUCCEEDED','REFUSED','FAILED_FINAL','AMBIGUOUS')),
  error_class text CHECK (error_class IS NULL OR error_class IN
    ('SIGNATURE_INVALID','JOB_EXPIRED','NONCE_REPLAYED','SCOPE_MISMATCH',
     'CONNECTION_EPOCH_MISMATCH','ENROLLMENT_EPOCH_MISMATCH',
     'POLICY_DIGEST_MISMATCH','CATALOG_DIGEST_MISMATCH',
     'ADAPTER_REVISION_MISMATCH','OPERATION_DENIED','PARAMETER_BOUND_EXCEEDED',
     'ENDPOINT_DENIED','IDENTITY_INVALID','KILL_SWITCH_ENGAGED','UPSTREAM_DENIED',
     'UPSTREAM_UNAVAILABLE','UPSTREAM_RATE_LIMITED','OUTPUT_BOUND_EXCEEDED',
     'REDACTION_FAILED','LOCAL_RESULT_MISSING','UPSTREAM_EFFECT_UNKNOWN')),
  input_hash text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
  attempt_outcome_hash text NOT NULL CHECK (attempt_outcome_hash ~ '^sha256:[0-9a-f]{64}$'),
  local_result_hash text CHECK
    (local_result_hash IS NULL OR local_result_hash ~ '^sha256:[0-9a-f]{64}$'),
  evidence_object_ref text,
  evidence_content_hash text CHECK (evidence_content_hash IS NULL OR evidence_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  evidence_manifest_hash text CHECK (evidence_manifest_hash IS NULL OR evidence_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  redaction_manifest_hash text CHECK (redaction_manifest_hash IS NULL OR redaction_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  resource_binding_hash text CHECK (resource_binding_hash IS NULL OR resource_binding_hash ~ '^sha256:[0-9a-f]{64}$'),
  upload_grant_id text,
  upload_grant_digest text CHECK (upload_grant_digest IS NULL OR upload_grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  object_generation text,
  object_metadata_hash text CHECK (object_metadata_hash IS NULL OR object_metadata_hash ~ '^sha256:[0-9a-f]{64}$'),
  classification text CHECK (classification IS NULL OR classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  residency_region text,
  item_count integer NOT NULL CHECK (item_count BETWEEN 0 AND 1000),
  page_count integer NOT NULL CHECK (page_count BETWEEN 0 AND 20),
  byte_count integer NOT NULL CHECK (byte_count BETWEEN 0 AND 1048576),
  call_count integer NOT NULL CHECK (call_count BETWEEN 0 AND 20),
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, collection_job_id),
  UNIQUE (organization_id, project_id, environment_id, id, collection_job_id),
  UNIQUE (organization_id, project_id, environment_id, receipt_nonce),
  UNIQUE (organization_id, project_id, environment_id, receipt_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, collection_job_id, job_digest)
    REFERENCES collection_jobs
      (organization_id, project_id, environment_id, id, job_digest),
  FOREIGN KEY (organization_id, project_id, environment_id, attempt_id,
               collection_job_id, job_digest)
    REFERENCES relay_attempts
      (organization_id, project_id, environment_id, id, collection_job_id, job_digest),
  FOREIGN KEY (organization_id, project_id, environment_id, attempt_id,
               collection_job_id, job_digest, attempt_outcome_hash)
    REFERENCES relay_attempts
      (organization_id, project_id, environment_id, id, collection_job_id,
       job_digest, outcome_hash),
  FOREIGN KEY (organization_id,project_id,environment_id,
               upload_grant_id,upload_grant_digest)
    REFERENCES relay_upload_grants
      (organization_id,project_id,environment_id,id,grant_digest),
  CHECK (completed_at >= started_at),
  CHECK ((result = 'SUCCEEDED' AND error_class IS NULL AND
     local_result_hash IS NOT NULL AND
     evidence_object_ref IS NOT NULL AND evidence_content_hash IS NOT NULL AND
     evidence_manifest_hash IS NOT NULL AND redaction_manifest_hash IS NOT NULL AND
     resource_binding_hash IS NOT NULL AND upload_grant_id IS NOT NULL AND
     upload_grant_digest IS NOT NULL AND object_generation IS NOT NULL AND
     object_metadata_hash IS NOT NULL AND classification IS NOT NULL AND
     residency_region IS NOT NULL) OR
    (result <> 'SUCCEEDED' AND error_class IS NOT NULL AND
     evidence_object_ref IS NULL AND evidence_content_hash IS NULL AND
     evidence_manifest_hash IS NULL AND redaction_manifest_hash IS NULL AND
     resource_binding_hash IS NULL AND upload_grant_id IS NULL AND
     upload_grant_digest IS NULL AND object_generation IS NULL AND
     object_metadata_hash IS NULL AND classification IS NULL AND
     residency_region IS NULL))
);

CREATE TABLE relay_evidence_acceptances (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  collection_job_id text NOT NULL,
  relay_receipt_id text NOT NULL,
  evidence_item_id text NOT NULL,
  incident_id text NOT NULL,
  accepted_by_principal text NOT NULL,
  acceptance_policy_hash text NOT NULL CHECK (acceptance_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  accepted_outbox_event_id text NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, collection_job_id),
  UNIQUE (organization_id, project_id, environment_id, relay_receipt_id),
  UNIQUE (organization_id, project_id, environment_id, evidence_item_id),
  FOREIGN KEY (organization_id, project_id, environment_id, collection_job_id)
    REFERENCES collection_jobs(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, relay_receipt_id,
               collection_job_id)
    REFERENCES relay_receipts
      (organization_id, project_id, environment_id, id, collection_job_id),
  FOREIGN KEY (organization_id, project_id, environment_id, evidence_item_id)
    REFERENCES evidence_items(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, accepted_outbox_event_id)
    REFERENCES outbox_events(organization_id, project_id, environment_id, id)
);

CREATE TABLE relay_retention_controls (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  object_kind text NOT NULL CHECK (object_kind IN
    ('EVIDENCE_OBJECT','REDACTION_MANIFEST','ATTESTATION','SAFE_RECEIPT')),
  object_id text NOT NULL,
  storage_region text NOT NULL,
  classification text NOT NULL CHECK (classification IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  retention_until timestamptz NOT NULL,
  legal_hold_ref text,
  deletion_state text NOT NULL CHECK (deletion_state IN
    ('RETAIN','DELETE_PENDING','DELETED','REFUSED')),
  deletion_job_ref text,
  deleted_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, object_kind, object_id),
  CHECK (legal_hold_ref IS NULL OR deletion_state = 'RETAIN'),
  CHECK ((deletion_state = 'DELETED') = (deleted_at IS NOT NULL)),
  CHECK (deletion_state <> 'DELETE_PENDING' OR deletion_job_ref IS NOT NULL)
);
CREATE INDEX relay_retention_due_idx
  ON relay_retention_controls(retention_until)
  WHERE deletion_state = 'RETAIN' AND legal_hold_ref IS NULL;

CREATE FUNCTION relay_length_prefix(value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN value IS NULL THEN '-1:'
    ELSE octet_length(convert_to(value,'UTF8'))::text||':'||value END
$$;

CREATE FUNCTION relay_resource_binding_hash(
  schema_version integer, organization_id text, project_id text,
  environment_id text, cell_id text, placement_epoch bigint, snapshot_id text,
  snapshot_material_hash text, node_id text, node_key text, node_kind text,
  resource_ref text, external_project_id text, effective_classification text,
  region text, instrumentation_state text, observation_id text,
  source_key text, source_revision bigint
) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT 'sha256:'||encode(public.digest(convert_to(
    'relay-resource-binding-v1|'||concat_ws('|',
      relay_length_prefix(schema_version::text),relay_length_prefix(organization_id),
      relay_length_prefix(project_id),relay_length_prefix(environment_id),
      relay_length_prefix(cell_id),relay_length_prefix(placement_epoch::text),
      relay_length_prefix(snapshot_id),relay_length_prefix(snapshot_material_hash),
      relay_length_prefix(node_id),relay_length_prefix(node_key),
      relay_length_prefix(node_kind),relay_length_prefix(resource_ref),
      relay_length_prefix(external_project_id),relay_length_prefix(effective_classification),
      relay_length_prefix(region),relay_length_prefix(instrumentation_state),
      relay_length_prefix(observation_id),relay_length_prefix(source_key),
      relay_length_prefix(source_revision::text)), 'UTF8'),'sha256'),'hex')
$$;

CREATE FUNCTION classification_rank(value text) RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE value WHEN 'PUBLIC' THEN 1 WHEN 'INTERNAL' THEN 2
    WHEN 'CONFIDENTIAL' THEN 3 WHEN 'RESTRICTED' THEN 4 ELSE NULL END
$$;

CREATE FUNCTION assert_relay_readiness_proof() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM relay_runtime_policy_proofs p
    JOIN relay_readiness_challenges c ON
      (c.organization_id,c.project_id,c.environment_id,c.id,c.challenge_digest)=
      (p.organization_id,p.project_id,p.environment_id,p.challenge_id,p.challenge_digest)
    WHERE (p.organization_id,p.project_id,p.environment_id,p.id,p.proof_digest)=
          (NEW.organization_id,NEW.project_id,NEW.environment_id,
           NEW.runtime_policy_proof_id,NEW.runtime_policy_proof_digest)
      AND (p.enrollment_id,p.enrollment_epoch,p.placement_epoch,
           p.principal_claims_hash,p.expected_audience,p.image_digest,
           p.local_policy_digest,p.local_policy_signature_digest,p.policy_key_id,
           p.connector_catalog_digest,p.redaction_revision,p.region,
           p.classification_ceiling)=
          (NEW.enrollment_id,NEW.enrollment_epoch,NEW.placement_epoch,
           NEW.principal_claims_hash,NEW.expected_audience,NEW.image_digest,
           NEW.local_policy_digest,NEW.local_policy_signature_digest,NEW.policy_key_id,
           NEW.connector_catalog_digest,NEW.redaction_revision,NEW.region,
           NEW.classification_ceiling)
      AND c.consumed_at IS NOT NULL AND c.consumed_at=p.verified_at
      AND p.verified_at <= NEW.observed_at AND p.expires_at >= NEW.expires_at
  ) THEN RAISE EXCEPTION 'relay readiness receipt lacks exact runtime policy proof'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relay_readiness_exact_runtime_proof
  AFTER INSERT ON relay_readiness_receipts DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_relay_readiness_proof();

CREATE FUNCTION assert_relay_enrollment_ready() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,solvan,solvan_scale,pg_temp AS $$
DECLARE connection_ok boolean; placement_ok boolean; attestation_ok boolean;
        readiness_ok boolean;
BEGIN
  IF NEW.lifecycle <> 'READY' THEN RETURN NEW; END IF;
  SELECT EXISTS (
    SELECT 1 FROM solvan.tenant_connections c
     WHERE (c.organization_id,c.project_id,c.environment_id,c.id)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.relay_connection_id)
       AND c.kind='RELAY' AND c.provider='SOLVAN_RELAY'
       AND c.credential_posture='CUSTOMER_SIDE_NONE'
       AND c.lifecycle='ENABLED' AND c.availability='READY'
  ) INTO connection_ok;
  SELECT EXISTS (
    SELECT 1 FROM solvan_scale.tenant_placements p
     WHERE (p.organization_id,p.placement_epoch,p.cell_id)=
           (NEW.organization_id,NEW.placement_epoch,NEW.cell_id)
       AND p.is_current AND p.lifecycle='ACTIVE' AND p.home_region=NEW.region
  ) INTO placement_ok;
  SELECT EXISTS (
    SELECT 1 FROM relay_image_attestations a
     JOIN relay_signing_key_revisions k ON k.key_id=a.signing_key_id
     WHERE a.id=NEW.image_attestation_id AND a.image_digest=NEW.image_digest
       AND a.decision='ALLOW' AND a.issued_at <= clock_timestamp()
       AND a.expires_at > clock_timestamp()
       AND k.lifecycle IN ('ACTIVE','VERIFY_ONLY')
       AND k.valid_from <= clock_timestamp() AND k.verify_until > clock_timestamp()
  ) INTO attestation_ok;
  SELECT EXISTS (
    SELECT 1 FROM relay_readiness_receipts r
    JOIN relay_policy_key_revisions pk ON
      (pk.organization_id,pk.project_id,pk.environment_id,pk.key_id,pk.public_key_digest)=
      (r.organization_id,r.project_id,r.environment_id,r.policy_key_id,r.policy_key_digest)
     WHERE (r.organization_id,r.project_id,r.environment_id,r.enrollment_id,
            r.enrollment_epoch,r.placement_epoch,r.cell_id,r.relay_connection_id)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
            NEW.enrollment_epoch,NEW.placement_epoch,NEW.cell_id,NEW.relay_connection_id)
       AND r.decision='ALLOW' AND r.expires_at > clock_timestamp()
       AND pk.lifecycle IN ('ACTIVE','VERIFY_ONLY')
       AND pk.valid_from <= r.observed_at AND pk.verify_until > clock_timestamp()
       AND r.expected_audience=NEW.expected_audience
       AND r.image_digest=NEW.image_digest
       AND r.image_attestation_id=NEW.image_attestation_id
       AND r.local_policy_digest=NEW.local_policy_digest
       AND r.connector_catalog_digest=NEW.connector_catalog_digest
       AND r.redaction_revision=NEW.redaction_revision
       AND r.region=NEW.region
       AND r.classification_ceiling=NEW.classification_ceiling
       AND r.relay_version=NEW.relay_version
  ) INTO readiness_ok;
  IF NOT (connection_ok AND placement_ok AND attestation_ok AND readiness_ok) THEN
    RAISE EXCEPTION 'relay enrollment READY prerequisites are not current'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relay_ready_prerequisites
  AFTER INSERT OR UPDATE OF lifecycle,image_digest,image_attestation_id,
    placement_epoch,cell_id,region,relay_connection_id
  ON relay_enrollments DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_relay_enrollment_ready();

CREATE FUNCTION assert_relay_enrollment_transition_recorded() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,pg_temp AS $$
BEGIN
  IF NEW.lifecycle=OLD.lifecycle THEN RETURN NEW; END IF;
  IF NEW.workflow_version <> OLD.workflow_version + 1 OR NOT EXISTS (
    SELECT 1 FROM relay_enrollment_transitions t
     WHERE (t.organization_id,t.project_id,t.environment_id,t.enrollment_id,
            t.workflow_version,t.from_state,t.to_state)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
            NEW.workflow_version,OLD.lifecycle,NEW.lifecycle)
  ) THEN RAISE EXCEPTION 'relay enrollment state change lacks exact transition record'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relay_enrollment_transition_recorded
  AFTER UPDATE OF lifecycle ON relay_enrollments DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_relay_enrollment_transition_recorded();

CREATE FUNCTION assert_collection_job_authority() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,solvan,solvan_graph,solvan_operability,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM solvan.tenant_connections c
     WHERE (c.organization_id,c.project_id,c.environment_id,c.id,c.connection_epoch)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.relay_connection_id,NEW.relay_connection_epoch)
       AND c.kind='RELAY' AND c.provider='SOLVAN_RELAY'
       AND c.credential_posture='CUSTOMER_SIDE_NONE'
       AND c.lifecycle='ENABLED' AND c.availability='READY'
  ) THEN RAISE EXCEPTION 'collection job connection authority is stale'
    USING ERRCODE='23514'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM relay_enrollments e
     WHERE (e.organization_id,e.project_id,e.environment_id,e.id,
            e.enrollment_epoch,e.relay_connection_id,e.cell_id,e.placement_epoch)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.enrollment_id,
            NEW.enrollment_epoch,NEW.relay_connection_id,NEW.cell_id,NEW.placement_epoch)
       AND e.lifecycle='READY' AND e.connector_catalog_digest=NEW.connector_catalog_digest
       AND e.redaction_revision=NEW.redaction_revision
       AND e.region=NEW.residency_region
       AND classification_rank(NEW.classification_ceiling) <=
           classification_rank(e.classification_ceiling)
       AND EXISTS (
         SELECT 1 FROM relay_readiness_receipts rr
          WHERE (rr.organization_id,rr.project_id,rr.environment_id,
                 rr.enrollment_id,rr.enrollment_epoch)=
                (e.organization_id,e.project_id,e.environment_id,e.id,e.enrollment_epoch)
            AND rr.decision='ALLOW' AND rr.expires_at > clock_timestamp()
            AND rr.local_policy_digest=e.local_policy_digest
            AND rr.connector_catalog_digest=e.connector_catalog_digest
            AND rr.image_digest=e.image_digest
       )
  ) THEN RAISE EXCEPTION 'collection job enrollment authority is stale'
    USING ERRCODE='23514'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM relay_source_bindings b
    JOIN solvan.tenant_connections c ON
      (c.organization_id,c.project_id,c.environment_id,c.id,c.connection_epoch)=
      (b.organization_id,b.project_id,b.environment_id,b.source_connection_id,
       b.source_connection_epoch)
     WHERE (b.organization_id,b.project_id,b.environment_id,b.id,b.enrollment_id,
            b.enrollment_epoch,b.source_connection_id,b.source_connection_epoch)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.source_binding_id,
            NEW.enrollment_id,NEW.enrollment_epoch,NEW.source_connection_id,
            NEW.source_connection_epoch)
       AND b.lifecycle='READY' AND b.adapter_key=NEW.adapter_key
       AND b.adapter_revision=NEW.adapter_revision
       AND b.capability_receipt_id=NEW.capability_receipt_id
       AND b.capability_receipt_hash=NEW.capability_receipt_hash
       AND b.region=NEW.residency_region
       AND classification_rank(NEW.classification_ceiling) <=
           classification_rank(b.classification_ceiling)
       AND c.credential_posture='CUSTOMER_SIDE_NONE'
       AND c.kind <> 'RELAY' AND c.provider <> 'SOLVAN_RELAY'
       AND c.provider=(CASE
         WHEN NEW.adapter_key='cloud-monitoring.v1' THEN 'CLOUD_MONITORING'
         WHEN NEW.adapter_key='managed-prometheus.v1' THEN 'MANAGED_PROMETHEUS'
         WHEN NEW.adapter_key='cloud-logging.v1' AND NEW.operation='logging.audit-events.read.v1' THEN 'CLOUD_AUDIT'
         WHEN NEW.adapter_key='cloud-logging.v1' THEN 'CLOUD_LOGGING'
         WHEN NEW.adapter_key='cloud-trace.v1' THEN 'CLOUD_TRACE'
         WHEN NEW.adapter_key='kubernetes-metadata.v1' THEN 'KUBERNETES'
         WHEN NEW.adapter_key='error-reporting.v1' THEN 'ERROR_REPORTING'
         WHEN NEW.adapter_key='cloud-resource-metadata.v1' AND NEW.operation='cloud_run.service_revision.read.v1' THEN 'CLOUD_RUN'
         WHEN NEW.adapter_key='cloud-resource-metadata.v1' AND NEW.operation='cloud_sql.instance_metadata.read.v1' THEN 'CLOUD_SQL'
         ELSE NULL END)
       AND c.residency_region=NEW.residency_region
       AND classification_rank(NEW.classification_ceiling) <=
           classification_rank(c.classification)
       AND c.lifecycle='ENABLED' AND c.availability='READY'
  ) THEN RAISE EXCEPTION 'collection job source binding is stale'
    USING ERRCODE='23514'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM solvan_operability.agent_run_tool_bindings rb
    JOIN solvan_operability.agent_run_accepted_tool_bindings ab ON
      (ab.organization_id,ab.project_id,ab.environment_id,ab.agent_run_id)=
      (rb.organization_id,rb.project_id,rb.environment_id,rb.agent_run_id)
     WHERE (rb.organization_id,rb.project_id,rb.environment_id,rb.agent_run_id,
            rb.profile_key,rb.profile_version,rb.profile_material_hash)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.agent_run_id,
            NEW.profile_key,NEW.profile_version,NEW.profile_material_hash)
       AND ab.ordinal=NEW.profile_ordinal AND ab.tool_key=NEW.tool_key
       AND ab.tool_version=NEW.tool_version
       AND ab.connection_id=NEW.source_connection_id
       AND ab.connection_epoch=NEW.source_connection_epoch
       AND ab.capability_receipt_id=NEW.capability_receipt_id
       AND ab.capability_receipt_hash=NEW.capability_receipt_hash
       AND ab.provider=(CASE
         WHEN NEW.adapter_key='cloud-monitoring.v1' THEN 'CLOUD_MONITORING'
         WHEN NEW.adapter_key='managed-prometheus.v1' THEN 'MANAGED_PROMETHEUS'
         WHEN NEW.adapter_key='cloud-logging.v1' AND NEW.operation='logging.audit-events.read.v1' THEN 'CLOUD_AUDIT'
         WHEN NEW.adapter_key='cloud-logging.v1' THEN 'CLOUD_LOGGING'
         WHEN NEW.adapter_key='cloud-trace.v1' THEN 'CLOUD_TRACE'
         WHEN NEW.adapter_key='kubernetes-metadata.v1' THEN 'KUBERNETES'
         WHEN NEW.adapter_key='error-reporting.v1' THEN 'ERROR_REPORTING'
         WHEN NEW.adapter_key='cloud-resource-metadata.v1' AND NEW.operation='cloud_run.service_revision.read.v1' THEN 'CLOUD_RUN'
         WHEN NEW.adapter_key='cloud-resource-metadata.v1' AND NEW.operation='cloud_sql.instance_metadata.read.v1' THEN 'CLOUD_SQL'
         ELSE NULL END)
       AND ab.capability_key=(CASE
         WHEN NEW.adapter_key='cloud-monitoring.v1' THEN 'METRIC_READ'
         WHEN NEW.adapter_key='managed-prometheus.v1' THEN 'PROMQL_READ'
         WHEN NEW.adapter_key='cloud-logging.v1' AND NEW.operation='logging.audit-events.read.v1' THEN 'AUDIT_LOG_READ'
         WHEN NEW.adapter_key='cloud-logging.v1' THEN 'LOG_SEARCH'
         WHEN NEW.adapter_key='cloud-trace.v1' THEN 'TRACE_READ'
         WHEN NEW.adapter_key='kubernetes-metadata.v1' THEN 'KUBERNETES_METADATA_READ'
         WHEN NEW.adapter_key='error-reporting.v1' THEN 'ERROR_GROUP_READ'
         WHEN NEW.adapter_key='cloud-resource-metadata.v1' THEN 'RESOURCE_METADATA_READ'
         ELSE NULL END)
  ) THEN RAISE EXCEPTION 'collection job is not the exact accepted Tool binding'
    USING ERRCODE='23514'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM solvan.tool_calls t
     WHERE (t.organization_id,t.project_id,t.environment_id,t.id,t.agent_run_id,
            t.arguments_hash,t.tool_name,t.status)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.tool_call_id,
            NEW.agent_run_id,NEW.tool_arguments_hash,NEW.tool_key,'RESERVED')
  ) THEN RAISE EXCEPTION 'collection job Tool call binding is not reserved and exact'
    USING ERRCODE='23514'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM relay_signing_key_revisions k
     WHERE k.key_id=NEW.signing_key_id AND k.region=NEW.residency_region
       AND k.lifecycle='ACTIVE' AND k.valid_from <= NEW.issued_at
       AND k.issue_until >= NEW.issued_at AND k.verify_until >= NEW.expires_at
  ) THEN RAISE EXCEPTION 'collection job signing key is not eligible'
    USING ERRCODE='23514'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM solvan_graph.graph_nodes n
    JOIN solvan_graph.graph_snapshots s USING
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id)
    JOIN solvan_graph.graph_scope_bindings scope USING
      (organization_id,project_id,environment_id,cell_id,placement_epoch)
     WHERE (n.organization_id,n.project_id,n.environment_id,n.cell_id,
            n.placement_epoch,n.snapshot_id,n.node_id)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.cell_id,
            NEW.placement_epoch,NEW.graph_snapshot_id,NEW.resource_binding_id)
       AND s.status='APPROVED' AND s.material_hash IS NOT NULL
       AND NEW.resource_binding_hash=relay_resource_binding_hash(
         1,n.organization_id,n.project_id,n.environment_id,n.cell_id,
         n.placement_epoch,n.snapshot_id,s.material_hash,n.node_id,n.node_key,
         n.node_kind,n.resource_ref,n.external_project_id,
         coalesce(n.data_classification,scope.classification_ceiling),n.region,
         n.instrumentation_state,n.observation_id,n.source_key,n.source_revision)
  ) THEN RAISE EXCEPTION 'collection job graph binding is not approved'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_job_authority_current
  AFTER INSERT ON collection_jobs DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_collection_job_authority();

CREATE FUNCTION assert_collection_job_transition_recorded() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,pg_temp AS $$
BEGIN
  IF NEW.state=OLD.state THEN RETURN NEW; END IF;
  IF NEW.workflow_version <> OLD.workflow_version + 1 OR NOT EXISTS (
    SELECT 1 FROM collection_job_transitions t
     WHERE (t.organization_id,t.project_id,t.environment_id,t.collection_job_id,
            t.workflow_version,t.from_state,t.to_state)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.id,
            NEW.workflow_version,OLD.state,NEW.state)
  ) THEN RAISE EXCEPTION 'collection job state change lacks exact transition record'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_job_transition_recorded
  AFTER UPDATE OF state ON collection_jobs DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_collection_job_transition_recorded();

CREATE FUNCTION assert_relay_upload_grant_bindings() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM collection_jobs j
    JOIN relay_attempts a ON
      (a.organization_id,a.project_id,a.environment_id,a.id,
       a.collection_job_id,a.job_digest)=
      (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.attempt_id,
       NEW.collection_job_id,NEW.job_digest)
    WHERE (j.organization_id,j.project_id,j.environment_id,j.id,j.job_digest)=
          (NEW.organization_id,NEW.project_id,NEW.environment_id,
           NEW.collection_job_id,NEW.job_digest)
      AND j.claim_token=NEW.claim_token AND a.claim_token=NEW.claim_token
      AND a.attempt_number=NEW.attempt_number
      AND a.state IN ('LOCAL_RESULT_STORED','UPLOADED')
      AND a.local_result_hash IS NOT NULL
      AND NEW.resource_binding_hash=j.resource_binding_hash
      AND NEW.residency_region=j.residency_region
      AND classification_rank(NEW.classification) <=
          classification_rank(j.classification_ceiling)
      AND NEW.content_length <= j.maximum_bytes
  ) THEN RAISE EXCEPTION 'relay upload grant does not match job and attempt authority'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relay_upload_grant_exact_bindings
  AFTER INSERT OR UPDATE OF consumed_at,object_generation,object_metadata_hash
  ON relay_upload_grants NOT DEFERRABLE INITIALLY IMMEDIATE
  FOR EACH ROW EXECUTE FUNCTION assert_relay_upload_grant_bindings();

CREATE FUNCTION assert_relay_receipt_bindings() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM collection_jobs j
    JOIN relay_attempts a ON
      (a.organization_id,a.project_id,a.environment_id,a.id,
       a.collection_job_id,a.job_digest)=
      (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.attempt_id,
       NEW.collection_job_id,NEW.job_digest)
     WHERE (j.organization_id,j.project_id,j.environment_id,j.id,j.job_digest)=
           (NEW.organization_id,NEW.project_id,NEW.environment_id,
            NEW.collection_job_id,NEW.job_digest)
       AND j.claim_token=NEW.claim_token AND j.input_hash=NEW.input_hash
       AND a.claim_token=NEW.claim_token AND a.attempt_number=NEW.attempt_number
       AND a.process_boot_id=NEW.process_boot_id
       AND a.outcome_hash=NEW.attempt_outcome_hash
       AND a.local_result_hash IS NOT DISTINCT FROM NEW.local_result_hash
       AND (NEW.result <> 'SUCCEEDED' OR (
         NEW.resource_binding_hash=j.resource_binding_hash
       AND NEW.residency_region=j.residency_region
       AND classification_rank(NEW.classification) <=
           classification_rank(j.classification_ceiling)
       AND EXISTS (
         SELECT 1 FROM relay_upload_grants g
          WHERE (g.organization_id,g.project_id,g.environment_id,g.id,g.grant_digest)=
                (NEW.organization_id,NEW.project_id,NEW.environment_id,
                 NEW.upload_grant_id,NEW.upload_grant_digest)
            AND g.collection_job_id=NEW.collection_job_id
            AND g.attempt_id=NEW.attempt_id AND g.attempt_number=NEW.attempt_number
            AND g.claim_token=NEW.claim_token AND g.consumed_at IS NOT NULL
            AND g.object_ref=NEW.evidence_object_ref
            AND g.content_hash=NEW.evidence_content_hash
            AND g.evidence_manifest_hash=NEW.evidence_manifest_hash
            AND g.redaction_manifest_hash=NEW.redaction_manifest_hash
            AND g.resource_binding_hash=NEW.resource_binding_hash
            AND g.classification=NEW.classification
            AND g.residency_region=NEW.residency_region
            AND g.object_generation=NEW.object_generation
            AND g.object_metadata_hash=NEW.object_metadata_hash)))
  ) THEN RAISE EXCEPTION 'relay receipt does not match its job and attempt'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relay_receipt_exact_bindings
  AFTER INSERT ON relay_receipts DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_relay_receipt_bindings();

CREATE FUNCTION assert_relay_evidence_acceptance() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_relay,solvan,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM collection_jobs j
    JOIN relay_receipts r ON
      (r.organization_id,r.project_id,r.environment_id,r.collection_job_id)=
      (j.organization_id,j.project_id,j.environment_id,j.id)
    JOIN solvan.evidence_items e ON
      (e.organization_id,e.project_id,e.environment_id,e.id)=
      (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.evidence_item_id)
    WHERE (j.organization_id,j.project_id,j.environment_id,j.id)=
          (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.collection_job_id)
      AND r.id=NEW.relay_receipt_id AND r.result='SUCCEEDED'
      AND j.state='ACCEPTED' AND j.completed_at IS NOT NULL
      AND j.incident_id=NEW.incident_id AND e.incident_id=NEW.incident_id
      AND r.resource_binding_hash=j.resource_binding_hash
      AND r.residency_region=j.residency_region
      AND classification_rank(r.classification) <=
          classification_rank(j.classification_ceiling)
      AND e.source_kind='SOLVAN_RELAY'
      AND e.content_ref=r.evidence_object_ref
      AND e.content_hash=r.evidence_content_hash
      AND e.classification=r.classification AND e.residency=r.residency_region
      AND e.redaction_manifest_ref=r.redaction_manifest_hash
      AND e.created_by_agent_run_id=j.agent_run_id
      AND e.provenance_json=jsonb_build_object(
        'schema_version',1,
        'collection_job_id',j.id,
        'job_digest',j.job_digest,
        'relay_receipt_id',r.id,
        'receipt_hash',r.receipt_hash,
        'upload_grant_id',r.upload_grant_id,
        'upload_grant_digest',r.upload_grant_digest,
        'object_generation',r.object_generation,
        'object_metadata_hash',r.object_metadata_hash,
        'evidence_manifest_hash',r.evidence_manifest_hash,
        'redaction_manifest_hash',r.redaction_manifest_hash,
        'resource_binding_hash',r.resource_binding_hash,
        'source_binding_id',j.source_binding_id,
        'source_connection_id',j.source_connection_id,
        'source_connection_epoch',j.source_connection_epoch,
        'enrollment_id',j.enrollment_id,
        'enrollment_epoch',j.enrollment_epoch,
        'adapter_key',j.adapter_key,
        'adapter_revision',j.adapter_revision,
        'operation',j.operation)
      AND EXISTS (
        SELECT 1 FROM relay_upload_grants g
         WHERE (g.organization_id,g.project_id,g.environment_id,g.id,g.grant_digest)=
               (r.organization_id,r.project_id,r.environment_id,
                r.upload_grant_id,r.upload_grant_digest)
           AND g.consumed_at IS NOT NULL
           AND g.object_ref=r.evidence_object_ref
           AND g.object_generation=r.object_generation
           AND g.object_metadata_hash=r.object_metadata_hash)
      AND EXISTS (
        SELECT 1 FROM relay_attempts a
         WHERE (a.organization_id,a.project_id,a.environment_id,a.id)=
               (r.organization_id,r.project_id,r.environment_id,r.attempt_id)
           AND a.state='ACKNOWLEDGED' AND a.terminal_at IS NOT NULL)
      AND EXISTS (
        SELECT 1 FROM collection_job_transitions t
         WHERE (t.organization_id,t.project_id,t.environment_id,t.collection_job_id,
                t.workflow_version,t.from_state,t.event,t.to_state)=
               (j.organization_id,j.project_id,j.environment_id,j.id,
                j.workflow_version,'RESULT_STORED','RECEIPT_ACCEPTED','ACCEPTED'))
      AND EXISTS (
        SELECT 1 FROM solvan.tool_calls t
         WHERE (t.organization_id,t.project_id,t.environment_id,t.id,t.agent_run_id,
                t.status,t.evidence_item_id)=
               (j.organization_id,j.project_id,j.environment_id,j.tool_call_id,
                j.agent_run_id,'SUCCEEDED',e.id))
      AND EXISTS (
        SELECT 1 FROM solvan.outbox_events o
         WHERE (o.organization_id,o.project_id,o.environment_id,o.id)=
               (NEW.organization_id,NEW.project_id,NEW.environment_id,
                NEW.accepted_outbox_event_id)
           AND o.aggregate_type='RELAY_COLLECTION_JOB'
           AND o.aggregate_id=j.id AND o.aggregate_version=j.workflow_version
           AND o.topic='relay.evidence.accepted'
           AND o.event_type='RELAY_EVIDENCE_ACCEPTED'
           AND o.idempotency_key='relay-evidence-accepted:'||j.id
           AND o.payload_json=jsonb_build_object(
             'collection_job_id',j.id,'relay_receipt_id',r.id,
             'evidence_item_id',e.id,'tool_call_id',j.tool_call_id))
  ) THEN RAISE EXCEPTION 'relay evidence acceptance bindings do not agree'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relay_evidence_acceptance_exact
  AFTER INSERT ON relay_evidence_acceptances DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_relay_evidence_acceptance();

-- Sole successful acceptance command. Deployment grants the control-plane
-- application role EXECUTE on this function, never direct DML on its member
-- tables. Deferred constraints above adjudicate the completed bundle.
CREATE FUNCTION relay_commit_success_v1(
  p_receipt relay_receipts,
  p_evidence solvan.evidence_items,
  p_acceptance relay_evidence_acceptances,
  p_transition collection_job_transitions,
  p_outbox solvan.outbox_events
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=solvan_relay,solvan,pg_temp AS $$
DECLARE job collection_jobs%ROWTYPE;
BEGIN
  SELECT * INTO job FROM collection_jobs
   WHERE (organization_id,project_id,environment_id,id)=
         (p_receipt.organization_id,p_receipt.project_id,
          p_receipt.environment_id,p_receipt.collection_job_id)
   FOR UPDATE;
  IF job.id IS NULL OR job.state <> 'RESULT_STORED'
     OR p_receipt.result <> 'SUCCEEDED'
     OR p_transition.collection_job_id <> job.id
     OR p_transition.workflow_version <> job.workflow_version+1
     OR (p_transition.from_state,p_transition.event,p_transition.to_state) <>
        ('RESULT_STORED','RECEIPT_ACCEPTED','ACCEPTED')
     OR p_acceptance.collection_job_id <> job.id
     OR p_acceptance.relay_receipt_id <> p_receipt.id
     OR p_acceptance.evidence_item_id <> p_evidence.id
     OR p_acceptance.accepted_outbox_event_id <> p_outbox.id THEN
    RAISE EXCEPTION 'relay success command members do not form one exact bundle'
      USING ERRCODE='23514';
  END IF;

  UPDATE relay_upload_grants SET consumed_at=clock_timestamp(),
    object_generation=p_receipt.object_generation,
    object_metadata_hash=p_receipt.object_metadata_hash
   WHERE (organization_id,project_id,environment_id,id,grant_digest)=
         (p_receipt.organization_id,p_receipt.project_id,p_receipt.environment_id,
          p_receipt.upload_grant_id,p_receipt.upload_grant_digest)
     AND consumed_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'relay upload grant is absent or consumed'
    USING ERRCODE='23514'; END IF;

  INSERT INTO relay_receipts SELECT (p_receipt).*;
  INSERT INTO solvan.evidence_items SELECT (p_evidence).*;
  UPDATE relay_attempts SET state='ACKNOWLEDGED',terminal_at=clock_timestamp()
   WHERE (organization_id,project_id,environment_id,id,collection_job_id)=
         (job.organization_id,job.project_id,job.environment_id,
          p_receipt.attempt_id,job.id)
     AND state IN ('LOCAL_RESULT_STORED','UPLOADED');
  IF NOT FOUND THEN RAISE EXCEPTION 'relay attempt cannot be acknowledged'
    USING ERRCODE='23514'; END IF;
  INSERT INTO solvan.outbox_events SELECT (p_outbox).*;
  INSERT INTO collection_job_transitions SELECT (p_transition).*;
  UPDATE solvan.tool_calls SET status='SUCCEEDED',evidence_item_id=p_evidence.id,
    error_class=NULL,completed_at=clock_timestamp()
   WHERE (organization_id,project_id,environment_id,id,agent_run_id,status)=
         (job.organization_id,job.project_id,job.environment_id,
          job.tool_call_id,job.agent_run_id,'RESERVED');
  IF NOT FOUND THEN RAISE EXCEPTION 'relay Tool call cannot complete'
    USING ERRCODE='23514'; END IF;
  UPDATE collection_jobs SET state='ACCEPTED',
    workflow_version=p_transition.workflow_version,completed_at=clock_timestamp()
   WHERE (organization_id,project_id,environment_id,id,state,workflow_version)=
         (job.organization_id,job.project_id,job.environment_id,job.id,
          'RESULT_STORED',job.workflow_version);
  IF NOT FOUND THEN RAISE EXCEPTION 'relay job acceptance lost compare-and-set'
    USING ERRCODE='23514'; END IF;
  INSERT INTO relay_evidence_acceptances SELECT (p_acceptance).*;
END $$;

-- Every tenant-scoped Relay table is isolated with the same database-enforced
-- scope predicate as the authoritative schema. Global signing keys and image
-- attestations contain no tenant content and remain available only to typed
-- control-plane repositories.
DO $relay_scope_policies$
DECLARE scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
      FROM information_schema.columns
     WHERE table_schema = 'solvan_relay'
       AND column_name IN ('organization_id','project_id','environment_id')
     GROUP BY table_name
    HAVING count(DISTINCT column_name) = 3
  LOOP
    EXECUTE format('ALTER TABLE solvan_relay.%I ENABLE ROW LEVEL SECURITY',
                   scoped_table.table_name);
    EXECUTE format('ALTER TABLE solvan_relay.%I FORCE ROW LEVEL SECURITY',
                   scoped_table.table_name);
    EXECUTE format(
      'CREATE POLICY exact_scope_isolation ON solvan_relay.%I '
      'USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))',
      scoped_table.table_name);
  END LOOP;
END
$relay_scope_policies$;

REVOKE ALL ON SCHEMA solvan_relay FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA solvan_relay FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA solvan_relay FROM PUBLIC;

COMMIT;
