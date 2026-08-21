-- Target migration for Agent Skills interchange (specification 18).
-- This is not release schema.sql and remains excluded from the MSR.
BEGIN;

-- The baseline role enum predates export destinations. Keep the role additive
-- and scoped: export authorization is still checked by the API and repository
-- boundary, but a legitimate exporter binding must be representable in SQL.
ALTER TABLE solvan_operability.operability_role_bindings
  DROP CONSTRAINT operability_role_bindings_role_check;
ALTER TABLE solvan_operability.operability_role_bindings
  ADD CONSTRAINT operability_role_bindings_role_check CHECK (role IN
    ('GUIDANCE_AUTHOR','GUIDANCE_EVALUATOR','GUIDANCE_APPROVER','GUIDANCE_EXPORTER',
     'TRIGGER_POLICY_AUTHOR','TRIGGER_POLICY_EVALUATOR',
     'TRIGGER_POLICY_APPROVER','TRIGGER_POLICY_ACTIVATOR',
     'TRIGGER_POLICY_LIFECYCLE_MANAGER','OPERABILITY_ADMIN'));

-- Evaluation claims are accepted only from a generation-pinned receipt read
-- through the registered verifier.  Persist the complete reproducibility
-- binding rather than trusting client-supplied PASS metadata.
ALTER TABLE solvan_operability.guidance_evaluations
  ADD COLUMN receipt_generation text NOT NULL CHECK (receipt_generation ~ '^[0-9]+$'),
  ADD COLUMN corpus_digest text NOT NULL CHECK (corpus_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN case_set_digest text NOT NULL CHECK (case_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN scorer_name text NOT NULL CHECK (length(scorer_name) BETWEEN 1 AND 120),
  ADD COLUMN scorer_version text NOT NULL CHECK (length(scorer_version) BETWEEN 1 AND 120),
  ADD COLUMN model_config_pins_json jsonb NOT NULL CHECK
    (jsonb_typeof(model_config_pins_json) = 'object'),
  ADD COLUMN repetitions integer NOT NULL CHECK (repetitions > 0),
  ADD COLUMN pass_thresholds_json jsonb NOT NULL CHECK
    (jsonb_typeof(pass_thresholds_json) = 'object');

CREATE TABLE solvan_operability.skill_owner_department_slugs (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  owner_slug text NOT NULL CHECK (owner_slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  owner_department text NOT NULL CHECK (length(owner_department) BETWEEN 1 AND 160),
  owner_principal text NOT NULL,
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, owner_slug)
);

CREATE TABLE solvan_operability.skill_reader_grants (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  principal text NOT NULL,
  owner_department text NOT NULL CHECK (length(owner_department) BETWEEN 1 AND 160),
  purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 160),
  region text NOT NULL CHECK (region ~ '^[a-z0-9-]+$'),
  classification_ceiling text NOT NULL CHECK
    (classification_ceiling IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  granted_by_principal text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, principal,
               owner_department, purpose, region)
);

CREATE TABLE solvan_operability.skill_license_policies (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  normalized_identifier text NOT NULL CHECK (length(normalized_identifier) BETWEEN 1 AND 160),
  policy_version text NOT NULL,
  import_allowed boolean NOT NULL,
  redistribution_allowed boolean NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  reviewed_by_principal text NOT NULL,
  reviewed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, normalized_identifier)
);

CREATE TABLE solvan_operability.guidance_current_heads (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  approved_version text,
  head_epoch bigint NOT NULL DEFAULT 0 CHECK (head_epoch >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, guidance_key),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key)
    REFERENCES solvan_operability.guidance_definitions(organization_id, project_id, environment_id, guidance_key),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key, approved_version)
    REFERENCES solvan_operability.guidance_revisions(organization_id, project_id, environment_id, guidance_key, version)
);

CREATE TABLE solvan_operability.skill_import_attempts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^sia_[0-9A-HJKMNP-TV-Z]{26}$'),
  import_request_hash text NOT NULL CHECK (import_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  source_kind text NOT NULL CHECK (source_kind IN ('ARCHIVE','REPOSITORY','FIRST_PARTY')),
  source_ref text NOT NULL,
  purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 160),
  requested_classification text NOT NULL CHECK (requested_classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  requested_region text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('QUARANTINED','REJECTED')),
  reason_codes_json jsonb NOT NULL CHECK (jsonb_typeof(reason_codes_json) = 'array'),
  scanner_receipts_json jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(scanner_receipts_json) = 'array'),
  importer_principal text NOT NULL,
  authorization_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, import_request_hash),
  UNIQUE (organization_id, project_id, environment_id, idempotency_key)
);

CREATE TABLE solvan_operability.skill_imports (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^si_[0-9A-HJKMNP-TV-Z]{26}$'),
  attempt_id text NOT NULL,
  source_skill_name text NOT NULL CHECK (length(source_skill_name) BETWEEN 1 AND 160),
  source_bundle_hash text CHECK (source_bundle_hash IS NULL OR source_bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
  normalized_package_hash text NOT NULL CHECK (normalized_package_hash ~ '^sha256:[0-9a-f]{64}$'),
  guidance_content_hash text NOT NULL CHECK (guidance_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  canonicalization_version text NOT NULL CHECK (canonicalization_version = 'skill-canonicalization/1'),
  package_object_ref text NOT NULL,
  package_object_hash text NOT NULL CHECK (package_object_hash ~ '^sha256:[0-9a-f]{64}$'),
  content_manifest_ref text NOT NULL,
  license_state text NOT NULL CHECK (license_state IN ('PRESENT','MISSING','REJECTED_BY_POLICY')),
  normalized_license_identifier text CHECK (
    normalized_license_identifier IS NULL OR
    (length(normalized_license_identifier) BETWEEN 1 AND 160 AND
     normalized_license_identifier !~ '[\r\n]')
  ),
  license_evidence_ref text,
  license_evidence_hash text CHECK (license_evidence_hash IS NULL OR license_evidence_hash ~ '^sha256:[0-9a-f]{64}$'),
  upstream_ref text,
  upstream_subdirectory text,
  upstream_commit_sha text,
  upstream_subtree_hash text CHECK (upstream_subtree_hash IS NULL OR upstream_subtree_hash ~ '^sha256:[0-9a-f]{64}$'),
  scanner_versions_json jsonb NOT NULL CHECK (jsonb_typeof(scanner_versions_json) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, attempt_id),
  FOREIGN KEY (organization_id, project_id, environment_id, attempt_id)
    REFERENCES solvan_operability.skill_import_attempts(organization_id, project_id, environment_id, id),
  CONSTRAINT skill_imports_license_binding_check CHECK (
    (license_state = 'MISSING' AND normalized_license_identifier IS NULL AND
     license_evidence_ref IS NULL AND license_evidence_hash IS NULL) OR
    (license_state IN ('PRESENT','REJECTED_BY_POLICY') AND
     normalized_license_identifier IS NOT NULL AND license_evidence_ref IS NOT NULL AND
     license_evidence_hash IS NOT NULL)
  ),
  CHECK (upstream_subdirectory IS NULL OR
         (length(upstream_subdirectory) <= 512 AND upstream_subdirectory !~ '(^|/)\.\.(/|$)')),
  CHECK (source_bundle_hash IS NOT NULL OR upstream_commit_sha IS NOT NULL)
);

CREATE TABLE solvan_operability.skill_import_files (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  import_id text NOT NULL,
  path text NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  media_type text NOT NULL,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  object_ref text NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('PROMPT_ELIGIBLE','INERT_STORED','STRIPPED')),
  PRIMARY KEY (organization_id, project_id, environment_id, import_id, path),
  FOREIGN KEY (organization_id, project_id, environment_id, import_id)
    REFERENCES solvan_operability.skill_imports(organization_id, project_id, environment_id, id)
);

CREATE TABLE solvan_operability.skill_validation_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  import_id text NOT NULL,
  sequence integer NOT NULL CHECK (sequence > 0),
  reason_code text NOT NULL,
  path text,
  detail_json jsonb NOT NULL CHECK (jsonb_typeof(detail_json) = 'object'),
  object_ref text NOT NULL,
  object_generation text NOT NULL CHECK (object_generation ~ '^[0-9]+$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, import_id, sequence),
  FOREIGN KEY (organization_id, project_id, environment_id, import_id)
    REFERENCES solvan_operability.skill_imports(organization_id, project_id, environment_id, id)
);

CREATE TABLE solvan_operability.skill_retention_policies (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  policy_id text NOT NULL CHECK (policy_id = 'default'),
  storage_region text NOT NULL CHECK (storage_region ~ '^[a-z0-9-]+$'),
  retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, policy_id)
);

CREATE TABLE solvan_operability.skill_refresh_ledgers (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  lease_token text,
  lease_expires_at timestamptz,
  last_checked_at timestamptz,
  last_outcome text CHECK (last_outcome IS NULL OR last_outcome IN ('UNCHANGED','CHANGED','FAILED')),
  failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
  PRIMARY KEY (organization_id, project_id, environment_id, guidance_key),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key)
    REFERENCES solvan_operability.guidance_definitions(organization_id, project_id, environment_id, guidance_key),
  CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL))
);

CREATE TABLE solvan_operability.skill_refresh_attempts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^sra_[0-9A-HJKMNP-TV-Z]{26}$'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  refresh_request_hash text NOT NULL CHECK (refresh_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  guidance_key text NOT NULL,
  expected_head_epoch bigint NOT NULL CHECK (expected_head_epoch > 0),
  decision text NOT NULL CHECK (decision IN ('COMPLETED','REFUSED')),
  outcome text CHECK (outcome IS NULL OR outcome IN ('UNCHANGED','CHANGED')),
  observed_commit_sha text,
  observed_tree_hash text CHECK
    (observed_tree_hash IS NULL OR observed_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  reason_code text,
  requester_principal text NOT NULL,
  authorization_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, idempotency_key),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key)
    REFERENCES solvan_operability.guidance_definitions
      (organization_id, project_id, environment_id, guidance_key),
  CHECK ((decision = 'COMPLETED') =
         (outcome IS NOT NULL AND observed_commit_sha IS NOT NULL AND
          observed_tree_hash IS NOT NULL AND reason_code IS NULL)),
  CHECK ((decision = 'REFUSED') = (reason_code IS NOT NULL))
);

CREATE TABLE solvan_operability.skill_upstream_change_notices (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^suc_[0-9A-HJKMNP-TV-Z]{26}$'),
  guidance_key text NOT NULL,
  upstream_ref text NOT NULL,
  observed_commit_sha text NOT NULL,
  observed_tree_hash text NOT NULL CHECK (observed_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, guidance_key, upstream_ref, observed_commit_sha, observed_tree_hash),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key)
    REFERENCES solvan_operability.guidance_definitions(organization_id, project_id, environment_id, guidance_key)
);

CREATE TABLE solvan_operability.guidance_incompatibilities (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  declaring_guidance_key text NOT NULL,
  declaring_version text NOT NULL,
  incompatible_guidance_key text NOT NULL,
  reason_code text NOT NULL,
  reviewable_digest text NOT NULL CHECK (reviewable_digest ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id, project_id, environment_id, declaring_guidance_key, declaring_version, incompatible_guidance_key),
  FOREIGN KEY (organization_id, project_id, environment_id, declaring_guidance_key, declaring_version)
    REFERENCES solvan_operability.guidance_revisions(organization_id, project_id, environment_id, guidance_key, version),
  FOREIGN KEY (organization_id, project_id, environment_id, incompatible_guidance_key)
    REFERENCES solvan_operability.guidance_definitions(organization_id, project_id, environment_id, guidance_key),
  CHECK (declaring_guidance_key <> incompatible_guidance_key)
);

CREATE TABLE solvan_operability.guidance_skill_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  import_attempt_id text NOT NULL,
  normalized_license_identifier text NOT NULL,
  license_evidence_hash text NOT NULL CHECK (license_evidence_hash ~ '^sha256:[0-9a-f]{64}$'),
  source_classification text NOT NULL CHECK (source_classification IN ('IMPORTED','SOLVAN_AUTHORED')),
  provenance_attestation_ref text,
  provenance_attestation_hash text CHECK
    (provenance_attestation_hash IS NULL OR provenance_attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
  contains_third_party_material boolean NOT NULL DEFAULT false,
  reviewable_digest text NOT NULL CHECK (reviewable_digest ~ '^sha256:[0-9a-f]{64}$'),
  compiled_by_principal text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, guidance_key, guidance_version),
  UNIQUE (organization_id, project_id, environment_id, guidance_key, guidance_version,
          reviewable_digest),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key, guidance_version)
    REFERENCES solvan_operability.guidance_revisions
      (organization_id, project_id, environment_id, guidance_key, version),
  FOREIGN KEY (organization_id, project_id, environment_id, import_attempt_id)
    REFERENCES solvan_operability.skill_import_attempts
      (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, normalized_license_identifier)
    REFERENCES solvan_operability.skill_license_policies
      (organization_id, project_id, environment_id, normalized_identifier),
  CHECK ((provenance_attestation_ref IS NULL) = (provenance_attestation_hash IS NULL)),
  CHECK (source_classification <> 'SOLVAN_AUTHORED' OR
         (provenance_attestation_ref IS NOT NULL AND NOT contains_third_party_material))
);

CREATE TABLE solvan_operability.guidance_invocation_requests (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^gir_[0-9A-HJKMNP-TV-Z]{26}$'),
  thread_id text NOT NULL,
  answer_message_id text NOT NULL,
  anchor_kind text NOT NULL CHECK (anchor_kind IN ('RECORD','SERVICE_WINDOW','SCOPE')),
  anchor_record_type text,
  anchor_record_id text,
  selector text NOT NULL CHECK (length(selector) BETWEEN 2 AND 320),
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  guidance_hash text NOT NULL CHECK (guidance_hash ~ '^sha256:[0-9a-f]{64}$'),
  requester_principal text NOT NULL,
  request_status text NOT NULL CHECK
    (request_status IN ('PENDING_COORDINATOR','ACCEPTED','REFUSED','EXPIRED')),
  membership_epoch bigint NOT NULL CHECK (membership_epoch > 0),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, answer_message_id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               guidance_key, guidance_version)
    REFERENCES solvan_operability.guidance_revisions
      (organization_id, project_id, environment_id, guidance_key, version),
  CHECK ((anchor_kind = 'RECORD' AND anchor_record_type IS NOT NULL AND
          anchor_record_id IS NOT NULL) OR
         (anchor_kind <> 'RECORD' AND anchor_record_type IS NULL AND
          anchor_record_id IS NULL))
);

CREATE TABLE solvan_operability.guidance_invocation_conflicts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  invocation_request_id text NOT NULL,
  conflicting_invocation_request_id text NOT NULL,
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 120),
  detected_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
               invocation_request_id, conflicting_invocation_request_id),
  FOREIGN KEY (organization_id, project_id, environment_id, invocation_request_id)
    REFERENCES solvan_operability.guidance_invocation_requests
      (organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id,
               conflicting_invocation_request_id)
    REFERENCES solvan_operability.guidance_invocation_requests
      (organization_id, project_id, environment_id, id),
  CHECK (invocation_request_id <> conflicting_invocation_request_id)
);

CREATE TABLE solvan_operability.guidance_operator_notes (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  invocation_request_id text NOT NULL,
  note_text text NOT NULL CHECK (length(note_text) <= 2_000),
  note_classification text NOT NULL CHECK (note_classification IN ('INTERNAL','CONFIDENTIAL','RESTRICTED')),
  author_principal text NOT NULL,
  access_mode text NOT NULL CHECK (access_mode IN ('SELECTION_READERS','CASE_READERS')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, invocation_request_id),
  FOREIGN KEY (organization_id, project_id, environment_id, invocation_request_id)
    REFERENCES solvan_operability.guidance_invocation_requests
      (organization_id, project_id, environment_id, id)
);

CREATE TABLE solvan_operability.guidance_selection_analytics (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  selection_reason text NOT NULL CHECK (selection_reason IN ('MODEL_RANKED','OPERATOR_INVOKED')),
  outcome_code text NOT NULL,
  selection_count bigint NOT NULL DEFAULT 0 CHECK (selection_count >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, guidance_key, guidance_version, selection_reason, outcome_code),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key, guidance_version)
    REFERENCES solvan_operability.guidance_revisions(organization_id, project_id, environment_id, guidance_key, version)
);

CREATE TABLE solvan_operability.guidance_export_destinations (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  destination_id text NOT NULL,
  destination_kind text NOT NULL CHECK (destination_kind = 'GCS'),
  binding_ref text NOT NULL CHECK (binding_ref ~ '^gs://[a-z0-9][a-z0-9._-]{1,221}/[^#]*$'),
  region text NOT NULL CHECK (region ~ '^[a-z0-9-]+$'),
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  enabled boolean NOT NULL DEFAULT true,
  PRIMARY KEY (organization_id, project_id, environment_id, destination_id)
);

CREATE TABLE solvan_operability.skill_export_attempts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK (id ~ '^sea_[0-9A-HJKMNP-TV-Z]{26}$'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  export_request_hash text NOT NULL CHECK (export_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  destination_id text NOT NULL,
  purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 160),
  decision text NOT NULL CHECK (decision IN ('PREPARED','EXPORTED','REJECTED','CONFLICT')),
  reason_code text,
  exporter_principal text NOT NULL,
  authorization_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, id),
  UNIQUE (organization_id, project_id, environment_id, idempotency_key),
  UNIQUE (organization_id, project_id, environment_id, export_request_hash),
  CHECK ((decision IN ('PREPARED','EXPORTED')) =
         (authorization_ref IS NOT NULL AND reason_code IS NULL)),
  CHECK ((decision IN ('REJECTED','CONFLICT')) = (reason_code IS NOT NULL))
);

CREATE TABLE solvan_operability.skill_export_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  attempt_id text NOT NULL,
  guidance_key text NOT NULL,
  guidance_version text NOT NULL,
  lifecycle_at_export text NOT NULL CHECK (lifecycle_at_export IN ('APPROVED','DEPRECATED')),
  export_request_hash text NOT NULL CHECK (export_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  export_bundle_hash text NOT NULL CHECK (export_bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
  guidance_content_hash text NOT NULL CHECK (guidance_content_hash ~ '^sha256:[0-9a-f]{64}$'),
  stale_acknowledged boolean NOT NULL,
  license_policy_result text NOT NULL CHECK (license_policy_result IN ('ALLOWED','DENIED')),
  byte_rescan_result text NOT NULL CHECK (byte_rescan_result IN ('ALLOWED','DENIED')),
  scanner_receipts_json jsonb NOT NULL CHECK
    (jsonb_typeof(scanner_receipts_json) = 'array' AND jsonb_array_length(scanner_receipts_json) >= 4),
  disclosure_policy_version text NOT NULL,
  destination_kind text NOT NULL CHECK (destination_kind = 'GCS'),
  destination_binding_ref text NOT NULL CHECK (
    destination_binding_ref ~ '^gs://[a-z0-9][a-z0-9._-]{1,221}/[^#]+$'
  ),
  destination_region text NOT NULL CHECK (destination_region ~ '^[a-z0-9-]+$'),
  destination_receipt_ref text NOT NULL CHECK (destination_receipt_ref ~ '^gs://'),
  destination_receipt_generation text NOT NULL CHECK (destination_receipt_generation ~ '^[0-9]+$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, attempt_id),
  FOREIGN KEY (organization_id, project_id, environment_id, attempt_id)
    REFERENCES solvan_operability.skill_export_attempts(organization_id, project_id, environment_id, id),
  FOREIGN KEY (organization_id, project_id, environment_id, guidance_key, guidance_version)
    REFERENCES solvan_operability.guidance_revisions
      (organization_id, project_id, environment_id, guidance_key, version),
  CONSTRAINT skill_export_receipts_policy_check CHECK
    (license_policy_result = 'ALLOWED' AND byte_rescan_result = 'ALLOWED'),
  CONSTRAINT skill_export_receipts_stale_ack_check CHECK
    ((lifecycle_at_export = 'DEPRECATED' AND stale_acknowledged) OR
     (lifecycle_at_export = 'APPROVED' AND NOT stale_acknowledged))
);

CREATE TABLE solvan_operability.skill_retention_controls (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  object_kind text NOT NULL CHECK (object_kind IN
    ('SOURCE_PACKAGE','CONTENT_MANIFEST','IMPORT_FILE','LICENSE_EVIDENCE',
     'VALIDATION_RECEIPT','EXPORT_RECEIPT')),
  object_id text NOT NULL,
  storage_region text NOT NULL CHECK (storage_region ~ '^[a-z0-9-]+$'),
  retention_until timestamptz NOT NULL,
  legal_hold_ref text,
  object_uri text,
  object_generation text NOT NULL CHECK (object_generation ~ '^[0-9]+$'),
  deletion_state text NOT NULL CHECK (deletion_state IN ('RETAINED','PENDING','DELETED')),
  deletion_job_ref text,
  deletion_claimed_at timestamptz,
  deleted_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, object_kind, object_id),
  CHECK ((deletion_state = 'DELETED') = (deleted_at IS NOT NULL)),
  CHECK (deletion_state <> 'DELETED' OR legal_hold_ref IS NULL),
  CHECK (deletion_state <> 'DELETED' OR deletion_job_ref IS NOT NULL),
  CHECK (deletion_state = 'RETAINED' OR deletion_claimed_at IS NOT NULL),
  CHECK (deletion_state = 'RETAINED' OR object_uri IS NOT NULL)
);

CREATE TABLE solvan_operability.skill_deletion_receipts (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  object_kind text NOT NULL,
  object_id text NOT NULL,
  deletion_job_ref text NOT NULL,
  object_uri text NOT NULL,
  expected_generation text NOT NULL CHECK (expected_generation ~ '^[0-9]+$'),
  provider_receipt_ref text NOT NULL,
  verified_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, object_kind, object_id, deletion_job_ref),
  FOREIGN KEY (organization_id, project_id, environment_id, object_kind, object_id)
    REFERENCES solvan_operability.skill_retention_controls
      (organization_id, project_id, environment_id, object_kind, object_id)
);

CREATE INDEX skill_import_attempts_scope_idx ON solvan_operability.skill_import_attempts
  (organization_id, project_id, environment_id, created_at DESC);
CREATE INDEX skill_import_files_hash_idx ON solvan_operability.skill_import_files
  (organization_id, project_id, environment_id, content_hash);
CREATE INDEX skill_validation_receipts_scope_idx ON solvan_operability.skill_validation_receipts
  (organization_id, project_id, environment_id, created_at DESC);
CREATE INDEX skill_notices_lineage_idx ON solvan_operability.skill_upstream_change_notices
  (organization_id, project_id, environment_id, guidance_key, observed_at DESC);
CREATE INDEX skill_refresh_attempts_lineage_idx ON solvan_operability.skill_refresh_attempts
  (organization_id, project_id, environment_id, guidance_key, created_at DESC);
CREATE INDEX guidance_invocation_requests_pending_idx ON
  solvan_operability.guidance_invocation_requests
  (organization_id, project_id, environment_id, created_at)
  WHERE request_status = 'PENDING_COORDINATOR';
CREATE INDEX skill_export_attempts_revision_idx ON solvan_operability.skill_export_attempts
  (organization_id, project_id, environment_id, guidance_key, guidance_version, created_at DESC);
CREATE INDEX skill_retention_due_idx ON solvan_operability.skill_retention_controls
  (organization_id, project_id, environment_id, retention_until)
  WHERE deletion_state <> 'DELETED' AND legal_hold_ref IS NULL;
CREATE INDEX skill_deletion_receipts_scope_idx ON solvan_operability.skill_deletion_receipts
  (organization_id, project_id, environment_id, verified_at DESC);

DO $skills_scope_policies$
DECLARE
  scoped_table record;
BEGIN
  FOR scoped_table IN
    SELECT table_name
      FROM information_schema.columns
     WHERE table_schema = 'solvan_operability'
       AND column_name IN ('organization_id','project_id','environment_id')
     GROUP BY table_name
    HAVING count(DISTINCT column_name) = 3
  LOOP
    EXECUTE format('ALTER TABLE solvan_operability.%I ENABLE ROW LEVEL SECURITY', scoped_table.table_name);
    EXECUTE format('ALTER TABLE solvan_operability.%I FORCE ROW LEVEL SECURITY', scoped_table.table_name);
    EXECUTE format(
      'CREATE POLICY skill_scope_isolation ON solvan_operability.%I '
      'USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id)) '
      'WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))',
      scoped_table.table_name);
  END LOOP;
END
$skills_scope_policies$;

COMMIT;
