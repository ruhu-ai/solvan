-- Negative constraint oracles for specification 18 target migration v3.
SET search_path TO solvan_operability, solvan, public;
BEGIN;

INSERT INTO solvan.organizations(id, display_name)
VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S', 'Skills contract')
ON CONFLICT DO NOTHING;
INSERT INTO solvan.projects(organization_id, id, display_name, gcp_project_id)
VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'Skills contract','solvan-skills-contract')
ON CONFLICT DO NOTHING;
INSERT INTO solvan.environments
  (organization_id, project_id, id, display_name, region, classification)
VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','Skills contract','europe-west1','INTERNAL')
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION skills_must_fail(statement text, label text)
RETURNS void AS $$
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    RAISE NOTICE 'ok: %', label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION skills_must_fail_check(
  statement text, label text, expected_constraint text
)
RETURNS void AS $$
DECLARE
  actual_constraint text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS actual_constraint = CONSTRAINT_NAME;
    IF actual_constraint <> expected_constraint THEN
      RAISE EXCEPTION 'wrong constraint for %: expected %, got %',
        label, expected_constraint, actual_constraint;
    END IF;
    RAISE NOTICE 'ok: %', label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END
$$ LANGUAGE plpgsql;

INSERT INTO operability_role_bindings
  (organization_id, project_id, environment_id, principal, role, department, granted_by)
VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','user:exporter@example.com',
        'GUIDANCE_EXPORTER','Payments SRE','test');
SELECT 1 AS exporter_role_is_representable;
DELETE FROM operability_role_bindings
 WHERE organization_id='org_01J4QZK8Q4J8Q6B95KQY4M9R2S'
   AND project_id='prj_01J4QZK8Q4J8Q6B95KQY4M9R2S'
   AND environment_id='env_01J4QZK8Q4J8Q6B95KQY4M9R2S'
   AND principal='user:exporter@example.com';

SELECT skills_must_fail($$
  INSERT INTO skill_import_attempts
    (organization_id, project_id, environment_id, id, import_request_hash, idempotency_key,
     source_kind, source_ref, purpose, requested_classification, requested_region,
     decision, reason_codes_json, importer_principal, authorization_ref)
  VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','sia_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'sha256:1111111111111111111111111111111111111111111111111111111111111111','idem-00000001',
          'ARCHIVE','upload://1','GUIDANCE_IMPORT','INTERNAL','europe-west1',
          'UNKNOWN','[]','user:author@example.com','grant://1')
$$, 'skill import decision is closed');

INSERT INTO skill_import_attempts
  (organization_id, project_id, environment_id, id, import_request_hash, idempotency_key,
   source_kind, source_ref, purpose, requested_classification, requested_region,
   decision, reason_codes_json, importer_principal, authorization_ref)
VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
        'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','sia_01J4QZK8Q4J8Q6B95KQY4M9R2T',
        'sha256:7777777777777777777777777777777777777777777777777777777777777777',
        'idem-00000002','ARCHIVE','upload://2','GUIDANCE_IMPORT','INTERNAL',
        'europe-west1','QUARANTINED','[]','user:author@example.com','grant://2');

SELECT skills_must_fail_check($$
  INSERT INTO skill_imports
    (organization_id, project_id, environment_id, id, attempt_id, source_skill_name,
     source_bundle_hash, normalized_package_hash, guidance_content_hash,
     canonicalization_version, package_object_ref, package_object_hash,
     content_manifest_ref, license_state, normalized_license_identifier,
     license_evidence_ref, license_evidence_hash, scanner_versions_json)
  VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','si_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'sia_01J4QZK8Q4J8Q6B95KQY4M9R2T','demo',
          'sha256:1111111111111111111111111111111111111111111111111111111111111111',
          'sha256:2222222222222222222222222222222222222222222222222222222222222222',
          'sha256:3333333333333333333333333333333333333333333333333333333333333333',
          'skill-canonicalization/1','gs://bucket/package',
          'sha256:4444444444444444444444444444444444444444444444444444444444444444',
          'gs://bucket/manifest','PRESENT','Apache-2.0',NULL,NULL,'{}')
$$, 'present license requires evidence artifact and digest',
    'skill_imports_license_binding_check');

SELECT skills_must_fail_check($$
  INSERT INTO skill_export_receipts
    (organization_id, project_id, environment_id, attempt_id, guidance_key,
     guidance_version, lifecycle_at_export, export_request_hash, export_bundle_hash,
     guidance_content_hash, stale_acknowledged, license_policy_result, byte_rescan_result,
     scanner_receipts_json, disclosure_policy_version, destination_kind,
     destination_binding_ref,destination_region,destination_receipt_ref,
     destination_receipt_generation)
  VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','sea_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'demo','1','APPROVED',
          'sha256:4444444444444444444444444444444444444444444444444444444444444444',
          'sha256:5555555555555555555555555555555555555555555555555555555555555555',
          'sha256:6666666666666666666666666666666666666666666666666666666666666666',
          false,'DENIED','ALLOWED',
          '[{"scanner":"a"},{"scanner":"b"},{"scanner":"c"},{"scanner":"d"}]',
          'policy/1','GCS','gs://skills-export/path','europe-west1',
          'gs://skills-export/path/export.zip#generation=1','1')
$$, 'an export receipt cannot claim a denied license policy',
    'skill_export_receipts_policy_check');

SELECT skills_must_fail($$
  INSERT INTO skill_retention_controls
    (organization_id, project_id, environment_id, object_kind, object_id,
     storage_region, retention_until, legal_hold_ref, deletion_state,
     deletion_job_ref, deleted_at)
  VALUES ('org_01J4QZK8Q4J8Q6B95KQY4M9R2S','prj_01J4QZK8Q4J8Q6B95KQY4M9R2S',
          'env_01J4QZK8Q4J8Q6B95KQY4M9R2S','SOURCE_PACKAGE','obj_1',
          'europe-west1', now(), 'hold_1', 'DELETED', 'job_1', now())
$$, 'a legal hold cannot be deleted');

ROLLBACK;
