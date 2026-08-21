-- Negative constraint oracle for specifications 16 and 17 target DDL.

SET search_path TO solvan_operability, solvan, public;
BEGIN;

CREATE OR REPLACE FUNCTION operability_must_fail(
  statement text,
  label text,
  expected_state text,
  expected_fragment text
)
RETURNS void AS $$
DECLARE
  actual_state text;
  actual_message text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN others THEN
    GET STACKED DIAGNOSTICS
      actual_state = RETURNED_SQLSTATE,
      actual_message = MESSAGE_TEXT;
    IF actual_state IS DISTINCT FROM expected_state OR
       position(expected_fragment IN actual_message) = 0 THEN
      RAISE EXCEPTION
        'wrong refusal for %: expected [% / %], got [% / %]',
        label, expected_state, expected_fragment, actual_state, actual_message;
    END IF;
    RAISE NOTICE 'ok [%/%]: %', actual_state, expected_fragment, label;
    RETURN;
  END;
  RAISE EXCEPTION 'constraint did not hold: %', label;
END;
$$ LANGUAGE plpgsql;

-- v6 turned these two tables into revision histories with a current head, and
-- the head carries a composite foreign key over the whole material tuple so it
-- cannot name material that was never published. Publication therefore appends
-- the revision first and then points the head at it, which is what
-- `register_principal` and `publish_tool` do. This oracle still seeded heads
-- directly, so every load after v6 aborted here and took the rest of
-- `scripts/check` with it.
INSERT INTO catalog_principal_revisions
  (principal_key, version, display_name, registry_kind, execution_role,
   model_backed, manifest_hash)
VALUES
  ('evidence-agent', 1, 'Evidence Agent', 'AGENT', 'SPECIALIST', true,
   'sha256:1111111111111111111111111111111111111111111111111111111111111111'),
  ('action-actuator', 1, 'Action Actuator', 'DETERMINISTIC_SERVICE', 'SERVICE', false,
   'sha256:2222222222222222222222222222222222222222222222222222222222222222');

INSERT INTO catalog_principals
  (principal_key, display_name, registry_kind, execution_role, model_backed, manifest_hash)
VALUES
  ('evidence-agent', 'Evidence Agent', 'AGENT', 'SPECIALIST', true,
   'sha256:1111111111111111111111111111111111111111111111111111111111111111'),
  ('action-actuator', 'Action Actuator', 'DETERMINISTIC_SERVICE', 'SERVICE', false,
   'sha256:2222222222222222222222222222222222222222222222222222222222222222');

SELECT operability_must_fail($$
  INSERT INTO catalog_principals
    (principal_key, display_name, registry_kind, execution_role, model_backed, manifest_hash)
  VALUES ('bad-agent','Bad Agent','AGENT','SERVICE',true,
          'sha256:1111111111111111111111111111111111111111111111111111111111111111')
$$, 'a model-backed Agent cannot carry deterministic SERVICE role',
    '23514', 'catalog_principals_check');

INSERT INTO tool_definition_revisions(tool_key, version, display_name, owner_department)
VALUES
  ('bounded_read', 1, 'Bounded read', 'Reliability'),
  ('production_mutation', 1, 'Production mutation', 'Reliability');

INSERT INTO tool_definitions(tool_key, display_name, owner_department)
VALUES
  ('bounded_read', 'Bounded read', 'Reliability'),
  ('production_mutation', 'Production mutation', 'Reliability');

INSERT INTO tool_revisions
  (tool_key, version, description, permission_class, implementation_kind,
   required_capabilities_json, required_connection_providers_json,
   input_schema_ref, input_schema_hash, output_schema_ref, output_schema_hash,
   use_cases_json, anti_use_cases_json, evidence_kind, output_semantics_json,
   supported_retrieval_controls_json, no_data_semantics, failure_taxonomy_json,
   supported_data_classes_json, runtime_regions_json, registry_resource,
   gateway_destination, model_armor_coverage, network_policy_hash, timeout_ms,
   max_input_bytes, max_output_bytes, default_call_budget, idempotency,
   lifecycle, approval_ref, evaluation_ref, content_hash)
VALUES
  ('bounded_read','1','one typed read','READ','CONNECTOR',
   '["metrics.read"]','["MANAGED_PROMETHEUS"]','schema://in',
   'sha256:1111111111111111111111111111111111111111111111111111111111111111',
   'schema://out','sha256:1111111111111111111111111111111111111111111111111111111111111111',
   '["bounded evidence read"]','["arbitrary query"]','METRICS',
   '["bounded series"]','["bounded_window"]','UNKNOWN','["NO_DATA"]',
   '["INTERNAL"]','["europe-west1"]','registry://read','monitoring.googleapis.com',
   'NOT_APPLICABLE','sha256:1111111111111111111111111111111111111111111111111111111111111111',
   10000,4096,65536,3,'NOT_APPLICABLE','APPROVED','approval://1','evaluation://1',
   'sha256:3333333333333333333333333333333333333333333333333333333333333333'),
  ('production_mutation','1','one enumerated mutation','MUTATE','DETERMINISTIC_SERVICE',
   '["action.execute"]','["SOLVAN_COLLECTOR"]','schema://mutation-in',
   'sha256:2222222222222222222222222222222222222222222222222222222222222222',
   'schema://mutation-out','sha256:2222222222222222222222222222222222222222222222222222222222222222',
   '["execute an authorized action"]','["model-facing use"]','NONE',
   '["execution receipt"]','["exact_action"]','NOT_APPLICABLE','["POLICY_DENIED"]',
   '["INTERNAL"]','["europe-west1"]','registry://mutation','actuator.internal',
   'NOT_APPLICABLE','sha256:2222222222222222222222222222222222222222222222222222222222222222',
   10000,4096,65536,1,'SOLVAN_RECONCILED','APPROVED','approval://2','evaluation://2',
   'sha256:4444444444444444444444444444444444444444444444444444444444444444');

SELECT operability_must_fail($$
  INSERT INTO tool_revision_requesters(tool_key, tool_version, requester_key)
  VALUES ('production_mutation','1','evidence-agent')
$$, 'a model-backed Agent cannot request a MUTATE Tool',
    'P0001', 'model-backed Agent cannot request a MUTATE Tool');

INSERT INTO tool_revision_requesters(tool_key, tool_version, requester_key)
VALUES ('production_mutation','1','action-actuator'),
       ('bounded_read','1','evidence-agent');

INSERT INTO tool_profile_revisions
  (schema_version, canonicalization_version, profile_key, version, purpose,
   allowed_agent_key, maximum_total_calls, maximum_parallel_calls,
   maximum_read_window_ms, maximum_aggregate_evidence_bytes,
   data_classification_ceiling, runtime_region, lifecycle, profile_material_hash,
   approval_ref, evaluation_ref)
VALUES (2,1,'evidence.core','1','bounded evidence','evidence-agent',3,1,
        3600000,1048576,'INTERNAL','europe-west1','APPROVED',
        'sha256:5555555555555555555555555555555555555555555555555555555555555555',
        'approval://profile','evaluation://profile');

INSERT INTO tool_profile_members
  (profile_key, profile_version, ordinal, tool_key, tool_version)
VALUES ('evidence.core','1',1,'bounded_read','1');

INSERT INTO tool_profile_connection_requirements
  (profile_key, profile_version, ordinal, tool_key, tool_version, binding_kind)
VALUES ('evidence.core','1',1,'bounded_read','1','COMPUTE_ONLY');

SELECT operability_must_fail($$
  INSERT INTO tool_profile_members
    (profile_key, profile_version, ordinal, tool_key, tool_version)
  VALUES ('evidence.core','1',2,'production_mutation','1')
$$, 'a model-facing profile cannot contain a MUTATE Tool',
    'P0001', 'model-facing profile cannot contain a MUTATE Tool');

SELECT operability_must_fail($$
  INSERT INTO tool_profile_revisions
    (schema_version, canonicalization_version, profile_key, version, purpose,
     allowed_agent_key, maximum_total_calls, maximum_parallel_calls,
     maximum_read_window_ms, maximum_aggregate_evidence_bytes,
     data_classification_ceiling, runtime_region, lifecycle, profile_material_hash)
  VALUES (2,1,'unapproved.profile','1','bad','evidence-agent',1,1,
          3600000,1048576,'INTERNAL','europe-west1','APPROVED',
          'sha256:6666666666666666666666666666666666666666666666666666666666666666')
$$, 'an approved profile requires approval and evaluation',
    '23514', 'tool_profile_revisions_check');

SELECT operability_must_fail($$
  INSERT INTO tool_probe_receipts
    (organization_id, project_id, environment_id, id, connection_id,
     connection_epoch, tool_key, tool_version, agent_key, identity_ref,
     registry_resource, gateway_policy_ref, network_policy_hash, outcome,
     reason_code, missing_grant, observed_at, expires_at, receipt_ref, receipt_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','tpr_01J4QZK8Q4J8Q6B95KQY4M9R2S','missing',1,
          'bounded_read','1','evidence-agent','identity://evidence','registry://read',
          'gateway://1',
          'sha256:1111111111111111111111111111111111111111111111111111111111111111',
          'PASSED','SHOULD_BE_NULL','roles/monitoring.viewer',now(),now()+interval '1 hour',
          'receipt://1',
          'sha256:1111111111111111111111111111111111111111111111111111111111111111')
$$, 'a successful probe cannot carry failure material',
    '23514', 'tool_probe_receipts_check');

INSERT INTO guidance_definitions
  (organization_id, project_id, environment_id, guidance_key, display_name,
   owner_department)
VALUES ('org_0000000000000000000000000J','prj_x','env_x','payments.pool','Payments pool','Reliability');

SELECT operability_must_fail($$
  INSERT INTO guidance_revisions
    (organization_id, project_id, environment_id, guidance_key, version,
     description, discoverable_departments_json, guidance_kind,
     applicable_service_kinds_json, applicable_incident_classes_json,
     symptom_tags_json, purpose, classification, eligible_regions_json,
     content_ref, content_hash, revision_hash, source_kind, source_ref, evaluation_ref,
     approval_ref, approved_digest, author_principal, approved_by_principal,
     lifecycle, approved_at)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','payments.pool','1','pool diagnosis',
          '["Reliability"]','RUNBOOK','["CLOUD_RUN"]','["CONNECTION_EXHAUSTION"]',
          '["http-503"]','INCIDENT_INVESTIGATION','INTERNAL','["europe-west1"]',
          'gs://guidance/body',
          'sha256:7777777777777777777777777777777777777777777777777777777777777777',
          'sha256:7777777777777777777777777777777777777777777777777777777777777777',
          'SOLVAN_AUTHORED','repo://guidance','evaluation://1','approval://1',
          'sha256:7777777777777777777777777777777777777777777777777777777777777777',
          'user:same@example.com','user:same@example.com','APPROVED',now())
$$, 'a guidance author cannot approve their own revision',
    '23514', 'guidance_revisions_check');

SELECT operability_must_fail($$
  INSERT INTO trigger_policy_revisions
    (organization_id, project_id, environment_id, policy_key, version,
     owner_department, trigger_kind, source_connection_id,
     source_connection_epoch, source_tool_key, source_tool_version,
     source_agent_key, source_identity_ref, source_capability_class,
     target_selector_ref, incident_class, severity,
     deduplication_dimension, action_budget, repeated_action_limit,
     profile_key, profile_version,
     delay_ms, cooldown_ms, maximum_pending_per_target, supersession, region,
     classification_ceiling, lifecycle, author_principal, policy_hash)
  VALUES ('org_0000000000000000000000000J','prj_x','env_x','rollout.trigger','1','Reliability',
          'DEPLOYMENT_ROLLOUT','missing',1,'bounded_read','1',
          'evidence-agent','identity://evidence-agent/1','METRIC_READ',
          'selector://1','deployment_regression',
          'SEV3','rollout',2,1,'evidence.core','1',
          0,0,1,'LATEST_WAITING_PER_TARGET','europe-west1','INTERNAL','APPROVED',
          'user:trigger-author@example.com',
          'sha256:9999999999999999999999999999999999999999999999999999999999999999')
$$, 'an approved trigger policy requires approval and evaluation',
    '23514', 'trigger_policy_revisions_check');

-- v7: the catalog is immutable at the database, not only at the store. These
-- hostile writes would otherwise succeed for any principal with SQL access.
SELECT operability_must_fail($$
  UPDATE tool_revisions SET lifecycle='RETIRED'
    WHERE tool_key='bounded_read' AND version='1'
$$, 'a published Tool revision cannot be retired out of band',
    '55000', 'immutable after insert');

SELECT operability_must_fail($$
  UPDATE tool_profile_revisions SET lifecycle='RETIRED'
$$, 'a published profile revision cannot be retired out of band',
    '55000', 'immutable after insert');

SELECT operability_must_fail($$
  DELETE FROM tool_profile_members
$$, 'profile membership cannot be rewritten out of band',
    '55000', 'immutable after insert');

SELECT operability_must_fail($$
  DELETE FROM tool_profile_connection_requirements
$$, 'profile connection requirements cannot be rewritten out of band',
    '55000', 'immutable after insert');

-- A probe receipt must exist for the row trigger to meet.
INSERT INTO solvan.organizations(id, display_name)
VALUES ('org_00000000000000000000000901', 'Probe immutability') ON CONFLICT DO NOTHING;
INSERT INTO solvan.projects(organization_id, id, display_name, gcp_project_id)
VALUES ('org_00000000000000000000000901', 'prj_00000000000000000000000901', 'Probe immutability', 'solvan-test')
ON CONFLICT DO NOTHING;
INSERT INTO solvan.environments(organization_id, project_id, id, display_name, region, classification)
VALUES ('org_00000000000000000000000901', 'prj_00000000000000000000000901', 'env_00000000000000000000000901',
        'Probe immutability', 'europe-west1', 'INTERNAL')
ON CONFLICT DO NOTHING;
INSERT INTO solvan.tenant_connections
  (organization_id, project_id, environment_id, id, display_name, kind, provider,
   credential_posture, authentication_mode, residency_region, classification,
   connection_epoch, lifecycle, availability, availability_reason_code,
   availability_explanation, availability_remediation_kind, availability_receipt_ref,
   solvan_delegator_principal, customer_reader_principal, delegation_condition_digest,
   token_lifetime_seconds, last_probe_at, last_probe_result, last_success_at,
   created_by_principal)
VALUES ('org_00000000000000000000000901', 'prj_00000000000000000000000901', 'env_00000000000000000000000901',
        'con_00000000000000000000000901', 'Probe connection', 'GCP_NATIVE', 'CLOUD_MONITORING',
        'FEDERATED_SHORT_LIVED', 'GCP_SERVICE_ACCOUNT_IMPERSONATION', 'europe-west1',
        'INTERNAL', 1, 'ENABLED', 'READY', NULL, NULL, NULL, 'probe://immutability',
        'serviceAccount:reader@solvan.iam.gserviceaccount.com',
        'serviceAccount:reader@metrics-scope.iam.gserviceaccount.com',
        'sha256:' || repeat('e', 64), 900, now(), 'SUCCEEDED', now(), 'admin@example.com');
INSERT INTO tool_probe_receipts
  (organization_id, project_id, environment_id, id, connection_id,
   connection_epoch, tool_key, tool_version, agent_key, identity_ref,
   registry_resource, gateway_policy_ref, network_policy_hash, outcome,
   reason_code, missing_grant, observed_at, expires_at, receipt_ref, receipt_hash)
VALUES ('org_00000000000000000000000901', 'prj_00000000000000000000000901', 'env_00000000000000000000000901',
        'tpr_01J4QZK8Q4J8Q6B95KQY4M9R2X', 'con_00000000000000000000000901', 1,
        'bounded_read', '1', 'evidence-agent', 'identity://evidence', 'registry://read',
        'gateway://1',
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        'PASSED', NULL, NULL, now(), now() + interval '1 hour', 'receipt://immutable',
        'sha256:1111111111111111111111111111111111111111111111111111111111111111');

SELECT operability_must_fail($$
  DELETE FROM tool_probe_receipts WHERE id='tpr_01J4QZK8Q4J8Q6B95KQY4M9R2X'
$$, 'probe receipts cannot be rewritten out of band',
    '55000', 'immutable after insert');

ROLLBACK;
