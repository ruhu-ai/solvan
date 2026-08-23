-- Executable negative/positive constraint checks for the authoritative DDL.
-- This file runs only against a disposable database and rolls back all fixtures.

BEGIN;
SET search_path TO solvan, public;

INSERT INTO organizations (id, display_name)
VALUES ('org_00000000000000000000000000', 'Contract Org');
INSERT INTO projects (organization_id, id, display_name, gcp_project_id)
VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'Contract Project',
  'solvan-contract-project'
);
INSERT INTO environments (
  organization_id, project_id, id, display_name, region, classification
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'Contract Environment',
  'europe-west1',
  'INTERNAL'
);
INSERT INTO services (
  organization_id, project_id, environment_id, id, service_key, display_name,
  platform_kind, platform_resource, owner_department
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'svc_00000000000000000000000000',
  'payments-api',
  'Payments API',
  'CLOUD_RUN_SERVICE',
  'projects/test/locations/europe-west1/services/payments-api',
  'payments'
);
INSERT INTO production_graph_snapshots (
  organization_id, project_id, environment_id, id, version, status,
  source_manifest_ref, content_hash, effective_at, approved_by, approved_at
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'pgs_00000000000000000000000000',
  1,
  'APPROVED',
  'fixture://graph',
  'sha256:graph',
  now(),
  'contract-owner',
  now()
);
INSERT INTO detection_rules (
  organization_id, project_id, environment_id, id, version, service_id,
  incident_class, signal_kind, query_json, evaluation_interval_ms, comparator, threshold,
  sustained_windows, severity, deduplication_dimension,
  action_budget, repeated_action_limit, status,
  calibration_receipt_ref, approved_by, approved_at
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'payments-http-5xx',
  1,
  'svc_00000000000000000000000000',
  'connection_exhaustion',
  'HTTP_5XX_RATIO',
  '{}'::jsonb,
  25000,
  'GT',
  0.05,
  2,
  'SEV2',
  'http-5xx',
  2,
  1,
  'APPROVED',
  'fixture://calibration',
  'contract-owner',
  now()
);

INSERT INTO incidents (
  organization_id, project_id, environment_id, id, display_id,
  state_machine_version, state, severity, incident_class, primary_service_id,
  production_graph_snapshot_id, detected_at, detection_rule_id,
  detection_rule_version, deduplication_key, action_budget,
  repeated_action_limit
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'inc_00000000000000000000000001',
  'INC-0001',
  '1',
  'DETECTED',
  'SEV2',
  'connection_exhaustion',
  'svc_00000000000000000000000000',
  'pgs_00000000000000000000000000',
  now(),
  'payments-http-5xx',
  1,
  'payments-http-5xx:payments-api:http-5xx',
  2,
  1
);
INSERT INTO reliability_cases (
  organization_id, project_id, environment_id, id, display_id,
  state_machine_version, state, next_action_kind, next_action_at
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'rel_00000000000000000000000001',
  'REL-0001',
  '1',
  'OPEN',
  'START_RCA',
  now()
);
UPDATE reliability_cases
SET originating_incident_id = 'inc_00000000000000000000000001'
WHERE organization_id = 'org_00000000000000000000000000'
  AND project_id = 'prj_00000000000000000000000000'
  AND environment_id = 'env_00000000000000000000000000'
  AND id = 'rel_00000000000000000000000001';
UPDATE incidents
SET reliability_case_id = 'rel_00000000000000000000000001'
WHERE organization_id = 'org_00000000000000000000000000'
  AND project_id = 'prj_00000000000000000000000000'
  AND environment_id = 'env_00000000000000000000000000'
  AND id = 'inc_00000000000000000000000001';
INSERT INTO case_incidents (
  organization_id, project_id, environment_id, case_id, incident_id, relationship
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'rel_00000000000000000000000001',
  'inc_00000000000000000000000001',
  'ORIGINATING'
);

INSERT INTO incidents (
  organization_id, project_id, environment_id, id, display_id,
  state_machine_version, state, severity, incident_class, primary_service_id,
  production_graph_snapshot_id, detected_at, detection_rule_id,
  detection_rule_version, deduplication_key, action_budget,
  repeated_action_limit
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'inc_00000000000000000000000002',
  'INC-0002',
  '1',
  'DETECTED',
  'SEV2',
  'connection_exhaustion',
  'svc_00000000000000000000000000',
  'pgs_00000000000000000000000000',
  now(),
  'payments-http-5xx',
  1,
  'payments-http-5xx:payments-api:latency',
  2,
  1
);

INSERT INTO policy_decisions (
  organization_id, project_id, environment_id, id, policy_kind,
  policy_version, input_ref, input_hash, decision, reason_code,
  receipt_ref, receipt_hash
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'pol_00000000000000000000000001',
  'PROVIDER_ELIGIBILITY',
  'workspace-provider-v1',
  'gs://contract/eligibility-input.json',
  'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  'ALLOW',
  'PUBLIC_SYNTHETIC_ATTESTED',
  'gs://contract/eligibility-receipt.json',
  'sha256:2222222222222222222222222222222222222222222222222222222222222222'
);

INSERT INTO workspaces (
  organization_id, project_id, environment_id, id, kind, service_id,
  reliability_case_id, provider, implementation_sdk,
  implementation_sdk_version, provider_revision, registry_agent_key,
  provider_agent_resource, provider_service_identity,
  implementation_sdk_distribution_hash, provider_artifact_digest,
  effective_network_policy_hash,
  classification, synthetic, synthetic_attestation_ref,
  synthetic_attestation_hash, provider_eligibility_decision_id,
  artifact_prefix, input_manifest_ref, input_manifest_hash, status,
  created_by_principal
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'wsp_00000000000000000000000001',
  'INCIDENT',
  'svc_00000000000000000000000000',
  'rel_00000000000000000000000001',
  'ANTIGRAVITY_SDK_CLOUD_RUN',
  'google-antigravity',
  '0.1.13',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'incident-workspace-alpha',
  'https://solvan-antigravity-workspace-test-uc.a.run.app',
  'solvan-antigravity-workspace@test.iam.gserviceaccount.com',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'PUBLIC',
  true,
  'gs://contract/synthetic-attestation.json',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'pol_00000000000000000000000001',
  'gs://contract/workspaces/wsp-1/',
  'gs://contract/workspaces/wsp-1/input.json',
  'sha256:4444444444444444444444444444444444444444444444444444444444444444',
  'OPEN',
  'coordinator:test'
);

INSERT INTO workspace_checkpoints (
  organization_id, project_id, environment_id, id, workspace_id,
  workspace_generation, sequence_no, event_kind, provider,
  implementation_sdk, implementation_sdk_version,
  implementation_sdk_distribution_hash, provider_artifact_digest,
  provider_revision,
  provider_request_hash, provider_receipt_ref, provider_receipt_hash,
  provider_boot_hash, provider_service_revision,
  input_manifest_ref, input_manifest_hash, artifact_manifest_ref,
  artifact_manifest_hash, effective_tool_set_hash, effective_network_policy_hash,
  created_by_principal
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'wck_00000000000000000000000001',
  'wsp_00000000000000000000000001',
  1,
  1,
  'CHECKPOINT',
  'ANTIGRAVITY_SDK_CLOUD_RUN',
  'google-antigravity',
  '0.1.13',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  'gs://contract/workspaces/wsp-1/provider-receipt.json',
  'sha256:abababababababababababababababababababababababababababababababab',
  'sha256:5555555555555555555555555555555555555555555555555555555555555555',
  'solvan-antigravity-workspace-00001-abc',
  'gs://contract/workspaces/wsp-1/input.json',
  'sha256:4444444444444444444444444444444444444444444444444444444444444444',
  'gs://contract/workspaces/wsp-1/checkpoint.json',
  'sha256:6666666666666666666666666666666666666666666666666666666666666666',
  'sha256:7777777777777777777777777777777777777777777777777777777777777777',
  'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'coordinator:test'
);

INSERT INTO workspace_checkpoints (
  organization_id, project_id, environment_id, id, workspace_id,
  workspace_generation, sequence_no, event_kind, parent_checkpoint_id, provider,
  implementation_sdk, implementation_sdk_version,
  implementation_sdk_distribution_hash, provider_artifact_digest,
  provider_revision,
  provider_request_hash, provider_receipt_ref, provider_receipt_hash,
  provider_boot_hash, provider_service_revision,
  input_manifest_ref, input_manifest_hash, artifact_manifest_ref,
  artifact_manifest_hash, effective_tool_set_hash, effective_network_policy_hash,
  created_by_principal
) VALUES (
  'org_00000000000000000000000000',
  'prj_00000000000000000000000000',
  'env_00000000000000000000000000',
  'wck_00000000000000000000000003',
  'wsp_00000000000000000000000001',
  1,
  2,
  'REHYDRATION',
  'wck_00000000000000000000000001',
  'ANTIGRAVITY_SDK_CLOUD_RUN',
  'google-antigravity',
  '0.1.13',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'gs://contract/workspaces/wsp-1/rehydration-receipt.json',
  'sha256:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc',
  'sha256:9999999999999999999999999999999999999999999999999999999999999999',
  'solvan-antigravity-workspace-00002-def',
  'gs://contract/workspaces/wsp-1/input.json',
  'sha256:4444444444444444444444444444444444444444444444444444444444444444',
  'gs://contract/workspaces/wsp-1/rehydration.json',
  'sha256:6666666666666666666666666666666666666666666666666666666666666666',
  'sha256:7777777777777777777777777777777777777777777777777777777777777777',
  'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'coordinator:test'
);

DO $$
BEGIN
  BEGIN
    INSERT INTO case_incidents (
      organization_id, project_id, environment_id, case_id, incident_id, relationship
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'rel_00000000000000000000000001',
      'inc_00000000000000000000000002',
      'ORIGINATING'
    );
    RAISE EXCEPTION 'second originating incident was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO incidents (
      organization_id, project_id, environment_id, id, display_id,
      state_machine_version, state, severity, incident_class, primary_service_id,
      production_graph_snapshot_id, detected_at, detection_rule_id,
      detection_rule_version, deduplication_key, action_budget,
      repeated_action_limit
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'inc_00000000000000000000000003',
      'INC-0003',
      '1',
      'DETECTED',
      'SEV2',
      'connection_exhaustion',
      'svc_00000000000000000000000000',
      'pgs_00000000000000000000000000',
      now(),
      'payments-http-5xx',
      99,
      'invalid-rule-version',
      3,
      1
    );
    RAISE EXCEPTION 'unknown detection-rule version was accepted';
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO reliability_cases (
      organization_id, project_id, environment_id, id, display_id,
      state_machine_version, state, lease_owner
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'rel_00000000000000000000000002',
      'REL-0002',
      '1',
      'OPEN',
      'stale-owner'
    );
    RAISE EXCEPTION 'partial lease tuple was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO workspaces (
      organization_id, project_id, environment_id, id, kind, service_id,
      provider, implementation_sdk, implementation_sdk_version,
      provider_revision, registry_agent_key, provider_agent_resource,
      provider_service_identity, implementation_sdk_distribution_hash,
      provider_artifact_digest, effective_network_policy_hash, classification,
      synthetic, provider_eligibility_decision_id, artifact_prefix,
      input_manifest_ref, input_manifest_hash, status, created_by_principal
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'wsp_00000000000000000000000002',
      'SERVICE',
      'svc_00000000000000000000000000',
      'ANTIGRAVITY_SDK_CLOUD_RUN',
      'google-antigravity',
      '0.1.13',
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'invalid-alpha',
      'https://solvan-antigravity-workspace-test-uc.a.run.app',
      'solvan-antigravity-workspace@test.iam.gserviceaccount.com',
      'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      'INTERNAL',
      false,
      'pol_00000000000000000000000001',
      'gs://contract/workspaces/invalid/',
      'gs://contract/workspaces/invalid/input.json',
      'sha256:8888888888888888888888888888888888888888888888888888888888888888',
      'OPEN',
      'coordinator:test'
    );
    RAISE EXCEPTION 'non-public unattested Antigravity workspace was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO workspace_checkpoints (
      organization_id, project_id, environment_id, id, workspace_id,
      workspace_generation, sequence_no, event_kind, provider,
      implementation_sdk, implementation_sdk_version,
      implementation_sdk_distribution_hash, provider_artifact_digest,
      provider_revision,
      provider_request_hash, provider_receipt_ref, provider_receipt_hash,
      provider_boot_hash, provider_service_revision,
      input_manifest_ref, input_manifest_hash, artifact_manifest_ref,
      artifact_manifest_hash, effective_tool_set_hash, effective_network_policy_hash,
      created_by_principal
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'wck_00000000000000000000000002',
      'wsp_00000000000000000000000001',
      1,
      2,
      'REHYDRATION',
      'ANTIGRAVITY_SDK_CLOUD_RUN',
      'google-antigravity',
      '0.1.13',
      'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      'gs://contract/workspaces/wsp-1/invalid-rehydration-receipt.json',
      'sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
      'sha256:9999999999999999999999999999999999999999999999999999999999999999',
      'solvan-antigravity-workspace-00002-def',
      'gs://contract/workspaces/wsp-1/input.json',
      'sha256:4444444444444444444444444444444444444444444444444444444444444444',
      'gs://contract/workspaces/wsp-1/rehydration.json',
      'sha256:6666666666666666666666666666666666666666666666666666666666666666',
      'sha256:7777777777777777777777777777777777777777777777777777777777777777',
      'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      'coordinator:test'
    );
    RAISE EXCEPTION 'rehydration without parent checkpoint was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO workspace_checkpoints (
      organization_id, project_id, environment_id, id, workspace_id,
      workspace_generation, sequence_no, event_kind, parent_checkpoint_id,
      provider, implementation_sdk, implementation_sdk_version,
      implementation_sdk_distribution_hash, provider_artifact_digest,
      provider_revision,
      provider_request_hash, provider_receipt_ref, provider_receipt_hash,
      provider_boot_hash, provider_service_revision,
      input_manifest_ref, input_manifest_hash, artifact_manifest_ref,
      artifact_manifest_hash, effective_tool_set_hash, effective_network_policy_hash,
      created_by_principal
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'wck_00000000000000000000000004',
      'wsp_00000000000000000000000001',
      1,
      3,
      'REHYDRATION',
      'wck_00000000000000000000000003',
      'ANTIGRAVITY_SDK_CLOUD_RUN',
      'google-antigravity',
      '0.1.13',
      'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'sha256:1212121212121212121212121212121212121212121212121212121212121212',
      'gs://contract/workspaces/wsp-1/reused-boot-receipt.json',
      'sha256:dededededededededededededededededededededededededededededededede',
      'sha256:9999999999999999999999999999999999999999999999999999999999999999',
      'solvan-antigravity-workspace-00002-def',
      'gs://contract/workspaces/wsp-1/input.json',
      'sha256:4444444444444444444444444444444444444444444444444444444444444444',
      'gs://contract/workspaces/wsp-1/rehydration-2.json',
      'sha256:6666666666666666666666666666666666666666666666666666666666666666',
      'sha256:7777777777777777777777777777777777777777777777777777777777777777',
      'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      'coordinator:test'
    );
    RAISE EXCEPTION 'rehydration with a reused boot hash was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

DO $$
BEGIN
  BEGIN
    INSERT INTO outbox_events (
      organization_id, project_id, environment_id, id, aggregate_type,
      aggregate_id, aggregate_version, topic, event_type, payload_json,
      idempotency_key, published_at, quarantined_at
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'evt_00000000000000000000000090',
      'INCIDENT',
      'inc_00000000000000000000000001',
      1,
      'workflow-transitions',
      'ContractCheck',
      '{}',
      'contract-published-and-quarantined',
      now(),
      now()
    );
    RAISE EXCEPTION 'published-and-quarantined outbox event was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO inbox_events (
      organization_id, project_id, environment_id, id, source, source_event_id,
      event_type, payload_ref, payload_hash, attempts
    ) VALUES (
      'org_00000000000000000000000000',
      'prj_00000000000000000000000000',
      'env_00000000000000000000000000',
      'evt_00000000000000000000000091',
      'contract',
      'contract-negative-attempts',
      'ContractCheck',
      'gs://contract/inbox.json',
      'sha256:contract',
      -1
    );
    RAISE EXCEPTION 'negative inbox attempt count was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  -- Specification 13 §4. A connection may only be READY on a successful probe,
  -- and every state that is not READY must say why and what to do about it.
  INSERT INTO tenant_connections (
    organization_id, project_id, environment_id, id, display_name, kind,
    provider, credential_posture, authentication_mode, solvan_delegator_principal,
    customer_reader_principal, delegation_condition_digest, token_lifetime_seconds,
    residency_region, classification, created_by_principal
  ) VALUES (
    'org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','con_00000000000000000000000001',
    'Contract connection','GCP_NATIVE','CLOUD_MONITORING',
    'FEDERATED_SHORT_LIVED','GCP_SERVICE_ACCOUNT_IMPERSONATION',
    'serviceAccount:reader@solvan.iam.gserviceaccount.com',
    'serviceAccount:reader@customer.iam.gserviceaccount.com',
    'sha256:'||repeat('a',64),900,'europe-west1','INTERNAL','contract'
  );

  BEGIN
    UPDATE tenant_connections SET availability = 'READY'
     WHERE id = 'con_00000000000000000000000001';
    RAISE EXCEPTION 'a connection became READY with no successful probe';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- DENIED with no reason code, explanation, remediation, or receipt leaves
    -- an operator knowing only that something failed. The reason fields are
    -- cleared explicitly here: a newly registered row already carries the
    -- NEVER_PROBED default, so an UPDATE that only set availability would
    -- satisfy the constraint on the strength of a stale reason and prove
    -- nothing.
    UPDATE tenant_connections
       SET availability = 'DENIED', availability_reason_code = NULL,
           availability_explanation = NULL,
           availability_remediation_kind = NULL, availability_receipt_ref = NULL
     WHERE id = 'con_00000000000000000000000001';
    RAISE EXCEPTION 'a non-ready availability was accepted with no reason';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- A probe cannot overrule an administrator's decision to stop using a
    -- connection.
    UPDATE tenant_connections
       SET lifecycle = 'DISABLED', availability = 'DEGRADED',
           availability_reason_code = 'PARTIAL_CAPABILITY',
           availability_explanation = 'some capabilities are proven',
           availability_remediation_kind = 'GRANT_ROLE',
           availability_receipt_ref = 'probe://1'
     WHERE id = 'con_00000000000000000000000001';
    RAISE EXCEPTION 'a disabled connection reported a probe-derived availability';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  -- Specification 13 §3.3. Whether a stored key is read-only is an observation.
  -- This was a boolean a caller supplied, so the constraint proved only that
  -- somebody had set it; these three cases are what the column now costs to
  -- lie about.
  BEGIN
    UPDATE tenant_connections SET read_only_scope_verified = true
     WHERE id = 'con_00000000000000000000000001';
    RAISE EXCEPTION 'read-only verification was written directly';
  EXCEPTION WHEN generated_always THEN
    NULL;
  END;

  INSERT INTO tenant_connections (
    organization_id, project_id, environment_id, id, display_name, kind,
    provider, credential_posture, authentication_mode, credential_secret_ref,
    credential_cmek_key_ref, read_only_scope_state, read_only_scope_reason_code,
    residency_region, classification, created_by_principal
  ) VALUES (
    'org_00000000000000000000000000','prj_00000000000000000000000000',
    'env_00000000000000000000000000','con_00000000000000000000000002',
    'Unverified vendor key','VENDOR_API','DATADOG',
    'STORED_LONG_LIVED','STORED_SECRET_REFERENCE',
    'projects/acme/secrets/datadog/versions/3','projects/acme/locations/eu/keyRings/k/cryptoKeys/c',
    'UNVERIFIABLE','NO_SCOPE_INTROSPECTION','europe-west1','INTERNAL','contract'
  );

  BEGIN
    -- An unverified key may be recorded so its refusal is legible, but a key
    -- nobody proved read-only can never be the one a read runs on.
    UPDATE tenant_connections
       SET availability = 'READY', last_probe_result = 'SUCCEEDED'
     WHERE id = 'con_00000000000000000000000002';
    RAISE EXCEPTION 'an unverified stored key became READY';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- An alias follows whatever payload was added most recently, so a
    -- write-capable key could replace a verified one with nothing re-checked.
    UPDATE tenant_connections
       SET credential_secret_ref = 'projects/acme/secrets/datadog/versions/latest'
     WHERE id = 'con_00000000000000000000000002';
    RAISE EXCEPTION 'a floating secret version was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  DELETE FROM tenant_connections WHERE id = 'con_00000000000000000000000002';

  BEGIN
    -- Specification 13 §4.2. A Google Cloud node must name the project that
    -- holds it. Without this a Cloud SQL node carries no address and is read
    -- at whatever project the caller happens to hold, which returns nothing
    -- while looking like an answer.
    INSERT INTO production_graph_nodes (
      organization_id, project_id, environment_id, id, snapshot_id, node_key,
      node_kind, resource_ref, external_project_id, classification, provenance_ref
    ) VALUES (
      'org_00000000000000000000000000','prj_00000000000000000000000000',
      'env_00000000000000000000000000','pgn_00000000000000000000000090',
      'pgs_00000000000000000000000000','contract-database','DATABASE',
      'projects/other/instances/payments', NULL, 'INTERNAL', 'fixture://graph'
    );
    RAISE EXCEPTION 'a Cloud SQL graph node was accepted with no project';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- And a node that is not a Google Cloud resource must not invent one. A
    -- repository lives in git; naming a project for it would be a fiction the
    -- reader could then address.
    INSERT INTO production_graph_nodes (
      organization_id, project_id, environment_id, id, snapshot_id, node_key,
      node_kind, resource_ref, external_project_id, classification, provenance_ref
    ) VALUES (
      'org_00000000000000000000000000','prj_00000000000000000000000000',
      'env_00000000000000000000000000','pgn_00000000000000000000000091',
      'pgs_00000000000000000000000000','contract-repository','REPOSITORY',
      'gs://runtime/repositories/payments.json', 'contract-project', 'INTERNAL',
      'fixture://graph'
    );
    RAISE EXCEPTION 'a repository graph node claimed a Google Cloud project';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- A series projection that is not a series. The console draws an axis from
    -- this column and never reads the evidence object itself, so a malformed
    -- projection would become a malformed chart with no way to notice.
    INSERT INTO evidence_items (
      organization_id, project_id, environment_id, id, incident_id, source_kind,
      source_resource, query_spec_json, window_start, window_end, observed_at,
      content_ref, content_hash, classification, residency,
      redaction_manifest_ref, provenance_json, freshness_expires_at,
      projection_json
    ) VALUES (
      'org_00000000000000000000000000','prj_00000000000000000000000000',
      'env_00000000000000000000000000','evd_00000000000000000000000091',
      'inc_00000000000000000000000001','CLOUD_MONITORING','payments-api',
      '{}'::jsonb, now() - interval '15 minutes', now(), now(),
      'gs://evidence/91.json',
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      'INTERNAL','europe-west1','gs://redaction/91.json','{}'::jsonb,
      now() + interval '7 days',
      '{"kind": "metric_series", "signal_kind": "HTTP_P95_LATENCY", "points": "not-an-array"}'::jsonb
    );
    RAISE EXCEPTION 'a series projection carried points that are not an array';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- The window is bounded at fifteen minutes and the alignment at a minute,
    -- so a projection with more buckets than that describes a window the read
    -- was never allowed to take.
    INSERT INTO evidence_items (
      organization_id, project_id, environment_id, id, incident_id, source_kind,
      source_resource, query_spec_json, window_start, window_end, observed_at,
      content_ref, content_hash, classification, residency,
      redaction_manifest_ref, provenance_json, freshness_expires_at,
      projection_json
    ) VALUES (
      'org_00000000000000000000000000','prj_00000000000000000000000000',
      'env_00000000000000000000000000','evd_00000000000000000000000092',
      'inc_00000000000000000000000001','CLOUD_MONITORING','payments-api',
      '{}'::jsonb, now() - interval '15 minutes', now(), now(),
      'gs://evidence/92.json',
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      'INTERNAL','europe-west1','gs://redaction/92.json','{}'::jsonb,
      now() + interval '7 days',
      jsonb_build_object(
        'kind', 'metric_series',
        'signal_kind', 'HTTP_P95_LATENCY',
        'points', (SELECT jsonb_agg(jsonb_build_object('value', 1)) FROM generate_series(1, 65))
      )
    );
    RAISE EXCEPTION 'a series projection carried more buckets than the window allows';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- An unknown discriminator. The console dispatches on `kind`, so a shape it
    -- has no branch for would render as nothing while looking like evidence.
    INSERT INTO evidence_items (
      organization_id, project_id, environment_id, id, incident_id, source_kind,
      source_resource, query_spec_json, window_start, window_end, observed_at,
      content_ref, content_hash, classification, residency,
      redaction_manifest_ref, provenance_json, freshness_expires_at,
      projection_json
    ) VALUES (
      'org_00000000000000000000000000','prj_00000000000000000000000000',
      'env_00000000000000000000000000','evd_00000000000000000000000093',
      'inc_00000000000000000000000001','CLOUD_RUN_METADATA','payments-api',
      '{}'::jsonb, now() - interval '1 minute', now(), now(),
      'gs://evidence/93.json',
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      'INTERNAL','europe-west1','gs://redaction/93.json','{}'::jsonb,
      now() + interval '7 days',
      '{"kind": "something_else", "revision": "r1", "changed_at": "2026-08-23T00:00:00Z"}'::jsonb
    );
    RAISE EXCEPTION 'a projection carried a discriminator nothing renders';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    -- Availability and outcome are two views of one probe answer.
    INSERT INTO connection_capabilities (
      organization_id, project_id, environment_id, connection_id, capability,
      available, outcome, missing_grant, probe_receipt_ref
    ) VALUES (
      'org_00000000000000000000000000','prj_00000000000000000000000000',
      'env_00000000000000000000000000','con_00000000000000000000000001',
      'metrics.read', true, 'DENIED', 'roles/monitoring.viewer', 'probe://1'
    );
    RAISE EXCEPTION 'an available capability claimed a denied outcome';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

ROLLBACK;
