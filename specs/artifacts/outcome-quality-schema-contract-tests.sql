-- Exact negative oracles for outcome quality and earned autonomy.
SET search_path TO solvan_quality, public;
BEGIN ISOLATION LEVEL SERIALIZABLE;

INSERT INTO solvan.organizations(id,display_name)
VALUES ('org_00000000000000000000000001','Quality contract organization');
INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000001',
        'prj_00000000000000000000000001','Quality contract estate','quality-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000001',
        'prj_00000000000000000000000001',
        'env_00000000000000000000000001','Production','europe-west1','INTERNAL');

CREATE OR REPLACE FUNCTION quality_must_violate(
 statement text,expected_state text,expected_constraint text,expected_message text,label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE observed_state text; observed_constraint text; observed_message text;
BEGIN
 BEGIN EXECUTE statement;
 EXCEPTION WHEN others THEN
  GET STACKED DIAGNOSTICS observed_state=RETURNED_SQLSTATE,
   observed_constraint=CONSTRAINT_NAME,observed_message=MESSAGE_TEXT;
  IF observed_state IS DISTINCT FROM expected_state
     OR observed_constraint IS DISTINCT FROM expected_constraint
     OR position(expected_message IN observed_message)=0 THEN
   RAISE EXCEPTION 'oracle % got state %, constraint %, message %',
    label,observed_state,observed_constraint,observed_message;
  END IF;
  RAISE NOTICE 'ok: %',label; RETURN;
 END;
 RAISE EXCEPTION 'constraint did not hold: %',label;
END $$;

-- Current target placement and one approved, complete graph.
INSERT INTO solvan_scale.cell_eligibility_profiles
 (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
  allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
  allowed_recovery_regions,approved_ref)
VALUES ('sha256:'||repeat('6',64),ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
 'sha256:'||repeat('7',64),false,ARRAY['europe-west1'],'ref_quality_eligibility');
INSERT INTO solvan_scale.cells
 (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
  capacity_profile_hash,data_policy_hash,eligibility_profile_hash,deployment_manifest_hash)
VALUES ('cell_quality','OSS_SINGLE_TENANT','europe-west1','quality-test','READY',1,
 'sha256:'||repeat('1',64),'sha256:'||repeat('2',64),'sha256:'||repeat('6',64),
 'sha256:'||repeat('3',64));
INSERT INTO solvan_scale.tenant_eligibility_requirements
 (organization_id,requirement_hash,allowed_classifications,allowed_residency_regions,
  allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
  allowed_recovery_regions,approved_ref)
VALUES ('org_00000000000000000000000001','sha256:'||repeat('8',64),ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
 'sha256:'||repeat('7',64),false,ARRAY['europe-west1'],'ref_quality_tenant');
INSERT INTO solvan_scale.tenant_placements
 (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,home_region,
  classification_ceiling,eligibility_requirement_hash,policy_hash,encryption_profile_hash,activated_at)
VALUES ('org_00000000000000000000000001',1,'cell_quality','ACTIVE',true,'OSS_SINGLE_TENANT','europe-west1','INTERNAL',
 'sha256:'||repeat('8',64),'sha256:'||repeat('4',64),'sha256:'||repeat('7',64),now());
INSERT INTO solvan_graph.graph_scope_bindings VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'europe-west1','INTERNAL','ACTIVE',true,now());
INSERT INTO solvan_graph.graph_source_policies VALUES
 ('quality_app_hub',1,1,'app-hub-v1','CATALOG','GA',false,true,
  ARRAY['SERVICE'],ARRAY[]::text[],'sha256:'||repeat('d',64),now(),NULL),
 ('quality_iam',1,2,'cloud-iam','IDENTITY_AUTHORITY','GA',false,true,
  ARRAY[]::text[],ARRAY['ALLOWED_TO_CALL'],'sha256:'||repeat('e',64),now(),NULL),
 ('quality_assets',1,3,'cloud-asset-inventory','DECLARED_RELATIONSHIP','GA',true,true,
  ARRAY[]::text[],ARRAY['DEPENDS_ON_DECLARED'],'sha256:'||repeat('f',64),now(),NULL);
INSERT INTO solvan_graph.graph_reconciliation_runs
 (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id,
  source_policy_set_hash,requested_by,state,started_at,ended_at)
VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'run_q','sha256:'||repeat('9',64),
 'scheduler','COMPLETED',now(),now());
INSERT INTO solvan_graph.graph_snapshots
 (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,
  snapshot_version,run_id,reconciled_at)
VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pgs_00000000000000000000000003',1,'run_q',now());
INSERT INTO solvan_graph.graph_snapshot_tier_status VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pgs_00000000000000000000000003',1,true,'COMPLETE',1),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pgs_00000000000000000000000003',2,true,'COMPLETE',1),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pgs_00000000000000000000000003',3,true,'COMPLETE',1),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pgs_00000000000000000000000003',4,false,'NOT_CONFIGURED',0);
SELECT solvan_graph.graph_finalize_snapshot('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pgs_00000000000000000000000003');
SELECT solvan_graph.graph_promote_snapshot('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,
 'pgs_00000000000000000000000003','dec_q','HUMAN_APPROVED','principal:operator',NULL);
INSERT INTO solvan_graph.graph_staleness_policy_revisions VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001',1,86400,604800,'sha256:'||repeat('a',64),'principal:operator',now());
INSERT INTO solvan_graph.graph_staleness_policy_bindings VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001',1,1,true,now());
INSERT INTO quality_scope_bindings VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'ACTIVE',true,now());

INSERT INTO fault_scenarios VALUES
 ('pool_exhaustion',1,'injector://pool','payments-api','SATURATION',true,
  'VERIFIED_RECOVERY','baseline://pool','oracle://pool','sha256:'||repeat('b',64),NULL),
 ('hard_dependency_down',1,'injector://dep','payments-api','DEPENDENCY',false,
  'ESCALATION_WITHOUT_DECLARATION','baseline://dep','oracle://dep','sha256:'||repeat('c',64),NULL);
SELECT quality_must_violate($$
 INSERT INTO fault_scenarios VALUES
 ('bad_restraint',1,'injector://bad','payments-api','LATENCY',false,
  'VERIFIED_RECOVERY','baseline://bad','oracle://bad','sha256:'||repeat('d',64),NULL)
$$,'23514','quality_scenario_restraint','violates check constraint',
 'unrecoverable scenarios cannot declare recovery');

INSERT INTO fault_catalog_revisions(catalog_version,status) VALUES (1,'DRAFT'),(2,'DRAFT');
INSERT INTO fault_catalog_memberships VALUES
 (1,'pool_exhaustion',1),(1,'hard_dependency_down',1),(2,'pool_exhaustion',1);
SELECT quality_must_violate($$SELECT quality_approve_catalog(2,'principal:operator')$$,
 '23514','quality_catalog_balanced','QUALITY_CATALOG_REQUIRES_RECOVERY_AND_RESTRAINT',
 'catalog needs both recovery and restraint');
SELECT quality_approve_catalog(1,'principal:operator');
SELECT quality_must_violate($$
 UPDATE fault_catalog_revisions SET status='RETIRED' WHERE catalog_version=1
$$,'42501','quality_catalog_approval_function_only','QUALITY_CATALOG_APPROVAL_FUNCTION_REQUIRED',
 'catalog authority is function-only');

INSERT INTO recovery_episodes
 (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id,
  incident_ref,incident_generation,action_class,service_key,catalog_version,
  scenario_key,scenario_version,eligible_at,settled_at,outcome,unresolved_effect_count)
VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'ep_declared','inc_1',1,
  'PAYMENTS_POOL_RECYCLE','payments-api',1,'pool_exhaustion',1,
  '2026-08-02T00:00:00Z','2026-08-02T01:00:00Z','VERIFIED_RECOVERY',0),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'ep_undeclared','inc_2',1,
  'PAYMENTS_POOL_RECYCLE','payments-api',1,'pool_exhaustion',1,
  '2026-08-03T00:00:00Z','2026-08-03T01:00:00Z','VERIFIED_RECOVERY',0),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'ep_inconclusive','inc_3',1,
  'PAYMENTS_POOL_RECYCLE','payments-api',1,'pool_exhaustion',1,
  '2026-08-04T00:00:00Z','2026-08-04T01:00:00Z','INCONCLUSIVE',0),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'ep_censored','inc_4',1,
  'PAYMENTS_POOL_RECYCLE','payments-api',1,'pool_exhaustion',1,
  '2026-08-05T00:00:00Z','2026-08-05T01:00:00Z','CENSORED',0),
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'ep_escalated','inc_5',1,
  'PAYMENTS_POOL_RECYCLE','payments-api',1,'hard_dependency_down',1,
  '2026-08-06T00:00:00Z','2026-08-06T01:00:00Z','ESCALATED_WITHOUT_DECLARATION',0);

SELECT quality_must_violate($$
 INSERT INTO recovery_declarations
  (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id,
   episode_id,declaration_kind,producer_principal,producer_service_revision,subject_ref,
   declared_at,falsification_window_seconds,window_closes_at)
 VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'dcl_bad','ep_declared',
  'VERIFICATION_PASSED','verifier@','rev-a','ver://bad','2026-08-02T01:00:00Z',1800,
  '2026-08-02T01:00:01Z')
$$,'23514','quality_exact_falsification_window','violates check constraint',
 'window arithmetic is exact');
INSERT INTO recovery_declarations VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'dcl_1','ep_declared','VERIFICATION_PASSED',
  'verifier@','verifier-rev-a','ver://1','2026-08-02T01:00:00Z',1800,
  '2026-08-02T01:30:00Z');

SELECT quality_must_violate($$
 INSERT INTO verification_isolation_receipts VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'iso_weak','dcl_1','verifier@','oracle@',
  'shared-rev','shared-rev','boot-a','boot-b','req-a','req-b',
  'sha256:'||repeat('1',64),'sha256:'||repeat('2',64),
  'sha256:'||repeat('3',64),'sha256:'||repeat('4',64),ARRAY['metrics'],ARRAY['probe'],
  'attester@','sha256:'||repeat('5',64),now())
$$,'23514','quality_structural_oracle_independence','violates check constraint',
 'different names are insufficient for oracle independence');
INSERT INTO verification_isolation_receipts VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'iso_1','dcl_1','verifier@','oracle@',
  'verifier-rev-a','oracle-rev-b','boot-a','boot-b','req-a','req-b',
  'sha256:'||repeat('1',64),'sha256:'||repeat('2',64),
  'sha256:'||repeat('3',64),'sha256:'||repeat('4',64),ARRAY['verification'],ARRAY['probe'],
  'attester@','sha256:'||repeat('6',64),now());

SELECT quality_must_violate($$
 INSERT INTO recovery_falsifications
  (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id,
   declaration_id,isolation_receipt_id,oracle_kind,timing_class,evidence_ref,observed_at)
 VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'fls_wrong_time','dcl_1','iso_1',
  'INDEPENDENT_PROBE_FAILED','PRIMARY_WINDOW','evidence://late','2026-08-02T02:00:00Z')
$$,'23514','quality_falsification_timing','QUALITY_FALSIFICATION_TIMING_MISMATCH',
 'late recurrence cannot disappear into primary window');
INSERT INTO recovery_falsifications
 (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id,
  declaration_id,isolation_receipt_id,oracle_kind,timing_class,evidence_ref,observed_at)
VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'fls_1','dcl_1','iso_1',
 'INDEPENDENT_PROBE_FAILED','PRIMARY_WINDOW','evidence://primary','2026-08-02T01:10:00Z');

SELECT quality_must_violate($$
 INSERT INTO falsification_attributions VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'att_bad','fls_1','DISTINCT_MECHANISM_CONFIRMED',
  'principal:sre','principal:sre','review://1','mechanism://1','reason://1',now())
$$,'23514','quality_attribution_separation','violates check constraint',
 'attribution requires independent review');

INSERT INTO metric_population_revisions
 (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id,
  catalog_version,action_class,service_key,period_start,period_end,taxonomy_hash,
  population_rule_hash,status,approved_by)
VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pop_1',1,'PAYMENTS_POOL_RECYCLE',
 'payments-api','2026-08-01T00:00:00Z','2026-09-01T00:00:00Z',
 'sha256:'||repeat('7',64),'sha256:'||repeat('8',64),'DRAFT','principal:operator');
SELECT quality_must_violate($$
 INSERT INTO metric_population_members VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pop_1','ep_declared','DECLARED')
$$,'42501','quality_derivation_function_only','QUALITY_DERIVATION_FUNCTION_REQUIRED',
 'population members are derived only');
SELECT quality_build_population('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pop_1');
SELECT quality_publish_receipt('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'pop_1','qlt_1');

DO $$
DECLARE receipt outcome_quality_receipts%ROWTYPE;
BEGIN
 SELECT * INTO receipt FROM outcome_quality_receipts WHERE receipt_id='qlt_1';
 IF receipt.eligible_episodes<>5 OR receipt.declared_episodes<>1
    OR receipt.primary_falsifications<>1 OR receipt.inconclusive_episodes<>1
    OR receipt.censored_episodes<>1 OR receipt.unrecoverable_escalations<>1
    OR receipt.false_confirmation_rate<>1 THEN
  RAISE EXCEPTION 'derived population/count receipt is wrong'; END IF;
END $$;
SELECT quality_must_violate($$
 INSERT INTO outcome_quality_receipts
 SELECT organization_id,project_id,environment_id,cell_id,placement_epoch,'forged',
  population_id,population_hash,eligible_episodes,declared_episodes,verified_recoveries,
  0,delayed_recurrences,attributed_falsifications,inconclusive_episodes,censored_episodes,
  unrecoverable_escalations,unresolved_effects,0,declaration_coverage,
  falsification_sequence_high_water,true,'sha256:'||repeat('f',64),now()
 FROM outcome_quality_receipts WHERE receipt_id='qlt_1'
$$,'42501','quality_derivation_function_only','QUALITY_DERIVATION_FUNCTION_REQUIRED',
 'rounded or asserted zero receipt cannot be inserted');

INSERT INTO competence_policy_revisions VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','PAYMENTS_POOL_RECYCLE',1,1,0,1,10,7776000,
  'sha256:'||repeat('9',64),'principal:operator',now());
INSERT INTO competence_policy_bindings VALUES
 ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','PAYMENTS_POOL_RECYCLE',1,1,'2026-08-01T00:00:00Z',0,true,now());
SELECT quality_derive_competence('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,
 'PAYMENTS_POOL_RECYCLE','qlt_1','cmp_1');
DO $$BEGIN
 IF (SELECT eligible FROM autonomy_competence_receipts WHERE receipt_id='cmp_1') THEN
  RAISE EXCEPTION 'one falsification must prevent earned autonomy'; END IF;
END $$;
SELECT quality_must_violate($$
 INSERT INTO autonomy_competence_receipts
 SELECT organization_id,project_id,environment_id,cell_id,placement_epoch,'cmp_forged',
  action_class,policy_binding_epoch,quality_receipt_id,graph_snapshot_id,
  graph_policy_binding_epoch,falsification_sequence_high_water,true,NULL,
  now()+interval '1 day','sha256:'||repeat('e',64),now()
 FROM autonomy_competence_receipts WHERE receipt_id='cmp_1'
$$,'42501','quality_derivation_function_only','QUALITY_DERIVATION_FUNCTION_REQUIRED',
 'competence cannot be asserted');

-- A falsification that commits after competence derivation changes the high-water.
INSERT INTO recovery_falsifications
 (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id,
  declaration_id,isolation_receipt_id,oracle_kind,timing_class,evidence_ref,observed_at)
VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'fls_delayed','dcl_1','iso_1',
 'DETECTION_RULE_REFIRED','DELAYED_RECURRENCE','evidence://delayed','2026-08-03T01:00:00Z');
SELECT quality_must_violate($$
 SELECT quality_reserve_earned_action('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,
  'ear_1','act_1','PAYMENTS_POOL_RECYCLE','payments-admin/pool','pre_1',1,'cmp_1',
  'CONNECTOR_CALL',1,'cap_1','11111111-1111-1111-1111-111111111111',now()+interval '1 minute')
$$,'40001','earned_auth_falsification_high_water','EARNED_AUTH_FALSIFICATION_FENCE',
 'revocation committed before reservation wins atomically');

SELECT quality_must_violate($$
 INSERT INTO earned_action_reservations
  (organization_id,project_id,environment_id,cell_id,placement_epoch,reservation_id,
   action_id,action_class,target_key,standing_preauthorization_id,
   standing_preauthorization_version,competence_receipt_id,graph_snapshot_id,
   competence_policy_binding_epoch,graph_policy_binding_epoch,capacity_resource_kind,
   capacity_binding_epoch,capacity_receipt_id,falsification_sequence_high_water,
   lease_token,expires_at)
 VALUES ('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,'forged','act_1','PAYMENTS_POOL_RECYCLE',
  'target','pre_1',1,'cmp_1','pgs_00000000000000000000000003',1,1,'CONNECTOR_CALL',1,'cap_1',2,
  '11111111-1111-1111-1111-111111111111',now()+interval '1 minute')
$$,'42501','quality_derivation_function_only','QUALITY_DERIVATION_FUNCTION_REQUIRED',
 'earned reservation cannot be inserted directly');

SELECT quality_must_violate($$
 DELETE FROM recovery_falsifications WHERE falsification_id='fls_1'
$$,'23514','quality_history_immutable','QUALITY_HISTORY_IMMUTABLE',
 'falsification history is immutable');

SELECT quality_must_violate($$
 SELECT quality_purge_scope('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,
  'job_missing',1)
$$,'42501','quality_purge_verified_delete_only','QUALITY_PURGE_LIFECYCLE_REFUSED',
 'quality purge requires the exact verified deletion job');
INSERT INTO solvan_scale.tenant_lifecycle_jobs
 (organization_id,job_id,job_kind,expected_placement_epoch,source_cell_id,state,request_hash)
VALUES ('org_00000000000000000000000001','job_delete_q','DELETE',1,'cell_quality','VERIFYING',
 'sha256:'||repeat('4',64));
SELECT quality_purge_scope('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,
 'job_delete_q',1);
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM quality_scope_bindings WHERE organization_id='org_00000000000000000000000001')
    OR EXISTS (SELECT 1 FROM recovery_episodes WHERE organization_id='org_00000000000000000000000001')
    OR EXISTS (SELECT 1 FROM outcome_quality_receipts WHERE organization_id='org_00000000000000000000000001')
    OR (SELECT count(*) FROM quality_deletion_receipts
         WHERE organization_id='org_00000000000000000000000001' AND deletion_epoch=1)<>1 THEN
  RAISE EXCEPTION 'quality purge did not leave only its terminal receipt';
 END IF;
END $$;
SELECT solvan_graph.graph_purge_scope('org_00000000000000000000000001','prj_00000000000000000000000001','env_00000000000000000000000001','cell_quality',1,
 'job_delete_q',1);
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM solvan_graph.graph_scope_bindings WHERE organization_id='org_00000000000000000000000001')
    OR EXISTS (SELECT 1 FROM solvan_graph.graph_snapshots WHERE organization_id='org_00000000000000000000000001')
    OR (SELECT count(*) FROM solvan_graph.graph_deletion_receipts
         WHERE organization_id='org_00000000000000000000000001' AND deletion_epoch=1)<>1 THEN
  RAISE EXCEPTION 'graph purge did not leave only its terminal receipt';
 END IF;
END $$;

ROLLBACK;
