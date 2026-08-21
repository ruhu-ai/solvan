-- Exact negative oracles for specification 20 target DDL.
SET search_path TO solvan_graph, public;
BEGIN;

INSERT INTO solvan.organizations(id,display_name)
VALUES ('org_00000000000000000000000000','Graph contract organization');
INSERT INTO solvan.projects(organization_id,id,display_name,gcp_project_id)
VALUES ('org_00000000000000000000000000',
        'prj_00000000000000000000000000','Graph contract estate','graph-contract');
INSERT INTO solvan.environments
  (organization_id,project_id,id,display_name,region,classification)
VALUES ('org_00000000000000000000000000',
        'prj_00000000000000000000000000',
        'env_00000000000000000000000000','Production','europe-west1','INTERNAL');

CREATE OR REPLACE FUNCTION graph_must_violate(
  statement text, expected_state text, expected_constraint text,
  expected_message text, label text
) RETURNS void LANGUAGE plpgsql AS $$
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

INSERT INTO solvan_scale.cell_eligibility_profiles
  (eligibility_profile_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES ('sha256:'||repeat('6',64),ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
  'sha256:'||repeat('7',64),false,ARRAY['europe-west1'],'ref_graph_eligibility');
INSERT INTO solvan_scale.cells
  (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
   capacity_profile_hash,data_policy_hash,eligibility_profile_hash,deployment_manifest_hash)
VALUES ('cell_graph','OSS_SINGLE_TENANT','europe-west1','graph-test','READY',1,
  'sha256:'||repeat('1',64),'sha256:'||repeat('2',64),'sha256:'||repeat('6',64),
  'sha256:'||repeat('3',64));
INSERT INTO solvan_scale.tenant_eligibility_requirements
  (organization_id,requirement_hash,allowed_classifications,allowed_residency_regions,
   allowed_provider_launch_stages,encryption_profile_hash,support_access_allowed,
   allowed_recovery_regions,approved_ref)
VALUES ('org_00000000000000000000000000','sha256:'||repeat('8',64),ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],
  'sha256:'||repeat('7',64),false,ARRAY['europe-west1'],'ref_graph_tenant');
INSERT INTO solvan_scale.tenant_placements
  (organization_id,placement_epoch,cell_id,lifecycle,is_current,isolation_tier,home_region,
   classification_ceiling,eligibility_requirement_hash,policy_hash,encryption_profile_hash,
   activated_at)
VALUES ('org_00000000000000000000000000',1,'cell_graph','ACTIVE',true,'OSS_SINGLE_TENANT','europe-west1','INTERNAL',
  'sha256:'||repeat('8',64),'sha256:'||repeat('4',64),'sha256:'||repeat('7',64),now());
INSERT INTO graph_scope_bindings VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'europe-west1','INTERNAL','ACTIVE',true,now());

-- The baseline installs the four implemented GA source policies. This target
-- fixture adds only the optional Preview tier-four policy used by negative
-- authority tests.
INSERT INTO graph_source_policies VALUES
 ('app_topology',1,4,'app-topology','OBSERVED_HINT','PREVIEW',false,false,
  ARRAY[]::text[],ARRAY['DEPENDS_ON_OBSERVED'],'sha256:'||repeat('d',64),now(),NULL);

SELECT graph_must_violate($$
 INSERT INTO graph_source_policies VALUES
 ('bad_hint',1,4,'preview','OBSERVED_HINT','PREVIEW',false,false,
  ARRAY[]::text[],ARRAY['ALLOWED_TO_CALL'],'sha256:'||repeat('e',64),now(),NULL)
$$,'23514','graph_observed_hint_edge_kinds','violates check constraint',
 'INV-PG-02 observed policy cannot register authority');

INSERT INTO graph_reconciliation_runs
 (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id,
  source_policy_set_hash,requested_by,state,started_at,ended_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','sha256:'||repeat('f',64),
 'scheduler','COMPLETED',now(),now());
INSERT INTO graph_reconciliation_run_sources VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1',1,'app_hub',1,1,true,
  'sha256:f4b2799990adb69891e12424433f18fa88b02b26de9db22f55bbe2631926932c'),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1',2,'cloud_asset_inventory_search',1,1,true,
  'sha256:94b7bd0ae3a2e8752be49a491723ea11b1e2e0adf79844839ec1a4c7b66dafb8'),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1',3,'iam',1,2,true,
  'sha256:c230469cc82d7a24845dfb0a2b352efd9ca34b82f9b0afa7066c3fad437dc102'),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1',4,'asset_relationships',1,3,true,
  'sha256:93f2ac54070122c2fb2726e63f84f48912ade6bd4aa5730ffa2e408d620580ec'),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1',5,'app_topology',1,4,false,
  'sha256:'||repeat('d',64));
INSERT INTO graph_source_observations VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_app','app_hub',1,
  'tool://app','sha256:'||repeat('1',64),1,2,true,'COMPLETE','europe-west1',now()),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_iam','iam',1,
  'tool://iam','sha256:'||repeat('2',64),1,1,true,'COMPLETE','europe-west1',now()),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_asset','asset_relationships',1,
  'tool://asset','sha256:'||repeat('3',64),1,1,true,'COMPLETE','europe-west1',now()),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_hint','app_topology',1,
  'tool://hint','sha256:'||repeat('4',64),1,1,true,'COMPLETE','europe-west1',now()),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_inventory',
  'cloud_asset_inventory_search',1,'tool://inventory','sha256:'||repeat('5',64),
  1,0,true,'COMPLETE','europe-west1',now());

SELECT graph_must_violate($$
 INSERT INTO graph_source_observations VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_unplanned','bad_hint',1,
  'tool://bad','sha256:'||repeat('5',64),0,0,false,'UNAVAILABLE','europe-west1',now())
$$,'23503','graph_observation_run_source_fk',
 'violates foreign key constraint','an observation must belong to the frozen run source set');

SELECT graph_must_violate($$
 INSERT INTO graph_source_observations VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_1','obs_bad','app_hub',1,
  'tool://bad','sha256:'||repeat('5',64),1,1,false,'COMPLETE','europe-west1',now())
$$,'23514','graph_observation_completion','violates check constraint',
 'complete observation requires exhausted pagination');

-- A complete source cannot mask a partial required peer in the same tier.
INSERT INTO graph_reconciliation_runs
 (organization_id,project_id,environment_id,cell_id,placement_epoch,run_id,
  source_policy_set_hash,requested_by,state,started_at,ended_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_partial','sha256:'||repeat('e',64),
 'scheduler','COMPLETED',now(),now());
INSERT INTO graph_reconciliation_run_sources VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_partial',1,'app_hub',1,1,true,
  'sha256:f4b2799990adb69891e12424433f18fa88b02b26de9db22f55bbe2631926932c'),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_partial',2,
  'cloud_asset_inventory_search',1,1,true,
  'sha256:94b7bd0ae3a2e8752be49a491723ea11b1e2e0adf79844839ec1a4c7b66dafb8');
INSERT INTO graph_source_observations VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_partial','obs_partial_app','app_hub',1,
  'tool://app','sha256:'||repeat('6',64),1,0,true,'COMPLETE','europe-west1',now()),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'run_partial','obs_partial_inventory',
  'cloud_asset_inventory_search',1,'tool://inventory','sha256:'||repeat('7',64),
  1,1,false,'PARTIAL','europe-west1',now());
INSERT INTO graph_snapshots
 (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,
  snapshot_version,run_id,reconciled_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000002',2,'run_partial',now());
INSERT INTO graph_snapshot_tier_status VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000002',1,true,'COMPLETE',2);
SELECT graph_finalize_snapshot('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000002');
DO $$
BEGIN
  IF (SELECT completeness FROM graph_snapshots WHERE snapshot_id='pgs_00000000000000000000000002')
       IS DISTINCT FROM 'INCOMPLETE' THEN
    RAISE EXCEPTION 'partial required source was masked by a complete tier peer';
  END IF;
END $$;

INSERT INTO graph_snapshots
 (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id,
  snapshot_version,run_id,reconciled_at)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',1,'run_1',now());
INSERT INTO graph_snapshot_tier_status VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',1,true,'COMPLETE',1),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',2,true,'COMPLETE',1),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',3,true,'COMPLETE',1),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',4,false,'COMPLETE',1);
-- Specification 13 §4.2 gives each node a typed external_project_id. The two
-- nodes sit in different Google Cloud projects deliberately: a database in a
-- project other than its service's is the ordinary case under §4.3, and a
-- fixture that used one project everywhere could not expose a read that
-- resolved its address from the wrong node.
INSERT INTO graph_nodes VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
  'pgn_00000000000000000000000001','payments','SERVICE','run://payments',
  'customer-payments-prod',
  'payments-sre','PRODUCTION','HIGH','INTERNAL','payments-boundary','payments-recovery-v1',
  'europe-west1','INSTRUMENTED','obs_app','app_hub',1),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
  'pgn_00000000000000000000000002','database','DATABASE','sql://payments',
  'customer-data-prod',
  NULL,NULL,NULL,NULL,NULL,NULL,
  'europe-west1','UNKNOWN','obs_inventory','cloud_asset_inventory_search',1);
INSERT INTO graph_edges VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
  'pge_00000000000000000000000001','iam_1','payments','database',
  'ALLOWED_TO_CALL','obs_iam','iam',1),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
  'pge_00000000000000000000000002','dep_1','payments','database',
  'DEPENDS_ON_DECLARED','obs_asset','asset_relationships',1);

SELECT graph_must_violate($$
 INSERT INTO graph_edges VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
  'pge_00000000000000000000000003','bad_auth','payments','database',
  'ALLOWED_TO_CALL','obs_hint','app_topology',1)
$$,'23514','graph_edge_source_policy','GRAPH_EDGE_KIND_NOT_ALLOWED',
 'INV-PG-02 observed element cannot carry authority');

SELECT graph_must_violate($$
 INSERT INTO graph_edges VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
  'pge_00000000000000000000000004','bad_obs','payments','database',
  'ALLOWED_TO_CALL','obs_app','iam',1)
$$,'23514','graph_source_observation_match','GRAPH_SOURCE_OBSERVATION_MISMATCH',
 'element provenance must match exact observation');

SELECT graph_finalize_snapshot('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001');
INSERT INTO graph_snapshot_diffs
 (organization_id,project_id,environment_id,cell_id,placement_epoch,diff_id,
  base_snapshot_id,candidate_snapshot_id,node_changes,edge_changes,owner_changes,
  environment_changes,criticality_changes,classification_changes,authorization_changes,
  verification_profile_changes,region_changes,source_authority_changes,
  instrumentation_changes,completeness_changes,diff_hash)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'diff_1',NULL,'pgs_00000000000000000000000001',2,2,2,2,2,2,2,2,2,2,2,0,
 'sha256:'||repeat('6',64));

SELECT graph_must_violate($$
 SELECT graph_promote_snapshot('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
   'dec_auto_first','AUTO_PROMOTED',NULL,NULL)
$$,'23514','graph_first_snapshot_human','GRAPH_FIRST_SNAPSHOT_NEEDS_HUMAN',
 'INV-PG-04 first snapshot requires a human');
SELECT graph_promote_snapshot('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'pgs_00000000000000000000000001',
 'dec_human','HUMAN_APPROVED','principal:operator',NULL);

DO $$
DECLARE projected record;
BEGIN
  SELECT classification,attributes_json->>'classification_source' AS source
    INTO projected FROM solvan.production_graph_nodes
   WHERE organization_id='org_00000000000000000000000000'
     AND project_id='prj_00000000000000000000000000'
     AND environment_id='env_00000000000000000000000000'
     AND snapshot_id='pgs_00000000000000000000000001'
     AND node_key='database';
  IF projected.classification IS DISTINCT FROM 'INTERNAL'
     OR projected.source IS DISTINCT FROM 'ENVIRONMENT_CEILING' THEN
    RAISE EXCEPTION 'unknown source classification did not project as an explicit conservative ceiling';
  END IF;
  RAISE NOTICE 'ok: unknown source classification uses the hash-bound environment ceiling';
END $$;

DO $$
DECLARE authority record;
BEGIN
  SELECT * INTO authority FROM solvan.production_graph_snapshots
   WHERE organization_id='org_00000000000000000000000000'
     AND project_id='prj_00000000000000000000000000'
     AND environment_id='env_00000000000000000000000000'
     AND id='pgs_00000000000000000000000001';
  IF authority.status IS DISTINCT FROM 'APPROVED'
     OR authority.version IS DISTINCT FROM 1
     OR authority.approved_by IS DISTINCT FROM 'principal:operator'
     OR (SELECT count(*) FROM solvan.production_graph_nodes
          WHERE snapshot_id=authority.id) IS DISTINCT FROM 2::bigint
     OR (SELECT count(*) FROM solvan.production_graph_edges
          WHERE snapshot_id=authority.id) IS DISTINCT FROM 2::bigint THEN
    RAISE EXCEPTION 'candidate did not atomically materialize as release authority: %',
      row_to_json(authority);
  END IF;
END $$;

SELECT graph_must_violate($$
 UPDATE graph_snapshots SET status='RETIRED' WHERE snapshot_id='pgs_00000000000000000000000001'
$$,'42501','graph_promotion_function_only','GRAPH_PROMOTION_FUNCTION_REQUIRED',
 'promotion state is function-only');
SELECT graph_must_violate($$
 INSERT INTO graph_promotion_decisions
  (organization_id,project_id,environment_id,cell_id,placement_epoch,decision_id,
   snapshot_id,decision,decided_by,content_hash)
 SELECT organization_id,project_id,environment_id,cell_id,placement_epoch,'forged',
   snapshot_id,'HUMAN_APPROVED','principal:forger',content_hash FROM graph_snapshots
   WHERE snapshot_id='pgs_00000000000000000000000001'
$$,'42501','graph_promotion_function_only','GRAPH_PROMOTION_FUNCTION_REQUIRED',
 'promotion receipt cannot be asserted directly');

INSERT INTO graph_staleness_policy_revisions VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000',1,86400,604800,'sha256:'||repeat('7',64),'principal:operator',now()),
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000',2,43200,604800,'sha256:'||repeat('8',64),'principal:operator',now());
INSERT INTO graph_staleness_policy_bindings VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000',1,1,true,now());
SELECT graph_must_violate($$
 INSERT INTO graph_staleness_policy_bindings VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000',2,2,true,now())
$$,'23505','graph_one_current_staleness_policy','duplicate key value',
 'INV-PG-06 one current staleness policy');

DO $$
DECLARE projection record;
BEGIN
  SELECT * INTO projection
    FROM graph_read_current('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000');
  IF projection.snapshot_id IS DISTINCT FROM 'pgs_00000000000000000000000001'
     OR projection.snapshot_version IS DISTINCT FROM 1
     OR projection.completeness IS DISTINCT FROM 'COMPLETE'
     OR projection.autonomy_eligible IS DISTINCT FROM true
     OR projection.assisted_usable IS DISTINCT FROM true
     OR projection.cell_id IS DISTINCT FROM 'cell_graph'
     OR projection.placement_epoch IS DISTINCT FROM 1
     OR projection.graph_policy_binding_epoch IS DISTINCT FROM 1
     OR projection.age_seconds < 0 THEN
    RAISE EXCEPTION 'current graph projection is not exact: %',row_to_json(projection);
  END IF;
END $$;

INSERT INTO graph_findings
 (organization_id,project_id,environment_id,cell_id,placement_epoch,finding_id,
  snapshot_id,finding_kind,subject_node_key,detail_ref,status)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'fnd_1','pgs_00000000000000000000000001',
 'UNINSTRUMENTED_COMPONENT','payments','detail://1','OPEN');
SELECT graph_must_violate($$
 INSERT INTO graph_findings
  (organization_id,project_id,environment_id,cell_id,placement_epoch,finding_id,
   snapshot_id,finding_kind,subject_node_key,detail_ref,status)
 VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'fnd_2','pgs_00000000000000000000000001',
  'UNINSTRUMENTED_COMPONENT','payments','detail://2','OPEN')
$$,'23505','graph_unique_node_finding','duplicate key value',
 'nullable finding uniqueness is exact');

INSERT INTO graph_findings
 (organization_id,project_id,environment_id,cell_id,placement_epoch,finding_id,
  snapshot_id,finding_kind,detail_ref,subject_source_key,subject_source_revision,status)
VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'fnd_source','pgs_00000000000000000000000001',
 'SOURCE_INCOMPLETE','detail://source','cloud_asset_inventory_search',1,'OPEN');
SELECT graph_must_violate($$
 INSERT INTO graph_findings
  (organization_id,project_id,environment_id,cell_id,placement_epoch,finding_id,
   snapshot_id,finding_kind,subject_node_key,detail_ref,status)
 VALUES ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'fnd_bad_source','pgs_00000000000000000000000001',
  'SOURCE_INCOMPLETE','payments','detail://bad-source','OPEN')
$$,'23514','graph_findings_check2','violates check constraint',
 'source incompleteness must name the exact source revision');

INSERT INTO graph_citations VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'cit_1','pgs_00000000000000000000000001','ACTION_AUTHORIZATION','act_1',1,now());
SELECT graph_must_violate($$
 UPDATE graph_citations SET snapshot_id='other' WHERE citation_id='cit_1'
$$,'23514','graph_history_immutable','GRAPH_HISTORY_IMMUTABLE',
 'INV-PG-07 citations are immutable');
SELECT graph_must_violate($$
 INSERT INTO graph_citations VALUES
 ('org_00000000000000000000000000','prj_00000000000000000000000000','env_00000000000000000000000000','cell_graph',1,'cit_dangling','missing','AGENT_RUN','run_x',1,now())
$$,'23503','graph_citation_snapshot_fk',
 'violates foreign key constraint','dangling snapshot citations fail');

ROLLBACK;
