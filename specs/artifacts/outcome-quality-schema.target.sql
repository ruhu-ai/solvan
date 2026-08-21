-- Solvan outcome quality and earned autonomy: TARGET database contract.
-- Rates and competence are derived from immutable episodes/populations. Direct
-- receipt or reservation assertion is rejected.

BEGIN;
CREATE SCHEMA IF NOT EXISTS solvan_quality;
SET search_path TO solvan_quality, public;

CREATE TABLE quality_scope_bindings (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, lifecycle text NOT NULL,
  is_current boolean NOT NULL, bound_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch)
    REFERENCES solvan_graph.graph_scope_bindings
      (organization_id,project_id,environment_id,cell_id,placement_epoch),
  CHECK (lifecycle IN ('ACTIVE','MOVED','DELETED')),
  CHECK (NOT is_current OR lifecycle='ACTIVE')
);
CREATE UNIQUE INDEX quality_one_current_scope ON quality_scope_bindings
  (organization_id,project_id,environment_id) WHERE is_current;

CREATE TABLE fault_scenarios (
  scenario_key text NOT NULL, version bigint NOT NULL CHECK (version>0),
  injector_ref text NOT NULL, affected_service_key text NOT NULL,
  observable_class text NOT NULL CHECK (observable_class IN
    ('SATURATION','LATENCY','ERROR_RATIO','DATA_PATH','DEPENDENCY','CONFIGURATION')),
  recoverable boolean NOT NULL,
  expected_outcome text NOT NULL CHECK (expected_outcome IN
    ('VERIFIED_RECOVERY','ESCALATION_WITHOUT_DECLARATION')),
  baseline_contract_ref text NOT NULL, termination_oracle_ref text NOT NULL,
  definition_hash text NOT NULL CHECK (definition_hash ~ '^sha256:[0-9a-f]{64}$'),
  retired_at timestamptz,
  PRIMARY KEY (scenario_key,version), UNIQUE(definition_hash),
  CONSTRAINT quality_scenario_restraint CHECK
    (recoverable=(expected_outcome='VERIFIED_RECOVERY'))
);

CREATE TABLE fault_catalog_revisions (
  catalog_version bigint PRIMARY KEY CHECK (catalog_version>0),
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RETIRED')),
  catalog_hash text CHECK (catalog_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_by text, approved_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT quality_catalog_approval_shape CHECK
    ((status='APPROVED')=(catalog_hash IS NOT NULL AND approved_by IS NOT NULL AND approved_at IS NOT NULL))
);
CREATE TABLE fault_catalog_memberships (
  catalog_version bigint NOT NULL REFERENCES fault_catalog_revisions(catalog_version),
  scenario_key text NOT NULL, scenario_version bigint NOT NULL,
  PRIMARY KEY (catalog_version,scenario_key,scenario_version),
  FOREIGN KEY (scenario_key,scenario_version)
    REFERENCES fault_scenarios(scenario_key,version)
);

CREATE FUNCTION quality_catalog_status_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
BEGIN
 IF OLD.status IS DISTINCT FROM NEW.status
    AND current_setting('solvan_quality.catalog_approval',true) IS DISTINCT FROM 'on' THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='QUALITY_CATALOG_APPROVAL_FUNCTION_REQUIRED',
   CONSTRAINT='quality_catalog_approval_function_only'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER quality_catalog_status_gate BEFORE UPDATE OF status ON fault_catalog_revisions
 FOR EACH ROW EXECUTE FUNCTION quality_catalog_status_guard();

CREATE FUNCTION quality_approve_catalog(p_catalog bigint,p_principal text)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
DECLARE recoverable_count integer; unrecoverable_count integer; digest_value text;
BEGIN
 SELECT count(*) FILTER (WHERE s.recoverable),count(*) FILTER (WHERE NOT s.recoverable),
  'sha256:'||encode(public.digest(string_agg(m.scenario_key||':'||m.scenario_version,
   '|' ORDER BY m.scenario_key,m.scenario_version)::bytea,'sha256'),'hex')
 INTO recoverable_count,unrecoverable_count,digest_value
 FROM fault_catalog_memberships m JOIN fault_scenarios s
  ON (s.scenario_key,s.version)=(m.scenario_key,m.scenario_version)
 WHERE m.catalog_version=p_catalog;
 IF recoverable_count=0 OR unrecoverable_count=0 THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='QUALITY_CATALOG_REQUIRES_RECOVERY_AND_RESTRAINT',
   CONSTRAINT='quality_catalog_balanced'; END IF;
 PERFORM set_config('solvan_quality.catalog_approval','on',true);
 UPDATE fault_catalog_revisions SET status='APPROVED',catalog_hash=digest_value,
  approved_by=p_principal,approved_at=now() WHERE catalog_version=p_catalog AND status='DRAFT';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='QUALITY_CATALOG_NOT_DRAFT',
  CONSTRAINT='quality_catalog_draft_once'; END IF;
 PERFORM set_config('solvan_quality.catalog_approval','off',true);
END $$;

CREATE TABLE recovery_episodes (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, episode_id text NOT NULL,
  incident_ref text NOT NULL, incident_generation bigint NOT NULL CHECK (incident_generation>0),
  action_class text NOT NULL, service_key text NOT NULL,
  catalog_version bigint NOT NULL REFERENCES fault_catalog_revisions(catalog_version),
  scenario_key text NOT NULL, scenario_version bigint NOT NULL,
  eligible_at timestamptz NOT NULL, settled_at timestamptz,
  outcome text CHECK (outcome IN
    ('VERIFIED_RECOVERY','ESCALATED_WITHOUT_DECLARATION','INCONCLUSIVE','CENSORED')),
  unresolved_effect_count integer NOT NULL DEFAULT 0 CHECK (unresolved_effect_count>=0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id),
  UNIQUE (organization_id,project_id,environment_id,incident_ref,incident_generation),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch)
    REFERENCES quality_scope_bindings
      (organization_id,project_id,environment_id,cell_id,placement_epoch),
  FOREIGN KEY (catalog_version,scenario_key,scenario_version)
    REFERENCES fault_catalog_memberships(catalog_version,scenario_key,scenario_version),
  CONSTRAINT quality_episode_settlement CHECK ((settled_at IS NULL)=(outcome IS NULL))
);

CREATE TABLE recovery_declarations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, declaration_id text NOT NULL,
  episode_id text NOT NULL, declaration_kind text NOT NULL CHECK (declaration_kind IN
    ('VERIFICATION_PASSED','INCIDENT_MITIGATED','INCIDENT_RESOLVED','CASE_REPAIR_VERIFIED')),
  producer_principal text NOT NULL, producer_service_revision text NOT NULL,
  subject_ref text NOT NULL, declared_at timestamptz NOT NULL,
  falsification_window_seconds integer NOT NULL CHECK
    (falsification_window_seconds BETWEEN 1800 AND 86400),
  window_closes_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id)
    REFERENCES recovery_episodes
      (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id,declaration_kind),
  CONSTRAINT quality_exact_falsification_window CHECK
    (window_closes_at=declared_at+make_interval(secs=>falsification_window_seconds))
);

CREATE TABLE verification_isolation_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, isolation_receipt_id text NOT NULL,
  declaration_id text NOT NULL,
  producer_principal text NOT NULL, oracle_principal text NOT NULL,
  producer_service_revision text NOT NULL, oracle_service_revision text NOT NULL,
  producer_process_boot_id text NOT NULL, oracle_process_boot_id text NOT NULL,
  producer_provider_request_id text NOT NULL, oracle_provider_request_id text NOT NULL,
  producer_context_hash text NOT NULL CHECK (producer_context_hash ~ '^sha256:[0-9a-f]{64}$'),
  oracle_context_hash text NOT NULL CHECK (oracle_context_hash ~ '^sha256:[0-9a-f]{64}$'),
  producer_policy_hash text NOT NULL CHECK (producer_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  oracle_policy_hash text NOT NULL CHECK (oracle_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  producer_evidence_partitions text[] NOT NULL,
  oracle_evidence_partitions text[] NOT NULL,
  attested_by text NOT NULL, receipt_hash text NOT NULL UNIQUE CHECK
    (receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,isolation_receipt_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id)
    REFERENCES recovery_declarations
      (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id),
  CONSTRAINT quality_structural_oracle_independence CHECK
    (producer_principal<>oracle_principal
     AND producer_service_revision<>oracle_service_revision
     AND producer_process_boot_id<>oracle_process_boot_id
     AND producer_provider_request_id<>oracle_provider_request_id
     AND producer_context_hash<>oracle_context_hash
     AND producer_policy_hash<>oracle_policy_hash
     AND NOT (producer_evidence_partitions && oracle_evidence_partitions))
);

CREATE TABLE recovery_falsifications (
  falsification_sequence bigint GENERATED ALWAYS AS IDENTITY,
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, falsification_id text NOT NULL,
  declaration_id text NOT NULL, isolation_receipt_id text NOT NULL,
  oracle_kind text NOT NULL CHECK (oracle_kind IN
    ('DETECTION_RULE_REFIRED','INDEPENDENT_PROBE_FAILED','RECONCILED_STATE_DIVERGED')),
  timing_class text NOT NULL CHECK (timing_class IN ('PRIMARY_WINDOW','DELAYED_RECURRENCE')),
  evidence_ref text NOT NULL, observed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id),
  UNIQUE (falsification_sequence),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id)
    REFERENCES recovery_declarations
      (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,isolation_receipt_id)
    REFERENCES verification_isolation_receipts
      (organization_id,project_id,environment_id,cell_id,placement_epoch,isolation_receipt_id)
);

CREATE FUNCTION quality_falsification_timing() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
DECLARE closes timestamptz; receipt_declaration text;
BEGIN
  SELECT window_closes_at INTO closes FROM recovery_declarations WHERE
   (organization_id,project_id,environment_id,cell_id,placement_epoch,declaration_id)=
   (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.cell_id,NEW.placement_epoch,NEW.declaration_id);
  SELECT declaration_id INTO receipt_declaration FROM verification_isolation_receipts WHERE
   (organization_id,project_id,environment_id,cell_id,placement_epoch,isolation_receipt_id)=
   (NEW.organization_id,NEW.project_id,NEW.environment_id,NEW.cell_id,NEW.placement_epoch,NEW.isolation_receipt_id);
  IF receipt_declaration IS DISTINCT FROM NEW.declaration_id THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='QUALITY_ISOLATION_DECLARATION_MISMATCH',
      CONSTRAINT='quality_isolation_declaration_match'; END IF;
  IF (NEW.timing_class='PRIMARY_WINDOW') IS DISTINCT FROM (NEW.observed_at<=closes) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='QUALITY_FALSIFICATION_TIMING_MISMATCH',
      CONSTRAINT='quality_falsification_timing'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER quality_falsification_timing_gate BEFORE INSERT ON recovery_falsifications
  FOR EACH ROW EXECUTE FUNCTION quality_falsification_timing();

CREATE TABLE falsification_attributions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, attribution_id text NOT NULL,
  falsification_id text NOT NULL, decision text NOT NULL CHECK (decision IN
    ('DISTINCT_MECHANISM_CONFIRMED','ATTRIBUTION_REJECTED')),
  proposed_by text NOT NULL, reviewed_by text NOT NULL,
  independent_review_receipt text NOT NULL, distinct_mechanism_ref text NOT NULL,
  reason_ref text NOT NULL, decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,attribution_id),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id)
    REFERENCES recovery_falsifications
      (organization_id,project_id,environment_id,cell_id,placement_epoch,falsification_id),
  CONSTRAINT quality_attribution_separation CHECK (proposed_by<>reviewed_by)
);

CREATE TABLE metric_population_revisions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, population_id text NOT NULL,
  catalog_version bigint NOT NULL REFERENCES fault_catalog_revisions(catalog_version),
  action_class text NOT NULL, service_key text NOT NULL,
  period_start timestamptz NOT NULL, period_end timestamptz NOT NULL,
  taxonomy_hash text NOT NULL CHECK (taxonomy_hash ~ '^sha256:[0-9a-f]{64}$'),
  population_rule_hash text NOT NULL CHECK (population_rule_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('DRAFT','FROZEN')),
  population_hash text CHECK (population_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), frozen_at timestamptz,
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch)
    REFERENCES quality_scope_bindings
      (organization_id,project_id,environment_id,cell_id,placement_epoch),
  CHECK (period_end>period_start),
  CONSTRAINT quality_population_freeze_shape CHECK
    ((status='FROZEN')=(population_hash IS NOT NULL AND frozen_at IS NOT NULL))
);
CREATE TABLE metric_population_members (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, population_id text NOT NULL,
  episode_id text NOT NULL, disposition text NOT NULL CHECK (disposition IN
    ('DECLARED','UNDECLARED','UNRECOVERABLE_ESCALATED','INCONCLUSIVE','CENSORED')),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id,episode_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)
    REFERENCES metric_population_revisions
      (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id)
    REFERENCES recovery_episodes
      (organization_id,project_id,environment_id,cell_id,placement_epoch,episode_id)
);

CREATE TABLE outcome_quality_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, receipt_id text NOT NULL,
  population_id text NOT NULL, population_hash text NOT NULL,
  eligible_episodes integer NOT NULL, declared_episodes integer NOT NULL,
  verified_recoveries integer NOT NULL, primary_falsifications integer NOT NULL,
  delayed_recurrences integer NOT NULL, attributed_falsifications integer NOT NULL,
  inconclusive_episodes integer NOT NULL, censored_episodes integer NOT NULL,
  unrecoverable_escalations integer NOT NULL, unresolved_effects integer NOT NULL,
  false_confirmation_rate numeric NOT NULL, declaration_coverage numeric NOT NULL,
  falsification_sequence_high_water bigint NOT NULL,
  published boolean NOT NULL, receipt_hash text NOT NULL UNIQUE,
  computed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,receipt_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)
    REFERENCES metric_population_revisions
      (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id),
  CONSTRAINT quality_receipt_count_bounds CHECK
    (eligible_episodes>=0 AND declared_episodes>=0 AND verified_recoveries>=0
     AND primary_falsifications>=0 AND delayed_recurrences>=0
     AND attributed_falsifications>=0 AND inconclusive_episodes>=0
     AND censored_episodes>=0 AND unrecoverable_escalations>=0
     AND unresolved_effects>=0 AND declared_episodes<=eligible_episodes
     AND primary_falsifications<=declared_episodes),
  CHECK (false_confirmation_rate>=0 AND false_confirmation_rate<=1
     AND declaration_coverage>=0 AND declaration_coverage<=1)
);

CREATE TABLE competence_policy_revisions (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  action_class text NOT NULL, revision bigint NOT NULL CHECK (revision>0),
  minimum_verified_recoveries integer NOT NULL CHECK (minimum_verified_recoveries>0),
  maximum_primary_falsifications integer NOT NULL CHECK (maximum_primary_falsifications=0),
  minimum_coverage_numerator integer NOT NULL CHECK (minimum_coverage_numerator>0),
  minimum_coverage_denominator integer NOT NULL CHECK
    (minimum_coverage_denominator>=minimum_coverage_numerator),
  competence_ttl_seconds integer NOT NULL CHECK (competence_ttl_seconds BETWEEN 3600 AND 7776000),
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,action_class,revision)
);
CREATE TABLE competence_policy_bindings (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  action_class text NOT NULL, binding_epoch bigint NOT NULL CHECK (binding_epoch>0),
  policy_revision bigint NOT NULL, earning_epoch_started_at timestamptz NOT NULL,
  revocation_sequence_high_water bigint NOT NULL CHECK (revocation_sequence_high_water>=0),
  is_current boolean NOT NULL, bound_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,action_class,binding_epoch),
  FOREIGN KEY (organization_id,project_id,environment_id,action_class,policy_revision)
    REFERENCES competence_policy_revisions
      (organization_id,project_id,environment_id,action_class,revision)
);
CREATE UNIQUE INDEX quality_one_current_competence_policy
  ON competence_policy_bindings(organization_id,project_id,environment_id,action_class)
  WHERE is_current;

CREATE TABLE autonomy_competence_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, receipt_id text NOT NULL,
  action_class text NOT NULL, policy_binding_epoch bigint NOT NULL,
  quality_receipt_id text NOT NULL, graph_snapshot_id text NOT NULL,
  graph_policy_binding_epoch bigint NOT NULL,
  falsification_sequence_high_water bigint NOT NULL,
  eligible boolean NOT NULL, ineligible_reason text,
  evidence_expires_at timestamptz NOT NULL, receipt_hash text NOT NULL UNIQUE,
  computed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,receipt_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,quality_receipt_id)
    REFERENCES outcome_quality_receipts
      (organization_id,project_id,environment_id,cell_id,placement_epoch,receipt_id),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,graph_snapshot_id)
    REFERENCES solvan_graph.graph_snapshots
      (organization_id,project_id,environment_id,cell_id,placement_epoch,snapshot_id),
  CHECK (eligible=(ineligible_reason IS NULL))
);

CREATE TABLE earned_action_reservations (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL, reservation_id text NOT NULL,
  action_id text NOT NULL, action_class text NOT NULL, target_key text NOT NULL,
  standing_preauthorization_id text NOT NULL, standing_preauthorization_version integer NOT NULL,
  competence_receipt_id text NOT NULL, graph_snapshot_id text NOT NULL,
  competence_policy_binding_epoch bigint NOT NULL, graph_policy_binding_epoch bigint NOT NULL,
  capacity_resource_kind text NOT NULL, capacity_binding_epoch bigint NOT NULL,
  capacity_receipt_id text NOT NULL, falsification_sequence_high_water bigint NOT NULL,
  lease_token uuid NOT NULL, expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,reservation_id),
  UNIQUE (organization_id,project_id,environment_id,action_id),
  FOREIGN KEY (organization_id,project_id,environment_id,
    standing_preauthorization_id,standing_preauthorization_version)
    REFERENCES solvan.standing_preauthorizations
      (organization_id,project_id,environment_id,id,version),
  FOREIGN KEY (organization_id,project_id,environment_id,cell_id,placement_epoch,competence_receipt_id)
    REFERENCES autonomy_competence_receipts
      (organization_id,project_id,environment_id,cell_id,placement_epoch,receipt_id),
  FOREIGN KEY (cell_id,capacity_resource_kind,capacity_binding_epoch,capacity_receipt_id)
    REFERENCES solvan_scale.cell_capacity_bindings(cell_id,resource_kind,binding_epoch,receipt_id),
  CHECK (expires_at>created_at)
);

CREATE TABLE quality_deletion_receipts (
  organization_id text NOT NULL, project_id text NOT NULL, environment_id text NOT NULL,
  cell_id text NOT NULL, placement_epoch bigint NOT NULL CHECK (placement_epoch>0),
  lifecycle_job_id text NOT NULL, deletion_epoch bigint NOT NULL CHECK (deletion_epoch>0),
  content_row_count bigint NOT NULL CHECK (content_row_count>=0),
  terminal_digest text NOT NULL CHECK (terminal_digest ~ '^sha256:[0-9a-f]{64}$'),
  deleted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,deletion_epoch),
  UNIQUE (organization_id,project_id,environment_id,cell_id,placement_epoch),
  FOREIGN KEY (organization_id,lifecycle_job_id)
    REFERENCES solvan_scale.tenant_lifecycle_jobs(organization_id,job_id)
);

CREATE FUNCTION quality_function_write_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
BEGIN
 IF current_setting('solvan_quality.derived_write',true) IS DISTINCT FROM 'on' THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='QUALITY_DERIVATION_FUNCTION_REQUIRED',
   CONSTRAINT='quality_derivation_function_only'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER quality_population_member_guard BEFORE INSERT ON metric_population_members
 FOR EACH ROW EXECUTE FUNCTION quality_function_write_guard();
CREATE TRIGGER quality_receipt_guard BEFORE INSERT ON outcome_quality_receipts
 FOR EACH ROW EXECUTE FUNCTION quality_function_write_guard();
CREATE TRIGGER quality_competence_guard BEFORE INSERT ON autonomy_competence_receipts
 FOR EACH ROW EXECUTE FUNCTION quality_function_write_guard();
CREATE TRIGGER quality_earned_reservation_guard BEFORE INSERT ON earned_action_reservations
 FOR EACH ROW EXECUTE FUNCTION quality_function_write_guard();

CREATE FUNCTION quality_build_population(
 p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,p_population text)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
DECLARE pop metric_population_revisions%ROWTYPE; hash_value text;
BEGIN
 SELECT * INTO pop FROM metric_population_revisions WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population) FOR UPDATE;
 IF pop.status<>'DRAFT' THEN RAISE EXCEPTION USING ERRCODE='23514',
  MESSAGE='QUALITY_POPULATION_NOT_DRAFT',CONSTRAINT='quality_population_draft_once'; END IF;
 PERFORM set_config('solvan_quality.derived_write','on',true);
 INSERT INTO metric_population_members
 SELECT organization_id,project_id,environment_id,cell_id,placement_epoch,p_population,episode_id,
  CASE outcome WHEN 'VERIFIED_RECOVERY' THEN
    CASE WHEN EXISTS (SELECT 1 FROM recovery_declarations d WHERE
      (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.episode_id)=
      (e.organization_id,e.project_id,e.environment_id,e.cell_id,e.placement_epoch,e.episode_id))
      THEN 'DECLARED' ELSE 'UNDECLARED' END
   WHEN 'ESCALATED_WITHOUT_DECLARATION' THEN 'UNRECOVERABLE_ESCALATED'
   WHEN 'INCONCLUSIVE' THEN 'INCONCLUSIVE' ELSE 'CENSORED' END
 FROM recovery_episodes e WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch)
  AND action_class=pop.action_class AND service_key=pop.service_key
  AND catalog_version=pop.catalog_version AND eligible_at>=pop.period_start AND eligible_at<pop.period_end;
 SELECT 'sha256:'||encode(public.digest(coalesce(string_agg(episode_id||':'||disposition,'|' ORDER BY episode_id),'')::bytea,'sha256'),'hex')
  INTO hash_value FROM metric_population_members WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population);
 UPDATE metric_population_revisions SET status='FROZEN',population_hash=hash_value,frozen_at=now()
  WHERE (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population);
 PERFORM set_config('solvan_quality.derived_write','off',true);
END $$;

CREATE FUNCTION quality_publish_receipt(
 p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,
 p_population text,p_receipt text)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
DECLARE pop metric_population_revisions%ROWTYPE; eligible integer; declared integer;
DECLARE verified integer; primary_false integer; delayed integer; attributed integer;
DECLARE inconclusive integer; censored integer; escalated integer; unresolved integer;
DECLARE highwater bigint; receipt_digest text;
BEGIN
 SELECT * INTO pop FROM metric_population_revisions WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population) FOR SHARE;
 IF pop.status<>'FROZEN' OR NOT EXISTS (SELECT 1 FROM fault_catalog_revisions
   WHERE catalog_version=pop.catalog_version AND status='APPROVED') THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='QUALITY_POPULATION_NOT_PUBLISHABLE',
   CONSTRAINT='quality_population_publishable'; END IF;
 SELECT count(*),count(*) FILTER (WHERE disposition='DECLARED'),
  count(*) FILTER (WHERE disposition IN ('DECLARED','UNDECLARED')),
  count(*) FILTER (WHERE disposition='INCONCLUSIVE'),
  count(*) FILTER (WHERE disposition='CENSORED'),
  count(*) FILTER (WHERE disposition='UNRECOVERABLE_ESCALATED')
 INTO eligible,declared,verified,inconclusive,censored,escalated
 FROM metric_population_members WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population);
 SELECT count(*) FILTER (WHERE f.timing_class='PRIMARY_WINDOW'),
  count(*) FILTER (WHERE f.timing_class='DELAYED_RECURRENCE'),
  count(*) FILTER (WHERE a.decision='DISTINCT_MECHANISM_CONFIRMED'),
  coalesce(max(f.falsification_sequence),0)
 INTO primary_false,delayed,attributed,highwater
 FROM metric_population_members m
 JOIN recovery_declarations d ON
  (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.episode_id)=
  (m.organization_id,m.project_id,m.environment_id,m.cell_id,m.placement_epoch,m.episode_id)
 LEFT JOIN recovery_falsifications f ON
  (f.organization_id,f.project_id,f.environment_id,f.cell_id,f.placement_epoch,f.declaration_id)=
  (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.declaration_id)
 LEFT JOIN falsification_attributions a ON
  (a.organization_id,a.project_id,a.environment_id,a.cell_id,a.placement_epoch,a.falsification_id)=
  (f.organization_id,f.project_id,f.environment_id,f.cell_id,f.placement_epoch,f.falsification_id)
 WHERE (m.organization_id,m.project_id,m.environment_id,m.cell_id,m.placement_epoch,m.population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population);
 SELECT coalesce(sum(e.unresolved_effect_count),0) INTO unresolved
 FROM metric_population_members m JOIN recovery_episodes e ON
  (e.organization_id,e.project_id,e.environment_id,e.cell_id,e.placement_epoch,e.episode_id)=
  (m.organization_id,m.project_id,m.environment_id,m.cell_id,m.placement_epoch,m.episode_id)
 WHERE (m.organization_id,m.project_id,m.environment_id,m.cell_id,m.placement_epoch,m.population_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_population);
 receipt_digest:='sha256:'||encode(public.digest(concat_ws(':',pop.population_hash,
  eligible,declared,verified,primary_false,delayed,attributed,inconclusive,censored,
  escalated,unresolved,highwater)::bytea,'sha256'),'hex');
 PERFORM set_config('solvan_quality.derived_write','on',true);
 INSERT INTO outcome_quality_receipts VALUES
  (p_org,p_project,p_environment,p_cell,p_epoch,p_receipt,p_population,pop.population_hash,
   eligible,declared,verified,primary_false,delayed,attributed,inconclusive,censored,
   escalated,unresolved,
   CASE WHEN declared=0 THEN 0 ELSE primary_false::numeric/declared END,
   CASE WHEN eligible=0 THEN 0 ELSE declared::numeric/eligible END,
   highwater,true,receipt_digest,now());
 PERFORM set_config('solvan_quality.derived_write','off',true);
END $$;

CREATE FUNCTION quality_derive_competence(
 p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,p_action_class text,
 p_quality_receipt text,p_competence_receipt text)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_quality,solvan_graph,pg_temp AS $$
DECLARE binding competence_policy_bindings%ROWTYPE; policy competence_policy_revisions%ROWTYPE;
DECLARE quality outcome_quality_receipts%ROWTYPE; graph graph_snapshots%ROWTYPE;
DECLARE population metric_population_revisions%ROWTYPE; graph_binding bigint;
DECLARE graph_max_age integer; latest_false bigint; okay boolean; why text; expiry timestamptz;
BEGIN
 SELECT * INTO binding FROM competence_policy_bindings WHERE organization_id=p_org
  AND project_id=p_project AND environment_id=p_environment AND action_class=p_action_class
  AND is_current FOR SHARE;
 SELECT * INTO policy FROM competence_policy_revisions WHERE
  (organization_id,project_id,environment_id,action_class,revision)=
  (p_org,p_project,p_environment,p_action_class,binding.policy_revision);
 SELECT * INTO quality FROM outcome_quality_receipts WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,receipt_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_quality_receipt) AND published FOR SHARE;
 SELECT * INTO population FROM metric_population_revisions WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,population_id)=
  (quality.organization_id,quality.project_id,quality.environment_id,quality.cell_id,
   quality.placement_epoch,quality.population_id);
 SELECT * INTO graph FROM solvan_graph.graph_snapshots WHERE organization_id=p_org
  AND project_id=p_project AND environment_id=p_environment AND cell_id=p_cell
  AND placement_epoch=p_epoch AND status='APPROVED' FOR SHARE;
 SELECT b.binding_epoch,p.autonomy_max_age_seconds INTO graph_binding,graph_max_age
  FROM solvan_graph.graph_staleness_policy_bindings b
  JOIN solvan_graph.graph_staleness_policy_revisions p ON
   (p.organization_id,p.project_id,p.environment_id,p.revision)=
   (b.organization_id,b.project_id,b.environment_id,b.policy_revision)
  WHERE b.organization_id=p_org AND b.project_id=p_project
   AND b.environment_id=p_environment AND b.is_current FOR SHARE OF b;
 SELECT coalesce(max(f.falsification_sequence),0) INTO latest_false
  FROM recovery_falsifications f JOIN recovery_declarations d ON
   (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.declaration_id)=
   (f.organization_id,f.project_id,f.environment_id,f.cell_id,f.placement_epoch,f.declaration_id)
  JOIN recovery_episodes e ON
   (e.organization_id,e.project_id,e.environment_id,e.cell_id,e.placement_epoch,e.episode_id)=
   (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.episode_id)
  WHERE e.organization_id=p_org AND e.project_id=p_project
   AND e.environment_id=p_environment AND e.action_class=p_action_class;
 okay:=binding.is_current AND quality.receipt_id IS NOT NULL AND graph.snapshot_id IS NOT NULL
  AND graph.autonomy_eligible AND quality.verified_recoveries>=policy.minimum_verified_recoveries
  AND quality.primary_falsifications<=policy.maximum_primary_falsifications
  AND quality.declared_episodes*policy.minimum_coverage_denominator>=
      quality.eligible_episodes*policy.minimum_coverage_numerator
  AND quality.unresolved_effects=0
  AND population.period_start>=binding.earning_epoch_started_at
  AND extract(epoch FROM (now()-graph.reconciled_at))<=graph_max_age
  AND quality.falsification_sequence_high_water=latest_false;
 why:=CASE WHEN okay THEN NULL ELSE 'PRECONDITION_FAILED' END;
 expiry:=quality.computed_at+make_interval(secs=>policy.competence_ttl_seconds);
 PERFORM set_config('solvan_quality.derived_write','on',true);
 INSERT INTO autonomy_competence_receipts VALUES
  (p_org,p_project,p_environment,p_cell,p_epoch,p_competence_receipt,p_action_class,
   binding.binding_epoch,p_quality_receipt,graph.snapshot_id,graph_binding,latest_false,
   okay,why,expiry,
   'sha256:'||encode(public.digest(concat_ws(':',p_quality_receipt,graph.snapshot_id,
     binding.binding_epoch,graph_binding,latest_false,okay)::bytea,'sha256'),'hex'),now());
 PERFORM set_config('solvan_quality.derived_write','off',true);
END $$;

-- The eventual production caller invokes this inside the same transaction that
-- holds the current placement, policy, graph, quality, capacity, standing
-- preauthorization and target locks. Any falsification committed first changes
-- the high-water and refuses this reservation.
CREATE FUNCTION quality_reserve_earned_action(
 p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,
 p_reservation text,p_action text,p_action_class text,p_target text,
 p_preauth text,p_preauth_version integer,p_competence text,
 p_capacity_kind text,p_capacity_epoch bigint,p_capacity_receipt text,
 p_lease uuid,p_expires timestamptz)
RETURNS void LANGUAGE plpgsql SET search_path=solvan_quality,solvan_graph,solvan_scale,solvan,pg_temp AS $$
DECLARE competence autonomy_competence_receipts%ROWTYPE; latest_false bigint;
DECLARE current_cell text; current_epoch bigint;
BEGIN
 IF current_setting('transaction_isolation') <> 'serializable' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='EARNED_AUTH_REQUIRES_SERIALIZABLE',
   CONSTRAINT='earned_auth_serializable'; END IF;
 SELECT cell_id,placement_epoch INTO current_cell,current_epoch FROM solvan_graph.graph_scope_bindings
  WHERE organization_id=p_org AND project_id=p_project AND environment_id=p_environment
   AND is_current AND lifecycle='ACTIVE' FOR UPDATE;
 IF (current_cell,current_epoch) IS DISTINCT FROM (p_cell,p_epoch) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='EARNED_AUTH_PLACEMENT_CHANGED',
   CONSTRAINT='earned_auth_placement_fence'; END IF;
 SELECT * INTO competence FROM autonomy_competence_receipts WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch,receipt_id)=
  (p_org,p_project,p_environment,p_cell,p_epoch,p_competence) FOR UPDATE;
 SELECT coalesce(max(f.falsification_sequence),0) INTO latest_false
  FROM recovery_falsifications f JOIN recovery_declarations d ON
   (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.declaration_id)=
   (f.organization_id,f.project_id,f.environment_id,f.cell_id,f.placement_epoch,f.declaration_id)
  JOIN recovery_episodes e ON
   (e.organization_id,e.project_id,e.environment_id,e.cell_id,e.placement_epoch,e.episode_id)=
   (d.organization_id,d.project_id,d.environment_id,d.cell_id,d.placement_epoch,d.episode_id)
  WHERE e.organization_id=p_org AND e.project_id=p_project
   AND e.environment_id=p_environment AND e.action_class=p_action_class;
 IF competence.falsification_sequence_high_water<>latest_false THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='EARNED_AUTH_FALSIFICATION_FENCE',
   CONSTRAINT='earned_auth_falsification_high_water'; END IF;
 IF NOT competence.eligible OR competence.evidence_expires_at<=now()
    OR NOT EXISTS (SELECT 1 FROM competence_policy_bindings WHERE
      organization_id=p_org AND project_id=p_project AND environment_id=p_environment
      AND action_class=p_action_class AND is_current
      AND binding_epoch=competence.policy_binding_epoch)
    OR NOT EXISTS (SELECT 1 FROM solvan_graph.graph_snapshots graph
      JOIN solvan.production_graph_snapshots authority ON
       (authority.organization_id,authority.project_id,authority.environment_id,authority.id)=
       (graph.organization_id,graph.project_id,graph.environment_id,graph.snapshot_id)
      WHERE graph.organization_id=p_org AND graph.project_id=p_project
       AND graph.environment_id=p_environment
       AND graph.snapshot_id=competence.graph_snapshot_id
       AND graph.status='APPROVED' AND graph.autonomy_eligible
       AND authority.status='APPROVED' AND authority.superseded_at IS NULL)
    OR NOT EXISTS (SELECT 1 FROM solvan_graph.graph_snapshots g
      JOIN solvan_graph.graph_staleness_policy_bindings b ON
       (b.organization_id,b.project_id,b.environment_id)=
       (g.organization_id,g.project_id,g.environment_id) AND b.is_current
      JOIN solvan_graph.graph_staleness_policy_revisions p ON
       (p.organization_id,p.project_id,p.environment_id,p.revision)=
       (b.organization_id,b.project_id,b.environment_id,b.policy_revision)
      WHERE g.organization_id=p_org AND g.project_id=p_project
       AND g.environment_id=p_environment AND g.snapshot_id=competence.graph_snapshot_id
       AND b.binding_epoch=competence.graph_policy_binding_epoch
       AND extract(epoch FROM (now()-g.reconciled_at))<=p.autonomy_max_age_seconds)
    OR NOT EXISTS (SELECT 1 FROM solvan_scale.cell_capacity_bindings b
      JOIN solvan_scale.cell_capacity_receipts r ON
       (r.cell_id,r.receipt_id)=(b.cell_id,b.receipt_id)
      WHERE b.cell_id=p_cell AND b.resource_kind=p_capacity_kind
       AND b.binding_epoch=p_capacity_epoch AND b.receipt_id=p_capacity_receipt
       AND b.decision='QUALIFY' AND r.expires_at>now())
    OR NOT EXISTS (SELECT 1 FROM solvan.standing_preauthorizations WHERE
      organization_id=p_org AND project_id=p_project AND environment_id=p_environment
      AND id=p_preauth AND version=p_preauth_version AND action_type=p_action_class
      AND status='APPROVED' AND valid_from<=now() AND valid_until>now())
    OR NOT EXISTS (SELECT 1 FROM solvan.actions action
      LEFT JOIN solvan.incidents incident ON
       (incident.organization_id,incident.project_id,incident.environment_id,incident.id)=
       (action.organization_id,action.project_id,action.environment_id,action.incident_id)
      LEFT JOIN solvan.reliability_cases repair_case ON
       (repair_case.organization_id,repair_case.project_id,
        repair_case.environment_id,repair_case.id)=
       (action.organization_id,action.project_id,
        action.environment_id,action.reliability_case_id)
      WHERE action.organization_id=p_org AND action.project_id=p_project
       AND action.environment_id=p_environment AND action.id=p_action
       AND action.action_type=p_action_class AND action.target_key=p_target
       AND action.standing_preauthorization_id=p_preauth
       AND action.standing_preauthorization_version=p_preauth_version
       AND action.status='AUTHORIZED' AND action.expires_at>now()
       AND coalesce(incident.production_graph_snapshot_id,
                    repair_case.production_graph_snapshot_id)=competence.graph_snapshot_id)
    OR p_expires<=now() THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='EARNED_AUTH_PRECONDITION_CHANGED',
   CONSTRAINT='earned_auth_atomic_fence'; END IF;
 IF EXISTS (SELECT 1 FROM earned_action_reservations reservation WHERE
      reservation.organization_id=p_org AND reservation.project_id=p_project
      AND reservation.environment_id=p_environment AND reservation.action_id=p_action
      AND reservation.cell_id=p_cell AND reservation.placement_epoch=p_epoch
      AND reservation.reservation_id=p_reservation
      AND reservation.action_class=p_action_class AND reservation.target_key=p_target
      AND reservation.standing_preauthorization_id=p_preauth
      AND reservation.standing_preauthorization_version=p_preauth_version
      AND reservation.competence_receipt_id=p_competence
      AND reservation.capacity_resource_kind=p_capacity_kind
      AND reservation.capacity_binding_epoch=p_capacity_epoch
      AND reservation.capacity_receipt_id=p_capacity_receipt
      AND reservation.falsification_sequence_high_water=latest_false
      AND reservation.lease_token=p_lease AND reservation.expires_at=p_expires
      AND reservation.expires_at>now()) THEN RETURN; END IF;
 PERFORM set_config('solvan_quality.derived_write','on',true);
 INSERT INTO earned_action_reservations VALUES
  (p_org,p_project,p_environment,p_cell,p_epoch,p_reservation,p_action,p_action_class,p_target,
   p_preauth,p_preauth_version,p_competence,competence.graph_snapshot_id,
   competence.policy_binding_epoch,competence.graph_policy_binding_epoch,p_capacity_kind,
   p_capacity_epoch,p_capacity_receipt,latest_false,p_lease,p_expires,now());
 PERFORM set_config('solvan_quality.derived_write','off',true);
END $$;

CREATE FUNCTION quality_history_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_quality,pg_temp AS $$
BEGIN
 IF current_setting('solvan_quality.purge_transaction',true)='on' THEN RETURN OLD; END IF;
 RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='QUALITY_HISTORY_IMMUTABLE',
  CONSTRAINT='quality_history_immutable';
END $$;
CREATE TRIGGER quality_declarations_immutable BEFORE UPDATE OR DELETE ON recovery_declarations
 FOR EACH ROW EXECUTE FUNCTION quality_history_immutable();
CREATE TRIGGER quality_isolation_immutable BEFORE UPDATE OR DELETE ON verification_isolation_receipts
 FOR EACH ROW EXECUTE FUNCTION quality_history_immutable();
CREATE TRIGGER quality_falsifications_immutable BEFORE UPDATE OR DELETE ON recovery_falsifications
 FOR EACH ROW EXECUTE FUNCTION quality_history_immutable();
CREATE TRIGGER quality_attributions_immutable BEFORE UPDATE OR DELETE ON falsification_attributions
 FOR EACH ROW EXECUTE FUNCTION quality_history_immutable();
CREATE TRIGGER quality_receipts_immutable BEFORE UPDATE OR DELETE ON outcome_quality_receipts
 FOR EACH ROW EXECUTE FUNCTION quality_history_immutable();
CREATE TRIGGER quality_competence_immutable BEFORE UPDATE OR DELETE ON autonomy_competence_receipts
 FOR EACH ROW EXECUTE FUNCTION quality_history_immutable();

-- Quality evidence is purged before its referenced Production Graph snapshot.
-- Global fault catalogs remain because they contain no tenant content. Only a
-- content-free count/digest receipt survives the verified deletion job.
CREATE FUNCTION quality_purge_scope(
 p_org text,p_project text,p_environment text,p_cell text,p_epoch bigint,
 p_lifecycle_job text,p_deletion_epoch bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=solvan_quality,solvan_scale,pg_temp AS $$
DECLARE job solvan_scale.tenant_lifecycle_jobs%ROWTYPE;
DECLARE content_total bigint; terminal text;
BEGIN
 SELECT * INTO job FROM solvan_scale.tenant_lifecycle_jobs
  WHERE organization_id=p_org AND job_id=p_lifecycle_job FOR UPDATE;
 IF job.job_kind IS DISTINCT FROM 'DELETE' OR job.state IS DISTINCT FROM 'VERIFYING'
    OR job.legal_hold_ref IS NOT NULL OR job.unsettled_mutation_count<>0
    OR job.source_cell_id IS DISTINCT FROM p_cell
    OR job.expected_placement_epoch IS DISTINCT FROM p_epoch THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='QUALITY_PURGE_LIFECYCLE_REFUSED',
   CONSTRAINT='quality_purge_verified_delete_only';
 END IF;
 SELECT
   (SELECT count(*) FROM recovery_episodes WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM recovery_declarations WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM verification_isolation_receipts WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM recovery_falsifications WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM falsification_attributions WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM metric_population_revisions WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM metric_population_members WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM outcome_quality_receipts WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM autonomy_competence_receipts WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM earned_action_reservations WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))+
   (SELECT count(*) FROM competence_policy_revisions WHERE
    (organization_id,project_id,environment_id)=(p_org,p_project,p_environment))+
   (SELECT count(*) FROM competence_policy_bindings WHERE
    (organization_id,project_id,environment_id)=(p_org,p_project,p_environment))+
   (SELECT count(*) FROM quality_scope_bindings WHERE
    (organization_id,project_id,environment_id,cell_id,placement_epoch)=
    (p_org,p_project,p_environment,p_cell,p_epoch))
  INTO content_total;
 terminal:='sha256:'||encode(public.digest(concat_ws(':','QUALITY_PURGED',p_org,
   p_project,p_environment,p_cell,p_epoch,p_deletion_epoch,content_total)::bytea,
   'sha256'),'hex');
 PERFORM set_config('solvan_quality.purge_transaction','on',true);
 DELETE FROM earned_action_reservations WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM autonomy_competence_receipts WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM outcome_quality_receipts WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM metric_population_members WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM metric_population_revisions WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM falsification_attributions WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM recovery_falsifications WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM verification_isolation_receipts WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM recovery_declarations WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM recovery_episodes WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 DELETE FROM competence_policy_bindings WHERE
  (organization_id,project_id,environment_id)=(p_org,p_project,p_environment);
 DELETE FROM competence_policy_revisions WHERE
  (organization_id,project_id,environment_id)=(p_org,p_project,p_environment);
 DELETE FROM quality_scope_bindings WHERE
  (organization_id,project_id,environment_id,cell_id,placement_epoch)=
  (p_org,p_project,p_environment,p_cell,p_epoch);
 INSERT INTO quality_deletion_receipts VALUES
  (p_org,p_project,p_environment,p_cell,p_epoch,p_lifecycle_job,p_deletion_epoch,
   content_total,terminal,now());
 PERFORM set_config('solvan_quality.purge_transaction','off',true);
END $$;

REVOKE INSERT,UPDATE,DELETE ON outcome_quality_receipts,autonomy_competence_receipts,
 metric_population_members,earned_action_reservations FROM PUBLIC;
REVOKE ALL ON FUNCTION quality_purge_scope(text,text,text,text,bigint,text,bigint) FROM PUBLIC;
COMMIT;
