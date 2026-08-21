-- Solvan SaaS scale and isolation: TARGET schema for specification 19.
-- Separate from competition release DDL. It is a loadable target contract,
-- not evidence of a deployed or qualified multi-tenant service.

BEGIN;
CREATE SCHEMA solvan_scale;
SET search_path TO solvan_scale, public;

-- An immutable, human-approved admission profile is evaluated before a cell
-- can host any tenant. Arrays are closed allow-lists: an empty list never
-- means "all". Provider launch stage is recorded because Preview/Alpha
-- services cannot silently become eligible for confidential shared tenancy.
CREATE TABLE cell_eligibility_profiles (
  eligibility_profile_hash text PRIMARY KEY
    CHECK (eligibility_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  allowed_classifications text[] NOT NULL
    CHECK (cardinality(allowed_classifications) > 0 AND
           allowed_classifications <@ ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED']::text[]),
  allowed_residency_regions text[] NOT NULL
    CHECK (cardinality(allowed_residency_regions) > 0),
  allowed_provider_launch_stages text[] NOT NULL
    CHECK (cardinality(allowed_provider_launch_stages) > 0 AND
           allowed_provider_launch_stages <@ ARRAY['GA','PREVIEW','ALPHA']::text[]),
  encryption_profile_hash text NOT NULL
    CHECK (encryption_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  support_access_allowed boolean NOT NULL,
  allowed_recovery_regions text[] NOT NULL
    CHECK (cardinality(allowed_recovery_regions) > 0),
  approved_ref text NOT NULL CHECK (approved_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Tenant requirements are an independently approved immutable operand. A
-- cell profile cannot prove compatibility with itself.
CREATE TABLE tenant_eligibility_requirements (
  organization_id text NOT NULL CHECK (organization_id ~ '^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  requirement_hash text NOT NULL CHECK (requirement_hash ~ '^sha256:[0-9a-f]{64}$'),
  allowed_classifications text[] NOT NULL
    CHECK (cardinality(allowed_classifications) > 0 AND
           allowed_classifications <@ ARRAY['PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED']::text[]),
  allowed_residency_regions text[] NOT NULL CHECK (cardinality(allowed_residency_regions) > 0),
  allowed_provider_launch_stages text[] NOT NULL
    CHECK (cardinality(allowed_provider_launch_stages) > 0 AND
           allowed_provider_launch_stages <@ ARRAY['GA','PREVIEW','ALPHA']::text[]),
  encryption_profile_hash text NOT NULL
    CHECK (encryption_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  support_access_allowed boolean NOT NULL,
  allowed_recovery_regions text[] NOT NULL CHECK (cardinality(allowed_recovery_regions) > 0),
  approved_ref text NOT NULL CHECK (approved_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, requirement_hash)
);

CREATE TABLE cells (
  cell_id text PRIMARY KEY CHECK (cell_id ~ '^cell_[a-z0-9]+([_-][a-z0-9]+)*$'),
  deployment_profile text NOT NULL CHECK (deployment_profile IN
    ('OSS_SINGLE_TENANT','SHARED_CELL','DEDICATED_CELL')),
  region text NOT NULL CHECK (length(region) BETWEEN 2 AND 63),
  project_ref text NOT NULL CHECK (length(project_ref) BETWEEN 1 AND 255),
  lifecycle text NOT NULL CHECK (lifecycle IN
    ('PROVISIONING','READY','DRAINING','SUSPENDED','RETIRED')),
  max_organizations integer NOT NULL CHECK (max_organizations > 0),
  capacity_profile_hash text NOT NULL CHECK (capacity_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  data_policy_hash text NOT NULL CHECK (data_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  eligibility_profile_hash text NOT NULL
    REFERENCES cell_eligibility_profiles(eligibility_profile_hash),
  deployment_manifest_hash text NOT NULL UNIQUE CHECK (deployment_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CONSTRAINT cells_profile_capacity_ck CHECK
    ((deployment_profile = 'SHARED_CELL' AND max_organizations >= 2) OR
     (deployment_profile <> 'SHARED_CELL' AND max_organizations = 1)),
  CHECK ((lifecycle = 'RETIRED') = (retired_at IS NOT NULL)),
  UNIQUE (cell_id, deployment_manifest_hash),
  UNIQUE (cell_id, project_ref, region, deployment_manifest_hash)
);

CREATE TABLE tenant_placements (
  organization_id text NOT NULL CHECK (organization_id ~ '^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  cell_id text NOT NULL REFERENCES cells(cell_id),
  lifecycle text NOT NULL CHECK (lifecycle IN
    ('PROVISIONING','ACTIVE','SUSPENDING','SUSPENDED','MOVING','DELETING','DELETED','FAILED')),
  is_current boolean NOT NULL DEFAULT false,
  isolation_tier text NOT NULL CHECK (isolation_tier IN
    ('OSS_SINGLE_TENANT','SHARED_CELL','DEDICATED_CELL')),
  home_region text NOT NULL CHECK (length(home_region) BETWEEN 2 AND 63),
  classification_ceiling text NOT NULL CHECK (classification_ceiling IN
    ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
  eligibility_requirement_hash text NOT NULL CHECK
    (eligibility_requirement_hash ~ '^sha256:[0-9a-f]{64}$'),
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  encryption_profile_hash text NOT NULL CHECK (encryption_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  retired_at timestamptz,
  PRIMARY KEY (organization_id, placement_epoch),
  FOREIGN KEY (organization_id, eligibility_requirement_hash)
    REFERENCES tenant_eligibility_requirements(organization_id, requirement_hash),
  UNIQUE (organization_id, placement_epoch, cell_id),
  CHECK (NOT is_current OR lifecycle IN ('ACTIVE','SUSPENDING','SUSPENDED','MOVING','DELETING')),
  CHECK (lifecycle <> 'ACTIVE' OR activated_at IS NOT NULL),
  CHECK (NOT is_current OR activated_at IS NOT NULL),
  CHECK ((lifecycle = 'DELETED') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX one_current_placement_per_tenant
  ON tenant_placements(organization_id) WHERE is_current;
CREATE INDEX current_tenants_by_cell
  ON tenant_placements(cell_id, organization_id) WHERE is_current;

CREATE TABLE placement_lifecycle_transitions (
  from_state text NOT NULL,
  to_state text NOT NULL,
  PRIMARY KEY (from_state, to_state),
  CHECK (from_state <> 'DELETED')
);
INSERT INTO placement_lifecycle_transitions(from_state,to_state) VALUES
 ('PROVISIONING','ACTIVE'),('PROVISIONING','FAILED'),
 ('ACTIVE','SUSPENDING'),('ACTIVE','MOVING'),('ACTIVE','DELETING'),
 ('SUSPENDING','SUSPENDED'),('SUSPENDING','FAILED'),
 ('SUSPENDED','ACTIVE'),('SUSPENDED','MOVING'),('SUSPENDED','DELETING'),
 ('MOVING','ACTIVE'),('MOVING','FAILED'),
 ('DELETING','DELETED'),('DELETING','FAILED');

CREATE TABLE tenant_location_policies (
  organization_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  policy_version bigint NOT NULL CHECK (policy_version > 0),
  location_kind text NOT NULL CHECK (location_kind IN
    ('ROUTING_PLANE_PROCESSING','MODEL_PROCESSING','PRIMARY_DATA','BACKUP','LOG_SINK',
     'SUPPORT_PROCESSING','CUSTOMER_AUDIT','CHANNEL_DESTINATION','EXPORT','FAILOVER')),
  allowed_locations text[] NOT NULL CHECK (cardinality(allowed_locations) > 0),
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_ref text NOT NULL CHECK (approved_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, policy_version, location_kind),
  FOREIGN KEY (organization_id, placement_epoch)
    REFERENCES tenant_placements(organization_id, placement_epoch)
);

CREATE TABLE scale_database_roles (
  database_role name PRIMARY KEY,
  cell_id text NOT NULL REFERENCES cells(cell_id),
  role_kind text NOT NULL CHECK (role_kind IN ('ACCESS_BROKER','LIFECYCLE','AUDIT','SUPPORT')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (database_role, cell_id)
);

-- Closed input to the deployment privilege materializer. It creates NOINHERIT
-- roles with no cross-role membership and applies only these grants; the target
-- DDL itself grants nothing to an application principal.
CREATE TABLE scale_database_privilege_manifest (
  role_kind text NOT NULL CHECK (role_kind IN ('ACCESS_BROKER','LIFECYCLE','AUDIT','SUPPORT')),
  object_kind text NOT NULL CHECK (object_kind IN ('SCHEMA','TABLE','VIEW','FUNCTION','COLUMN')),
  object_name text NOT NULL CHECK (object_name ~ '^[a-z_]+(\([a-z, ]+\))?$'),
  privilege_name text NOT NULL CHECK (privilege_name IN
    ('USAGE','SELECT','INSERT','UPDATE','DELETE','EXECUTE')),
  column_name text NOT NULL DEFAULT '' CHECK (column_name = '' OR column_name ~ '^[a-z_]+$'),
  PRIMARY KEY (role_kind,object_kind,object_name,privilege_name,column_name),
  CHECK ((object_kind = 'COLUMN') = (column_name <> ''))
);
INSERT INTO scale_database_privilege_manifest VALUES
 ('ACCESS_BROKER','SCHEMA','solvan_scale','USAGE',''),
 ('ACCESS_BROKER','FUNCTION','scope_permitted(text, text, text)','EXECUTE',''),
 ('ACCESS_BROKER','TABLE','routing_grant_sessions','INSERT',''),
 ('ACCESS_BROKER','COLUMN','routing_grant_sessions','UPDATE','invalidated_at'),
 ('ACCESS_BROKER','TABLE','tenant_work_registry','SELECT',''),
 ('ACCESS_BROKER','TABLE','tenant_work_registry','INSERT',''),
 ('ACCESS_BROKER','TABLE','tenant_capacity_reservations','SELECT',''),
 ('ACCESS_BROKER','TABLE','tenant_capacity_reservations','INSERT',''),
 ('ACCESS_BROKER','TABLE','tenant_capacity_reservations','UPDATE',''),
 ('ACCESS_BROKER','TABLE','tenant_scheduler_lanes','SELECT',''),
 ('ACCESS_BROKER','TABLE','tenant_scheduler_lanes','INSERT',''),
 ('ACCESS_BROKER','TABLE','tenant_scheduler_lanes','UPDATE',''),
 ('ACCESS_BROKER','TABLE','tenant_dispatch_queue','SELECT',''),
 ('ACCESS_BROKER','TABLE','tenant_dispatch_queue','INSERT',''),
 ('ACCESS_BROKER','TABLE','tenant_dispatch_queue','UPDATE',''),
 ('ACCESS_BROKER','TABLE','usage_events','SELECT',''),
 ('ACCESS_BROKER','TABLE','usage_events','INSERT',''),
 ('ACCESS_BROKER','TABLE','cell_event_ingress','SELECT',''),
 ('ACCESS_BROKER','TABLE','cell_event_ingress','INSERT',''),
 ('ACCESS_BROKER','TABLE','cell_event_ingress','UPDATE',''),
 ('LIFECYCLE','SCHEMA','solvan_scale','USAGE',''),
 ('LIFECYCLE','TABLE','tenant_placements','SELECT',''),
 ('LIFECYCLE','TABLE','tenant_placements','INSERT',''),
 ('LIFECYCLE','TABLE','tenant_placements','UPDATE',''),
 ('LIFECYCLE','TABLE','tenant_lifecycle_jobs','SELECT',''),
 ('LIFECYCLE','TABLE','tenant_lifecycle_jobs','INSERT',''),
 ('LIFECYCLE','TABLE','tenant_lifecycle_jobs','UPDATE',''),
 ('AUDIT','SCHEMA','solvan_scale','USAGE',''),
 ('AUDIT','TABLE','routing_grant_audits','SELECT',''),
 ('SUPPORT','SCHEMA','solvan_scale','USAGE','');

-- Immutable, credential-free grant history. Spoofed or denied grants can be
-- recorded even when no valid placement exists, so there is deliberately no
-- placement FK. grant_jti_hash is never usable as database authority.
CREATE TABLE routing_grant_audits (
  audit_id text PRIMARY KEY CHECK (audit_id ~ '^audit_[A-Za-z0-9_-]+$'),
  organization_id text CHECK (
    organization_id IS NULL OR organization_id ~ '^org_[0-7][0-9A-HJKMNP-TV-Z]{25}$'
  ),
  grant_jti_hash text NOT NULL CHECK (grant_jti_hash ~ '^sha256:[0-9a-f]{64}$'),
  cell_id text,
  placement_epoch bigint CHECK (placement_epoch IS NULL OR placement_epoch > 0),
  principal_hash text NOT NULL CHECK (principal_hash ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  audience_hash text NOT NULL CHECK (audience_hash ~ '^sha256:[0-9a-f]{64}$'),
  outcome text NOT NULL CHECK (outcome IN ('ISSUED','ACCEPTED','DENIED','EXPIRED','REVOKED')),
  reason_code text CHECK (reason_code IS NULL OR reason_code ~ '^[A-Z0-9_]{1,64}$'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (grant_jti_hash, outcome, audit_id),
  CHECK ((outcome IN ('ISSUED','ACCEPTED')) = (reason_code IS NULL)),
  CHECK (expires_at > occurred_at)
);
CREATE INDEX routing_grant_audits_by_hash_time
  ON routing_grant_audits(grant_jti_hash, occurred_at DESC);

CREATE FUNCTION enforce_grant_audit_terminality() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_scale,pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(193718, hashtext(NEW.grant_jti_hash));
  IF NEW.outcome = 'ACCEPTED' AND EXISTS (
    SELECT 1 FROM routing_grant_audits prior
     WHERE prior.grant_jti_hash=NEW.grant_jti_hash
       AND prior.outcome IN ('ACCEPTED','DENIED','EXPIRED','REVOKED')) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='terminal grant cannot be accepted';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER routing_grant_terminality BEFORE INSERT ON routing_grant_audits
FOR EACH ROW EXECUTE FUNCTION enforce_grant_audit_terminality();

-- Private, short-lived live authorization state. Only the broker entry point
-- inserts it; application/support/audit roles receive no SELECT/INSERT grants.
CREATE TABLE routing_grant_sessions (
  context_id uuid PRIMARY KEY,
  grant_jti_hash text NOT NULL CHECK (grant_jti_hash ~ '^sha256:[0-9a-f]{64}$'),
  organization_id text NOT NULL,
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  database_role name NOT NULL,
  principal_hash text NOT NULL CHECK (principal_hash ~ '^sha256:[0-9a-f]{64}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  audience_hash text NOT NULL CHECK (audience_hash ~ '^sha256:[0-9a-f]{64}$'),
  backend_pid integer NOT NULL CHECK (backend_pid > 0),
  transaction_id xid8 NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  invalidated_at timestamptz,
  UNIQUE (grant_jti_hash),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  FOREIGN KEY (database_role, cell_id)
    REFERENCES scale_database_roles(database_role, cell_id),
  CHECK (expires_at > accepted_at)
);
CREATE INDEX live_routing_sessions_by_expiry
  ON routing_grant_sessions(expires_at) WHERE invalidated_at IS NULL;

CREATE FUNCTION enforce_live_grant_acceptance() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_scale,pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM routing_grant_audits accepted
     WHERE accepted.grant_jti_hash=NEW.grant_jti_hash
       AND accepted.outcome='ACCEPTED'
       AND accepted.organization_id=NEW.organization_id
       AND accepted.cell_id=NEW.cell_id
       AND accepted.placement_epoch=NEW.placement_epoch
       AND accepted.principal_hash=NEW.principal_hash
       AND accepted.request_hash=NEW.request_hash
       AND accepted.audience_hash=NEW.audience_hash
       AND accepted.expires_at >= NEW.expires_at
  ) OR EXISTS (
    SELECT 1 FROM routing_grant_audits terminal
     WHERE terminal.grant_jti_hash=NEW.grant_jti_hash
       AND terminal.outcome IN ('DENIED','EXPIRED','REVOKED')) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='live session requires non-terminal acceptance';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER live_grant_requires_acceptance BEFORE INSERT ON routing_grant_sessions
FOR EACH ROW EXECUTE FUNCTION enforce_live_grant_acceptance();

CREATE FUNCTION scope_permitted(
  requested_organization_id text,
  requested_project_id text,
  requested_environment_id text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = solvan_scale, pg_temp
AS $scope$
  SELECT EXISTS (
    SELECT 1
      FROM routing_grant_sessions session
      JOIN tenant_placements placement
        ON placement.organization_id = session.organization_id
       AND placement.placement_epoch = session.placement_epoch
       AND placement.cell_id = session.cell_id
       AND placement.is_current
       AND placement.lifecycle = 'ACTIVE'
     WHERE session.context_id::text = current_setting('solvan.routing_context_id', true)
       AND session.organization_id = requested_organization_id
       AND session.project_id = requested_project_id
       AND session.environment_id = requested_environment_id
       AND session.database_role = COALESCE(
         NULLIF(current_setting('role', true), 'none')::name,
         session_user::name)
       AND session.backend_pid = pg_backend_pid()
       AND session.transaction_id = pg_current_xact_id()
       AND session.invalidated_at IS NULL
       AND session.expires_at > statement_timestamp()
       AND NOT EXISTS (
         SELECT 1 FROM routing_grant_audits terminal
          WHERE terminal.grant_jti_hash = session.grant_jti_hash
            AND terminal.outcome IN ('DENIED','EXPIRED','REVOKED'))
  )
$scope$;
REVOKE ALL ON FUNCTION scope_permitted(text, text, text) FROM PUBLIC;

CREATE TABLE tenant_quota_policy_revisions (
  organization_id text NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  policy_hash text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  approval_ref text NOT NULL CHECK (approval_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  effective_at timestamptz NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, version),
  UNIQUE (organization_id, policy_hash),
  CHECK (expires_at IS NULL OR expires_at > effective_at)
);
CREATE TABLE tenant_quota_policy_bindings (
  organization_id text NOT NULL,
  binding_epoch bigint NOT NULL CHECK (binding_epoch > 0),
  decision text NOT NULL CHECK (decision IN ('ACTIVATE','REVOKE')),
  policy_version bigint,
  decision_ref text NOT NULL CHECK (decision_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, binding_epoch),
  FOREIGN KEY (organization_id, policy_version)
    REFERENCES tenant_quota_policy_revisions(organization_id, version),
  CHECK ((decision = 'ACTIVATE') = (policy_version IS NOT NULL))
);
CREATE TABLE tenant_quota_limits (
  organization_id text NOT NULL,
  policy_version bigint NOT NULL,
  resource_kind text NOT NULL CHECK (resource_kind IN
    ('API_REQUEST','CONVERSATION_TURN','AGENT_RUN','MODEL_REQUEST','MODEL_INPUT_TOKEN',
     'MODEL_OUTPUT_TOKEN','MEMORY_READ','MEMORY_WRITE','CONNECTOR_CALL',
     'CHANNEL_DELIVERY','SSE_CONNECTION','SUBSCRIPTION','STORED_BYTE')),
  window_seconds integer NOT NULL CHECK (window_seconds BETWEEN 1 AND 2678400),
  sustained_limit bigint NOT NULL CHECK (sustained_limit > 0),
  burst_limit bigint NOT NULL CHECK (burst_limit >= sustained_limit),
  maximum_concurrent integer NOT NULL CHECK (maximum_concurrent > 0),
  exhaustion_behavior text NOT NULL CHECK (exhaustion_behavior IN ('WAIT','REJECT')),
  PRIMARY KEY (organization_id, policy_version, resource_kind),
  FOREIGN KEY (organization_id, policy_version)
    REFERENCES tenant_quota_policy_revisions(organization_id, version)
);
CREATE TABLE tenant_quota_counters (
  organization_id text NOT NULL,
  policy_version bigint NOT NULL,
  resource_kind text NOT NULL,
  token_nanounits numeric(30,0) NOT NULL CHECK (token_nanounits >= 0),
  refill_remainder numeric(30,0) NOT NULL DEFAULT 0 CHECK (refill_remainder >= 0),
  active_reservations integer NOT NULL DEFAULT 0 CHECK (active_reservations >= 0),
  refill_at timestamptz NOT NULL,
  counter_epoch bigint NOT NULL CHECK (counter_epoch > 0),
  PRIMARY KEY (organization_id, policy_version, resource_kind),
  FOREIGN KEY (organization_id, policy_version, resource_kind)
    REFERENCES tenant_quota_limits(organization_id, policy_version, resource_kind)
);

CREATE TABLE cell_capacity_receipts (
  cell_id text NOT NULL REFERENCES cells(cell_id),
  receipt_id text NOT NULL CHECK (receipt_id ~ '^cap_[A-Za-z0-9_-]+$'),
  resource_kind text NOT NULL CHECK (resource_kind IN
    ('CLOUD_SQL_CONNECTION','CLOUD_RUN_INSTANCE','AGENT_RUNTIME_QUERY','SESSION_READ',
     'SESSION_WRITE','SESSION_EVENT_APPEND','MEMORY_READ','MEMORY_WRITE','MODEL_REQUEST',
     'CONNECTOR_CALL','PUBSUB_BACKLOG')),
  project_ref text NOT NULL CHECK (length(project_ref) BETWEEN 1 AND 255),
  region text NOT NULL CHECK (length(region) BETWEEN 2 AND 63),
  observed_limit bigint NOT NULL CHECK (observed_limit > 0),
  reserved_headroom bigint NOT NULL CHECK (reserved_headroom >= 0 AND reserved_headroom < observed_limit),
  deployment_manifest_hash text NOT NULL,
  source_ref text NOT NULL CHECK (source_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  source_hash text NOT NULL CHECK (source_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_model_resource text NOT NULL DEFAULT '',
  provider_endpoint_ref text NOT NULL DEFAULT '',
  provider_profile_hash text NOT NULL DEFAULT '' CHECK
    (provider_profile_hash = '' OR provider_profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (cell_id, receipt_id),
  UNIQUE (cell_id,receipt_id,resource_kind,project_ref,region,deployment_manifest_hash,
          provider_model_resource,provider_endpoint_ref,provider_profile_hash),
  CONSTRAINT capacity_receipt_cell_deployment_fk
  FOREIGN KEY (cell_id,project_ref,region,deployment_manifest_hash)
    REFERENCES cells(cell_id,project_ref,region,deployment_manifest_hash),
  CHECK (expires_at > observed_at),
  CHECK ((resource_kind = 'MODEL_REQUEST') =
         (provider_model_resource <> '' AND provider_endpoint_ref <> '' AND
          provider_profile_hash <> ''))
);
CREATE INDEX capacity_receipts_by_resource
  ON cell_capacity_receipts(cell_id, resource_kind, observed_at DESC);
CREATE TABLE cell_capacity_bindings (
  cell_id text NOT NULL,
  resource_kind text NOT NULL,
  binding_epoch bigint NOT NULL CHECK (binding_epoch > 0),
  decision text NOT NULL CHECK (decision IN ('QUALIFY','REVOKE')),
  receipt_id text,
  project_ref text,
  region text,
  deployment_manifest_hash text,
  provider_model_resource text NOT NULL DEFAULT '',
  provider_endpoint_ref text NOT NULL DEFAULT '',
  provider_profile_hash text NOT NULL DEFAULT '',
  decision_ref text NOT NULL CHECK (decision_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  decided_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cell_id, resource_kind, binding_epoch),
  UNIQUE (cell_id,resource_kind,binding_epoch,receipt_id),
  CONSTRAINT capacity_binding_receipt_fk
  FOREIGN KEY (cell_id,receipt_id,resource_kind,project_ref,region,deployment_manifest_hash,
               provider_model_resource,provider_endpoint_ref,provider_profile_hash)
    REFERENCES cell_capacity_receipts
      (cell_id,receipt_id,resource_kind,project_ref,region,deployment_manifest_hash,
       provider_model_resource,provider_endpoint_ref,provider_profile_hash),
  CHECK ((decision = 'QUALIFY') =
         (receipt_id IS NOT NULL AND project_ref IS NOT NULL AND region IS NOT NULL AND
          deployment_manifest_hash IS NOT NULL)),
  CHECK (decision = 'QUALIFY' OR
         (receipt_id IS NULL AND project_ref IS NULL AND region IS NULL AND
          deployment_manifest_hash IS NULL AND provider_model_resource = '' AND
          provider_endpoint_ref = '' AND provider_profile_hash = '')),
  CHECK ((resource_kind = 'MODEL_REQUEST' AND decision = 'QUALIFY') =
         (provider_model_resource <> '' AND provider_endpoint_ref <> '' AND
          provider_profile_hash <> ''))
);

CREATE TABLE cell_capacity_profiles (
  cell_id text NOT NULL REFERENCES cells(cell_id),
  profile_version bigint NOT NULL CHECK (profile_version > 0),
  ordinary_dispatch_slots integer NOT NULL CHECK (ordinary_dispatch_slots > 0),
  control_reserve_slots integer NOT NULL CHECK (control_reserve_slots > 0),
  base_quantum integer NOT NULL CHECK (base_quantum > 0),
  max_deficit integer NOT NULL CHECK (max_deficit >= base_quantum),
  maximum_wait_seconds integer NOT NULL CHECK (maximum_wait_seconds > 0),
  maximum_tenant_share_basis_points integer NOT NULL CHECK
    (maximum_tenant_share_basis_points BETWEEN 1 AND 10000),
  job_connection_budget integer NOT NULL CHECK (job_connection_budget >= 0),
  migration_connection_budget integer NOT NULL CHECK (migration_connection_budget >= 0),
  pooler_admin_connection_budget integer NOT NULL CHECK (pooler_admin_connection_budget >= 0),
  failover_overlap_budget integer NOT NULL CHECK (failover_overlap_budget >= 0),
  operator_emergency_reserve integer NOT NULL CHECK (operator_emergency_reserve > 0),
  profile_hash text NOT NULL CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
  approved_ref text NOT NULL CHECK (approved_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  PRIMARY KEY (cell_id, profile_version)
);
CREATE TABLE cell_service_pool_profiles (
  cell_id text NOT NULL,
  profile_version bigint NOT NULL,
  service_key text NOT NULL CHECK (service_key ~ '^[a-z][a-z0-9-]{1,62}$'),
  service_revision text NOT NULL CHECK (length(service_revision) BETWEEN 1 AND 128),
  max_instances integer NOT NULL CHECK (max_instances > 0),
  request_concurrency integer NOT NULL CHECK (request_concurrency > 0),
  per_instance_pool_min integer NOT NULL CHECK (per_instance_pool_min >= 0),
  per_instance_pool_max integer NOT NULL CHECK (per_instance_pool_max > 0),
  acquisition_timeout_ms integer NOT NULL CHECK (acquisition_timeout_ms > 0),
  idle_lifetime_seconds integer NOT NULL CHECK (idle_lifetime_seconds > 0),
  max_connection_lifetime_seconds integer NOT NULL CHECK (max_connection_lifetime_seconds > 0),
  iam_token_lifetime_seconds integer NOT NULL CHECK (iam_token_lifetime_seconds > 0),
  identity_safety_margin_seconds integer NOT NULL CHECK (identity_safety_margin_seconds > 0),
  rolling_overlap_instances integer NOT NULL CHECK (rolling_overlap_instances >= 0),
  overshoot_numerator integer NOT NULL CHECK (overshoot_numerator >= overshoot_denominator),
  overshoot_denominator integer NOT NULL CHECK (overshoot_denominator > 0),
  overshoot_receipt_ref text NOT NULL CHECK (overshoot_receipt_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  overshoot_expires_at timestamptz NOT NULL,
  application_name text NOT NULL CHECK (application_name ~ '^[a-z][a-z0-9-]{1,62}$'),
  PRIMARY KEY (cell_id, profile_version, service_key),
  FOREIGN KEY (cell_id, profile_version)
    REFERENCES cell_capacity_profiles(cell_id, profile_version),
  CHECK (per_instance_pool_min <= per_instance_pool_max),
  CHECK (max_connection_lifetime_seconds + identity_safety_margin_seconds < iam_token_lifetime_seconds)
);

CREATE TABLE tenant_work_registry (
  organization_id text NOT NULL,
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  work_kind text NOT NULL CHECK (work_kind IN
    ('CONVERSATION_TURN','AGENT_RUN','CHANNEL_DELIVERY','LIFECYCLE_JOB','SECURITY_RECONCILIATION')),
  work_id text NOT NULL CHECK (work_id ~ '^wrk_[A-Za-z0-9_-]+$'),
  state text NOT NULL CHECK (state IN ('PENDING','STARTED','TERMINAL','AMBIGUOUS')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, work_kind, work_id)
);
CREATE TABLE tenant_capacity_reservations (
  organization_id text NOT NULL,
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  reservation_id text NOT NULL CHECK (reservation_id ~ '^res_[A-Za-z0-9_-]+$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  policy_version bigint NOT NULL,
  resource_kind text NOT NULL,
  capacity_binding_epoch bigint NOT NULL CHECK (capacity_binding_epoch > 0),
  capacity_receipt_id text NOT NULL,
  units bigint NOT NULL CHECK (units > 0),
  work_kind text NOT NULL,
  work_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  reservation_token uuid NOT NULL,
  borrowed boolean NOT NULL DEFAULT false,
  capacity_class text NOT NULL CHECK (capacity_class IN ('ORDINARY','CONTROL')),
  status text NOT NULL CHECK (status IN ('HELD','STARTED','SETTLED','RELEASED','EXPIRED','FENCED')),
  acquired_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  terminal_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, reservation_id),
  CONSTRAINT tenant_capacity_reservation_idempotency_uk
    UNIQUE (organization_id, project_id, environment_id, resource_kind, idempotency_key),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  FOREIGN KEY (organization_id, policy_version, resource_kind)
    REFERENCES tenant_quota_limits(organization_id, policy_version, resource_kind),
  FOREIGN KEY (cell_id,resource_kind,capacity_binding_epoch,capacity_receipt_id)
    REFERENCES cell_capacity_bindings(cell_id,resource_kind,binding_epoch,receipt_id),
  FOREIGN KEY (organization_id,project_id,environment_id,work_kind,work_id)
    REFERENCES tenant_work_registry
      (organization_id,project_id,environment_id,work_kind,work_id),
  CHECK (expires_at > acquired_at),
  CHECK ((status IN ('HELD','STARTED')) = (terminal_at IS NULL)),
  CONSTRAINT tenant_capacity_control_reserve_ck CHECK
    (capacity_class <> 'CONTROL' OR
     (resource_kind NOT IN ('CONVERSATION_TURN','AGENT_RUN','MODEL_REQUEST','CONNECTOR_CALL')))
);
CREATE INDEX held_reservations_by_expiry
  ON tenant_capacity_reservations(cell_id, expires_at) WHERE status IN ('HELD','STARTED');
CREATE INDEX reservations_by_work
  ON tenant_capacity_reservations
    (organization_id,project_id,environment_id,work_kind,work_id);

CREATE TABLE tenant_scheduler_lanes (
  organization_id text NOT NULL,
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  weight integer NOT NULL CHECK (weight BETWEEN 1 AND 100),
  deficit bigint NOT NULL DEFAULT 0 CHECK (deficit >= 0),
  active_reservations integer NOT NULL DEFAULT 0 CHECK (active_reservations >= 0),
  scheduler_epoch bigint NOT NULL CHECK (scheduler_epoch > 0),
  next_tenant_sequence bigint NOT NULL DEFAULT 1 CHECK (next_tenant_sequence > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,project_id,environment_id,cell_id),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id)
);
CREATE TABLE tenant_dispatch_queue (
  organization_id text NOT NULL,
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  work_id text NOT NULL CHECK (work_id ~ '^wrk_[A-Za-z0-9_-]+$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  work_kind text NOT NULL CHECK (work_kind IN
    ('CONVERSATION_TURN','AGENT_RUN','CHANNEL_DELIVERY','LIFECYCLE_JOB','SECURITY_RECONCILIATION')),
  work_class text NOT NULL CHECK (work_class IN
    ('CONTROL_RECONCILIATION','SECURITY','RECONCILIATION','DELETION',
     'OPEN_SEVERE','OPEN_OTHER','INTERACTIVE_ASK','BACKGROUND')),
  resource_kind text NOT NULL,
  cost_units integer NOT NULL CHECK (cost_units BETWEEN 1 AND 1000000),
  tenant_sequence bigint NOT NULL CHECK (tenant_sequence > 0),
  state text NOT NULL CHECK (state IN
    ('QUEUED','QUOTA_WAIT','READY','CLAIMED','COMPLETED','CANCELLED','FAILED')),
  available_at timestamptz NOT NULL,
  claim_token uuid,
  lease_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, work_id),
  UNIQUE (organization_id, project_id, environment_id, tenant_sequence),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  FOREIGN KEY (organization_id,project_id,environment_id,work_kind,work_id)
    REFERENCES tenant_work_registry
      (organization_id,project_id,environment_id,work_kind,work_id),
  CHECK ((state = 'CLAIMED') = (claim_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX dispatch_queue_eligible
  ON tenant_dispatch_queue(cell_id, state, organization_id, available_at, tenant_sequence)
  WHERE state IN ('QUEUED','QUOTA_WAIT','READY');
CREATE INDEX dispatch_queue_expired_claims
  ON tenant_dispatch_queue(cell_id, lease_expires_at) WHERE state = 'CLAIMED';

CREATE TABLE usage_events (
  organization_id text NOT NULL,
  event_id text NOT NULL CHECK (event_id ~ '^use_[A-Za-z0-9_-]+$'),
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  resource_kind text NOT NULL,
  units bigint NOT NULL CHECK (units > 0),
  unit_scale text NOT NULL CHECK (unit_scale IN ('UNIT','TOKEN','BYTE','MILLISECOND')),
  source_work_kind text NOT NULL,
  source_work_id text NOT NULL,
  provider_key_hash text CHECK (provider_key_hash IS NULL OR provider_key_hash ~ '^sha256:[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL,
  event_hash text NOT NULL CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id, event_id),
  UNIQUE (organization_id, event_hash),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  FOREIGN KEY (organization_id,project_id,environment_id,source_work_kind,source_work_id)
    REFERENCES tenant_work_registry
      (organization_id,project_id,environment_id,work_kind,work_id)
);
CREATE INDEX usage_events_for_aggregation
  ON usage_events(organization_id, resource_kind, occurred_at);
CREATE INDEX usage_events_by_cell_time
  ON usage_events(cell_id, occurred_at DESC);

CREATE TABLE cell_event_ingress (
  organization_id text NOT NULL,
  project_id text NOT NULL CHECK (project_id ~ '^prj_[a-z0-9_]+$'),
  environment_id text NOT NULL CHECK (environment_id ~ '^env_[a-z0-9_]+$'),
  event_id text NOT NULL CHECK (event_id ~ '^evt_[A-Za-z0-9_-]+$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  event_ref text NOT NULL CHECK (event_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
  sequencing_state text NOT NULL DEFAULT 'UNSEQUENCED' CHECK
    (sequencing_state IN ('UNSEQUENCED','CLAIMED','SEQUENCED','QUARANTINED','SUPERSEDED')),
  claim_token uuid,
  claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
  claim_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  error_ref text CHECK (error_ref IS NULL OR error_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  scope_sequence bigint CHECK (scope_sequence > 0),
  ingress_created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  sequenced_at timestamptz,
  PRIMARY KEY (organization_id, project_id, environment_id, event_id),
  UNIQUE (organization_id, project_id, environment_id, event_hash),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  CHECK ((sequencing_state = 'CLAIMED') = (claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)),
  CHECK ((sequencing_state = 'SEQUENCED') = (scope_sequence IS NOT NULL AND sequenced_at IS NOT NULL)),
  CHECK ((sequencing_state = 'QUARANTINED') = (error_ref IS NOT NULL))
);
CREATE UNIQUE INDEX one_scope_sequence_per_event_scope
  ON cell_event_ingress(organization_id, project_id, environment_id, scope_sequence)
  WHERE scope_sequence IS NOT NULL;
CREATE INDEX unsequenced_events_by_scope
  ON cell_event_ingress(cell_id, organization_id, project_id, environment_id,
                        ingress_created_at, event_id)
  WHERE sequencing_state = 'UNSEQUENCED';
CREATE INDEX expired_event_claims
  ON cell_event_ingress(cell_id, claim_expires_at) WHERE sequencing_state = 'CLAIMED';
CREATE INDEX blocking_poison_events
  ON cell_event_ingress(organization_id, project_id, environment_id, ingress_created_at)
  WHERE sequencing_state = 'QUARANTINED';

CREATE TABLE scope_sequencer_leases (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL,
  next_scope_sequence bigint NOT NULL DEFAULT 1 CHECK (next_scope_sequence > 0),
  lease_token uuid,
  lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
  lease_expires_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL))
);

CREATE TABLE tenant_lifecycle_jobs (
  organization_id text NOT NULL,
  job_id text NOT NULL CHECK (job_id ~ '^job_[A-Za-z0-9_-]+$'),
  job_kind text NOT NULL CHECK (job_kind IN
    ('PROVISION','SUSPEND','RESUME','MOVE','EXPORT','DELETE','RESTORE_TEST')),
  expected_placement_epoch bigint NOT NULL,
  source_cell_id text NOT NULL,
  destination_cell_id text,
  proposed_placement_epoch bigint,
  state text NOT NULL CHECK (state IN
    ('PENDING','QUIESCING','EXPORTING','RESTORING','VERIFYING','CUTOVER_READY',
     'CUTOVER_COMMITTED','COMPLETED','BLOCKED','FAILED','CANCELLED')),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  quiesce_receipt_hash text CHECK (quiesce_receipt_hash IS NULL OR quiesce_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  source_high_water bigint CHECK (source_high_water IS NULL OR source_high_water >= 0),
  export_manifest_hash text CHECK (export_manifest_hash IS NULL OR export_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  destination_verification_hash text CHECK (destination_verification_hash IS NULL OR destination_verification_hash ~ '^sha256:[0-9a-f]{64}$'),
  isolation_verification_hash text CHECK (isolation_verification_hash IS NULL OR isolation_verification_hash ~ '^sha256:[0-9a-f]{64}$'),
  cutover_decision_ref text CHECK (cutover_decision_ref IS NULL OR cutover_decision_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  completion_proof_hash text CHECK (completion_proof_hash IS NULL OR completion_proof_hash ~ '^sha256:[0-9a-f]{64}$'),
  legal_hold_ref text CHECK (legal_hold_ref IS NULL OR legal_hold_ref ~ '^ref_[A-Za-z0-9_-]+$'),
  unsettled_mutation_count integer NOT NULL DEFAULT 0 CHECK (unsettled_mutation_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, job_id),
  FOREIGN KEY (organization_id, expected_placement_epoch, source_cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  CHECK (proposed_placement_epoch IS NULL OR proposed_placement_epoch > expected_placement_epoch),
  CHECK ((state IN ('COMPLETED','CUTOVER_COMMITTED')) = (completed_at IS NOT NULL)),
  CONSTRAINT tenant_lifecycle_delete_completion_ck CHECK
    (job_kind <> 'DELETE' OR state <> 'COMPLETED' OR
     (legal_hold_ref IS NULL AND unsettled_mutation_count = 0 AND completion_proof_hash IS NOT NULL)),
  CHECK (job_kind <> 'MOVE' OR state NOT IN ('CUTOVER_READY','CUTOVER_COMMITTED','COMPLETED') OR
    (destination_cell_id IS NOT NULL AND proposed_placement_epoch IS NOT NULL AND
     quiesce_receipt_hash IS NOT NULL AND source_high_water IS NOT NULL AND
     export_manifest_hash IS NOT NULL AND destination_verification_hash IS NOT NULL AND
     isolation_verification_hash IS NOT NULL))
);
CREATE INDEX lifecycle_jobs_due
  ON tenant_lifecycle_jobs(state, created_at)
  WHERE state NOT IN ('COMPLETED','FAILED','CANCELLED');

CREATE TABLE tenant_lifecycle_job_transitions (
  from_state text NOT NULL,
  to_state text NOT NULL,
  PRIMARY KEY (from_state,to_state),
  CHECK (from_state NOT IN ('COMPLETED','FAILED','CANCELLED'))
);
INSERT INTO tenant_lifecycle_job_transitions(from_state,to_state) VALUES
 ('PENDING','QUIESCING'),('PENDING','BLOCKED'),('PENDING','FAILED'),('PENDING','CANCELLED'),
 ('QUIESCING','EXPORTING'),('QUIESCING','VERIFYING'),('QUIESCING','BLOCKED'),
 ('QUIESCING','FAILED'),('QUIESCING','CANCELLED'),
 ('EXPORTING','RESTORING'),('EXPORTING','VERIFYING'),('EXPORTING','BLOCKED'),('EXPORTING','FAILED'),
 ('RESTORING','VERIFYING'),('RESTORING','BLOCKED'),('RESTORING','FAILED'),
 ('VERIFYING','CUTOVER_READY'),('VERIFYING','COMPLETED'),('VERIFYING','BLOCKED'),('VERIFYING','FAILED'),
 ('CUTOVER_READY','CUTOVER_COMMITTED'),('CUTOVER_READY','BLOCKED'),('CUTOVER_READY','FAILED'),('CUTOVER_READY','CANCELLED'),
 ('CUTOVER_COMMITTED','COMPLETED'),('BLOCKED','PENDING'),('BLOCKED','FAILED'),('BLOCKED','CANCELLED');

-- Append-only target ledgers. Mutable projections/counters/leases are excluded.
CREATE FUNCTION reject_scale_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='immutable scale history'; END $$;
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'routing_grant_audits','tenant_quota_policy_revisions','tenant_quota_policy_bindings',
    'tenant_quota_limits','tenant_location_policies','placement_lifecycle_transitions',
    'cell_capacity_receipts','cell_capacity_bindings','cell_capacity_profiles',
    'cell_service_pool_profiles','tenant_lifecycle_job_transitions',
    'scale_database_privilege_manifest','usage_events','cell_eligibility_profiles',
    'tenant_eligibility_requirements'
  ] LOOP
    EXECUTE format('CREATE TRIGGER %I_immutable BEFORE UPDATE OR DELETE ON %I '
                   'FOR EACH ROW EXECUTE FUNCTION reject_scale_history_mutation()',
                   table_name, table_name);
  END LOOP;
END $$;

CREATE FUNCTION enforce_placement_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=solvan_scale,pg_temp AS $$
DECLARE
  profile text;
  region_value text;
  occupancy integer;
  eligible_classifications text[];
  eligible_regions text[];
  eligible_launch_stages text[];
  cell_encryption_profile_hash text;
  cell_support_access_allowed boolean;
  eligible_recovery_regions text[];
  tenant_classifications text[];
  tenant_regions text[];
  tenant_launch_stages text[];
  tenant_encryption_profile_hash text;
  tenant_support_access_allowed boolean;
  tenant_recovery_regions text[];
BEGIN
  -- Every insert and every change to the current projection serializes per
  -- organization. Without this lock an older, already-present epoch could be
  -- reactivated after a newer epoch had been created.
  PERFORM pg_advisory_xact_lock(193714, hashtext(NEW.organization_id));
  IF TG_OP = 'UPDATE' THEN
    IF OLD.organization_id <> NEW.organization_id OR OLD.placement_epoch <> NEW.placement_epoch OR
       OLD.cell_id <> NEW.cell_id OR OLD.isolation_tier <> NEW.isolation_tier OR
       OLD.home_region <> NEW.home_region OR
       OLD.eligibility_requirement_hash <> NEW.eligibility_requirement_hash THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable placement identity';
    END IF;
    IF OLD.lifecycle = 'DELETED' AND NEW.lifecycle <> 'DELETED' THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='deleted placement is terminal';
    END IF;
    IF OLD.lifecycle <> NEW.lifecycle AND NOT EXISTS (
      SELECT 1 FROM placement_lifecycle_transitions transition
       WHERE transition.from_state=OLD.lifecycle AND transition.to_state=NEW.lifecycle
    ) THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='undeclared placement lifecycle transition';
    END IF;
  ELSE
    IF EXISTS (SELECT 1 FROM tenant_placements p WHERE p.organization_id=NEW.organization_id
               AND p.placement_epoch >= NEW.placement_epoch) THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='placement epoch must increase';
    END IF;
  END IF;
  IF NEW.is_current THEN
    IF EXISTS (
      SELECT 1 FROM tenant_placements p
       WHERE p.organization_id=NEW.organization_id
         AND p.placement_epoch > NEW.placement_epoch
    ) THEN
      RAISE EXCEPTION USING ERRCODE='23514',
        MESSAGE='only the highest placement epoch may be current';
    END IF;
    PERFORM pg_advisory_xact_lock(193715, hashtext(NEW.cell_id));
    SELECT c.deployment_profile,c.region,c.max_organizations,
           e.allowed_classifications,e.allowed_residency_regions,
           e.allowed_provider_launch_stages,e.encryption_profile_hash,
           e.support_access_allowed,e.allowed_recovery_regions,
           t.allowed_classifications,t.allowed_residency_regions,
           t.allowed_provider_launch_stages,t.encryption_profile_hash,
           t.support_access_allowed,t.allowed_recovery_regions
      INTO profile,region_value,occupancy,eligible_classifications,eligible_regions,
           eligible_launch_stages,cell_encryption_profile_hash,
           cell_support_access_allowed,eligible_recovery_regions,
           tenant_classifications,tenant_regions,tenant_launch_stages,
           tenant_encryption_profile_hash,tenant_support_access_allowed,
           tenant_recovery_regions
      FROM cells c
      JOIN cell_eligibility_profiles e
        ON e.eligibility_profile_hash=c.eligibility_profile_hash
      JOIN tenant_eligibility_requirements t
        ON t.organization_id=NEW.organization_id
       AND t.requirement_hash=NEW.eligibility_requirement_hash
     WHERE c.cell_id=NEW.cell_id;
    IF profile IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='placement eligibility operands unavailable';
    END IF;
    IF profile <> NEW.isolation_tier OR region_value <> NEW.home_region THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='placement does not match cell';
    END IF;
    IF NOT (NEW.classification_ceiling = ANY(eligible_classifications)) OR
       NOT (NEW.classification_ceiling = ANY(tenant_classifications)) OR
       NOT (NEW.home_region = ANY(eligible_regions)) OR
       NOT (NEW.home_region = ANY(tenant_regions)) OR
       NOT (eligible_launch_stages <@ tenant_launch_stages) OR
       cell_encryption_profile_hash <> tenant_encryption_profile_hash OR
       NEW.encryption_profile_hash <> tenant_encryption_profile_hash OR
       (cell_support_access_allowed AND NOT tenant_support_access_allowed) OR
       NOT (eligible_recovery_regions <@ tenant_recovery_regions) THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='placement is ineligible for cell profile';
    END IF;
    IF (SELECT count(*) FROM tenant_placements p WHERE p.cell_id=NEW.cell_id AND p.is_current
        AND p.organization_id<>NEW.organization_id) >= occupancy THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='cell occupancy exceeded';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER enforce_placement BEFORE INSERT OR UPDATE ON tenant_placements
FOR EACH ROW EXECUTE FUNCTION enforce_placement_change();
REVOKE ALL ON FUNCTION enforce_placement_change() FROM PUBLIC;

CREATE FUNCTION enforce_monotonic_binding_epoch() RETURNS trigger
LANGUAGE plpgsql SET search_path=solvan_scale,pg_temp AS $$
DECLARE latest bigint;
BEGIN
  IF TG_TABLE_NAME = 'tenant_quota_policy_bindings' THEN
    PERFORM pg_advisory_xact_lock(193716, hashtext(NEW.organization_id));
    SELECT max(binding_epoch) INTO latest FROM tenant_quota_policy_bindings
      WHERE organization_id=NEW.organization_id;
  ELSE
    PERFORM pg_advisory_xact_lock(193717, hashtext(NEW.cell_id || ':' || NEW.resource_kind));
    SELECT max(binding_epoch) INTO latest FROM cell_capacity_bindings
      WHERE cell_id=NEW.cell_id AND resource_kind=NEW.resource_kind;
  END IF;
  IF latest IS NOT NULL AND NEW.binding_epoch <= latest THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='binding epoch must increase';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER quota_binding_epoch_monotonic BEFORE INSERT ON tenant_quota_policy_bindings
FOR EACH ROW EXECUTE FUNCTION enforce_monotonic_binding_epoch();
CREATE TRIGGER capacity_binding_epoch_monotonic BEFORE INSERT ON cell_capacity_bindings
FOR EACH ROW EXECUTE FUNCTION enforce_monotonic_binding_epoch();

CREATE FUNCTION enforce_lifecycle_job_terminality() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP = 'DELETE' OR OLD.state IN ('COMPLETED','FAILED','CANCELLED') THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='terminal lifecycle job is immutable';
  END IF;
  IF OLD.job_kind = 'MOVE' AND NEW.state = 'COMPLETED' AND OLD.state <> 'CUTOVER_COMMITTED' THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='move completion requires the committed cutover';
  END IF;
  IF OLD.state <> NEW.state AND NOT EXISTS (
    SELECT 1 FROM tenant_lifecycle_job_transitions transition
     WHERE transition.from_state=OLD.state AND transition.to_state=NEW.state
  ) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='undeclared lifecycle job transition';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER lifecycle_job_terminality BEFORE UPDATE OR DELETE ON tenant_lifecycle_jobs
FOR EACH ROW EXECUTE FUNCTION enforce_lifecycle_job_terminality();

CREATE FUNCTION forbid_scope_sequence_decrease() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.next_scope_sequence < OLD.next_scope_sequence THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='scope sequence cannot decrease';
  END IF; RETURN NEW;
END $$;
CREATE TRIGGER scope_sequence_monotonic BEFORE UPDATE ON scope_sequencer_leases
FOR EACH ROW EXECUTE FUNCTION forbid_scope_sequence_decrease();

-- A cursor is a content-free, reader-bound projection of authoritative SQL
-- order.  It is deliberately separate from the wake-up channel: Pub/Sub
-- delivery order and a cursor record can never become workflow authority.
CREATE TABLE scope_event_cursors (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  cursor_id text NOT NULL CHECK (cursor_id ~ '^cur_[A-Za-z0-9_-]+$'),
  reader_key_hash text NOT NULL CHECK (reader_key_hash ~ '^sha256:[0-9a-f]{64}$'),
  cell_id text NOT NULL,
  placement_epoch bigint NOT NULL CHECK (placement_epoch > 0),
  scope_sequence bigint NOT NULL DEFAULT 0 CHECK (scope_sequence >= 0),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  membership_epoch bigint NOT NULL CHECK (membership_epoch > 0),
  cursor_schema_version integer NOT NULL DEFAULT 1 CHECK (cursor_schema_version = 1),
  state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE','RECOVERY_REQUIRED')),
  invalidated_reason text,
  recovery_receipt_hash text CHECK
    (recovery_receipt_hash IS NULL OR recovery_receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, cursor_id),
  UNIQUE (organization_id, project_id, environment_id, reader_key_hash),
  FOREIGN KEY (organization_id, placement_epoch, cell_id)
    REFERENCES tenant_placements(organization_id, placement_epoch, cell_id),
  CHECK ((state = 'RECOVERY_REQUIRED') = (invalidated_reason IS NOT NULL)),
  CHECK (state <> 'ACTIVE' OR invalidated_reason IS NULL)
);
CREATE INDEX scope_event_cursors_by_scope
  ON scope_event_cursors(organization_id, project_id, environment_id, state, updated_at);

CREATE FUNCTION recover_scope_event_cursor(
  p_organization_id text,
  p_project_id text,
  p_environment_id text,
  p_cursor_id text,
  p_reader_key_hash text,
  p_cell_id text,
  p_placement_epoch bigint,
  p_policy_epoch bigint,
  p_membership_epoch bigint,
  p_scope_sequence bigint,
  p_recovery_receipt_hash text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=solvan_scale,pg_temp AS $$
DECLARE
  current_high_water bigint;
BEGIN
  IF p_scope_sequence < 0 OR p_recovery_receipt_hash !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='cursor recovery operands are invalid';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM tenant_placements
     WHERE organization_id=p_organization_id
       AND placement_epoch=p_placement_epoch
       AND cell_id=p_cell_id
       AND is_current AND lifecycle='ACTIVE'
     FOR SHARE
  ) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='cursor recovery placement is not current';
  END IF;
  SELECT COALESCE(max(scope_sequence),0) INTO current_high_water
    FROM cell_event_ingress
   WHERE organization_id=p_organization_id AND project_id=p_project_id
     AND environment_id=p_environment_id AND sequencing_state='SEQUENCED';
  IF p_scope_sequence > current_high_water THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='cursor recovery high-water exceeds feed';
  END IF;
  INSERT INTO scope_event_cursors
    (organization_id,project_id,environment_id,cursor_id,reader_key_hash,cell_id,
     placement_epoch,scope_sequence,policy_epoch,membership_epoch,state,
     invalidated_reason,recovery_receipt_hash,updated_at)
  VALUES
    (p_organization_id,p_project_id,p_environment_id,p_cursor_id,p_reader_key_hash,p_cell_id,
     p_placement_epoch,p_scope_sequence,p_policy_epoch,p_membership_epoch,'ACTIVE',NULL,
     p_recovery_receipt_hash,clock_timestamp())
  ON CONFLICT (organization_id,project_id,environment_id,reader_key_hash) DO UPDATE
    SET cursor_id=EXCLUDED.cursor_id, cell_id=EXCLUDED.cell_id,
        placement_epoch=EXCLUDED.placement_epoch, scope_sequence=EXCLUDED.scope_sequence,
        policy_epoch=EXCLUDED.policy_epoch, membership_epoch=EXCLUDED.membership_epoch,
        state='ACTIVE', invalidated_reason=NULL,
        recovery_receipt_hash=EXCLUDED.recovery_receipt_hash, updated_at=clock_timestamp();
  RETURN p_cursor_id;
END $$;
REVOKE ALL ON FUNCTION recover_scope_event_cursor(
  text,text,text,text,text,text,bigint,bigint,bigint,bigint,text) FROM PUBLIC;

CREATE FUNCTION advance_scope_event_cursor(
  p_organization_id text,
  p_project_id text,
  p_environment_id text,
  p_cursor_id text,
  p_expected_sequence bigint,
  p_next_sequence bigint
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=solvan_scale,pg_temp AS $$
DECLARE
  cursor_row scope_event_cursors%ROWTYPE;
BEGIN
  IF p_next_sequence <= p_expected_sequence THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='cursor sequence must increase';
  END IF;
  SELECT * INTO cursor_row FROM scope_event_cursors
   WHERE organization_id=p_organization_id AND project_id=p_project_id
     AND environment_id=p_environment_id AND cursor_id=p_cursor_id
   FOR UPDATE;
  IF NOT FOUND OR cursor_row.state <> 'ACTIVE' OR
     cursor_row.scope_sequence <> p_expected_sequence THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='cursor is stale or requires recovery';
  END IF;
  IF EXISTS (
    SELECT 1 FROM cell_event_ingress
     WHERE organization_id=p_organization_id AND project_id=p_project_id
       AND environment_id=p_environment_id AND sequencing_state='QUARANTINED'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='quarantined event blocks cursor advancement';
  END IF;
  IF EXISTS (
    SELECT 1 FROM cell_event_ingress
     WHERE organization_id=p_organization_id AND project_id=p_project_id
       AND environment_id=p_environment_id AND scope_sequence > p_expected_sequence
       AND scope_sequence <= p_next_sequence AND sequencing_state <> 'SEQUENCED'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='cursor range contains an unsequenced event';
  END IF;
  UPDATE scope_event_cursors SET scope_sequence=p_next_sequence, updated_at=clock_timestamp()
   WHERE organization_id=p_organization_id AND project_id=p_project_id
     AND environment_id=p_environment_id AND cursor_id=p_cursor_id;
  RETURN p_cursor_id;
END $$;
REVOKE ALL ON FUNCTION advance_scope_event_cursor(text,text,text,text,bigint,bigint) FROM PUBLIC;

CREATE FUNCTION invalidate_obsolete_scope_event_cursors() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=solvan_scale,pg_temp AS $$
BEGIN
  IF NEW.is_current THEN
    UPDATE scope_event_cursors
       SET state='RECOVERY_REQUIRED', invalidated_reason='PLACEMENT_EPOCH_CHANGED',
           updated_at=clock_timestamp()
     WHERE organization_id=NEW.organization_id
       AND state='ACTIVE'
       AND (placement_epoch <> NEW.placement_epoch OR cell_id <> NEW.cell_id);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER invalidate_obsolete_cursors
AFTER INSERT OR UPDATE OF is_current, lifecycle, placement_epoch, cell_id ON tenant_placements
FOR EACH ROW EXECUTE FUNCTION invalidate_obsolete_scope_event_cursors();
REVOKE ALL ON FUNCTION invalidate_obsolete_scope_event_cursors() FROM PUBLIC;

-- Shared-cell RLS covers every reader-visible or dispatchable tenant
-- operational row. Organization-wide lifecycle/placement policy is
-- content-free control-plane state and is reachable only through typed
-- lifecycle procedures; cell-wide capacity/catalog rows are never granted to
-- tenant roles. Profile-specific migrations retain this exact policy for OSS
-- and dedicated deployments rather than weakening it.
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'tenant_work_registry','tenant_capacity_reservations','tenant_scheduler_lanes',
    'tenant_dispatch_queue','usage_events','cell_event_ingress','scope_event_cursors'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY exact_scope_isolation ON %I USING '
      '(scope_permitted(organization_id, project_id, environment_id)) WITH CHECK '
      '(scope_permitted(organization_id, project_id, environment_id))', table_name);
  END LOOP;
END $$;

REVOKE ALL ON SCHEMA solvan_scale FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA solvan_scale FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA solvan_scale FROM PUBLIC;

COMMIT;
