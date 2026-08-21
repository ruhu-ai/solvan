-- Target delta for specification 13 §4.1 and §4.2.
--
-- This file is not release schema.sql. It lives in its own schema because the
-- release schema is fixed at 61 tables and target work never enlarges it. Every
-- reference into `solvan` is qualified: this delta reads the release schema and
-- never modifies it.
CREATE SCHEMA IF NOT EXISTS solvan_onboarding;
SET search_path TO solvan_onboarding, solvan, public;

BEGIN;

-- §4.1: one connection names exactly one external resource scope at one
-- hierarchy level.
CREATE TABLE connection_external_resource_scopes (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  connection_id text NOT NULL,
  resource_kind text NOT NULL CHECK
    (resource_kind IN ('GCP_PROJECT','GCP_FOLDER','GCP_ORGANIZATION')),
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 160),
  metrics_scoping_project_id text,
  authored_by_principal text NOT NULL,
  decision_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, connection_id),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES solvan.tenant_connections
      (organization_id, project_id, environment_id, id),
  -- §4.1: reach above one project comes from a configured metrics scope, so a
  -- folder or organization scope must name one and a project scope must not.
  CHECK ((resource_kind = 'GCP_PROJECT') = (metrics_scoping_project_id IS NULL)),
  CHECK (metrics_scoping_project_id IS NULL OR
         metrics_scoping_project_id ~ '^[a-z][a-z0-9-]{4,61}$')
);

-- §4.3: environment authorization. "This external project belongs to this
-- environment" is authored once and is authority. It carries no connection:
-- §4.1 makes coverage a property of the capability, so a logging connection and
-- a monitoring connection covering one project is the ordinary case, and keying
-- authority by connection would make them compete for it.
--
-- Rebinding is a new generation rather than an edit, so many rows may name one
-- external project and exactly one of them is current.
CREATE TABLE environment_external_project_bindings (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  external_project_id text NOT NULL CHECK
    (external_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  binding_epoch bigint NOT NULL CHECK (binding_epoch > 0),
  deciding_principal text NOT NULL,
  decision_ref text NOT NULL,
  is_current boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id,
               external_project_id, binding_epoch),
  FOREIGN KEY (organization_id, project_id, environment_id)
    REFERENCES solvan.environments (organization_id, project_id, id)
);

-- §4.3: one external project holds at most one current binding per
-- organization. The same Google Cloud project in two blast-radius environments
-- would need resource-level isolation that project-wide Logging and Monitoring
-- APIs cannot provide.
CREATE UNIQUE INDEX one_current_external_project_binding
  ON environment_external_project_bindings
    (organization_id, external_project_id)
  WHERE is_current;

-- §4.3: connection coverage. "This connection can read this external project
-- for this capability class" is observed per probe and is reach, never
-- authority. Recorded per capability because §4.1's whole point is that one
-- connection answers differently for logs and for metrics.
CREATE TABLE connection_external_project_coverage (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  connection_id text NOT NULL,
  capability_class text NOT NULL CHECK (capability_class IN
    ('LOG_SEARCH','METRIC_READ','PROMQL_READ','AUDIT_LOG_READ','TRACE_READ',
     'ERROR_GROUP_READ','ASSET_SEARCH','RESOURCE_ADMIN_READ',
     'RESOURCE_METADATA_READ','KUBERNETES_METADATA_READ')),
  external_project_id text NOT NULL CHECK
    (external_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
  observed_at timestamptz NOT NULL,
  probe_receipt_ref text NOT NULL,
  PRIMARY KEY (organization_id, project_id, environment_id, connection_id,
               capability_class, external_project_id, connection_epoch),
  FOREIGN KEY (organization_id, project_id, environment_id, connection_id)
    REFERENCES solvan.tenant_connections
      (organization_id, project_id, environment_id, id)
);

-- §4.2: attribution observed from the provider, checked against the project the
-- environment currently authorizes.
--
-- Nothing is added to `incidents`. The incident already pins a graph snapshot,
-- and under §4.2 the declared location of a read is the selected graph node's
-- `external_project_id` inside that snapshot. A copy on the incident would be a
-- second source of truth for one fact, and the two would diverge.
--
-- This table carries the observation. On promotion it collapses into a column
-- on `evidence_items`.
CREATE TABLE evidence_resource_attribution (
  organization_id text NOT NULL,
  project_id text NOT NULL,
  environment_id text NOT NULL,
  evidence_item_id text NOT NULL,
  observed_project_id text NOT NULL CHECK
    (observed_project_id ~ '^[a-z][a-z0-9-]{4,61}$'),
  observed_resource_type text NOT NULL,
  -- Every other observed label, under the provider's own names, because a
  -- citation must reproduce what the provider returned. Never interpreted.
  observed_labels_json jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(observed_labels_json) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, project_id, environment_id, evidence_item_id),
  FOREIGN KEY (organization_id, project_id, environment_id, evidence_item_id)
    REFERENCES solvan.evidence_items
      (organization_id, project_id, environment_id, id)
);

-- SQLSTATE 23901 is Solvan's code for evidence whose observed origin is not
-- authorized for its environment. This cannot be a foreign key: §4.3 makes
-- rebinding a new generation, so the binding table holds many rows per external
-- project and only one is current. A key would either forbid generations or
-- accept a superseded one.
--
-- This enforces limb 2 of §4.2's four-way agreement — environment
-- authorization. Limb 1 (the frozen graph node) and limb 3 (connection
-- capability coverage) are checked at read time against the pinned snapshot and
-- the connection epoch, neither of which is reachable from this row.
CREATE FUNCTION evidence_project_is_authorized() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM environment_external_project_bindings b
   WHERE (b.organization_id, b.project_id, b.environment_id, b.external_project_id)
       = (NEW.organization_id, NEW.project_id, NEW.environment_id,
          NEW.observed_project_id)
     AND b.is_current;
  IF NOT FOUND THEN
    RAISE EXCEPTION
      'evidence observed Google Cloud project % which this environment does not '
      'currently authorize', NEW.observed_project_id USING ERRCODE = '23901';
  END IF;
  RETURN NEW;
END $$;

-- AFTER, so the column CHECKs are evaluated first. A BEFORE trigger preempts
-- them, and a malformed project id would then refuse as an authorization
-- failure — one rule reporting another's violation.
CREATE CONSTRAINT TRIGGER evidence_project_is_authorized
  AFTER INSERT OR UPDATE ON evidence_resource_attribution
  FOR EACH ROW EXECUTE FUNCTION evidence_project_is_authorized();

ALTER TABLE connection_external_resource_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_external_resource_scopes FORCE ROW LEVEL SECURITY;
ALTER TABLE environment_external_project_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE environment_external_project_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE connection_external_project_coverage ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_external_project_coverage FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_resource_attribution ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_resource_attribution FORCE ROW LEVEL SECURITY;

CREATE POLICY connection_scope_isolation ON connection_external_resource_scopes
  USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))
  WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id));
CREATE POLICY environment_binding_scope_isolation ON environment_external_project_bindings
  USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))
  WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id));
CREATE POLICY connection_coverage_scope_isolation ON connection_external_project_coverage
  USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))
  WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id));
CREATE POLICY evidence_attribution_scope_isolation ON evidence_resource_attribution
  USING (solvan.scope_permitted(current_user, organization_id, project_id, environment_id))
  WITH CHECK (solvan.scope_permitted(current_user, organization_id, project_id, environment_id));

COMMIT;
