-- Catalog principals and Tool definitions become versioned revisions with a
-- current head, the shape `tool_revisions` and `tool_profile_revisions` have.
--
-- Both were immutable rows keyed only by their business key, so the only
-- material either could ever hold was the material of its first publication.
-- The store correctly refuses to rewrite one, which left no way to publish a
-- changed agent manifest at all: `release_admin publish-catalog` derives
-- `manifest_hash` from the agent manifest file, so the first release that
-- edited a manifest raised `a catalog principal key already has different
-- immutable material` and rolled the entire catalog transaction back. On a
-- development host that looks like "recreate the database"; against Cloud SQL
-- there is nothing to recreate and the release simply cannot publish.
--
-- Immutability without versioning is a one-shot write rather than a history.
-- Publication now adds a superseding revision and moves a head, which is what
-- the change discipline requires of every other governed record.

BEGIN;

CREATE TABLE solvan_operability.catalog_principal_revisions (
  principal_key text NOT NULL CHECK
    (principal_key ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  version bigint NOT NULL CHECK (version > 0),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  registry_kind text NOT NULL CHECK
    (registry_kind IN ('AGENT','DETERMINISTIC_SERVICE')),
  execution_role text NOT NULL CHECK
    (execution_role IN ('SUPERVISOR','SPECIALIST','WORKSPACE',
                        'WORKSPACE_PROVIDER','SERVICE')),
  model_backed boolean NOT NULL,
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  published_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_key, version),
  -- The head references a whole published tuple, so it cannot name material
  -- that was never published.
  UNIQUE (principal_key, version, display_name, registry_kind, execution_role,
          model_backed, manifest_hash),
  -- One version per distinct material. Republishing an unchanged catalog
  -- resolves to the revision that already exists instead of minting a new one,
  -- so publication is idempotent in the database rather than by convention.
  UNIQUE (principal_key, display_name, registry_kind, execution_role,
          model_backed, manifest_hash),
  CHECK (model_backed = (registry_kind = 'AGENT')),
  CHECK ((model_backed AND execution_role <> 'SERVICE') OR
         (NOT model_backed AND execution_role = 'SERVICE'))
);

CREATE TABLE solvan_operability.tool_definition_revisions (
  tool_key text NOT NULL CHECK (tool_key ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'),
  version bigint NOT NULL CHECK (version > 0),
  display_name text NOT NULL,
  owner_department text NOT NULL,
  published_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tool_key, version),
  UNIQUE (tool_key, version, display_name, owner_department),
  UNIQUE (tool_key, display_name, owner_department)
);

-- Every already-published row becomes version 1 of its own history, so an
-- existing deployment migrates without losing or restating what it published.
INSERT INTO solvan_operability.catalog_principal_revisions
  (principal_key,version,display_name,registry_kind,execution_role,
   model_backed,manifest_hash,published_at)
SELECT principal_key,1,display_name,registry_kind,execution_role,
       model_backed,manifest_hash,created_at
  FROM solvan_operability.catalog_principals;

INSERT INTO solvan_operability.tool_definition_revisions
  (tool_key,version,display_name,owner_department,published_at)
SELECT tool_key,1,display_name,owner_department,created_at
  FROM solvan_operability.tool_definitions;

-- The head carries which revision is current and an epoch that counts every
-- move, so a head change is observable and can be fenced.
ALTER TABLE solvan_operability.catalog_principals
  ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN head_epoch bigint NOT NULL DEFAULT 1 CHECK (head_epoch > 0);

ALTER TABLE solvan_operability.catalog_principals
  ADD CONSTRAINT catalog_principals_revision_fk
  FOREIGN KEY (principal_key,version,display_name,registry_kind,
               execution_role,model_backed,manifest_hash)
  REFERENCES solvan_operability.catalog_principal_revisions
    (principal_key,version,display_name,registry_kind,execution_role,
     model_backed,manifest_hash);

ALTER TABLE solvan_operability.tool_definitions
  ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN head_epoch bigint NOT NULL DEFAULT 1 CHECK (head_epoch > 0);

ALTER TABLE solvan_operability.tool_definitions
  ADD CONSTRAINT tool_definitions_revision_fk
  FOREIGN KEY (tool_key,version,display_name,owner_department)
  REFERENCES solvan_operability.tool_definition_revisions
    (tool_key,version,display_name,owner_department);

CREATE TRIGGER catalog_principal_revision_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.catalog_principal_revisions
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();

CREATE TRIGGER tool_definition_revision_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.tool_definition_revisions
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();

-- A head may be repointed at any published revision, including an earlier one:
-- rolling a release back is a legitimate head move and the history it moves
-- across stays intact. What a head may never do is rename its own key, vanish,
-- or move without advancing its epoch.
CREATE FUNCTION solvan_operability.guard_catalog_head_move() RETURNS trigger
LANGUAGE plpgsql
SET search_path = solvan_operability, pg_temp
AS $catalog_head_move$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = '23964',
      MESSAGE = format('%s is a current head and cannot be deleted', TG_TABLE_NAME);
  END IF;
  IF NEW.head_epoch <> OLD.head_epoch + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23965',
      MESSAGE = format('%s head moved without advancing its epoch exactly once',
                       TG_TABLE_NAME);
  END IF;
  RETURN NEW;
END
$catalog_head_move$;

CREATE TRIGGER catalog_principal_head_move
BEFORE UPDATE OR DELETE ON solvan_operability.catalog_principals
FOR EACH ROW EXECUTE FUNCTION solvan_operability.guard_catalog_head_move();

CREATE TRIGGER tool_definition_head_move
BEFORE UPDATE OR DELETE ON solvan_operability.tool_definitions
FOR EACH ROW EXECUTE FUNCTION solvan_operability.guard_catalog_head_move();

COMMIT;
