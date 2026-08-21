-- Governed Tool Catalog: immutable revisions at the database, not just the store.
--
-- The application never UPDATEs or DELETEs these five tables, so the only
-- writes a refuse trigger can ever meet are out-of-band ones: a principal
-- with direct SQL access retiring a revision back to APPROVED or rewriting
-- published content in place. Until now nothing stopped that at the database,
-- where "immutable Tool Catalog" is the stated contract. The binding tables
-- already refuse; the catalog they bind against now does too.

CREATE TRIGGER tool_revision_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.tool_revisions
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();

CREATE TRIGGER tool_profile_revision_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.tool_profile_revisions
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();

CREATE TRIGGER tool_profile_member_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.tool_profile_members
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();

CREATE TRIGGER tool_profile_connection_requirement_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.tool_profile_connection_requirements
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();

CREATE TRIGGER tool_probe_receipt_immutable
BEFORE UPDATE OR DELETE ON solvan_operability.tool_probe_receipts
FOR EACH ROW
EXECUTE FUNCTION solvan_operability.refuse_frozen_operability_history_mutation();
