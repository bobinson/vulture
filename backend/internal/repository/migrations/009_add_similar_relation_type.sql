-- Add 'similar' to the relation_type check constraint on memory_edges.
-- The inferRelationType() function returns 'similar' as a fallback when
-- neither finding_type nor category match between two memories.
--
-- Idempotent: drops the constraint only if it exists, then re-adds the
-- updated form. Safe to re-run after the constraint is already updated —
-- it'll drop the new version and re-add an identical new version.

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'memory_edges_relation_type_check'
    ) THEN
        ALTER TABLE memory_edges DROP CONSTRAINT memory_edges_relation_type_check;
    END IF;
END $$;

ALTER TABLE memory_edges ADD CONSTRAINT memory_edges_relation_type_check
    CHECK (relation_type IN (
        'same_issue', 'supersedes', 'derived_from', 'contradicts',
        'remediated_by', 'related_compliance', 'escalates_to', 'similar'
    ));
