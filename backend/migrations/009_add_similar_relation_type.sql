-- Add 'similar' to the relation_type check constraint on memory_edges.
-- The inferRelationType() function returns 'similar' as a fallback when
-- neither finding_type nor category match between two memories.

ALTER TABLE memory_edges DROP CONSTRAINT memory_edges_relation_type_check;

ALTER TABLE memory_edges ADD CONSTRAINT memory_edges_relation_type_check
    CHECK (relation_type IN (
        'same_issue', 'supersedes', 'derived_from', 'contradicts',
        'remediated_by', 'related_compliance', 'escalates_to', 'similar'
    ));
