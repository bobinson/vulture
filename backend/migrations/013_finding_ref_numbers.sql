-- Feature 0033: human-readable finding reference numbers
ALTER TABLE finding_lineage ADD COLUMN ref_number INTEGER;

-- Backfill: assign ref_numbers to existing records by creation order
UPDATE finding_lineage SET ref_number = sub.rn
FROM (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) AS rn
    FROM finding_lineage
) sub
WHERE finding_lineage.id = sub.id;
