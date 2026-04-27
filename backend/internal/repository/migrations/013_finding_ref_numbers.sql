-- Feature 0033: human-readable finding reference numbers
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS ref_number INTEGER;

-- Backfill: assign ref_numbers to existing records by creation order.
-- The `WHERE ... ref_number IS NULL` guard makes the UPDATE a no-op on
-- subsequent runs (idempotent), and preserves any operator-set values.
UPDATE finding_lineage SET ref_number = sub.rn
FROM (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) AS rn
    FROM finding_lineage
    WHERE ref_number IS NULL
) sub
WHERE finding_lineage.id = sub.id AND finding_lineage.ref_number IS NULL;
