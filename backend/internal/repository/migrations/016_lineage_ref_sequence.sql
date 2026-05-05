-- Migration 016: Fix lineage ref_number race via dedicated sequence.
--
-- finding_lineage.ref_number was assigned application-side via
-- `SELECT COALESCE(MAX(ref_number), 0) + 1` inside a default-isolation
-- transaction. Two concurrent UpsertLineage calls with distinct
-- fingerprints could both read MAX=100 and both INSERT 101, producing
-- duplicate ref_numbers (the unique constraint is only on
-- fingerprint/source_path/agent_type, not on ref_number).
--
-- Fix: drive ref_number off a dedicated sequence so concurrent writers
-- get distinct values atomically. The Go side switches to
-- INSERT ... RETURNING ref_number so the server tells us what was
-- assigned (handles both the new-row and ON-CONFLICT branches).
--
-- Sequence values may have gaps when ON CONFLICT triggers the update
-- branch (the sequence increments but the value is unused) — that's
-- expected and harmless: ref_numbers stay unique and monotonically
-- increasing, with occasional gaps.

CREATE SEQUENCE IF NOT EXISTS finding_lineage_ref_seq;

-- Pin the sequence to the highest existing ref_number so newly assigned
-- values don't collide with rows backfilled by migration 013. Skip on
-- an empty table — sequences default to start=1 so the first nextval()
-- already returns 1, and setval() rejects values below MINVALUE (1).
DO $$
DECLARE
    max_ref INTEGER;
BEGIN
    SELECT MAX(ref_number) INTO max_ref FROM finding_lineage;
    IF max_ref IS NOT NULL AND max_ref > 0 THEN
        PERFORM setval('finding_lineage_ref_seq', max_ref, true);
    END IF;
END $$;

-- New rows get a sequence value automatically; existing rows already have
-- backfilled values from migration 013, so ALTER ... SET DEFAULT is safe.
ALTER TABLE finding_lineage
    ALTER COLUMN ref_number SET DEFAULT nextval('finding_lineage_ref_seq');

-- Tighten to NOT NULL only if every row has a value (backfill complete).
-- Skipping the constraint if any rows are still NULL keeps the migration
-- safe to apply on a partially-backfilled DB.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM finding_lineage WHERE ref_number IS NULL) THEN
        BEGIN
            ALTER TABLE finding_lineage ALTER COLUMN ref_number SET NOT NULL;
        EXCEPTION WHEN others THEN
            -- Already NOT NULL or another constraint conflict; tolerate.
            RAISE NOTICE 'Skipping NOT NULL on ref_number: %', SQLERRM;
        END;
    END IF;
END $$;
