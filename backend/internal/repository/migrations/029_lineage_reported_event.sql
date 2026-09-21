-- Migration 029 (feature 0091): admit the `reported` lineage event.
--
-- The closure pass records what each scan OBSERVED about every known row as a
-- lineage event — out_of_scope, scope_unknown, skipped_degraded,
-- confirmed_by_evidence, absent_in_result — and the aggregate report labels
-- each row with the newest of them. The one observation that never wrote an
-- event was a plain re-find: the scan reported the finding again, seen_count
-- went up, and the timeline stayed silent. So the newest event on a re-found
-- row was whatever the PREVIOUS scan had said, and the report showed
-- "Outside the scan's scope" under a "last seen: today" that contradicted it.
--
-- scanPass.markSeen now writes `reported`. This file lets the database accept
-- it: `lineage_events.event_type` is bounded by a CHECK written in 004 and
-- widened in 027, and a value outside it is not a degraded label — it is a
-- rejected INSERT on every re-find of every row.
--
-- Same shape as 027 step 2: drop-if-exists then add-if-absent, both probes
-- scoped with `conrelid = 'lineage_events'::regclass` so a same-named
-- constraint in another schema cannot satisfy the guard and leave the table
-- with no CHECK at all. SQLite needs nothing here — its inline schema never
-- constrained event_type.
DO $$ BEGIN
    ALTER TABLE lineage_events DROP CONSTRAINT IF EXISTS lineage_events_event_type_check;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'lineage_events_event_type_check'
           AND conrelid = 'lineage_events'::regclass
    ) THEN
        ALTER TABLE lineage_events ADD CONSTRAINT lineage_events_event_type_check
            CHECK (event_type IN (
                'detected','status_change','fixed','regression','note_added',
                'confirmed_by_evidence','evidence_gone','unconfirmable',
                'skipped_degraded','out_of_scope','absent_in_result',
                'scope_unknown','memory_synced','merged','reported'
            ));
    END IF;
END $$;
