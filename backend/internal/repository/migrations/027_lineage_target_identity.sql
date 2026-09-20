-- Migration 027 (feature 0091): target identity and evidence columns on
-- finding_lineage, plus the CHECK-constraint widening that makes the new
-- status and the new events writable at all.
--
-- SCOPE. This file is steps 1-2 of the six-step plan. The backfills
-- (fingerprint_v2, target_key), the duplicate merge and the two new indexes
-- are step 3-6 and land with the target-identity phase. Splitting them is
-- deliberate: steps 1-2 are pure additions that no running code depends on
-- until it opts in, so they can ship — and be rolled back to — on their own.
--
-- WHY STEP 2 IS LOAD-BEARING. `finding_lineage.current_status` and
-- `lineage_events.event_type` are bounded by CHECK constraints written in 004.
-- Every value 0091 introduces is outside both sets. Without this widening the
-- feature does not degrade, it FAILS AT RUNTIME: the first attempt to record
-- `unconfirmed`, or to write a `confirmed_by_evidence` event, is rejected by
-- the database. The columns in step 1 would be inert, and the closure pass
-- would error on its first interesting row.
--
-- The constraints are dropped and re-created rather than widened in place
-- because Postgres has no ALTER ... CHECK. Both halves are guarded so the file
-- is idempotent: DROP CONSTRAINT IF EXISTS, then ADD only when absent.

-- ── Step 1: the new columns ────────────────────────────────────────────────
-- All nullable (or defaulted) and all read through COALESCE, so a row written
-- before this migration is indistinguishable from one written after it.

-- Canonical target identity (§7.1). Backfilled in a later migration; NULL here.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS target_key TEXT;
-- The 0079 stable identity, adopted as the matching key from the identity phase.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS fingerprint_v2 TEXT;
-- Branch of the scan that last saw the row. Closure is per branch (§7.4): a
-- scan of another branch may CONFIRM a row but never close it, so a row whose
-- file simply does not exist on the branch being scanned is left alone.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS git_branch TEXT;
-- Provenance of the finding that raised the row. This is the ONLY input to
-- model.TierOf, and therefore the single fact that decides whether the row
-- closes on absence (deterministic) or only on evidence (LLM). It is stored
-- rather than derived per scan because the deciding scan is precisely the one
-- in which the finding is ABSENT — there is nothing left to derive it from.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS provenance TEXT;
-- sha256 of the whitespace-normalised evidence quote. The quote TEXT is never
-- stored here, or anywhere else on this side of the wire; only the agent holds
-- it, in its own cache. This column exists so the agent can prove that the
-- entry in that cache is the one this row was raised on.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS quote_hash TEXT;
-- The window verified at the last confirmation.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS evidence_line_start INTEGER;
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS evidence_line_end INTEGER;
-- sha256 of the cited file at last confirmation / at fix. Bounds the fixed-row
-- re-check: a fixed row whose file has not changed since it was fixed needs no
-- second look.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS evidence_file_hash TEXT;
-- Scans that re-found the finding OR positively confirmed its code is still
-- present. DEFAULT 1 (not 0): every existing row was seen at least once, by
-- the scan that created it.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS seen_count INTEGER DEFAULT 1;
-- Lets the aggregate report "last seen" without joining findings.
-- UUID, matching audits.id (001_init) — the FK type-match rule.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS last_seen_audit_id UUID;
-- Set on the loser of a duplicate merge; such a row is excluded from reads.
-- UUID, matching finding_lineage.id.
ALTER TABLE finding_lineage ADD COLUMN IF NOT EXISTS merged_into UUID;

-- ── Step 2: widen the CHECK constraints ────────────────────────────────────

-- EVERY existence probe below is scoped with `conrelid = '<table>'::regclass`,
-- not by name alone. `pg_constraint.conname` is unique per TABLE, not per
-- database: a second schema holding a constraint of the same name — a staging
-- copy, a per-tenant schema, the integration harness's own test schema —
-- satisfies a bare `conname =` probe. The DROP above it resolves through
-- search_path and removes the REAL constraint, the guard then reads the
-- stranger's row and skips the ADD, and the table is left with no CHECK at
-- all. Silent, and the opposite of what this step exists to guarantee.

-- current_status gains `unconfirmed`: the state of a row the scan could not
-- decide (lost quote, unreadable file, verifier exception, or an agent that
-- returned no check for a row it was asked about). It is ACTIVE, so the next
-- scan may still act on it — a terminal "unconfirmed" would be a slower
-- version of the silent disappearance this feature exists to end.
DO $$ BEGIN
    ALTER TABLE finding_lineage DROP CONSTRAINT IF EXISTS finding_lineage_current_status_check;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'finding_lineage_current_status_check'
           AND conrelid = 'finding_lineage'::regclass
    ) THEN
        ALTER TABLE finding_lineage ADD CONSTRAINT finding_lineage_current_status_check
            CHECK (current_status IN (
                'open','in_progress','resolved','accepted_risk','false_positive',
                'fixed','regression','unconfirmed'
            ));
    END IF;
END $$;

-- event_type gains the nine 0091 events. They exist so the timeline records
-- WHY a scan did or did not act on a row: `confirmed_by_evidence` (the code
-- was re-read and is still there) is a different claim from `fixed` (the model
-- stopped mentioning it), and collapsing the two is the defect.
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
                'scope_unknown','memory_synced','merged'
            ));
    END IF;
END $$;

-- ── Step 3: the identity column, and the fingerprint_v2 backfill ───────────
--
-- `sources` gets the same key so a target can be named without walking
-- finding_lineage; the Go ingest computes it (service.ResolveTarget) and this
-- column is where it lands.
ALTER TABLE sources ADD COLUMN IF NOT EXISTS target_key TEXT;

-- finding_lineage.fingerprint_v2 is backfilled from `findings`, which is where
-- the 0079 identity already lives for 62,188 rows. It is the matching key from
-- P3 onward, and without this every pre-existing row would match on v1 only —
-- the identity that embeds the absolute path and therefore CHANGES with the
-- mount, which is the defect being fixed.
--
-- A lineage row whose fingerprint appears nowhere in `findings` with a v2 keeps
-- NULL and continues to match on v1 (the 0079 bridge). That is not a gap: v1 is
-- still the stable id, and a row with no v2 anywhere has no better answer
-- available.
--
-- MIN() rather than "the first one written": the two are the same whenever a
-- fingerprint has one v2 (the overwhelming case), and MIN is deterministic on
-- re-run, which "first" is not once rows are deleted.
UPDATE finding_lineage fl
   SET fingerprint_v2 = v.fp2
  FROM (
        SELECT f.fingerprint, f.agent_type, MIN(f.fingerprint_v2) AS fp2
          FROM findings f
         WHERE f.fingerprint IS NOT NULL
           AND COALESCE(f.fingerprint_v2, '') <> ''
         GROUP BY f.fingerprint, f.agent_type
       ) v
 WHERE COALESCE(fl.fingerprint_v2, '') = ''
   AND fl.fingerprint = v.fingerprint
   AND fl.agent_type  = v.agent_type;

-- finding_lineage.provenance is backfilled the same way, from the same join,
-- and it is the more consequential of the two.
--
-- WHY A COLUMN LEFT EMPTY HERE IS NOT MERELY INCOMPLETE. `provenance` is the
-- ONLY input to model.TierOf (see the ADD COLUMN above), and TierOf('')
-- answers `det` — the pre-0091 rule that a finding missing from a scan has
-- been repaired. Adding the column without filling it therefore does not
-- leave the tier "unknown": it silently classifies every pre-existing row as
-- deterministic, so the first scan after this migration closes every LLM-tier
-- row the model does not happen to repeat. That is the incident 0091 exists
-- to prevent, applied to the whole historical corpus at once.
--
-- AND IT CANNOT BE RECOVERED LATER. A row only ever acquires provenance in
-- updateExistingLineage, which runs when the finding is REPORTED — while the
-- row whose tier decides the outcome is, by construction, the one this scan
-- did NOT report. The rows that need the value are exactly the rows runtime
-- can never give it to. It has to be done here or not at all.
--
-- The empty-is-deterministic default stays correct for what it was written
-- for: a row whose fingerprint appears in no finding that records a
-- provenance keeps NULL, because there is genuinely no better answer.
--
-- AN LLM PROVENANCE WINS A TIE, and this is not a preference. One fingerprint
-- can have been reported by both tiers. Choosing the deterministic value lets
-- the row close on the model's silence; choosing the LLM value costs at most
-- an `unconfirmed` that the next scan resolves. Only one of those two errors
-- destroys triage state. Note that a plain MIN() over the column would pick
-- 'catalog_rollup' over 'llm_l5_verified' and get precisely this backwards —
-- hence the two-armed COALESCE rather than one aggregate.
UPDATE finding_lineage fl
   SET provenance = v.prov
  FROM (
        SELECT f.fingerprint,
               f.agent_type,
               COALESCE(
                 MIN(TRIM(f.provenance)) FILTER (
                   WHERE LOWER(TRIM(COALESCE(f.provenance, ''))) LIKE 'llm%'),
                 MIN(TRIM(f.provenance))
               ) AS prov
          FROM findings f
         WHERE f.fingerprint IS NOT NULL
           AND COALESCE(TRIM(f.provenance), '') <> ''
         GROUP BY f.fingerprint, f.agent_type
       ) v
 WHERE COALESCE(fl.provenance, '') = ''
   AND fl.fingerprint = v.fingerprint
   AND fl.agent_type  = v.agent_type;

-- ── Step 4: the target_key backfill — STRING ONLY ─────────────────────────
--
-- WHY NO GIT AND NO FILESYSTEM. The Go resolver (§7.1) asks git for a remote
-- and stats the disk for a scan-root marker. A migration cannot: the paths in
-- this table are historical, most of them name directories that never existed
-- on the machine now running the migration (a container mount, a per-ingest
-- clone dir deleted months ago), and a migration that stats 10,663 of them
-- stalls startup on every deployment. So the backfill is pure string work over
-- the paths, and the Go resolver takes over for every scan from here on.
--
-- The rule: strip the run-mode prefix, then take the FIRST path segment under
-- a known scan root — "known" meaning the parent of some path in `sources`,
-- which is the only record of what a project root looked like on this
-- installation. /home/user/src/vulture and /mnt/source/vulture both reduce to
-- `vulture`, which is exactly the pair the merge below exists to collapse.

-- The run-mode prefixes. This list MIRRORS pathutil.RunModeRoots(); the mirror
-- is pinned by TestRunModeRootsMatchMigration027 so the two cannot drift.
CREATE OR REPLACE FUNCTION vlt_0091_strip_runmode(p TEXT) RETURNS TEXT AS $$
DECLARE
    r   TEXT;
    pre TEXT;
BEGIN
    IF p IS NULL OR p = '' THEN
        RETURN '/';
    END IF;
    r := rtrim(p, '/');
    IF r = '' THEN
        RETURN '/';
    END IF;
    FOREACH pre IN ARRAY ARRAY['/mnt/source', '/tmp/vulture-sources'] LOOP
        IF r = pre THEN
            RETURN '/';           -- the bare mount: names no project at all
        END IF;
        IF r LIKE pre || '/%' THEN
            RETURN substring(r FROM length(pre) + 1);
        END IF;
    END LOOP;
    RETURN r;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Parent directory of a slash path; '/' for a top-level entry.
CREATE OR REPLACE FUNCTION vlt_0091_parent(p TEXT) RETURNS TEXT AS $$
DECLARE
    i INT;
BEGIN
    IF p IS NULL OR p = '' OR p = '/' THEN
        RETURN '/';
    END IF;
    i := length(p) - position('/' IN reverse(p)) + 1;
    IF i <= 1 THEN
        RETURN '/';
    END IF;
    RETURN substring(p FROM 1 FOR i - 1);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- The key itself. `unresolved:` when the path names no project — surfaced as
-- "Unattributed scans" and NEVER folded into a target, because nothing can be
-- attributed to a codebase from `/mnt/source` alone and guessing is how one
-- project's history acquires another project's findings.
CREATE OR REPLACE FUNCTION vlt_0091_target_key(src_path TEXT) RETURNS TEXT AS $$
DECLARE
    norm TEXT;
    best TEXT;
    rest TEXT;
BEGIN
    norm := vlt_0091_strip_runmode(src_path);
    IF norm = '/' THEN
        RETURN 'unresolved:' || COALESCE(NULLIF(rtrim(src_path, '/'), ''), '/');
    END IF;
    -- A candidate container that is ITSELF a scanned source path is skipped, so
    -- a sub-path scan inherits its project rather than becoming its own target
    -- (LLD 7.2). Without this, scanning `<proj>/.vscode` makes `<proj>` a
    -- container and the row keys to `path:.vscode` — measured on the live source
    -- set, where the folder-open incident's rows sit under exactly that path.
    -- `/` is exempt and must stay a container: it is what a bare `/mnt/source`
    -- normalises to, and dropping it stops `/mnt/source/<proj>` unifying with the
    -- native path, which is the whole point of the run-mode strip above.
    SELECT r.root INTO best
      FROM (SELECT DISTINCT vlt_0091_parent(vlt_0091_strip_runmode(s.path)) AS root
              FROM sources s) r
     WHERE (r.root = '/' OR norm LIKE r.root || '/%')
       AND (r.root = '/' OR NOT EXISTS (
             SELECT 1 FROM sources s2
              WHERE vlt_0091_strip_runmode(s2.path) = r.root))
     ORDER BY length(r.root) DESC
     LIMIT 1;
    IF best IS NULL THEN
        RETURN 'path:' || norm;   -- no known root: the whole path is the name
    END IF;
    IF best = '/' THEN
        rest := substring(norm FROM 2);
    ELSE
        rest := substring(norm FROM length(best) + 2);
    END IF;
    rest := split_part(rest, '/', 1);
    IF rest = '' THEN
        RETURN 'path:' || norm;
    END IF;
    RETURN 'path:' || rest;
END;
$$ LANGUAGE plpgsql STABLE;

-- Batched and predicated on `target_key IS NULL`, which makes the backfill
-- both RESUMABLE (an interrupted run resumes where it stopped) and idempotent
-- (a completed one is a no-op). The batch bounds the working set of a single
-- statement on a table with five figures of rows.
DO $$
DECLARE
    touched INTEGER;
BEGIN
    LOOP
        UPDATE finding_lineage
           SET target_key = vlt_0091_target_key(source_path)
         WHERE id IN (SELECT id FROM finding_lineage WHERE target_key IS NULL LIMIT 5000);
        GET DIAGNOSTICS touched = ROW_COUNT;
        EXIT WHEN touched = 0;
    END LOOP;
END $$;

-- Sources get the same treatment, so a pre-0091 source row is attributable
-- without waiting for its next ingest.
UPDATE sources SET target_key = vlt_0091_target_key(path) WHERE target_key IS NULL;

-- ── Step 5: merge the duplicates target identity has just revealed ────────
--
-- This is the only part of 0091 that destroys a distinction rather than adding
-- one, so WHICH row survives is not a matter of taste:
--
--   * EARLIEST first_found_at survives. "How long has this been open" is the
--     number an aggregate report exists to answer, and keeping the later date
--     silently resets the age of every merged finding to the day of the mount
--     change.
--   * LOWEST ref_number is carried. VLT-0007 is written in tickets, commits
--     and review comments; the older ref is the one that has been quoted, so
--     it is the one that must keep resolving.
--   * The loser is MARKED, not deleted (`merged_into`), so a stale link still
--     leads somewhere.
--   * The loser's EVENTS move to the survivor. They are the audit trail; a
--     merge that drops half of it destroys the record of when the finding was
--     first seen and what a human decided about it.
--
-- NULLIF on fingerprint_v2 is not decoration: the Go writer stores '' rather
-- than NULL for a finding with no v2, and a bare COALESCE would collapse every
-- such row of a target onto the single key '' — merging unrelated findings.
DROP TABLE IF EXISTS vlt_0091_merge;
CREATE TEMP TABLE vlt_0091_merge ON COMMIT DROP AS
WITH grouped AS (
    SELECT id, target_key, agent_type, first_found_at, ref_number,
           COALESCE(NULLIF(fingerprint_v2, ''), fingerprint) AS match_key
      FROM finding_lineage
     WHERE merged_into IS NULL AND target_key IS NOT NULL
),
ranked AS (
    SELECT g.id,
           FIRST_VALUE(g.id) OVER (PARTITION BY g.target_key, g.agent_type, g.match_key
                                   ORDER BY g.first_found_at ASC, g.id ASC) AS survivor_id,
           MIN(g.ref_number) OVER (PARTITION BY g.target_key, g.agent_type, g.match_key) AS min_ref,
           COUNT(*)          OVER (PARTITION BY g.target_key, g.agent_type, g.match_key) AS group_size
      FROM grouped g
)
SELECT survivor_id, id AS row_id, min_ref, (id = survivor_id) AS is_survivor
  FROM ranked
 WHERE group_size > 1;

UPDATE finding_lineage fl
   SET ref_number = m.min_ref, updated_at = now()
  FROM vlt_0091_merge m
 WHERE fl.id = m.row_id AND m.is_survivor
   AND m.min_ref IS NOT NULL AND fl.ref_number IS DISTINCT FROM m.min_ref;

UPDATE lineage_events e
   SET lineage_id = m.survivor_id
  FROM vlt_0091_merge m
 WHERE e.lineage_id = m.row_id AND NOT m.is_survivor;

INSERT INTO lineage_events (lineage_id, event_type, old_status, new_status, notes)
SELECT m.survivor_id, 'merged', NULL, NULL,
       'absorbed duplicate lineage ' || m.row_id::text || ' (027 target-identity merge)'
  FROM vlt_0091_merge m
 WHERE NOT m.is_survivor;

UPDATE finding_lineage fl
   SET merged_into = m.survivor_id, updated_at = now()
  FROM vlt_0091_merge m
 WHERE fl.id = m.row_id AND NOT m.is_survivor;

-- ── Step 6: the indexes that keep the duplicates from coming back ─────────
--
-- The unique index is not an optimisation. Without it the next scan under a
-- third path form re-creates exactly what step 5 just merged. It is also the
-- CHECK on step 5: if the merge left any duplicate behind, this index cannot
-- be built and the failure surfaces here rather than in production.
--
-- `WHERE merged_into IS NULL` scopes it to live rows, so the marked losers do
-- not collide with the survivors that absorbed them.
CREATE UNIQUE INDEX IF NOT EXISTS uq_lineage_target
    ON finding_lineage (target_key, agent_type, COALESCE(NULLIF(fingerprint_v2, ''), fingerprint))
 WHERE merged_into IS NULL;

-- The read index for ActiveByTarget. idx_lineage_open cannot serve it: that one
-- is partial on (source_path, agent_type) over only open/in_progress, and both
-- halves are wrong here.
CREATE INDEX IF NOT EXISTS idx_lineage_active_target
    ON finding_lineage (target_key, agent_type)
 WHERE current_status IN ('open', 'in_progress', 'regression', 'unconfirmed');

-- uq_lineage (fingerprint, source_path, agent_type) is deliberately KEPT: the
-- VULTURE_LINEAGE_KEY=path rollback reads and writes through it, and dropping
-- it would make that rollback a data migration instead of a switch.

DROP FUNCTION IF EXISTS vlt_0091_target_key(TEXT);
DROP FUNCTION IF EXISTS vlt_0091_parent(TEXT);
DROP FUNCTION IF EXISTS vlt_0091_strip_runmode(TEXT);
