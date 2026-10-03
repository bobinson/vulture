-- Migration 031 (feature 0096): retire the OWASP lineage rows.
--
-- The OWASP agent (0063) re-emitted every CWE finding it categorised as a
-- second finding with its OWN lineage row, so one weakness carried two VLT
-- refs, two triage states and two timelines. 0096 replaces the copy with a
-- label on the finding (030), and from then on a mapping-mode OWASP run writes
-- no lineage at all. This file folds the rows the copies already created.
--
-- THE RULE. A candidate is a live OWASP row (`merged_into IS NULL`). Its twin
-- is a live row of ANY other agent (the OWASP agent categorised CWE findings
-- from cwe, xss, ssdf, soc2 ...) that has
--
--   * the same TARGET — equal target_key, or the two keys are the halves of
--     the 0091 legacy-key bridge: one is the `path:<segment>` key migration
--     027 would give a source's path, the other the `git:`/`marker:` key the
--     live resolver gave that source. Every read already shows those rows as
--     one project (loadTargetAliases), so comparing the strings would retire
--     a copy the dashboard shows beside its twin as "no twin" — past the
--     triage check below. A legacy key two resolved targets claim is no
--     bridge (attributing it to either is a guess),
--   * the same file: the same path RELATIVE TO THE TARGET, or the same
--     absolute path. A row's path is resolved to an absolute one against its
--     own source_path, then made relative to the SHORTEST scanned root
--     (`sources.path`) of its bridged target that contains it, else to its own
--     source_path. Not simply "relative to its own source_path": a row's
--     source_path is frozen at creation while the lineage writers refresh its
--     file_path on every re-find (possibly from another checkout of the same
--     remote), and a 0091 sub-path scan shares its root's target_key under a
--     deeper source_path — either way one file reduced to two strings and the
--     copy was retired as "no twin", past the triage check. The SHORTEST root,
--     so root/hooks/z.js and root/src/hooks/z.js never reduce to one string;
--     the own-source fallback keeps two mount forms of one file one file,
--   * the same title once the OWASP copy's `[A07] ` prefix is removed.
--
-- Several twins: a cwe row first (it is the finding the copy was made from),
-- then one under the copy's OWN target_key (the pass that wrote the copy wrote
-- its source under the same key; a twin across the bridge is a sibling row the
-- 0091 convergence has not re-keyed yet), then the LOWEST ref (the one quoted
-- longest), then id for determinism.
--
--   twin found  merged_into = twin, and a `merged` event on BOTH rows so the
--               absorbed history is discoverable from the twin's own timeline.
--   no twin     merged_into = its own id (retired; nothing reads a self-merge
--               as a pointer to follow — no code walks merge chains). A
--               TRIAGED row retired this way is named in the log: there is no
--               twin to disagree with, so it does not abort, but its decision
--               is readable only by id from then on.
--
-- THE TWIN IS NEVER UPDATED. Its status, notes and ticket are the human record
-- and stay as they are (D4); 031 only adds an event to it. That is safe only
-- while a triaged OWASP row agrees with its twin, so a disagreement ABORTS the
-- migration — the runner rolls the whole file back and the backend does not
-- start until an operator reconciles the named rows. A NON-triaged OWASP row
-- decided nothing, so a twin that has moved on (in_progress, fixed) is folded
-- into as it stands. The OWASP row's own notes and ticket — the REASON behind
-- an agreeing triage — ride on the twin's `absorbed` event, because the folded
-- row drops out of every list and the twin may carry no reason of its own.
--
-- Idempotent by the candidate predicate: a folded row is no longer live, so a
-- re-run finds nothing. Plain SQL, one transaction (the runner's).

-- strip(): fp with "<root>/" stripped when it is a prefix, then a leading
-- "./". substring/left rather than LIKE, so a path holding `%` or `_` cannot
-- match as a pattern.
CREATE OR REPLACE FUNCTION vlt_0096_strip(src TEXT, fp TEXT) RETURNS TEXT AS $$
    SELECT regexp_replace(
             CASE WHEN COALESCE(src, '') <> ''
                   AND left(fp, length(rtrim(src, '/')) + 1) = rtrim(src, '/') || '/'
                  THEN substring(fp FROM length(rtrim(src, '/')) + 2)
                  ELSE fp
             END,
             '^\./', '')
$$ LANGUAGE sql IMMUTABLE;

-- abs(): a relative file_path resolved against the row's own source_path.
CREATE OR REPLACE FUNCTION vlt_0096_abs(src TEXT, fp TEXT) RETURNS TEXT AS $$
    SELECT CASE WHEN left(fp, 1) = '/' OR rtrim(COALESCE(src, ''), '/') = '' THEN fp
                ELSE rtrim(src, '/') || '/' || regexp_replace(fp, '^\./', '')
           END
$$ LANGUAGE sql IMMUTABLE;

-- The ref as model.FindingLineage.FormatRef renders it (VLT-%04d). lpad alone
-- would TRUNCATE a five-digit ref, hence the GREATEST.
CREATE OR REPLACE FUNCTION vlt_0096_ref(ref INTEGER, id UUID) RETURNS TEXT AS $$
    SELECT CASE WHEN ref > 0
                THEN 'VLT-' || lpad(ref::text, GREATEST(4, length(ref::text)), '0')
                ELSE id::text
           END
$$ LANGUAGE sql IMMUTABLE;

-- ── The legacy key, as 027 computed it ──────────────────────────────────
--
-- 027's vlt_0091_* functions, recreated verbatim because 027 dropped them.
-- The Go twin is stringTargetKey (repository/sqlite_target_identity.go), which
-- is what loadTargetAliases derives the read-side bridge from; the run-mode
-- list is pinned against pathutil.RunModeRoots() by TestRunModeRootsMatchMigration027.
CREATE OR REPLACE FUNCTION vlt_0096_strip_runmode(p TEXT) RETURNS TEXT AS $$
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
            RETURN '/';
        END IF;
        IF r LIKE pre || '/%' THEN
            RETURN substring(r FROM length(pre) + 1);
        END IF;
    END LOOP;
    RETURN r;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION vlt_0096_parent(p TEXT) RETURNS TEXT AS $$
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

CREATE OR REPLACE FUNCTION vlt_0096_legacy_key(src_path TEXT) RETURNS TEXT AS $$
DECLARE
    norm TEXT;
    best TEXT;
    rest TEXT;
BEGIN
    norm := vlt_0096_strip_runmode(src_path);
    IF norm = '/' THEN
        RETURN 'unresolved:' || COALESCE(NULLIF(rtrim(src_path, '/'), ''), '/');
    END IF;
    SELECT r.root INTO best
      FROM (SELECT DISTINCT vlt_0096_parent(vlt_0096_strip_runmode(s.path)) AS root
              FROM sources s) r
     WHERE (r.root = '/' OR norm LIKE r.root || '/%')
       AND (r.root = '/' OR NOT EXISTS (
             SELECT 1 FROM sources s2
              WHERE vlt_0096_strip_runmode(s2.path) = r.root))
     ORDER BY length(r.root) DESC
     LIMIT 1;
    IF best IS NULL THEN
        RETURN 'path:' || norm;
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

-- The bridge: each legacy key and the ONE resolved key it belongs to. A legacy
-- key claimed by two resolved keys is left out, so a row under it keeps its
-- own key and twins only a row under that same string.
DROP TABLE IF EXISTS vlt_0096_alias;
CREATE TEMP TABLE vlt_0096_alias ON COMMIT DROP AS
SELECT legacy, min(resolved) AS resolved
  FROM (SELECT DISTINCT vlt_0096_legacy_key(s.path) AS legacy, s.target_key AS resolved
          FROM sources s
         WHERE COALESCE(s.target_key, '') <> '') a
 WHERE legacy <> resolved
 GROUP BY legacy
HAVING count(DISTINCT resolved) = 1;

-- Every scanned root of a target: each source's path under its bridged key
-- (its resolved key, else the legacy key 027 gave its path). COALESCE computes
-- the legacy key only for a source that has no resolved one.
DROP TABLE IF EXISTS vlt_0096_root;
CREATE TEMP TABLE vlt_0096_root ON COMMIT DROP AS
SELECT DISTINCT COALESCE(a.resolved, k.key) AS target, k.root
  FROM (SELECT rtrim(s.path, '/') AS root,
               COALESCE(NULLIF(s.target_key, ''), vlt_0096_legacy_key(s.path)) AS key
          FROM sources s) k
  LEFT JOIN vlt_0096_alias a ON a.legacy = k.key
 WHERE k.root <> '';

-- rel(): the row's path relative to the shortest root of its target that
-- contains it, else to its own source_path.
CREATE OR REPLACE FUNCTION vlt_0096_rel(tgt TEXT, src TEXT, fp TEXT) RETURNS TEXT AS $$
    SELECT vlt_0096_strip(
             COALESCE((SELECT r.root FROM vlt_0096_root r
                        WHERE r.target = tgt
                          AND left(x.abs, length(r.root) + 1) = r.root || '/'
                        ORDER BY length(r.root)
                        LIMIT 1),
                      src),
             x.abs)
      FROM (SELECT vlt_0096_abs(src, fp) AS abs) x
$$ LANGUAGE sql STABLE;

DROP TABLE IF EXISTS vlt_0096_retire;
CREATE TEMP TABLE vlt_0096_retire ON COMMIT DROP AS
WITH cand AS (
    SELECT o.id, o.ref_number, o.current_status, o.target_key,
           COALESCE(o.notes, '') AS notes, COALESCE(o.ticket_url, '') AS ticket,
           COALESCE(a.resolved, o.target_key)          AS target,
           vlt_0096_abs(o.source_path, o.file_path)   AS abs,
           vlt_0096_rel(COALESCE(a.resolved, o.target_key), o.source_path, o.file_path) AS rel,
           regexp_replace(o.title, '^\[A\d+\] ', '')   AS title0
      FROM finding_lineage o
      LEFT JOIN vlt_0096_alias a ON a.legacy = o.target_key
     WHERE o.agent_type = 'owasp' AND o.merged_into IS NULL
),
pool AS (
    SELECT c.id, c.agent_type, c.ref_number, c.current_status, c.title, c.target_key,
           COALESCE(a.resolved, c.target_key)          AS target,
           vlt_0096_abs(c.source_path, c.file_path)   AS abs,
           vlt_0096_rel(COALESCE(a.resolved, c.target_key), c.source_path, c.file_path) AS rel
      FROM finding_lineage c
      LEFT JOIN vlt_0096_alias a ON a.legacy = c.target_key
     WHERE c.agent_type <> 'owasp' AND c.merged_into IS NULL
),
twins AS (
    SELECT cand.id AS owasp_id, c.id AS twin_id, c.ref_number AS twin_ref,
           c.current_status AS twin_status,
           row_number() OVER (PARTITION BY cand.id
                              ORDER BY (c.agent_type = 'cwe') DESC,
                                       (c.target_key = cand.target_key) DESC,
                                       c.ref_number ASC NULLS LAST, c.id ASC) AS rn,
           count(*)     OVER (PARTITION BY cand.id) AS n
      FROM cand
      JOIN pool c
        ON c.target = cand.target
       AND c.title = cand.title0
       AND (c.rel = cand.rel OR (left(c.abs, 1) = '/' AND c.abs = cand.abs))
)
SELECT cand.id AS owasp_id, cand.ref_number AS owasp_ref, cand.current_status AS owasp_status,
       cand.notes AS owasp_notes, cand.ticket AS owasp_ticket,
       t.twin_id, t.twin_ref, t.twin_status, COALESCE(t.n, 0) AS twin_count
  FROM cand
  LEFT JOIN twins t ON t.owasp_id = cand.id AND t.rn = 1;

-- The safety stop, BEFORE any write. A human decision recorded only on the
-- OWASP row would be hidden by the fold, because the twin keeps its own status.
DO $$
DECLARE
    bad    INTEGER;
    sample TEXT;
BEGIN
    SELECT count(*),
           string_agg(vlt_0096_ref(owasp_ref, owasp_id) || ' ' || owasp_status || ' vs twin '
                      || vlt_0096_ref(twin_ref, twin_id) || ' ' || twin_status, '; ')
      INTO bad, sample
      FROM vlt_0096_retire
     WHERE twin_id IS NOT NULL
       AND owasp_status IN ('false_positive', 'accepted_risk', 'resolved')
       AND twin_status IS DISTINCT FROM owasp_status;
    IF bad > 0 THEN
        RAISE EXCEPTION '0096: % triaged OWASP lineage row(s) disagree with the twin they would fold into (%); set the twin''s status to match, then restart',
            bad, sample;
    END IF;
END $$;

INSERT INTO lineage_events (lineage_id, event_type, notes)
SELECT owasp_id, 'merged', '0096: OWASP lineage folded into ' || vlt_0096_ref(twin_ref, twin_id)
  FROM vlt_0096_retire WHERE twin_id IS NOT NULL
UNION ALL
SELECT twin_id, 'merged', '0096: absorbed OWASP lineage ' || vlt_0096_ref(owasp_ref, owasp_id)
       || CASE WHEN owasp_notes = '' AND owasp_ticket = '' THEN ''
               ELSE ' (' || concat_ws('; ', owasp_status,
                                      'notes: '  || NULLIF(owasp_notes, ''),
                                      'ticket: ' || NULLIF(owasp_ticket, '')) || ')'
          END
  FROM vlt_0096_retire WHERE twin_id IS NOT NULL
UNION ALL
SELECT owasp_id, 'merged', '0096: OWASP lineage retired, no twin'
  FROM vlt_0096_retire WHERE twin_id IS NULL;

UPDATE finding_lineage fl
   SET merged_into = COALESCE(r.twin_id, r.owasp_id), updated_at = now()
  FROM vlt_0096_retire r
 WHERE fl.id = r.owasp_id;

-- The §10 log line. The runner carries a migration's NOTICEs into the backend
-- log; silent when there was nothing to retire (a fresh install, a re-run).
DO $$
DECLARE
    c INTEGER; tw INTEGER; re INTEGER; mu INTEGER;
    tri INTEGER; sample TEXT;
BEGIN
    SELECT count(*), count(twin_id), count(*) - count(twin_id), count(*) FILTER (WHERE twin_count > 1)
      INTO c, tw, re, mu
      FROM vlt_0096_retire;
    IF c > 0 THEN
        RAISE NOTICE '[migrate] 0096 owasp lineage: candidates=% twinned=% retired=% multi_twin=%',
            c, tw, re, mu;
    END IF;
    SELECT count(*),
           string_agg(vlt_0096_ref(owasp_ref, owasp_id) || ' ' || owasp_status, '; '
                      ORDER BY owasp_ref, owasp_id)
      INTO tri, sample
      FROM vlt_0096_retire
     WHERE twin_id IS NULL
       AND owasp_status IN ('false_positive', 'accepted_risk', 'resolved');
    IF tri > 0 THEN
        RAISE NOTICE '[migrate] 0096 owasp lineage: % triaged row(s) retired with no twin: %', tri, sample;
    END IF;
END $$;

DROP FUNCTION IF EXISTS vlt_0096_legacy_key(TEXT);
DROP FUNCTION IF EXISTS vlt_0096_parent(TEXT);
DROP FUNCTION IF EXISTS vlt_0096_strip_runmode(TEXT);
DROP FUNCTION IF EXISTS vlt_0096_ref(INTEGER, UUID);
DROP FUNCTION IF EXISTS vlt_0096_rel(TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS vlt_0096_abs(TEXT, TEXT);
DROP FUNCTION IF EXISTS vlt_0096_strip(TEXT, TEXT);
