-- Migration 028 (feature 0091): re-issue the finding_lineage.provenance
-- backfill that migration 027 step 3 carries.
--
-- WHY A SECOND MIGRATION FOR A STATEMENT 027 ALREADY CONTAINS. The backfill
-- was added to 027 after 027 had been applied to a deployed database. The
-- runner records a migration as applied by version, so on that database 027
-- is done and the statement inside it has never run: 10,443 of 10,756
-- lineage rows carry an empty `provenance`. The authoring contract is clear
-- about the remedy — an applied migration is frozen, so the change ships as
-- the next version. A fresh database runs the statement in 027 and finds
-- nothing to do here; a database that applied 027 before the statement
-- existed runs it here. Both end in the same state.
--
-- WHY IT IS CRITICAL, NOT COSMETIC. `provenance` is the ONLY input to
-- model.TierOf, and TierOf decides whether a row may close on ABSENCE
-- (deterministic) or only on EVIDENCE (LLM). An LLM-raised row with an empty
-- provenance is classed deterministic, so a later scan that simply does not
-- mention it — because the prior-findings block told the model to skip known
-- issues, or because the scan could not see the file, or because the LLM
-- tier failed outright — closes it as `fixed`. Measured on the deployed
-- database: nine rows on one codebase, five of them critical, marked fixed
-- with the offending code still on disk byte for byte, all nine LLM-raised,
-- all nine with an empty provenance.
--
-- THE STATEMENT IS 027 STEP 3 VERBATIM, and keeps its contract:
--   * guarded by `COALESCE(fl.provenance,'') = ''` — a row the runtime has
--     since stamped is never overwritten, so the file is idempotent;
--   * the value comes from `findings` joined on (fingerprint, agent_type),
--     the only place the tier of a historical row was ever recorded;
--   * AN LLM PROVENANCE WINS A TIE. One fingerprint can have been reported
--     by both tiers. Choosing the deterministic value lets the row close on
--     the model's silence; choosing the LLM value costs at most an
--     `unconfirmed` the next scan resolves. Only one of those errors destroys
--     triage state. A plain MIN() would pick 'catalog_rollup' over
--     'llm_l5_verified' and get this exactly backwards — hence the two-armed
--     COALESCE.
-- A row whose fingerprint appears in `findings` with no provenance anywhere
-- keeps NULL: there is genuinely no better answer, and TierOf's documented
-- empty-is-deterministic rule owns it.
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
