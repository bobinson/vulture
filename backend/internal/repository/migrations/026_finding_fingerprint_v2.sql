-- Migration 026 (feature 0079 A3): the stable finding identity, beside v1.
--
-- v1 (title|path|category|agent) hashes the title, which the LLM tier rephrases
-- every run. Measured across three identical runs: 2 of ~113 LLM fingerprints
-- survived all three, so 105 of 124 findings were reported NEW each time. Real
-- accumulated data shows the same shape: 26,714 ref_numbers minted for 5,109
-- surviving lineages.
--
-- ADDED BESIDE v1, never replacing it. finding_lineage has UNIQUE
-- (fingerprint, source_path, agent_type) and carries human triage state
-- (accepted_risk, false_positive, notes, ticket_url, ref_number). Rewriting the
-- column in place would orphan every one of those rows and mark them all FIXED
-- on the next run. The dual-key bridge in lineage_service matches on either
-- value instead, so the flip is lossless and needs no backfill.
--
-- Nullable and read through COALESCE, matching every findings column added
-- since 001, so the nullableString binder cannot trip the 0055 failure mode.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint_v2 TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint_v2
    ON findings (fingerprint_v2) WHERE fingerprint_v2 IS NOT NULL;
