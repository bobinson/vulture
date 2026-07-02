-- Migration 022: per-finding provenance column (feature 0057, P6d).
--
-- The Python agents emit a `provenance` field on each finding describing
-- how it was produced: skill / signature_trusted / signature_candidate /
-- catalog_rollup / llm / llm_l5_verified. The Go backend previously
-- dropped it (no column), so GET /api/audits/:id and the findings table
-- never carried it. Add the column so provenance round-trips end-to-end.
--
-- Idempotent (IF NOT EXISTS) per the auto-runner contract. TEXT to mirror
-- the existing nullable string columns (e.g. validation_status); SQLite
-- parity is handled by migrateAddColumns() in sqlite_repo.go.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS provenance TEXT;
