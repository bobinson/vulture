-- Migration 007: Add fingerprint column to prove_results for lineage traceability.

ALTER TABLE prove_results ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_prove_fingerprint ON prove_results (fingerprint);
