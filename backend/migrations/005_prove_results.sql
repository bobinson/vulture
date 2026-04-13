-- Migration 005: Create prove_results table for finding verification tracking.

CREATE TABLE IF NOT EXISTS prove_results (
    id             TEXT PRIMARY KEY,
    audit_id       TEXT NOT NULL,
    finding_id     TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'inconclusive',
    evidence       TEXT NOT NULL DEFAULT '',
    iterations_used INTEGER NOT NULL DEFAULT 0,
    staging_url    TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prove_results_audit_id ON prove_results (audit_id);
CREATE INDEX IF NOT EXISTS idx_prove_results_finding_id ON prove_results (finding_id);
CREATE INDEX IF NOT EXISTS idx_prove_results_status ON prove_results (status);
