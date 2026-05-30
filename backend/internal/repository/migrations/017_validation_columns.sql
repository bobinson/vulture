-- Migration 017: validation phase columns (feature 0045).
--
-- Adds per-finding validation classification + the user_label corpus
-- column on audit_memories. All ADDs use IF NOT EXISTS so the
-- migration is idempotent under feature 0040's auto-runner.
--
-- The `validation` column stores the full check trace as JSON.
-- Postgres treats TEXT as TEXT (no JSONB benefits in v1; promote to
-- JSONB in a follow-up migration once query patterns demand it).
-- SQLite stores TEXT and uses the json1 extension for queries.

-- ── findings: per-finding classification ─────────────────────────
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS validation_status TEXT;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS validation_confidence REAL;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS validation TEXT;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS is_rollup BOOLEAN DEFAULT FALSE;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS rolled_up_into TEXT;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS instance_count INTEGER DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_findings_validation_status
    ON findings(audit_id, validation_status);

-- ── audit_memories: human-feedback corpus ────────────────────────
ALTER TABLE audit_memories
    ADD COLUMN IF NOT EXISTS user_label TEXT;

ALTER TABLE audit_memories
    ADD COLUMN IF NOT EXISTS labelled_by TEXT;

ALTER TABLE audit_memories
    ADD COLUMN IF NOT EXISTS labelled_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_audit_memories_label
    ON audit_memories(user_label);
