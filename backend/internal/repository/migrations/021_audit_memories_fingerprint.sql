-- Migration 021: add the fingerprint column the L4 memory-prior lookup needs.
--
-- Feature 0045's L4 validation queries:
--   SELECT fingerprint, user_label FROM audit_memories
--   WHERE user_label IS NOT NULL AND fingerprint IN (...)
-- (internal/service/validation_memory.go). But migration 017 added
-- user_label / labelled_by / labelled_at to audit_memories WITHOUT the
-- fingerprint column, so EVERY audit logged:
--   [validate.l4] lookup failed (skipping): pq: column "fingerprint" does not exist
-- Add the column (+ an index for the IN-list lookup). Idempotent.
--
-- NOTE: the memory write path does not yet populate this column, so L4
-- fingerprint matching is inert until that is wired; this migration
-- removes the recurring error and makes the column available.

ALTER TABLE audit_memories
    ADD COLUMN IF NOT EXISTS fingerprint TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_memories_fingerprint
    ON audit_memories (fingerprint);
