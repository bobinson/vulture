-- Migration 019: Add L5 (LLM judge) verdict cache column on audit_memories.
--
-- Feature 0046 caches per-finding LLM verdicts so re-audits of
-- unchanged source skip the LLM call entirely. The cache key is
-- (file_sha256, line_range, check_id, model_name), stored as JSONB
-- so the cache value can grow without further schema changes.
--
-- Idempotent: re-applying is a no-op. Older deployments that haven't
-- run this migration get L5 working at full cost (cache disabled,
-- backend logs a startup warning per D20).

ALTER TABLE audit_memories
    ADD COLUMN IF NOT EXISTS l5_verdict_cache JSONB;

-- Lookup uses an md5 hash of the composite key to keep the index small
-- and avoid duplicating the cache key in the index itself.
CREATE INDEX IF NOT EXISTS idx_audit_memories_l5_cache
    ON audit_memories ((l5_verdict_cache->>'key'))
    WHERE l5_verdict_cache IS NOT NULL;
