-- Migration: Add performance indexes for memory queries.
-- Addresses slow ListByCodebasePath, DISTINCT ON, and text search queries.

-- Composite index for the primary prior-findings query pattern:
-- SELECT DISTINCT ON (title, finding_type) ... WHERE codebase_path = $1 AND agent_type = $2
CREATE INDEX IF NOT EXISTS idx_memories_codebase_agent
    ON audit_memories (codebase_path, agent_type)
    WHERE is_archived = false;

-- Composite index supporting DISTINCT ON (title, finding_type) ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_memories_title_type_created
    ON audit_memories (title, finding_type, created_at DESC)
    WHERE is_archived = false;

-- GIN trigram index for text search with similarity() and ILIKE
-- Requires pg_trgm extension (already enabled in 001_init.sql)
CREATE INDEX IF NOT EXISTS idx_memories_title_trgm
    ON audit_memories USING gin (title gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_memories_content_trgm
    ON audit_memories USING gin (content gin_trgm_ops);

-- NOTE: audit_id index already exists as idx_memories_audit in 001_init.sql

-- Index for ListRecent query
CREATE INDEX IF NOT EXISTS idx_memories_created_at
    ON audit_memories (created_at DESC)
    WHERE is_archived = false;
