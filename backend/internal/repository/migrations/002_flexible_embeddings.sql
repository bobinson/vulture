-- Migration: Support variable-dimension embeddings (Ollama nomic-embed-text = 768d, OpenAI = 1536d)
-- pgvector supports untyped vector columns that accept any dimension.

-- Drop dimension-specific HNSW indexes
DROP INDEX IF EXISTS idx_memories_embedding_hnsw;
DROP INDEX IF EXISTS idx_patterns_embedding_hnsw;

-- Change embedding columns from vector(1536) to untyped vector
-- This allows both 768d (nomic-embed-text) and 1536d (OpenAI) embeddings.
-- Guard with a type check so re-running on an already-untyped column is a
-- no-op (avoids unnecessary table rewrite + makes the migration idempotent).
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relname = 'audit_memories' AND a.attname = 'embedding'
          AND format_type(a.atttypid, a.atttypmod) <> 'vector'
    ) THEN
        ALTER TABLE audit_memories ALTER COLUMN embedding TYPE vector USING embedding::vector;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relname = 'remediation_patterns' AND a.attname = 'embedding'
          AND format_type(a.atttypid, a.atttypmod) <> 'vector'
    ) THEN
        ALTER TABLE remediation_patterns ALTER COLUMN embedding TYPE vector USING embedding::vector;
    END IF;
END $$;

-- Recreate HNSW indexes without dimension constraint.
-- Note: pgvector HNSW requires dimension at index time. Use IVFFlat instead for
-- dimension-agnostic indexing, or create separate indexes per known dimension.
-- For now, use exact search (no index) which is fine for <100K rows.
-- When scale requires it, create dimension-specific partial indexes:
--   CREATE INDEX ... ON audit_memories USING hnsw (embedding vector_cosine_ops)
--     WHERE array_length(embedding, 1) = 768;
