-- Migration 018: Make pgvector HNSW indexes dimension-conditional.
--
-- Migration 015 created HNSW indexes on `(embedding::vector(N))` but
-- forgot the `WHERE vector_dims(embedding) = N` predicate. Without it,
-- every INSERT casts the row through both the 1536-d and 768-d
-- indexes; rows whose actual dimension differs from the index get
-- rejected by the cast with `pq: expected N dimensions, not M`. The
-- net effect was that a DB containing a mix of embedding dimensions
-- couldn't accept new rows at all — and even a single-dimension DB
-- would still pay the cost of the mismatched-cast attempts.
--
-- Fix: drop the unconditional indexes and recreate them as PARTIAL
-- indexes, each scoped to the rows whose stored embedding actually
-- matches the index dimension. Queries that match the same expression
-- form + WHERE clause shape can still use the index.
--
-- Re-applying this migration is a no-op (DROP IF EXISTS + CREATE
-- IF NOT EXISTS). Older pgvector that doesn't support expression-
-- based HNSW falls through silently (the same fallback path as 015).

-- ─── audit_memories ──────────────────────────────────────────────────────
DROP INDEX IF EXISTS idx_memories_emb_1536_hnsw;
DROP INDEX IF EXISTS idx_memories_emb_768_hnsw;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_memories_emb_1536_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_memories_emb_1536_hnsw
                 ON audit_memories
                 USING hnsw ((embedding::vector(1536)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)
                 WHERE embedding IS NOT NULL
                   AND vector_dims(embedding) = 1536';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping idx_memories_emb_1536_hnsw: %', SQLERRM;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_memories_emb_768_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_memories_emb_768_hnsw
                 ON audit_memories
                 USING hnsw ((embedding::vector(768)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)
                 WHERE embedding IS NOT NULL
                   AND vector_dims(embedding) = 768';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping idx_memories_emb_768_hnsw: %', SQLERRM;
END $$;

-- ─── remediation_patterns ────────────────────────────────────────────────
DROP INDEX IF EXISTS idx_patterns_emb_1536_hnsw;
DROP INDEX IF EXISTS idx_patterns_emb_768_hnsw;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_patterns_emb_1536_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_patterns_emb_1536_hnsw
                 ON remediation_patterns
                 USING hnsw ((embedding::vector(1536)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)
                 WHERE embedding IS NOT NULL
                   AND vector_dims(embedding) = 1536';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping idx_patterns_emb_1536_hnsw: %', SQLERRM;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_patterns_emb_768_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_patterns_emb_768_hnsw
                 ON remediation_patterns
                 USING hnsw ((embedding::vector(768)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)
                 WHERE embedding IS NOT NULL
                   AND vector_dims(embedding) = 768';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping idx_patterns_emb_768_hnsw: %', SQLERRM;
END $$;
