-- Migration 015: Performance indexes (audit findings 2026-05-05).
--
-- Addresses:
--   * audit_memories has no vector index after 002 (sequential scan on
--     similarity searches). Recreate dimension-aware HNSW partial indexes
--     so 768d and 1536d embeddings each get an index without re-pinning
--     the column to a fixed dim. Queries must use the matching cast in
--     ORDER BY for the planner to pick the partial index.
--   * finding_lineage and lineage_events have FK columns without indexes,
--     so cascade deletes / parent updates on audits seq-scan those tables.
--   * memory_edges' OR (target_id, bidirectional) branch has no covering
--     index.
--   * confidence_score lookups scoped to an audit have no composite index.
--   * Several existing 'is_archived = false' filters lacked partial indexes.
--
-- Each index uses IF NOT EXISTS / DO blocks so repeated apply is a no-op.

-- ─── Vector indexes on audit_memories ─────────────────────────────────────
--
-- pgvector HNSW requires a fixed dimension at index build time, but
-- migration 002 made the column dimension-flexible. Solution: create
-- partial HNSW indexes on the cast expression, one per common dimension.
-- Queries that match the expression form (and the partial WHERE) can use
-- the index.
--
-- Skipped silently if pgvector is too old to support expression-based HNSW
-- (pre-0.5.0); in that case queries fall through to seq scan, which is the
-- existing behavior — no regression.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_memories_emb_1536_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_memories_emb_1536_hnsw
                 ON audit_memories
                 USING hnsw ((embedding::vector(1536)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)';
    END IF;
EXCEPTION WHEN OTHERS THEN
    -- pgvector version doesn't support expression-based HNSW; tolerate.
    RAISE NOTICE 'Skipping idx_memories_emb_1536_hnsw: %', SQLERRM;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_memories_emb_768_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_memories_emb_768_hnsw
                 ON audit_memories
                 USING hnsw ((embedding::vector(768)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping idx_memories_emb_768_hnsw: %', SQLERRM;
END $$;

-- Same for remediation_patterns.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_patterns_emb_1536_hnsw') THEN
        EXECUTE 'CREATE INDEX idx_patterns_emb_1536_hnsw
                 ON remediation_patterns
                 USING hnsw ((embedding::vector(1536)) vector_cosine_ops)
                 WITH (m = 16, ef_construction = 64)';
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
                 WITH (m = 16, ef_construction = 64)';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping idx_patterns_emb_768_hnsw: %', SQLERRM;
END $$;

-- ─── FK indexes on finding_lineage / lineage_events ──────────────────────
-- Without these, cascade DELETE on audits (or any UPDATE that touches the
-- referenced row) sequential-scans the lineage tables.

CREATE INDEX IF NOT EXISTS idx_lineage_latest_audit
    ON finding_lineage (latest_audit_id)
    WHERE latest_audit_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_lineage_fixed_audit
    ON finding_lineage (fixed_audit_id)
    WHERE fixed_audit_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_lineage_first_audit
    ON finding_lineage (first_audit_id);

CREATE INDEX IF NOT EXISTS idx_lineage_events_audit
    ON lineage_events (audit_id)
    WHERE audit_id IS NOT NULL;

-- Open-status query path: list lineage rows that are still actionable.
CREATE INDEX IF NOT EXISTS idx_lineage_open
    ON finding_lineage (source_path, agent_type, current_status)
    WHERE current_status IN ('open', 'in_progress');

-- ─── memory_edges composite for the (target_id, bidirectional) OR branch ─
-- GetEdges queries `WHERE source_id = $1 OR (target_id = $1 AND bidirectional = true)`.
-- The first branch has idx_edges_source; this index serves the second branch.

CREATE INDEX IF NOT EXISTS idx_edges_target_bidir
    ON memory_edges (target_id, bidirectional)
    WHERE bidirectional = TRUE;

-- ─── audit_memories: confidence + archived composite ─────────────────────
-- Audit-scoped confidence queries (e.g. ranked memories per audit) need
-- (audit_id, confidence_score) for index-only scan eligibility.

CREATE INDEX IF NOT EXISTS idx_memories_audit_confidence
    ON audit_memories (audit_id, confidence_score DESC)
    WHERE is_archived = FALSE;

-- Existing idx_memories_audit lacks the is_archived filter; add a partial
-- duplicate that excludes archived rows for hot list paths.
CREATE INDEX IF NOT EXISTS idx_memories_audit_active
    ON audit_memories (audit_id)
    WHERE is_archived = FALSE;

-- ─── prove_results: ensure FK index exists with type alignment hint ──────
-- Migration 005 created idx_prove_results_audit_id; the postgres_repo
-- ListAudits query casts `a.id::text` against `pr.audit_id` which is TEXT.
-- The original index is fine; this comment documents the type rationale
-- for future readers (no schema change needed here).
