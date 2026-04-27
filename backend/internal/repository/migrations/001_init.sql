-- Vulture Compliance Audit Platform - Database Schema
-- ISO 26262 ASIL-B: Data integrity critical

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Teams: organizational units
CREATE TABLE IF NOT EXISTS teams (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(255) NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users: authenticated platform users
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    name            VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member', 'viewer')),
    team_id         UUID REFERENCES teams(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_team ON users (team_id);

-- Sources: repositories or local paths being audited
CREATE TABLE IF NOT EXISTS sources (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type        VARCHAR(20) NOT NULL CHECK (type IN ('git', 'local')),
    url         TEXT,
    path        TEXT NOT NULL,
    file_count  INTEGER DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sources_created ON sources (created_at DESC);

-- Audits: audit runs
CREATE TABLE IF NOT EXISTS audits (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id     UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    types         TEXT[] NOT NULL DEFAULT '{}',
    config        JSONB NOT NULL DEFAULT '{}',
    status        VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    findings      JSONB DEFAULT '[]',
    scores        JSONB DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audits_source ON audits (source_id);
CREATE INDEX IF NOT EXISTS idx_audits_status ON audits (status);
CREATE INDEX IF NOT EXISTS idx_audits_created ON audits (created_at DESC);

-- Findings: individual audit findings (normalized from agent output)
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    audit_id        TEXT NOT NULL,
    agent_type      VARCHAR(50) NOT NULL,
    severity        VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category        VARCHAR(200) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_start      INTEGER NOT NULL DEFAULT 0,
    line_end        INTEGER NOT NULL DEFAULT 0,
    recommendation  TEXT NOT NULL DEFAULT '',
    refs            JSONB NOT NULL DEFAULT '[]',
    code_snippet    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings (audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_agent ON findings (agent_type);

-- Audit memories: vector-indexed findings for semantic search
-- Inspired by mem0ai/mem0 + jeffpierce/memory-palace architecture
CREATE TABLE IF NOT EXISTS audit_memories (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ,

    -- Source tracking
    audit_id            UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    agent_type          VARCHAR(50) NOT NULL,
    codebase_path       TEXT NOT NULL,

    -- Finding content
    finding_type        VARCHAR(100) NOT NULL,
    title               VARCHAR(500) NOT NULL,
    content             TEXT NOT NULL,
    severity            VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    compliance_ref      VARCHAR(100),
    category            VARCHAR(100),

    -- Searchability
    keywords            TEXT[] NOT NULL DEFAULT '{}',
    tags                TEXT[] NOT NULL DEFAULT '{}',
    file_paths          TEXT[] NOT NULL DEFAULT '{}',

    -- Vector embedding for semantic search
    embedding           vector(1536),

    -- Remediation tracking
    remediation_status  VARCHAR(30) DEFAULT 'open' CHECK (remediation_status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')),
    remediation_notes   TEXT,
    remediated_at       TIMESTAMPTZ,

    -- Lifecycle
    access_count        INTEGER DEFAULT 0,
    last_accessed_at    TIMESTAMPTZ,
    is_archived         BOOLEAN DEFAULT FALSE
);

-- HNSW index for vector similarity search (cosine distance).
-- Guarded with a dimension check so this migration stays idempotent even
-- after migration 002 strips dimensions from the embedding column (HNSW
-- requires a fixed dimension; an untyped `vector` column would fail here).
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relname = 'audit_memories' AND a.attname = 'embedding'
          AND format_type(a.atttypid, a.atttypmod) <> 'vector'
    ) THEN
        CREATE INDEX IF NOT EXISTS idx_memories_embedding_hnsw ON audit_memories
            USING hnsw (embedding vector_cosine_ops)
            WITH (m = 16, ef_construction = 64);
    END IF;
END $$;

-- Common query indexes
CREATE INDEX IF NOT EXISTS idx_memories_audit ON audit_memories (audit_id);
CREATE INDEX IF NOT EXISTS idx_memories_agent ON audit_memories (agent_type);
CREATE INDEX IF NOT EXISTS idx_memories_severity ON audit_memories (severity);
CREATE INDEX IF NOT EXISTS idx_memories_compliance ON audit_memories (compliance_ref) WHERE compliance_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_memories_remediation ON audit_memories (remediation_status);
CREATE INDEX IF NOT EXISTS idx_memories_finding_type ON audit_memories (finding_type);
CREATE INDEX IF NOT EXISTS idx_memories_archived ON audit_memories (is_archived) WHERE is_archived = FALSE;

-- Knowledge graph: relationships between findings
CREATE TABLE IF NOT EXISTS memory_edges (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_id       UUID NOT NULL REFERENCES audit_memories(id) ON DELETE CASCADE,
    target_id       UUID NOT NULL REFERENCES audit_memories(id) ON DELETE CASCADE,
    relation_type   VARCHAR(50) NOT NULL CHECK (relation_type IN (
        'same_issue', 'supersedes', 'derived_from', 'contradicts',
        'remediated_by', 'related_compliance', 'escalates_to', 'similar'
    )),
    strength        FLOAT NOT NULL DEFAULT 1.0 CHECK (strength >= 0 AND strength <= 1),
    bidirectional   BOOLEAN DEFAULT FALSE,
    edge_metadata   JSONB DEFAULT '{}',
    created_by      VARCHAR(50),

    CONSTRAINT uq_edge_triple UNIQUE (source_id, target_id, relation_type),
    CONSTRAINT check_no_self_loops CHECK (source_id != target_id)
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON memory_edges (source_id, relation_type);
CREATE INDEX IF NOT EXISTS idx_edges_target ON memory_edges (target_id);

-- Remediation patterns: shared knowledge for fixing common issues
CREATE TABLE IF NOT EXISTS remediation_patterns (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finding_type    VARCHAR(100) NOT NULL,
    compliance_ref  VARCHAR(100),
    pattern_name    VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL,
    code_example    TEXT,
    embedding       vector(1536),
    success_count   INTEGER DEFAULT 0,

    CONSTRAINT uq_pattern UNIQUE (finding_type, pattern_name)
);

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relname = 'remediation_patterns' AND a.attname = 'embedding'
          AND format_type(a.atttypid, a.atttypmod) <> 'vector'
    ) THEN
        CREATE INDEX IF NOT EXISTS idx_patterns_embedding_hnsw ON remediation_patterns
            USING hnsw (embedding vector_cosine_ops)
            WITH (m = 16, ef_construction = 64);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_patterns_finding_type ON remediation_patterns (finding_type);
