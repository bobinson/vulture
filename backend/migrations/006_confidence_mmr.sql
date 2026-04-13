-- Migration 006: Confidence scoring and pattern profiles for self-learning.
-- Adds confidence_score to audit_memories for tracking finding reliability.
-- Creates codebase_pattern_profiles for per-codebase pattern tracking.

-- Confidence score: 0.0-1.0, tracks how reliable a finding is across audits.
-- Starts at 0.5 (neutral), increases when confirmed, decreases on false_positive.
ALTER TABLE audit_memories ADD COLUMN confidence_score REAL NOT NULL DEFAULT 0.5;

-- CWE-specific metadata from catalog enrichment.
ALTER TABLE audit_memories ADD COLUMN cwe_name TEXT;
ALTER TABLE audit_memories ADD COLUMN cwe_likelihood TEXT;

-- Index for confidence-weighted queries.
CREATE INDEX idx_memories_confidence ON audit_memories (confidence_score DESC)
    WHERE is_archived = false;

-- Pattern profiles: track which CWE patterns are most relevant per codebase.
-- Used by self-learning to prioritize patterns that have been confirmed before.
CREATE TABLE codebase_pattern_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    codebase_path   TEXT NOT NULL,
    agent_type      VARCHAR(50) NOT NULL,
    category        VARCHAR(200) NOT NULL,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    confirmed_count INTEGER NOT NULL DEFAULT 0,
    false_pos_count INTEGER NOT NULL DEFAULT 0,
    avg_confidence  REAL NOT NULL DEFAULT 0.5,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_pattern_profile UNIQUE (codebase_path, agent_type, category)
);

CREATE INDEX idx_pattern_profiles_path ON codebase_pattern_profiles (codebase_path, agent_type);
