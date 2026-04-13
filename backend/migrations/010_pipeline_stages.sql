-- Pipeline table for multi-stage audits (scan → discover → prove)
CREATE TABLE IF NOT EXISTS pipelines (
    id                TEXT PRIMARY KEY,
    target_url        TEXT NOT NULL,
    source_id         TEXT NOT NULL,
    stages            TEXT NOT NULL DEFAULT '[]',
    config            TEXT NOT NULL DEFAULT '{}',
    scan_audit_id     TEXT,
    discover_audit_id TEXT,
    prove_audit_id    TEXT,
    status            TEXT NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at      TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pipelines_source ON pipelines (source_id);
CREATE INDEX IF NOT EXISTS idx_pipelines_status ON pipelines (status);

-- Discover results table for structured discovery output
CREATE TABLE IF NOT EXISTS discover_results (
    id            TEXT PRIMARY KEY,
    audit_id      TEXT NOT NULL UNIQUE,
    target_url    TEXT NOT NULL,
    site_map_json TEXT NOT NULL DEFAULT '{}',
    url_count     INTEGER NOT NULL DEFAULT 0,
    api_count     INTEGER NOT NULL DEFAULT 0,
    form_count    INTEGER NOT NULL DEFAULT 0,
    technologies  TEXT NOT NULL DEFAULT '[]',
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_discover_results_target ON discover_results (target_url);
CREATE INDEX IF NOT EXISTS idx_discover_results_audit ON discover_results (audit_id);
