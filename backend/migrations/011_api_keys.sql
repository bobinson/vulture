CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    prefix      TEXT NOT NULL,
    hash        TEXT NOT NULL,
    name        TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '["read","write"]',
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by);
