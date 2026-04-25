-- Feature 0031: audit webhook callbacks
ALTER TABLE audits ADD COLUMN webhook_url TEXT;

CREATE TABLE IF NOT EXISTS audit_webhook_deliveries (
    id            TEXT PRIMARY KEY,
    audit_id      TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    delivered_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_audit ON audit_webhook_deliveries(audit_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON audit_webhook_deliveries(status);
