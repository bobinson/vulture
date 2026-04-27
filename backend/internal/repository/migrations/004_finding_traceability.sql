-- Migration 004: Finding Lifecycle Traceability
-- Adds git metadata to sources, fingerprints to findings,
-- and creates finding_lineage + lineage_events tables.

-- Add git metadata to sources
ALTER TABLE sources ADD COLUMN IF NOT EXISTS git_branch TEXT;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS git_commit_hash TEXT;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS git_commit_short TEXT;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS git_remote_url TEXT;

-- Add fingerprint to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings (fingerprint) WHERE fingerprint IS NOT NULL;

-- Finding lineage: cross-audit identity and lifecycle
CREATE TABLE IF NOT EXISTS finding_lineage (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fingerprint     TEXT NOT NULL,
    source_path     TEXT NOT NULL,
    agent_type      VARCHAR(50) NOT NULL,
    current_status  VARCHAR(30) NOT NULL DEFAULT 'open'
        CHECK (current_status IN ('open','in_progress','resolved','accepted_risk','false_positive','fixed','regression')),
    notes           TEXT,
    ticket_url      TEXT,
    first_audit_id  UUID NOT NULL REFERENCES audits(id),
    first_found_at  TIMESTAMPTZ NOT NULL,
    first_commit    TEXT,
    latest_audit_id UUID REFERENCES audits(id),
    latest_found_at TIMESTAMPTZ,
    latest_commit   TEXT,
    fixed_audit_id  UUID REFERENCES audits(id),
    fixed_at        TIMESTAMPTZ,
    fixed_commit    TEXT,
    severity        VARCHAR(20) NOT NULL,
    category        VARCHAR(200) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    file_path       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_lineage UNIQUE (fingerprint, source_path, agent_type)
);

CREATE INDEX IF NOT EXISTS idx_lineage_source_path ON finding_lineage (source_path);
CREATE INDEX IF NOT EXISTS idx_lineage_status ON finding_lineage (current_status);

-- Lineage events: audit trail
CREATE TABLE IF NOT EXISTS lineage_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    lineage_id  UUID NOT NULL REFERENCES finding_lineage(id) ON DELETE CASCADE,
    event_type  VARCHAR(30) NOT NULL
        CHECK (event_type IN ('detected','status_change','fixed','regression','note_added')),
    audit_id    UUID REFERENCES audits(id),
    git_commit  TEXT,
    git_branch  TEXT,
    old_status  VARCHAR(30),
    new_status  VARCHAR(30),
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_lineage_events_lineage ON lineage_events (lineage_id, created_at);
