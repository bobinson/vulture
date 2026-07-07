-- Migration 023: persist the OWASP Top 10 coverage manifest on the audit.
--
-- Feature 0063: the OWASP agent maps CWE findings onto OWASP categories and
-- emits a per-category coverage manifest on its result event. Without storing
-- it, the manifest was live-stream-only — a page reload or a later view of a
-- completed audit lost it (the completed-audit replay synthesizes snapshots
-- from findings + score only). Persist it as an opaque JSON blob so it
-- survives reload/replay and is served via GET /api/audits/:id.
--
-- Nullable + additive: existing rows and non-OWASP audits are unaffected.
-- Idempotent.

ALTER TABLE audits
    ADD COLUMN IF NOT EXISTS owasp_coverage TEXT;
