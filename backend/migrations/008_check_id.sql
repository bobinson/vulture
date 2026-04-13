-- Add hierarchical check_id column for stable cross-session dedup and grouping.
-- Format: domain.category.specific (e.g. cwe.injection.sql, owasp.auth.weak_hash)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS check_id TEXT NOT NULL DEFAULT '';
