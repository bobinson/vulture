-- Feature 0039: per-audit degraded-mode reason.
--
-- When LLM is unreachable at audit-creation time, the canonical
-- LLMHealthStatus.message() string is persisted here so the UI banner
-- can render it even after the audit completes. Empty string means
-- "audit ran in normal mode" (LLM was reachable, or LLM was disabled
-- by config — both are non-degraded states).
--
-- Pure additive ALTER; safe to roll back by dropping the column.

ALTER TABLE audits ADD COLUMN IF NOT EXISTS degraded_reason TEXT NOT NULL DEFAULT '';
