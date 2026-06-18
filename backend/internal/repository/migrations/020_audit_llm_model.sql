-- Migration 020: Record the LLM model per audit.
--
-- Feature 0055 — the audit record now stores which LLM the scan ran
-- against (VULTURE_LLM_MODEL captured at creation when VULTURE_USE_LLM is
-- enabled, else "skills-only"), so GET /api/audits/:id reports it. The
-- backend's configured model mirrors the agents' (both spawned from the
-- same launcher config) in the normal flow.
--
-- Idempotent: re-applying is a no-op. Older rows backfill to '' (which the
-- API omits via omitempty — "unknown / pre-migration").

ALTER TABLE audits
    ADD COLUMN IF NOT EXISTS llm_model TEXT NOT NULL DEFAULT '';
