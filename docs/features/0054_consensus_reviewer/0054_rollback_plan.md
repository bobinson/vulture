# 0054 — Rollback plan

The feature is gated end-to-end behind `VULTURE_CONSENSUS_REVIEWER` (default `false` in v1). Rollback is therefore graceful in most scenarios — flip the flag, redeploy, audits revert to legacy `deduplicateCrossAgent` weighting bit-for-bit.

## Triggers

| Trigger | Action |
|---|---|
| Consensus service produces incorrect tier classification | Set `VULTURE_CONSENSUS_REVIEWER=false`, redeploy backend. Existing canonical_findings rows remain (read-only); voter ignores them; UI falls back to per-agent finding view. |
| Reviewer LLM blows past token budget repeatedly | Set `VULTURE_REVIEWER_LLM_ENABLED=false`. Consensus stage still runs but skips LLM-on-conflict. No DB change required. |
| Trust ledger modifier swings producing user-visible severity drift | Set `VULTURE_TRUST_LEDGER_ENABLED=false`. Voter uses `modifier=1.0` for all plugins. Last computed modifiers remain in DB but ignored. |
| Coverage manifests in a plugin produce incorrect competent-silence inference | Ship a plugin point release (`0.1.x`) that downgrades the affected category to `tier=advisory`. Operators redeploy that plugin. |
| Canonical lineage backfill corrupted (unlikely; INSERT-only) | `DELETE FROM canonical_findings WHERE audit_id IN (...affected...)` and re-run backfill. Per-agent lineage records are untouched; nothing user-visible lost. |
| Reviewer agent crashes / OOMs in production | `docker compose stop agent-reviewer`. Consensus service degrades gracefully — emits `verdict='needs_human'` for disputed groups; audit completes. |
| Migration failure mid-deploy | Migrations are additive (`CREATE TABLE` / `ADD COLUMN`); standard migration rollback applies (drop new tables; drop `findings.canonical_finding_id` column). No data loss. |
| Full revert | `git revert <0054-merge-sha>`. Migrations rolled back via standard `down` migrations (one per new table). Plugin contract v1.1 fields ignored by reverted backend (harmless on existing manifests). |

## Data implications

| Table | On rollback |
|---|---|
| `plugin_coverage_manifests` | Drop. No application data lost (declared metadata only). |
| `scan_completion_acks` | Drop. Per-audit declarative state; not user-facing. |
| `canonical_findings` | Drop. UI falls back to per-agent findings; users see the same data as pre-0054. |
| `canonical_lineages` | Drop. Per-agent `finding_lineages` records preserved; lineage history continues from where it was. |
| `plugin_trust_ledger` | Drop or retain (read-only). Modifier defaults to 1.0 when reverted; no live use. |
| `findings.canonical_finding_id` | Drop column; rows otherwise intact. |

No data migration is required to roll back. New tables are additive; per-agent lineage remains the source of truth for cross-audit continuity until 0054 lands again.

## No user-visible regressions on revert

With `VULTURE_CONSENSUS_REVIEWER=false`:

- Voter weights match pre-0054 (legacy L3 `deduplicateCrossAgent` boost path preserved as fallback).
- Lineage UI shows per-agent records (the v1 default until canonical promotion ships).
- No SSE events of the new types (`scan_completed`, `consensus_verdict`, `reviewer_budget_exhausted`) are emitted; frontend ignores absent events.
- Plugin contract v1.1 manifests load on a v1.0 backend (forward-compatible; new fields ignored).

## Forward-fix vs. revert

Default to **forward-fix**:

- Bad tier classification → patch `consensus_service.go`, ship a backend point release.
- Bad weight calibration → tune env vars (`VULTURE_REVIEWER_LLM_*`, weight caps).
- Bad coverage manifest → ship plugin point release.

**Revert** is reserved for:

- Schema-level regression breaking unrelated queries (escalated to migration rollback).
- Voter-level regression causing user-visible severity flip on >1% of findings (escalated; flag-off first, then revert if patch unsafe).
