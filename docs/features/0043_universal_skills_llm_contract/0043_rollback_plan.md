# 0043 — Rollback Plan

This feature mostly adds new code (the `mode.py` helper, the prove
rule-based runner, the SSE event, the analysis_mode column) and
refactors two agents (prove + discover) to honor the contract. Rollback
is split per phase because the scope spans the agent layer, backend
schema, and CI.

## Pre-flight

1. Identify which phases are live in the deployment you're rolling
   back. Read `0043_implementation_status.md` for the canonical state
   and `git log --oneline -- docs/features/0043_*` for shipped commits.
2. Snapshot the live findings table:
   ```bash
   docker compose exec postgres pg_dump -U vulture -d vulture \
     -t findings -t prove_results > findings_backup_$(date +%Y%m%d_%H%M%S).sql
   ```
3. Note the values of `VULTURE_USE_LLM`, `VULTURE_REQUIRE_LLM`, and any
   feature flags (`VULTURE_PROVE_SKILLS_MODE`, etc.) on the running
   deployment so you can reproduce them after rollback.

## Rollback by phase (newest first)

### Phase 8 — Default-on cutover

- Re-introduce the feature flag (`VULTURE_PROVE_SKILLS_MODE` defaulting
  to false).
- Skills-mode prove only runs when explicitly enabled.
- Discover defaults back to LLM-augmented unless flag is set.

This phase is metadata-only — toggling it doesn't touch DB or schema.

### Phase 7 — Documentation

- Revert the `CLAUDE.md` edits across agents.
- Revert `agent_protocol.md` and `cli_usage.md` updates.

No runtime effect.

### Phase 6 — CI test

- Delete `.github/workflows/skills-mode-purity.yml`.
- Existing CI continues unchanged.

No runtime effect.

### Phase 5 — `degraded_mode` event + `analysis_mode` field

- Frontend `Finding` type drops the optional `analysis_mode` field
  (revert the type + the small UI label).
- Go `model.Finding` reverts; repos drop INSERT/SELECT references to
  `analysis_mode`.
- Migration is **left in place** — `analysis_mode` column persists in
  the `findings` table with its default value. Removing the column
  would require a destructive `DROP COLUMN`; given the column is
  additive and harmless, leave it. (Operators can drop it manually if
  desired.)
- Backend `agui/translator.go` reverts any explicit case for
  `degraded_mode`. The event becomes unrecognized — frontends ignore
  it gracefully (degraded-banner suppression).

### Phase 4 — Discover gating

- Revert `discover_agent/agent.py::run_discover` to the pre-0043
  unconditional-LLM behavior.
- Discover now requires LLM in skills-only deployments (regression to
  pre-0043 state).

### Phase 3 — Prove rewrite

- Revert `prove_agent/agent.py::run_prove` to the pre-0043 form
  (LLM-mandatory, AuthenticationError loops if no API key).
- Delete `prove_agent/runners/rule_based.py`.
- Strategy modules (`strategies/{chaos,owasp,…}.py`) are NOT removed —
  they pre-date 0043 and stay.
- Operators using `dev skills` see the cooldown loops return.

### Phase 2 — Scan-agent audit

Documentation-only. Revert the audit table updates in the status doc.

### Phase 1 — Contract + helper

- Delete `agents/shared/shared/llm/mode.py`.
- Delete `agents/shared/tests/unit/llm/test_mode.py`.
- Delete `docs/architecture/agent_llm_contract.md`.
- Phase 3 / Phase 4 must already be rolled back first (they import
  `mode.py`).

## Full rollback

```bash
git revert <0043 commits in reverse order: 8 → 7 → 6 → 5 → 4 → 3 → 2 → 1>
```

Schema-level: the `analysis_mode` column persists by design (rolling
back the column requires a destructive `ALTER TABLE DROP COLUMN`). To
drop manually:

```sql
ALTER TABLE findings DROP COLUMN IF EXISTS analysis_mode;
ALTER TABLE prove_results DROP COLUMN IF EXISTS analysis_mode;
```

Optional. The column has no application-side reader after rollback.

## What this rollback does NOT do

- Doesn't undo feature 0039's `audits.degraded_reason` column or the
  `LLMHealthStatus.message()` helper. Those stay regardless.
- Doesn't undo feature 0041's Mode-B CI smoke (if shipped by then).
- Doesn't undo feature 0042's secret-scan skill.
- Doesn't change `VULTURE_USE_LLM` or `VULTURE_REQUIRE_LLM` semantics
  (those are pre-existing).

## Smoke checks after rollback

```bash
# 1) Backend starts and accepts requests
curl -fsS http://localhost:28080/health

# 2) Skills-mode dev stack starts but prove + discover regress to
#    LLM-mandatory (pre-0043 behavior):
./scripts/vulture.sh dev skills
# Expect agent-prove cooldown loops to return (this confirms
# rollback is complete).

# 3) Existing scan-agent smoke
~/src/vulture/cli/bin/vulture scan agents/shared/shared/llm/ \
  --types chaos --no-cache --wait
# Should still complete (scan agents weren't touched by 0043).

# 4) Findings table query
docker compose exec postgres psql -U vulture -d vulture -p 25432 \
  -c "SELECT COUNT(*) FROM findings WHERE analysis_mode IS NOT NULL;"
# Returns the historical row count (column persists by default).
```

If all four behave as expected, rollback is clean.

## Post-rollback gap

After full rollback, the original audit gap returns:

- `dev skills` mode produces cooldown-loop spam from prove + discover
  again.
- Operators who don't have LLM keys can't usefully run prove or
  discover.
- No CI signal that agents respect `VULTURE_USE_LLM=false`.

If you rolled back due to instability in the `mode.py` helper or the
prove rewrite, prefer rolling back **only the affected phase** rather
than the whole feature. The Phase 1 helper itself is small (~50 lines)
and unlikely to be the source of an issue.

## Risk-assessment matrix

| What rolls back | Affects | Operator-visible change |
|---|---|---|
| Phase 8 (cutover flag) | Prove/discover skills mode behind a flag | None visible if flag wasn't enabled |
| Phase 7 (docs) | Operator docs | Outdated guides |
| Phase 6 (CI test) | CI signal | No detection of skills-mode regressions |
| Phase 5 (SSE event + column) | UI labels | `analysis_mode` label disappears; no functional effect |
| Phase 4 (discover gating) | Discover behavior | LLM-mandatory regression |
| Phase 3 (prove rewrite) | Prove behavior | Cooldown loops return; AuthenticationError spam |
| Phase 2 (audit results) | Doc clutter only | None |
| Phase 1 (contract + helper) | Foundation | Phase 3 / 4 must roll back first |
