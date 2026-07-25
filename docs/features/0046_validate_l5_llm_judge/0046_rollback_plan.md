# 0046 — Rollback plan

## Summary

L5 is **opt-in by default** (`VULTURE_USE_VALIDATE_LLM=false`). Disabling
the flag fully removes L5's behaviour without any code or data
changes — this is the operational rollback path. Code removal is only
necessary for a permanent rip-out.

## Operational rollback (per-deployment, zero-downtime)

If L5 is misbehaving (excessive cost, parse errors flooding logs,
hallucinated FP suppression) and the operator wants to disable it
**right now**:

```bash
# bare-metal dev mode:
unset VULTURE_USE_VALIDATE_LLM
./scripts/vulture.sh stop && ./scripts/vulture.sh dev lmstudio --pg

# docker:
# remove VULTURE_USE_VALIDATE_LLM from .env, then:
docker compose up -d backend
```

After the restart:
- New audits run validate with L1+L2 only (Python) + L3+L4 (Go).
- Existing `audit_memories` rows keep their `validation` JSON
  unchanged; the `validation.checks` array still contains historical
  `llm_judge` entries but the voter no longer adds new ones.
- Frontend continues to render historical `llm_judge` checks (they
  are JSON, no special UI required).

Verification:

```bash
# No new L5 checks should appear after the restart:
docker compose exec postgres psql -U vulture -d vulture -c "
  SELECT COUNT(*) FROM audit_memories
  WHERE created_at > NOW() - INTERVAL '5 minutes'
    AND validation::jsonb ? 'checks'
    AND validation::jsonb #> '{checks}' @> '[{\"id\":\"llm_judge\"}]';
"
# Expected: 0
```

## Per-audit rollback

A single audit can disable L5 by passing `config.validate.llm=false`
in the audit request body, or by omitting the `--validate-llm` CLI
flag. No global change required.

## Cache invalidation

If L5 is disabled permanently and the operator wants to reclaim
storage:

```sql
-- Drops cached verdicts; safe to run any time, L5 reseeds on next call.
UPDATE audit_memories SET l5_verdict_cache = NULL
WHERE l5_verdict_cache IS NOT NULL;
```

The `l5_verdict_cache` column itself is harmless to leave in place
(nullable, JSONB) — see the next section if you want to remove it.

## Schema rollback (migration 019)

Migration 019 only **adds** a nullable JSONB column + a hash-style
index. Down migration is straightforward:

```sql
-- Run manually; the migration runner has no auto-down.
DROP INDEX IF EXISTS idx_audit_memories_l5_cache;
ALTER TABLE audit_memories DROP COLUMN IF EXISTS l5_verdict_cache;
DELETE FROM schema_migrations WHERE version = 19;
```

Note: per feature 0040, migration files don't ship with `_down.sql`;
manual rollback SQL is the contract.

## Code rollback (permanent removal)

If the team decides L5 was a net negative and wants to delete the
feature outright:

1. `git rm -r agents/shared/shared/validate/llm_judge.py \
       agents/shared/shared/validate/prompts/ \
       agents/shared/tests/unit/validate/test_llm_judge.py \
       agents/shared/tests/unit/validate/test_language_detect.py \
       docs/features/0046_validate_l5_llm_judge/`
2. Revert the `validate/__init__.py` L5 invocation block (the patch
   sits between two clearly-marked comments
   `# ── L5 llm_judge ──` … `# ── /L5 llm_judge ──`).
3. Revert the `types.py` `ValidateConfig.validate_llm` field.
4. Revert the CLI flag block (`--validate-llm`, `--validate-llm-top-n`)
   in `cli/main.go`.
5. Revert the `audit_handler.go` config-passthrough patch (5 LOC).
6. Drop migration 019 per the schema rollback section above.

The audit_runner's existing validate-stage block (already shipped in
0045) continues to work; removing L5 leaves L1+L2 (Python) and
L3+L4 (Go) functional and unchanged.

## What does NOT need to roll back

- Migrations 001–018 — untouched by 0046.
- `audit_memories.validation` JSON column — schema unchanged; only
  the `checks` array contents grew to optionally include
  `llm_judge` entries, which are inert if no longer produced.
- Frontend — renders `validation.checks` as opaque JSON; no UI work
  was added for L5 in this feature.
- Prompts directory — pure data; removing the code already removes
  the dependency.

## Acceptance criteria for a successful rollback

After operational rollback:

- `VULTURE_USE_VALIDATE_LLM` is unset / `false` in the running
  environment.
- A test audit completes with **zero** new `llm_judge` entries in
  `audit_memories.validation.checks`.
- The audit's elapsed time falls back to the pre-0046 baseline
  (within 5% of the L1+L2 latency).
- `expected dimensions` / `database is locked` / other regressions
  introduced by adjacent fixes remain absent.

After schema rollback (additionally):

- `\d audit_memories` no longer lists `l5_verdict_cache`.
- `SELECT version FROM schema_migrations` no longer lists `19`.

## Lessons-learned hook

If L5 is rolled back due to a soundness issue (model hallucination
hiding real bugs), document the case in `docs/features/0045_validation_phase/0045_implementation_status.md`
under "L5 disabled — reason" so feature 0045's plan can be updated
to reflect the operational reality.
