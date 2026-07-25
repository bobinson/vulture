# 0045 — Validation phase · Rollback plan

**Last updated**: 2026-05-20

The validation phase is **additive and behind a single feature flag**.
Disabling it returns the audit pipeline to the exact behaviour it had
in commit `b0df208` (last commit before this feature). The DB
migration is non-destructive (adds nullable columns); rolling it back
is optional and only needed if the new columns are causing operational
pain.

## Layered rollback strategy

Three layers, in order of preferred-to-disruptive:

1. **Disable the feature flag** (instant, no migration).
2. **Revert the audit-runner integration commit** (skip validate
   entirely; DB columns stay in place but go unused).
3. **Full revert + migration rollback** (remove the new module, drop
   the validation_* columns).

### Layer 1 — Disable the feature flag

Set on the host running the agents:

```sh
export VULTURE_DISABLE_VALIDATE=true
```

Or in `config.ini`:

```ini
[validate]
enabled = false
```

Effects:

- `is_enabled(config)` returns false; the validate block in
  `run_combined_audit` is skipped wholesale.
- Findings come out of the audit runner with no `validation` field.
- Backend stores them with `validation_status = NULL`,
  `validation = NULL`.
- Frontend: `ValidationBadge` renders `validation_status = NULL` as
  "not yet validated" (neutral; default filter shows them).

What stays in place: DB columns, the package, CI tests, the frontend
column (just renders blank). Everything is dormant but operational.

Reversal: unset the env var; behavior returns instantly on next
audit. No data loss.

### Layer 1.5 — Per-audit opt-out

If only specific audits are problematic, pass
`config.disable_validate = true` in the audit-create request body:

```json
POST /api/audits
{
  "source_id": "...",
  "types": ["chaos", "owasp", "soc2", "cwe", "xss", "ssdf", "asvs"],
  "config": { "disable_validate": true }
}
```

Useful for compliance-evidence audits where you want the raw scan
output without any classifier metadata at all (note: compliance mode
keeps classifier metadata but doesn't filter — Layer 1.5 strips both).

### Layer 2 — Revert the audit-runner integration commit

If validate is silently breaking SSE pacing, throwing in production,
or producing spurious classifications and the feature flag isn't
enough:

```sh
git revert <validate-runner-integration-commit>
git push
```

Effects:

- The validate import + invocation is removed from
  `agents/shared/shared/audit_runner.py`.
- The `shared.validate` package stays in the repo (no production
  code calls into it).
- Backend + frontend still know about `validation_status` columns
  and the `ValidationBadge` component, but they always render
  `NULL` because nothing writes to the columns.
- Existing audits with populated validation columns continue to
  render correctly.

Reversal: `git revert` the revert.

### Layer 3 — Full revert + migration rollback

If the DB columns become a problem (storage cost, query plan
regression, JSONB indexing issues):

```sh
# 1. Revert the feature merge commit.
git revert -m 1 <merge-commit-sha>
git push
```

This removes:

- `agents/shared/shared/validate/`
- The validate block from `run_combined_audit`
- `backend/internal/service/audit_aggregator.go` extensions
- `backend/internal/handler/finding_label_handler.go`
- `frontend/src/components/results/ValidationBadge.tsx`
- The `validation_status` query parameter on `/api/audits/:id/findings`
- The `validation_*` columns from the migration script

```sh
# 2. Apply the rollback DDL by hand. The project's auto-migration
#    runner (feature 0040) is forward-only — there is no down-script
#    mechanism, by design. Operators run the DROP statements
#    explicitly:

# --- Postgres (Mode B central server) ---
psql "$VULTURE_DB_DSN" <<'SQL'
BEGIN;
DROP INDEX IF EXISTS idx_findings_validation_status;
DROP INDEX IF EXISTS idx_audit_memories_label_team;
ALTER TABLE findings
    DROP COLUMN IF EXISTS instance_count,
    DROP COLUMN IF EXISTS rolled_up_into,
    DROP COLUMN IF EXISTS is_rollup,
    DROP COLUMN IF EXISTS validation,
    DROP COLUMN IF EXISTS validation_confidence,
    DROP COLUMN IF EXISTS validation_status;
ALTER TABLE audit_memories
    DROP COLUMN IF EXISTS labelled_at,
    DROP COLUMN IF EXISTS labelled_by,
    DROP COLUMN IF EXISTS user_label;
COMMIT;
SQL

# --- SQLite (Mode A dev / Mode E install) ---
# SQLite supports DROP COLUMN as of 3.35 (2021). Mode A / E always
# ship with a newer SQLite than that. Otherwise the operator must
# CREATE-TABLE-RENAME-COPY (SQLite docs cover the pattern).
sqlite3 "$VULTURE_DB_PATH" <<'SQL'
BEGIN;
DROP INDEX IF EXISTS idx_findings_validation_status;
DROP INDEX IF EXISTS idx_audit_memories_label;
ALTER TABLE findings DROP COLUMN instance_count;
ALTER TABLE findings DROP COLUMN rolled_up_into;
ALTER TABLE findings DROP COLUMN is_rollup;
ALTER TABLE findings DROP COLUMN validation;
ALTER TABLE findings DROP COLUMN validation_confidence;
ALTER TABLE findings DROP COLUMN validation_status;
ALTER TABLE audit_memories DROP COLUMN labelled_at;
ALTER TABLE audit_memories DROP COLUMN labelled_by;
ALTER TABLE audit_memories DROP COLUMN user_label;
COMMIT;
SQL
```

Also remove the now-orphan migration file from the auto-runner's
search:

```sh
# Or: ship the revert PR with a no-op patch that comments-out the
# CREATE INDEX / ALTER lines in 017_validation_columns.sql so re-runs
# are silent.
git rm backend/internal/repository/migrations/017_validation_columns.sql
```

(The runner is idempotent — re-applying 017 after the revert is a
no-op given `IF NOT EXISTS` guards — but removing the file keeps the
migrations sequence tidy.)

**Data loss**: any thumbs-up/down feedback collected during the
feature's lifetime is lost. Document this in the revert PR; export
`audit_memories.user_label` before running the down migration if you
want to keep the corpus for re-enablement later.

### Layer 4 — Yank a buggy validate logic without reverting

A specific layer (e.g., L5 LLM judge) is producing bad demotions:

```sh
# Disable just that layer:
export VULTURE_DISABLE_VALIDATE_L5=true
# or in code: ValidateConfig(enable_l5=False)
```

Per-layer kill switches let you keep the rest of validate while
isolating the problematic layer. Each layer is independent and the
voter (V7) tolerates missing layers — they just don't contribute
weight.

## Specific component rollback notes

### DB rollback when the column is referenced by queries

Backend code may already be doing `SELECT validation_status FROM
findings WHERE …` in indexed queries. The down migration must run
*after* the backend is redeployed without those references — either:

1. Deploy a backend that ignores the validation_* columns (Layer 2
   above leaves them in the schema but stops populating them; reads
   tolerate NULL).
2. THEN run the column-drop migration.

Order matters: dropping the column while the backend still references
it causes 500s.

### Frontend rollback without backend rollback

If only the UI is causing problems (e.g., the new column breaks
mobile layout):

```sh
git revert <frontend-validation-commit>
```

Backend stays populated; old UI clients just don't show validation.
Reversal: `git revert` the revert.

### Memory contamination cleanup

If a wave of bad user-labels has poisoned L4's near-neighbor lookups:

```sql
-- Wipe user-supplied labels (keeps the embeddings):
UPDATE audit_memories SET user_label = NULL,
                         labelled_by = NULL,
                         labelled_at = NULL;
```

L4 returns "novel" for every finding until labels accumulate again.
Validate continues to work; just loses the memory-prior signal.

## Security-incident response (if the feature itself becomes the
vector)

A pathological case worth planning for: a malicious finding-label
post that causes L4 to mass-demote real bugs.

### SI-1. Disable label POSTs

```sh
# Backend-side feature flag:
export VULTURE_DISABLE_LABEL_POST=true
```

`POST /api/findings/:id/label` returns 404. Existing labels stay in
place but no new ones land.

### SI-2. Audit the label corpus

```sql
SELECT labelled_by, COUNT(*) AS labels, MIN(labelled_at), MAX(labelled_at)
FROM audit_memories
WHERE user_label IS NOT NULL
GROUP BY labelled_by
ORDER BY labels DESC;
```

A single user with thousands of FP labels deposited in a short
window is the smoking gun. Wipe their labels:

```sql
UPDATE audit_memories SET user_label = NULL,
                         labelled_by = NULL,
                         labelled_at = NULL
WHERE labelled_by = '<attacker-uuid>';
```

### SI-3. Re-validate affected audits

```sh
# Re-run validate against historic audits using the post-cleanup memory:
vulture scan --revalidate-audit <audit-id>
```

(`--revalidate-audit` is a thin CLI wrapper — pulls findings, re-runs
`shared.validate.validate(...)`, persists updated `validation_*`
columns. Doesn't re-run scan or LLM phases.)

## Risk matrix (rollback-time concerns)

| Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|
| Disable flag missed during incident | low | medium | Documented prominently in this rollback plan; `vulture doctor` reports the validate-enabled state |
| Migration down fails on Postgres (FK constraints) | low | high | `ON DELETE SET NULL` in the up migration; down migration drops in reverse order with `IF EXISTS` |
| Frontend cached JS still calls `/api/findings/:id/label` after server-side disable | medium | low | Endpoint returns 404 cleanly; UI handles 404 by showing the buttons as disabled with a "feature disabled" tooltip |
| Existing audits' validation data displays inconsistently after Layer 2 revert | low | low | Data remains in DB; the UI renders past audits using the column when present, NULL otherwise. Roll-forward of new audits without validate is the documented behavior |
| L5 LLM-judge cost runaway | low | medium | Already opt-in; default-off via `VULTURE_USE_VALIDATE_LLM=true`. The per-layer kill switch covers it |
| Drift detection triggers false-alarm reverts | medium | low | The "demotion rate spiked >2× week-over-week" alert is informational, not auto-acting. Operator decides whether to invoke Layer 1 |

## Decision: when to invoke each layer

- **Layer 1 (env flag)** — any time validate misbehaves in production.
  Free, instant, fully reversible. The default response to any
  validate-related incident.
- **Layer 2 (revert integration commit)** — if Layer 1 fixes the
  user-visible problem but the feature flag itself becomes
  load-bearing (e.g., production runbook clutter). Code-level
  rollback while preserving the schema for future re-enablement.
- **Layer 3 (full revert + migration drop)** — only if the DB
  columns are causing operational pain (storage, query plans, etc.)
  AND there's no near-term plan to re-enable. **Loses the
  human-feedback label corpus.**
- **Layer 4 (per-layer kill switches)** — surgical: turn off the one
  bad layer (most likely L4 or L5) while keeping the rest. Use when
  you can identify the misbehaving signal.

## Recovery from a bad release

If a release introduces a validate bug that ships to users:

1. **Immediately**: Layer 1 (disable flag) on the central server +
   document the flag in the release notes for native installs.
2. **Within 24 h**: yank the release per the 0044 rollback plan
   (cosign tag delete + new release with the validate change reverted
   per Layer 2).
3. **For native-install users on the bad release**: `vulture doctor`
   reports the validate-enabled state and the operator/user can set
   `VULTURE_DISABLE_VALIDATE=true` in `config/.env` until they
   upgrade.

## What survives by layer

| Item | Layer 1 (env flag) | Layer 1.5 (per-audit) | Layer 2 (revert integration) | Layer 3 (full revert + drop columns) |
|---|---|---|---|---|
| Scan findings (raw) | ✓ | ✓ | ✓ | ✓ |
| `validation_status` column on findings | ✓ (populated until disabled) | ✓ (populated for prior audits) | ✓ (column stays, unwritten) | ✗ (dropped) |
| `validation` JSON blob | ✓ | ✓ | ✓ | ✗ |
| `audit_memories.user_label` corpus | ✓ | ✓ | ✓ | ✗ (data loss; export first) |
| Thumbs-up/down UI buttons | ✓ (rendered but writes 404) | ✓ | ✗ (frontend revert) | ✗ |
| `POST /api/findings/:id/label` endpoint | ✓ (or 404 per SH7) | ✓ | ✗ | ✗ |
| Validate CI gates (separation invariants, perf) | ✓ | ✓ | ✗ | ✗ |
| L4 HNSW index on `audit_memories` | ✓ | ✓ | ✓ | ✗ |
| `vulture doctor` validate diagnostics | ✓ | ✓ | ✗ | ✗ |

## What survives every rollback layer

- Scan findings (raw): always present in `findings` table.
- Audit history: never affected by validate state.
- Existing modes A–E: untouched; validate only modifies behavior
  inside `run_combined_audit`.
- Memory + embeddings (feature 0006): the embedding column remains;
  only the `user_label` field is feature-0045-specific.
- Discover and prove agents: still callable directly via the API
  even if validate is disabled (they just receive un-validated
  findings).

## References

- Feature 0040 (auto-migration runner): handles applying both up
  and down SQL automatically at backend startup.
- Feature 0044 rollback plan: parallel structure (Layer 1 / 2 / 3
  shape).
- Feature 0006 rollback plan: covers the underlying memory layer
  whose columns this feature extends.
