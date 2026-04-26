# 0039 — Rollback Plan

> Per-phase rollback. The schema change (`audits.degraded_reason` column) is the only persistent artifact; all other rollback is pure code revert.

## Rollback summary

| Phase | Rollback time | Data loss | User impact |
|---|---|---|---|
| 1 | ~5 min | none | LLM health probe unavailable |
| 2 | ~5 min | none | Agent `/health` returns old shape |
| 3 | ~5 min | none | `/api/llm/health` returns 404 |
| 4 | ~5 min | none | Launcher reverts to Ollama-only check |
| 5 | feature flag (column stays) | none | Per-audit preflight disabled |
| 6 | feature flag | none | Banner not shown |
| 7 | tests-only | none | none |
| 8 | feature flag | none | Strict mode disabled |

Worst-case full rollback: ~20 minutes. The `degraded_reason` column on `audits` is harmless to leave even if Phase 5 is rolled back (default empty string; existing readers ignore unknown fields).

---

## Phase 1 — Canonical health probe

### Triggers
- A provider probe causes audit-time crashes (unlikely; probes are fully wrapped in try/except).
- Excessive latency on `/health` due to slow probes (timeout default 3s; should be hard cap).

### Procedure

1. Revert the merge commit for Phase 1.
2. Confirm `agents/shared/shared/llm/health.py` is deleted.
3. Confirm `agents/shared/tests/unit/llm/test_health.py` is deleted (if Phase 7 also rolled back).
4. Rebuild agent images.

### Per-provider rollback

If only one provider's probe is buggy (say `_probe_anthropic`), edit `health.py` to short-circuit that provider to a default-degraded response while keeping others working:

```python
async def _probe_anthropic(model, timeout):
    return LLMHealthStatus(
        "anthropic", "api.anthropic.com", model, False,
        "probe disabled — see github issue #...", {},
    )
```

This is preferable to full Phase 1 rollback because other providers stay protected.

---

## Phase 2 — Agent /health integration

### Triggers
- Agent `/health` latency regression (> 3s) breaks backend liveness checks.
- LLM probe blocks the response thread.

### Procedure

1. Revert the `/health` handler to its pre-feature shape:
   ```python
   @app.get("/health")
   async def health():
       return {"ok": True}
   ```
2. Backend's `agent_handler.go::checkAgentHealth` continues to work because it only reads `ok`.
3. `/api/llm/health` (Phase 3) starts returning 502 since aggregator can't find `llm` key — that's expected when Phase 2 is rolled back.

---

## Phase 3 — Backend /api/llm/health aggregator

### Triggers
- Aggregator timeout cascade (one slow agent blocks the cache miss path).
- Memory leak in cache (unlikely; bounded by single-entry).

### Procedure

1. Revert `backend/internal/handler/llm_health_handler.go` deletion + route registration.
2. `/api/llm/health` returns 404 (route not found).
3. Frontend `useLLMHealth` hook gracefully handles 404 → returns `null` → banner doesn't render.

### Partial rollback

Disable cache (set `VULTURE_LLM_HEALTH_CACHE_TTL=0`) if cache logic is buggy but probe itself is fine.

---

## Phase 4 — Bare-metal launcher integration

### Triggers
- Launcher hangs waiting for agent `/health` after 15s timeout.
- Strict mode (`VULTURE_REQUIRE_LLM=true`) refuses startup when user wants to proceed.

### Procedure

1. Revert `backend/internal/localdev/llm_check.go` deletion + the call site in `launcher.go`.
2. Restore the original Ollama-only check.
3. Launcher resumes today's behavior — silent fall-through when LM Studio etc. unreachable.

### Forward-fix preferred over rollback

If users complain about the strict-mode behavior:
- Set `VULTURE_REQUIRE_LLM=false` (default). Strict mode is opt-in.
- Or document it in CLI flag `--no-require-llm`.

---

## Phase 5 — `audits.degraded_reason` column

### Triggers
- Migration fails on a customer's Postgres (extremely unlikely — pure ADD COLUMN with default).
- Per-audit preflight adds latency to audit creation that breaks SLAs.

### Schema rollback

```sql
-- backend/migrations/015_audit_degraded_reason.rollback.sql
ALTER TABLE audits DROP COLUMN IF EXISTS degraded_reason;
```

Run only if you're sure no code path still references the column.

### Code rollback (without dropping column)

Set env `VULTURE_LLM_PREFLIGHT_DISABLED=true` (new escape hatch — easy add).
`audit_handler.go::Create` skips the preflight call. Column stays in DB but is never written. Existing rows keep their value.

This is the recommended rollback path — the column itself is harmless.

### Per-audit preflight rollback

Revert the call in `audit_handler.go::Create`. Audits proceed without the preflight (today's behavior).

---

## Phase 6 — Frontend

### Triggers
- Banner annoyance ("don't show me this every time"; dismissible UX needed).
- Banner positioning breaks on mobile.

### Procedure

1. Set frontend env `VITE_LLM_HEALTH_BANNER_ENABLED=false` (build-time).
2. `<LLMDegradedBanner>` early-returns null.
3. Or revert the banner component imports in `AuditNew.tsx` / `AuditResults.tsx`.

### Per-page disablement

Each page imports the banner separately; remove from one page without touching the other.

---

## Phase 7 — Tests

### Triggers
- Test flakiness due to httpx mock changes.
- Coverage gate failing CI.

### Procedure

Tests don't need rollback — they're additive. If they break CI, mark them with `@pytest.mark.skip` and file an issue. The implementation continues to work.

---

## Phase 8 — VULTURE_REQUIRE_LLM strict mode

### Triggers
- Strict mode rejects audits in CI environments where it's enabled by mistake.

### Procedure

1. Unset `VULTURE_REQUIRE_LLM` env var (or set to `false`).
2. `audit_handler.go::Create` reverts to per-audit warning instead of 503.
3. CLI no longer exits non-zero on degraded mode.

Configuration-only rollback; no code revert needed.

---

## Database rollback (full)

If feature 0039 is fully reverted:

```sql
-- backend/migrations/015_audit_degraded_reason.rollback.sql
ALTER TABLE audits DROP COLUMN IF EXISTS degraded_reason;
```

Verify:
```sql
SELECT column_name FROM information_schema.columns
WHERE table_name = 'audits' AND column_name = 'degraded_reason';
-- Expected: 0 rows
```

---

## Compose / image rollback

This feature has no compose service additions. Rollback is purely code revert + image rebuild + (optional) migration revert.

---

## Verification post-rollback (full)

```bash
# 1. shared/llm/health.py removed
ls agents/shared/shared/llm/health.py 2>&1
# Expected: No such file

# 2. Backend /api/llm/health 404
curl -s -o /dev/null -w '%{http_code}' http://localhost:28080/api/llm/health
# Expected: 404

# 3. Agent /health returns old shape (no llm key)
curl -s http://localhost:28001/health | jq 'has("llm")'
# Expected: false

# 4. Frontend banner not present
# (manual check in browser at /audits/new and /audits/<id>)

# 5. degraded_reason column dropped
psql -c "\d audits" | grep degraded_reason
# Expected: empty (or column not present)

# 6. Existing test suites green
cd backend && go test ./internal/handler/ -count=1
python3 -m pytest agents/shared/tests/unit/ -q
# Expected: all green
```

---

## User communication

If a phase is rolled back in production:

1. Update `0039_implementation_status.md` with rollback timestamp + reason.
2. Add CHANGELOG entry under affected version.
3. If user-visible (banner disappears, strict mode disabled), notify via release notes.
4. If silent (Phase 1-3 rollback before any user-visible surface shipped), no notification needed.

---

## Forward-fix preferred over rollback

The unified health probe is genuinely useful infrastructure. Most issues should be fixed forward rather than rolled back:

- Slow provider probe → reduce timeout, add per-provider override
- Buggy probe → short-circuit that provider only (preserves coverage of others)
- UI banner annoyance → make dismissible, lower its prominence
- Strict-mode CI failure → users opt out via env

Full rollback is reserved for cases where the feature itself causes data corruption or system-wide outage — neither is plausible given the read-only nature of the probes and the additive schema change.
