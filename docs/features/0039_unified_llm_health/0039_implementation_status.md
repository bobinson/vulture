# 0039 — Implementation Status

**Branch**: tbd (recommend `feat/0039-unified-llm-health`)
**Status**: PLANNED
**Owner**: tbd
**Started**: not started
**Target v1.0** (Phases 1+2+3+7): ~3.5 days
**Target v1.1** (Phases 4+5+6): +1.5 days
**Target v1.2** (Phase 8): +0.5 day

## Phase summary

| Phase | Status | E2E green | v1.x | Notes |
|---|---|---|---|---|
| 1 — Canonical health probe (`shared/llm/health.py`) | PLANNED | — | v1.0 | 6 provider probes + LLMHealthStatus dataclass |
| 2 — Agent `/health` integration | PLANNED | — | v1.0 | Adds `llm` + `llm_message` to existing endpoint |
| 3 — Backend `/api/llm/health` aggregator | PLANNED | — | v1.0 | 5s LRU cache; queries any one agent |
| 4 — Bare-metal launcher integration | PLANNED | — | v1.1 | Replaces Ollama-only check |
| 5 — `audits.degraded_reason` column + per-audit preflight | PLANNED | — | v1.1 | Migration `015_audit_degraded_reason.sql` |
| 6 — Frontend banner + `useLLMHealth` hook | PLANNED | — | v1.1 | Used in AuditNew + AuditResults |
| 7 — Per-provider test fixtures (~50 tests) | PLANNED | — | v1.0 | 6 providers × 7 failure modes + edge cases |
| 8 — `VULTURE_REQUIRE_LLM` strict mode | PLANNED | — | v1.2 | 503 + canonical message on degraded |

## Detailed task list

### Phase 1 — Canonical health probe

#### 1.1 LLMHealthStatus dataclass
- [ ] 1.1.t1 — Create `agents/shared/shared/llm/health.py` with `LLMHealthStatus` dataclass + `message()` formatter

#### 1.2 check_llm_health() entry point
- [ ] 1.2.t1 — Implement detection precedence matching `provider.py` routing logic exactly

#### 1.3 Per-provider probes
- [ ] 1.3.t1 — `_probe_openai_compatible` + `_probe_openai` + `_probe_openai_models_endpoint` + `_interpret_models_response`
- [ ] 1.3.t2 — `_probe_anthropic` (POST /v1/messages 1-token probe)
- [ ] 1.3.t3 — `_probe_gemini` (GET /v1beta/models)
- [ ] 1.3.t4 — `_probe_ollama` (GET /api/tags)

#### 1.4 Verification
- [ ] 1.4.t1 — Smoke import test
- [ ] 1.4.t2 — Manual probe against running LM Studio with canonical message printed

### Phase 2 — Agent /health endpoint

- [ ] 2.1.t1 — Update `sse_app.py:49` to include `llm` and `llm_message`
- [ ] 2.1.t2 — Verify all 8 agent containers' `/health` returns expanded shape
- [ ] 2.1.t3 — Latency confirmation (< 2.5s p95)

### Phase 3 — Backend aggregator

- [ ] 3.1.t1 — Create `backend/internal/handler/llm_health_handler.go`
- [ ] 3.1.t2 — 5s LRU cache implementation
- [ ] 3.1.t3 — Wire into `server.go::registerRoutes`
- [ ] 3.2.t1 — Smoke test: `curl http://localhost:28080/api/llm/health | jq`
- [ ] 3.2.t2 — Cache test: 100 polls in 2s yield only 1 underlying call

### Phase 4 — Bare-metal launcher

- [ ] 4.1.t1 — Create `backend/internal/localdev/llm_check.go::reportLLMHealthOrAbort`
- [ ] 4.1.t2 — Modify `launcher.go::startAll` to call after agents ready
- [ ] 4.1.t3 — Update Ollama autopull path to NOT unilaterally set `VULTURE_USE_LLM=true`
- [ ] 4.2.t1 — Manual test all 6 provider configs; canonical message renders

### Phase 5 — Per-audit preflight

- [ ] 5.1.t1 — Write `backend/migrations/015_audit_degraded_reason.sql` (Postgres)
- [ ] 5.1.t2 — Write `backend/migrations/015_audit_degraded_reason.sqlite.sql`
- [ ] 5.2.t1 — Add `DegradedReason` to `model.Audit`
- [ ] 5.2.t2 — Update Postgres + SQLite repos
- [ ] 5.3.t1 — Inject `LLMHealthHandler` into `AuditHandler`
- [ ] 5.3.t2 — Implement preflight in `Create`
- [ ] 5.3.t3 — `VULTURE_REQUIRE_LLM=true` returns 503
- [ ] 5.4.t1 — E2E: stop LM Studio, submit audit, confirm `degraded_reason` populated

### Phase 6 — Frontend

- [ ] 6.1.t1 — Create `frontend/src/hooks/useLLMHealth.ts`
- [ ] 6.1.t2 — Create `frontend/src/components/results/LLMDegradedBanner.tsx`
- [ ] 6.2.t1 — Add `degraded_reason?: string` to `Audit` type
- [ ] 6.3.t1 — Add `<LLMDegradedBanner />` to `AuditNew.tsx`
- [ ] 6.3.t2 — Add `<LLMDegradedBanner preset={audit.degraded_reason} />` to `AuditResults.tsx`
- [ ] 6.4.t1 — Playwright E2E: stop LM Studio, submit via UI, banner appears
- [ ] 6.4.t2 — `tsc --noEmit` clean

### Phase 7 — Test fixtures

- [ ] 7.1.t1 — Create `agents/shared/tests/unit/llm/{__init__,test_health}.py`
- [ ] 7.2.t1 — LM Studio: 7 tests (reachable / model-not-loaded / connection-refused / timeout / 401 / 429 / 500)
- [ ] 7.2.t2 — vLLM: 7 tests
- [ ] 7.2.t3 — LocalAI: 7 tests
- [ ] 7.2.t4 — Generic OpenAI-compatible: 7 tests
- [ ] 7.2.t5 — OpenAI cloud: 7 tests
- [ ] 7.2.t6 — Anthropic: 7 tests (incl. 404 = model-not-available)
- [ ] 7.2.t7 — Gemini: 7 tests
- [ ] 7.2.t8 — Ollama: 7 tests
- [ ] 7.2.t9 — Detection precedence + edge cases (~6 tests)
- [ ] 7.2.t10 — Message-format invariance (~3 tests, char-for-char asserts)
- [ ] 7.3.t1 — `python3 -m pytest agents/shared/tests/unit/llm/test_health.py -v` all green
- [ ] 7.3.t2 — `pytest --cov=shared.llm.health` shows 100% coverage

### Phase 8 — Strict mode

- [ ] 8.1.t1 — `ErrLLMRequired` constant in `audit_handler.go`
- [ ] 8.1.t2 — CLI handles 503; exit code 75 (EX_TEMPFAIL); stderr canonical message
- [ ] 8.1.t3 — Docs in `docs/guides/ci_integration.md`
- [ ] 8.2.t1 — E2E: `VULTURE_REQUIRE_LLM=true` + LM Studio off → `vulture scan` exits non-zero

## Cross-cutting

- [ ] CC.1 — TDD discipline: tests in Phase 7 written first; Phase 1 implementation makes them green
- [ ] CC.2 — Performance budgets met (< 50 ms p95 backend, < 2.5s p95 agent)
- [ ] CC.3 — No API keys in logs or response bodies
- [ ] CC.4 — Structured logs at info/warn levels include provider + endpoint + reachable
- [ ] CC.5 — Backwards-compat verified: existing `/health` consumers still work; `degraded_reason` defaults to ''
- [ ] CC.6 — `docs/guides/llm_setup.md` written
- [ ] CC.7 — `README.md` and `docs/architecture/agent_protocol.md` updated

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-04-26 | Single Python module `shared/llm/health.py` is the canonical implementation; Go side delegates via agent `/health` to avoid duplicating provider logic. | spec |
| 2026-04-26 | One canonical message format produced by `LLMHealthStatus.message()`; consumed verbatim by every surface (agent /health, backend /api/llm/health, launcher banner, audit-create response, frontend banner). | spec |
| 2026-04-26 | Detection precedence mirrors `provider.py` routing exactly (OPENAI_BASE_URL > Anthropic > Gemini > Ollama > OpenAI). Health probe never disagrees with actual call routing. | spec |
| 2026-04-26 | `audits.degraded_reason` column persists the canonical message at audit-creation time so UI shows the warning even after audit completes. | spec |
| 2026-04-26 | Anthropic uses 1-token POST `/v1/messages` probe (no GET /models exists). Cost ~$0.000001 per probe; cached for 5s. Acceptable. | spec |
| 2026-04-26 | `VULTURE_REQUIRE_LLM=true` returns 503 + canonical message on per-audit preflight; CLI exits 75 (EX_TEMPFAIL). For CI / regulated environments. | spec |
| 2026-04-26 | Cache TTL default 5s. Frontend polls every 30s; ~1 of 6 polls hits agents. Tunable via `VULTURE_LLM_HEALTH_CACHE_TTL`. | spec |
| TBD | Should the launcher refuse to start when LLM unreachable AND `VULTURE_USE_LLM=true` AND `VULTURE_REQUIRE_LLM` unset? | |
| TBD | Add Prometheus metrics in v1.2 polish | |
| TBD | Add health banner to Dashboard / Settings pages? | |

## Out of scope (tracked separately)

- Refactoring `audit_runner.py` LLM phase logic (existing in-flight catch stays).
- Model-quality probes (latency benchmarks, output validation).
- Provider-specific feature detection (e.g. "does this model support tool use?").
- LiteLLM cooldown_manager interaction (separate concern).
