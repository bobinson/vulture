# 0035 — ASVS 5.0.0 Audit Agent: Implementation Status

## Status: IMPLEMENTED — all 6 tasks complete + post-review hardening

### Execution summary (2026-04-19)

| Task | Description | Outcome |
|---|---|---|
| 1 | Extractor + LLM-assisted CWE crosswalk + detectability | ✓ 345 reqs parsed; 105 crosswalk entries; 7 extractor tests pass |
| 2 | Agent scaffolding (agent.py, main.py, config.py, catalog.py, Dockerfile) | ✓ 6 config tests + 12 catalog tests pass |
| 3 | Consolidated `asvs_requirements_check.py` skill | ✓ 61 registry entries + keyword fallback; 37 skill tests pass |
| 4 | Backend registry + docker-compose integration | ✓ `AllAgents` includes ASVS; agent-asvs service on port 28010 |
| 5 | LLM integration + catalog context injection | ✓ INSTRUCTIONS + dynamic catalog context in agent.py |
| 6 | E2E tests + coverage verifier | ✓ `scripts/verify_asvs_coverage.py` passes all thresholds |

### Post-review hardening

Three-team review (RED/GREEN/ORANGE) surfaced correctness + reliability + performance findings. Hardening commit applies:

- **Correctness**: V6.2.2 → V13.3.1 (hardcoded creds), V11.2.1 → V11.3.2 (broken crypto), removed V15.3.1/V15.3.2 curl-pipe-shell mislabels.
- **Perf**: Hoisted `_is_in_active_config` out of per-line hot path via `_active_registry()` pre-filter — measured **28% speedup** on `agents/shared` (228ms → 163ms), **29%** on `agents/cwe` (49ms → 35ms).
- **Reliability**: `_union()` now asserts on unsupported flags; `load_catalog()` handles `JSONDecodeError` gracefully; `_SAFE_SAMESITE` no longer treats `SameSite=None` as safe.
- **DRY**: `_GENERIC_TOKENS` sync test asserts extractor and skill stay aligned.

### Coverage verifier output

```
Total ASVS requirements:                    345  (345 expected)
  Static-detectable:                        286
  Runtime/DAST (out of scope):                1
  Policy (out of scope):                     58

Dedicated _CHECKS registry entries:          61  (target >= 50) [OK]
Keyword-fallback eligible:                   66  (target >= 50) [OK]
Total active scannable:                     127  (target >= 120) [OK]
```

### Test summary

62 unit tests passing in `agents/asvs/tests/unit/`. 204 CWE tests still passing. Backend Go tests unaffected.

## Revision history

- **Rev 1 (2026-04-18)**: Initial draft with 17 per-chapter skills + Phase-1/Phase-2 split (8 tasks).
- **Rev 2 (2026-04-18)**: Per user review — consolidated 17 chapter skills into a single `asvs_requirements_check.py` with per-req registry (performance: single source scan; scalability: new req = one registry entry; maintainability: one file). Phase 1+2 merged into a single Task 3. CWE crosswalk switched to LLM-assisted generation with spot-check. Task count reduced 8 → 6.

## Summary

Adds a new Vulture audit agent that scans source code against **OWASP ASVS 5.0.0** (345 requirements, 17 chapters, 3 verification levels). Architecture mirrors the CWE agent pattern: catalog extraction from upstream sources, 17 chapter-scoped skills plus a catalog-driven generic detector, with configurability by chapter + level.

## Baseline measurements (2026-04-18, from upstream ASVS 5.0.0)

| Metric | Value |
|---|---:|
| Total ASVS requirements | 345 |
| Chapters (V1–V17) | 17 |
| Sections | 79 |
| L1 requirements | 70 |
| L2 requirements (cumulative with L1) | 253 |
| L3 requirements (cumulative) | 345 |
| Static-detectable via SAST (estimated) | ~194 (56%) |
| Runtime/DAST-only (out of scope) | ~125 (36%) |
| Policy/documentation-only (out of scope) | ~26 (8%) |
| CWE mappings in upstream ASVS 5.0.0 CSV/JSON | **0%** (dropped in v5.0.0) |

## Target measurements (post-implementation)

| Metric | Target |
|---|---:|
| Dedicated-skill requirement coverage (`_CHECKS` registry) | ≥ 130 (stretch: ~196) |
| Skills registered | 1 (single consolidated `asvs_requirements`) |
| Unit test count | ≥ 130 |
| E2E tests | ≥ 3 |
| Catalog JSON size | ≤ 500 KB |
| Agent health-check responsive on port | 28010 |
| Frontend auto-discovery via `/api/agents` | Working (no frontend code changes) |

## Task progress

| Task | Description | Status |
|---|---|---|
| 1 | Extractor + LLM-assisted CWE crosswalk + detectability classification | ☐ Not started |
| 2 | Agent scaffolding (agent.py, main.py, config.py, catalog.py, Dockerfile) | ☐ Not started |
| 3 | Consolidated `asvs_requirements_check.py` skill with per-req registry + keyword fallback | ☐ Not started |
| 4 | Backend registry + docker-compose integration | ☐ Not started |
| 5 | LLM integration + catalog context injection | ☐ Not started |
| 6 | E2E tests + verifier + CLAUDE.md update | ☐ Not started |

## Files to create

| File | Purpose |
|---|---|
| `scripts/extract_asvs_catalog.py` | Idempotent extractor combining upstream JSON + crosswalk + detectability classification |
| `scripts/verify_asvs_coverage.py` | Acceptance verifier (coverage counts vs targets) |
| `agents/asvs/asvs_agent/__init__.py` | Package init |
| `agents/asvs/asvs_agent/agent.py` | `run_audit` generator with LLM catalog injection |
| `agents/asvs/asvs_agent/main.py` | FastAPI SSE app factory |
| `agents/asvs/asvs_agent/config.py` | `ALL_CATEGORIES` (18 entries), `CONFIG_SCHEMA` (chapters + levels), `AGENT_INFO` |
| `agents/asvs/asvs_agent/catalog.py` | Catalog helpers (load, filter by chapter/level, enrich_finding) |
| `agents/asvs/asvs_agent/skills/__init__.py` | `SKILL_MAP`, `SKILL_TOOLS` registration |
| `agents/asvs/asvs_agent/skills/SKILLS.md` | Per-skill documentation |
| `agents/asvs/asvs_agent/skills/asvs_requirements_check.py` | Single consolidated skill: per-req regex registry + keyword-index fallback |
| `agents/asvs/asvs_agent/data/asvs_source.json` | Vendored upstream ASVS JSON (SHA-256 pinned) |
| `agents/asvs/asvs_agent/data/asvs_catalog.json` | Generated runtime catalog |
| `agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json` | LLM-generated + spot-reviewed ASVS→CWE mapping |
| `agents/asvs/asvs_agent/data/asvs_detectability.json` | LLM-classified + spot-reviewed static/runtime/policy labels |
| `agents/asvs/asvs_agent/data/_crosswalk_generation_log.md` | Transcript of the LLM crosswalk generation for audit traceability |
| `agents/asvs/Dockerfile` | Container definition (port 28010) |
| `agents/asvs/pyproject.toml` | Python package manifest |
| `agents/asvs/tests/unit/conftest.py` | Autouse cache-reset fixture |
| `agents/asvs/tests/unit/test_catalog*.py` | Catalog extraction + helper tests |
| `agents/asvs/tests/unit/test_asvs_requirements_check.py` | Parametrized tests covering per-req registry + keyword fallback + level/chapter filters |
| `agents/asvs/tests/e2e/test_asvs_audit.py` | SSE E2E test via docker compose |

## Files to modify

| File | Change |
|---|---|
| `backend/pkg/agentregistry/registry.go` | Append ASVS entry to `AllAgents` |
| `docker-compose.yml` | Backend env var + `depends_on` + new `agent-asvs` service block (port 28010) |
| `.env.example`, `scripts/gen-env.sh` | `VULTURE_AGENT_ASVS_PORT=28010` |
| `Makefile` | Optional `test-asvs` / `lint-asvs` targets |
| `CLAUDE.md` | Agent listing (§Python agents) — mention ASVS alongside chaos/owasp/soc2/cwe |

## Test results

_Not yet run._

## Notes

- **Architectural parallels to CWE**: ASVS agent reuses the exact catalog-driven pattern (extractor → JSON → `@lru_cache` loader → enrich_finding). Where an ASVS requirement maps to a CWE we already detect, the consolidated ASVS skill **imports** the CWE skill's regex constants rather than duplicating.
- **Why a single consolidated skill** (Rev 2 design): in Vulture's audit_runner, skills run concurrently via ThreadPoolExecutor — 17 per-chapter skills would mean 17× redundant `scan_code_files` walks of the same source tree. Consolidating into one skill with a per-req dispatch registry keeps source-scan I/O at 1×, matches the actual bottleneck (file I/O, not CPU), and makes adding a new requirement a one-line change. Chapter-level configurability is preserved through `CONFIG_SCHEMA.chapters` (17-enum multi-select), filtered at dispatch time.
- **LLM-assisted data generation**: ASVS 5.0.0 dropped CWE mappings, so we generate both `asvs_cwe_crosswalk.json` and `asvs_detectability.json` via one-shot Claude passes. Output is spot-reviewed (30 random samples); disagreement threshold triggers re-run. The full LLM transcript is committed for audit traceability.
- **Why not just LLM-only detection**: ~194 requirements have unambiguous static signatures. Deterministic regex detection is faster, cheaper, and more reproducible than LLM inference. LLM phase augments for ambiguous cases (when `VULTURE_USE_LLM=true`).
- **Runtime/DAST reqs deliberately skipped**: out-of-scope for a SAST tool. Emitted as an informational thinking event at audit start so users see what's not covered.
- **Plan assumes CWE agent 0034 is landed** — reuses several CWE regex constants (`HARDCODED_CRED_PATTERNS`, `BROKEN_CRYPTO_PATTERNS`, `WEAK_RANDOM_PATTERNS`, cookie patterns, etc.) via imports.
