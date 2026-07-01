# Feature 0059 — Implementation Status

| | |
|---|---|
| **Status** | 🟢 **`--fresh` + Tier‑3 toggle BOTH Implemented & GREEN.** Default policy = **(a) unconditional OFF** (decision resolved §6; smarter routing deferred to future). **Per-request Tier‑3 config (`config.llm_tier3` / `--llm-tier3`) is now honored FLEET-WIDE** (all scan agents, not CWE-only — uniformity change 2026-06-29). Uncommitted on `feature/0057-cwe-agent-hardening`. |
| **Date** | 2026-06-29 |

## Part A — `--fresh` (memory bypass) — ✅ DONE
| # | Item | Test | Status |
|---|---|---|---|
| 1 | `auditRequestsFresh` config parse (`stream_handler.go`) | T-fresh `TestAuditRequestsFresh` (9 cases) | ✅ |
| 2 | Both dispatch sites skip `loadPriorFindings` when fresh (live + SSE paths) | handler suite green | ✅ |
| 3 | `scripts/dev/scan.py --fresh` → `config:{"fresh":true}` + note | `py_compile` + `--help` shows `--fresh` | ✅ |
| 4 | `vulture scan --fresh` → config `fresh:true` + implies `--no-cache` | `cd cli && go build ./... && go vet ./...` clean | ✅ |
| 5 | Config chain `req.Config → audit.Config` | verified (audit_service.go:74,91; same path as `--validate-llm`) | ✅ |

## Part B — Tier‑3 toggle (LLM cost guard) — ✅ DONE (default OFF)
| # | Item | Test | Status |
|---|---|---|---|
| B1 | `_llm_tier3_enabled(config>env>OFF)` resolver (`audit_runner.py`) | `TestLlmTier3Enabled` (4 cases) | ✅ |
| B2 | `_prioritize_files(..., include_tier3=False)` drops Tier 3 | `test_tier3_excluded_when_disabled` | ✅ |
| B3 | Threaded `llm_tier3` **fleet-wide** (updated 2026-06-29): **all** scan agents `agent.py` (`config.get("llm_tier3")`) — `cwe, chaos_engineering, asvs, owasp, xss, soc2, ssdf, do178c` — → `run_combined_audit` → `_collect_llm_findings` → batched collector. *(Was CWE-only; the uniformity change forwards the per-request override from every scan agent.)* | shared suite green | ✅ |
| B4 | Skip **notice** with file count (R10) folded into the collector's `notice` return | shared suite green | ✅ |
| B5 | CLI `vulture scan --llm-tier3` + `scan.py --llm-tier3` → `config.llm_tier3` | CLI build+vet; `scan.py --help` | ✅ |
| B6 | Deterministic coverage unaffected (R9) — the 2 full-sweep tests (`TestT12BatchSweep`, `TestT7BudgetCap`) keep their assertions, now with an explicit `VULTURE_LLM_TIER3=on` precondition | both green | ✅ |

## Verification (Part B)
- New unit tests: `TestLlmTier3Enabled` (precedence) + `test_tier3_excluded_when_disabled` — green.
- Default-OFF behavior change surfaced exactly the two full-sweep tests; fixed by adding their true precondition (`VULTURE_LLM_TIER3=on`) — **assertions unchanged** (6 batch calls; budget notice).
- Full suites: **shared 962 passed · cwe 601 passed/1 skip** · `ruff check` clean · CLI `go build`+`go vet` clean · `scan.py` compiles + `--llm-tier3` in help.

**Future (deferred, §6):** cost-aware default / per-tier / dataflow-aware routing + operator hard-lock.

## Verification
- `go test ./internal/handler/` — green (incl. `TestAuditRequestsFresh`); `go vet ./internal/handler/` clean.
- `cli` builds + vets after the `parseScanFlags`/`cmdScan` signature changes (2 call sites updated).
- `scan.py` compiles; `--fresh` in help.
- No DB migration; no new env var; default behavior unchanged (memory ON unless `fresh:true`).

## Not done / follow-ups
- **Live E2E not run here**: the running dev backend predates this change (would need a `go build` + `serve` restart). The gate is unit-tested and the config chain is verified by reading + precedent (`--validate-llm` uses the identical path). A live demo = scan a path twice, then `--fresh` shows full LLM re-discovery vs. the suppressed re-scan.
- The memory-system bugs found in the companion audit (git-URL prior mismatch; exact-path matching; PG/SQLite retrieval divergence; untested Multi/L4-revote/label-handler; dormant agent memory tools) are **enumerated, not fixed** — `--fresh` mitigates by bypassing memory, but does not repair them.
