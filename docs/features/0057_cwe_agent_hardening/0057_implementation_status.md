# Feature 0057 — Implementation Status

| | |
|---|---|
| **Feature** | 0057_cwe_agent_hardening (LLM-when-enabled, fleet-uniform + signatures + verified coverage) |
| **Status** | 🟢 **Phases 0–6 COMPLETE & GREEN** (T1–T24 + T26; T25 = Phase-7). **N=10 corpus-verified.** **End-to-end audited (32-agent), 13 findings all fixed.** Phase 7 (soak) ongoing — open cluster is reasoning-model LLM reliability (7.5–7.7). **R1 reversed 2026-06-29 — CWE LLM phase now off by default, opt-in via `VULTURE_USE_LLM` (fleet-uniform); that change is in the working tree, UNCOMMITTED.** |
| **Last updated** | 2026-06-29 |
| **Branch** | `feature/0057-cwe-agent-hardening` — **Phases 0–6 + the audit-fixes committed** (Phase 0+1 `da07f8d`; signatures `642096f`; migration 022 `26c9cd5`; reconciliation `6c4acda`; audit-fixes `a3f051e`/`9ab0b72`; R17 CI lane `2690a10`; HEAD `d19bfc6`). **UNCOMMITTED (working tree, 15 files): the 2026-06-29 R1-reversal + fleet-tier3 uniformity change** — implemented & green but not yet committed (committed HEAD still has the old CWE LLM-on-by-default). |
| **Suites** | agents/cwe **604 passed / 1 skip** · agents/shared **976 passed** · 7 non-CWE scan agents + owasp/soc2 regression green · `ruff` clean (re-verified 2026-06-29) |

> Tests are written **before** the implementation in every phase (CLAUDE.md). An item is
> "done" only when its tests pass **and** the full existing CWE + shared suites still pass.
> **N is gate-computed, never asserted — seed N=10 verified** (growth path to ~80). Phases are
> independently shippable — gate each before the next.

## Checkpoints

### Phase 0 — Code-grounding (shared infra; prerequisite) ✅
| # | Item | Tests | Status |
|---|------|-------|--------|
| 0.1 | `code_snippet` field on the in-memory finding (`audit_runner.py` `AuditFinding`) | T1 | ✅ Done |
| 0.2 | `_attach_code_snippet()` central populator before `_validate` | T1 | ✅ Done |
| 0.3 | L5 skips empty-window findings (`_has_code_window`) | T2 | ✅ Done |

### Phase 1 — LLM phase, safely (fleet-uniform opt-in) ✅
| # | Item | Tests | Status |
|---|------|-------|--------|
| 1a | CWE `use_llm` keys off `VULTURE_USE_LLM` (default off, fleet-uniform — **R1 reversed 2026-06-29**) + graceful skills-only notice when LLM enabled but model unusable + `VULTURE_CWE_DISABLE_LLM` hatch | T6, T8 | ✅ Done (reflects reversal) |
| 1b | L5 default-on; RC6 blast-radius cap; crypto/policy exemption (`_apply_l5_safeguards`) | T3, T5, T10 | ✅ Done |
| 1c | LLM read/grep tools on the inline path (source-root confined, `confine.py`) | T9 | ✅ Done |
| 1d | Cost/work cap (`VULTURE_LLM_BUDGET_USD`, `VULTURE_LLM_MAX_FILES`) + honest tokens + partial notice | T7 | ✅ Done |
| 1f | Whole-codebase batch-loop sweep + cross-batch/skill dedup; tail-drop eliminated | T4, T12 | ✅ Done |
| **Gate** | Soak: recall/FP/cost telemetry | T3–T12 | ☐ Phase-7 soak (operational) |

### Phase 2 — Snippet redaction ✅
| # | Item | Tests | Status |
|---|------|-------|--------|
| 2.0 | **Redact `code_snippet` for secret-bearing CWEs** before SSE/DB persist | T-redact | ✅ Done — `_redact_finding_inplace` at all 3 egress points; set `{256,259,312,319,321,522,798}` (review-widened) |
| 2.1 | RC6 threshold, crypto-exempt set, budget defaults | — | ☐ Phase-7 soak (operational) |

### Phase 3 — LLM-when-enabled (fleet-uniform) docs ✅
| 3.1 | Opt-in default (`VULTURE_USE_LLM`) + generate-verify flow + env vars (agent.py, CLAUDE.md) — updated for the 2026-06-29 R1 reversal | — | ✅ Done |

### Phase 4 — Signature registry + detector (land as `candidate`) ✅
| # | Item | Tests | Status |
|---|------|-------|--------|
| 4a | `CweSignature` schema (compiled-regex py modules) | T13 | ✅ Done — `skills/signatures/schema.py` (frozen dataclass) |
| 4b | Generic 3-step matcher, ext-indexed | T13 | ✅ Done — `skills/signatures/detector.py` (`_SIGS_BY_EXT`, sink→source→sanitizer, line length-capped) |
| 4c | Registry + family modules | T13 | ✅ Done — `registry.py` + `families/{redos,injection_ldap_xpath,el_injection,nosql,log_injection,dir_listing}.py`; `covered_cwe_ids()` introspectable |
| 4d | **(BLOCKING)** route via `check_catalog_generic` + `_DEDICATED_SKILL_CWES` | T14 | ✅ Done — `_apply_signatures()` in `catalog_detector.py`. **R12 strategy (B) ADDITIVE: keyword path RETAINED (reframed as low-yield metadata in Phase 6, not removed) — zero test edits** |
| 4e | Validation tiering (trusted/candidate) | T15 | ✅ Done — `_is_deterministic` reads `signature_status` (candidate → L5-demotable; trusted → authoritative) |
| 4f | Seed net-new signatures as `candidate` | T13 | ✅ Done — 7 shipped (1333/90/91/917/943/117/548). **CWE-489 DROPPED** (collides with `configuration` skill CWE-1188/1295) |
| 4g | Signature-tier escape hatches `VULTURE_CWE_DISABLE_SIGNATURES` (skip the tier) + `VULTURE_CWE_SIGNATURES_CANDIDATE_OFF` (trusted-only) | `test_signature_killswitch.py` | ✅ Done — implemented in `catalog_detector.py` (2026-06-29 audit fix; docs listed them but they were missing) |

### Phase 5 — Corpus + per-CWE gates ✅  → **N=10**
| # | Item | Tests | Status |
|---|------|-------|--------|
| 5a | Corpus tree + `manifest.d/*.yaml` (**128 first-party Apache-2.0 fixtures total** = **120 production** [10 CWEs × 6 pos + 6 clean = 120, feed N] + **8 `_golden`** unit-test fixtures) | T16 | ✅ Done — Juliet CC0 deferred to Phase 7 |
| 5b | `gates.yaml` + `corpus_runner.py` (deterministic, no LLM; strict recall=1.0/fp=0.0/min_fixtures=3) | T16–T19 | ✅ Done |
| 5c | `promote_signatures.py` (data-driven) | T21 | ✅ Done — **all 7 signatures promoted to `trusted`** |
| 5d | License rows; no GPL/unlicensed | — | ✅ Done — all first-party Apache-2.0; corpus in `.vultureignore` |
| 5e | CI: PR curated subset + nightly full lane | — | ✅ Done (2026-06-29 audit fix, committed `2690a10`) — `make cwe-corpus` (curated PR subset) + `report_coverage.py --check` (stale golden → fail) wired into `ci.yml`; `cwe-corpus-nightly.yml` (schedule/dispatch) for the full sweep. Validated by YAML-parse + local `make cwe-corpus`; a live GitHub-Actions run + enforce-vs-advisory tuning remain soak |
| **Result** | **N=10 VERIFIED** {78,89,90,91,117,548,798,917,943,1333}; below-gate band empty | T16–T21 | ✅ |

### Phase 6 — Attestation + doc reconciliation (6a–c ✅; 6d ⏳ provenance persistence)
| # | Item | Tests | Status |
|---|------|-------|--------|
| 6a | `report_coverage.py` → golden `VERIFIED_CWES.md` (4 buckets); stale→CI fail | T22, T24 | ✅ Done — N=10; DECLARED-ONLY=70; below-gate=0; LLM-ASSISTED=0 |
| 6b | Per-finding `provenance` tag (6-value vocabulary, in-memory) | T23 | ✅ Done — `skill/signature_trusted/signature_candidate/catalog_rollup/llm/llm_l5_verified` |
| 6c | Replace "846/400+" with honest multi-tier statement (846 kept as catalog metadata, not collapsed to 10) | — | ✅ Done — agent.py/config.py/SKILLS.md + lockstep test corrections |
| 6d | **Provenance persistence (backend, R18)** — surface provenance at `GET /api/audits/:id` + findings table (model + migration 022 + sqlite/postgres repos) | T26 | ✅ Done — **proven live** at the API. Also fixed a real bug: `_retag_l5_verified` was wired only on the OFFLINE validate path → `llm_l5_verified` was **dead code on live (streaming) audits**; now called on both paths (+4 `TestL5StreamingRetag` tests) |

### Phase 7 — Soak (ongoing / operational)
| 7.1 | Real-audit soak; tune `gates.yaml`/RC6/budget from telemetry | — | ☐ ongoing |
| 7.2 | **Juliet CC0 ingestion** — grow DECLARED-ONLY (70) → VERIFIED toward ~80 | — | ☐ ongoing |
| 7.3 | Line-precision gate (currently file-level recall/fp) | — | ☐ ongoing |
| 7.4 | T25 LLM recall-lift (opt-in, never gated) | T25 | ☐ ongoing (needs a live model) |
| 7.5 | **Widen the L5 code window for LLM-tier (cross-function) findings** — ±2 lines can't show a cross-function source→sink flow, so the judge can't *affirmatively* confirm them (they reach `llm_l5_verified` via the RC6 survival path, not `exploitable>0.5`) | — | ☐ ongoing (real-model E2E finding) |
| 7.6 | **Finish L5 truncation hardening for reasoning models** — even at max_tokens=16000/batch≤2, qwen3.6-35b occasionally truncates a batch's verdict JSON under load | — | ☐ ongoing |
| 7.7 | **Generate-phase token tuning for reasoning models** — the thinking model can burn the whole output budget on hidden reasoning → empty answer → 0 LLM findings (~33% reliable on the 35B); the generate-side analog of the L5 fix | — | ☐ ongoing |

## Test ledger
| ID | Contract | Tier | Status |
|----|----------|------|--------|
| T1 | code_snippet populated on all findings | det | ✅ |
| T2 | L5 skips blind (empty window) | det | ✅ |
| T3 | skills authoritative (≥2-check floor) | det | ✅ |
| T4 | LLM findings deduped vs deterministic | det | ✅ |
| T5 | RC6 cap freezes L5 at >50% demote | det | ✅ |
| T6 | graceful degradation, no model | det | ✅ |
| T7 | budget/max-files cap stops LLM phase | det | ✅ |
| T8 | **CWE LLM phase OFF by default; ON only when `VULTURE_USE_LLM=true`** (fleet-uniform — reversed 2026-06-29; was "on by default") | det | ✅ |
| T9 | LLM finds a cross-line gap skills miss | llm-fake | ✅ |
| T10 | crypto CWE not auto-suppressed | det | ✅ |
| T11 | clean code stays within FP gate | det | ✅ |
| T12 | LLM sweeps beyond one context window | llm-fake | ✅ |
| T-redact | secret-bearing snippet masked, structure preserved | det | ✅ |
| T13 | signature detects cross-line gap, LLM OFF | det | ✅ |
| T14 | dedup precedence — no double-report (R11) | det | ✅ |
| T15 | candidate demotable / trusted needs 2 checks | det | ✅ |
| T16 | corpus runner scores per-CWE | det | ✅ |
| T17 | recall gate fails on regression | det | ✅ |
| T18 | per-CWE precision gate | det | ✅ |
| T19 | min_fixtures anti-vacuity guard | det | ✅ |
| T20 | weak candidate measured, not gating | det | ✅ |
| T21 | promotion is data-driven | det | ✅ |
| T22 | VERIFIED_CWES.md golden not stale | det | ✅ |
| T23 | provenance tagged (every finding, one tag) | det | ✅ |
| T24 | attestation counts reconcile (3 ways, disjoint buckets) | det | ✅ |
| T25 | LLM raises recall on dataflow fixtures (opt-in, not gating) | llm | ☐ Phase-7 (needs live model) |
| T26 | provenance round-trips agent → backend → GET /api/audits/:id (sqlite + postgres) | det | ✅ sqlite unit-tested + proven live (API histogram {skill:2, llm_l5_verified:7}); **postgres** now has a committed integration-tagged test (`postgres_repo_provenance_integration_test.go`, gated on `POSTGRES_TEST_DSN`) — 2026-06-29 audit fix closed the "PG untested" gap |

## Honest coverage summary
- **Detects:** ~73–84 declared skill CWE-IDs **+ 7 trusted signature CWEs** (90/91/117/548/917/943/1333).
- **Corpus-VERIFIED (provable N): 10** — {78,89,90,91,117,548,798,917,943,1333}, strict gate, CI-reproducible.
- **846 catalog:** reframed as metadata/context (keyword path fires ~0; not counted).
- **Caveats:** corpus is first-party + author-aligned (a real regression gate, not independent-benchmark validation — Juliet is Phase 7); recall/fp are file-level; no live model here so the LLM path is proven by fakes + the graceful E2E.

## Decisions log
- **R1 REVERSED — fleet uniformity (2026-06-29, maintainer):** the CWE agent **no longer
  defaults its LLM phase on**. It now respects `VULTURE_USE_LLM` (default `false`) **exactly
  like every other scan agent** — the LLM phase is **opt-in**, fleet-uniform. `_resolve_cwe_llm`
  no longer falls back to `True`; absent a per-request `use_llm`, it falls back to the
  `VULTURE_USE_LLM` default (read at runtime, monkeypatch-testable). The graceful **model-health
  gate** and the **`VULTURE_CWE_DISABLE_LLM`** escape hatch are **retained** — they apply only
  when the LLM phase IS enabled. **T8 contract changed** accordingly: it now asserts the CWE LLM
  phase is **off by default** and **on when `VULTURE_USE_LLM=true`** (was "on by default"). The
  companion per-request Tier-3 forward is fleet-wide too (see feature 0059). *(Implemented under
  feature 0057/0059 uniformity change; this status doc reflects the reversal, code changes land
  in the agent cluster.)*
- **End-to-end audit + 13-finding fix (2026-06-29):** a 32-agent end-to-end audit verified
  Phases 0–6 working/green and surfaced 13 findings (3 MED / 9 LOW / 1 INFO); **all fixed**:
  (MED) the two signature kill-switches implemented (4g); a committed Postgres provenance
  integration test (T26); the R17 PR/nightly corpus CI lane (5e). (LOW) T12 batch-sweep + T2
  `_has_code_window` assertions strengthened; stale docstrings (R7 / catalog "400+") corrected;
  status/plan doc fixes (commit state, suite counts, fixtures 128 = 120 + 8 golden,
  `promote_signatures.py` path, §13 pytest path). Separately hardened the validate **L5** path
  (live-found): the verdict parser now extracts the JSON object (balanced-brace) so a
  reasoning model's prose-wrapping no longer drops verdicts, and the L5 verdict cache is now
  concurrency-safe (was `SQLITE_MISUSE` under the judge thread-pool). Committed
  (`a3f051e`/`9ab0b72`/`2690a10`).
- **§12.1 (2026-06-26):** `VULTURE_LLM_MAX_FILES=10000` (per user) — file count not the cap; context window + USD budget bound the sweep.
- **#15 folded in (2026-06-26):** LLM batch-loop sweep in scope (P1f).
- **#4 + #2 folded in (2026-06-26):** signatures + corpus + per-CWE gates kept **in 0057** as Phases 4–7 (per user — the design workflow had recommended a 0058 split). Standalone 0058 docs removed.
- **Tranche (2026-06-27, impl):** **7 signatures shipped** (1333/90/91/917/943/117/548); CWE-489 dropped (overlaps `configuration`); CWE-77/119/120/377 dropped (overlap); CWE-121/73 deferred (need AST/dataflow).
- **R12 strategy (B) ADDITIVE (2026-06-27, impl):** keyword path retained (reframed as metadata, not removed) — zero existing-test edits.
- **RC6 cap shape (2026-06-27, impl):** freezes L5 only when the demotion fraction is in the OPEN band `(0.5, 1.0)` with `≥3` judged findings; a unanimous 100%-demote is treated as an internally-consistent verdict. Tunable in Phase 7 soak.
- **Provenance marker (impl):** 6-value vocabulary set at a single central choke point; LLM findings surviving a non-demoting L5 check re-tag to `llm_l5_verified`; crypto/policy CWEs (326/327/328/330/798/319) L5-exempt regardless of provenance.
- **Provenance persistence — SCOPE CORRECTED (2026-06-27, per maintainer):** P6b's "in-memory only" is superseded by **R18 / P6d** — provenance MUST surface at `GET /api/audits/:id` + the findings table (multi-impl backend change). Real-model E2E (LM Studio `qwen3.6-35b-a3b` on `woofy/app`) confirmed the agent emits **6 `provenance="llm"` findings**; the live-stack proof of `llm_l5_verified` + API-surfaced provenance is pending the **L5-on restart + the P6d plumbing**.
- **Real-model E2E CLOSED (2026-06-27, LM Studio qwen3.6-35b-a3b):** (1) **`llm_l5_verified` produced + live at the API** (audit `54505115`, histogram {skill:2, llm_l5_verified:7}, incl. 4 cross-line `export_route.ts` findings the regex skills miss). (2) **Found + fixed a real dead-code bug** — the streaming validate path never retagged `llm_l5_verified` (P6b was wired/tested offline-only), so it never worked on live audits; fixed + 4 regression tests (`TestL5StreamingRetag`). (3) **L5 `max_tokens` fix** (default 4000, tunable) resolves the thinking-model verdict-JSON truncation that returned 0 verdicts. **Honest caveats:** the promotions survived via the RC6 safeguard (weight=0), NOT affirmative confirmation (0 verdicts `exploitable>0.5`) — the ±2-line L5 window can't see cross-function flows (7.5); generate is ~33% reliable on this thinking model without token tuning (7.7); L5 still occasionally truncates under load (7.6). **Net: caveat 2's mechanism is proven and a real bug was fixed; quality/reliability are Phase-7 follow-ups.**
- **Budget-aware batching (impl):** with `VULTURE_LLM_BUDGET_USD` set, the sweep batches cautiously (`VULTURE_LLM_FILES_PER_BATCH`, default 1 in budget mode); with no budget it packs ~40 files/batch.
- **R7 corrected (2026-06-27):** `code_snippet` **persists** to the SSE result + the pre-existing `code_snippet` DB column (`001_init.sql:73`) — no migration; the plan's original "in-memory only" was wrong. Redaction for secret-bearing CWEs added (Phase 2 P2a).
- **N=10 (2026-06-27, gate-computed):** the seed corpus (10 CWEs × 6+6 first-party fixtures) yields N=10 under the strict gate; honest, not inflated toward the aspirational ~50–65. Growth to ~80 via more fixtures + Juliet CC0 (Phase 7).
- **§12.4 Juliet:** deferred to Phase 7 (CC0-compatible; needs network + per-pair vetting against the file-level detector). **§12.6 PR-gate:** 5e **WIRED + committed** (`2690a10`, 2026-06-29) — the PR lane runs `make cwe-corpus` + `report_coverage --check`; enforce-vs-advisory tuning + a live GitHub-Actions confirmation remain soak.

## Notes / blockers
- **0057 code complete (Phases 0–6); all green + end-to-end audited (32-agent) with all 13 findings fixed.** Phase 7 is operational/ongoing — the substantive open cluster is **reasoning-model LLM reliability** (7.5 cross-function L5 window · 7.6 L5 truncation under load · 7.7 generate-phase token burn, ~33% reliable on the 35B), plus Juliet ingestion (7.2), line-precision (7.3), and live-model T25.
- **Committed** on the branch through HEAD `d19bfc6` (Phases 0–6 `da07f8d`→`6c4acda`; audit-fixes `a3f051e`/`9ab0b72`; R17 CI `2690a10`; 0059 scan-controls `6168a1a`).
- **UNCOMMITTED (working tree, 15 files):** the 2026-06-29 R1-reversal + fleet-tier3 uniformity change — green but not committed; the committed HEAD still ships the old CWE LLM-on-by-default. Until committed, the headline "CWE LLM opt-in" holds only in the working tree (and is not yet live in the `~/.vulture/runtime` stack, which serves a stale copy).
- Adversarial review across the 5 phase-workflows caught + fixed real issues: an arbitrary-file-read exfil, a raw-secret SSE leak, untagged rollup parents, and 4 signature false-positive sources.
