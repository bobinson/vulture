# Feature 0057 — Implementation Status

| | |
|---|---|
| **Feature** | 0057_cwe_agent_hardening (LLM-on + signatures + verified coverage) |
| **Status** | 🟢 Phase 0 + Phase 1 IMPLEMENTED & GREEN (T1–T12). Phases 4–7 not started. |
| **Last updated** | 2026-06-27 |

> Tests are written **before** the implementation in every phase (CLAUDE.md). An item is
> "done" only when its tests pass **and** the full existing CWE + shared suites still pass.
> **N is gate-computed (≈50–65 ship → ~80 ceiling), never asserted.** Phases are
> independently shippable — gate each before the next.

## Checkpoints

### Phase 0 — Code-grounding (shared infra; prerequisite)
| # | Item | Tests | Status |
|---|------|-------|--------|
| 0.1 | `code_snippet` field on the in-memory finding (`audit_runner.py` `AuditFinding`) | T1 | ✅ Done |
| 0.2 | `_attach_code_snippet()` central populator before `_validate` | T1 | ✅ Done |
| 0.3 | L5 skips empty-window findings (`_has_code_window` in `_select_findings`) | T2 | ✅ Done |

### Phase 1 — LLM phase on, safely
| # | Item | Tests | Status |
|---|------|-------|--------|
| 1a | CWE `use_llm` default True (model-gated via `check_llm_health`) + graceful skills-only notice + `VULTURE_CWE_DISABLE_LLM` hatch | T6, T8 | ✅ Done |
| 1b | L5 default-on for CWE when LLM on; RC6 blast-radius cap; crypto/policy exemption (`_apply_l5_safeguards`) | T3, T5, T10 | ✅ Done |
| 1c | LLM read/grep tools attached on the inline path too | T9 | ✅ Done |
| 1d | Cost/work cap (`VULTURE_LLM_BUDGET_USD`, `VULTURE_LLM_MAX_FILES`) + honest token reporting + partial notice | T7 | ✅ Done |
| 1f | Whole-codebase batch-loop sweep + cross-batch/skill dedup; tail-drop eliminated (`_build_source_batches` + `_collect_llm_findings_batched_async`) | T4, T12 | ✅ Done |
| **Gate** | Soak: recall/FP/cost telemetry | T3–T12 | ☐ (pending real-audit soak) |

### Phase 2 — Tune from soak
| 2.1 | RC6 threshold, crypto-exempt set, budget defaults | — | ☐ Not started |

### Phase 3 — LLM-on docs
| 3.1 | Default + generate-verify flow + env vars (agent.py, CLAUDE.md) | — | ☐ Not started |

### Phase 4 — Signature registry + detector (land as `candidate`)
| # | Item | Tests | Status |
|---|------|-------|--------|
| 4a | `CweSignature` schema (compiled-regex py modules) | T13 | ☐ Not started |
| 4b | Generic 3-step matcher, ext-indexed | T13 | ☐ Not started |
| 4c | Registry + family modules | T13 | ☐ Not started |
| 4d | **(BLOCKING)** route via `check_catalog_generic` + `_DEDICATED_SKILL_CWES`; remove keyword path | T14 | ☐ Not started |
| 4e | Validation tiering (trusted/candidate) | T15 | ☐ Not started |
| 4f | Seed 7–8 net-new signatures as `candidate` | T13 | ☐ Not started |

### Phase 5 — Corpus + per-CWE gates
| # | Item | Tests | Status |
|---|------|-------|--------|
| 5a | Corpus tree + `manifest.yaml` (Apache-2.0 + Juliet CC0) | T16 | ☐ Not started |
| 5b | `gates.yaml` + `corpus_runner.py` (deterministic) | T16–T19 | ☐ Not started |
| 5c | `promote_signatures.py` (data-driven) | T21 | ☐ Not started |
| 5d | License rows; no GPL/unlicensed | — | ☐ Not started |
| 5e | CI: PR curated subset (<~60s) + nightly full lane | — | ☐ Not started |

### Phase 6 — Attestation + doc reconciliation
| # | Item | Tests | Status |
|---|------|-------|--------|
| 6a | `report_coverage.py` → golden `VERIFIED_CWES.md`; stale→CI fail | T22, T24 | ☐ Not started |
| 6b | Per-finding `provenance` tag (in-memory) | T23 | ☐ Not started |
| 6c | Replace "846/400+" with attested N | — | ☐ Not started |

### Phase 7 — Soak (signatures)
| 7.1 | Run signatures + gate on real audits; tune `gates.yaml`; decide CWE-489 | — | ☐ Not started |
| 7.2 | Measure T25 LLM recall-lift (opt-in, never gated) | T25 | ☐ Not started |

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
| T8 | CWE LLM on by default (model gated) | det | ✅ |
| T9 | LLM finds a cross-line gap skills miss | llm-fake | ✅ |
| T10 | crypto CWE not auto-suppressed | det | ✅ |
| T11 | clean code stays within FP gate | det | ✅ |
| T12 | LLM sweeps beyond one context window | llm-fake | ✅ |
| T13 | signature detects cross-line gap, LLM OFF | det | ☐ |
| T14 | dedup precedence — no double-report (R11) | det | ☐ |
| T15 | candidate demotable / trusted needs 2 checks | det | ☐ |
| T16 | corpus runner scores per-CWE | det | ☐ |
| T17 | recall gate fails on regression | det | ☐ |
| T18 | per-CWE precision gate | det | ☐ |
| T19 | min_fixtures anti-vacuity guard | det | ☐ |
| T20 | weak candidate measured, not gating | det | ☐ |
| T21 | promotion is data-driven | det | ☐ |
| T22 | VERIFIED_CWES.md golden not stale | det | ☐ |
| T23 | provenance tagged | det | ☐ |
| T24 | attestation counts reconcile | det | ☐ |
| T25 | LLM raises recall on dataflow fixtures (opt-in, not gating) | llm | ☐ |

## Decisions log
- **§12.1 (2026-06-26):** `VULTURE_LLM_MAX_FILES=10000` (per user) — file count not the cap;
  context window + USD budget bound the sweep.
- **#15 folded in (2026-06-26):** LLM batch-loop sweep in scope (P1f).
- **#4 + #2 folded in (2026-06-26):** signatures + corpus + per-CWE gates kept **in 0057** as
  Phases 4–7 (per user — the design workflow had recommended a 0058 split). Standalone 0058
  docs removed.
- **Tranche-1 = 8 signatures** (7 solid + CWE-489 provisional); CWE-77/119/120/377 dropped
  (overlap), CWE-121/73 deferred (need AST/dataflow).
- **N gate-computed ≈50–65 → ~80 ceiling** — not 87, not 846.
- **RC6 cap shape (2026-06-27, impl):** the blast-radius cap freezes L5 only when the
  demotion fraction is in the OPEN band `(0.5, 1.0)` with `≥3` judged findings — a *majority
  but not unanimous* demotion (the inconsistent signal RC6 guards against). A **unanimous**
  100%-demote is treated as an internally-consistent verdict (clean tree) and applies
  normally; this is what keeps the pre-existing L5 unit tests (single-finding + all-demoted
  batch) green while satisfying T5/T5b. Tunable in Phase 2 from soak.
- **Provenance marker (impl):** the audit runner tags LLM findings `provenance="llm"`; the
  validate stage treats a finding as deterministic/trusted (R2 voter floor + L5-exempt) iff
  it carries a `check_id` AND is not `provenance=="llm"`. Crypto/policy CWEs
  (326/327/328/330/798/319) are L5-exempt regardless of provenance.
- **Budget-aware batching (impl):** with `VULTURE_LLM_BUDGET_USD` set, the sweep batches
  cautiously (`VULTURE_LLM_FILES_PER_BATCH`, default 1 in budget mode) so cost accrues
  incrementally and the cap halts it mid-tree; with no budget it packs large batches
  (default 40 files/batch) for efficiency — file count is not the throttle.
- _(§12.3–6 pending review)_

## Notes / blockers
- Awaiting review sign-off on §12 (esp. tranche size, Juliet go/no-go, gate strictness, PR
  enforcement) before implementation begins.
- Phases 4–6 depend on Phase 0 (`code_snippet`). Phases 0–1 are shippable independently.
